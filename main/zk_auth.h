#ifndef ZK_AUTH_H
#define ZK_AUTH_H

#include "tang_storage.h"
#include "tang_tee_service.h"
#include <cJSON.h>
#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_random.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <inttypes.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <string.h>

// Zero-Knowledge Authentication Module
// Implements Client-Side KDF + ECIES Tunnel for ESP32-C6
//
// After ECIES decryption the PBKDF2 hash is passed to the TEE which
// derives the master key via the hardware HMAC peripheral (eFuse KEY5).
// Private keys never leave the TEE.

// Forward declarations — defined in TangServer.h after all includes
extern TangKeyStore keystore;
extern bool unlocked;

static const char *TAG_ZK_AUTH = "zk_auth";

class ZKAuth {
private:
  mbedtls_ecp_group grp;
  mbedtls_mpi device_private_d;
  mbedtls_ecp_point device_public_Q;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  uint8_t device_public_key[65]; // Uncompressed P-256: 0x04 + X(32) + Y(32)

  bool initialized;

  // Rate limiting state
  uint32_t failed_attempts;
  int64_t lockout_until_us; // esp_timer microsecond timestamp

  static constexpr uint32_t MAX_BACKOFF_SECS = 300; // 5 minutes cap

  // Returns the lockout duration in seconds for the given failure count.
  static uint32_t backoff_secs(uint32_t failures) {
    if (failures == 0)
      return 0;
    // 2^(failures-1) seconds, capped at MAX_BACKOFF_SECS
    uint32_t secs = 1u << (failures - 1 > 30 ? 30 : failures - 1);
    return secs > MAX_BACKOFF_SECS ? MAX_BACKOFF_SECS : secs;
  }

  // Check if rate-limited. If so, sets *error_json with retry_after and returns
  // true.
  bool check_rate_limit(char **error_json) {
    int64_t now = esp_timer_get_time();
    if (now < lockout_until_us) {
      uint32_t remaining =
          (uint32_t)((lockout_until_us - now + 999999) / 1000000);
      char buf[128];
      snprintf(buf, sizeof(buf),
               "{\"error\":\"Too many attempts\",\"retry_after\":%" PRIu32 "}",
               remaining);
      *error_json = strdup(buf);
      ESP_LOGW(TAG_ZK_AUTH, "Rate limited: %" PRIu32 " seconds remaining",
               remaining);
      return true;
    }
    return false;
  }

  // Record a failed authentication attempt and set the lockout window.
  void record_failure() {
    failed_attempts++;
    uint32_t delay = backoff_secs(failed_attempts);
    lockout_until_us = esp_timer_get_time() + (int64_t)delay * 1000000;
    ESP_LOGW(TAG_ZK_AUTH,
             "Auth failure #%" PRIu32 " \u2014 next attempt allowed in %" PRIu32
             " s",
             failed_attempts, delay);
  }

  // Reset rate limiting after a successful authentication.
  void record_success() {
    failed_attempts = 0;
    lockout_until_us = 0;
  }

  static void bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
      snprintf(hex + (i * 2), 3, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
  }

  bool hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    if (strlen(hex) != bin_len * 2)
      return false;
    for (size_t i = 0; i < bin_len; i++) {
      if (sscanf(hex + (i * 2), "%2hhx", &bin[i]) != 1)
        return false;
    }
    return true;
  }

  // Decrypt an ECIES blob encrypted under the device's ephemeral tunnel key.
  // Blob format: IV(16) + Ciphertext(N) + HMAC(32), N must be a multiple of 16.
  // Returns heap-allocated plaintext of N bytes (caller must free and zeroize).
  // On error returns NULL and sets *error_json to a heap-allocated error
  // string.
  uint8_t *decrypt_ecies_payload(const char *client_pub_hex,
                                 const char *blob_hex, size_t *out_len,
                                 char **error_json) {
    *out_len = 0;

    size_t client_pub_len = strlen(client_pub_hex) / 2;
    uint8_t *client_pub_bin = (uint8_t *)malloc(client_pub_len);
    if (!hex_to_bin(client_pub_hex, client_pub_bin, client_pub_len)) {
      free(client_pub_bin);
      *error_json = strdup("{\"error\":\"Invalid client public key format\"}");
      return NULL;
    }

    mbedtls_ecp_point client_point;
    mbedtls_ecp_point_init(&client_point);
    int ret = mbedtls_ecp_point_read_binary(&grp, &client_point, client_pub_bin,
                                            client_pub_len);
    free(client_pub_bin);
    if (ret != 0) {
      mbedtls_ecp_point_free(&client_point);
      *error_json = strdup("{\"error\":\"Invalid client public key\"}");
      return NULL;
    }

    mbedtls_mpi shared_secret_mpi;
    mbedtls_mpi_init(&shared_secret_mpi);
    ret = mbedtls_ecdh_compute_shared(&grp, &shared_secret_mpi, &client_point,
                                      &device_private_d,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_point_free(&client_point);
    if (ret != 0) {
      mbedtls_mpi_free(&shared_secret_mpi);
      *error_json = strdup("{\"error\":\"ECDH failed\"}");
      return NULL;
    }

    uint8_t shared_secret_raw[32];
    ret = mbedtls_mpi_write_binary(&shared_secret_mpi, shared_secret_raw, 32);
    mbedtls_mpi_free(&shared_secret_mpi);
    if (ret != 0) {
      *error_json = strdup("{\"error\":\"Shared secret export failed\"}");
      return NULL;
    }

    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t enc_key[32], mac_key[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 0);

    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, (const uint8_t *)"encryption", 10);
    mbedtls_md_update(&md_ctx, shared_secret_raw, sizeof(shared_secret_raw));
    mbedtls_md_finish(&md_ctx, enc_key);

    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, (const uint8_t *)"authentication", 14);
    mbedtls_md_update(&md_ctx, shared_secret_raw, sizeof(shared_secret_raw));
    mbedtls_md_finish(&md_ctx, mac_key);
    mbedtls_md_free(&md_ctx);

    mbedtls_platform_zeroize(shared_secret_raw, sizeof(shared_secret_raw));

    size_t blob_len = strlen(blob_hex) / 2;
    if (blob_len < 48 + 16) {
      mbedtls_platform_zeroize(enc_key, 32);
      mbedtls_platform_zeroize(mac_key, 32);
      *error_json = strdup("{\"error\":\"Invalid blob size\"}");
      return NULL;
    }

    size_t ct_len = blob_len - 16 - 32;
    if (ct_len % 16 != 0) {
      mbedtls_platform_zeroize(enc_key, 32);
      mbedtls_platform_zeroize(mac_key, 32);
      *error_json = strdup("{\"error\":\"Invalid blob alignment\"}");
      return NULL;
    }

    uint8_t *blob = (uint8_t *)malloc(blob_len);
    if (!hex_to_bin(blob_hex, blob, blob_len)) {
      free(blob);
      mbedtls_platform_zeroize(enc_key, 32);
      mbedtls_platform_zeroize(mac_key, 32);
      *error_json = strdup("{\"error\":\"Invalid blob format\"}");
      return NULL;
    }

    uint8_t *iv = blob;
    uint8_t *ciphertext = blob + 16;
    uint8_t *received_hmac = blob + 16 + ct_len;

    uint8_t computed_hmac[32];
    ret =
        mbedtls_md_hmac(md_info, mac_key, 32, blob, 16 + ct_len, computed_hmac);
    mbedtls_platform_zeroize(mac_key, 32);

    if (ret != 0) {
      free(blob);
      mbedtls_platform_zeroize(enc_key, 32);
      *error_json = strdup("{\"error\":\"HMAC computation failed\"}");
      return NULL;
    }

    int hmac_result = 0;
    for (int i = 0; i < 32; i++)
      hmac_result |= received_hmac[i] ^ computed_hmac[i];

    if (hmac_result != 0) {
      free(blob);
      mbedtls_platform_zeroize(enc_key, 32);
      ESP_LOGW(TAG_ZK_AUTH, "HMAC verification failed");
      *error_json = strdup(
          "{\"error\":\"Authentication failed - data tampered or wrong key\"}");
      return NULL;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_dec(&aes, enc_key, 256);
    mbedtls_platform_zeroize(enc_key, 32);

    if (ret != 0) {
      mbedtls_aes_free(&aes);
      free(blob);
      *error_json = strdup("{\"error\":\"AES setup failed\"}");
      return NULL;
    }

    uint8_t *plaintext = (uint8_t *)malloc(ct_len);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ct_len, iv_copy,
                                ciphertext, plaintext);
    mbedtls_aes_free(&aes);
    free(blob);

    if (ret != 0) {
      free(plaintext);
      *error_json = strdup("{\"error\":\"Decryption failed\"}");
      return NULL;
    }

    *out_len = ct_len;
    return plaintext;
  }

  // Parse ECIES JSON payload and decrypt. Common to all process_* methods.
  // On success returns heap-allocated plaintext and sets *out_len.
  // On error returns NULL and sets *error_json.
  // Caller must zeroize and free the returned plaintext.
  uint8_t *parse_and_decrypt(const char *json_payload, size_t expected_len,
                             size_t *out_len, char **error_json) {
    *out_len = 0;

    cJSON *doc = cJSON_Parse(json_payload);
    if (!doc) {
      *error_json = strdup("{\"error\":\"Invalid JSON\"}");
      return NULL;
    }

    cJSON *client_pub_item = cJSON_GetObjectItem(doc, "clientPub");
    cJSON *blob_item = cJSON_GetObjectItem(doc, "blob");

    const char *client_pub_hex =
        cJSON_IsString(client_pub_item) ? client_pub_item->valuestring : NULL;
    const char *blob_hex =
        cJSON_IsString(blob_item) ? blob_item->valuestring : NULL;

    if (!client_pub_hex || !blob_hex) {
      cJSON_Delete(doc);
      *error_json = strdup("{\"error\":\"Missing required fields\"}");
      return NULL;
    }

    uint8_t *decrypted =
        decrypt_ecies_payload(client_pub_hex, blob_hex, out_len, error_json);
    cJSON_Delete(doc);

    if (!decrypted)
      return NULL;

    if (*out_len != expected_len) {
      mbedtls_platform_zeroize(decrypted, *out_len);
      free(decrypted);
      *error_json = strdup("{\"error\":\"Invalid payload size\"}");
      return NULL;
    }

    return decrypted;
  }

public:
  ZKAuth() : initialized(false), failed_attempts(0), lockout_until_us(0) {
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&device_private_d);
    mbedtls_ecp_point_init(&device_public_Q);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
  }

  ~ZKAuth() {
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&device_private_d);
    mbedtls_ecp_point_free(&device_public_Q);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
  }

  bool init() {
    if (initialized)
      return true;

    const char *pers = "zk_auth_esp32";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
      ESP_LOGE(TAG_ZK_AUTH, "mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
      return false;
    }

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
      ESP_LOGE(TAG_ZK_AUTH, "mbedtls_ecp_group_load failed: -0x%04x", -ret);
      return false;
    }

    if (!regenerate_tunnel_key()) {
      return false;
    }

    initialized = true;
    ESP_LOGI(TAG_ZK_AUTH,
             "ZK Authentication initialized (ephemeral tunnel key ready)");

    return true;
  }

  // Generate a fresh ephemeral ECDH keypair for the ECIES tunnel.
  // Called at init and after every use to provide forward secrecy.
  bool regenerate_tunnel_key() {
    int ret = mbedtls_ecdh_gen_public(&grp, &device_private_d, &device_public_Q,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
      ESP_LOGE(TAG_ZK_AUTH, "mbedtls_ecdh_gen_public failed: -0x%04x", -ret);
      return false;
    }

    size_t olen;
    ret = mbedtls_ecp_point_write_binary(
        &grp, &device_public_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
        device_public_key, sizeof(device_public_key));
    if (ret != 0 || olen != 65) {
      ESP_LOGE(TAG_ZK_AUTH, "mbedtls_ecp_point_write_binary failed: -0x%04x",
               -ret);
      return false;
    }

    return true;
  }

  // Return ephemeral tunnel public key + eFuse UID (PBKDF2 salt) for the
  // browser
  char *get_identity_json() {
    char pubkey_hex[131]; // 65 bytes * 2 + null
    bin_to_hex(device_public_key, 65, pubkey_hex);

    uint8_t uid[16];
    esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, uid, 128);
    char uid_hex[33]; // 16 bytes * 2 + null
    bin_to_hex(uid, 16, uid_hex);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "pubKey", pubkey_hex);
    cJSON_AddStringToObject(root, "salt", uid_hex);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
  }

  // Returns seconds until next attempt is allowed, or 0 if not rate-limited.
  uint32_t rate_limit_remaining() const {
    int64_t now = esp_timer_get_time();
    if (now < lockout_until_us)
      return (uint32_t)((lockout_until_us - now + 999999) / 1000000);
    return 0;
  }

  uint32_t get_failed_attempts() const { return failed_attempts; }

  char *process_unlock(const char *json_payload, bool *success_out) {
    *success_out = false;

    if (!initialized)
      return strdup("{\"error\":\"Not initialized\"}");

    char *rate_err = NULL;
    if (check_rate_limit(&rate_err))
      return rate_err;

    ESP_LOGI(TAG_ZK_AUTH, "Processing unlock request");

    size_t plaintext_len = 0;
    char *error_msg = NULL;
    uint8_t *decrypted =
        parse_and_decrypt(json_payload, 32, &plaintext_len, &error_msg);
    if (!decrypted)
      return error_msg;

    bool verification_result = false;
    bool first_setup = !keystore.has_exchange_key();

    // Load or generate KDF salt for forward secrecy
    if (first_setup) {
      keystore.generate_kdf_salt();
    } else if (!keystore.load_kdf_salt()) {
      mbedtls_platform_zeroize(decrypted, 32);
      free(decrypted);
      ESP_LOGE(TAG_ZK_AUTH, "KDF salt missing from NVS");
      return strdup("{\"error\":\"KDF salt missing — device may need "
                    "re-initialization\"}");
    }

    if (keystore.derive_and_verify(decrypted)) {
      if (first_setup) {
        ESP_LOGI(TAG_ZK_AUTH, "First-time setup: storing derived public keys");
      }
      verification_result = keystore.store_public_keys();
    }

    mbedtls_platform_zeroize(decrypted, 32);
    free(decrypted);

    if (verification_result) {
      record_success();
      keystore.activated = true;
      unlocked = true;
      ESP_LOGI(TAG_ZK_AUTH, "Password verification successful");
    } else {
      record_failure();
      keystore.wipe_secrets();
      unlocked = false;
      ESP_LOGW(TAG_ZK_AUTH, "Password verification failed");
    }

    cJSON *resp_doc = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp_doc, "success", verification_result);
    cJSON_AddStringToObject(resp_doc, verification_result ? "message" : "error",
                            verification_result ? "Unlock successful"
                                                : "Invalid password");
    if (!verification_result) {
      uint32_t retry = rate_limit_remaining();
      if (retry > 0)
        cJSON_AddNumberToObject(resp_doc, "retry_after", retry);
    }

    char *response_str = cJSON_PrintUnformatted(resp_doc);
    cJSON_Delete(resp_doc);

    // Rotate tunnel key so the old private key can't decrypt future sessions
    regenerate_tunnel_key();

    *success_out = verification_result;
    return response_str;
  }

  // Process password change request.
  // Expects ECIES blob containing old_hash(32) + new_hash(32) = 64 bytes.
  char *process_change_password(const char *json_payload, bool *success_out) {
    *success_out = false;

    if (!initialized)
      return strdup("{\"error\":\"Not initialized\"}");
    if (!unlocked)
      return strdup("{\"error\":\"Device not unlocked\"}");

    char *rate_err = NULL;
    if (check_rate_limit(&rate_err))
      return rate_err;

    ESP_LOGI(TAG_ZK_AUTH, "Processing password change");

    size_t plaintext_len = 0;
    char *error_msg = NULL;
    uint8_t *decrypted =
        parse_and_decrypt(json_payload, 64, &plaintext_len, &error_msg);
    if (!decrypted)
      return error_msg;

    // Load old salt for verification, generate new salt for forward secrecy
    if (!keystore.load_kdf_salt()) {
      mbedtls_platform_zeroize(decrypted, 64);
      free(decrypted);
      ESP_LOGE(TAG_ZK_AUTH, "KDF salt missing from NVS");
      return strdup("{\"success\":false,\"error\":\"KDF salt missing\"}");
    }

    // Build 64-byte keying materials: password_hash(32) || kdf_salt(32)
    uint8_t old_keying[64], new_keying[64];
    memcpy(old_keying, decrypted, 32);
    memcpy(old_keying + 32, keystore.kdf_salt, 32);

    uint8_t new_salt[32];
    esp_fill_random(new_salt, sizeof(new_salt));
    memcpy(new_keying, decrypted + 32, 32);
    memcpy(new_keying + 32, new_salt, 32);

    uint8_t pub_keys_buf[NUM_EXCHANGE_KEYS * TEE_EC_PUBLIC_KEY_SIZE];
    esp_err_t err = tang_tee_change_password(old_keying, new_keying,
                                             NUM_EXCHANGE_KEYS, pub_keys_buf);

    mbedtls_platform_zeroize(old_keying, sizeof(old_keying));
    mbedtls_platform_zeroize(new_keying, sizeof(new_keying));
    mbedtls_platform_zeroize(decrypted, 64);
    free(decrypted);

    if (err != ESP_OK) {
      mbedtls_platform_zeroize(new_salt, sizeof(new_salt));
      if (err == ESP_ERR_INVALID_ARG)
        record_failure();
      ESP_LOGW(TAG_ZK_AUTH, "Password change failed: %s", esp_err_to_name(err));
      return strdup(
          err == ESP_ERR_INVALID_ARG
              ? "{\"success\":false,\"error\":\"Current password incorrect\"}"
              : "{\"success\":false,\"error\":\"Failed to derive new keys\"}");
    }

    // Update the salt to the newly generated one
    memcpy(keystore.kdf_salt, new_salt, 32);
    keystore.kdf_salt_loaded = true;
    mbedtls_platform_zeroize(new_salt, sizeof(new_salt));

    for (int s = 0; s < NUM_EXCHANGE_KEYS; s++) {
      memcpy(keystore.exc_pub[s], pub_keys_buf + s * TEE_EC_PUBLIC_KEY_SIZE,
             TEE_EC_PUBLIC_KEY_SIZE);
    }
    keystore.exc_pub_loaded = true;
    keystore.gen = NUM_EXCHANGE_KEYS - 1;
    keystore.activated = true;

    if (!keystore.store_public_keys()) {
      keystore.wipe_secrets();
      ESP_LOGE(TAG_ZK_AUTH, "Password change failed: NVS write error");
      return strdup(
          "{\"success\":false,\"error\":\"Failed to store new keys\"}");
    }

    ESP_LOGI(TAG_ZK_AUTH, "Password changed successfully");
    regenerate_tunnel_key();
    *success_out = true;
    return strdup(
        "{\"success\":true,\"message\":\"Password changed and keys rotated\"}");
  }

  // Process key-rotation request.
  // Expects ECIES blob containing password_hash (32 bytes).
  char *process_rotate(const char *json_payload, bool *success_out) {
    *success_out = false;

    if (!initialized)
      return strdup("{\"error\":\"Not initialized\"}");
    if (!unlocked)
      return strdup("{\"error\":\"Device not unlocked\"}");

    ESP_LOGI(TAG_ZK_AUTH, "Processing key rotation");

    size_t plaintext_len = 0;
    char *error_msg = NULL;
    uint8_t *decrypted =
        parse_and_decrypt(json_payload, 32, &plaintext_len, &error_msg);
    if (!decrypted)
      return error_msg;

    // Ensure KDF salt is available (should be from unlock, but verify)
    if (!keystore.kdf_salt_loaded && !keystore.load_kdf_salt()) {
      mbedtls_platform_zeroize(decrypted, 32);
      free(decrypted);
      return strdup("{\"success\":false,\"error\":\"KDF salt missing\"}");
    }

    bool rotate_ok = keystore.rotate(decrypted);
    mbedtls_platform_zeroize(decrypted, 32);
    free(decrypted);

    if (!rotate_ok) {
      ESP_LOGE(TAG_ZK_AUTH, "Key rotation failed");
      return strdup("{\"success\":false,\"error\":\"Rotation failed\"}");
    }

    ESP_LOGI(TAG_ZK_AUTH, "Key rotation successful — gen %u", keystore.gen);
    regenerate_tunnel_key();
    *success_out = true;

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddNumberToObject(resp, "gen", keystore.gen);
    char *response_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return response_str;
  }

  bool is_unlocked() const { return unlocked; }

  void lock() {
    unlocked = false;
    keystore.wipe_secrets();
  }
};

#endif // ZK_AUTH_H
