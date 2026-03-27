#ifndef ZK_AUTH_H
#define ZK_AUTH_H

#include "provision.h"
#include "tang_storage.h"
#include <cJSON.h>
#include <esp_mac.h>
#include <esp_system.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <string.h>

// Zero-Knowledge Authentication Module
// Implements Client-Side KDF + ECIES Tunnel for ESP32-C6
//
// After ECIES decryption the PBKDF2 hash is run through the hardware HMAC
// peripheral (eFuse KEY5) to produce a device-bound AES-256 key.  That key
// encrypts/decrypts the exchange private key via AES-256-GCM.

// Forward declarations — defined in TangServer.h after all includes
extern TangKeyStore keystore;
extern bool unlocked;

class ZKAuth {
private:
  mbedtls_ecp_group grp;
  mbedtls_mpi device_private_d;
  mbedtls_ecp_point device_public_Q;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  uint8_t device_public_key[133]; // Uncompressed: 0x04 + X(66) + Y(66)

  bool initialized;

  void bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
      sprintf(hex + (i * 2), "%02x", bin[i]);
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

    uint8_t shared_secret_raw[66];
    ret = mbedtls_mpi_write_binary(&shared_secret_mpi, shared_secret_raw, 66);
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
      printf("HMAC verification FAILED\n");
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

public:
  ZKAuth() : initialized(false) {
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
      printf("mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
      return false;
    }

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP521R1);
    if (ret != 0) {
      printf("mbedtls_ecp_group_load failed: -0x%04x\n", -ret);
      return false;
    }

    // Generate ephemeral tunnel keypair (fresh each boot)
    ret = mbedtls_ecdh_gen_public(&grp, &device_private_d, &device_public_Q,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
      printf("mbedtls_ecdh_gen_public failed: -0x%04x\n", -ret);
      return false;
    }

    size_t olen;
    ret = mbedtls_ecp_point_write_binary(
        &grp, &device_public_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
        device_public_key, sizeof(device_public_key));
    if (ret != 0 || olen != 133) {
      printf("mbedtls_ecp_point_write_binary failed: -0x%04x\n", -ret);
      return false;
    }

    initialized = true;

    printf("\n=== ZK Authentication Initialized ===\n");
    printf("Ephemeral Tunnel Key: ");
    for (int i = 0; i < 133; i++)
      printf("%02x", device_public_key[i]);
    printf("\n=====================================\n\n");

    return true;
  }

  // Return ephemeral tunnel public key + MAC address for the browser
  char *get_identity_json() {
    char pubkey_hex[267]; // 133 bytes * 2 + null
    bin_to_hex(device_public_key, 133, pubkey_hex);

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char mac_hex[13];
    bin_to_hex(mac, 6, mac_hex);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "pubKey", pubkey_hex);
    cJSON_AddStringToObject(root, "macAddress", mac_hex);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
  }

  // Process unlock request with ECIES tunnel.
  // After decryption:
  //   1. Derive device-bound AES key via hardware HMAC
  //   2. First-time: generate & encrypt exchange key
  //      Subsequent: decrypt exchange key (GCM tag = password check)
  char *process_unlock(const char *json_payload, bool *success_out) {
    *success_out = false;

    if (!initialized)
      return strdup("{\"error\":\"Not initialized\"}");

    cJSON *doc = cJSON_Parse(json_payload);
    if (!doc)
      return strdup("{\"error\":\"Invalid JSON\"}");

    cJSON *client_pub_item = cJSON_GetObjectItem(doc, "clientPub");
    cJSON *encrypted_blob_item = cJSON_GetObjectItem(doc, "blob");

    const char *client_pub_hex =
        cJSON_IsString(client_pub_item) ? client_pub_item->valuestring : NULL;
    const char *encrypted_blob_hex = cJSON_IsString(encrypted_blob_item)
                                         ? encrypted_blob_item->valuestring
                                         : NULL;

    if (!client_pub_hex || !encrypted_blob_hex) {
      cJSON_Delete(doc);
      return strdup("{\"error\":\"Missing required fields\"}");
    }

    printf("\n=== Processing Unlock Request ===\n");

    size_t plaintext_len = 0;
    char *error_msg = NULL;
    uint8_t *decrypted = decrypt_ecies_payload(
        client_pub_hex, encrypted_blob_hex, &plaintext_len, &error_msg);
    cJSON_Delete(doc);

    if (!decrypted)
      return error_msg;

    if (plaintext_len != 32) {
      mbedtls_platform_zeroize(decrypted, plaintext_len);
      free(decrypted);
      return strdup("{\"error\":\"Invalid payload size\"}");
    }

    // --- Store password hash and derive keys for verification ---
    memcpy(keystore.password_hash, decrypted, 32);
    mbedtls_platform_zeroize(decrypted, 32);
    free(decrypted);
    keystore.activated = true;

    // --- Derive keys, verify or store public keys ---
    bool verification_result = false;

    if (keystore.derive_and_verify()) {
      if (!keystore.has_exchange_key()) {
        // First activation: store derived public keys in NVS
        printf("First-time setup: storing derived public keys\n");
        verification_result = keystore.store_public_keys();
      } else {
        // Subsequent: verify derived public keys match stored ones
        verification_result = keystore.verify_public_keys();
      }
    }

    if (!verification_result)
      keystore.wipe_secrets();

    cJSON *resp_doc = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp_doc, "success", verification_result);

    if (verification_result) {
      printf("Password verification SUCCESSFUL\n");
      unlocked = true;
      cJSON_AddStringToObject(resp_doc, "message", "Unlock successful");
    } else {
      printf("Password verification FAILED\n");
      unlocked = false;
      cJSON_AddStringToObject(resp_doc, "error", "Invalid password");
    }

    char *response_str = cJSON_PrintUnformatted(resp_doc);
    cJSON_Delete(resp_doc);

    *success_out = verification_result;
    return response_str;
  }

  // Process password change request.
  // Expects ECIES blob containing old_hash(32) + new_hash(32) = 64 bytes.
  // Verifies old password, derives new keys from new password, overwrites NVS.
  char *process_change_password(const char *json_payload, bool *success_out) {
    *success_out = false;

    if (!initialized)
      return strdup("{\"error\":\"Not initialized\"}");
    if (!unlocked)
      return strdup("{\"error\":\"Device not unlocked\"}");

    cJSON *doc = cJSON_Parse(json_payload);
    if (!doc)
      return strdup("{\"error\":\"Invalid JSON\"}");

    cJSON *client_pub_item = cJSON_GetObjectItem(doc, "clientPub");
    cJSON *encrypted_blob_item = cJSON_GetObjectItem(doc, "blob");

    const char *client_pub_hex =
        cJSON_IsString(client_pub_item) ? client_pub_item->valuestring : NULL;
    const char *encrypted_blob_hex = cJSON_IsString(encrypted_blob_item)
                                         ? encrypted_blob_item->valuestring
                                         : NULL;

    if (!client_pub_hex || !encrypted_blob_hex) {
      cJSON_Delete(doc);
      return strdup("{\"error\":\"Missing required fields\"}");
    }

    printf("\n=== Processing Password Change ===\n");

    size_t plaintext_len = 0;
    char *error_msg = NULL;
    uint8_t *decrypted = decrypt_ecies_payload(
        client_pub_hex, encrypted_blob_hex, &plaintext_len, &error_msg);
    cJSON_Delete(doc);

    if (!decrypted)
      return error_msg;

    if (plaintext_len != 64) {
      mbedtls_platform_zeroize(decrypted, plaintext_len);
      free(decrypted);
      return strdup("{\"error\":\"Invalid payload size\"}");
    }

    // First 32 bytes = old password hash, last 32 = new password hash
    uint8_t old_hash[32], new_hash[32];
    memcpy(old_hash, decrypted, 32);
    memcpy(new_hash, decrypted + 32, 32);
    mbedtls_platform_zeroize(decrypted, 64);
    free(decrypted);

    // Verify old password by deriving keys and comparing to NVS
    memcpy(keystore.password_hash, old_hash, 32);
    mbedtls_platform_zeroize(old_hash, 32);
    keystore.activated = true;

    if (!keystore.derive_and_verify() || !keystore.verify_public_keys()) {
      keystore.wipe_secrets();
      mbedtls_platform_zeroize(new_hash, 32);
      printf("Password change FAILED: old password incorrect\n");
      return strdup(
          "{\"success\":false,\"error\":\"Current password incorrect\"}");
    }

    printf("Old password verified, deriving new keys...\n");

    // Derive new keys from new password hash
    memcpy(keystore.password_hash, new_hash, 32);
    mbedtls_platform_zeroize(new_hash, 32);
    keystore.activated = true;
    keystore.gen =
        NUM_EXCHANGE_KEYS - 1; // Reset rotation — all keys change with new password

    if (!keystore.derive_and_verify()) {
      keystore.wipe_secrets();
      printf("Password change FAILED: key derivation error\n");
      return strdup(
          "{\"success\":false,\"error\":\"Failed to derive new keys\"}");
    }

    // Store new public keys in NVS (overwrites old ones)
    if (!keystore.store_public_keys()) {
      keystore.wipe_secrets();
      printf("Password change FAILED: NVS write error\n");
      return strdup(
          "{\"success\":false,\"error\":\"Failed to store new keys\"}");
    }

    printf("Password changed successfully — keys rotated\n");
    *success_out = true;
    return strdup(
        "{\"success\":true,\"message\":\"Password changed and keys rotated\"}");
  }

  bool is_unlocked() const { return unlocked; }

  void lock() {
    unlocked = false;
    keystore.wipe_secrets();
  }
};

#endif // ZK_AUTH_H
