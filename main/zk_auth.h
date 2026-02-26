#ifndef ZK_AUTH_H
#define ZK_AUTH_H

#include "cryptoauthlib.h"
#include "host/atca_host.h"
#include "mbedtls/sha256.h"
#include <cJSON.h>
#include <esp_mac.h>
#include <esp_system.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <string.h>

// Zero-Knowledge Authentication Module
// Implements Client-Side KDF + ECIES Tunnel for ESP32-C6
// Format: SHA-256 compatible with ATECC608B
//
// Encryption: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
// - Provides confidentiality (CBC) + authenticity (HMAC)
// - Blob format: IV (16 bytes) + Ciphertext (32 bytes) + HMAC (32 bytes) = 80
// bytes
// - HMAC verified BEFORE decryption (prevents padding oracle attacks)

class ZKAuth {
private:
  mbedtls_ecp_group grp;
  mbedtls_mpi device_private_d;
  mbedtls_ecp_point device_public_Q;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  uint8_t device_public_key[65];    // Uncompressed: 0x04 + X(32) + Y(32)
  uint8_t stored_password_hash[32]; // PBKDF2 hash of the correct password

  bool initialized;
  bool password_set;
  bool unlocked = false; // Set to true after successful authentication

  // Convert binary to hex string
  void bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
      sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
  }

  // Convert hex string to binary
  bool hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    if (strlen(hex) != bin_len * 2)
      return false;

    for (size_t i = 0; i < bin_len; i++) {
      if (sscanf(hex + (i * 2), "%2hhx", &bin[i]) != 1) {
        return false;
      }
    }
    return true;
  }

public:
  ZKAuth() : initialized(false), password_set(false), unlocked(false) {
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

  // Initialize the ZK authentication system
  bool init() {
    if (initialized)
      return true;

    // Seed the random number generator
    const char *pers = "zk_auth_esp32";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
      printf("mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
      return false;
    }

    // Setup ECC group for NIST P-256 (secp256r1)
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
      printf("mbedtls_ecp_group_load failed: -0x%04x\n", -ret);
      return false;
    }

    // Generate device keypair
    ret = mbedtls_ecdh_gen_public(&grp, &device_private_d, &device_public_Q,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
      printf("mbedtls_ecdh_gen_public failed: -0x%04x\n", -ret);
      return false;
    }

    // Export public key to uncompressed format (0x04 + X + Y)
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(
        &grp, &device_public_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
        device_public_key, sizeof(device_public_key));
    if (ret != 0 || olen != 65) {
      printf("mbedtls_ecp_point_write_binary failed: -0x%04x\n", -ret);
      return false;
    }

    initialized = true;

    printf("\n=== ZK Authentication Initialized ===\n");
    printf("Public Key: ");
    for (int i = 0; i < 65; i++) {
      printf("%02x", device_public_key[i]);
    }
    printf("\n");
    printf("=====================================\n\n");

    return true;
  }

  // Get device identity (for /api/identity endpoint)
  char *get_identity_json() {
    char pubkey_hex[131]; // 65 bytes * 2 + null
    bin_to_hex(device_public_key, 65, pubkey_hex);

    // Get MAC address to use as salt
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char mac_hex[13]; // 6 bytes * 2 + null
    bin_to_hex(mac, 6, mac_hex);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "pubKey", pubkey_hex);
    cJSON_AddStringToObject(root, "macAddress", mac_hex);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
  }

  void my_host_check_mac(const uint8_t *target_key, const uint8_t *tempkey,
                         const uint8_t *other_data, const uint8_t *sn,
                         uint8_t *out_mac) {
    // See section 11.2 of the ATECC608B datasheet CheckMac message format
    uint8_t msg[88] = {0};
    memcpy(&msg[0], target_key, 32);
    memcpy(&msg[32], tempkey, 32);
    memcpy(&msg[64], &other_data[0], 4);
    memset(&msg[68], 0, 8);
    memcpy(&msg[76], &other_data[4], 3);
    msg[79] = sn[8];
    memcpy(&msg[80], &other_data[7], 4);
    msg[84] = sn[0];
    msg[85] = sn[1];
    memcpy(&msg[86], &other_data[11], 2);
    // Hash the exact 88 bytes using the ESP32's hardware accelerator
    mbedtls_sha256(msg, sizeof(msg), out_mac, 0);
  }

  bool verify_key(const uint8_t *received_key, size_t key_len) {
    (void)key_len;
    if (received_key == NULL)
      return false;

    ATCA_STATUS status;

    bool latch_status = false;
    status = atcab_info_get_latch(&latch_status);

    printf("Device Latch Status: %s (0x%02X)\n",
           latch_status ? "LATCHED" : "UNLATCHED", status);

    uint8_t sn[ATCA_SERIAL_NUM_SIZE] = {0};
    status = atcab_read_serial_number(sn);
    if (status != ATCA_SUCCESS) {
      printf("Failed to read Serial Number\n");
      return false;
    }

    // ==========================================
    // SLOT 13: No Nonce Required
    // ==========================================
    uint8_t challenge_32[32] = {0x11, 0x22, 0x33, 0x44};
    uint8_t slot13_mac[32] = {0};
    uint8_t other_data_13[13] = "TangActivate";

    // Host manually calculates the expected MAC
    my_host_check_mac(received_key, challenge_32, other_data_13, sn,
                      slot13_mac);

    // CRITICAL FIX: CheckMac Mode MUST be 0x00 here
    // Bit 0 = 0 (Use ClientChal directly)
    // Bit 1 = 0 (Use the password stored in Slot 13)
    status = atcab_checkmac(0x00, 13, challenge_32, slot13_mac, other_data_13);
    printf("Slot 13 CheckMac: %s (0x%02X)\n",
           (status == ATCA_SUCCESS) ? "PASSED" : "FAILED", status);

    // ==========================================
    // SLOT 10: Requires Nonce
    // ==========================================
    uint8_t nonce_num_in[20] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t rand_out[32] = {0};
    uint8_t slot10_mac[32] = {0};
    uint8_t other_data_10[13] = {0};
    struct atca_temp_key temp_key;
    memset(&temp_key, 0, sizeof(temp_key));

    status = atcab_nonce_rand(nonce_num_in, rand_out);

    // Print the nonce output for debugging
    printf("Nonce RandOut: ");
    for (int i = 0; i < 32; i++)
      printf("%02x", rand_out[i]);
    printf("\n");

    if (status != ATCA_SUCCESS) {
      printf("Slot 10 Nonce failed: 0x%02X\n", status);
    } else {
      // Compute the TempKey on the ESP32
      struct atca_nonce_in_out nonce_params;
      memset(&nonce_params, 0, sizeof(nonce_params));
      nonce_params.mode = 0x00;
      nonce_params.num_in = nonce_num_in;
      nonce_params.rand_out = rand_out;
      nonce_params.temp_key = &temp_key;

      atcah_nonce(&nonce_params);

      // Print temp_key for debugging
      printf("TempKey: ");
      for (int i = 0; i < 32; i++)
        printf("%02x", temp_key.value[i]);
      printf("\n");

      // Host calculates MAC using the calculated TempKey as the challenge
      my_host_check_mac(received_key, temp_key.value, other_data_10, sn,
                        slot10_mac);

      // CRITICAL FIX: CheckMac Mode MUST be 0x01 here
      // Bit 0 = 1 (Use TempKey as the Challenge)
      // Bit 1 = 0 (Use the password stored in Slot 10)
      // Bit 2 = 0 (TempKey.SourceFlag is random)
      status = atcab_checkmac(0x01, 10, NULL, slot10_mac, other_data_10);
      if (status == ATCA_SUCCESS) {
        printf("Slot 10 CheckMac: PASSED\n");
      } else if (status == (ATCA_STATUS)ATCA_CHECKMAC_VERIFY_FAILED) {
        // 0xD1 (-47 / 0xFFFFFFD1) see atca_status.h
        printf("Slot 10 CheckMac: ACCESS DENIED (Wrong Password)\n");
      } else {
        printf("Slot 10 CheckMac: HARDWARE ERROR (0x%02X)\n", status);
      }
    }
    status = atcab_info_set_latch(true);

    if (status == ATCA_SUCCESS) {
      printf("Device latched successfully\n");
    } else {
      printf("Failed to latch device: 0x%02X\n", status);
    }

    atcab_info_get_latch(&latch_status);
    printf("Device Latch Status after setting: %s (0x%02X)\n",
           latch_status ? "LATCHED" : "UNLATCHED", status);

    return (status == ATCA_SUCCESS);
  }

  // Process unlock request with ECIES tunnel
  char *process_unlock(const char *json_payload, bool *success_out) {
    *success_out = false;

    if (!initialized) {
      return strdup("{\"error\":\"Not initialized\"}");
    }

    // Parse JSON
    cJSON *doc = cJSON_Parse(json_payload);
    if (doc == NULL) {
      const char *error_ptr = cJSON_GetErrorPtr();
      if (error_ptr != NULL) {
        printf("JSON parse error before: %s\n", error_ptr);
      }
      return strdup("{\"error\":\"Invalid JSON\"}");
    }

    cJSON *client_pub_item = cJSON_GetObjectItem(doc, "clientPub");
    cJSON *encrypted_blob_item = cJSON_GetObjectItem(doc, "blob");

    const char *client_pub_hex = NULL;
    const char *encrypted_blob_hex = NULL;

    if (cJSON_IsString(client_pub_item))
      client_pub_hex = client_pub_item->valuestring;
    if (cJSON_IsString(encrypted_blob_item))
      encrypted_blob_hex = encrypted_blob_item->valuestring;

    if (!client_pub_hex || !encrypted_blob_hex) {
      cJSON_Delete(doc);
      return strdup("{\"error\":\"Missing required fields\"}");
    }

    printf("\n=== Processing Unlock Request ===\n");
    printf("Client Public Key: %s\n", client_pub_hex);
    printf("Encrypted Blob: %s\n", encrypted_blob_hex);

    // Convert client public key from hex
    size_t client_pub_len = strlen(client_pub_hex) / 2;
    uint8_t *client_pub_bin = (uint8_t *)malloc(client_pub_len);
    if (!hex_to_bin(client_pub_hex, client_pub_bin, client_pub_len)) {
      free(client_pub_bin);
      cJSON_Delete(doc);
      return strdup("{\"error\":\"Invalid client public key format\"}");
    }

    // Parse client public key point
    mbedtls_ecp_point client_point;
    mbedtls_ecp_point_init(&client_point);

    int ret = mbedtls_ecp_point_read_binary(&grp, &client_point, client_pub_bin,
                                            client_pub_len);
    free(client_pub_bin);

    if (ret != 0) {
      mbedtls_ecp_point_free(&client_point);
      cJSON_Delete(doc);
      printf("Failed to parse client key: -0x%04x\n", -ret);
      return strdup("{\"error\":\"Invalid client public key\"}");
    }

    // Compute shared secret using ECDH
    mbedtls_mpi shared_secret_mpi;
    mbedtls_mpi_init(&shared_secret_mpi);

    ret = mbedtls_ecdh_compute_shared(&grp, &shared_secret_mpi, &client_point,
                                      &device_private_d,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ecp_point_free(&client_point);

    if (ret != 0) {
      mbedtls_mpi_free(&shared_secret_mpi);
      cJSON_Delete(doc);
      printf("ECDH computation failed: -0x%04x\n", -ret);
      return strdup("{\"error\":\"ECDH failed\"}");
    }

    // Export shared secret to binary
    uint8_t shared_secret_raw[32];
    ret = mbedtls_mpi_write_binary(&shared_secret_mpi, shared_secret_raw, 32);
    mbedtls_mpi_free(&shared_secret_mpi);

    if (ret != 0) {
      cJSON_Delete(doc);
      printf("Shared secret export failed: -0x%04x\n", -ret);
      return strdup("{\"error\":\"Shared secret export failed\"}");
    }

    printf("Shared Secret (raw): ");
    for (int i = 0; i < 32; i++)
      printf("%02x", shared_secret_raw[i]);
    printf("\n");

    // Derive separate keys for encryption and authentication
    // This prevents key reuse vulnerabilities
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    // Encryption key: SHA256("encryption" || shared_secret)
    uint8_t enc_key[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, (const uint8_t *)"encryption", 10);
    mbedtls_md_update(&md_ctx, shared_secret_raw, 32);
    mbedtls_md_finish(&md_ctx, enc_key);

    // MAC key: SHA256("authentication" || shared_secret)
    uint8_t mac_key[32];
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, (const uint8_t *)"authentication", 14);
    mbedtls_md_update(&md_ctx, shared_secret_raw, 32);
    mbedtls_md_finish(&md_ctx, mac_key);
    mbedtls_md_free(&md_ctx);

    printf("Encryption Key: ");
    for (int i = 0; i < 32; i++)
      printf("%02x", enc_key[i]);
    printf("\n");

    printf("MAC Key: ");
    for (int i = 0; i < 32; i++)
      printf("%02x", mac_key[i]);
    printf("\n");

    // Securely wipe the raw shared secret
    memset(shared_secret_raw, 0, 32);

    // Convert encrypted blob from hex
    // Format: IV (16 bytes) + Ciphertext (32 bytes) + HMAC (32 bytes) = 80
    // bytes
    size_t encrypted_len = strlen(encrypted_blob_hex) / 2;
    uint8_t *encrypted_blob = (uint8_t *)malloc(encrypted_len);
    if (!hex_to_bin(encrypted_blob_hex, encrypted_blob, encrypted_len)) {
      free(encrypted_blob);
      memset(enc_key, 0, 32);
      memset(mac_key, 0, 32);
      cJSON_Delete(doc);
      return strdup("{\"error\":\"Invalid blob format\"}");
    }

    // Verify blob length: IV(16) + Ciphertext(32) + HMAC(32) = 80 bytes
    if (encrypted_len != 80) {
      free(encrypted_blob);
      memset(enc_key, 0, 32);
      memset(mac_key, 0, 32);
      cJSON_Delete(doc);
      printf("Expected 80 bytes, got %d\n", encrypted_len);
      return strdup("{\"error\":\"Invalid blob length\"}");
    }

    // Extract components from blob
    uint8_t *iv = encrypted_blob;                 // First 16 bytes
    uint8_t *ciphertext = encrypted_blob + 16;    // Next 32 bytes
    uint8_t *received_hmac = encrypted_blob + 48; // Last 32 bytes

    printf("IV: ");
    for (int i = 0; i < 16; i++)
      printf("%02x", iv[i]);
    printf("\n");

    printf("Received HMAC: ");
    for (int i = 0; i < 32; i++)
      printf("%02x", received_hmac[i]);
    printf("\n");

    // ⚠️ CRITICAL: Verify HMAC BEFORE decrypting
    // This prevents padding oracle attacks and ensures data authenticity
    uint8_t computed_hmac[32];
    ret = mbedtls_md_hmac(md_info, mac_key, 32, encrypted_blob, 48,
                          computed_hmac);

    if (ret != 0) {
      free(encrypted_blob);
      memset(enc_key, 0, 32);
      memset(mac_key, 0, 32);
      cJSON_Delete(doc);
      printf("HMAC computation failed: -0x%04x\n", -ret);
      return strdup("{\"error\":\"HMAC computation failed\"}");
    }

    printf("Computed HMAC: ");
    for (int i = 0; i < 32; i++)
      printf("%02x", computed_hmac[i]);
    printf("\n");

    // Constant-time comparison to prevent timing attacks
    int hmac_result = 0;
    for (int i = 0; i < 32; i++) {
      hmac_result |= received_hmac[i] ^ computed_hmac[i];
    }

    // Wipe MAC key after verification
    memset(mac_key, 0, 32);

    if (hmac_result != 0) {
      free(encrypted_blob);
      memset(enc_key, 0, 32);
      cJSON_Delete(doc);
      printf("❌ HMAC verification FAILED - ciphertext was modified or wrong "
             "key!\n");
      return strdup("{\"error\":\"Authentication failed - data tampered or "
                    "wrong password\"}");
    }

    printf("✅ HMAC verified - data is authentic\n");

    // Now safe to decrypt (HMAC passed)
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_dec(&aes, enc_key, 256);
    if (ret != 0) {
      mbedtls_aes_free(&aes);
      free(encrypted_blob);
      memset(enc_key, 0, 32);
      cJSON_Delete(doc);
      printf("AES setkey failed: -0x%04x\n", -ret);
      return strdup("{\"error\":\"AES setup failed\"}");
    }

    uint8_t *decrypted_data = (uint8_t *)malloc(32);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16); // CBC mode modifies IV

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT,
                                32,              // data length
                                iv_copy,         // IV (will be modified)
                                ciphertext,      // input
                                decrypted_data); // output

    mbedtls_aes_free(&aes);
    free(encrypted_blob);
    memset(enc_key, 0, 32);

    if (ret != 0) {
      free(decrypted_data);
      cJSON_Delete(doc);
      printf("AES decrypt failed: -0x%04x\n", -ret);
      return strdup("{\"error\":\"Decryption failed\"}");
    }

    // Extract the derived key (PBKDF2 hash, 32 bytes)
    printf("\n=== DECRYPTED DERIVED KEY ===\n");
    printf("Key (hex): ");
    for (size_t i = 0; i < 32; i++) {
      printf("%02x", decrypted_data[i]);
    }
    printf("\n");
    printf("=============================\n\n");

    // Verify the decrypted key against stored password hash
    bool verification_result = verify_key(decrypted_data, 32);

    cJSON *resp_doc = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp_doc, "success", verification_result);

    if (verification_result) {
      printf("✅ Password verification SUCCESSFUL\n");
      unlocked = true;
      cJSON_AddStringToObject(resp_doc, "message", "Unlock successful");
    } else {
      printf("❌ Password verification FAILED\n");
      unlocked = false;
      cJSON_AddStringToObject(resp_doc, "error", "Invalid password");
    }

    char *response_str = cJSON_PrintUnformatted(resp_doc);
    cJSON_Delete(resp_doc);
    cJSON_Delete(doc);

    // Securely wipe decrypted data
    memset(decrypted_data, 0, 32);
    free(decrypted_data);

    *success_out = verification_result;
    return response_str;
  }

  // Check if device is unlocked
  bool is_unlocked() const { return unlocked; }

  // Lock the device
  void lock() { unlocked = false; }
};

#endif // ZK_AUTH_H
