#ifndef ZK_AUTH_H
#define ZK_AUTH_H

#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pkcs5.h>
#include <esp_system.h>
#include <esp_mac.h>
#include <ArduinoJson.h>

// Zero-Knowledge Authentication Module
// Implements Client-Side KDF + ECIES Tunnel for ESP32-C6
// Format: SHA-256 compatible with ATECC608B

class ZKAuth
{
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
  void bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex)
  {
    for (size_t i = 0; i < bin_len; i++)
    {
      sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
  }

  // Convert hex string to binary
  bool hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len)
  {
    if (strlen(hex) != bin_len * 2)
      return false;

    for (size_t i = 0; i < bin_len; i++)
    {
      if (sscanf(hex + (i * 2), "%2hhx", &bin[i]) != 1)
      {
        return false;
      }
    }
    return true;
  }

public:
  ZKAuth() : initialized(false), password_set(false), unlocked(false)
  {
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&device_private_d);
    mbedtls_ecp_point_init(&device_public_Q);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
  }

  ~ZKAuth()
  {
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&device_private_d);
    mbedtls_ecp_point_free(&device_public_Q);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
  }

  // Initialize the ZK authentication system
  bool init()
  {
    if (initialized)
      return true;

    // Seed the random number generator
    const char *pers = "zk_auth_esp32";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                    &entropy,
                                    (const unsigned char *)pers,
                                    strlen(pers));
    if (ret != 0)
    {
      Serial.printf("mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
      return false;
    }

    // Setup ECC group for NIST P-256 (secp256r1)
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0)
    {
      Serial.printf("mbedtls_ecp_group_load failed: -0x%04x\n", -ret);
      return false;
    }

    // Generate device keypair
    ret = mbedtls_ecdh_gen_public(&grp,
                                  &device_private_d,
                                  &device_public_Q,
                                  mbedtls_ctr_drbg_random,
                                  &ctr_drbg);
    if (ret != 0)
    {
      Serial.printf("mbedtls_ecdh_gen_public failed: -0x%04x\n", -ret);
      return false;
    }

    // Export public key to uncompressed format (0x04 + X + Y)
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&grp,
                                         &device_public_Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen,
                                         device_public_key,
                                         sizeof(device_public_key));
    if (ret != 0 || olen != 65)
    {
      Serial.printf("mbedtls_ecp_point_write_binary failed: -0x%04x\n", -ret);
      return false;
    }

    initialized = true;

    Serial.println("\n=== ZK Authentication Initialized ===");
    Serial.print("Public Key: ");
    for (int i = 0; i < 65; i++)
    {
      Serial.printf("%02x", device_public_key[i]);
    }
    Serial.println();
    Serial.println("=====================================\n");

    return true;
  }

  // Get device identity (for /api/identity endpoint)
  void get_identity_json(String &json_out)
  {
    StaticJsonDocument<512> doc;

    char pubkey_hex[131]; // 65 bytes * 2 + null
    bin_to_hex(device_public_key, 65, pubkey_hex);

    doc["pubKey"] = pubkey_hex;

    // Get MAC address to use as salt
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char mac_hex[13]; // 6 bytes * 2 + null
    bin_to_hex(mac, 6, mac_hex);
    doc["macAddress"] = mac_hex;

    serializeJson(doc, json_out);
  }

  // ⚠️ TESTING ONLY - DO NOT USE IN PRODUCTION ⚠️
  // This function accepts a plaintext password and computes PBKDF2 on the device.
  // This violates the zero-knowledge principle!
  // In production, use an activation endpoint that receives the pre-computed hash
  // from the browser, so the device never sees the plaintext password.
  // Must match browser: PBKDF2(password, MAC_ADDRESS, 10000, SHA256)
  bool set_password(const char *password)
  {
    if (!initialized)
    {
      Serial.println("ZKAuth not initialized");
      return false;
    }

    // ⚠️ TESTING ONLY: Computing PBKDF2 on device
    // In production, this should be done client-side and only the hash sent to device

    // Use MAC address as salt
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_setup(&md_ctx, md_info, 1); // 1 = HMAC

    if (ret != 0)
    {
      mbedtls_md_free(&md_ctx);
      Serial.printf("mbedtls_md_setup failed: -0x%04x\n", -ret);
      return false;
    }

    ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                        (const unsigned char *)password, strlen(password),
                                        mac, 6, // Use MAC address as salt
                                        10000,  // iterations (must match browser)
                                        32,     // key length
                                        stored_password_hash);

    mbedtls_md_free(&md_ctx);

    if (ret != 0)
    {
      Serial.printf("mbedtls_pkcs5_pbkdf2_hmac_ext failed: -0x%04x\n", -ret);
      return false;
    }

    password_set = true;

    Serial.println("\n=== Password Set ===");
    Serial.print("Salt (MAC Address): ");
    for (int i = 0; i < 6; i++)
      Serial.printf("%02x", mac[i]);
    Serial.println();
    Serial.print("Stored PBKDF2 Hash: ");
    for (int i = 0; i < 32; i++)
      Serial.printf("%02x", stored_password_hash[i]);
    Serial.println("\n===================\n");

    return true;
  }

  // Verify a decrypted key against the stored password hash
  bool verify_key(const uint8_t *received_key, size_t key_len)
  {
    if (!password_set)
    {
      Serial.println("No password set for verification");
      return false;
    }

    if (key_len != 32)
    {
      Serial.println("Invalid key length");
      return false;
    }

    // Constant-time comparison to prevent timing attacks
    int result = 0;
    for (size_t i = 0; i < 32; i++)
    {
      result |= stored_password_hash[i] ^ received_key[i];
    }

    return (result == 0);
  }

  // Process unlock request with ECIES tunnel
  bool process_unlock(const char *json_payload, String &response)
  {
    if (!initialized)
    {
      response = "{\"error\":\"Not initialized\"}";
      return false;
    }

    // Parse JSON
    StaticJsonDocument<1024> doc;
    DeserializationError error = deserializeJson(doc, json_payload);

    if (error)
    {
      response = "{\"error\":\"Invalid JSON\"}";
      Serial.printf("JSON parse error: %s\n", error.c_str());
      return false;
    }

    const char *client_pub_hex = doc["clientPub"];
    const char *encrypted_blob_hex = doc["blob"];

    if (!client_pub_hex || !encrypted_blob_hex)
    {
      response = "{\"error\":\"Missing required fields\"}";
      return false;
    }

    Serial.println("\n=== Processing Unlock Request ===");
    Serial.printf("Client Public Key: %s\n", client_pub_hex);
    Serial.printf("Encrypted Blob: %s\n", encrypted_blob_hex);

    // Convert client public key from hex
    size_t client_pub_len = strlen(client_pub_hex) / 2;
    uint8_t *client_pub_bin = (uint8_t *)malloc(client_pub_len);
    if (!hex_to_bin(client_pub_hex, client_pub_bin, client_pub_len))
    {
      free(client_pub_bin);
      response = "{\"error\":\"Invalid client public key format\"}";
      return false;
    }

    // Parse client public key point
    mbedtls_ecp_point client_point;
    mbedtls_ecp_point_init(&client_point);

    int ret = mbedtls_ecp_point_read_binary(&grp,
                                            &client_point,
                                            client_pub_bin,
                                            client_pub_len);
    free(client_pub_bin);

    if (ret != 0)
    {
      mbedtls_ecp_point_free(&client_point);
      response = "{\"error\":\"Invalid client public key\"}";
      Serial.printf("Failed to parse client key: -0x%04x\n", -ret);
      return false;
    }

    // Compute shared secret using ECDH
    mbedtls_mpi shared_secret_mpi;
    mbedtls_mpi_init(&shared_secret_mpi);

    ret = mbedtls_ecdh_compute_shared(&grp,
                                      &shared_secret_mpi,
                                      &client_point,
                                      &device_private_d,
                                      mbedtls_ctr_drbg_random,
                                      &ctr_drbg);

    mbedtls_ecp_point_free(&client_point);

    if (ret != 0)
    {
      mbedtls_mpi_free(&shared_secret_mpi);
      response = "{\"error\":\"ECDH failed\"}";
      Serial.printf("ECDH computation failed: -0x%04x\n", -ret);
      return false;
    }

    // Export shared secret to binary
    uint8_t shared_secret_raw[32];
    ret = mbedtls_mpi_write_binary(&shared_secret_mpi, shared_secret_raw, 32);
    mbedtls_mpi_free(&shared_secret_mpi);

    if (ret != 0)
    {
      response = "{\"error\":\"Failed to export shared secret\"}";
      return false;
    }

    // Hash the shared secret with SHA-256 to derive AES key
    uint8_t aes_key[32];
    mbedtls_sha256(shared_secret_raw, 32, aes_key, 0);

    Serial.print("Shared Secret (raw): ");
    for (int i = 0; i < 32; i++)
      Serial.printf("%02x", shared_secret_raw[i]);
    Serial.println();

    Serial.print("AES Key (SHA-256): ");
    for (int i = 0; i < 32; i++)
      Serial.printf("%02x", aes_key[i]);
    Serial.println();

    // Securely wipe the raw shared secret
    memset(shared_secret_raw, 0, 32);

    // Convert encrypted blob from hex
    size_t encrypted_len = strlen(encrypted_blob_hex) / 2;
    uint8_t *encrypted_blob = (uint8_t *)malloc(encrypted_len);
    if (!hex_to_bin(encrypted_blob_hex, encrypted_blob, encrypted_len))
    {
      free(encrypted_blob);
      memset(aes_key, 0, 32);
      response = "{\"error\":\"Invalid encrypted blob format\"}";
      return false;
    }

    // Decrypt using AES-256-CBC with zero IV (to match browser)
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_dec(&aes, aes_key, 256);
    if (ret != 0)
    {
      mbedtls_aes_free(&aes);
      free(encrypted_blob);
      memset(aes_key, 0, 32);
      response = "{\"error\":\"AES init failed\"}";
      return false;
    }

    // Zero IV for CBC mode
    uint8_t iv[16] = {0};

    // Decrypt using CBC mode
    uint8_t *decrypted_data = (uint8_t *)malloc(encrypted_len);
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encrypted_len,
                                iv, encrypted_blob, decrypted_data);

    if (ret != 0)
    {
      mbedtls_aes_free(&aes);
      free(encrypted_blob);
      free(decrypted_data);
      memset(aes_key, 0, 32);
      response = "{\"error\":\"Decryption failed\"}";
      Serial.printf("AES decrypt failed: -0x%04x\n", -ret);
      return false;
    }

    mbedtls_aes_free(&aes);
    free(encrypted_blob);
    memset(aes_key, 0, 32);

    // Extract the derived key (PBKDF2 hash, 32 bytes)
    Serial.println("\n=== DECRYPTED DERIVED KEY ===");
    Serial.print("Key (hex): ");
    for (size_t i = 0; i < 32 && i < encrypted_len; i++)
    {
      Serial.printf("%02x", decrypted_data[i]);
    }
    Serial.println();
    Serial.println("=============================\n");

    // Verify the decrypted key against stored password hash
    bool verification_result = verify_key(decrypted_data, 32);

    StaticJsonDocument<256> resp_doc;

    if (verification_result)
    {
      Serial.println("✅ Password verification SUCCESSFUL");
      unlocked = true; // Set unlocked state
      resp_doc["success"] = true;
      resp_doc["message"] = "Unlock successful";
    }
    else
    {
      Serial.println("❌ Password verification FAILED");
      resp_doc["success"] = false;
      resp_doc["error"] = "Invalid password";
    }

    serializeJson(resp_doc, response);

    // Securely wipe decrypted data
    memset(decrypted_data, 0, encrypted_len);
    free(decrypted_data);

    return verification_result;
  }

  // Check if device is unlocked
  bool is_unlocked() const { return unlocked; }

  // Lock the device
  void lock() { unlocked = false; }
};

#endif // ZK_AUTH_H
