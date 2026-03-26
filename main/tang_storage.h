#ifndef TANG_STORAGE_H
#define TANG_STORAGE_H

#include "crypto.h"
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
#include <nvs.h>
#include <nvs_flash.h>

static const char *TAG_STORAGE = "tang_storage";

class TangKeyStore {
public:
  // Signing key (persistent, unencrypted in NVS)
  uint8_t sig_priv[P256_PRIVATE_KEY_SIZE];
  uint8_t sig_pub[P256_PUBLIC_KEY_SIZE];
  bool sig_loaded;

  // Exchange key (private part encrypted at rest, public in NVS)
  uint8_t exc_priv[P256_PRIVATE_KEY_SIZE];
  uint8_t exc_pub[P256_PUBLIC_KEY_SIZE];
  bool exc_pub_loaded;

  TangKeyStore() : sig_loaded(false), exc_pub_loaded(false) {
    memset(sig_priv, 0, sizeof(sig_priv));
    memset(sig_pub, 0, sizeof(sig_pub));
    memset(exc_priv, 0, sizeof(exc_priv));
    memset(exc_pub, 0, sizeof(exc_pub));
  }

  // Check if an encrypted exchange key exists in NVS
  bool has_exchange_key() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = 0;
    err = nvs_get_blob(handle, "exc_enc", nullptr, &len);
    bool found = (err == ESP_OK && len == P256_PRIVATE_KEY_SIZE);
    nvs_close(handle);
    return found;
  }

  // Check if a signing key exists in NVS
  bool has_signing_key() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = 0;
    err = nvs_get_blob(handle, "sig_priv", nullptr, &len);
    bool found = (err == ESP_OK && len == P256_PRIVATE_KEY_SIZE);
    nvs_close(handle);
    return found;
  }

  // Generate signing keypair and persist to NVS (unencrypted)
  bool generate_signing_key() {
    if (!P256::generate_keypair(sig_pub, sig_priv)) {
      ESP_LOGE(TAG_STORAGE, "Failed to generate signing keypair");
      return false;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
      return false;

    bool ok = true;
    ok = ok && (nvs_set_blob(handle, "sig_priv", sig_priv,
                             P256_PRIVATE_KEY_SIZE) == ESP_OK);
    ok = ok && (nvs_set_blob(handle, "sig_pub", sig_pub,
                             P256_PUBLIC_KEY_SIZE) == ESP_OK);
    if (ok)
      ok = (nvs_commit(handle) == ESP_OK);

    nvs_close(handle);

    if (ok) {
      sig_loaded = true;
      ESP_LOGI(TAG_STORAGE, "Signing key generated and saved to NVS");
    }
    return ok;
  }

  // Load signing key from NVS into RAM
  bool load_signing_key() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = P256_PRIVATE_KEY_SIZE;
    err = nvs_get_blob(handle, "sig_priv", sig_priv, &len);
    if (err != ESP_OK || len != P256_PRIVATE_KEY_SIZE) {
      nvs_close(handle);
      return false;
    }

    len = P256_PUBLIC_KEY_SIZE;
    err = nvs_get_blob(handle, "sig_pub", sig_pub, &len);
    if (err != ESP_OK || len != P256_PUBLIC_KEY_SIZE) {
      nvs_close(handle);
      return false;
    }

    nvs_close(handle);
    sig_loaded = true;
    ESP_LOGI(TAG_STORAGE, "Signing key loaded from NVS");
    return true;
  }

  // Load exchange public key from NVS (for /adv before activation)
  bool load_exchange_pub() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = P256_PUBLIC_KEY_SIZE;
    err = nvs_get_blob(handle, "exc_pub", exc_pub, &len);
    nvs_close(handle);

    if (err == ESP_OK && len == P256_PUBLIC_KEY_SIZE) {
      exc_pub_loaded = true;
      ESP_LOGI(TAG_STORAGE, "Exchange public key loaded from NVS");
      return true;
    }
    return false;
  }

  // Generate exchange keypair, encrypt private key with AES-256-GCM, store all
  bool generate_and_encrypt_exchange_key(const uint8_t *aes_key) {
    if (!P256::generate_keypair(exc_pub, exc_priv)) {
      ESP_LOGE(TAG_STORAGE, "Failed to generate exchange keypair");
      return false;
    }

    uint8_t iv[12];
    uint8_t tag[GCM_TAG_SIZE];
    uint8_t encrypted[P256_PRIVATE_KEY_SIZE];

    esp_fill_random(iv, sizeof(iv));
    memcpy(encrypted, exc_priv, P256_PRIVATE_KEY_SIZE);

    if (!AESGCM::encrypt(encrypted, P256_PRIVATE_KEY_SIZE, aes_key, 32, iv,
                         sizeof(iv), nullptr, 0, tag)) {
      ESP_LOGE(TAG_STORAGE, "Failed to encrypt exchange key");
      return false;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
      return false;

    bool ok = true;
    ok = ok && (nvs_set_blob(handle, "exc_pub", exc_pub,
                             P256_PUBLIC_KEY_SIZE) == ESP_OK);
    ok = ok && (nvs_set_blob(handle, "exc_enc", encrypted,
                             P256_PRIVATE_KEY_SIZE) == ESP_OK);
    ok = ok && (nvs_set_blob(handle, "exc_iv", iv, sizeof(iv)) == ESP_OK);
    ok = ok && (nvs_set_blob(handle, "exc_tag", tag, GCM_TAG_SIZE) == ESP_OK);

    if (ok)
      ok = (nvs_commit(handle) == ESP_OK);

    nvs_close(handle);

    if (ok) {
      exc_pub_loaded = true;
      ESP_LOGI(TAG_STORAGE, "Exchange key generated and encrypted in NVS");
    }
    return ok;
  }

  // Decrypt exchange private key from NVS using AES-256-GCM.
  // GCM tag verification acts as implicit password check.
  bool decrypt_exchange_key(const uint8_t *aes_key) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    uint8_t encrypted[P256_PRIVATE_KEY_SIZE];
    uint8_t iv[12];
    uint8_t tag[GCM_TAG_SIZE];
    uint8_t stored_pub[P256_PUBLIC_KEY_SIZE];
    size_t len;

    len = P256_PRIVATE_KEY_SIZE;
    if (nvs_get_blob(handle, "exc_enc", encrypted, &len) != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    len = sizeof(iv);
    if (nvs_get_blob(handle, "exc_iv", iv, &len) != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    len = GCM_TAG_SIZE;
    if (nvs_get_blob(handle, "exc_tag", tag, &len) != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    len = P256_PUBLIC_KEY_SIZE;
    if (nvs_get_blob(handle, "exc_pub", stored_pub, &len) != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    nvs_close(handle);

    // AES-256-GCM decrypt — tag mismatch means wrong password or wrong device
    if (!AESGCM::decrypt(encrypted, P256_PRIVATE_KEY_SIZE, aes_key, 32, iv,
                         sizeof(iv), nullptr, 0, tag)) {
      ESP_LOGW(TAG_STORAGE,
               "GCM tag verification failed — wrong password or wrong device");
      return false;
    }

    memcpy(exc_priv, encrypted, P256_PRIVATE_KEY_SIZE);
    P256::compute_public_key(exc_priv, exc_pub);

    // Verify computed public key matches stored public key
    if (memcmp(exc_pub, stored_pub, P256_PUBLIC_KEY_SIZE) != 0) {
      ESP_LOGE(TAG_STORAGE, "Public key mismatch after decryption");
      memset(exc_priv, 0, P256_PRIVATE_KEY_SIZE);
      return false;
    }

    exc_pub_loaded = true;
    ESP_LOGI(TAG_STORAGE, "Exchange key decrypted and verified");
    return true;
  }
};

#endif // TANG_STORAGE_H
