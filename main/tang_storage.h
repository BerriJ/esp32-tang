#ifndef TANG_STORAGE_H
#define TANG_STORAGE_H

#include "crypto.h"
#include "encoding.h"
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
#include <nvs.h>
#include <nvs_flash.h>

static const char *TAG_STORAGE = "tang_storage";

// --- Key Storage & Management ---
class TangKeyStore {
private:
  // No longer need salt for password-based encryption

public:
  // Tang server keys (encrypted at rest, decrypted in memory when active)
  uint8_t sig_priv[P256_PRIVATE_KEY_SIZE];
  uint8_t sig_pub[P256_PUBLIC_KEY_SIZE];
  uint8_t exc_priv[P256_PRIVATE_KEY_SIZE];
  uint8_t exc_pub[P256_PUBLIC_KEY_SIZE];

  // Admin key (persistent)
  uint8_t admin_priv[P256_PRIVATE_KEY_SIZE];
  uint8_t admin_pub[P256_PUBLIC_KEY_SIZE];

  bool is_configured() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
      return false;
    }

    size_t required_size = 0;
    err = nvs_get_blob(handle, "admin_key", nullptr, &required_size);
    bool configured = (err == ESP_OK && required_size == P256_PRIVATE_KEY_SIZE);

    nvs_close(handle);
    return configured;
  }

  bool load_admin_key() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return false;
    }

    size_t len = P256_PRIVATE_KEY_SIZE;
    err = nvs_get_blob(handle, "admin_key", admin_priv, &len);
    bool success = (err == ESP_OK && len == P256_PRIVATE_KEY_SIZE);

    if (success) {
      P256::compute_public_key(admin_priv, admin_pub);
    }

    nvs_close(handle);
    return success;
  }

  bool save_admin_key() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return false;
    }

    // Save admin key
    err = nvs_set_blob(handle, "admin_key", admin_priv, P256_PRIVATE_KEY_SIZE);
    if (err != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    err = nvs_commit(handle);
    nvs_close(handle);
    return (err == ESP_OK);
  }

  // Save Tang keys directly to NVS (no encryption)
  bool save_tang_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return false;
    }

    // Save signing key
    err = nvs_set_blob(handle, "tang_sig_key", sig_priv, P256_PRIVATE_KEY_SIZE);
    if (err != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    // Save exchange key
    err = nvs_set_blob(handle, "tang_exc_key", exc_priv, P256_PRIVATE_KEY_SIZE);
    if (err != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    err = nvs_commit(handle);
    nvs_close(handle);
    return (err == ESP_OK);
  }

  // Load Tang keys directly from NVS (no decryption)
  bool load_tang_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return false;
    }

    // Load signing key
    size_t len = P256_PRIVATE_KEY_SIZE;
    err = nvs_get_blob(handle, "tang_sig_key", sig_priv, &len);
    if (err != ESP_OK || len != P256_PRIVATE_KEY_SIZE) {
      nvs_close(handle);
      return false;
    }
    P256::compute_public_key(sig_priv, sig_pub);

    // Load exchange key
    len = P256_PRIVATE_KEY_SIZE;
    err = nvs_get_blob(handle, "tang_exc_key", exc_priv, &len);
    if (err != ESP_OK || len != P256_PRIVATE_KEY_SIZE) {
      nvs_close(handle);
      return false;
    }
    P256::compute_public_key(exc_priv, exc_pub);

    nvs_close(handle);
    return true;
  }

  void clear_tang_keys() {
    memset(sig_priv, 0, P256_PRIVATE_KEY_SIZE);
    memset(sig_pub, 0, P256_PUBLIC_KEY_SIZE);
    memset(exc_priv, 0, P256_PRIVATE_KEY_SIZE);
    memset(exc_pub, 0, P256_PUBLIC_KEY_SIZE);
  }

  void nuke() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return;
    }

    nvs_erase_all(handle);
    nvs_commit(handle);
    nvs_close(handle);
  }
};

#endif // TANG_STORAGE_H
