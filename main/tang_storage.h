#ifndef TANG_STORAGE_H
#define TANG_STORAGE_H

#include <nvs_flash.h>
#include <nvs.h>
#include <esp_log.h>
#include <esp_random.h>
#include <cstring>
#include "crypto.h"
#include "encoding.h"

static const char *TAG_STORAGE = "tang_storage";

// --- Key Storage & Management ---
class TangKeyStore
{
private:
  uint8_t salt[SALT_SIZE];

public:
  // Tang server keys (encrypted at rest, decrypted in memory when active)
  uint8_t sig_priv[P521_PRIVATE_KEY_SIZE];
  uint8_t sig_pub[P521_PUBLIC_KEY_SIZE];
  uint8_t exc_priv[P521_PRIVATE_KEY_SIZE];
  uint8_t exc_pub[P521_PUBLIC_KEY_SIZE];

  // Admin key (persistent)
  uint8_t admin_priv[P521_PRIVATE_KEY_SIZE];
  uint8_t admin_pub[P521_PUBLIC_KEY_SIZE];

  bool is_configured()
  {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
    {
      return false;
    }

    size_t required_size = 0;
    err = nvs_get_blob(handle, "admin_key", nullptr, &required_size);
    bool configured = (err == ESP_OK && required_size == P521_PRIVATE_KEY_SIZE);

    nvs_close(handle);
    return configured;
  }

  bool load_admin_key()
  {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
    {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return false;
    }

    size_t len = P521_PRIVATE_KEY_SIZE;
    err = nvs_get_blob(handle, "admin_key", admin_priv, &len);
    bool success = (err == ESP_OK && len == P521_PRIVATE_KEY_SIZE);

    if (success)
    {
      P521::compute_public_key(admin_priv, admin_pub);

      len = SALT_SIZE;
      nvs_get_blob(handle, "salt", salt, &len);
    }

    nvs_close(handle);
    return success;
  }

  bool save_admin_key()
  {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
    {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return false;
    }

    // Generate and save salt
    esp_fill_random(salt, SALT_SIZE);
    err = nvs_set_blob(handle, "salt", salt, SALT_SIZE);
    if (err != ESP_OK)
    {
      nvs_close(handle);
      return false;
    }

    // Save admin key
    err = nvs_set_blob(handle, "admin_key", admin_priv, P521_PRIVATE_KEY_SIZE);
    if (err != ESP_OK)
    {
      nvs_close(handle);
      return false;
    }

    err = nvs_commit(handle);
    nvs_close(handle);
    return (err == ESP_OK);
  }

  bool encrypt_and_save_tang_keys(const char *password)
  {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
    {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return false;
    }

    // Derive key and encrypt signing key
    uint8_t encrypted_sig[P521_PRIVATE_KEY_SIZE];
    uint8_t sig_tag[GCM_TAG_SIZE];
    memcpy(encrypted_sig, sig_priv, P521_PRIVATE_KEY_SIZE);

    uint8_t key[16], iv[12] = {0};
    if (PBKDF2::derive_key(key, sizeof(key), password, salt, SALT_SIZE, PBKDF2_ITERATIONS) != 0)
    {
      nvs_close(handle);
      return false;
    }

    if (!AESGCM::encrypt(encrypted_sig, P521_PRIVATE_KEY_SIZE, key, sizeof(key),
                         iv, sizeof(iv), nullptr, 0, sig_tag))
    {
      nvs_close(handle);
      return false;
    }

    err = nvs_set_blob(handle, "tang_sig_key", encrypted_sig, P521_PRIVATE_KEY_SIZE);
    if (err != ESP_OK)
    {
      nvs_close(handle);
      return false;
    }

    err = nvs_set_blob(handle, "tang_sig_tag", sig_tag, GCM_TAG_SIZE);
    if (err != ESP_OK)
    {
      nvs_close(handle);
      return false;
    }

    // Encrypt and save exchange key
    uint8_t encrypted_exc[P521_PRIVATE_KEY_SIZE];
    uint8_t exc_tag[GCM_TAG_SIZE];
    memcpy(encrypted_exc, exc_priv, P521_PRIVATE_KEY_SIZE);

    if (!AESGCM::encrypt(encrypted_exc, P521_PRIVATE_KEY_SIZE, key, sizeof(key),
                         iv, sizeof(iv), nullptr, 0, exc_tag))
    {
      nvs_close(handle);
      return false;
    }

    err = nvs_set_blob(handle, "tang_exc_key", encrypted_exc, P521_PRIVATE_KEY_SIZE);
    if (err != ESP_OK)
    {
      nvs_close(handle);
      return false;
    }

    err = nvs_set_blob(handle, "tang_exc_tag", exc_tag, GCM_TAG_SIZE);
    if (err != ESP_OK)
    {
      nvs_close(handle);
      return false;
    }

    err = nvs_commit(handle);
    nvs_close(handle);
    return (err == ESP_OK);
  }

  bool decrypt_and_load_tang_keys(const char *password)
  {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
    {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return false;
    }

    // Load salt
    size_t len = SALT_SIZE;
    err = nvs_get_blob(handle, "salt", salt, &len);
    if (err != ESP_OK || len != SALT_SIZE)
    {
      nvs_close(handle);
      return false;
    }

    // Derive key
    uint8_t key[16], iv[12] = {0};
    if (PBKDF2::derive_key(key, sizeof(key), password, salt, SALT_SIZE, PBKDF2_ITERATIONS) != 0)
    {
      nvs_close(handle);
      return false;
    }

    // Load and decrypt signing key
    uint8_t encrypted_sig[P521_PRIVATE_KEY_SIZE];
    uint8_t sig_tag[GCM_TAG_SIZE];

    len = P521_PRIVATE_KEY_SIZE;
    err = nvs_get_blob(handle, "tang_sig_key", encrypted_sig, &len);
    if (err != ESP_OK || len != P521_PRIVATE_KEY_SIZE)
    {
      nvs_close(handle);
      return false;
    }

    len = GCM_TAG_SIZE;
    err = nvs_get_blob(handle, "tang_sig_tag", sig_tag, &len);
    if (err != ESP_OK || len != GCM_TAG_SIZE)
    {
      nvs_close(handle);
      return false;
    }

    if (!AESGCM::decrypt(encrypted_sig, P521_PRIVATE_KEY_SIZE, key, sizeof(key),
                         iv, sizeof(iv), nullptr, 0, sig_tag))
    {
      nvs_close(handle);
      return false;
    }
    memcpy(sig_priv, encrypted_sig, P521_PRIVATE_KEY_SIZE);
    P521::compute_public_key(sig_priv, sig_pub);

    // Load and decrypt exchange key
    uint8_t encrypted_exc[P521_PRIVATE_KEY_SIZE];
    uint8_t exc_tag[GCM_TAG_SIZE];

    len = P521_PRIVATE_KEY_SIZE;
    err = nvs_get_blob(handle, "tang_exc_key", encrypted_exc, &len);
    if (err != ESP_OK || len != P521_PRIVATE_KEY_SIZE)
    {
      nvs_close(handle);
      return false;
    }

    len = GCM_TAG_SIZE;
    err = nvs_get_blob(handle, "tang_exc_tag", exc_tag, &len);
    if (err != ESP_OK || len != GCM_TAG_SIZE)
    {
      nvs_close(handle);
      return false;
    }

    if (!AESGCM::decrypt(encrypted_exc, P521_PRIVATE_KEY_SIZE, key, sizeof(key),
                         iv, sizeof(iv), nullptr, 0, exc_tag))
    {
      nvs_close(handle);
      return false;
    }
    memcpy(exc_priv, encrypted_exc, P521_PRIVATE_KEY_SIZE);
    P521::compute_public_key(exc_priv, exc_pub);

    nvs_close(handle);
    return true;
  }

  void clear_tang_keys()
  {
    memset(sig_priv, 0, P521_PRIVATE_KEY_SIZE);
    memset(sig_pub, 0, P521_PUBLIC_KEY_SIZE);
    memset(exc_priv, 0, P521_PRIVATE_KEY_SIZE);
    memset(exc_pub, 0, P521_PUBLIC_KEY_SIZE);
  }

  void nuke()
  {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
    {
      ESP_LOGE(TAG_STORAGE, "Failed to open NVS: %s", esp_err_to_name(err));
      return;
    }

    nvs_erase_all(handle);
    nvs_commit(handle);
    nvs_close(handle);
  }
};

#endif // TANG_STORAGE_H
