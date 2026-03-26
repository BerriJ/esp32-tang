#ifndef TANG_STORAGE_H
#define TANG_STORAGE_H

#include "crypto.h"
#include "provision.h"
#include <cstring>
#include <esp_log.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <nvs.h>
#include <nvs_flash.h>

static const char *TAG_STORAGE = "tang_storage";

class TangKeyStore {
public:
  // Public keys (loaded from NVS at boot, available without activation)
  uint8_t sig_pub[P256_PUBLIC_KEY_SIZE];
  bool sig_loaded;

  uint8_t exc_pub[P256_PUBLIC_KEY_SIZE];
  bool exc_pub_loaded;

  // Password hash kept in RAM after activation (PBKDF2 output from browser)
  uint8_t password_hash[32];
  bool activated;

  TangKeyStore() : sig_loaded(false), exc_pub_loaded(false), activated(false) {
    memset(sig_pub, 0, sizeof(sig_pub));
    memset(exc_pub, 0, sizeof(exc_pub));
    memset(password_hash, 0, sizeof(password_hash));
  }

  // Check if public keys exist in NVS (i.e. device was activated before)
  bool has_exchange_key() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = 0;
    err = nvs_get_blob(handle, "exc_pub", nullptr, &len);
    bool found = (err == ESP_OK && len == P256_PUBLIC_KEY_SIZE);
    nvs_close(handle);
    return found;
  }

  bool has_signing_key() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = 0;
    err = nvs_get_blob(handle, "sig_pub", nullptr, &len);
    bool found = (err == ESP_OK && len == P256_PUBLIC_KEY_SIZE);
    nvs_close(handle);
    return found;
  }

  // Derive the master key from password_hash via hardware HMAC, then derive
  // signing and exchange private keys using HMAC-SHA256 with domain separation.
  // Writes results into caller-provided buffers. Wipes intermediates on return.
  bool derive_private_keys(uint8_t *sig_priv_out, uint8_t *exc_priv_out) {
    if (!activated)
      return false;

    uint8_t master_key[32];
    if (!derive_aes_key(password_hash, master_key)) {
      ESP_LOGE(TAG_STORAGE, "Hardware HMAC failed");
      return false;
    }

    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    bool ok = true;

    // sig_priv = HMAC-SHA256(master_key, "tang-signing-key")
    if (sig_priv_out) {
      if (mbedtls_md_hmac(md_info, master_key, 32,
                          (const uint8_t *)"tang-signing-key", 16,
                          sig_priv_out) != 0) {
        ESP_LOGE(TAG_STORAGE, "Failed to derive signing key");
        ok = false;
      }
    }

    // exc_priv = HMAC-SHA256(master_key, "tang-exchange-key")
    if (ok && exc_priv_out) {
      if (mbedtls_md_hmac(md_info, master_key, 32,
                          (const uint8_t *)"tang-exchange-key", 17,
                          exc_priv_out) != 0) {
        ESP_LOGE(TAG_STORAGE, "Failed to derive exchange key");
        ok = false;
      }
    }

    mbedtls_platform_zeroize(master_key, sizeof(master_key));
    return ok;
  }

  // Derive both keys, compute public keys, and verify against NVS.
  // Used during activation to confirm password correctness.
  bool derive_and_verify() {
    uint8_t sig_priv[P256_PRIVATE_KEY_SIZE];
    uint8_t exc_priv[P256_PRIVATE_KEY_SIZE];

    if (!derive_private_keys(sig_priv, exc_priv)) {
      return false;
    }

    // Compute public keys from derived private keys
    uint8_t derived_sig_pub[P256_PUBLIC_KEY_SIZE];
    uint8_t derived_exc_pub[P256_PUBLIC_KEY_SIZE];

    bool ok = P256::compute_public_key(sig_priv, derived_sig_pub) &&
              P256::compute_public_key(exc_priv, derived_exc_pub);

    mbedtls_platform_zeroize(sig_priv, sizeof(sig_priv));
    mbedtls_platform_zeroize(exc_priv, sizeof(exc_priv));

    if (!ok) {
      ESP_LOGE(TAG_STORAGE, "Failed to compute public keys");
      return false;
    }

    // Copy to member public keys (used by /adv)
    memcpy(sig_pub, derived_sig_pub, P256_PUBLIC_KEY_SIZE);
    memcpy(exc_pub, derived_exc_pub, P256_PUBLIC_KEY_SIZE);
    sig_loaded = true;
    exc_pub_loaded = true;

    return true;
  }

  // Store derived public keys to NVS (first-time activation only)
  bool store_public_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
      return false;

    bool ok = true;
    ok = ok && (nvs_set_blob(handle, "sig_pub", sig_pub,
                             P256_PUBLIC_KEY_SIZE) == ESP_OK);
    ok = ok && (nvs_set_blob(handle, "exc_pub", exc_pub,
                             P256_PUBLIC_KEY_SIZE) == ESP_OK);

    if (ok)
      ok = (nvs_commit(handle) == ESP_OK);

    nvs_close(handle);

    if (ok)
      ESP_LOGI(TAG_STORAGE, "Public keys stored in NVS");
    return ok;
  }

  // Verify that derived public keys match the ones stored in NVS.
  // This replaces GCM tag verification as the password check.
  bool verify_public_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    uint8_t stored_sig_pub[P256_PUBLIC_KEY_SIZE];
    uint8_t stored_exc_pub[P256_PUBLIC_KEY_SIZE];
    size_t len;

    len = P256_PUBLIC_KEY_SIZE;
    if (nvs_get_blob(handle, "sig_pub", stored_sig_pub, &len) != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    len = P256_PUBLIC_KEY_SIZE;
    if (nvs_get_blob(handle, "exc_pub", stored_exc_pub, &len) != ESP_OK) {
      nvs_close(handle);
      return false;
    }

    nvs_close(handle);

    if (memcmp(sig_pub, stored_sig_pub, P256_PUBLIC_KEY_SIZE) != 0 ||
        memcmp(exc_pub, stored_exc_pub, P256_PUBLIC_KEY_SIZE) != 0) {
      ESP_LOGW(TAG_STORAGE,
               "Public key mismatch — wrong password or wrong device");
      sig_loaded = false;
      exc_pub_loaded = false;
      return false;
    }

    ESP_LOGI(TAG_STORAGE, "Derived public keys match NVS — password verified");
    return true;
  }

  // Load signing public key from NVS (for reference before activation)
  bool load_signing_pub() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = P256_PUBLIC_KEY_SIZE;
    err = nvs_get_blob(handle, "sig_pub", sig_pub, &len);
    nvs_close(handle);

    if (err == ESP_OK && len == P256_PUBLIC_KEY_SIZE) {
      ESP_LOGI(TAG_STORAGE, "Signing public key loaded from NVS");
      return true;
    }
    return false;
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

  void wipe_secrets() {
    mbedtls_platform_zeroize(password_hash, sizeof(password_hash));
    activated = false;
  }
};

#endif // TANG_STORAGE_H
