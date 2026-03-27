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
#include <sdkconfig.h>

static const char *TAG_STORAGE = "tang_storage";

const int NUM_EXCHANGE_KEYS = CONFIG_NUM_EXCHANGE_KEYS;

class TangKeyStore {
public:
  // Public keys (loaded from NVS at boot, available without activation)
  uint8_t sig_pub[P256_PUBLIC_KEY_SIZE];
  bool sig_loaded;

  // Exchange public keys stored in NUM_EXCHANGE_KEYS slots (ring buffer indexed
  // by gen % NUM_EXCHANGE_KEYS)
  uint8_t exc_pub[NUM_EXCHANGE_KEYS][P256_PUBLIC_KEY_SIZE];
  bool exc_pub_loaded;

  // Generation counter (monotonically increasing, newest key).
  // Active keys are: gen, gen-1, ... gen-(NUM_EXCHANGE_KEYS-1).
  // Slot = generation % NUM_EXCHANGE_KEYS.
  // Starts at NUM_EXCHANGE_KEYS-1 so first activation produces all keys.
  unsigned int gen;

  // Password hash kept in RAM after activation (PBKDF2 output from browser)
  uint8_t password_hash[32];
  bool activated;

  TangKeyStore()
      : sig_loaded(false), exc_pub_loaded(false),
        gen(NUM_EXCHANGE_KEYS - 1), activated(false) {
    memset(sig_pub, 0, sizeof(sig_pub));
    memset(exc_pub, 0, sizeof(exc_pub));
    memset(password_hash, 0, sizeof(password_hash));
  }

  // Slot index (0..2) for a given generation number
  static int slot(unsigned int generation) {
    return (int)(generation % NUM_EXCHANGE_KEYS);
  }

  // NVS key name for a slot
  static const char *exc_pub_nvs_key(int s) {
    static char buf[16];
    snprintf(buf, sizeof(buf), "exc_pub_%d", s);
    return buf;
  }

  // Check if public keys exist in NVS (i.e. device was activated before)
  bool has_exchange_key() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = 0;
    err = nvs_get_blob(handle, "exc_pub_0", nullptr, &len);
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

  // Derive signing private key from password hash via hardware HMAC.
  bool derive_signing_key(uint8_t *sig_priv_out) {
    if (!activated)
      return false;

    uint8_t master_key[32];
    if (!derive_aes_key(password_hash, master_key)) {
      ESP_LOGE(TAG_STORAGE, "Hardware HMAC failed");
      return false;
    }

    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    // sig_priv = HMAC-SHA256(master_key, "tang-signing-key")
    int ret =
        mbedtls_md_hmac(md_info, master_key, 32,
                        (const uint8_t *)"tang-signing-key", 16, sig_priv_out);
    mbedtls_platform_zeroize(master_key, sizeof(master_key));

    if (ret != 0) {
      ESP_LOGE(TAG_STORAGE, "Failed to derive signing key");
      return false;
    }
    return true;
  }

  // Derive exchange private key for a specific generation (any counter value).
  bool derive_exchange_key(unsigned int generation, uint8_t *exc_priv_out) {
    if (!activated)
      return false;

    uint8_t master_key[32];
    if (!derive_aes_key(password_hash, master_key)) {
      ESP_LOGE(TAG_STORAGE, "Hardware HMAC failed");
      return false;
    }

    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    // exc_priv = HMAC-SHA256(master_key, "tang-exchange-key-{gen}")
    char info[32];
    int info_len =
        snprintf(info, sizeof(info), "tang-exchange-key-%u", generation);

    int ret = mbedtls_md_hmac(md_info, master_key, 32, (const uint8_t *)info,
                              info_len, exc_priv_out);
    mbedtls_platform_zeroize(master_key, sizeof(master_key));

    if (ret != 0) {
      ESP_LOGE(TAG_STORAGE, "Failed to derive exchange key gen %u", generation);
      return false;
    }
    return true;
  }

  // Derive all keys, compute public keys.
  // Derives signing key + exchange keys for gen, gen-1, gen-2.
  bool derive_and_verify() {
    // Derive signing key and compute public key
    uint8_t sig_priv[P256_PRIVATE_KEY_SIZE];
    if (!derive_signing_key(sig_priv))
      return false;

    bool ok = P256::compute_public_key(sig_priv, sig_pub);
    mbedtls_platform_zeroize(sig_priv, sizeof(sig_priv));

    if (!ok) {
      ESP_LOGE(TAG_STORAGE, "Failed to compute signing public key");
      return false;
    }
    sig_loaded = true;

    // Derive all active exchange keys: gen, gen-1, ... gen-(NUM_EXCHANGE_KEYS-1)
    for (int offset = 0; offset < NUM_EXCHANGE_KEYS; offset++) {
      unsigned int g = gen - offset;
      int s = slot(g);

      uint8_t exc_priv[P256_PRIVATE_KEY_SIZE];
      if (!derive_exchange_key(g, exc_priv))
        return false;

      ok = P256::compute_public_key(exc_priv, exc_pub[s]);
      mbedtls_platform_zeroize(exc_priv, sizeof(exc_priv));

      if (!ok) {
        ESP_LOGE(TAG_STORAGE,
                 "Failed to compute exchange public key gen %u (slot %d)", g,
                 s);
        return false;
      }
    }

    exc_pub_loaded = true;
    return true;
  }

  // Store all public keys + gen counter to NVS
  bool store_public_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
      return false;

    bool ok = true;
    ok = ok && (nvs_set_blob(handle, "sig_pub", sig_pub,
                             P256_PUBLIC_KEY_SIZE) == ESP_OK);

    for (int s = 0; s < NUM_EXCHANGE_KEYS && ok; s++) {
      ok = ok && (nvs_set_blob(handle, exc_pub_nvs_key(s), exc_pub[s],
                               P256_PUBLIC_KEY_SIZE) == ESP_OK);
    }

    ok = ok && (nvs_set_u32(handle, "gen", (uint32_t)gen) == ESP_OK);

    if (ok)
      ok = (nvs_commit(handle) == ESP_OK);

    nvs_close(handle);

    if (ok)
      ESP_LOGI(TAG_STORAGE, "Public keys stored in NVS (gen %u, %d active keys)",
               gen, NUM_EXCHANGE_KEYS);
    return ok;
  }

  // Verify that derived public keys match the ones stored in NVS.
  bool verify_public_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    // Verify signing key
    uint8_t stored[P256_PUBLIC_KEY_SIZE];
    size_t len = P256_PUBLIC_KEY_SIZE;
    if (nvs_get_blob(handle, "sig_pub", stored, &len) != ESP_OK ||
        memcmp(sig_pub, stored, P256_PUBLIC_KEY_SIZE) != 0) {
      nvs_close(handle);
      ESP_LOGW(TAG_STORAGE,
               "Signing key mismatch — wrong password or wrong device");
      sig_loaded = false;
      exc_pub_loaded = false;
      return false;
    }

    // Verify all exchange key slots
    for (int s = 0; s < NUM_EXCHANGE_KEYS; s++) {
      len = P256_PUBLIC_KEY_SIZE;
      if (nvs_get_blob(handle, exc_pub_nvs_key(s), stored, &len) != ESP_OK ||
          memcmp(exc_pub[s], stored, P256_PUBLIC_KEY_SIZE) != 0) {
        nvs_close(handle);
        ESP_LOGW(TAG_STORAGE, "Exchange key slot %d mismatch", s);
        sig_loaded = false;
        exc_pub_loaded = false;
        return false;
      }
    }

    nvs_close(handle);
    ESP_LOGI(TAG_STORAGE,
             "All derived public keys match NVS — password verified");
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

  // Load all exchange public keys and generation counter from NVS
  bool load_exchange_pubs() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    for (int s = 0; s < NUM_EXCHANGE_KEYS; s++) {
      size_t len = P256_PUBLIC_KEY_SIZE;
      if (nvs_get_blob(handle, exc_pub_nvs_key(s), exc_pub[s], &len) !=
              ESP_OK ||
          len != P256_PUBLIC_KEY_SIZE) {
        nvs_close(handle);
        return false;
      }
    }

    uint32_t stored_gen = NUM_EXCHANGE_KEYS - 1;
    if (nvs_get_u32(handle, "gen", &stored_gen) == ESP_OK) {
      gen = (unsigned int)stored_gen;
    }

    nvs_close(handle);
    exc_pub_loaded = true;
    ESP_LOGI(TAG_STORAGE,
             "Exchange public keys loaded (gen %u, %d active keys)", gen,
             NUM_EXCHANGE_KEYS);
    return true;
  }

  // Rotate: increment gen, derive new key, overwrite oldest slot in NVS.
  // Requires activation (password hash must be in RAM).
  bool rotate() {
    if (!activated)
      return false;

    unsigned int new_gen = gen + 1;
    int s = slot(new_gen);

    // Derive new exchange key and compute its public key
    uint8_t exc_priv[P256_PRIVATE_KEY_SIZE];
    if (!derive_exchange_key(new_gen, exc_priv))
      return false;

    bool ok = P256::compute_public_key(exc_priv, exc_pub[s]);
    mbedtls_platform_zeroize(exc_priv, sizeof(exc_priv));

    if (!ok) {
      ESP_LOGE(TAG_STORAGE, "Failed to compute public key for gen %u", new_gen);
      return false;
    }

    // Persist the new slot and updated gen counter
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
      return false;

    ok = (nvs_set_blob(handle, exc_pub_nvs_key(s), exc_pub[s],
                        P256_PUBLIC_KEY_SIZE) == ESP_OK) &&
         (nvs_set_u32(handle, "gen", (uint32_t)new_gen) == ESP_OK) &&
         (nvs_commit(handle) == ESP_OK);
    nvs_close(handle);

    if (ok) {
      unsigned int dropped = gen - (NUM_EXCHANGE_KEYS - 1);
      gen = new_gen;
      ESP_LOGI(TAG_STORAGE,
               "Rotated: gen %u (dropped %u, %d active keys)", gen, dropped,
               NUM_EXCHANGE_KEYS);
    }
    return ok;
  }

  void wipe_secrets() {
    mbedtls_platform_zeroize(password_hash, sizeof(password_hash));
    activated = false;
  }
};

#endif // TANG_STORAGE_H
