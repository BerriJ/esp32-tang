#ifndef TANG_STORAGE_H
#define TANG_STORAGE_H

#include "tang_tee_service.h"
#include <cstring>
#include <esp_log.h>
extern "C" {
#include <mbedtls/constant_time.h>
}
#include <mbedtls/platform_util.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <sdkconfig.h>

static const char *TAG_STORAGE = "tang_storage";

const int NUM_EXCHANGE_KEYS = CONFIG_NUM_EXCHANGE_KEYS;

class TangKeyStore {
public:
  // Public keys (loaded from NVS at boot, available without activation)
  uint8_t sig_pub[TEE_EC_PUBLIC_KEY_SIZE];
  bool sig_loaded;

  // Exchange public keys stored in NUM_EXCHANGE_KEYS slots (ring buffer indexed
  // by gen % NUM_EXCHANGE_KEYS)
  uint8_t exc_pub[NUM_EXCHANGE_KEYS][TEE_EC_PUBLIC_KEY_SIZE];
  bool exc_pub_loaded;

  // Generation counter (monotonically increasing, newest key).
  // Active keys are: gen, gen-1, ... gen-(NUM_EXCHANGE_KEYS-1).
  // Slot = generation % NUM_EXCHANGE_KEYS.
  // Starts at NUM_EXCHANGE_KEYS-1 so first activation produces all keys.
  unsigned int gen;

  bool activated;

  TangKeyStore()
      : sig_loaded(false), exc_pub_loaded(false), gen(NUM_EXCHANGE_KEYS - 1),
        activated(false) {
    memset(sig_pub, 0, sizeof(sig_pub));
    memset(exc_pub, 0, sizeof(exc_pub));
  }

  // Slot index for a given generation number
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
    bool found = (err == ESP_OK && len == TEE_EC_PUBLIC_KEY_SIZE);
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
    bool found = (err == ESP_OK && len == TEE_EC_PUBLIC_KEY_SIZE);
    nvs_close(handle);
    return found;
  }

  // Derive all keys via TEE, compute public keys.
  // password_hash is passed to the TEE and immediately forgotten by REE.
  bool derive_and_verify(const uint8_t *password_hash) {
    // Buffer for all public keys: signing + NUM_EXCHANGE_KEYS exchange keys
    uint8_t pub_keys_buf[(1 + NUM_EXCHANGE_KEYS) * TEE_EC_PUBLIC_KEY_SIZE];

    esp_err_t err =
        tang_tee_activate(password_hash, gen, NUM_EXCHANGE_KEYS, pub_keys_buf);
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "TEE activation failed: %s", esp_err_to_name(err));
      sig_loaded = false;
      exc_pub_loaded = false;
      return false;
    }

    // Copy signing public key (first 64 bytes)
    memcpy(sig_pub, pub_keys_buf, TEE_EC_PUBLIC_KEY_SIZE);
    sig_loaded = true;

    // Copy exchange public keys (64 bytes each, indexed by slot)
    for (int s = 0; s < NUM_EXCHANGE_KEYS; s++) {
      memcpy(exc_pub[s], pub_keys_buf + (1 + s) * TEE_EC_PUBLIC_KEY_SIZE,
             TEE_EC_PUBLIC_KEY_SIZE);
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
    ok = ok && (nvs_set_blob(handle, "sig_pub", sig_pub, TEE_EC_PUBLIC_KEY_SIZE) ==
                ESP_OK);

    for (int s = 0; s < NUM_EXCHANGE_KEYS && ok; s++) {
      ok = ok && (nvs_set_blob(handle, exc_pub_nvs_key(s), exc_pub[s],
                               TEE_EC_PUBLIC_KEY_SIZE) == ESP_OK);
    }

    ok = ok && (nvs_set_u32(handle, "gen", (uint32_t)gen) == ESP_OK);

    if (ok)
      ok = (nvs_commit(handle) == ESP_OK);

    nvs_close(handle);

    if (ok)
      ESP_LOGI(TAG_STORAGE,
               "Public keys stored in NVS (gen %u, %d active keys)", gen,
               NUM_EXCHANGE_KEYS);
    return ok;
  }

  // Verify that derived public keys match the ones stored in NVS.
  bool verify_public_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    // Verify signing key (constant-time comparison)
    uint8_t stored[TEE_EC_PUBLIC_KEY_SIZE];
    size_t len = TEE_EC_PUBLIC_KEY_SIZE;
    bool mismatch = false;
    if (nvs_get_blob(handle, "sig_pub", stored, &len) != ESP_OK ||
        mbedtls_ct_memcmp(sig_pub, stored, TEE_EC_PUBLIC_KEY_SIZE) != 0) {
      mismatch = true;
    }

    // Verify all exchange key slots (constant-time comparison)
    for (int s = 0; s < NUM_EXCHANGE_KEYS && !mismatch; s++) {
      len = TEE_EC_PUBLIC_KEY_SIZE;
      if (nvs_get_blob(handle, exc_pub_nvs_key(s), stored, &len) != ESP_OK ||
          mbedtls_ct_memcmp(exc_pub[s], stored, TEE_EC_PUBLIC_KEY_SIZE) != 0) {
        mismatch = true;
      }
    }

    if (mismatch) {
      nvs_close(handle);
      ESP_LOGW(TAG_STORAGE,
               "Public key mismatch — wrong password or wrong device");
      sig_loaded = false;
      exc_pub_loaded = false;
      return false;
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

    size_t len = TEE_EC_PUBLIC_KEY_SIZE;
    err = nvs_get_blob(handle, "sig_pub", sig_pub, &len);
    nvs_close(handle);

    if (err == ESP_OK && len == TEE_EC_PUBLIC_KEY_SIZE) {
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
      size_t len = TEE_EC_PUBLIC_KEY_SIZE;
      if (nvs_get_blob(handle, exc_pub_nvs_key(s), exc_pub[s], &len) !=
              ESP_OK ||
          len != TEE_EC_PUBLIC_KEY_SIZE) {
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

  // Rotate: increment gen, derive new key via TEE, overwrite oldest slot in
  // NVS.
  bool rotate() {
    if (!activated)
      return false;

    unsigned int new_gen = gen + 1;
    int s = slot(new_gen);

    // Derive new exchange key via TEE
    uint8_t new_pub[TEE_EC_PUBLIC_KEY_SIZE];
    esp_err_t err = tang_tee_rotate(new_gen, new_pub);
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "TEE rotate failed for gen %u", new_gen);
      return false;
    }

    memcpy(exc_pub[s], new_pub, TEE_EC_PUBLIC_KEY_SIZE);

    // Persist the new slot and updated gen counter
    nvs_handle_t handle;
    err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
      return false;

    bool ok = (nvs_set_blob(handle, exc_pub_nvs_key(s), exc_pub[s],
                            TEE_EC_PUBLIC_KEY_SIZE) == ESP_OK) &&
              (nvs_set_u32(handle, "gen", (uint32_t)new_gen) == ESP_OK) &&
              (nvs_commit(handle) == ESP_OK);
    nvs_close(handle);

    if (ok) {
      unsigned int dropped = gen - (NUM_EXCHANGE_KEYS - 1);
      gen = new_gen;
      ESP_LOGI(TAG_STORAGE, "Rotated: gen %u (dropped %u, %d active keys)", gen,
               dropped, NUM_EXCHANGE_KEYS);
    }
    return ok;
  }

  void wipe_secrets() {
    tang_tee_lock();
    activated = false;
  }
};

#endif // TANG_STORAGE_H
