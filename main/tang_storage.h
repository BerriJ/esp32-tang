#ifndef TANG_STORAGE_H
#define TANG_STORAGE_H

#include "tang_tee_service.h"
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
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

  // Random salt mixed into master key derivation for forward secrecy.
  // Generated on first setup and regenerated on every password change.
  // Ensures that reverting to a previous password still yields fresh keys.
  uint8_t kdf_salt[32];
  bool kdf_salt_loaded;

  bool activated;

  TangKeyStore()
      : sig_loaded(false), exc_pub_loaded(false), gen(NUM_EXCHANGE_KEYS - 1),
        kdf_salt_loaded(false), activated(false) {
    memset(sig_pub, 0, sizeof(sig_pub));
    memset(exc_pub, 0, sizeof(exc_pub));
    memset(kdf_salt, 0, sizeof(kdf_salt));
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

  // Generate the stable signing key in TEE Secure Storage (first boot only).
  // Idempotent — silently succeeds if the key already exists.
  bool init_signing_key() {
    tee_sec_stg_key_cfg_t cfg = {.id = "tang-sig",
                                 .type = TEE_SEC_STG_KEY_ECDSA_SECP256R1,
                                 .flags = TEE_SEC_STG_FLAG_WRITE_ONCE};
    esp_err_t err = tee_sec_stg_gen_key(&cfg);
    if (err == ESP_OK) {
      ESP_LOGI(TAG_STORAGE, "Signing key generated in TEE Secure Storage");
      return true;
    }
    // Key already exists — treat as success
    ESP_LOGI(TAG_STORAGE, "Signing key already in TEE Secure Storage (err=%s)",
             esp_err_to_name(err));
    return true;
  }

  // Load signing public key from TEE Secure Storage
  bool load_signing_pub_from_tee() {
    tee_sec_stg_key_cfg_t cfg = {.id = "tang-sig",
                                 .type = TEE_SEC_STG_KEY_ECDSA_SECP256R1,
                                 .flags = TEE_SEC_STG_FLAG_NONE};
    tee_sec_stg_ecdsa_pubkey_t pubkey;
    esp_err_t err = tee_sec_stg_ecdsa_get_pubkey(&cfg, &pubkey);
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "Failed to load signing pubkey from TEE: %s",
               esp_err_to_name(err));
      sig_loaded = false;
      return false;
    }
    memcpy(sig_pub, pubkey.pub_x, TEE_EC_COORDINATE_SIZE);
    memcpy(sig_pub + TEE_EC_COORDINATE_SIZE, pubkey.pub_y,
           TEE_EC_COORDINATE_SIZE);
    sig_loaded = true;
    ESP_LOGI(TAG_STORAGE, "Signing public key loaded from TEE Secure Storage");
    return true;
  }

  // Derive exchange keys via TEE, compute public keys.
  // password_hash is combined with kdf_salt to form 64-byte keying material,
  // then passed to the TEE and immediately forgotten by REE.
  // Signing key is not involved — it lives in TEE Secure Storage.
  bool derive_and_verify(const uint8_t *password_hash) {
    // Build keying material: password_hash(32) || kdf_salt(32)
    uint8_t keying[64];
    memcpy(keying, password_hash, 32);
    memcpy(keying + 32, kdf_salt, 32);

    // Buffer for exchange public keys only
    uint8_t pub_keys_buf[NUM_EXCHANGE_KEYS * TEE_EC_PUBLIC_KEY_SIZE];

    esp_err_t err =
        tang_tee_activate(keying, gen, NUM_EXCHANGE_KEYS, pub_keys_buf);
    mbedtls_platform_zeroize(keying, sizeof(keying));
    if (err != ESP_OK) {
      ESP_LOGE(TAG_STORAGE, "TEE activation failed: %s", esp_err_to_name(err));
      exc_pub_loaded = false;
      return false;
    }

    // Copy exchange public keys (64 bytes each, indexed by slot)
    for (int s = 0; s < NUM_EXCHANGE_KEYS; s++) {
      memcpy(exc_pub[s], pub_keys_buf + s * TEE_EC_PUBLIC_KEY_SIZE,
             TEE_EC_PUBLIC_KEY_SIZE);
    }
    exc_pub_loaded = true;

    return true;
  }

  // Generate a fresh random KDF salt (for first setup or password change)
  void generate_kdf_salt() {
    esp_fill_random(kdf_salt, sizeof(kdf_salt));
    kdf_salt_loaded = true;
    ESP_LOGI(TAG_STORAGE, "Generated new KDF salt for forward secrecy");
  }

  // Load KDF salt from NVS
  bool load_kdf_salt() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    size_t len = sizeof(kdf_salt);
    err = nvs_get_blob(handle, "kdf_salt", kdf_salt, &len);
    nvs_close(handle);

    if (err == ESP_OK && len == sizeof(kdf_salt)) {
      kdf_salt_loaded = true;
      return true;
    }
    return false;
  }

  // Store exchange public keys + gen counter + KDF salt to NVS.
  // Signing public key is not stored here — it lives in TEE Secure Storage.
  bool store_public_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READWRITE, &handle);
    if (err != ESP_OK)
      return false;

    bool ok = true;

    for (int s = 0; s < NUM_EXCHANGE_KEYS && ok; s++) {
      ok = ok && (nvs_set_blob(handle, exc_pub_nvs_key(s), exc_pub[s],
                               TEE_EC_PUBLIC_KEY_SIZE) == ESP_OK);
    }

    ok = ok && (nvs_set_u32(handle, "gen", (uint32_t)gen) == ESP_OK);

    ok = ok && (nvs_set_blob(handle, "kdf_salt", kdf_salt, sizeof(kdf_salt)) ==
                ESP_OK);

    if (ok)
      ok = (nvs_commit(handle) == ESP_OK);

    nvs_close(handle);

    if (ok)
      ESP_LOGI(TAG_STORAGE,
               "Public keys stored in NVS (gen %u, %d active keys)", gen,
               NUM_EXCHANGE_KEYS);
    return ok;
  }

  // Verify that derived exchange public keys match the ones stored in NVS.
  bool verify_public_keys() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("tang-server", NVS_READONLY, &handle);
    if (err != ESP_OK)
      return false;

    uint8_t stored[TEE_EC_PUBLIC_KEY_SIZE];
    size_t len;
    bool mismatch = false;

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
               "Exchange key mismatch — wrong password or wrong device");
      exc_pub_loaded = false;
      return false;
    }

    nvs_close(handle);
    ESP_LOGI(TAG_STORAGE,
             "All derived exchange keys match NVS — password verified");
    return true;
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
