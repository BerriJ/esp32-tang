#ifndef TANG_TEE_SERVICE_H
#define TANG_TEE_SERVICE_H

#include "esp_err.h"
#include "esp_tee.h"
#include "esp_tee_sec_storage.h"
#include "secure_service_num.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P-256 key sizes */
#define TEE_EC_PRIVATE_KEY_SIZE 32
#define TEE_EC_PUBLIC_KEY_SIZE 64
#define TEE_EC_COORDINATE_SIZE 32
#define TEE_EC_SIGNATURE_SIZE 64

/* eFuse status codes returned by tang_tee_efuse_status() */
#define TEE_EFUSE_STATUS_FREE 0
#define TEE_EFUSE_STATUS_PROVISIONED 1
#define TEE_EFUSE_STATUS_WRONG_PURPOSE 2

/* --- Tang custom TEE services --- */

/**
 * Activate the TEE with keying material.
 * Derives master_key via hardware HMAC(eFuse KEY5, keying_material),
 * then derives exchange keys and computes public keys.
 *
 * @param keying_material  64-byte buffer: password_hash(32) || kdf_salt(32)
 * @param gen            Current generation counter
 * @param num_keys       Number of exchange keys (NUM_EXCHANGE_KEYS)
 * @param pub_keys_out   Output buffer: [exc_pub_0(64)] ... [exc_pub_N(64)]
 *                       Must be at least num_keys * 64 bytes
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_activate(const uint8_t *keying_material,
                                          uint32_t gen, uint32_t num_keys,
                                          uint8_t *pub_keys_out) {
  return (esp_err_t)esp_tee_service_call(
      5, SS_TANG_TEE_ACTIVATE, keying_material, gen, num_keys, pub_keys_out);
}

/**
 * Perform ECDH with a client public key using the exchange key for a
 * generation.
 *
 * @param client_pub       Client's public key (x||y, 64 bytes)
 * @param generation       Exchange key generation to use
 * @param shared_point_out Output shared point (x||y, 64 bytes)
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_ecdh(const uint8_t *client_pub,
                                      uint32_t generation,
                                      uint8_t *shared_point_out) {
  return (esp_err_t)esp_tee_service_call(4, SS_TANG_TEE_ECDH, client_pub,
                                         generation, shared_point_out);
}

/**
 * Rotate to a new exchange key generation.
 * Verifies password, derives new key, persists to NVS Secure Storage.
 *
 * @param keying_material  64-byte buffer: password_hash(32) || kdf_salt(32)
 * @param new_gen          New generation number
 * @param pub_key_out      Output public key for new generation (64 bytes)
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if password is wrong
 */
static inline esp_err_t tang_tee_rotate(const uint8_t *keying_material,
                                        uint32_t new_gen,
                                        uint8_t *pub_key_out) {
  return (esp_err_t)esp_tee_service_call(4, SS_TANG_TEE_ROTATE, keying_material,
                                         new_gen, pub_key_out);
}

/**
 * Lock: wipe all secrets from TEE memory.
 *
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_lock(void) {
  return (esp_err_t)esp_tee_service_call(1, SS_TANG_TEE_LOCK);
}

/**
 * Change password: verify old, derive new exchange keys, return new public
 * keys.
 *
 * @param old_keying    Old keying material: password_hash(32) || kdf_salt(32)
 * @param new_keying    New keying material: password_hash(32) || kdf_salt(32)
 * @param num_keys      Number of exchange keys
 * @param pub_keys_out  Output buffer: [exc_pub_0(64)] ... [exc_pub_N(64)]
 *                      Must be at least num_keys * 64 bytes
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if old password is wrong
 */
static inline esp_err_t tang_tee_change_password(const uint8_t *old_keying,
                                                 const uint8_t *new_keying,
                                                 uint32_t num_keys,
                                                 uint8_t *pub_keys_out) {
  return (esp_err_t)esp_tee_service_call(5, SS_TANG_TEE_CHANGE_PASSWORD,
                                         old_keying, new_keying, num_keys,
                                         pub_keys_out);
}

/**
 * Provision eFuse KEY5 with a random HMAC key.
 * No-op if KEY5 is already HMAC_UP.
 * Does not generate tee_salt — call tang_tee_ensure_tee_salt() separately.
 *
 * @return ESP_OK on success or if already provisioned
 */
static inline esp_err_t tang_tee_provision_efuse(void) {
  return (esp_err_t)esp_tee_service_call(1, SS_TANG_TEE_PROVISION_EFUSE);
}

/**
 * Ensure tee_salt exists in TEE Secure Storage.
 * Generates a random salt if missing, no-op if already present.
 * Must be called after eFuse KEY5 is provisioned.
 *
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_ensure_tee_salt(void) {
  return (esp_err_t)esp_tee_service_call(1, SS_TANG_TEE_ENSURE_TEE_SALT);
}

/**
 * Get eFuse KEY5 provisioning status.
 *
 * @param status_out  Output: TEE_EFUSE_STATUS_FREE, _PROVISIONED, or
 * _WRONG_PURPOSE
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_efuse_status(uint32_t *status_out) {
  return (esp_err_t)esp_tee_service_call(2, SS_TANG_TEE_EFUSE_STATUS,
                                         status_out);
}

#ifdef __cplusplus
}
#endif

#endif /* TANG_TEE_SERVICE_H */
