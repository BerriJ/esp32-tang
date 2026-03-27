#ifndef TANG_TEE_SERVICE_H
#define TANG_TEE_SERVICE_H

#include "esp_err.h"
#include "esp_tee.h"
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

/**
 * Activate the TEE with a password hash.
 * Derives master_key via hardware HMAC(eFuse KEY5, password_hash),
 * then derives signing + exchange keys, computes public keys.
 *
 * @param password_hash  32-byte PBKDF2 output from browser
 * @param gen            Current generation counter
 * @param num_keys       Number of exchange keys (NUM_EXCHANGE_KEYS)
 * @param pub_keys_out   Output buffer: [sig_pub(64)] [exc_pub_0(64)] ...
 * [exc_pub_N(64)] Must be at least (1 + num_keys) * 64 bytes
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_activate(const uint8_t *password_hash,
                                          uint32_t gen, uint32_t num_keys,
                                          uint8_t *pub_keys_out) {
  return (esp_err_t)esp_tee_service_call(5, SS_TANG_TEE_ACTIVATE, password_hash,
                                         gen, num_keys, pub_keys_out);
}

/**
 * Sign a hash with the TEE-stored signing key (ECDSA P-256).
 *
 * @param hash           Hash to sign
 * @param hash_len       Length of hash (32 for SHA-256)
 * @param signature_out  Output buffer for r||s signature (64 bytes)
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_sign(const uint8_t *hash, uint32_t hash_len,
                                      uint8_t *signature_out) {
  return (esp_err_t)esp_tee_service_call(4, SS_TANG_TEE_SIGN, hash, hash_len,
                                         signature_out);
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
 *
 * @param new_gen       New generation number
 * @param pub_key_out   Output public key for new generation (64 bytes)
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_rotate(uint32_t new_gen,
                                        uint8_t *pub_key_out) {
  return (esp_err_t)esp_tee_service_call(3, SS_TANG_TEE_ROTATE, new_gen,
                                         pub_key_out);
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
 * Change password: verify old, derive new keys, return new public keys.
 *
 * @param old_hash      Old password hash (32 bytes)
 * @param new_hash      New password hash (32 bytes)
 * @param num_keys      Number of exchange keys
 * @param pub_keys_out  Output buffer: same layout as tang_tee_activate
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if old password is wrong
 */
static inline esp_err_t tang_tee_change_password(const uint8_t *old_hash,
                                                 const uint8_t *new_hash,
                                                 uint32_t num_keys,
                                                 uint8_t *pub_keys_out) {
  return (esp_err_t)esp_tee_service_call(5, SS_TANG_TEE_CHANGE_PASSWORD,
                                         old_hash, new_hash, num_keys,
                                         pub_keys_out);
}

/**
 * Provision eFuse KEY5 with a random HMAC key (one-time operation).
 * Only succeeds if KEY5 is currently free.
 *
 * @return ESP_OK on success
 */
static inline esp_err_t tang_tee_provision_efuse(void) {
  return (esp_err_t)esp_tee_service_call(1, SS_TANG_TEE_PROVISION_EFUSE);
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
