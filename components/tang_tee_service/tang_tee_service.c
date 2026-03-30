/*
 * Tang TEE Secure Services
 *
 * All private key operations run inside the TEE (RISC-V M-mode).
 * Private keys never leave the TEE's hardware-protected memory.
 */
#include "esp_cpu.h"
#include "esp_err.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_hmac.h"
#include "esp_random.h"
#include "esp_tee.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "secure_service_num.h"

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <inttypes.h>
#include <string.h>

/* P-256 key sizes */
#define EC_PRIV_SIZE 32
#define EC_PUB_SIZE 64
#define EC_COORD_SIZE 32
#define TEE_SALT_SIZE 32
#define COMBINED_KM_SIZE (64 + TEE_SALT_SIZE) /* keying_material || tee_salt */

/* TEE-protected state — invisible to REE */
static uint8_t master_key[32];
static bool activated = false;
static uint32_t current_gen = 0;
static uint32_t num_exchange_keys = 0;

/* NVS handle for TEE Secure Storage */
static nvs_handle_t tang_nvs = 0;
static bool nvs_initialized = false;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/**
 * Open the TEE Secure Storage NVS partition (idempotent).
 */
static esp_err_t ensure_nvs(void) {
  if (nvs_initialized)
    return ESP_OK;

  esp_err_t err = nvs_flash_init_partition("secure_storage");
  if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
      err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    /* Should not erase in production — indicates corruption */
    return err;
  }
  if (err != ESP_OK)
    return err;

  err = nvs_open_from_partition("secure_storage", "tang_keys",
                                NVS_READWRITE, &tang_nvs);
  if (err != ESP_OK)
    return err;

  nvs_initialized = true;
  return ESP_OK;
}

/**
 * Read the TEE-side salt from Secure Storage.
 */
static esp_err_t read_tee_salt(uint8_t out[TEE_SALT_SIZE]) {
  esp_err_t err = ensure_nvs();
  if (err != ESP_OK)
    return err;

  size_t len = TEE_SALT_SIZE;
  return nvs_get_blob(tang_nvs, "tee_salt", out, &len);
}

/**
 * Build combined HMAC input: keying_material(64) || tee_salt(32).
 * Derives master_key via HMAC(eFuse KEY5, combined).
 * Zeroizes tee_salt and combined buffer on all paths.
 */
static esp_err_t derive_master_key(const uint8_t *keying_material,
                                   uint8_t *mk_out) {
  uint8_t tee_salt[TEE_SALT_SIZE];
  esp_err_t err = read_tee_salt(tee_salt);
  if (err != ESP_OK)
    return err;

  uint8_t combined[COMBINED_KM_SIZE];
  memcpy(combined, keying_material, 64);
  memcpy(combined + 64, tee_salt, TEE_SALT_SIZE);
  mbedtls_platform_zeroize(tee_salt, sizeof(tee_salt));

  err = esp_hmac_calculate(HMAC_KEY5, combined, COMBINED_KM_SIZE, mk_out);
  mbedtls_platform_zeroize(combined, sizeof(combined));
  return err;
}

/**
 * RNG callback for mbedtls ECP operations (side-channel blinding).
 * Required since mbedtls 3.x — software ecp_mul_comb rejects f_rng=NULL.
 */
static int tee_rng(void *ctx, unsigned char *buf, size_t len) {
  (void)ctx;
  esp_fill_random(buf, len);
  return 0;
}

/**
 * Compute HMAC-SHA256(key, msg) using raw SHA-256 primitives.
 * HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
 * where K' = K padded to block size (64 bytes for SHA-256).
 */
static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t out[32]) {
  uint8_t k_pad[64];
  uint8_t inner_hash[32];
  int ret;

  /* If key > block size, hash it first (not needed here, our key is 32 bytes) */
  memset(k_pad, 0, sizeof(k_pad));
  if (key_len <= 64) {
    memcpy(k_pad, key, key_len);
  } else {
    ret = mbedtls_sha256(key, key_len, k_pad, 0);
    if (ret != 0)
      return ret;
  }

  /* Inner hash: SHA256((K xor ipad) || msg) */
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);

  uint8_t ipad[64];
  for (int i = 0; i < 64; i++)
    ipad[i] = k_pad[i] ^ 0x36;

  ret = mbedtls_sha256_starts(&ctx, 0);
  if (ret == 0)
    ret = mbedtls_sha256_update(&ctx, ipad, 64);
  if (ret == 0)
    ret = mbedtls_sha256_update(&ctx, msg, msg_len);
  if (ret == 0)
    ret = mbedtls_sha256_finish(&ctx, inner_hash);
  mbedtls_sha256_free(&ctx);
  if (ret != 0)
    return ret;

  /* Outer hash: SHA256((K xor opad) || inner_hash) */
  mbedtls_sha256_init(&ctx);

  uint8_t opad[64];
  for (int i = 0; i < 64; i++)
    opad[i] = k_pad[i] ^ 0x5c;

  ret = mbedtls_sha256_starts(&ctx, 0);
  if (ret == 0)
    ret = mbedtls_sha256_update(&ctx, opad, 64);
  if (ret == 0)
    ret = mbedtls_sha256_update(&ctx, inner_hash, 32);
  if (ret == 0)
    ret = mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);

  mbedtls_platform_zeroize(k_pad, sizeof(k_pad));
  mbedtls_platform_zeroize(inner_hash, sizeof(inner_hash));
  mbedtls_platform_zeroize(ipad, sizeof(ipad));
  mbedtls_platform_zeroize(opad, sizeof(opad));
  return ret;
}

/**
 * Derive a P-256 private key using HKDF-Expand with HMAC-SHA256.
 * private_key = HMAC-SHA256(master_key, info || 0x01)
 */
static int derive_ec_private_key(const uint8_t *mk, const uint8_t *info,
                                 size_t info_len, uint8_t *out) {
  /* Build message: info || 0x01 */
  uint8_t msg[64];
  if (info_len >= sizeof(msg))
    return -1;
  memcpy(msg, info, info_len);
  msg[info_len] = 0x01;

  int ret = hmac_sha256(mk, 32, msg, info_len + 1, out);
  mbedtls_platform_zeroize(msg, sizeof(msg));
  return ret;
}

/**
 * Compute P-256 public key from private key: Q = d * G
 */
static int compute_public_key(const uint8_t *priv, uint8_t *pub) {
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0)
    ret = mbedtls_mpi_read_binary(&d, priv, EC_PRIV_SIZE);
  if (ret == 0)
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, tee_rng, NULL);
  if (ret == 0)
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub, EC_COORD_SIZE);
  if (ret == 0)
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), pub + EC_COORD_SIZE,
                                   EC_COORD_SIZE);

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  return ret;
}

/* Derive signing key from master_key */
static int derive_signing_key(uint8_t *priv_out) {
  const char *info = "tang-signing-key";
  return derive_ec_private_key(master_key, (const uint8_t *)info, strlen(info),
                               priv_out);
}

/* Derive exchange key for a generation from master_key */
static int derive_exchange_key(uint32_t generation, uint8_t *priv_out) {
  char info[32];
  int info_len =
      snprintf(info, sizeof(info), "tang-exchange-key-%" PRIu32, generation);
  return derive_ec_private_key(master_key, (const uint8_t *)info, info_len,
                               priv_out);
}

/* ------------------------------------------------------------------ */
/* Secure service implementations (_ss_ prefix)                        */
/* ------------------------------------------------------------------ */

/**
 * SS 200: Activate — derive master_key, compute all public keys.
 *
 * pub_keys_out layout: [sig_pub(64)] [exc_pub_0(64)] ... [exc_pub_N(64)]
 * where exc_pub slots are ordered by gen, gen-1, ... gen-(num_keys-1)
 * mapped to their ring buffer slots.
 *
 * @param keying_material  64 bytes: password_hash(32) || kdf_salt(32)
 *                         The kdf_salt ensures forward secrecy — same
 *                         password with different salt yields different keys.
 */
esp_err_t _ss_tang_tee_activate(const uint8_t *keying_material, uint32_t gen,
                                uint32_t nkeys, uint8_t *pub_keys_out) {
  if (!keying_material || !pub_keys_out || nkeys == 0)
    return ESP_ERR_INVALID_ARG;

  /* Derive master_key = HMAC(eFuse KEY5, keying_material || tee_salt) */
  esp_err_t err = derive_master_key(keying_material, master_key);
  if (err != ESP_OK)
    return err;

  current_gen = gen;
  num_exchange_keys = nkeys;

  /* Derive and output signing public key (first 64 bytes) */
  uint8_t priv[EC_PRIV_SIZE];
  int ret = derive_signing_key(priv);
  if (ret != 0) {
    mbedtls_platform_zeroize(priv, sizeof(priv));
    mbedtls_platform_zeroize(master_key, sizeof(master_key));
    return ESP_FAIL;
  }

  ret = compute_public_key(priv, pub_keys_out);
  mbedtls_platform_zeroize(priv, sizeof(priv));
  if (ret != 0) {
    mbedtls_platform_zeroize(master_key, sizeof(master_key));
    return ESP_FAIL;
  }

  /* Derive and output exchange public keys */
  for (uint32_t offset = 0; offset < nkeys; offset++) {
    uint32_t g = gen - offset;
    uint32_t s = g % nkeys;

    ret = derive_exchange_key(g, priv);
    if (ret != 0) {
      mbedtls_platform_zeroize(priv, sizeof(priv));
      mbedtls_platform_zeroize(master_key, sizeof(master_key));
      return ESP_FAIL;
    }

    /* Exchange keys start after the signing key: offset (1 + slot) * 64 */
    ret = compute_public_key(priv, pub_keys_out + (1 + s) * EC_PUB_SIZE);
    mbedtls_platform_zeroize(priv, sizeof(priv));
    if (ret != 0) {
      mbedtls_platform_zeroize(master_key, sizeof(master_key));
      return ESP_FAIL;
    }
  }

  activated = true;
  return ESP_OK;
}

/**
 * SS 201: Sign a hash with the signing key (ECDSA P-256).
 * signature_out = r(32) || s(32)
 */
esp_err_t _ss_tang_tee_sign(const uint8_t *hash, uint32_t hash_len,
                            uint8_t *signature_out) {
  if (!activated)
    return ESP_ERR_INVALID_STATE;
  if (!hash || !signature_out || hash_len == 0)
    return ESP_ERR_INVALID_ARG;

  uint8_t priv[EC_PRIV_SIZE];
  int ret = derive_signing_key(priv);
  if (ret != 0) {
    mbedtls_platform_zeroize(priv, sizeof(priv));
    return ESP_FAIL;
  }

  mbedtls_ecp_group grp;
  mbedtls_mpi d, r, s;

  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0)
    ret = mbedtls_mpi_read_binary(&d, priv, EC_PRIV_SIZE);
  mbedtls_platform_zeroize(priv, sizeof(priv));

  if (ret == 0)
    ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, hash_len, tee_rng, NULL);
  if (ret == 0)
    ret = mbedtls_mpi_write_binary(&r, signature_out, EC_COORD_SIZE);
  if (ret == 0)
    ret = mbedtls_mpi_write_binary(&s, signature_out + EC_COORD_SIZE,
                                   EC_COORD_SIZE);

  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  return (ret == 0) ? ESP_OK : ESP_FAIL;
}

/**
 * SS 202: ECDH with a client public key.
 * shared_point_out = x(32) || y(32) of the shared point.
 */
esp_err_t _ss_tang_tee_ecdh(const uint8_t *client_pub, uint32_t generation,
                            uint8_t *shared_point_out) {
  if (!activated)
    return ESP_ERR_INVALID_STATE;
  if (!client_pub || !shared_point_out)
    return ESP_ERR_INVALID_ARG;

  uint8_t priv[EC_PRIV_SIZE];
  int ret = derive_exchange_key(generation, priv);
  if (ret != 0) {
    mbedtls_platform_zeroize(priv, sizeof(priv));
    return ESP_FAIL;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0)
    ret = mbedtls_mpi_read_binary(&d, priv, EC_PRIV_SIZE);
  mbedtls_platform_zeroize(priv, sizeof(priv));

  if (ret == 0)
    ret =
        mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), client_pub, EC_COORD_SIZE);
  if (ret == 0)
    ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y),
                                  client_pub + EC_COORD_SIZE, EC_COORD_SIZE);
  if (ret == 0)
    ret = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);
  if (ret == 0)
    ret = mbedtls_ecp_check_pubkey(&grp, &Q);
  if (ret == 0)
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &Q, tee_rng, NULL);
  if (ret == 0)
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), shared_point_out,
                                   EC_COORD_SIZE);
  if (ret == 0)
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y),
                                   shared_point_out + EC_COORD_SIZE,
                                   EC_COORD_SIZE);

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);

  return (ret == 0) ? ESP_OK : ESP_FAIL;
}

/**
 * SS 203: Rotate — derive new exchange key, return its public key.
 */
esp_err_t _ss_tang_tee_rotate(uint32_t new_gen, uint8_t *pub_key_out) {
  if (!activated)
    return ESP_ERR_INVALID_STATE;
  if (!pub_key_out)
    return ESP_ERR_INVALID_ARG;

  uint8_t priv[EC_PRIV_SIZE];
  int ret = derive_exchange_key(new_gen, priv);
  if (ret != 0) {
    mbedtls_platform_zeroize(priv, sizeof(priv));
    return ESP_FAIL;
  }

  ret = compute_public_key(priv, pub_key_out);
  mbedtls_platform_zeroize(priv, sizeof(priv));

  if (ret == 0)
    current_gen = new_gen;

  return (ret == 0) ? ESP_OK : ESP_FAIL;
}

/**
 * SS 204: Lock — wipe all secrets from TEE memory.
 */
esp_err_t _ss_tang_tee_lock(void) {
  mbedtls_platform_zeroize(master_key, sizeof(master_key));
  activated = false;
  current_gen = 0;
  num_exchange_keys = 0;
  return ESP_OK;
}

/**
 * SS 205: Change password — verify old, derive new, return new public keys.
 *
 * @param old_keying  64 bytes: old_password_hash(32) || old_kdf_salt(32)
 * @param new_keying  64 bytes: new_password_hash(32) || new_kdf_salt(32)
 */
esp_err_t _ss_tang_tee_change_password(const uint8_t *old_keying,
                                       const uint8_t *new_keying,
                                       uint32_t nkeys,
                                       uint8_t *pub_keys_out) {
  if (!activated)
    return ESP_ERR_INVALID_STATE;
  if (!old_keying || !new_keying || !pub_keys_out || nkeys == 0)
    return ESP_ERR_INVALID_ARG;

  /* Verify old password: derive master from old keying material and compare */
  uint8_t test_master[32];
  esp_err_t err = derive_master_key(old_keying, test_master);
  if (err != ESP_OK) {
    mbedtls_platform_zeroize(test_master, sizeof(test_master));
    return err;
  }

  /* Constant-time comparison */
  int diff = 0;
  for (int i = 0; i < 32; i++)
    diff |= test_master[i] ^ master_key[i];
  mbedtls_platform_zeroize(test_master, sizeof(test_master));

  if (diff != 0)
    return ESP_ERR_INVALID_ARG; /* wrong old password */

  /* Derive new master_key from new keying material (includes new salt) */
  err = derive_master_key(new_keying, master_key);
  if (err != ESP_OK)
    return err;

  /* Reset generation — all keys change with new password */
  current_gen = nkeys - 1;
  num_exchange_keys = nkeys;

  /* Derive all new public keys (same layout as activate) */
  uint8_t priv[EC_PRIV_SIZE];
  int ret = derive_signing_key(priv);
  if (ret != 0) {
    mbedtls_platform_zeroize(priv, sizeof(priv));
    return ESP_FAIL;
  }

  ret = compute_public_key(priv, pub_keys_out);
  mbedtls_platform_zeroize(priv, sizeof(priv));
  if (ret != 0)
    return ESP_FAIL;

  for (uint32_t offset = 0; offset < nkeys; offset++) {
    uint32_t g = current_gen - offset;
    uint32_t s = g % nkeys;

    ret = derive_exchange_key(g, priv);
    if (ret != 0) {
      mbedtls_platform_zeroize(priv, sizeof(priv));
      return ESP_FAIL;
    }

    ret = compute_public_key(priv, pub_keys_out + (1 + s) * EC_PUB_SIZE);
    mbedtls_platform_zeroize(priv, sizeof(priv));
    if (ret != 0)
      return ESP_FAIL;
  }

  activated = true;
  return ESP_OK;
}

/**
 * SS 206: Provision eFuse KEY5 with a random HMAC key.
 */
esp_err_t _ss_tang_tee_provision_efuse(void) {
  /* Check if KEY5 is free */
  esp_efuse_purpose_t purpose;
  esp_err_t err = esp_efuse_read_field_blob(ESP_EFUSE_KEY_PURPOSE_5, &purpose,
                                            sizeof(purpose) * 8);
  if (err != ESP_OK)
    return err;

  if (purpose == ESP_EFUSE_KEY_PURPOSE_HMAC_UP) {
    /* KEY5 already provisioned — ensure tee_salt exists (firmware upgrade) */
    uint8_t existing[TEE_SALT_SIZE];
    esp_err_t salt_err = read_tee_salt(existing);
    mbedtls_platform_zeroize(existing, sizeof(existing));
    if (salt_err == ESP_OK)
      return ESP_OK; /* Both KEY5 and tee_salt present */
    if (salt_err != ESP_ERR_NVS_NOT_FOUND)
      return salt_err;
    /* tee_salt missing — generate it below */
    goto generate_salt;
  }

  if (purpose != ESP_EFUSE_KEY_PURPOSE_USER)
    return ESP_ERR_INVALID_STATE; /* Wrong purpose, can't provision */

  /* Generate random 256-bit key and burn to eFuse */
  uint8_t hmac_key[32];
  esp_fill_random(hmac_key, sizeof(hmac_key));

  err = esp_efuse_write_key(EFUSE_BLK_KEY5, ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
                            hmac_key, sizeof(hmac_key));
  mbedtls_platform_zeroize(hmac_key, sizeof(hmac_key));

  if (err != ESP_OK)
    return err;

  /* Verify protections */
  if (!esp_efuse_get_key_dis_read(EFUSE_BLK_KEY5) ||
      !esp_efuse_get_key_dis_write(EFUSE_BLK_KEY5) ||
      !esp_efuse_get_keypurpose_dis_write(EFUSE_BLK_KEY5)) {
    return ESP_FAIL;
  }

generate_salt:;
  /* Generate and store TEE-side salt in Secure Storage */
  err = ensure_nvs();
  if (err != ESP_OK)
    return err;

  uint8_t tee_salt[TEE_SALT_SIZE];
  esp_fill_random(tee_salt, sizeof(tee_salt));

  err = nvs_set_blob(tang_nvs, "tee_salt", tee_salt, sizeof(tee_salt));
  mbedtls_platform_zeroize(tee_salt, sizeof(tee_salt));
  if (err != ESP_OK)
    return err;

  err = nvs_commit(tang_nvs);
  return err;
}

/**
 * SS 207: Get eFuse KEY5 status.
 */
esp_err_t _ss_tang_tee_efuse_status(uint32_t *status_out) {
  if (!status_out)
    return ESP_ERR_INVALID_ARG;

  esp_efuse_purpose_t purpose;
  esp_err_t err = esp_efuse_read_field_blob(ESP_EFUSE_KEY_PURPOSE_5, &purpose,
                                            sizeof(purpose) * 8);
  if (err != ESP_OK)
    return err;

  if (purpose == ESP_EFUSE_KEY_PURPOSE_HMAC_UP)
    *status_out = 1; /* TEE_EFUSE_STATUS_PROVISIONED */
  else if (purpose == ESP_EFUSE_KEY_PURPOSE_USER)
    *status_out = 0; /* TEE_EFUSE_STATUS_FREE */
  else
    *status_out = 2; /* TEE_EFUSE_STATUS_WRONG_PURPOSE */

  return ESP_OK;
}
