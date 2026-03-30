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

/* Derive exchange key for a generation from an explicit master key */
static int derive_exchange_key(const uint8_t *mk, uint32_t generation,
                               uint8_t *priv_out) {
  char info[32];
  int info_len =
      snprintf(info, sizeof(info), "tang-exchange-key-%" PRIu32, generation);
  return derive_ec_private_key(mk, (const uint8_t *)info, info_len, priv_out);
}

/**
 * NVS key name for an exchange key slot.
 */
static const char *exc_nvs_key(uint32_t slot) {
  static char buf[16];
  snprintf(buf, sizeof(buf), "exc_%u", (unsigned)slot);
  return buf;
}

/**
 * Read exchange key private key from NVS by slot index.
 */
static esp_err_t read_exchange_key(uint32_t slot,
                                   uint8_t priv_out[EC_PRIV_SIZE]) {
  esp_err_t err = ensure_nvs();
  if (err != ESP_OK)
    return err;

  size_t len = EC_PRIV_SIZE;
  return nvs_get_blob(tang_nvs, exc_nvs_key(slot), priv_out, &len);
}

/**
 * Write exchange key private key to NVS by slot index.
 */
static esp_err_t write_exchange_key(uint32_t slot,
                                    const uint8_t priv[EC_PRIV_SIZE]) {
  esp_err_t err = ensure_nvs();
  if (err != ESP_OK)
    return err;

  return nvs_set_blob(tang_nvs, exc_nvs_key(slot), priv, EC_PRIV_SIZE);
}

/**
 * Erase all exchange keys from NVS (for partial-write recovery).
 */
static void erase_all_exchange_keys(uint32_t nkeys) {
  if (!nvs_initialized)
    return;
  for (uint32_t s = 0; s < nkeys; s++)
    nvs_erase_key(tang_nvs, exc_nvs_key(s));
  nvs_commit(tang_nvs);
}

/**
 * Verify password by deriving an exchange key and comparing with NVS.
 * Uses the key at current_gen slot for comparison.
 */
static esp_err_t verify_password(const uint8_t *mk, uint32_t gen,
                                 uint32_t nkeys) {
  uint8_t derived_priv[EC_PRIV_SIZE];
  int ret = derive_exchange_key(mk, gen, derived_priv);
  if (ret != 0) {
    mbedtls_platform_zeroize(derived_priv, sizeof(derived_priv));
    return ESP_FAIL;
  }

  uint8_t stored_priv[EC_PRIV_SIZE];
  esp_err_t err = read_exchange_key(gen % nkeys, stored_priv);
  if (err != ESP_OK) {
    mbedtls_platform_zeroize(derived_priv, sizeof(derived_priv));
    return err;
  }

  /* Constant-time comparison */
  int diff = 0;
  for (int i = 0; i < EC_PRIV_SIZE; i++)
    diff |= derived_priv[i] ^ stored_priv[i];
  mbedtls_platform_zeroize(derived_priv, sizeof(derived_priv));
  mbedtls_platform_zeroize(stored_priv, sizeof(stored_priv));

  return (diff == 0) ? ESP_OK : ESP_ERR_INVALID_ARG;
}

/* ------------------------------------------------------------------ */
/* Secure service implementations (_ss_ prefix)                        */
/* ------------------------------------------------------------------ */

/**
 * SS 200: Activate — derive master_key on stack, persist exchange private
 * keys in NVS Secure Storage, compute all exchange public keys.
 *
 * First activation: derive all exchange keys → write to NVS → compute pubkeys.
 * Subsequent: derive signing key on stack → compare with stored → if match,
 * load all exchange keys from NVS → compute pubkeys → output.
 * master_key is zeroized from the stack before returning.
 *
 * pub_keys_out layout: [exc_pub_0(64)] ... [exc_pub_N(64)]
 * where exc_pub slots are ordered by gen, gen-1, ... gen-(num_keys-1)
 * mapped to their ring buffer slots.
 *
 * Signing key is not involved — it lives in TEE Secure Storage.
 *
 * @param keying_material  64 bytes: password_hash(32) || kdf_salt(32)
 */
esp_err_t _ss_tang_tee_activate(const uint8_t *keying_material, uint32_t gen,
                                uint32_t nkeys, uint8_t *pub_keys_out) {
  if (!keying_material || !pub_keys_out || nkeys == 0)
    return ESP_ERR_INVALID_ARG;

  /* Derive master_key on stack — never stored statically */
  uint8_t mk[32];
  esp_err_t err = derive_master_key(keying_material, mk);
  if (err != ESP_OK)
    return err;

  err = ensure_nvs();
  if (err != ESP_OK) {
    mbedtls_platform_zeroize(mk, sizeof(mk));
    return err;
  }

  /* Check if exchange keys already exist in NVS */
  uint8_t probe[EC_PRIV_SIZE];
  size_t probe_len = EC_PRIV_SIZE;
  esp_err_t read_err =
      nvs_get_blob(tang_nvs, exc_nvs_key(gen % nkeys), probe, &probe_len);
  mbedtls_platform_zeroize(probe, sizeof(probe));

  if (read_err == ESP_ERR_NVS_NOT_FOUND) {
    /* First activation: derive all keys, write to NVS, compute pubkeys */
    uint8_t priv[EC_PRIV_SIZE];
    for (uint32_t offset = 0; offset < nkeys; offset++) {
      uint32_t g = gen - offset;
      uint32_t s = g % nkeys;

      int ret = derive_exchange_key(mk, g, priv);
      if (ret != 0) {
        mbedtls_platform_zeroize(priv, sizeof(priv));
        mbedtls_platform_zeroize(mk, sizeof(mk));
        erase_all_exchange_keys(nkeys);
        return ESP_FAIL;
      }

      err = write_exchange_key(s, priv);
      if (err != ESP_OK) {
        mbedtls_platform_zeroize(priv, sizeof(priv));
        mbedtls_platform_zeroize(mk, sizeof(mk));
        erase_all_exchange_keys(nkeys);
        return err;
      }

      ret = compute_public_key(priv, pub_keys_out + s * EC_PUB_SIZE);
      mbedtls_platform_zeroize(priv, sizeof(priv));
      if (ret != 0) {
        mbedtls_platform_zeroize(mk, sizeof(mk));
        erase_all_exchange_keys(nkeys);
        return ESP_FAIL;
      }
    }
    nvs_commit(tang_nvs);
  } else if (read_err == ESP_OK) {
    /* Subsequent activation: verify password via exchange key comparison */
    err = verify_password(mk, gen, nkeys);
    if (err != ESP_OK) {
      mbedtls_platform_zeroize(mk, sizeof(mk));
      return err; /* ESP_ERR_INVALID_ARG = wrong password */
    }

    /* Password verified — load all exchange keys from NVS, compute pubkeys */
    uint8_t priv[EC_PRIV_SIZE];
    for (uint32_t offset = 0; offset < nkeys; offset++) {
      uint32_t g = gen - offset;
      uint32_t s = g % nkeys;

      err = read_exchange_key(s, priv);
      if (err != ESP_OK) {
        /* Partial-write recovery: erase all, caller should retry */
        mbedtls_platform_zeroize(priv, sizeof(priv));
        mbedtls_platform_zeroize(mk, sizeof(mk));
        erase_all_exchange_keys(nkeys);
        return err;
      }

      int ret = compute_public_key(priv, pub_keys_out + s * EC_PUB_SIZE);
      mbedtls_platform_zeroize(priv, sizeof(priv));
      if (ret != 0) {
        mbedtls_platform_zeroize(mk, sizeof(mk));
        return ESP_FAIL;
      }
    }
  } else {
    mbedtls_platform_zeroize(mk, sizeof(mk));
    return read_err;
  }

  mbedtls_platform_zeroize(mk, sizeof(mk));
  current_gen = gen;
  num_exchange_keys = nkeys;
  activated = true;
  return ESP_OK;
}

/**
 * SS 202: ECDH with a client public key.
 * Reads exchange private key from NVS Secure Storage (no RAM cache).
 * shared_point_out = x(32) || y(32) of the shared point.
 */
esp_err_t _ss_tang_tee_ecdh(const uint8_t *client_pub, uint32_t generation,
                            uint8_t *shared_point_out) {
  if (!activated)
    return ESP_ERR_INVALID_STATE;
  if (!client_pub || !shared_point_out)
    return ESP_ERR_INVALID_ARG;

  uint8_t priv[EC_PRIV_SIZE];
  uint32_t s = generation % num_exchange_keys;
  esp_err_t err = read_exchange_key(s, priv);
  if (err != ESP_OK) {
    mbedtls_platform_zeroize(priv, sizeof(priv));
    return err;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
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
 * SS 203: Rotate — verify password, derive new exchange key, persist to NVS,
 * return its public key.
 *
 * @param keying_material  64 bytes: password_hash(32) || kdf_salt(32)
 * @param new_gen          New generation number
 * @param pub_key_out      Output public key for new generation (64 bytes)
 */
esp_err_t _ss_tang_tee_rotate(const uint8_t *keying_material, uint32_t new_gen,
                              uint8_t *pub_key_out) {
  if (!activated)
    return ESP_ERR_INVALID_STATE;
  if (!keying_material || !pub_key_out)
    return ESP_ERR_INVALID_ARG;

  /* Derive master_key on stack and verify password */
  uint8_t mk[32];
  esp_err_t err = derive_master_key(keying_material, mk);
  if (err != ESP_OK)
    return err;

  err = verify_password(mk, current_gen, num_exchange_keys);
  if (err != ESP_OK) {
    mbedtls_platform_zeroize(mk, sizeof(mk));
    return err; /* ESP_ERR_INVALID_ARG = wrong password */
  }

  /* Derive new exchange key for new_gen */
  uint8_t priv[EC_PRIV_SIZE];
  int ret = derive_exchange_key(mk, new_gen, priv);
  mbedtls_platform_zeroize(mk, sizeof(mk));
  if (ret != 0) {
    mbedtls_platform_zeroize(priv, sizeof(priv));
    return ESP_FAIL;
  }

  /* Persist to NVS */
  uint32_t s = new_gen % num_exchange_keys;
  err = write_exchange_key(s, priv);
  if (err != ESP_OK) {
    mbedtls_platform_zeroize(priv, sizeof(priv));
    return err;
  }
  nvs_commit(tang_nvs);

  ret = compute_public_key(priv, pub_key_out);
  mbedtls_platform_zeroize(priv, sizeof(priv));

  if (ret == 0)
    current_gen = new_gen;

  return (ret == 0) ? ESP_OK : ESP_FAIL;
}

/**
 * SS 204: Lock — no RAM secrets to wipe (keys are in NVS).
 */
esp_err_t _ss_tang_tee_lock(void) {
  activated = false;
  current_gen = 0;
  num_exchange_keys = 0;
  return ESP_OK;
}

/**
 * SS 205: Change password — verify old via exchange key comparison,
 * derive new keys, persist to NVS, return new public keys.
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

  /* Verify old password via exchange key comparison */
  uint8_t old_mk[32];
  esp_err_t err = derive_master_key(old_keying, old_mk);
  if (err != ESP_OK)
    return err;

  err = verify_password(old_mk, current_gen, num_exchange_keys);
  mbedtls_platform_zeroize(old_mk, sizeof(old_mk));
  if (err != ESP_OK)
    return err; /* ESP_ERR_INVALID_ARG = wrong old password */

  /* Derive new master_key from new keying material */
  uint8_t new_mk[32];
  err = derive_master_key(new_keying, new_mk);
  if (err != ESP_OK)
    return err;

  /* Reset generation — all keys change with new password */
  current_gen = nkeys - 1;
  num_exchange_keys = nkeys;

  /* Derive all new exchange keys, write to NVS, compute pubkeys */
  uint8_t priv[EC_PRIV_SIZE];
  for (uint32_t offset = 0; offset < nkeys; offset++) {
    uint32_t g = current_gen - offset;
    uint32_t s = g % nkeys;

    int ret = derive_exchange_key(new_mk, g, priv);
    if (ret != 0) {
      mbedtls_platform_zeroize(priv, sizeof(priv));
      mbedtls_platform_zeroize(new_mk, sizeof(new_mk));
      return ESP_FAIL;
    }

    err = write_exchange_key(s, priv);
    if (err != ESP_OK) {
      mbedtls_platform_zeroize(priv, sizeof(priv));
      mbedtls_platform_zeroize(new_mk, sizeof(new_mk));
      return err;
    }

    ret = compute_public_key(priv, pub_keys_out + s * EC_PUB_SIZE);
    mbedtls_platform_zeroize(priv, sizeof(priv));
    if (ret != 0) {
      mbedtls_platform_zeroize(new_mk, sizeof(new_mk));
      return ESP_FAIL;
    }
  }
  nvs_commit(tang_nvs);
  mbedtls_platform_zeroize(new_mk, sizeof(new_mk));

  activated = true;
  return ESP_OK;
}

/**
 * SS 206: Provision eFuse KEY5 with a random HMAC key.
 * Only burns the eFuse — does not touch tee_salt.
 * No-op if KEY5 is already HMAC_UP.
 */
esp_err_t _ss_tang_tee_provision_efuse(void) {
  esp_efuse_purpose_t purpose;
  esp_err_t err = esp_efuse_read_field_blob(ESP_EFUSE_KEY_PURPOSE_5, &purpose,
                                            sizeof(purpose) * 8);
  if (err != ESP_OK)
    return err;

  if (purpose == ESP_EFUSE_KEY_PURPOSE_HMAC_UP)
    return ESP_OK; /* Already provisioned */

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

  return ESP_OK;
}

/**
 * SS 208: Ensure tee_salt exists in TEE Secure Storage.
 * Generates a random 32-byte salt if missing. No-op if already present.
 * Must be called after eFuse KEY5 is provisioned.
 */
esp_err_t _ss_tang_tee_ensure_tee_salt(void) {
  /* Check if tee_salt already exists */
  uint8_t existing[TEE_SALT_SIZE];
  esp_err_t err = read_tee_salt(existing);
  mbedtls_platform_zeroize(existing, sizeof(existing));
  if (err == ESP_OK)
    return ESP_OK; /* Already present */
  if (err != ESP_ERR_NVS_NOT_FOUND)
    return err;

  /* Generate and store new tee_salt */
  err = ensure_nvs();
  if (err != ESP_OK)
    return err;

  uint8_t tee_salt[TEE_SALT_SIZE];
  esp_fill_random(tee_salt, sizeof(tee_salt));

  err = nvs_set_blob(tang_nvs, "tee_salt", tee_salt, sizeof(tee_salt));
  mbedtls_platform_zeroize(tee_salt, sizeof(tee_salt));
  if (err != ESP_OK)
    return err;

  return nvs_commit(tang_nvs);
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
