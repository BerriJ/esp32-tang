#ifndef CRYPTO_H
#define CRYPTO_H

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <esp_system.h>
#include <esp_log.h>

static const char *TAG_CRYPTO = "crypto";

// --- Constants ---

// P-256 uses 256 bits = 32 bytes per coordinate
const int P521_PRIVATE_KEY_SIZE = 32; // Scalar value (keeping name for compatibility)
const int P521_PUBLIC_KEY_SIZE = 64;  // Uncompressed point (x + y)
const int P521_COORDINATE_SIZE = 32;  // Single coordinate (x or y)
const int GCM_TAG_SIZE = 16;
const int SALT_SIZE = 16;
const int PBKDF2_ITERATIONS = 1000;

// --- RNG Management ---
class RNG
{
private:
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  bool initialized;

public:
  RNG() : initialized(false) {}

  ~RNG()
  {
    cleanup();
  }

  int init()
  {
    if (initialized)
      return 0;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "esp32_tang_server";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
      return ret;

    initialized = true;
    return 0;
  }

  void cleanup()
  {
    if (initialized)
    {
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      initialized = false;
    }
  }

  mbedtls_ctr_drbg_context *context()
  {
    return &ctr_drbg;
  }
};

// Global RNG instance
static RNG global_rng;

// --- P-256 EC Operations ---
class P521
{
public:
  static bool generate_keypair(uint8_t *pub_key, uint8_t *priv_key)
  {
    int ret = global_rng.init();
    if (ret != 0)
    {
      ESP_LOGE(TAG_CRYPTO, "RNG init failed: -0x%04x", -ret);
      return false;
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0)
    {
      ESP_LOGE(TAG_CRYPTO, "ECP group load failed: -0x%04x", -ret);
    }
    else
    {
      ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, global_rng.context());
      if (ret != 0)
      {
        ESP_LOGE(TAG_CRYPTO, "ECP keypair gen failed: -0x%04x", -ret);
      }
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_write_binary(&d, priv_key, P521_COORDINATE_SIZE);
      if (ret != 0)
      {
        ESP_LOGE(TAG_CRYPTO, "Write private key failed: -0x%04x", -ret);
      }
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_key, P521_COORDINATE_SIZE);
      if (ret != 0)
      {
        ESP_LOGE(TAG_CRYPTO, "Write pub key X failed: -0x%04x", -ret);
      }
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), pub_key + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
      if (ret != 0)
      {
        ESP_LOGE(TAG_CRYPTO, "Write pub key Y failed: -0x%04x", -ret);
      }
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    return (ret == 0);
  }

  static bool compute_public_key(const uint8_t *priv_key, uint8_t *pub_key)
  {
    if (global_rng.init() != 0)
      return false;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0)
    {
      ret = mbedtls_mpi_read_binary(&d, priv_key, P521_COORDINATE_SIZE);
    }
    if (ret == 0)
    {
      ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, global_rng.context());
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_key, P521_COORDINATE_SIZE);
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), pub_key + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    return (ret == 0);
  }

  static bool ecdh_compute_shared_point(const uint8_t *peer_pub_key, const uint8_t *priv_key, uint8_t *shared_point, bool full_point = true)
  {
    if (global_rng.init() != 0)
      return false;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0)
    {
      ret = mbedtls_mpi_read_binary(&d, priv_key, P521_COORDINATE_SIZE);
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), peer_pub_key, P521_COORDINATE_SIZE);
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y), peer_pub_key + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);
    }
    if (ret == 0)
    {
      ret = mbedtls_ecp_check_pubkey(&grp, &Q);
    }
    if (ret == 0)
    {
      ret = mbedtls_ecp_mul(&grp, &Q, &d, &Q, mbedtls_ctr_drbg_random, global_rng.context());
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), shared_point, P521_COORDINATE_SIZE);
    }
    if (ret == 0 && full_point)
    {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), shared_point + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    return (ret == 0);
  }

  static bool sign(const uint8_t *hash, size_t hash_len, const uint8_t *priv_key, uint8_t *signature)
  {
    if (global_rng.init() != 0)
      return false;

    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0)
    {
      ret = mbedtls_mpi_read_binary(&d, priv_key, P521_COORDINATE_SIZE);
    }
    if (ret == 0)
    {
      ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, hash_len, mbedtls_ctr_drbg_random, global_rng.context());
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_write_binary(&r, signature, P521_COORDINATE_SIZE);
    }
    if (ret == 0)
    {
      ret = mbedtls_mpi_write_binary(&s, signature + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return (ret == 0);
  }
};

// --- AES-GCM Operations ---
class AESGCM
{
public:
  static bool encrypt(uint8_t *plaintext, size_t len, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len,
                      uint8_t *tag)
  {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
    if (ret == 0)
    {
      ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len, iv, iv_len,
                                      aad, aad_len, plaintext, plaintext, GCM_TAG_SIZE, tag);
    }

    mbedtls_gcm_free(&ctx);
    return (ret == 0);
  }

  static bool decrypt(uint8_t *ciphertext, size_t len, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len,
                      const uint8_t *tag)
  {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
    if (ret == 0)
    {
      ret = mbedtls_gcm_auth_decrypt(&ctx, len, iv, iv_len, aad, aad_len, tag, GCM_TAG_SIZE,
                                     ciphertext, ciphertext);
    }

    mbedtls_gcm_free(&ctx);
    return (ret == 0);
  }
};

// --- PBKDF2 ---
class PBKDF2
{
public:
  static int derive_key(uint8_t *output, size_t key_len, const char *password,
                        const uint8_t *salt, size_t salt_len, int iterations)
  {
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                         (const uint8_t *)password, strlen(password),
                                         salt, salt_len, iterations, key_len, output);
  }
};

// --- Concat KDF (for JWE) ---
static void write_be32(uint8_t *buf, uint32_t val)
{
  buf[0] = (val >> 24) & 0xFF;
  buf[1] = (val >> 16) & 0xFF;
  buf[2] = (val >> 8) & 0xFF;
  buf[3] = val & 0xFF;
}

static void concat_kdf(uint8_t *output, size_t output_len, const uint8_t *shared_secret,
                       size_t secret_len, const char *alg_id, size_t alg_id_len)
{
  mbedtls_sha256_context ctx;
  uint8_t counter[4], field_len[4];
  const uint8_t zeros[4] = {0};
  uint8_t digest[32];

  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);

  write_be32(counter, 1);
  mbedtls_sha256_update(&ctx, counter, sizeof(counter));
  mbedtls_sha256_update(&ctx, shared_secret, secret_len);

  write_be32(field_len, alg_id_len);
  mbedtls_sha256_update(&ctx, field_len, sizeof(field_len));
  mbedtls_sha256_update(&ctx, (const uint8_t *)alg_id, alg_id_len);

  mbedtls_sha256_update(&ctx, zeros, sizeof(zeros));
  mbedtls_sha256_update(&ctx, zeros, sizeof(zeros));

  write_be32(field_len, output_len * 8);
  mbedtls_sha256_update(&ctx, field_len, sizeof(field_len));

  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);

  memcpy(output, digest, output_len);
  memset(digest, 0, sizeof(digest));
}

#endif // CRYPTO_H
