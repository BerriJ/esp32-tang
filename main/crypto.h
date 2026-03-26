#ifndef CRYPTO_H
#define CRYPTO_H

#include <esp_log.h>
#include <esp_system.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

static const char *TAG_CRYPTO = "crypto";

// --- Constants ---

// P-256 uses 256 bits = 32 bytes per coordinate
const int P256_PRIVATE_KEY_SIZE = 32; // Scalar value
const int P256_PUBLIC_KEY_SIZE = 64;  // Uncompressed point (x + y)
const int P256_COORDINATE_SIZE = 32;  // Single coordinate (x or y)

// --- RNG Management ---
class RNG {
private:
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  bool initialized;

public:
  RNG() : initialized(false) {}

  ~RNG() { cleanup(); }

  int init() {
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

  void cleanup() {
    if (initialized) {
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      initialized = false;
    }
  }

  mbedtls_ctr_drbg_context *context() { return &ctr_drbg; }
};

// Global RNG instance
static RNG global_rng;

// --- P-256 EC Operations ---
class P256 {
public:
  static bool generate_keypair(uint8_t *pub_key, uint8_t *priv_key) {
    int ret = global_rng.init();
    if (ret != 0) {
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
    if (ret != 0) {
      ESP_LOGE(TAG_CRYPTO, "ECP group load failed: -0x%04x", -ret);
    } else {
      ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random,
                                    global_rng.context());
      if (ret != 0) {
        ESP_LOGE(TAG_CRYPTO, "ECP keypair gen failed: -0x%04x", -ret);
      }
    }
    if (ret == 0) {
      ret = mbedtls_mpi_write_binary(&d, priv_key, P256_COORDINATE_SIZE);
      if (ret != 0) {
        ESP_LOGE(TAG_CRYPTO, "Write private key failed: -0x%04x", -ret);
      }
    }
    if (ret == 0) {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_key,
                                     P256_COORDINATE_SIZE);
      if (ret != 0) {
        ESP_LOGE(TAG_CRYPTO, "Write pub key X failed: -0x%04x", -ret);
      }
    }
    if (ret == 0) {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y),
                                     pub_key + P256_COORDINATE_SIZE,
                                     P256_COORDINATE_SIZE);
      if (ret != 0) {
        ESP_LOGE(TAG_CRYPTO, "Write pub key Y failed: -0x%04x", -ret);
      }
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    return (ret == 0);
  }

  static bool compute_public_key(const uint8_t *priv_key, uint8_t *pub_key) {
    if (global_rng.init() != 0)
      return false;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
      ret = mbedtls_mpi_read_binary(&d, priv_key, P256_COORDINATE_SIZE);
    }
    if (ret == 0) {
      ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random,
                            global_rng.context());
    }
    if (ret == 0) {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_key,
                                     P256_COORDINATE_SIZE);
    }
    if (ret == 0) {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y),
                                     pub_key + P256_COORDINATE_SIZE,
                                     P256_COORDINATE_SIZE);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    return (ret == 0);
  }

  static bool ecdh_compute_shared_point(const uint8_t *peer_pub_key,
                                        const uint8_t *priv_key,
                                        uint8_t *shared_point,
                                        bool full_point = true) {
    if (global_rng.init() != 0)
      return false;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
      ret = mbedtls_mpi_read_binary(&d, priv_key, P256_COORDINATE_SIZE);
    }
    if (ret == 0) {
      ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), peer_pub_key,
                                    P256_COORDINATE_SIZE);
    }
    if (ret == 0) {
      ret = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y),
                                    peer_pub_key + P256_COORDINATE_SIZE,
                                    P256_COORDINATE_SIZE);
    }
    if (ret == 0) {
      ret = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);
    }
    if (ret == 0) {
      ret = mbedtls_ecp_check_pubkey(&grp, &Q);
    }
    if (ret == 0) {
      ret = mbedtls_ecp_mul(&grp, &Q, &d, &Q, mbedtls_ctr_drbg_random,
                            global_rng.context());
    }
    if (ret == 0) {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), shared_point,
                                     P256_COORDINATE_SIZE);
    }
    if (ret == 0 && full_point) {
      ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y),
                                     shared_point + P256_COORDINATE_SIZE,
                                     P256_COORDINATE_SIZE);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

    return (ret == 0);
  }

  static bool sign(const uint8_t *hash, size_t hash_len,
                   const uint8_t *priv_key, uint8_t *signature) {
    if (global_rng.init() != 0)
      return false;

    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
      ret = mbedtls_mpi_read_binary(&d, priv_key, P256_COORDINATE_SIZE);
    }
    if (ret == 0) {
      ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, hash_len,
                               mbedtls_ctr_drbg_random, global_rng.context());
    }
    if (ret == 0) {
      ret = mbedtls_mpi_write_binary(&r, signature, P256_COORDINATE_SIZE);
    }
    if (ret == 0) {
      ret = mbedtls_mpi_write_binary(&s, signature + P256_COORDINATE_SIZE,
                                     P256_COORDINATE_SIZE);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return (ret == 0);
  }
};

#endif // CRYPTO_H
