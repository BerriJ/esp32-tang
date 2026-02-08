#ifndef JWE_H
#define JWE_H

#include <ArduinoJson.h>
#include "crypto.h"
#include "encoding.h"

// --- JWE Operations ---
class JWE
{
public:
  // Decrypt a JWE using ECDH-ES+A128GCM
  static bool decrypt_password(const JsonDocument &jwe_doc, const uint8_t *admin_priv_key,
                               char *password_out, size_t max_len)
  {
    // Extract ephemeral public key
    JsonObjectConst header = jwe_doc["header"];
    if (!header)
      return false;

    JsonObjectConst epk = header["epk"];
    if (!epk)
      return false;

    uint8_t eph_pub_key[P521_PUBLIC_KEY_SIZE];
    int x_len = Base64URL::decode(epk["x"].as<String>(), eph_pub_key, P521_COORDINATE_SIZE);
    int y_len = Base64URL::decode(epk["y"].as<String>(), eph_pub_key + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);

    if (x_len != P521_COORDINATE_SIZE || y_len != P521_COORDINATE_SIZE)
      return false;

    // Compute ECDH shared secret
    uint8_t shared_secret[P521_COORDINATE_SIZE];
    if (!P521::ecdh_compute_shared_point(eph_pub_key, admin_priv_key, shared_secret, false))
    {
      return false;
    }

    // Derive content encryption key using Concat KDF
    uint8_t cek[16];
    const char *enc_alg_id = "A128GCM";
    concat_kdf(cek, sizeof(cek), shared_secret, sizeof(shared_secret), enc_alg_id, strlen(enc_alg_id));

    // Extract IV, ciphertext, and tag
    uint8_t iv[12], tag[GCM_TAG_SIZE];
    Base64URL::decode(jwe_doc["iv"].as<String>(), iv, sizeof(iv));
    Base64URL::decode(jwe_doc["tag"].as<String>(), tag, sizeof(tag));

    // Decrypt ciphertext
    uint8_t ciphertext[65] = {0};
    int ct_len = Base64URL::decode(jwe_doc["ciphertext"].as<String>(), ciphertext, sizeof(ciphertext));
    if (ct_len < 0 || ct_len >= (int)max_len)
      return false;

    const char *protected_header = jwe_doc["protected"];
    if (!AESGCM::decrypt(ciphertext, ct_len, cek, sizeof(cek), iv, sizeof(iv),
                         (const uint8_t *)protected_header, strlen(protected_header), tag))
    {
      return false;
    }

    memcpy(password_out, ciphertext, ct_len);
    password_out[ct_len] = '\0';
    return true;
  }
};

#endif // JWE_H
