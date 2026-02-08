#ifndef TANG_STORAGE_H
#define TANG_STORAGE_H

#include <Preferences.h>
#include "crypto.h"
#include "encoding.h"

#ifndef DEBUG_PRINTLN
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#endif

// --- Key Storage & Management ---
class TangKeyStore
{
private:
  Preferences prefs;
  uint8_t salt[SALT_SIZE];

public:
  // Tang server keys (encrypted at rest, decrypted in memory when active)
  uint8_t sig_priv[P521_PRIVATE_KEY_SIZE];
  uint8_t sig_pub[P521_PUBLIC_KEY_SIZE];
  uint8_t exc_priv[P521_PRIVATE_KEY_SIZE];
  uint8_t exc_pub[P521_PUBLIC_KEY_SIZE];

  // Admin key (persistent)
  uint8_t admin_priv[P521_PRIVATE_KEY_SIZE];
  uint8_t admin_pub[P521_PUBLIC_KEY_SIZE];

  bool is_configured()
  {
    prefs.begin("tang-server", false); // Open in read-write mode to create if needed
    bool configured = prefs.isKey("admin_key");
    prefs.end();
    return configured;
  }

  bool load_admin_key()
  {
    prefs.begin("tang-server", false);

    size_t len = prefs.getBytes("admin_key", admin_priv, P521_PRIVATE_KEY_SIZE);
    bool success = (len == P521_PRIVATE_KEY_SIZE);

    if (success)
    {
      P521::compute_public_key(admin_priv, admin_pub);
      prefs.getBytes("salt", salt, SALT_SIZE);
    }

    prefs.end();
    return success;
  }

  bool save_admin_key()
  {
    prefs.begin("tang-server", false);

    // Generate and save salt
    esp_fill_random(salt, SALT_SIZE);
    prefs.putBytes("salt", salt, SALT_SIZE);

    // Save admin key
    prefs.putBytes("admin_key", admin_priv, P521_PRIVATE_KEY_SIZE);

    prefs.end();
    return true;
  }

  bool encrypt_and_save_tang_keys(const char *password)
  {
    prefs.begin("tang-server", false);

    // Derive key and encrypt signing key
    uint8_t encrypted_sig[P521_PRIVATE_KEY_SIZE];
    uint8_t sig_tag[GCM_TAG_SIZE];
    memcpy(encrypted_sig, sig_priv, P521_PRIVATE_KEY_SIZE);

    uint8_t key[16], iv[12] = {0};
    if (PBKDF2::derive_key(key, sizeof(key), password, salt, SALT_SIZE, PBKDF2_ITERATIONS) != 0)
    {
      prefs.end();
      return false;
    }

    if (!AESGCM::encrypt(encrypted_sig, P521_PRIVATE_KEY_SIZE, key, sizeof(key),
                         iv, sizeof(iv), nullptr, 0, sig_tag))
    {
      prefs.end();
      return false;
    }

    prefs.putBytes("tang_sig_key", encrypted_sig, P521_PRIVATE_KEY_SIZE);
    prefs.putBytes("tang_sig_tag", sig_tag, GCM_TAG_SIZE);

    // Encrypt and save exchange key
    uint8_t encrypted_exc[P521_PRIVATE_KEY_SIZE];
    uint8_t exc_tag[GCM_TAG_SIZE];
    memcpy(encrypted_exc, exc_priv, P521_PRIVATE_KEY_SIZE);

    if (!AESGCM::encrypt(encrypted_exc, P521_PRIVATE_KEY_SIZE, key, sizeof(key),
                         iv, sizeof(iv), nullptr, 0, exc_tag))
    {
      prefs.end();
      return false;
    }

    prefs.putBytes("tang_exc_key", encrypted_exc, P521_PRIVATE_KEY_SIZE);
    prefs.putBytes("tang_exc_tag", exc_tag, GCM_TAG_SIZE);

    prefs.end();
    return true;
  }

  bool decrypt_and_load_tang_keys(const char *password)
  {
    prefs.begin("tang-server", true);

    // Load salt
    prefs.getBytes("salt", salt, SALT_SIZE);

    // Derive key
    uint8_t key[16], iv[12] = {0};
    if (PBKDF2::derive_key(key, sizeof(key), password, salt, SALT_SIZE, PBKDF2_ITERATIONS) != 0)
    {
      prefs.end();
      return false;
    }

    // Load and decrypt signing key
    uint8_t encrypted_sig[P521_PRIVATE_KEY_SIZE];
    uint8_t sig_tag[GCM_TAG_SIZE];
    prefs.getBytes("tang_sig_key", encrypted_sig, P521_PRIVATE_KEY_SIZE);
    prefs.getBytes("tang_sig_tag", sig_tag, GCM_TAG_SIZE);

    if (!AESGCM::decrypt(encrypted_sig, P521_PRIVATE_KEY_SIZE, key, sizeof(key),
                         iv, sizeof(iv), nullptr, 0, sig_tag))
    {
      prefs.end();
      return false;
    }
    memcpy(sig_priv, encrypted_sig, P521_PRIVATE_KEY_SIZE);
    P521::compute_public_key(sig_priv, sig_pub);

    // Load and decrypt exchange key
    uint8_t encrypted_exc[P521_PRIVATE_KEY_SIZE];
    uint8_t exc_tag[GCM_TAG_SIZE];
    prefs.getBytes("tang_exc_key", encrypted_exc, P521_PRIVATE_KEY_SIZE);
    prefs.getBytes("tang_exc_tag", exc_tag, GCM_TAG_SIZE);

    if (!AESGCM::decrypt(encrypted_exc, P521_PRIVATE_KEY_SIZE, key, sizeof(key),
                         iv, sizeof(iv), nullptr, 0, exc_tag))
    {
      prefs.end();
      return false;
    }
    memcpy(exc_priv, encrypted_exc, P521_PRIVATE_KEY_SIZE);
    P521::compute_public_key(exc_priv, exc_pub);

    prefs.end();
    return true;
  }

  void clear_tang_keys()
  {
    memset(sig_priv, 0, P521_PRIVATE_KEY_SIZE);
    memset(sig_pub, 0, P521_PUBLIC_KEY_SIZE);
    memset(exc_priv, 0, P521_PRIVATE_KEY_SIZE);
    memset(exc_pub, 0, P521_PUBLIC_KEY_SIZE);
  }

  void nuke()
  {
    prefs.begin("tang-server", false);
    prefs.clear();
    prefs.end();
  }
};

#endif // TANG_STORAGE_H
