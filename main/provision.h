#ifndef PROVISION_H
#define PROVISION_H

#include "crypto.h"
#include "cryptoauthlib.h"
#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_hmac.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_random.h>

static const char *TAG_PROVISION = "provision";

// IO Protection Key for ATECC608B (32 bytes)
static const uint8_t IO_KEY[32] = {
    0x2c, 0x43, 0x34, 0x9c, 0x4c, 0xe6, 0x70, 0xf3, 0xcb, 0x10, 0xef,
    0xcc, 0x56, 0xf0, 0xd0, 0xc4, 0x03, 0x2c, 0x45, 0x9f, 0xf3, 0xcb,
    0x29, 0x27, 0x22, 0x8e, 0x93, 0x3c, 0xfe, 0x6e, 0x87, 0xed};

// Default initial password — must be changed after first provisioning.
static const char *PROVISION_DEFAULT_PASSWORD = "changeme";

// Must match the iteration count used by the web client (zk_web_page.h)
static const int PROVISION_PBKDF2_ITERATIONS = 10000;

/**
 * Run a 32-byte key through the ESP32-C6 HMAC hardware peripheral
 * using the bonding secret stored in eFuse BLOCK_KEY5.
 *
 * result = HMAC-SHA256(eFuse_KEY5, input_key)
 *
 * This creates a secure bond between the ESP32 chip and the ATECC608B:
 * only this specific ESP32 can reproduce the final key.
 *
 * @param input_key  32-byte input (e.g. PBKDF2 output)
 * @param out_key    32-byte output (the bonded key)
 * @return true on success
 */
bool bond_with_efuse_hmac(const uint8_t input_key[32], uint8_t out_key[32]) {
  esp_err_t err = esp_hmac_calculate(HMAC_KEY5, input_key, 32, out_key);
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "HMAC peripheral failed: %s", esp_err_to_name(err));
    return false;
  }
  return true;
}

/**
 * Derive the final authentication key from a password.
 *
 * Two-stage derivation that bonds the password to this specific ESP32 chip:
 *   1) PBKDF2-HMAC-SHA256(password, salt=MAC_address, iterations=10000)
 *   2) HMAC-SHA256 via hardware peripheral using eFuse BLOCK_KEY5
 *
 * The web client performs step 1 and sends the intermediate key over the
 * ECIES tunnel.  The ESP32 then applies step 2 before comparing against
 * the ATECC608B (CheckMac).  During provisioning both steps run locally.
 *
 * @param password   Null-terminated password string
 * @param out_key    Buffer of at least 32 bytes to receive the final key
 * @return true on success
 */
bool derive_hmac_key(const char *password, uint8_t out_key[32]) {
  // Use the Wi-Fi STA MAC address as salt (same as web client)
  uint8_t mac[6];
  esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_STA);
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "Failed to read MAC address: %s",
             esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "Deriving HMAC key with PBKDF2 (salt=MAC, iter=%d)",
           PROVISION_PBKDF2_ITERATIONS);
  ESP_LOG_BUFFER_HEX(TAG_PROVISION, mac, sizeof(mac));

  // Stage 1: PBKDF2
  uint8_t intermediate[32];
  int ret = PBKDF2::derive_key(intermediate, 32, password, mac, sizeof(mac),
                               PROVISION_PBKDF2_ITERATIONS);
  if (ret != 0) {
    ESP_LOGE(TAG_PROVISION, "PBKDF2 derivation failed: -0x%04x", -ret);
    return false;
  }

  // Stage 2: Bond with eFuse BLOCK_KEY5 via hardware HMAC
  ESP_LOGI(TAG_PROVISION, "Bonding with eFuse HMAC peripheral...");
  if (!bond_with_efuse_hmac(intermediate, out_key)) {
    memset(intermediate, 0, 32);
    return false;
  }

  memset(intermediate, 0, 32);
  ESP_LOGI(TAG_PROVISION, "HMAC key derived and bonded successfully");
  return true;
}

// ATECC608B Configuration values
// SlotConfig (Bytes 20-51): 32 bytes for 16 slots (2 bytes each)
static const uint8_t ATECC_SLOT_CONFIG[32] = {
    0x81, 0x00, 0x81, 0x20, 0x81, 0x20, 0x81, 0x20, 0x84, 0x20, 0x84,
    0x20, 0xc6, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x9a, 0x4a,
    0x84, 0x20, 0x84, 0x20, 0x9a, 0x4a, 0x00, 0x00, 0x00, 0x00};

// KeyConfig (Bytes 96-127): 32 bytes for 16 slots (2 bytes each)
static const uint8_t ATECC_KEY_CONFIG[32] = {
    0x33, 0x00, 0x13, 0x00, 0xd3, 0x09, 0x93, 0x0a, 0x53, 0x00, 0x53,
    0x10, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x5c, 0x00,
    0x53, 0x00, 0x53, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00};

// Byte 69: Persistent Latch enabled with Keyslot 10
static const uint8_t ATECC_LAST_KEY_USE_10 = 0x8a;

// Bytes 90-91: IO Protection optional and Key is Slot 6
static const uint8_t ATECC_CHIP_OPTIONS[2] = {0x02, 0x60};

/**
 * Check if ATECC608B config zone is locked
 * Returns: true if locked, false if unlocked
 */
bool is_atecc608b_config_locked() {
  extern uint8_t g_atecc_config_data[128];
  extern bool g_atecc_config_valid;

  // Read config if not already read
  if (!g_atecc_config_valid) {
    extern bool atecc608B_read_config();
    if (!atecc608B_read_config()) {
      ESP_LOGE(TAG_PROVISION, "Failed to read ATECC608B config");
      return false; // Assume unlocked if we can't read
    }
  }

  // Byte 87: LockConfig (Config Zone Lock)
  // 0x00 = LOCKED, any other value = UNLOCKED
  bool locked = (g_atecc_config_data[87] == 0x00);
  ESP_LOGI(TAG_PROVISION, "ATECC608B Config Zone: %s (0x%02X)",
           locked ? "LOCKED" : "UNLOCKED", g_atecc_config_data[87]);
  return locked;
}

/**
 * Check if ATECC608B data zone is locked
 * Returns: true if locked, false if unlocked
 */
bool is_atecc608b_data_locked() {
  extern uint8_t g_atecc_config_data[128];
  extern bool g_atecc_config_valid;

  // Read config if not already read
  if (!g_atecc_config_valid) {
    extern bool atecc608B_read_config();
    if (!atecc608B_read_config()) {
      ESP_LOGE(TAG_PROVISION, "Failed to read ATECC608B config");
      return false; // Assume unlocked if we can't read
    }
  }

  // Byte 86: LockValue (Data/OTP Zone Lock)
  // 0x00 = LOCKED, any other value = UNLOCKED
  bool locked = (g_atecc_config_data[86] == 0x00);
  ESP_LOGI(TAG_PROVISION, "ATECC608B Data Zone: %s (0x%02X)",
           locked ? "LOCKED" : "UNLOCKED", g_atecc_config_data[86]);
  return locked;
}

/**
 * Check if ESP32-C6 efuse BLOCK_KEY5 is already used
 * Returns: true if used, false if not used
 */
bool is_efuse_key5_used() {
  // Read the key purpose for BLOCK_KEY5
  esp_efuse_purpose_t purpose;
  esp_err_t err = esp_efuse_read_field_blob(ESP_EFUSE_KEY_PURPOSE_5, &purpose,
                                            sizeof(purpose) * 8);

  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "Failed to read KEY_PURPOSE_5: %s",
             esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "EFUSE KEY_PURPOSE_5: %d (0=NONE/unused)", purpose);

  // Purpose 0 (ESP_EFUSE_KEY_PURPOSE_USER) typically means unused/default
  // Any non-zero value means it's configured for something
  return (purpose != ESP_EFUSE_KEY_PURPOSE_USER);
}

/**
 * Provision the ATECC608B configuration and lock the config zone
 * Returns: true on success, false on failure
 */
bool provision_atecc608b_config() {
  ESP_LOGI(TAG_PROVISION,
           "=== Starting ATECC608B Configuration Provisioning ===");

  // Check if config zone is already locked
  if (is_atecc608b_config_locked()) {
    ESP_LOGW(TAG_PROVISION, "Config zone is already locked!");
    return false;
  }

  // Wake the device
  ATCA_STATUS status = atcab_wakeup();
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed to wake ATECC608B: 0x%02X", status);
    return false;
  }

  // 1. Ensure we have the current 128-byte config read into memory
  extern uint8_t g_atecc_config_data[128];
  extern bool g_atecc_config_valid;

  if (!g_atecc_config_valid) {
    ESP_LOGI(TAG_PROVISION, "Reading full config zone into memory...");
    status = atcab_read_config_zone(g_atecc_config_data);
    if (status != ATCA_SUCCESS) {
      ESP_LOGE(TAG_PROVISION, "Failed to read config zone: 0x%02X", status);
      return false;
    }
    g_atecc_config_valid = true;
  }

  // 2. Modify the in-memory array with our desired settings
  ESP_LOGI(TAG_PROVISION, "Applying configuration changes to memory...");
  memcpy(&g_atecc_config_data[20], ATECC_SLOT_CONFIG, 32); // SlotConfig
  g_atecc_config_data[69] = ATECC_LAST_KEY_USE_10;         // Persistent Latch
  memcpy(&g_atecc_config_data[90], ATECC_CHIP_OPTIONS, 2); // ChipOptions
  memcpy(&g_atecc_config_data[96], ATECC_KEY_CONFIG, 32);  // KeyConfig

  // 3. Write the whole modified config zone back to the device
  // atcab_write_config_zone safely skips the read-only bytes (0-15)
  ESP_LOGI(TAG_PROVISION, "Writing modified config zone back to ATECC608B...");
  status = atcab_write_config_zone(g_atecc_config_data);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed to write config zone: 0x%02X", status);
    return false;
  }
  ESP_LOGI(TAG_PROVISION, "Configuration written successfully");

  // 4. Lock the config zone
  ESP_LOGI(TAG_PROVISION, "Locking config zone...");
  status = atcab_lock_config_zone();
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed to lock config zone: 0x%02X", status);
    return false;
  }

  ESP_LOGI(TAG_PROVISION,
           "ATECC608B configuration provisioned and locked successfully!");

  // Invalidate cached config so it gets accurately re-read on next use
  g_atecc_config_valid = false;

  // Verify it was locked
  if (is_atecc608b_config_locked()) {
    ESP_LOGI(TAG_PROVISION, "Verification: Config zone is now locked");
    return true;
  } else {
    ESP_LOGE(TAG_PROVISION,
             "Verification failed: Config zone still appears unlocked");
    return false;
  }
}

/**
 * Provision the ATECC608B Data Zone with required keys
 * Returns: true on success, false on failure
 */
bool provision_atecc608b_data_zone() {
  ESP_LOGI(TAG_PROVISION, "=== Starting ATECC608B Data Zone Provisioning ===");

  // 1. Prerequisites check
  if (is_atecc608b_data_locked()) {
    ESP_LOGW(TAG_PROVISION,
             "Data zone is already locked! Cannot provision keys.");
    return false;
  }

  if (!is_atecc608b_config_locked()) {
    ESP_LOGE(TAG_PROVISION,
             "Config zone MUST be locked before generating keys (GenKey).");
    return false;
  }

  ATCA_STATUS status;

  // 2. Derive the HMAC key from the default password
  uint8_t hmac_key[32];
  if (!derive_hmac_key(PROVISION_DEFAULT_PASSWORD, hmac_key)) {
    ESP_LOGE(TAG_PROVISION, "Failed to derive HMAC key from password");
    return false;
  }

  // 3. Write Symmetric Keys (Slots 6, 10, 13)
  ESP_LOGI(TAG_PROVISION, "Writing IO_KEY to Slot 6...");
  status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 6, 0, IO_KEY, 32);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed Slot 6: 0x%02X", status);
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "Writing derived HMAC key to Slot 10...");
  status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 10, 0, hmac_key, 32);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed Slot 10: 0x%02X", status);
    memset(hmac_key, 0, 32);
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "Writing derived HMAC key to Slot 13...");
  status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 13, 0, hmac_key, 32);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed Slot 13: 0x%02X", status);
    memset(hmac_key, 0, 32);
    return false;
  }

  // Wipe the derived key from stack memory
  memset(hmac_key, 0, 32);

  // 4. Write ECC Public Key to Slot 9
  // Note: The 0x04 prefix byte is stripped. The ATECC608B expects exactly 64
  // bytes.
  static const uint8_t SLOT9_PUB_KEY[64] = {
      0x76, 0xc1, 0xa2, 0xe9, 0x63, 0xda, 0x58, 0x41, 0x12, 0x4e, 0xe7,
      0xc5, 0x3b, 0xeb, 0x2d, 0xad, 0x72, 0xf4, 0xc4, 0x61, 0xb8, 0x4a,
      0x65, 0xb7, 0xc7, 0x91, 0xdd, 0x59, 0xf9, 0x0a, 0xad, 0xf0, 0x6f,
      0x13, 0xf2, 0xb6, 0x29, 0x05, 0x4f, 0xab, 0x98, 0xdc, 0xfb, 0x93,
      0xab, 0xbd, 0x90, 0xd1, 0xea, 0x92, 0x91, 0x0a, 0xfe, 0x95, 0x7c,
      0xf6, 0xc7, 0x97, 0x41, 0x8e, 0x96, 0x6c, 0xaa, 0x15};

  ESP_LOGI(TAG_PROVISION, "Writing ECC Public Key to Slot 9...");
  status = atcab_write_pubkey(9, SLOT9_PUB_KEY);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed Slot 9: 0x%02X", status);
    return false;
  }

  // 5. Generate Random ECC Private Keys (Slots 0-5, 11, 12)
  uint8_t pubkey[64]; // Buffer to catch the generated public keys
  const uint8_t genkey_slots[] = {0, 1, 2, 3, 4, 5, 11, 12};

  for (int i = 0; i < sizeof(genkey_slots) / sizeof(genkey_slots[0]); i++) {
    uint8_t slot = genkey_slots[i];
    ESP_LOGI(TAG_PROVISION, "Generating ECC Private Key in Slot %d...", slot);

    status = atcab_genkey(slot, pubkey);
    if (status != ATCA_SUCCESS) {
      ESP_LOGE(TAG_PROVISION, "Failed GenKey Slot %d: 0x%02X", slot, status);
      return false;
    }

    ESP_LOGI(TAG_PROVISION, "Successfully generated Private Key in Slot %d.",
             slot);
    ESP_LOGI(TAG_PROVISION, "Corresponding Public Key (64 bytes):");

    // Standard ESP-IDF hex dump (good for reading)
    ESP_LOG_BUFFER_HEX(TAG_PROVISION, pubkey, sizeof(pubkey));

    // Continuous hex string (good for copy-pasting to host/scripts)
    printf("--> Copy this public key for Slot %d: 04",
           slot); // Prepending the 0x04 uncompressed prefix
    for (int j = 0; j < 64; j++) {
      printf("%02x", pubkey[j]);
    }
    printf("\n\n");
  }

  // 6. Lock the Data Zone
  ESP_LOGI(TAG_PROVISION, "Locking Data Zone...");
  status = atcab_lock_data_zone();
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed to lock Data Zone: 0x%02X", status);
    return false;
  }

  ESP_LOGI(TAG_PROVISION,
           "ATECC608B Data Zone provisioned and locked successfully!");
  return true;
}

/**
 * Check if provisioning is needed
 * Returns: true if any condition requires provisioning
 */
bool needs_provisioning() {
  bool config_unlocked = !is_atecc608b_config_locked();
  bool data_unlocked = !is_atecc608b_data_locked();
  bool key5_unused = !is_efuse_key5_used();

  ESP_LOGI(TAG_PROVISION, "Provisioning check:");
  ESP_LOGI(TAG_PROVISION, "  - Config unlocked: %s",
           config_unlocked ? "YES" : "NO");
  ESP_LOGI(TAG_PROVISION, "  - Data unlocked: %s",
           data_unlocked ? "YES" : "NO");
  ESP_LOGI(TAG_PROVISION, "  - KEY5 unused: %s", key5_unused ? "YES" : "NO");
  ESP_LOGI(TAG_PROVISION, "  - Needs provisioning: %s",
           (config_unlocked || data_unlocked || key5_unused) ? "YES" : "NO");

  return (config_unlocked || data_unlocked || key5_unused);
}

/**
 * Provision the ESP32-C6 efuse BLOCK_KEY5 with a random bonding secret.
 *
 * This key never leaves the eFuse and is only accessible to the HMAC
 * hardware peripheral.  It is used to create a secure bond between the
 * ESP32 chip and the ATECC608B: HMAC-SHA256(eFuse_key, PBKDF2_output)
 * produces a final key that only this specific ESP32 can reproduce.
 *
 * IMPORTANT: This must be called BEFORE provision_atecc608b_data_zone()
 * because the HMAC peripheral needs the eFuse key to derive the
 * authentication key that gets stored in the ATECC608B.
 *
 * Returns: true on success, false on failure
 */
bool provision_efuse_key5() {
  ESP_LOGI(TAG_PROVISION, "=== Starting EFUSE KEY5 Provisioning ===");

  // Check if already used
  if (is_efuse_key5_used()) {
    ESP_LOGW(TAG_PROVISION, "EFUSE KEY5 is already used!");
    return false;
  }

  // Generate a random 32-byte bonding secret
  uint8_t bonding_key[32];
  esp_fill_random(bonding_key, sizeof(bonding_key));

  // Write the random bonding key to BLOCK_KEY5 with HMAC_UP purpose
  ESP_LOGI(TAG_PROVISION, "Writing random bonding key to BLOCK_KEY5...");
  esp_err_t err =
      esp_efuse_write_key(EFUSE_BLK_KEY5, ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
                          bonding_key, sizeof(bonding_key));

  // Wipe the key from stack memory
  memset(bonding_key, 0, 32);

  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "Failed to write EFUSE KEY5: %s",
             esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "EFUSE KEY5 provisioned successfully!");
  ESP_LOGI(TAG_PROVISION, "Purpose set to: HMAC_UP");

  // Verify it was written
  if (is_efuse_key5_used()) {
    ESP_LOGI(TAG_PROVISION, "Verification: KEY5 is now marked as used");
    return true;
  } else {
    ESP_LOGE(TAG_PROVISION, "Verification failed: KEY5 still appears unused");
    return false;
  }
}

#endif // PROVISION_H
