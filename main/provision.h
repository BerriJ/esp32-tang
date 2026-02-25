#ifndef PROVISION_H
#define PROVISION_H

#include "cryptoauthlib.h"
#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_log.h>

static const char *TAG_PROVISION = "provision";

// Hardcoded HMAC key for prototyping (32 bytes)
// WARNING: This is for prototyping only! In production, this should be securely
// generated
static const uint8_t IO_KEY[32] = {
    0x2c, 0x43, 0x34, 0x9c, 0x4c, 0xe6, 0x70, 0xf3, 0xcb, 0x10, 0xef,
    0xcc, 0x56, 0xf0, 0xd0, 0xc4, 0x03, 0x2c, 0x45, 0x9f, 0xf3, 0xcb,
    0x29, 0x27, 0x22, 0x8e, 0x93, 0x3c, 0xfe, 0x6e, 0x87, 0xed};

static const uint8_t HMAC_KEY[32] = {
    0x24, 0x01, 0x2a, 0xf7, 0x3e, 0x62, 0x7a, 0x5e, 0x5e, 0xdc, 0xf0,
    0xce, 0xd6, 0xe5, 0x32, 0x20, 0x56, 0xca, 0x29, 0xd1, 0x52, 0xf8,
    0x17, 0x23, 0x06, 0x75, 0x4f, 0x1d, 0xb9, 0x85, 0x51, 0x5e};

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

  // 2. Write Symmetric Keys (Slots 6, 10, 13)
  ESP_LOGI(TAG_PROVISION, "Writing IO_KEY to Slot 6...");
  status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 6, 0, IO_KEY, 32);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed Slot 6: 0x%02X", status);
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "Writing HMAC_KEY to Slot 10...");
  status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 10, 0, HMAC_KEY, 32);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed Slot 10: 0x%02X", status);
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "Writing HMAC_KEY to Slot 13...");
  status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 13, 0, HMAC_KEY, 32);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_PROVISION, "Failed Slot 13: 0x%02X", status);
    return false;
  }

  // 3. Write ECC Public Key to Slot 9
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

  // 4. Generate Random ECC Private Keys (Slots 0-5, 11, 12)
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

  // 5. Lock the Data Zone
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
 * Provision the ESP32-C6 efuse BLOCK_KEY5 with hardcoded HMAC key
 * Returns: true on success, false on failure
 */
bool provision_efuse_key5() {
  ESP_LOGI(TAG_PROVISION, "=== Starting EFUSE KEY5 Provisioning ===");

  // Check if already used
  if (is_efuse_key5_used()) {
    ESP_LOGW(TAG_PROVISION, "EFUSE KEY5 is already used!");
    return false;
  }

  // Write the HMAC key to BLOCK_KEY5
  ESP_LOGI(TAG_PROVISION, "Writing HMAC key to BLOCK_KEY5...");
  esp_err_t err =
      esp_efuse_write_key(EFUSE_BLK_KEY5, ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
                          HMAC_KEY, sizeof(HMAC_KEY));

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
