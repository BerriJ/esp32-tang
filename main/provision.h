#ifndef PROVISION_H
#define PROVISION_H

#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_log.h>
#include "cryptoauthlib.h"

static const char *TAG_PROVISION = "provision";

// Hardcoded HMAC key for prototyping (32 bytes)
// WARNING: This is for prototyping only! In production, this should be securely generated
static const uint8_t HMAC_KEY[32] = {
    0x24, 0x01, 0x2a, 0xf7, 0x3e, 0x62, 0x7a, 0x5e,
    0x5e, 0xdc, 0xf0, 0xce, 0xd6, 0xe5, 0x32, 0x20,
    0x56, 0xca, 0x29, 0xd1, 0x52, 0xf8, 0x17, 0x23,
    0x06, 0x75, 0x4f, 0x1d, 0xb9, 0x85, 0x51, 0x5e};

/**
 * Check if ATECC608B config zone is locked
 * Returns: true if locked, false if unlocked
 */
bool is_atecc608b_config_locked()
{
  extern uint8_t g_atecc_config_data[128];
  extern bool g_atecc_config_valid;

  // Read config if not already read
  if (!g_atecc_config_valid)
  {
    extern bool atecc608B_read_config();
    if (!atecc608B_read_config())
    {
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
bool is_atecc608b_data_locked()
{
  extern uint8_t g_atecc_config_data[128];
  extern bool g_atecc_config_valid;

  // Read config if not already read
  if (!g_atecc_config_valid)
  {
    extern bool atecc608B_read_config();
    if (!atecc608B_read_config())
    {
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
bool is_efuse_key5_used()
{
  // Read the key purpose for BLOCK_KEY5
  esp_efuse_purpose_t purpose;
  esp_err_t err = esp_efuse_read_field_blob(ESP_EFUSE_KEY_PURPOSE_5, &purpose, sizeof(purpose) * 8);

  if (err != ESP_OK)
  {
    ESP_LOGE(TAG_PROVISION, "Failed to read KEY_PURPOSE_5: %s", esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "EFUSE KEY_PURPOSE_5: %d (0=NONE/unused)", purpose);

  // Purpose 0 (ESP_EFUSE_KEY_PURPOSE_USER) typically means unused/default
  // Any non-zero value means it's configured for something
  return (purpose != ESP_EFUSE_KEY_PURPOSE_USER);
}

/**
 * Check if provisioning is needed
 * Returns: true if any condition requires provisioning
 */
bool needs_provisioning()
{
  bool config_unlocked = !is_atecc608b_config_locked();
  bool data_unlocked = !is_atecc608b_data_locked();
  bool key5_unused = !is_efuse_key5_used();

  ESP_LOGI(TAG_PROVISION, "Provisioning check:");
  ESP_LOGI(TAG_PROVISION, "  - Config unlocked: %s", config_unlocked ? "YES" : "NO");
  ESP_LOGI(TAG_PROVISION, "  - Data unlocked: %s", data_unlocked ? "YES" : "NO");
  ESP_LOGI(TAG_PROVISION, "  - KEY5 unused: %s", key5_unused ? "YES" : "NO");
  ESP_LOGI(TAG_PROVISION, "  - Needs provisioning: %s",
           (config_unlocked || data_unlocked || key5_unused) ? "YES" : "NO");

  return (config_unlocked || data_unlocked || key5_unused);
}

/**
 * Provision the ESP32-C6 efuse BLOCK_KEY5 with hardcoded HMAC key
 * Returns: true on success, false on failure
 */
bool provision_efuse_key5()
{
  ESP_LOGI(TAG_PROVISION, "=== Starting EFUSE KEY5 Provisioning ===");

  // Check if already used
  if (is_efuse_key5_used())
  {
    ESP_LOGW(TAG_PROVISION, "EFUSE KEY5 is already used!");
    return false;
  }

  // Write the HMAC key to BLOCK_KEY5
  ESP_LOGI(TAG_PROVISION, "Writing HMAC key to BLOCK_KEY5...");
  esp_err_t err = esp_efuse_write_key(EFUSE_BLK_KEY5, ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
                                      HMAC_KEY, sizeof(HMAC_KEY));

  if (err != ESP_OK)
  {
    ESP_LOGE(TAG_PROVISION, "Failed to write EFUSE KEY5: %s", esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "EFUSE KEY5 provisioned successfully!");
  ESP_LOGI(TAG_PROVISION, "Purpose set to: HMAC_UP");

  // Verify it was written
  if (is_efuse_key5_used())
  {
    ESP_LOGI(TAG_PROVISION, "Verification: KEY5 is now marked as used");
    return true;
  }
  else
  {
    ESP_LOGE(TAG_PROVISION, "Verification failed: KEY5 still appears unused");
    return false;
  }
}

#endif // PROVISION_H
