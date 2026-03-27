#ifndef PROVISION_H
#define PROVISION_H

#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_hmac.h>
#include <esp_log.h>
#include <esp_random.h>
#include <string.h>

static const char *TAG_PROVISION = "provision";

/**
 * Read the purpose of EFUSE BLOCK_KEY5.
 * Returns ESP_EFUSE_KEY_PURPOSE_MAX on read failure.
 */
esp_efuse_purpose_t get_efuse_key5_purpose() {
  esp_efuse_purpose_t purpose;
  esp_err_t err = esp_efuse_read_field_blob(ESP_EFUSE_KEY_PURPOSE_5, &purpose,
                                            sizeof(purpose) * 8);
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "Failed to read KEY_PURPOSE_5: %s",
             esp_err_to_name(err));
    return ESP_EFUSE_KEY_PURPOSE_MAX;
  }
  return purpose;
}

/**
 * Check if EFUSE BLOCK_KEY5 is unused (available for provisioning).
 */
bool is_efuse_key5_free() {
  esp_efuse_purpose_t purpose = get_efuse_key5_purpose();
  if (purpose == ESP_EFUSE_KEY_PURPOSE_MAX)
    return false; // read failed — treat as not free
  ESP_LOGI(TAG_PROVISION, "EFUSE KEY_PURPOSE_5: %d (0=NONE/unused)", purpose);
  return (purpose == ESP_EFUSE_KEY_PURPOSE_USER);
}

/**
 * Check if EFUSE BLOCK_KEY5 is correctly provisioned for HMAC upstream.
 */
bool is_efuse_key5_hmac_up() {
  esp_efuse_purpose_t purpose = get_efuse_key5_purpose();
  if (purpose == ESP_EFUSE_KEY_PURPOSE_MAX)
    return false;
  return (purpose == ESP_EFUSE_KEY_PURPOSE_HMAC_UP);
}

/**
 * Provision a random 256-bit HMAC key to EFUSE BLOCK_KEY5.
 * Called once on first boot. The key is never readable by software afterwards;
 * only the HMAC peripheral can use it.
 */
bool provision_efuse_key5() {
  ESP_LOGI(TAG_PROVISION, "=== Starting EFUSE KEY5 Provisioning ===");

  if (!is_efuse_key5_free()) {
    esp_efuse_purpose_t cur = get_efuse_key5_purpose();
    ESP_LOGW(TAG_PROVISION,
             "EFUSE KEY5 is already programmed (purpose=%d)", (int)cur);
    return false;
  }

  uint8_t hmac_key[32];
  esp_fill_random(hmac_key, sizeof(hmac_key));

  ESP_LOGI(TAG_PROVISION, "Writing random HMAC key to BLOCK_KEY5...");
  esp_err_t err =
      esp_efuse_write_key(EFUSE_BLK_KEY5, ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
                          hmac_key, sizeof(hmac_key));

  memset(hmac_key, 0, sizeof(hmac_key));

  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "Failed to write EFUSE KEY5: %s",
             esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "EFUSE KEY5 key data written");

  // Verify purpose is HMAC_UP
  if (!is_efuse_key5_hmac_up()) {
    ESP_LOGE(TAG_PROVISION,
             "Verification failed: KEY_PURPOSE_5 is not HMAC_UP");
    return false;
  }
  ESP_LOGI(TAG_PROVISION, "KEY_PURPOSE_5 set to HMAC_UP");

  // Verify all protections are set (esp_efuse_write_key sets them for HMAC_UP,
  // but we check defensively to ensure the key is truly locked down).

  // Read protection — software cannot read the key back; only HMAC peripheral
  if (!esp_efuse_get_key_dis_read(EFUSE_BLK_KEY5)) {
    ESP_LOGE(TAG_PROVISION, "BLOCK_KEY5 read protection NOT set — aborting");
    return false;
  }
  ESP_LOGI(TAG_PROVISION, "BLOCK_KEY5 read-protected (locked)");

  // Write protection — key cannot be overwritten
  if (!esp_efuse_get_key_dis_write(EFUSE_BLK_KEY5)) {
    ESP_LOGE(TAG_PROVISION, "BLOCK_KEY5 write protection NOT set — aborting");
    return false;
  }
  ESP_LOGI(TAG_PROVISION, "BLOCK_KEY5 write-protected (locked)");

  // Key-purpose lock — purpose cannot be changed
  if (!esp_efuse_get_keypurpose_dis_write(EFUSE_BLK_KEY5)) {
    ESP_LOGE(TAG_PROVISION, "KEY_PURPOSE_5 lock NOT set — aborting");
    return false;
  }
  ESP_LOGI(TAG_PROVISION, "KEY_PURPOSE_5 locked");

  ESP_LOGI(TAG_PROVISION, "EFUSE KEY5 provisioned successfully!");
  return true;
}

/**
 * Derive AES-256 key using the hardware HMAC peripheral.
 * AES_key = HMAC_SHA256(efuse_key5, password_hash)
 *
 * Two-factor binding: password knowledge + device possession (eFuse key).
 */
bool derive_aes_key(const uint8_t *password_hash, uint8_t *aes_key_out) {
  esp_err_t err = esp_hmac_calculate(HMAC_KEY5, password_hash, 32, aes_key_out);
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "HMAC calculation failed: %s",
             esp_err_to_name(err));
    return false;
  }
  return true;
}

#endif // PROVISION_H
