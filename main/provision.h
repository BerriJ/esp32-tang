#ifndef PROVISION_H
#define PROVISION_H

#include "tang_tee_service.h"
#include <esp_log.h>

static const char *TAG_PROVISION = "provision";

/**
 * Check if EFUSE BLOCK_KEY5 is correctly provisioned for HMAC upstream.
 * Queries TEE since eFuse controller is TEE-protected.
 */
bool is_efuse_key5_hmac_up() {
  uint32_t status = 0;
  esp_err_t err = tang_tee_efuse_status(&status);
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "TEE efuse status query failed: %s",
             esp_err_to_name(err));
    return false;
  }
  return (status == TEE_EFUSE_STATUS_PROVISIONED);
}

/**
 * Check if EFUSE BLOCK_KEY5 is unused (available for provisioning).
 */
bool is_efuse_key5_free() {
  uint32_t status = 0;
  esp_err_t err = tang_tee_efuse_status(&status);
  if (err != ESP_OK)
    return false;
  return (status == TEE_EFUSE_STATUS_FREE);
}

/**
 * Provision a random 256-bit HMAC key to EFUSE BLOCK_KEY5 via TEE.
 * Called once on first boot.
 */
bool provision_efuse_key5() {
  ESP_LOGI(TAG_PROVISION, "=== Starting EFUSE KEY5 Provisioning via TEE ===");

  esp_err_t err = tang_tee_provision_efuse();
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "TEE efuse provisioning failed: %s",
             esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG_PROVISION, "EFUSE KEY5 provisioned successfully via TEE!");
  return true;
}

#endif // PROVISION_H
