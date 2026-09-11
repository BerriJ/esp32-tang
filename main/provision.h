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
 * Burn a random 256-bit HMAC key to eFuse KEY5 via TEE.
 * No-op if KEY5 is already HMAC_UP.
 */
bool provision_efuse_key5() {
  esp_err_t err = tang_tee_provision_efuse();
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "eFuse KEY5 provisioning failed: %s",
             esp_err_to_name(err));
    return false;
  }
  return true;
}

/**
 * Check if EFUSE BLOCK_KEY4 is correctly provisioned for ECDSA key.
 */
bool is_efuse_key4_ecdsa() {
  uint32_t status = 0;
  esp_err_t err = tang_tee_efuse_ecdsa_status(&status);
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "TEE efuse KEY4 status query failed: %s",
             esp_err_to_name(err));
    return false;
  }
  return (status == TEE_EFUSE_STATUS_PROVISIONED);
}

/**
 * Check if EFUSE BLOCK_KEY4 is unused.
 */
bool is_efuse_key4_free() {
  uint32_t status = 0;
  esp_err_t err = tang_tee_efuse_ecdsa_status(&status);
  if (err != ESP_OK)
    return false;
  return (status == TEE_EFUSE_STATUS_FREE);
}

/**
 * Burn a random 256-bit ECDSA key to eFuse KEY4 via TEE.
 */
bool provision_efuse_key4() {
  esp_err_t err = tang_tee_provision_efuse_ecdsa();
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "eFuse KEY4 provisioning failed: %s",
             esp_err_to_name(err));
    return false;
  }
  return true;
}

/**
 * Ensure tee_salt exists in TEE Secure Storage.
 * Generates a random salt if missing (e.g. after re-flash), no-op otherwise.
 */
bool ensure_tee_salt() {
  esp_err_t err = tang_tee_ensure_tee_salt();
  if (err != ESP_OK) {
    ESP_LOGE(TAG_PROVISION, "TEE salt initialization failed: %s",
             esp_err_to_name(err));
    return false;
  }
  return true;
}

#endif // PROVISION_H
