#ifndef ATECC608B_H
#define ATECC608B_H

#include "cryptoauthlib.h"
#include "sdkconfig.h"
#include <cJSON.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG_ATECC = "ATECC608B";

// ATECC608B Configuration
ATCAIfaceCfg atecc_cfg;

bool atecc608B_init() {
  ESP_LOGI(TAG_ATECC, "\n=== ATECC608B Initialization ===");

  // Configure cryptoauthlib for ATECC608B - it will handle I2C initialization
  atecc_cfg.iface_type = ATCA_I2C_IFACE;
  atecc_cfg.devtype = ATECC608B;
  atecc_cfg.atcai2c.address = CONFIG_ATCA_I2C_ADDRESS;
  atecc_cfg.atcai2c.bus = 0; // I2C bus number
  atecc_cfg.atcai2c.baud = CONFIG_ATCA_I2C_BAUD_RATE;
  atecc_cfg.wake_delay = 1500;
  atecc_cfg.rx_retries = 20;

  ESP_LOGI(TAG_ATECC,
           "Configuring ATECC608B: SDA=GPIO%d, SCL=GPIO%d, Address=0x%02X "
           "(7-bit: 0x%02X)",
           CONFIG_ATCA_I2C_SDA_PIN, CONFIG_ATCA_I2C_SCL_PIN,
           CONFIG_ATCA_I2C_ADDRESS, CONFIG_ATCA_I2C_ADDRESS >> 1);

  // Initialize cryptoauthlib (it will initialize I2C internally)
  ATCA_STATUS status = atcab_init(&atecc_cfg);
  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_ATECC, "ERROR: atcab_init failed with status 0x%02X", status);
    return false;
  }

  ESP_LOGI(TAG_ATECC, "ATECC608B initialized successfully");

  // Give the device a moment to stabilize
  vTaskDelay(pdMS_TO_TICKS(100));

  // Wake the device and test communication
  status = atcab_wakeup();
  if (status != ATCA_SUCCESS) {
    ESP_LOGW(TAG_ATECC, "WARNING: Wake command returned status 0x%02X", status);
  }

  // Put device to idle
  atcab_idle();

  vTaskDelay(pdMS_TO_TICKS(50));

  return true;
}

// Global storage for config zone data
uint8_t g_atecc_config_data[128] = {0};
bool g_atecc_config_valid = false;

/**
 * Read ATECC608B configuration zone into global buffer
 */
bool atecc608B_read_config() {
  ESP_LOGI(TAG_ATECC, "Reading ATECC608B configuration zone...");

  ATCA_STATUS status = atcab_read_config_zone(g_atecc_config_data);

  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_ATECC, "ERROR: Failed to read config zone, status 0x%02X",
             status);

    // Try reading it in blocks as a workaround
    ESP_LOGI(TAG_ATECC, "Attempting to read config in 4-byte blocks...");
    bool read_success = true;
    for (uint8_t block = 0; block < 32; block++) {
      status = atcab_read_zone(ATCA_ZONE_CONFIG, 0, block, 0,
                               &g_atecc_config_data[block * 4], 4);
      if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG_ATECC, "ERROR: Failed to read block %d, status 0x%02X",
                 block, status);
        read_success = false;
        break;
      }
    }

    if (!read_success) {
      ESP_LOGE(TAG_ATECC, "ERROR: Could not read configuration zone");
      g_atecc_config_valid = false;
      return false;
    }
    ESP_LOGI(TAG_ATECC, "Successfully read config in blocks");
  }

  g_atecc_config_valid = true;
  return true;
}

/**
 * Print ATECC608B configuration zone to console with detailed subzone breakdown
 * According to ATECC608B Table 2-4
 */
void atecc608B_print_config() {
  ESP_LOGI(TAG_ATECC, "\n=== ATECC608B Configuration Zone ===");

  // First, try to read the serial number as a simple communication test
  uint8_t serial_number[9];
  ATCA_STATUS status = atcab_read_serial_number(serial_number);

  if (status != ATCA_SUCCESS) {
    ESP_LOGE(TAG_ATECC, "ERROR: Failed to read serial number, status 0x%02X",
             status);
    ESP_LOGE(TAG_ATECC, "This might indicate a communication or wiring issue.");
    return;
  }

  // Read configuration zone into global buffer
  if (!atecc608B_read_config()) {
    return;
  }

  uint8_t *config_data = g_atecc_config_data;

  // Print complete hex dump first
  ESP_LOGI(TAG_ATECC, "\n--- Complete Configuration Zone (128 bytes) ---");
  for (int i = 0; i < 128; i++) {
    if (i % 16 == 0) {
      printf("\n0x%02X: ", i);
    }
    printf("%02X ", config_data[i]);
  }
  printf("\n");

  // Print detailed subzone breakdown according to Table 2-4
  ESP_LOGI(TAG_ATECC, "\n--- Subzone Breakdown (Table 2-4) ---");

  // Bytes 0-3: Serial Number[0:3]
  printf("\n[Bytes 0-3] Serial Number[0:3]: ");
  for (int i = 0; i < 4; i++)
    printf("%02X ", config_data[i]);
  printf("\n");

  // Bytes 4-7: Revision Number
  printf("[Bytes 4-7] Revision Number: ");
  for (int i = 4; i < 8; i++)
    printf("%02X ", config_data[i]);
  printf("\n");

  // Bytes 8-12: Serial Number[4:8]
  printf("[Bytes 8-12] Serial Number[4:8]: ");
  for (int i = 8; i < 13; i++)
    printf("%02X ", config_data[i]);
  printf("\n");

  // Full Serial Number
  printf("  --> Complete Serial Number: ");
  for (int i = 0; i < 4; i++)
    printf("%02X", config_data[i]);
  for (int i = 8; i < 13; i++)
    printf("%02X", config_data[i]);
  printf("\n");

  // Byte 13: Reserved
  printf("[Byte 13] Reserved: %02X\n", config_data[13]);

  // Byte 14: I2C_Enable
  printf("[Byte 14] I2C_Enable: %02X\n", config_data[14]);

  // Byte 15: Reserved
  printf("[Byte 15] Reserved: %02X\n", config_data[15]);

  // Byte 16: I2C_Address
  printf("[Byte 16] I2C_Address: 0x%02X (7-bit: 0x%02X)\n", config_data[16],
         config_data[16] >> 1);

  // Byte 17: Reserved
  printf("[Byte 17] Reserved: %02X\n", config_data[17]);

  // Byte 18: OTPmode
  printf("[Byte 18] OTPmode: 0x%02X\n", config_data[18]);

  // Byte 19: ChipMode
  printf("[Byte 19] ChipMode: 0x%02X ", config_data[19]);
  if (config_data[19] & 0x01)
    printf("[I2C_UserExtraAdd] ");
  if (config_data[19] & 0x02)
    printf("[TTL_Enable] ");
  if (config_data[19] & 0x04)
    printf("[Watchdog_1.3s] ");
  printf("\n");

  // Bytes 20-51: SlotConfig[0:15] (16 slots × 2 bytes)
  printf("\n[Bytes 20-51] SlotConfig[0:15]:\n");
  for (int slot = 0; slot < 16; slot++) {
    int offset = 20 + (slot * 2);
    uint8_t slot_config_low = config_data[offset];
    uint8_t slot_config_high = config_data[offset + 1];
    uint16_t slot_config = (slot_config_high << 8) | slot_config_low;
    printf("  Slot %2d [Bytes %2d-%2d]: 0x%02X 0x%02X (", slot, offset,
           offset + 1, slot_config_low, slot_config_high);

    // Print 16-bit binary representation
    for (int b = 15; b >= 0; b--)
      printf("%d", (slot_config >> b) & 1);
    printf(")");

    bool is_secret = (slot_config & 0x8000) != 0;
    bool encrypt_read = (slot_config & 0x4000) != 0;
    if (is_secret)
      printf(" [Secret]");
    if (encrypt_read)
      printf(" [EncryptRead]");
    printf("\n");
  }

  // Bytes 52-59: Counter[0]
  printf("\n[Bytes 52-59] Counter[0]: ");
  for (int i = 52; i < 60; i++)
    printf("%02X ", config_data[i]);
  printf("\n");

  // Bytes 60-67: Counter[1]
  printf("[Bytes 60-67] Counter[1]: ");
  for (int i = 60; i < 68; i++)
    printf("%02X ", config_data[i]);
  printf("\n");

  // Bytes 68-83: LastKeyUse[0:15]
  printf("\n[Bytes 68-83] LastKeyUse[0:15]: ");
  for (int i = 68; i < 84; i++)
    printf("%02X ", config_data[i]);
  printf("\n");

  // Byte 84: UserExtra
  printf("\n[Byte 84] UserExtra: 0x%02X\n", config_data[84]);

  // Byte 85: Selector
  printf("[Byte 85] Selector: 0x%02X\n", config_data[85]);

  // Byte 86: LockValue (Data/OTP Zone Lock)
  printf("[Byte 86] LockValue (Data/OTP): 0x%02X %s\n", config_data[86],
         config_data[86] == 0x00 ? "[LOCKED]" : "[UNLOCKED]");

  // Byte 87: LockConfig (Config Zone Lock)
  printf("[Byte 87] LockConfig: 0x%02X %s\n", config_data[87],
         config_data[87] == 0x00 ? "[LOCKED]" : "[UNLOCKED]");

  // Bytes 88-89: SlotLocked
  printf("\n[Bytes 88-89] SlotLocked: %02X %02X\n", config_data[88],
         config_data[89]);

  // Bytes 90-91: ChipOptions
  printf("[Bytes 90-91] ChipOptions: ");
  uint16_t chip_options = (config_data[91] << 8) | config_data[90];
  printf("0x%04X\n", chip_options);

  // Bytes 92-95: X509format
  printf("[Bytes 92-95] X509format: ");
  for (int i = 92; i < 96; i++)
    printf("%02X ", config_data[i]);
  printf("\n");

  // Bytes 96-127: KeyConfig[0:15] (16 slots × 2 bytes)
  printf("\n[Bytes 96-127] KeyConfig[0:15]:\n");
  for (int slot = 0; slot < 16; slot++) {
    int offset = 96 + (slot * 2);
    uint8_t key_config_low = config_data[offset];
    uint8_t key_config_high = config_data[offset + 1];
    uint16_t key_config = (key_config_high << 8) | key_config_low;
    printf("  Slot %2d [Bytes %2d-%2d]: 0x%02X 0x%02X (", slot, offset,
           offset + 1, key_config_low, key_config_high);

    // Print 16-bit binary representation
    for (int b = 15; b >= 0; b--)
      printf("%d", (key_config >> b) & 1);
    printf(")");

    bool is_private = (key_config & 0x0001) != 0;
    if (is_private)
      printf(" [Private]");
    printf("\n");
  }

  ESP_LOGI(TAG_ATECC, "\n=== End of ATECC608B Configuration ===\n");
}

/**
 * Get ATECC608B configuration as JSON string (caller must free the returned
 * string)
 */
char *atecc608B_get_config_json() {
  if (!g_atecc_config_valid) {
    ESP_LOGE(TAG_ATECC,
             "Config data not valid. Call atecc608B_print_config() first.");
    return NULL;
  }

  uint8_t *config = g_atecc_config_data;

  cJSON *root = cJSON_CreateObject();

  // Add raw hex data
  char hex_str[385]; // 128 bytes * 3 chars per byte + null
  char *ptr = hex_str;
  for (int i = 0; i < 128; i++) {
    ptr += sprintf(ptr, "%02X ", config[i]);
  }
  cJSON_AddStringToObject(root, "raw_hex", hex_str);

  // Serial Number
  char serial_str[19];
  sprintf(serial_str, "%02X%02X%02X%02X%02X%02X%02X%02X%02X", config[0],
          config[1], config[2], config[3], config[8], config[9], config[10],
          config[11], config[12]);
  cJSON_AddStringToObject(root, "serial_number", serial_str);

  // Revision
  char revision_str[12];
  sprintf(revision_str, "%02X%02X%02X%02X", config[4], config[5], config[6],
          config[7]);
  cJSON_AddStringToObject(root, "revision", revision_str);

  // I2C settings
  cJSON_AddNumberToObject(root, "i2c_enable", config[14]);
  cJSON_AddNumberToObject(root, "i2c_address", config[16]);

  // Mode settings
  cJSON_AddNumberToObject(root, "otp_mode", config[18]);
  cJSON_AddNumberToObject(root, "chip_mode", config[19]);

  // Lock status
  cJSON *locks = cJSON_CreateObject();
  cJSON_AddBoolToObject(locks, "config_locked", config[87] == 0x00);
  cJSON_AddBoolToObject(locks, "data_otp_locked", config[86] == 0x00);
  cJSON_AddItemToObject(root, "locks", locks);

  // Slot configurations
  cJSON *slots = cJSON_CreateArray();
  for (int slot = 0; slot < 16; slot++) {
    cJSON *slot_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(slot_obj, "slot", slot);

    int slot_config_offset = 20 + (slot * 2);
    uint8_t slot_config_low = config[slot_config_offset];
    uint8_t slot_config_high = config[slot_config_offset + 1];
    uint16_t slot_config = (slot_config_high << 8) | slot_config_low;

    cJSON *slot_config_arr = cJSON_CreateArray();
    char slot_config_low_str[5];
    char slot_config_high_str[5];
    sprintf(slot_config_low_str, "0x%02X", slot_config_low);
    sprintf(slot_config_high_str, "0x%02X", slot_config_high);
    cJSON_AddItemToArray(slot_config_arr,
                         cJSON_CreateString(slot_config_low_str));
    cJSON_AddItemToArray(slot_config_arr,
                         cJSON_CreateString(slot_config_high_str));
    cJSON_AddItemToObject(slot_obj, "slot_config", slot_config_arr);

    // Add 16-bit binary representation
    char slot_config_bin[18];
    for (int b = 0; b < 16; b++) {
      slot_config_bin[15 - b] = ((slot_config >> b) & 1) ? '1' : '0';
    }
    slot_config_bin[16] = '\0';
    cJSON_AddStringToObject(slot_obj, "slot_config_binary", slot_config_bin);

    int key_config_offset = 96 + (slot * 2);
    uint8_t key_config_low = config[key_config_offset];
    uint8_t key_config_high = config[key_config_offset + 1];
    uint16_t key_config = (key_config_high << 8) | key_config_low;

    cJSON *key_config_arr = cJSON_CreateArray();
    char key_config_low_str[5];
    char key_config_high_str[5];
    sprintf(key_config_low_str, "0x%02X", key_config_low);
    sprintf(key_config_high_str, "0x%02X", key_config_high);
    cJSON_AddItemToArray(key_config_arr,
                         cJSON_CreateString(key_config_low_str));
    cJSON_AddItemToArray(key_config_arr,
                         cJSON_CreateString(key_config_high_str));
    cJSON_AddItemToObject(slot_obj, "key_config", key_config_arr);

    // Add 16-bit binary representation
    char key_config_bin[18];
    for (int b = 0; b < 16; b++) {
      key_config_bin[15 - b] = ((key_config >> b) & 1) ? '1' : '0';
    }
    key_config_bin[16] = '\0';
    cJSON_AddStringToObject(slot_obj, "key_config_binary", key_config_bin);

    cJSON_AddBoolToObject(slot_obj, "is_secret", (slot_config & 0x8000) != 0);
    cJSON_AddBoolToObject(slot_obj, "encrypt_read",
                          (slot_config & 0x4000) != 0);
    cJSON_AddBoolToObject(slot_obj, "is_private", (key_config & 0x0001) != 0);

    cJSON_AddItemToArray(slots, slot_obj);
  }
  cJSON_AddItemToObject(root, "slots", slots);

  // Additional fields
  cJSON_AddNumberToObject(root, "user_extra", config[84]);
  cJSON_AddNumberToObject(root, "selector", config[85]);

  char *json_str = cJSON_Print(root);
  cJSON_Delete(root);

  return json_str;
}

/**
 * Release ATECC608B resources
 */
void atecc608B_release() { atcab_release(); }

#endif // ATECC608B_H
