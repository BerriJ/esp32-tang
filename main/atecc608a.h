#ifndef ATECC608B_H
#define ATECC608B_H

#include <Arduino.h>
#include "cryptoauthlib.h"
#include "sdkconfig.h"

// ATECC608B Configuration
// Note: I2C pins are configured via sdkconfig (CONFIG_ATCA_I2C_SDA_PIN, CONFIG_ATCA_I2C_SCL_PIN)
// These are used by the cryptoauthlib HAL layer
#define ATECC608B_I2C_ADDR CONFIG_ATCA_I2C_ADDRESS
#define ATECC608B_I2C_FREQ CONFIG_ATCA_I2C_BAUD_RATE

// Global ATCA configuration
ATCAIfaceCfg atecc_cfg;
cryptoauthlib

    /**
     * Initialize I2C and ATECC608B
     */
    bool
    atecc608B_init()
{
  Serial.println("\n=== ATECC608B Initialization ===");

  // Configure cryptoauthlib for ATECC608B - it will handle I2C initialization
  atecc_cfg.iface_type = ATCA_I2C_IFACE;
  atecc_cfg.devtype = ATECC608B;
  atecc_cfg.atcai2c.address = ATECC608B_I2C_ADDR;
  atecc_cfg.atcai2c.bus = 0; // I2C bus number
  atecc_cfg.atcai2c.baud = ATECC608B_I2C_FREQ;
  atecc_cfg.wake_delay = 1500;
  atecc_cfg.rx_retries = 20;

  Serial.printf("Configuring ATECC608B: SDA=GPIO%d, SCL=GPIO%d, Address=0x%02X (7-bit: 0x%02X)\n",
                CONFIG_ATCA_I2C_SDA_PIN, CONFIG_ATCA_I2C_SCL_PIN, ATECC608B_I2C_ADDR, ATECC608B_I2C_ADDR >> 1);

  // Initialize cryptoauthlib (it will initialize I2C internally)
  ATCA_STATUS status = atcab_init(&atecc_cfg);
  if (status != ATCA_SUCCESS)
  {
    Serial.printf("ERROR: atcab_init failed with status 0x%02X\n", status);
    return false;
  }

  Serial.println("ATECC608B initialized successfully");

  // Give the device a moment to stabilize
  delay(100);

  // Wake the device and test communication
  status = atcab_wakeup();
  if (status != ATCA_SUCCESS)
  {
    Serial.printf("WARNING: Wake command returned status 0x%02X\n", status);
  }

  // Put device to idle
  atcab_idle();

  delay(50);

  return true;
}

/**
 * Print ATECC608B configuration zone to console
 */
void atecc608B_print_config()
{
  Serial.println("\n=== ATECC608B Configuration ===");

  // First, try to read the serial number as a simple communication test
  uint8_t serial_number[9];
  ATCA_STATUS status = atcab_read_serial_number(serial_number);

  if (status != ATCA_SUCCESS)
  {
    Serial.printf("ERROR: Failed to read serial number, status 0x%02X\n", status);
    Serial.println("This might indicate a communication or wiring issue.");
    return;
  }

  Serial.print("Serial Number: ");
  for (int i = 0; i < 9; i++)
  {
    Serial.printf("%02X", serial_number[i]);
  }
  Serial.println();

  // Read configuration zone (128 bytes)
  uint8_t config_data[128];
  Serial.println("\nReading configuration zone...");
  status = atcab_read_config_zone(config_data);

  if (status != ATCA_SUCCESS)
  {
    Serial.printf("ERROR: Failed to read config zone, status 0x%02X\n", status);

    // Try reading it in blocks as a workaround
    Serial.println("Attempting to read config in 4-byte blocks...");
    bool read_success = true;
    for (uint8_t block = 0; block < 32; block++)
    {
      status = atcab_read_zone(ATCA_ZONE_CONFIG, 0, block, 0, &config_data[block * 4], 4);
      if (status != ATCA_SUCCESS)
      {
        Serial.printf("ERROR: Failed to read block %d, status 0x%02X\n", block, status);
        read_success = false;
        break;
      }
    }

    if (!read_success)
    {
      Serial.println("ERROR: Could not read configuration zone");
      return;
    }
    Serial.println("Successfully read config in blocks");
  }

  // Print configuration in hex format
  Serial.println("\nConfiguration Zone (128 bytes):");
  for (int i = 0; i < 128; i++)
  {
    if (i % 16 == 0)
    {
      Serial.printf("\n%02X: ", i);
    }
    Serial.printf("%02X ", config_data[i]);
  }
  Serial.println("\n");

  // Parse and display key configuration sections
  Serial.println("Key Configuration Details:");
  Serial.println("---------------------------");

  // Serial Number (bytes 0-3 and 8-12)
  Serial.print("Serial Number: ");
  for (int i = 0; i < 4; i++)
    Serial.printf("%02X", config_data[i]);
  for (int i = 8; i < 13; i++)
    Serial.printf("%02X", config_data[i]);
  Serial.println();

  // Revision Number (bytes 4-7)
  Serial.printf("Revision: %02X %02X %02X %02X\n",
                config_data[4], config_data[5], config_data[6], config_data[7]);

  // I2C Address (byte 16)
  Serial.printf("I2C Address: 0x%02X\n", config_data[16]);

  // OTP Mode (byte 18)
  Serial.printf("OTP Mode: 0x%02X\n", config_data[18]);

  // Chip Mode (byte 19)
  Serial.printf("Chip Mode: 0x%02X ", config_data[19]);
  if (config_data[19] & 0x01)
    Serial.print("[I2C_Address_UserExtraAdd] ");
  if (config_data[19] & 0x02)
    Serial.print("[TTL_Enable] ");
  if (config_data[19] & 0x04)
    Serial.print("[Watchdog_1.3s] ");
  Serial.println();

  // Slot configurations (starts at byte 20)
  Serial.println("\nSlot Configurations:");
  for (int slot = 0; slot < 16; slot++)
  {
    int slot_config_offset = 20 + (slot * 2);
    uint16_t slot_config = (config_data[slot_config_offset + 1] << 8) | config_data[slot_config_offset];

    int key_config_offset = 96 + (slot * 2);
    uint16_t key_config = (config_data[key_config_offset + 1] << 8) | config_data[key_config_offset];

    Serial.printf("  Slot %2d: SlotConfig=0x%04X, KeyConfig=0x%04X", slot, slot_config, key_config);

    // Decode some useful bits
    bool is_secret = (slot_config & 0x8000) != 0;
    bool encrypt_read = (slot_config & 0x4000) != 0;
    bool is_private = (key_config & 0x0001) != 0;

    if (is_secret)
      Serial.print(" [Secret]");
    if (encrypt_read)
      Serial.print(" [EncryptRead]");
    if (is_private)
      Serial.print(" [Private]");
    Serial.println();
  }

  // Lock status
  Serial.println("\nLock Status:");
  Serial.printf("  Config Zone Lock: 0x%02X %s\n", config_data[87],
                config_data[87] == 0x00 ? "[LOCKED]" : "[UNLOCKED]");
  Serial.printf("  Data/OTP Zone Lock: 0x%02X %s\n", config_data[86],
                config_data[86] == 0x00 ? "[LOCKED]" : "[UNLOCKED]");

  Serial.println("\n=== End of ATECC608B Configuration ===\n");
}

/**
 * Release ATECC608B resources
 */
void atecc608B_release()
{
  atcab_release();
}

#endif // ATECC608B_H
