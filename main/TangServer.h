#ifndef TANG_SERVER_H
#define TANG_SERVER_H

#include <WiFi.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <EEPROM.h>
#include <esp_task_wdt.h>
#include "sdkconfig.h"

// --- Compile-time Configuration ---
// Comment out this line to disable all Serial output for a "release" build.
#define DEBUG_SERIAL 1

// --- Debug Macros ---
#if defined(DEBUG_SERIAL) && DEBUG_SERIAL > 0
#define DEBUG_PRINT(...) Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif

// --- Wi-Fi Configuration ---
const char *wifi_ssid = CONFIG_WIFI_SSID;
const char *wifi_password = CONFIG_WIFI_PASSWORD;
enum WifiMode
{
  TANG_WIFI_STA,
  TANG_WIFI_AP
};
WifiMode current_wifi_mode = TANG_WIFI_STA;
unsigned long mode_switch_timestamp = 0;
const unsigned long WIFI_MODE_DURATION = 60000; // 60 seconds

// --- Server & Crypto Globals ---
WebServer server_http(80);

// --- Server State ---
bool is_active = false;
unsigned long activation_timestamp = 0; // Timestamp when server was activated

// --- Key Storage ---
uint8_t tang_sig_private_key[32]; // Signing key - in-memory only when active
uint8_t tang_sig_public_key[64];  // Signing key - in-memory only when active
uint8_t tang_exc_private_key[32]; // Exchange key - in-memory only when active
uint8_t tang_exc_public_key[64];  // Exchange key - in-memory only when active
uint8_t admin_private_key[32];    // Persistent in EEPROM
uint8_t admin_public_key[64];     // Derived from private key

// --- EEPROM Configuration ---
const int EEPROM_SIZE = 4096;
const int EEPROM_MAGIC_ADDR = 0;
const int EEPROM_SALT_ADDR = 4; // 16 bytes for PBKDF2 salt
const int EEPROM_ADMIN_KEY_ADDR = 20;
const int EEPROM_TANG_SIG_KEY_ADDR = EEPROM_ADMIN_KEY_ADDR + 32;
const int GCM_TAG_SIZE = 16;
const int EEPROM_TANG_SIG_TAG_ADDR = EEPROM_TANG_SIG_KEY_ADDR + 32;
const int EEPROM_TANG_EXC_KEY_ADDR = EEPROM_TANG_SIG_TAG_ADDR + GCM_TAG_SIZE;
const int EEPROM_TANG_EXC_TAG_ADDR = EEPROM_TANG_EXC_KEY_ADDR + 32;
const int EEPROM_WIFI_SSID_ADDR = EEPROM_TANG_EXC_TAG_ADDR + GCM_TAG_SIZE;
const int EEPROM_WIFI_PASS_ADDR = EEPROM_WIFI_SSID_ADDR + 33;
const uint32_t EEPROM_MAGIC_VALUE = 0xCAFEDEAD;
const int SALT_SIZE = 16;

// Forward declare functions
void startAPMode();
void startSTAMode();

// Include helper and handler files
#include "helpers.h"
#include "handlers.h"

// --- Main Application Logic ---
void setup()
{
  Serial.begin(115200);
  DEBUG_PRINTLN("\n\nESP32 Tang Server Starting...");

  EEPROM.begin(EEPROM_SIZE);
  uint32_t magic = 0;
  EEPROM.get(EEPROM_MAGIC_ADDR, magic);

  if (magic == EEPROM_MAGIC_VALUE)
  {
    DEBUG_PRINTLN("Found existing configuration in EEPROM.");
    // Load Admin Key
    for (int i = 0; i < 32; ++i)
      admin_private_key[i] = EEPROM.read(EEPROM_ADMIN_KEY_ADDR + i);
    compute_ec_public_key(admin_private_key, admin_public_key);
    DEBUG_PRINTLN("Loaded admin key.");

    // Load Wi-Fi credentials if they exist
    if (EEPROM.read(EEPROM_WIFI_SSID_ADDR) != 0xFF && EEPROM.read(EEPROM_WIFI_SSID_ADDR) != 0)
    {
      EEPROM.get(EEPROM_WIFI_SSID_ADDR, wifi_ssid);
      EEPROM.get(EEPROM_WIFI_PASS_ADDR, wifi_password);
      DEBUG_PRINTLN("Loaded Wi-Fi credentials from EEPROM.");
    }
  }
  else
  {
    DEBUG_PRINTLN("First run or NUKE'd: generating and saving new keys...");
    DEBUG_PRINTLN("\n=======================================================");
    DEBUG_PRINTLN("FIRST BOOT: INITIAL SETUP REQUIRED");
    DEBUG_PRINTLN("=======================================================");

    // 1. Generate random salt for PBKDF2
    uint8_t salt[SALT_SIZE];
    esp_fill_random(salt, SALT_SIZE);
    for (int i = 0; i < SALT_SIZE; ++i)
      EEPROM.write(EEPROM_SALT_ADDR + i, salt[i]);
    DEBUG_PRINTLN("Generated device-specific salt");

    // 2. Generate and save admin key
    generate_ec_keypair(admin_public_key, admin_private_key);
    for (int i = 0; i < 32; ++i)
      EEPROM.write(EEPROM_ADMIN_KEY_ADDR + i, admin_private_key[i]);
    DEBUG_PRINTLN("Generated admin keypair");

    // 3. Prompt for initial password via serial
    DEBUG_PRINTLN("\nPlease enter a password to encrypt the Tang keys:");
    DEBUG_PRINTLN("(Password will be used for activation/deactivation)");
    DEBUG_PRINTLN("Type your password and press Enter");
    DEBUG_PRINT("> ");

    // Wait for password input (wait for complete line with Enter)
    String password_input = "";
    bool password_complete = false;

    while (!password_complete)
    {
      while (Serial.available() > 0)
      {
        char c = Serial.read();
        if (c == '\n' || c == '\r')
        {
          if (password_input.length() > 0)
          {
            password_complete = true;
            break;
          }
          // Ignore empty lines (just pressing Enter without typing)
        }
        else if (c >= 32 && c <= 126) // Printable ASCII characters only
        {
          password_input += c;
          Serial.print('*'); // Echo asterisks for security
        }
      }
      delay(10);
    }
    DEBUG_PRINTLN(); // New line after password input

    if (password_input.length() < 8)
    {
      DEBUG_PRINTLN("ERROR: Password must be at least 8 characters!");
      DEBUG_PRINTLN("Device requires restart. Send NUKE command to try again.");
      while (true)
        delay(1000); // Halt
    }

    DEBUG_PRINTF("Password set (%d characters)\n", password_input.length());

    // Temporarily disable watchdog for PBKDF2 operations (can take 30-40 seconds)
    DEBUG_PRINTLN("Disabling watchdog timer for key generation...");
    esp_task_wdt_deinit();

    // 4. Generate initial Tang signing key and encrypt it with the password
    DEBUG_PRINTLN("Generating and encrypting signing key (this may take 20-30 seconds)...");
    generate_ec_keypair(tang_sig_public_key, tang_sig_private_key);
    uint8_t encrypted_tang_sig_key[32];
    uint8_t gcm_sig_tag[GCM_TAG_SIZE];
    memcpy(encrypted_tang_sig_key, tang_sig_private_key, 32);
    crypt_local_data_gcm(encrypted_tang_sig_key, 32, password_input.c_str(), salt, true, gcm_sig_tag);
    for (int i = 0; i < 32; ++i)
      EEPROM.write(EEPROM_TANG_SIG_KEY_ADDR + i, encrypted_tang_sig_key[i]);
    for (int i = 0; i < GCM_TAG_SIZE; ++i)
      EEPROM.write(EEPROM_TANG_SIG_TAG_ADDR + i, gcm_sig_tag[i]);

    // 5. Generate initial Tang exchange key and encrypt it with the password
    DEBUG_PRINTLN("Generating and encrypting exchange key...");
    generate_ec_keypair(tang_exc_public_key, tang_exc_private_key);
    uint8_t encrypted_tang_exc_key[32];
    uint8_t gcm_exc_tag[GCM_TAG_SIZE];
    memcpy(encrypted_tang_exc_key, tang_exc_private_key, 32);
    crypt_local_data_gcm(encrypted_tang_exc_key, 32, password_input.c_str(), salt, true, gcm_exc_tag);
    for (int i = 0; i < 32; ++i)
      EEPROM.write(EEPROM_TANG_EXC_KEY_ADDR + i, encrypted_tang_exc_key[i]);
    for (int i = 0; i < GCM_TAG_SIZE; ++i)
      EEPROM.write(EEPROM_TANG_EXC_TAG_ADDR + i, gcm_exc_tag[i]);

    // 6. Write magic number and commit
    EEPROM.put(EEPROM_MAGIC_ADDR, EEPROM_MAGIC_VALUE);
    if (EEPROM.commit())
    {
      DEBUG_PRINTLN("Initial configuration saved to EEPROM.");
      DEBUG_PRINTLN("=======================================================");
      DEBUG_PRINTLN("Setup complete! Device is ready to use.");
      DEBUG_PRINTLN("Use this password for /activate and /deactivate");
      DEBUG_PRINTLN("=======================================================\n");
    }
    else
    {
      DEBUG_PRINTLN("ERROR: Failed to save to EEPROM!");
    }

    // Re-enable watchdog after setup
    DEBUG_PRINTLN("Re-enabling watchdog timer...");
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = 5000,
        .idle_core_mask = (1 << 0) | (1 << 1),
        .trigger_panic = false};
    esp_task_wdt_init(&wdt_config);

    // Clear password from memory
    password_input = "";
  }

  DEBUG_PRINTLN("Admin Public Key:");
  print_hex(admin_public_key, sizeof(admin_public_key));

  startSTAMode();

  // --- Setup Server Routes ---
  server_http.on("/adv", HTTP_GET, handleAdv);
  server_http.on("/adv/", HTTP_GET, handleAdv);
  server_http.on("/rec", HTTP_POST, handleRec);
  server_http.on("/rec/", HTTP_POST, handleRec);
  server_http.on("/pub", HTTP_GET, handlePub);
  server_http.on("/activate", HTTP_POST, handleActivate);
  server_http.on("/deactivate", HTTP_GET, handleDeactivate);  // Simple deactivate
  server_http.on("/deactivate", HTTP_POST, handleDeactivate); // Deactivate and set new password
  server_http.on("/reboot", HTTP_GET, handleReboot);

  // Custom handler for /rec/{kid} paths - must be registered before onNotFound
  server_http.onNotFound([]()
                         {
    String uri = server_http.uri();
    if (uri.startsWith("/rec/") && server_http.method() == HTTP_POST) {
      handleRec();
    } else {
      handleNotFound();
    } });

  server_http.begin();
  DEBUG_PRINTLN("HTTP server listening on port 80.");
  if (!is_active)
  {
    DEBUG_PRINTLN("Server is INACTIVE. POST to /activate to enable Tang services.");
  }
}

void loop()
{
  // --- Check for Serial Commands ---
  if (Serial.available() > 0)
  {
    String command = Serial.readStringUntil('\n');
    command.trim();
    if (command.equalsIgnoreCase("NUKE"))
    {
      DEBUG_PRINTLN("!!! NUKE command received! Wiping configuration...");
      // By writing a different value to the magic address, we force
      // the setup() function to re-initialize everything on next boot.
      EEPROM.put(EEPROM_MAGIC_ADDR, (uint32_t)0x00);
      if (EEPROM.commit())
      {
        DEBUG_PRINTLN("Configuration wiped. Restarting device.");
      }
      else
      {
        DEBUG_PRINTLN("ERROR: Failed to wipe configuration!");
      }
      delay(1000);
      ESP.restart();
    }
  }

  // --- Wi-Fi Connection Management ---
  if (WiFi.status() != WL_CONNECTED)
  {
    if (millis() - mode_switch_timestamp > WIFI_MODE_DURATION)
    {
      if (current_wifi_mode == TANG_WIFI_STA)
      {
        startAPMode();
      }
      else
      {
        startSTAMode();
      }
    }
    if (current_wifi_mode == TANG_WIFI_STA)
    {
      // Print a dot every so often while trying to connect
      if ((millis() % 2000) < 50)
        DEBUG_PRINT(".");
    }
  }

  server_http.handleClient();
}

// --- WiFi Mode Management ---
void startAPMode()
{
  WiFi.mode(WIFI_AP);
  WiFi.softAP("Tang-Server-Setup", NULL);
  DEBUG_PRINTLN("\nStarting Access Point 'Tang-Server-Setup'.");
  DEBUG_PRINTF("AP IP address: %s\n", WiFi.softAPIP().toString().c_str());
  current_wifi_mode = TANG_WIFI_AP;
  mode_switch_timestamp = millis();
}

void startSTAMode()
{
  WiFi.mode(WIFI_STA);
  if (strlen(wifi_ssid) > 0)
  {
    WiFi.begin(wifi_ssid, wifi_password);
    DEBUG_PRINTF("\nConnecting to SSID: %s ", wifi_ssid);
  }
  else
  {
    DEBUG_PRINTLN("\nNo WiFi SSID configured. Skipping connection attempt.");
  }
  current_wifi_mode = TANG_WIFI_STA;
  mode_switch_timestamp = millis();
}

#endif // TANG_SERVER_H
