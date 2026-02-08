#ifndef TANG_SERVER_H
#define TANG_SERVER_H

#include <WiFi.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <Preferences.h>
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

// --- Server & Crypto Globals ---
WebServer server_http(80);

// --- Server State ---
bool is_active = false;
unsigned long activation_timestamp = 0; // Timestamp when server was activated

// --- Key Storage ---
uint8_t tang_sig_private_key[66]; // Signing key - in-memory only when active (P-521)
uint8_t tang_sig_public_key[132]; // Signing key - in-memory only when active (P-521)
uint8_t tang_exc_private_key[66]; // Exchange key - in-memory only when active (P-521)
uint8_t tang_exc_public_key[132]; // Exchange key - in-memory only when active (P-521)
uint8_t admin_private_key[66];    // Persistent in NVS (P-521)
uint8_t admin_public_key[132];    // Derived from private key (P-521)

// --- Preferences Configuration ---
Preferences preferences;
const int GCM_TAG_SIZE = 16;
const int SALT_SIZE = 16;

// Forward declare functions
void startSTAMode();

// Include helper and handler files
#include "helpers.h"
#include "handlers.h"

// --- Main Application Logic ---
void setup()
{
  Serial.begin(115200);
  DEBUG_PRINTLN("\n\nESP32 Tang Server Starting...");

  preferences.begin("tang-server", false);
  bool is_configured = preferences.isKey("admin_key");

  if (is_configured)
  {
    DEBUG_PRINTLN("Found existing configuration in NVS.");
    // Load Admin Key
    size_t len = preferences.getBytes("admin_key", admin_private_key, 66);
    if (len == 66)
    {
      compute_ec_public_key(admin_private_key, admin_public_key);
      DEBUG_PRINTLN("Loaded admin key.");
    }
    else
    {
      DEBUG_PRINTLN("ERROR: Failed to load admin key!");
    }

    // Load Wi-Fi credentials if they exist
    if (preferences.isKey("wifi_ssid"))
    {
      String ssid = preferences.getString("wifi_ssid", "");
      String pass = preferences.getString("wifi_pass", "");
      if (ssid.length() > 0)
      {
        wifi_ssid = ssid.c_str();
        wifi_password = pass.c_str();
        DEBUG_PRINTLN("Loaded Wi-Fi credentials from NVS.");
      }
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
    preferences.putBytes("salt", salt, SALT_SIZE);
    DEBUG_PRINTLN("Generated device-specific salt");

    // 2. Generate and save admin key
    generate_ec_keypair(admin_public_key, admin_private_key);
    preferences.putBytes("admin_key", admin_private_key, 66);
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
    uint8_t encrypted_tang_sig_key[66];
    uint8_t gcm_sig_tag[GCM_TAG_SIZE];
    memcpy(encrypted_tang_sig_key, tang_sig_private_key, 66);
    crypt_local_data_gcm(encrypted_tang_sig_key, 66, password_input.c_str(), salt, true, gcm_sig_tag);
    preferences.putBytes("tang_sig_key", encrypted_tang_sig_key, 66);
    preferences.putBytes("tang_sig_tag", gcm_sig_tag, GCM_TAG_SIZE);

    // 5. Generate initial Tang exchange key and encrypt it with the password
    DEBUG_PRINTLN("Generating and encrypting exchange key...");
    generate_ec_keypair(tang_exc_public_key, tang_exc_private_key);
    uint8_t encrypted_tang_exc_key[66];
    uint8_t gcm_exc_tag[GCM_TAG_SIZE];
    memcpy(encrypted_tang_exc_key, tang_exc_private_key, 66);
    crypt_local_data_gcm(encrypted_tang_exc_key, 66, password_input.c_str(), salt, true, gcm_exc_tag);
    preferences.putBytes("tang_exc_key", encrypted_tang_exc_key, 66);
    preferences.putBytes("tang_exc_tag", gcm_exc_tag, GCM_TAG_SIZE);

    // 6. Configuration saved automatically by Preferences
    DEBUG_PRINTLN("Initial configuration saved to NVS.");
    DEBUG_PRINTLN("=======================================================");
    DEBUG_PRINTLN("Setup complete! Device is ready to use.");
    DEBUG_PRINTLN("Use this password for /activate and /deactivate");
    DEBUG_PRINTLN("=======================================================\n");

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
      preferences.clear();
      preferences.end();
      DEBUG_PRINTLN("Configuration wiped. Restarting device.");
      delay(1000);
      ESP.restart();
    }
  }

  // --- Wi-Fi Connection Management ---
  if (WiFi.status() != WL_CONNECTED)
  {
    // Print a dot every so often while trying to connect
    if ((millis() % 2000) < 50)
      DEBUG_PRINT(".");
  }

  server_http.handleClient();
}

// --- WiFi Station Mode ---
void startSTAMode()
{
  WiFi.mode(WIFI_STA);
  WiFi.setHostname("esp-tang");
  if (strlen(wifi_ssid) > 0)
  {
    WiFi.begin(wifi_ssid, wifi_password);
    DEBUG_PRINTF("\nConnecting to SSID: %s ", wifi_ssid);
  }
  else
  {
    DEBUG_PRINTLN("\nNo WiFi SSID configured. Skipping connection attempt.");
  }
}

#endif // TANG_SERVER_H
