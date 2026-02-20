#ifndef TANG_SERVER_H
#define TANG_SERVER_H

#include <WiFi.h>
#include <WebServer.h>
#include <esp_task_wdt.h>
#include "sdkconfig.h"

// Enable/disable debug output
#define DEBUG_SERIAL 1

#if defined(DEBUG_SERIAL) && DEBUG_SERIAL > 0
#define DEBUG_PRINT(...) Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif

// Include core components
#include "crypto.h"
#include "encoding.h"
#include "jwe.h"
#include "tang_storage.h"
#include "tang_handlers.h"
#include "atecc608a.h"

// --- Configuration ---
const char *wifi_ssid = CONFIG_WIFI_SSID;
const char *wifi_password = CONFIG_WIFI_PASSWORD;

// --- Global State ---
WebServer server_http(80);
TangKeyStore keystore;
bool is_active = false;

// --- WiFi Setup ---
void setup_wifi()
{
  WiFi.mode(WIFI_STA);
  WiFi.setHostname("esp-tang-lol");

  if (strlen(wifi_ssid) > 0)
  {
    WiFi.begin(wifi_ssid, wifi_password);
    DEBUG_PRINTF("\nConnecting to SSID: %s ", wifi_ssid);
  }
  else
  {
    DEBUG_PRINTLN("\nNo WiFi SSID configured");
  }
}

// --- Initial Setup ---
bool perform_initial_setup()
{
  DEBUG_PRINTLN("\n=======================================================");
  DEBUG_PRINTLN("FIRST BOOT: INITIAL SETUP REQUIRED");
  DEBUG_PRINTLN("=======================================================");

  // Generate admin keypair
  if (!P521::generate_keypair(keystore.admin_pub, keystore.admin_priv))
  {
    DEBUG_PRINTLN("ERROR: Failed to generate admin keypair");
    return false;
  }
  DEBUG_PRINTLN("Generated admin keypair");

  // Prompt for password
  DEBUG_PRINTLN("\nEnter a password to encrypt the Tang keys:");
  DEBUG_PRINTLN("(Password required for activation/deactivation)");
  DEBUG_PRINT("> ");

  String password = "";
  while (true)
  {
    if (Serial.available() > 0)
    {
      char c = Serial.read();
      if (c == '\n' || c == '\r')
      {
        if (password.length() > 0)
          break;
        // Ignore empty newlines
      }
      else if (c >= 32 && c <= 126)
      {
        password += c;
        Serial.print('*');
      }
    }
    delay(10);
  }
  DEBUG_PRINTLN();

  if (password.length() < 8)
  {
    DEBUG_PRINTLN("ERROR: Password must be at least 8 characters");
    DEBUG_PRINTLN("Device requires restart. Use NUKE command to try again.");
    return false;
  }

  DEBUG_PRINTF("Password set (%d characters)\n", password.length());

  // Disable watchdog for key generation
  esp_task_wdt_deinit();

  // Generate and encrypt Tang keys
  DEBUG_PRINTLN("Generating Tang keys (this may take a while)...");

  if (!P521::generate_keypair(keystore.sig_pub, keystore.sig_priv))
  {
    DEBUG_PRINTLN("ERROR: Failed to generate signing key");
    return false;
  }

  if (!P521::generate_keypair(keystore.exc_pub, keystore.exc_priv))
  {
    DEBUG_PRINTLN("ERROR: Failed to generate exchange key");
    return false;
  }

  // Save admin key and salt
  keystore.save_admin_key();

  // Encrypt and save Tang keys
  if (!keystore.encrypt_and_save_tang_keys(password.c_str()))
  {
    DEBUG_PRINTLN("ERROR: Failed to save Tang keys");
    return false;
  }

  DEBUG_PRINTLN("Configuration saved to NVS");
  DEBUG_PRINTLN("=======================================================");
  DEBUG_PRINTLN("Setup complete! Device is ready to use");
  DEBUG_PRINTLN("=======================================================\n");

  // Re-enable watchdog
  esp_task_wdt_config_t wdt_config = {
      .timeout_ms = 5000,
      .idle_core_mask = (1 << 0) | (1 << 1),
      .trigger_panic = false};
  esp_task_wdt_init(&wdt_config);

  return true;
}

// --- Setup Routes ---
void setup_routes()
{
  server_http.on("/adv", HTTP_GET, handle_adv);
  server_http.on("/adv/", HTTP_GET, handle_adv);
  server_http.on("/rec", HTTP_POST, handle_rec);
  server_http.on("/rec/", HTTP_POST, handle_rec);
  server_http.on("/pub", HTTP_GET, handle_pub);
  server_http.on("/activate", HTTP_POST, handle_activate);
  server_http.on("/reboot", HTTP_GET, handle_reboot);
  server_http.on("/reset", HTTP_GET, handle_reset);
  server_http.on("/nuke", HTTP_GET, handle_reset);

  server_http.onNotFound(handle_not_found);
}

// --- Main Setup ---
void setup()
{
  Serial.begin(115200);
  DEBUG_PRINTLN("\n\nESP32 Tang Server Starting...");

  // Initialize ATECC608A
  if (atecc608a_init())
  {
    atecc608a_print_config();
  }
  else
  {
    DEBUG_PRINTLN("WARNING: ATECC608A initialization failed");
  }

  // Load or initialize configuration
  bool success;
  if (keystore.is_configured())
  {
    DEBUG_PRINTLN("Found existing configuration");
    success = keystore.load_admin_key();
    if (success)
      DEBUG_PRINTLN("Loaded admin key");
  }
  else
  {
    success = perform_initial_setup();
  }

  if (!success)
  {
    DEBUG_PRINTLN("ERROR: Setup failed. Nuking and restarting...");
    keystore.nuke();
    delay(1000);
    ESP.restart();
  }

  DEBUG_PRINTLN("\nAdmin Public Key (Base64):");
  DEBUG_PRINTF("\nAdmin Public Key x: %s", Base64URL::encode(keystore.admin_pub, P521_COORDINATE_SIZE).c_str());
  DEBUG_PRINTF("\nAdmin Public Key y: %s", Base64URL::encode(keystore.admin_pub + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE).c_str());

  setup_wifi();
  setup_routes();

  server_http.begin();
  DEBUG_PRINTLN("HTTP server listening on port 80");

  if (!is_active)
  {
    DEBUG_PRINTLN("Server is INACTIVE. POST to /activate to enable Tang services");
  }
}

// --- Main Loop ---
void loop()
{
  // WiFi status indicator
  if (WiFi.status() != WL_CONNECTED)
  {
    if ((millis() % 2000) < 50)
    {
      DEBUG_PRINT(".");
    }
  }

  server_http.handleClient();
}

#endif // TANG_SERVER_H
