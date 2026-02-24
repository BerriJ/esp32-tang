#ifndef TANG_SERVER_H
#define TANG_SERVER_H

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_http_server.h>
#include <esp_task_wdt.h>
#include <nvs_flash.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <string>
#include "sdkconfig.h"

static const char *TAG = "TangServer";

// Include core components
#include "crypto.h"
#include "encoding.h"
#include "tang_storage.h"
#include "atecc608a.h"
#include "tang_handlers.h"
#include "zk_auth.h"
#include "zk_handlers.h"
#include "provision.h"
#include "provision_handlers.h"

// --- Configuration ---
const char *wifi_ssid = CONFIG_WIFI_SSID;
const char *wifi_password = CONFIG_WIFI_PASSWORD;

// --- Global State ---
httpd_handle_t server_http = NULL;
TangKeyStore keystore;
bool is_active = true; // Auto-activate since we're using dummy keys
ZKAuth zk_auth;        // Zero-Knowledge Authentication

// WiFi event group
static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;

// --- WiFi Event Handler ---
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
  {
    esp_wifi_connect();
    ESP_LOGI(TAG, "WiFi connecting...");
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
  {
    esp_wifi_connect();
    ESP_LOGI(TAG, "WiFi disconnected, reconnecting...");
  }
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
  {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
    xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
  }
}

// --- WiFi Setup ---
void setup_wifi()
{
  // Initialize event group
  wifi_event_group = xEventGroupCreate();

  // Initialize network interface
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
  assert(sta_netif);

  // Set hostname
  ESP_ERROR_CHECK(esp_netif_set_hostname(sta_netif, "esp-tang-lol"));

  // Initialize WiFi
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  // Register event handlers
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

  // Configure WiFi
  wifi_config_t wifi_config = {};
  if (strlen(wifi_ssid) > 0)
  {
    strncpy((char *)wifi_config.sta.ssid, wifi_ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, wifi_password, sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to SSID: %s", wifi_ssid);
  }
  else
  {
    ESP_LOGI(TAG, "No WiFi SSID configured");
  }
}

// --- Initial Setup ---
bool perform_initial_setup()
{
  ESP_LOGI(TAG, "=======================================================");
  ESP_LOGI(TAG, "FIRST BOOT: INITIAL SETUP REQUIRED");
  ESP_LOGI(TAG, "=======================================================");

  // Generate admin keypair
  if (!P256::generate_keypair(keystore.admin_pub, keystore.admin_priv))
  {
    ESP_LOGE(TAG, "ERROR: Failed to generate admin keypair");
    return false;
  }
  ESP_LOGI(TAG, "Generated admin keypair");

  // Disable watchdog for key generation (can take a long time)
  esp_task_wdt_deinit();

  // Generate Tang keys
  ESP_LOGI(TAG, "Generating Tang keys (this may take a while)...");

  if (!P256::generate_keypair(keystore.sig_pub, keystore.sig_priv))
  {
    ESP_LOGE(TAG, "ERROR: Failed to generate signing key");
    return false;
  }

  if (!P256::generate_keypair(keystore.exc_pub, keystore.exc_priv))
  {
    ESP_LOGE(TAG, "ERROR: Failed to generate exchange key");
    return false;
  }

  // Save admin key
  keystore.save_admin_key();

  // Save Tang keys directly (no encryption in prototype)
  if (!keystore.save_tang_keys())
  {
    ESP_LOGE(TAG, "ERROR: Failed to save Tang keys");
    return false;
  }

  ESP_LOGI(TAG, "Configuration saved to NVS");
  ESP_LOGI(TAG, "=======================================================");
  ESP_LOGI(TAG, "Setup complete! Device is ready to use");
  ESP_LOGI(TAG, "NOTE: Keys are stored unencrypted for prototyping");
  ESP_LOGI(TAG, "=======================================================");

  // Re-enable watchdog
  esp_task_wdt_config_t wdt_config = {
      .timeout_ms = 5000,
      .idle_core_mask = (1 << 0) | (1 << 1),
      .trigger_panic = false};
  esp_task_wdt_init(&wdt_config);

  return true;
}

// --- Setup HTTP Server Routes ---
httpd_handle_t setup_http_server()
{
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.lru_purge_enable = true;
  config.stack_size = 8192;
  config.max_uri_handlers = 16; // Increased to accommodate all handlers including ZK

  httpd_handle_t server = NULL;

  if (httpd_start(&server, &config) == ESP_OK)
  {
    // Register provisioning handlers first (must be before ZK handlers)
    register_provision_handlers(server);

    // Register ZK authentication handlers (including root "/" handler)
    register_zk_handlers(server);

    // Register Tang protocol handlers
    httpd_uri_t adv_uri = {
        .uri = "/adv",
        .method = HTTP_GET,
        .handler = handle_adv,
        .user_ctx = NULL};
    httpd_register_uri_handler(server, &adv_uri);

    httpd_uri_t adv_uri_slash = {
        .uri = "/adv/",
        .method = HTTP_GET,
        .handler = handle_adv,
        .user_ctx = NULL};
    httpd_register_uri_handler(server, &adv_uri_slash);

    httpd_uri_t rec_uri = {
        .uri = "/rec",
        .method = HTTP_POST,
        .handler = handle_rec,
        .user_ctx = NULL};
    httpd_register_uri_handler(server, &rec_uri);

    httpd_uri_t config_uri = {
        .uri = "/config",
        .method = HTTP_GET,
        .handler = handle_config,
        .user_ctx = NULL};
    httpd_register_uri_handler(server, &config_uri);

    httpd_uri_t reboot_uri = {
        .uri = "/reboot",
        .method = HTTP_GET,
        .handler = handle_reboot,
        .user_ctx = NULL};
    httpd_register_uri_handler(server, &reboot_uri);

    // Register custom error handler for 404
    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, handle_not_found);

    ESP_LOGI(TAG, "HTTP server listening on port 80");
  }
  else
  {
    ESP_LOGE(TAG, "Failed to start HTTP server");
  }

  return server;
}

// --- Main Setup ---
void setup()
{
  ESP_LOGI(TAG, "\n\nESP32 Tang Server Starting...");

  // Initialize NVS (required before any storage operations)
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
  {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);
  ESP_LOGI(TAG, "NVS initialized");

  // Initialize ATECC608A
  if (atecc608B_init())
  {
    atecc608B_print_config();
  }
  else
  {
    ESP_LOGW(TAG, "WARNING: ATECC608A initialization failed");
  }

  // Load or initialize configuration
  bool success;
  if (keystore.is_configured())
  {
    ESP_LOGI(TAG, "Found existing configuration");
    success = keystore.load_admin_key();
    if (success)
    {
      ESP_LOGI(TAG, "Loaded admin key");
      // Auto-load Tang keys on startup (no activation needed in prototype)
      if (keystore.load_tang_keys())
      {
        ESP_LOGI(TAG, "Loaded Tang keys - server ready");
      }
      else
      {
        ESP_LOGW(TAG, "Failed to load Tang keys");
        success = false;
      }
    }
  }
  else
  {
    success = perform_initial_setup();
  }

  if (!success)
  {
    ESP_LOGE(TAG, "ERROR: Setup failed. Nuking and restarting...");
    keystore.nuke();
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
  }

  // Initialize Zero-Knowledge Authentication
  ESP_LOGI(TAG, "Initializing Zero-Knowledge Authentication...");
  if (zk_auth.init())
  {
    ESP_LOGI(TAG, "ZK Auth initialized successfully");

    // Set test password
    if (zk_auth.set_password("password"))
    {
      ESP_LOGI(TAG, "Test password set successfully");
    }
    else
    {
      ESP_LOGW(TAG, "Failed to set test password");
    }
  }
  else
  {
    ESP_LOGW(TAG, "ZK Auth initialization failed");
  }

  setup_wifi();
  server_http = setup_http_server();

  if (server_http)
  {
    ESP_LOGI(TAG, "HTTP server listening on port 80");
    ESP_LOGI(TAG, "  - ZK Auth UI: http://<ip>/");
    ESP_LOGI(TAG, "  - Tang Server: http://<ip>/adv");
  }
}

// --- Main Loop ---
void loop()
{
  // Just delay - HTTP server handles requests in its own task
  vTaskDelay(pdMS_TO_TICKS(1000));
}

#endif // TANG_SERVER_H
