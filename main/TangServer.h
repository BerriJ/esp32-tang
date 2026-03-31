#ifndef TANG_SERVER_H
#define TANG_SERVER_H

#include "sdkconfig.h"
#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_https_server.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/task.h>
#include <nvs_flash.h>

static const char *TAG = "TangServer";

// Core components
#include "encoding.h"
#include "provision.h"
#include "provision_handlers.h"
#include "tang_handlers.h"
#include "tang_storage.h"
#include "zk_auth.h"
#include "zk_handlers.h"

// --- Configuration ---
const char *wifi_ssid = CONFIG_WIFI_SSID;
const char *wifi_password = CONFIG_WIFI_PASSWORD;

// --- Global State ---
bool unlocked = false;
httpd_handle_t server_http = NULL;
httpd_handle_t server_https = NULL;
TangKeyStore keystore;
ZKAuth zk_auth;

// WiFi event group
static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;

// --- WiFi Event Handler ---
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
    ESP_LOGI(TAG, "WiFi connecting...");
  } else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_STA_DISCONNECTED) {
    esp_wifi_connect();
    ESP_LOGI(TAG, "WiFi disconnected, reconnecting...");
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
    xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
  }
}

// --- WiFi Setup ---
void setup_wifi() {
  wifi_event_group = xEventGroupCreate();

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
  assert(sta_netif);

  ESP_ERROR_CHECK(esp_netif_set_hostname(sta_netif, "esp-tang-lol"));

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                             &wifi_event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                             &wifi_event_handler, NULL));

  wifi_config_t wifi_config = {};
  if (strlen(wifi_ssid) > 0) {
    strncpy((char *)wifi_config.sta.ssid, wifi_ssid,
            sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, wifi_password,
            sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to SSID: %s", wifi_ssid);
  } else {
    ESP_LOGI(TAG, "No WiFi SSID configured");
  }
}

// Embedded TLS certificate and private key (via EMBED_TXTFILES)
extern const uint8_t server_crt_start[] asm("_binary_https_server_crt_start");
extern const uint8_t server_crt_end[] asm("_binary_https_server_crt_end");
extern const uint8_t server_key_start[] asm("_binary_https_server_key_start");
extern const uint8_t server_key_end[] asm("_binary_https_server_key_end");

// --- Setup HTTP Server (port 80) — Tang protocol + provisioning ---
// Tang protocol (/adv, /rec) is cryptographically authenticated via JWS/ECDH,
// so TLS is not required. Running plain HTTP ensures compatibility with
// standard tang clients (clevis) that cannot verify self-signed certificates.
httpd_handle_t setup_plain_http_server() {
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.lru_purge_enable = true;
  config.stack_size = 8192;
  config.max_uri_handlers = 10;
  config.uri_match_fn = httpd_uri_match_wildcard;

  httpd_handle_t server = NULL;

  if (httpd_start(&server, &config) == ESP_OK) {
    register_provision_handlers(server);

    httpd_uri_t adv_uri = {.uri = "/adv",
                           .method = HTTP_GET,
                           .handler = handle_adv,
                           .user_ctx = NULL};
    httpd_register_uri_handler(server, &adv_uri);

    httpd_uri_t adv_uri_slash = {.uri = "/adv/",
                                 .method = HTTP_GET,
                                 .handler = handle_adv,
                                 .user_ctx = NULL};
    httpd_register_uri_handler(server, &adv_uri_slash);

    httpd_uri_t rec_uri = {.uri = "/rec/*",
                           .method = HTTP_POST,
                           .handler = handle_rec,
                           .user_ctx = NULL};
    httpd_register_uri_handler(server, &rec_uri);

    httpd_uri_t reboot_uri = {.uri = "/reboot",
                              .method = HTTP_GET,
                              .handler = handle_reboot,
                              .user_ctx = NULL};
    httpd_register_uri_handler(server, &reboot_uri);

    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, handle_not_found);

    ESP_LOGI(TAG, "HTTP server listening on port 80 (Tang protocol)");
  } else {
    ESP_LOGE(TAG, "Failed to start HTTP server");
  }

  return server;
}

// --- Setup HTTPS Server (port 443) — Web UI + ZK auth API ---
// HTTPS provides the secure context required by the Web Crypto API.
httpd_handle_t setup_https_server() {
  httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
  config.servercert = server_crt_start;
  config.servercert_len = server_crt_end - server_crt_start;
  config.prvtkey_pem = server_key_start;
  config.prvtkey_len = server_key_end - server_key_start;

  config.httpd.lru_purge_enable = true;
  config.httpd.stack_size = 10240;
  config.httpd.max_uri_handlers = 12;
  config.httpd.uri_match_fn = httpd_uri_match_wildcard;

  httpd_handle_t server = NULL;

  if (httpd_ssl_start(&server, &config) == ESP_OK) {
    register_zk_handlers(server);

    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, handle_not_found);

    ESP_LOGI(TAG, "HTTPS server listening on port 443 (Web UI)");
  } else {
    ESP_LOGE(TAG, "Failed to start HTTPS server");
  }

  return server;
}

// --- Main Setup ---
void setup() {
  ESP_LOGI(TAG, "\n\nESP32 Tang Server Starting...");

  // 1. Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);
  ESP_LOGI(TAG, "NVS initialized");

  // 2. Provision eFuse KEY5 (no-op if already burned)
  if (is_efuse_key5_hmac_up()) {
    ESP_LOGI(TAG, "eFuse KEY5 already provisioned with HMAC_UP");
  } else if (is_efuse_key5_free()) {
    ESP_LOGI(TAG, "First boot — provisioning eFuse HMAC key...");
    if (provision_efuse_key5()) {
      ESP_LOGI(TAG, "eFuse KEY5 provisioned");
    } else {
      ESP_LOGE(TAG, "eFuse KEY5 provisioning failed");
    }
  } else {
    ESP_LOGE(TAG, "eFuse KEY5 has wrong purpose (expected HMAC_UP) — "
                  "HMAC key derivation will not work");
  }

  // 2b. Ensure TEE salt exists (may be missing after re-flash)
  if (is_efuse_key5_hmac_up() && !ensure_tee_salt()) {
    ESP_LOGE(TAG, "Failed to initialize TEE salt");
  }

  // 3. Initialize signing key in TEE Secure Storage (first boot generates,
  //    subsequent boots are a no-op). Then load the public key.
  keystore.init_signing_key();
  if (keystore.load_signing_pub_from_tee()) {
    ESP_LOGI(TAG, "Signing public key loaded");
  } else {
    ESP_LOGW(TAG, "Failed to load signing public key from TEE");
  }

  // 4. Load exchange public keys if available (for /adv before activation)
  if (keystore.has_exchange_key()) {
    if (keystore.load_exchange_pubs()) {
      ESP_LOGI(TAG, "Exchange public keys loaded (gen %u) — /adv available",
               keystore.gen);
    }
  } else {
    ESP_LOGI(TAG, "No exchange keys yet — will be created on first password");
  }

  // 5. Initialize Zero-Knowledge Authentication (ephemeral tunnel key)
  ESP_LOGI(TAG, "Initializing Zero-Knowledge Authentication...");
  if (zk_auth.init()) {
    ESP_LOGI(TAG, "ZK Auth initialized successfully");
  } else {
    ESP_LOGW(TAG, "ZK Auth initialization failed");
  }

  // 6. WiFi — wait for IP before starting servers
  setup_wifi();
  server_http = setup_plain_http_server();
  server_https = setup_https_server();

  if (server_http && server_https) {
    ESP_LOGI(TAG, "=== ESP32 Tang Server Ready ===");
    ESP_LOGI(TAG, "  ZK Auth UI:  https://<ip>/");
    ESP_LOGI(TAG, "  Tang /adv:   http://<ip>/adv");
    ESP_LOGI(TAG, "  Tang /rec:   http://<ip>/rec  (requires activation)");
  }
}

// --- Main Loop ---
void loop() { vTaskDelay(pdMS_TO_TICKS(1000)); }

#endif // TANG_SERVER_H
