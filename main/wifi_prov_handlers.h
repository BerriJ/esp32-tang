#ifndef WIFI_PROV_HANDLERS_H
#define WIFI_PROV_HANDLERS_H

#include "wifi_prov_page.h"
#include <cJSON.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <string.h>

static const char *TAG_WIFI_PROV = "wifi_prov";

#define WIFI_NVS_NAMESPACE "tang_wifi"
#define NVS_KEY_SSID "ssid"
#define NVS_KEY_PASSWORD "password"
#define NVS_KEY_HOSTNAME "hostname"
#define DEFAULT_HOSTNAME "esp-tang"

// --- NVS Read/Write ---

static bool read_wifi_config_from_nvs(char *ssid, size_t ssid_len,
                                      char *password, size_t pass_len,
                                      char *hostname, size_t host_len) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(WIFI_NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return false;
  }

  size_t len = ssid_len;
  err = nvs_get_str(nvs, NVS_KEY_SSID, ssid, &len);
  if (err != ESP_OK || len <= 1) {
    nvs_close(nvs);
    return false;
  }

  if (password && pass_len > 0) {
    len = pass_len;
    nvs_get_str(nvs, NVS_KEY_PASSWORD, password, &len); // OK if missing
  }

  if (hostname && host_len > 0) {
    len = host_len;
    nvs_get_str(nvs, NVS_KEY_HOSTNAME, hostname, &len); // OK if missing
  }

  nvs_close(nvs);
  return true;
}

static bool save_wifi_config_to_nvs(const char *ssid, const char *password,
                                    const char *hostname) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(WIFI_NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG_WIFI_PROV, "Failed to open NVS: %s", esp_err_to_name(err));
    return false;
  }

  nvs_set_str(nvs, NVS_KEY_SSID, ssid);
  nvs_set_str(nvs, NVS_KEY_PASSWORD, password ? password : "");
  nvs_set_str(nvs, NVS_KEY_HOSTNAME,
              (hostname && strlen(hostname) > 0) ? hostname : DEFAULT_HOSTNAME);
  err = nvs_commit(nvs);
  nvs_close(nvs);

  if (err != ESP_OK) {
    ESP_LOGE(TAG_WIFI_PROV, "NVS commit failed: %s", esp_err_to_name(err));
    return false;
  }

  return true;
}

// --- HTTP Handlers for Provisioning Mode ---

static esp_err_t handle_prov_root(httpd_req_t *req) {
  httpd_resp_set_type(req, "text/html");
  httpd_resp_set_hdr(
      req, "Content-Security-Policy",
      "default-src 'none'; "
      "script-src 'sha256-vYaSfpaKr5QWVc5HgWafqhev+ds32US2HcRFdVHbER4='; "
      "style-src 'sha256-EjixCmbU5VI4SexUFBLu5k4IDdN+JRiJ/L70jSmJPfw='; "
      "img-src data:; "
      "connect-src 'self'; "
      "form-action 'none'; "
      "frame-ancestors 'none'");
  httpd_resp_sendstr(req, WIFI_PROV_PAGE);
  return ESP_OK;
}

static esp_err_t handle_prov_configure(httpd_req_t *req) {
  char buf[256];
  int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
  if (ret <= 0) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
    return ESP_FAIL;
  }
  buf[ret] = '\0';

  cJSON *root = cJSON_Parse(buf);
  if (!root) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *j_ssid = cJSON_GetObjectItem(root, "ssid");
  cJSON *j_password = cJSON_GetObjectItem(root, "password");
  cJSON *j_hostname = cJSON_GetObjectItem(root, "hostname");

  if (!cJSON_IsString(j_ssid) || strlen(j_ssid->valuestring) == 0) {
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req,
                       "{\"success\":false,\"message\":\"SSID is required\"}");
    return ESP_OK;
  }

  const char *ssid = j_ssid->valuestring;
  const char *password =
      cJSON_IsString(j_password) ? j_password->valuestring : "";
  const char *hostname =
      cJSON_IsString(j_hostname) ? j_hostname->valuestring : DEFAULT_HOSTNAME;

  // Validate SSID length
  if (strlen(ssid) > 32) {
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(
        req, "{\"success\":false,\"message\":\"SSID too long (max 32)\"}");
    return ESP_OK;
  }

  // Validate password length
  if (strlen(password) > 64) {
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(
        req, "{\"success\":false,\"message\":\"Password too long (max 64)\"}");
    return ESP_OK;
  }

  // Validate hostname (RFC 1123: alphanumeric + hyphens, max 63 chars)
  size_t hlen = strlen(hostname);
  if (hlen > 63) {
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(
        req, "{\"success\":false,\"message\":\"Hostname too long (max 63)\"}");
    return ESP_OK;
  }
  for (size_t i = 0; i < hlen; i++) {
    char c = hostname[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-')) {
      cJSON_Delete(root);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"Hostname may "
                              "only contain letters, numbers and hyphens\"}");
      return ESP_OK;
    }
  }

  bool saved = save_wifi_config_to_nvs(ssid, password, hostname);
  cJSON_Delete(root);

  httpd_resp_set_type(req, "application/json");
  if (saved) {
    ESP_LOGI(TAG_WIFI_PROV, "WiFi config saved — SSID: %s, hostname: %s", ssid,
             hostname);
    httpd_resp_sendstr(req, "{\"success\":true}");
    // Delay then reboot to apply the new WiFi config
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
  } else {
    httpd_resp_sendstr(
        req, "{\"success\":false,\"message\":\"Failed to save to NVS\"}");
  }

  return ESP_OK;
}

static void register_wifi_prov_handlers(httpd_handle_t server) {
  httpd_uri_t root_uri = {.uri = "/",
                          .method = HTTP_GET,
                          .handler = handle_prov_root,
                          .user_ctx = NULL};
  httpd_register_uri_handler(server, &root_uri);

  httpd_uri_t configure_uri = {.uri = "/api/configure",
                               .method = HTTP_POST,
                               .handler = handle_prov_configure,
                               .user_ctx = NULL};
  httpd_register_uri_handler(server, &configure_uri);
}

#endif // WIFI_PROV_HANDLERS_H
