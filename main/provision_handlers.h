#ifndef PROVISION_HANDLERS_H
#define PROVISION_HANDLERS_H

#include "provision.h"
#include <cJSON.h>
#include <esp_http_server.h>
#include <esp_log.h>

static const char *TAG_PROVISION_HANDLERS = "provision_handlers";

// Shared CORS preflight handler (used by provision and ZK endpoints)
static esp_err_t handle_cors_options(httpd_req_t *req) {
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
  httpd_resp_set_status(req, "204 No Content");
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

/**
 * API endpoint: Get eFuse provisioning status
 */
static esp_err_t handle_provision_status(httpd_req_t *req) {
  cJSON *response = cJSON_CreateObject();

  bool hmac_up = is_efuse_key5_hmac_up();
  bool key5_free = is_efuse_key5_free();

  cJSON_AddBoolToObject(response, "key5_provisioned", hmac_up);
  cJSON_AddBoolToObject(response, "key5_free", key5_free);
  if (!hmac_up && !key5_free) {
    cJSON_AddStringToObject(response, "error",
                            "SLOT 5 occupied with wrong purpose");
  }

  char *json_str = cJSON_PrintUnformatted(response);
  cJSON_Delete(response);

  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_sendstr(req, json_str);
  free(json_str);

  return ESP_OK;
}

/**
 * API endpoint: Provision eFuse KEY5 (one-time operation)
 */
static esp_err_t handle_provision_api(httpd_req_t *req) {
  ESP_LOGI(TAG_PROVISION_HANDLERS, "Provisioning API called");

  cJSON *response = cJSON_CreateObject();
  bool success = false;
  const char *message = "Unknown error";

  if (is_efuse_key5_hmac_up()) {
    message = "EFUSE KEY5 is already provisioned with HMAC_UP";
    success = true;
  } else if (!is_efuse_key5_free()) {
    message = "EFUSE KEY5 has wrong purpose — cannot re-provision";
  } else {
    ESP_LOGI(TAG_PROVISION_HANDLERS, "Provisioning EFUSE KEY5...");
    if (provision_efuse_key5()) {
      message = "EFUSE KEY5 provisioned successfully with random HMAC key";
      success = true;
    } else {
      message = "Failed to provision EFUSE KEY5";
    }
  }

  cJSON_AddBoolToObject(response, "success", success);
  cJSON_AddStringToObject(response, "message", message);

  char *json_str = cJSON_PrintUnformatted(response);
  cJSON_Delete(response);

  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_status(req, success ? "200 OK" : "500 Internal Server Error");
  httpd_resp_sendstr(req, json_str);
  free(json_str);

  return ESP_OK;
}

/**
 * Register provisioning handlers
 */
void register_provision_handlers(httpd_handle_t server) {
  httpd_uri_t provision_status_uri = {.uri = "/api/provision/status",
                                      .method = HTTP_GET,
                                      .handler = handle_provision_status,
                                      .user_ctx = NULL};
  httpd_register_uri_handler(server, &provision_status_uri);

  httpd_uri_t provision_api_uri = {.uri = "/api/provision",
                                   .method = HTTP_POST,
                                   .handler = handle_provision_api,
                                   .user_ctx = NULL};
  httpd_register_uri_handler(server, &provision_api_uri);

  httpd_uri_t provision_options_uri = {.uri = "/api/provision",
                                       .method = HTTP_OPTIONS,
                                       .handler = handle_cors_options,
                                       .user_ctx = NULL};
  httpd_register_uri_handler(server, &provision_options_uri);

  ESP_LOGI(TAG_PROVISION_HANDLERS, "Provision routes registered:");
  ESP_LOGI(TAG_PROVISION_HANDLERS,
           "  GET  /api/provision/status  - eFuse provisioning status");
  ESP_LOGI(TAG_PROVISION_HANDLERS,
           "  POST /api/provision         - Trigger eFuse provisioning");
}

#endif // PROVISION_HANDLERS_H
