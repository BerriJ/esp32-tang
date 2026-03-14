#ifndef PROVISION_HANDLERS_H
#define PROVISION_HANDLERS_H

#include "provision.h"
#include "provision_web_page.h"
#include <cJSON.h>
#include <esp_http_server.h>
#include <esp_log.h>

static const char *TAG_PROVISION_HANDLERS = "provision_handlers";

// Forward declarations
extern httpd_handle_t server_http;

/**
 * Serve the provisioning web page
 */
static esp_err_t handle_provision_page(httpd_req_t *req) {
  httpd_resp_set_type(req, "text/html");
  httpd_resp_sendstr(req, PROVISION_WEB_PAGE);
  return ESP_OK;
}

/**
 * API endpoint: Get provisioning status
 */
static esp_err_t handle_provision_status(httpd_req_t *req) {
  cJSON *response = cJSON_CreateObject();

  bool config_unlocked = !is_atecc608b_config_locked();
  bool data_unlocked = !is_atecc608b_data_locked();
  bool key5_unused = !is_efuse_key5_used();
  bool needs_prov = needs_provisioning();

  cJSON_AddBoolToObject(response, "needs_provisioning", needs_prov);
  cJSON_AddBoolToObject(response, "config_unlocked", config_unlocked);
  cJSON_AddBoolToObject(response, "data_unlocked", data_unlocked);
  cJSON_AddBoolToObject(response, "key5_unused", key5_unused);

  char *json_str = cJSON_PrintUnformatted(response);
  cJSON_Delete(response);

  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_sendstr(req, json_str);
  free(json_str);

  return ESP_OK;
}

/**
 * API endpoint: Provision the device EFUSE
 */
static esp_err_t handle_provision_api(httpd_req_t *req) {
  ESP_LOGI(TAG_PROVISION_HANDLERS, "Provisioning API called");

  cJSON *response = cJSON_CreateObject();
  bool success = false;
  const char *message = "Unknown error";

  // Check if provisioning is actually needed
  if (!needs_provisioning()) {
    message = "Device is already provisioned";
    success = true;
    ESP_LOGI(TAG_PROVISION_HANDLERS, "%s", message);
  } else {
    bool efuse_done = true;
    bool config_done = true;
    bool data_done = true;

    // Track what was actually provisioned for the success message
    bool did_efuse = false;
    bool did_config = false;
    bool did_data = false;

    // Step 1: Provision EFUSE KEY5 first (needed by HMAC peripheral for
    // bonding)
    if (!is_efuse_key5_used()) {
      ESP_LOGI(TAG_PROVISION_HANDLERS, "Provisioning EFUSE KEY5...");
      did_efuse = true;
      efuse_done = provision_efuse_key5();
      if (!efuse_done) {
        message = "Failed to provision EFUSE KEY5";
        success = false;
        ESP_LOGE(TAG_PROVISION_HANDLERS, "%s", message);
      }
    }

    // Step 2: Provision ATECC608B config if needed
    if (efuse_done && !is_atecc608b_config_locked()) {
      ESP_LOGI(TAG_PROVISION_HANDLERS,
               "Provisioning ATECC608B configuration...");
      did_config = true;
      config_done = provision_atecc608b_config();
      if (!config_done) {
        message = "Failed to provision ATECC608B configuration";
        success = false;
        ESP_LOGE(TAG_PROVISION_HANDLERS, "%s", message);
      }
    }

    // Step 3: Provision ATECC608B data zone (uses HMAC peripheral + eFuse key)
    if (efuse_done && config_done && !is_atecc608b_data_locked()) {
      ESP_LOGI(TAG_PROVISION_HANDLERS, "Provisioning ATECC608B data zone...");
      did_data = true;
      data_done = provision_atecc608b_data_zone();
      if (!data_done) {
        message = "Failed to provision ATECC608B data zone";
        success = false;
        ESP_LOGE(TAG_PROVISION_HANDLERS, "%s", message);
      }
    }

    // Build success message based on what was actually done
    if (efuse_done && config_done && data_done) {
      if (did_efuse && did_config && did_data) {
        message = "Full provisioning complete (eFuse KEY5 + ATECC608B config + "
                  "data zone)";
      } else if (did_efuse && did_config) {
        message = "Provisioned eFuse KEY5 and ATECC608B configuration";
      } else if (did_config && did_data) {
        message = "Provisioned ATECC608B config and data zone (eFuse KEY5 was "
                  "already set)";
      } else if (did_efuse && did_data) {
        message = "Provisioned eFuse KEY5 and ATECC608B data zone";
      } else if (did_efuse) {
        message = "eFuse KEY5 provisioned successfully";
      } else if (did_config) {
        message = "ATECC608B configuration provisioned and locked";
      } else if (did_data) {
        message = "ATECC608B data zone provisioned and locked";
      } else {
        message = "Device is already provisioned";
      }
      success = true;
      ESP_LOGI(TAG_PROVISION_HANDLERS, "%s", message);
    }
  }

  // Build JSON response
  cJSON_AddBoolToObject(response, "success", success);
  cJSON_AddStringToObject(response, "message", message);

  char *json_str = cJSON_PrintUnformatted(response);
  cJSON_Delete(response);

  // Send response
  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_status(req, success ? "200 OK" : "500 Internal Server Error");
  httpd_resp_sendstr(req, json_str);
  free(json_str);

  return ESP_OK;
}

/**
 * Handle CORS preflight for provision API
 */
static esp_err_t handle_provision_options(httpd_req_t *req) {
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
  httpd_resp_set_status(req, "204 No Content");
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

/**
 * Register provisioning handlers
 */
void register_provision_handlers(httpd_handle_t server) {
  // Provision page
  httpd_uri_t provision_page_uri = {.uri = "/provision",
                                    .method = HTTP_GET,
                                    .handler = handle_provision_page,
                                    .user_ctx = NULL};
  httpd_register_uri_handler(server, &provision_page_uri);

  // API endpoint for getting status
  httpd_uri_t provision_status_uri = {.uri = "/api/provision/status",
                                      .method = HTTP_GET,
                                      .handler = handle_provision_status,
                                      .user_ctx = NULL};
  httpd_register_uri_handler(server, &provision_status_uri);

  // API endpoint for provisioning
  httpd_uri_t provision_api_uri = {.uri = "/api/provision",
                                   .method = HTTP_POST,
                                   .handler = handle_provision_api,
                                   .user_ctx = NULL};
  httpd_register_uri_handler(server, &provision_api_uri);

  // CORS preflight
  httpd_uri_t provision_options_uri = {.uri = "/api/provision",
                                       .method = HTTP_OPTIONS,
                                       .handler = handle_provision_options,
                                       .user_ctx = NULL};
  httpd_register_uri_handler(server, &provision_options_uri);

  ESP_LOGI(TAG_PROVISION_HANDLERS, "Provision routes registered:");
  ESP_LOGI(TAG_PROVISION_HANDLERS,
           "  GET  /provision             - Provision page");
  ESP_LOGI(TAG_PROVISION_HANDLERS,
           "  GET  /api/provision/status  - Provision status");
  ESP_LOGI(TAG_PROVISION_HANDLERS, "  POST /api/provision  - Provision API");
}

#endif // PROVISION_HANDLERS_H
