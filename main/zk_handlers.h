#ifndef ZK_HANDLERS_H
#define ZK_HANDLERS_H

#include "zk_auth.h"
#include "zk_web_page.h"
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <string.h>

static const char *TAG_ZK = "zk_handlers";

extern ZKAuth zk_auth;
extern TangKeyStore keystore;
extern httpd_handle_t server_http;

// Serve the main web interface
static esp_err_t handle_zk_root(httpd_req_t *req) {
  httpd_resp_set_type(req, "text/html");
  httpd_resp_sendstr(req, ZK_WEB_PAGE);
  return ESP_OK;
}

// API endpoint: Get device identity
static esp_err_t handle_zk_identity(httpd_req_t *req) {
  char *json_response = zk_auth.get_identity_json();
  if (json_response == NULL) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Failed to get identity");
    return ESP_FAIL;
  }

  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_sendstr(req, json_response);
  free(json_response);
  return ESP_OK;
}

// API endpoint: Process unlock request
static esp_err_t handle_zk_unlock(httpd_req_t *req) {
  // Read POST body
  char content[1024];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
      httpd_resp_send_408(req);
    }
    return ESP_FAIL;
  }
  content[ret] = '\0';

  bool success = false;
  char *response = zk_auth.process_unlock(content, &success);

  if (response == NULL) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Internal error");
    return ESP_FAIL;
  }

  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_status(req, success ? "200 OK" : "400 Bad Request");
  httpd_resp_sendstr(req, response);
  free(response);
  return ESP_OK;
}

static esp_err_t handle_zk_status(httpd_req_t *req) {
  unsigned long uptime_ms = esp_timer_get_time() / 1000;
  char response[192];
  snprintf(response, sizeof(response),
           "{\"unlocked\":%s,\"configured\":%s,\"gen\":%u,\"uptime\":%lu}",
           zk_auth.is_unlocked() ? "true" : "false",
           keystore.has_exchange_key() ? "true" : "false", keystore.gen,
           uptime_ms);

  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_sendstr(req, response);
  return ESP_OK;
}

// API endpoint: Lock the device
static esp_err_t handle_zk_lock(httpd_req_t *req) {
  zk_auth.lock();
  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_sendstr(req, "{\"unlocked\":false}");
  return ESP_OK;
}

// API endpoint: Change password (requires device to be unlocked)
static esp_err_t handle_zk_change_password(httpd_req_t *req) {
  char content[1024];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
      httpd_resp_send_408(req);
    }
    return ESP_FAIL;
  }
  content[ret] = '\0';

  bool success = false;
  char *response = zk_auth.process_change_password(content, &success);

  if (response == NULL) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Internal error");
    return ESP_FAIL;
  }

  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_status(req, success ? "200 OK" : "400 Bad Request");
  httpd_resp_sendstr(req, response);
  free(response);
  return ESP_OK;
}

// API endpoint: Rotate to next exchange key generation (requires unlock +
// password)
static esp_err_t handle_zk_rotate(httpd_req_t *req) {
  char content[1024];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
      httpd_resp_send_408(req);
    }
    return ESP_FAIL;
  }
  content[ret] = '\0';

  bool success = false;
  char *response = zk_auth.process_rotate(content, &success);

  if (response == NULL) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Internal error");
    return ESP_FAIL;
  }

  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_status(req, success ? "200 OK" : "400 Bad Request");
  httpd_resp_sendstr(req, response);
  free(response);
  return ESP_OK;
}

// Handle CORS preflight
static esp_err_t handle_zk_options(httpd_req_t *req) {
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
  httpd_resp_set_status(req, "204 No Content");
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

// Register all ZK auth routes to the HTTP server
void register_zk_handlers(httpd_handle_t server) {
  // Root handler for ZK web interface
  httpd_uri_t root_uri = {.uri = "/",
                          .method = HTTP_GET,
                          .handler = handle_zk_root,
                          .user_ctx = NULL};
  httpd_register_uri_handler(server, &root_uri);

  // API endpoints
  httpd_uri_t identity_uri = {.uri = "/api/identity",
                              .method = HTTP_GET,
                              .handler = handle_zk_identity,
                              .user_ctx = NULL};
  httpd_register_uri_handler(server, &identity_uri);

  httpd_uri_t status_uri = {.uri = "/api/status",
                            .method = HTTP_GET,
                            .handler = handle_zk_status,
                            .user_ctx = NULL};
  httpd_register_uri_handler(server, &status_uri);

  httpd_uri_t unlock_uri = {.uri = "/api/unlock",
                            .method = HTTP_POST,
                            .handler = handle_zk_unlock,
                            .user_ctx = NULL};
  httpd_register_uri_handler(server, &unlock_uri);

  httpd_uri_t unlock_options_uri = {.uri = "/api/unlock",
                                    .method = HTTP_OPTIONS,
                                    .handler = handle_zk_options,
                                    .user_ctx = NULL};
  httpd_register_uri_handler(server, &unlock_options_uri);

  httpd_uri_t lock_uri = {.uri = "/api/lock",
                          .method = HTTP_POST,
                          .handler = handle_zk_lock,
                          .user_ctx = NULL};
  httpd_register_uri_handler(server, &lock_uri);

  httpd_uri_t change_password_uri = {.uri = "/api/change-password",
                                     .method = HTTP_POST,
                                     .handler = handle_zk_change_password,
                                     .user_ctx = NULL};
  httpd_register_uri_handler(server, &change_password_uri);

  httpd_uri_t change_password_options_uri = {.uri = "/api/change-password",
                                             .method = HTTP_OPTIONS,
                                             .handler = handle_zk_options,
                                             .user_ctx = NULL};
  httpd_register_uri_handler(server, &change_password_options_uri);

  httpd_uri_t rotate_uri = {.uri = "/api/rotate",
                            .method = HTTP_POST,
                            .handler = handle_zk_rotate,
                            .user_ctx = NULL};
  httpd_register_uri_handler(server, &rotate_uri);

  httpd_uri_t rotate_options_uri = {.uri = "/api/rotate",
                                    .method = HTTP_OPTIONS,
                                    .handler = handle_zk_options,
                                    .user_ctx = NULL};
  httpd_register_uri_handler(server, &rotate_options_uri);

  ESP_LOGI(TAG_ZK, "ZK Auth routes registered:");
  ESP_LOGI(TAG_ZK, "  GET  /             - Web interface");
  ESP_LOGI(TAG_ZK, "  GET  /api/identity - Device identity");
  ESP_LOGI(TAG_ZK, "  GET  /api/status   - Session status");
  ESP_LOGI(TAG_ZK, "  POST /api/unlock   - Unlock request");
  ESP_LOGI(TAG_ZK, "  POST /api/lock     - Lock device");
  ESP_LOGI(TAG_ZK, "  POST /api/change-password - Change password");
  ESP_LOGI(TAG_ZK, "  POST /api/rotate   - Rotate exchange key");
}

#endif // ZK_HANDLERS_H
