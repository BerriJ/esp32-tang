#ifndef ZK_HANDLERS_H
#define ZK_HANDLERS_H

#include "zk_auth.h"
#include "zk_web_page.h"
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_timer.h>

static const char *TAG_ZK = "zk_handlers";

extern ZKAuth zk_auth;
extern TangKeyStore keystore;
extern httpd_handle_t server_http;

// Send a JSON response with CORS headers
static void send_json_response(httpd_req_t *req, const char *json,
                               bool success) {
  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_status(req, success ? "200 OK" : "400 Bad Request");
  httpd_resp_sendstr(req, json);
}

// Common handler for POST endpoints that process ECIES payloads via ZKAuth.
// processor: ZKAuth method that takes (json_payload, success_out) and returns
// response JSON.
typedef char *(ZKAuth::*zk_processor_t)(const char *, bool *);

static esp_err_t handle_zk_post(httpd_req_t *req, zk_processor_t processor) {
  char content[1024];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    if (ret == HTTPD_SOCK_ERR_TIMEOUT)
      httpd_resp_send_408(req);
    return ESP_FAIL;
  }
  content[ret] = '\0';

  bool success = false;
  char *response = (zk_auth.*processor)(content, &success);

  if (!response) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Internal error");
    return ESP_FAIL;
  }

  send_json_response(req, response, success);
  free(response);
  return ESP_OK;
}

// Serve the main web interface
static esp_err_t handle_zk_root(httpd_req_t *req) {
  httpd_resp_set_type(req, "text/html");
  httpd_resp_sendstr(req, ZK_WEB_PAGE);
  return ESP_OK;
}

static esp_err_t handle_zk_identity(httpd_req_t *req) {
  char *json_response = zk_auth.get_identity_json();
  if (!json_response) {
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

static esp_err_t handle_zk_unlock(httpd_req_t *req) {
  return handle_zk_post(req, &ZKAuth::process_unlock);
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

static esp_err_t handle_zk_lock(httpd_req_t *req) {
  zk_auth.lock();
  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_sendstr(req, "{\"unlocked\":false}");
  return ESP_OK;
}

static esp_err_t handle_zk_change_password(httpd_req_t *req) {
  return handle_zk_post(req, &ZKAuth::process_change_password);
}

static esp_err_t handle_zk_rotate(httpd_req_t *req) {
  return handle_zk_post(req, &ZKAuth::process_rotate);
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
                                    .handler = handle_cors_options,
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
                                             .handler = handle_cors_options,
                                             .user_ctx = NULL};
  httpd_register_uri_handler(server, &change_password_options_uri);

  httpd_uri_t rotate_uri = {.uri = "/api/rotate",
                            .method = HTTP_POST,
                            .handler = handle_zk_rotate,
                            .user_ctx = NULL};
  httpd_register_uri_handler(server, &rotate_uri);

  httpd_uri_t rotate_options_uri = {.uri = "/api/rotate",
                                    .method = HTTP_OPTIONS,
                                    .handler = handle_cors_options,
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
