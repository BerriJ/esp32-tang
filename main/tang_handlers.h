#ifndef TANG_HANDLERS_H
#define TANG_HANDLERS_H

#include <esp_http_server.h>
#include <cJSON.h>
#include <mbedtls/sha256.h>
#include <esp_log.h>
#include <string>
#include "crypto.h"
#include "encoding.h"
#include "jwe.h"
#include "tang_storage.h"

static const char *TAG_HANDLERS = "tang_handlers";

// Forward declarations
extern httpd_handle_t server_http;
extern TangKeyStore keystore;
extern bool is_active;

// --- Tang Protocol Handlers ---

// GET /adv - Advertisement endpoint (signed JWK set)
static esp_err_t handle_adv(httpd_req_t *req)
{
  if (!is_active)
  {
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_sendstr(req, "Server not active");
    return ESP_FAIL;
  }

  // Build JWK set payload using cJSON
  cJSON *payload_root = cJSON_CreateObject();
  cJSON *keys = cJSON_CreateArray();

  // Signing/verification key
  cJSON *sig_key = cJSON_CreateObject();
  cJSON_AddStringToObject(sig_key, "alg", "ES256");
  cJSON_AddStringToObject(sig_key, "kty", "EC");
  cJSON_AddStringToObject(sig_key, "crv", "P-256");
  cJSON_AddStringToObject(sig_key, "x", Base64URL::encode(keystore.sig_pub, P256_COORDINATE_SIZE).c_str());
  cJSON_AddStringToObject(sig_key, "y", Base64URL::encode(keystore.sig_pub + P256_COORDINATE_SIZE, P256_COORDINATE_SIZE).c_str());
  cJSON *sig_key_ops = cJSON_CreateArray();
  cJSON_AddItemToArray(sig_key_ops, cJSON_CreateString("verify"));
  cJSON_AddItemToObject(sig_key, "key_ops", sig_key_ops);
  cJSON_AddItemToArray(keys, sig_key);

  // Recovery/exchange key
  cJSON *rec_key = cJSON_CreateObject();
  cJSON_AddStringToObject(rec_key, "alg", "ECMR");
  cJSON_AddStringToObject(rec_key, "kty", "EC");
  cJSON_AddStringToObject(rec_key, "crv", "P-256");
  cJSON_AddStringToObject(rec_key, "x", Base64URL::encode(keystore.exc_pub, P256_COORDINATE_SIZE).c_str());
  cJSON_AddStringToObject(rec_key, "y", Base64URL::encode(keystore.exc_pub + P256_COORDINATE_SIZE, P256_COORDINATE_SIZE).c_str());
  cJSON *rec_key_ops = cJSON_CreateArray();
  cJSON_AddItemToArray(rec_key_ops, cJSON_CreateString("deriveKey"));
  cJSON_AddItemToObject(rec_key, "key_ops", rec_key_ops);
  cJSON_AddItemToArray(keys, rec_key);

  cJSON_AddItemToObject(payload_root, "keys", keys);

  char *payload_json = cJSON_PrintUnformatted(payload_root);
  std::string payload_b64 = Base64URL::encode((uint8_t *)payload_json, strlen(payload_json));
  free(payload_json);
  cJSON_Delete(payload_root);

  // Create protected header
  cJSON *protected_root = cJSON_CreateObject();
  cJSON_AddStringToObject(protected_root, "alg", "ES256");
  cJSON_AddStringToObject(protected_root, "cty", "jwk-set+json");

  char *protected_json = cJSON_PrintUnformatted(protected_root);
  std::string protected_b64 = Base64URL::encode((uint8_t *)protected_json, strlen(protected_json));
  free(protected_json);
  cJSON_Delete(protected_root);

  // Sign the payload
  std::string signing_input = protected_b64 + "." + payload_b64;
  uint8_t hash[32];
  mbedtls_sha256((uint8_t *)signing_input.c_str(), signing_input.length(), hash, 0);

  uint8_t signature[P256_PUBLIC_KEY_SIZE];
  if (!P256::sign(hash, 32, keystore.sig_priv, signature))
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Signing failed");
    return ESP_FAIL;
  }

  // Build JWS response
  cJSON *jws_root = cJSON_CreateObject();
  cJSON_AddStringToObject(jws_root, "payload", payload_b64.c_str());
  cJSON_AddStringToObject(jws_root, "protected", protected_b64.c_str());
  cJSON_AddStringToObject(jws_root, "signature", Base64URL::encode(signature, P256_PUBLIC_KEY_SIZE).c_str());

  char *response = cJSON_PrintUnformatted(jws_root);
  cJSON_Delete(jws_root);

  httpd_resp_set_type(req, "application/json");
  httpd_resp_sendstr(req, response);
  free(response);

  ESP_LOGI(TAG_HANDLERS, "Served /adv");
  return ESP_OK;
}

// POST /rec or /rec/{kid} - Recovery endpoint
static esp_err_t handle_rec(httpd_req_t *req)
{
  if (!is_active)
  {
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_sendstr(req, "Server not active");
    return ESP_FAIL;
  }

  // Read request body
  char *buf = (char *)malloc(req->content_len + 1);
  if (!buf)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory allocation failed");
    return ESP_FAIL;
  }

  int ret = httpd_req_recv(req, buf, req->content_len);
  if (ret <= 0)
  {
    free(buf);
    if (ret == HTTPD_SOCK_ERR_TIMEOUT)
    {
      httpd_resp_send_408(req);
    }
    return ESP_FAIL;
  }
  buf[ret] = '\0';

  // Parse JSON
  cJSON *req_doc = cJSON_Parse(buf);
  free(buf);

  if (!req_doc)
  {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  // Extract client's ephemeral public key
  cJSON *x_item = cJSON_GetObjectItem(req_doc, "x");
  cJSON *y_item = cJSON_GetObjectItem(req_doc, "y");

  if (!x_item || !y_item || !cJSON_IsString(x_item) || !cJSON_IsString(y_item))
  {
    cJSON_Delete(req_doc);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing x or y coordinates");
    return ESP_FAIL;
  }

  uint8_t client_pub_key[P256_PUBLIC_KEY_SIZE];
  if (Base64URL::decode(std::string(x_item->valuestring), client_pub_key, P256_COORDINATE_SIZE) != P256_COORDINATE_SIZE ||
      Base64URL::decode(std::string(y_item->valuestring), client_pub_key + P256_COORDINATE_SIZE, P256_COORDINATE_SIZE) != P256_COORDINATE_SIZE)
  {
    cJSON_Delete(req_doc);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid key coordinates");
    return ESP_FAIL;
  }

  cJSON_Delete(req_doc);

  // Perform ECDH to get shared point
  uint8_t shared_point[P256_PUBLIC_KEY_SIZE];
  if (!P256::ecdh_compute_shared_point(client_pub_key, keystore.exc_priv, shared_point, true))
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ECDH computation failed");
    return ESP_FAIL;
  }

  // Return shared point as JWK
  cJSON *resp_root = cJSON_CreateObject();
  cJSON_AddStringToObject(resp_root, "alg", "ECMR");
  cJSON_AddStringToObject(resp_root, "kty", "EC");
  cJSON_AddStringToObject(resp_root, "crv", "P-256");
  cJSON_AddStringToObject(resp_root, "x", Base64URL::encode(shared_point, P256_COORDINATE_SIZE).c_str());
  cJSON_AddStringToObject(resp_root, "y", Base64URL::encode(shared_point + P256_COORDINATE_SIZE, P256_COORDINATE_SIZE).c_str());
  cJSON *key_ops = cJSON_CreateArray();
  cJSON_AddItemToArray(key_ops, cJSON_CreateString("deriveKey"));
  cJSON_AddItemToObject(resp_root, "key_ops", key_ops);

  char *response = cJSON_PrintUnformatted(resp_root);
  cJSON_Delete(resp_root);

  httpd_resp_set_type(req, "application/jose+json");
  httpd_resp_sendstr(req, response);
  free(response);

  ESP_LOGI(TAG_HANDLERS, "Served %s", req->uri);
  return ESP_OK;
}

// --- Administration Handlers ---

// GET /config - Get ATECC608B configuration
static esp_err_t handle_config(httpd_req_t *req)
{
  ESP_LOGI(TAG_HANDLERS, "Serving ATECC608B config");

  char *json_str = atecc608B_get_config_json();

  if (!json_str)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Config data not available");
    return ESP_FAIL;
  }

  httpd_resp_set_type(req, "application/json");
  httpd_resp_sendstr(req, json_str);
  free(json_str);

  ESP_LOGI(TAG_HANDLERS, "Served /config");
  return ESP_OK;
}

// GET /pub - Get admin public key
static esp_err_t handle_pub(httpd_req_t *req)
{
  cJSON *doc = cJSON_CreateObject();
  cJSON_AddStringToObject(doc, "kty", "EC");
  cJSON_AddStringToObject(doc, "crv", "P-256");
  cJSON_AddStringToObject(doc, "x", Base64URL::encode(keystore.admin_pub, P256_COORDINATE_SIZE).c_str());
  cJSON_AddStringToObject(doc, "y", Base64URL::encode(keystore.admin_pub + P256_COORDINATE_SIZE, P256_COORDINATE_SIZE).c_str());
  cJSON_AddStringToObject(doc, "alg", "ECDH-ES");

  char *response = cJSON_PrintUnformatted(doc);
  cJSON_Delete(doc);

  httpd_resp_set_type(req, "application/json");
  httpd_resp_sendstr(req, response);
  free(response);

  ESP_LOGI(TAG_HANDLERS, "Served /pub");
  return ESP_OK;
}

// GET /reboot - Reboot device
static esp_err_t handle_reboot(httpd_req_t *req)
{
  httpd_resp_sendstr(req, "Rebooting...");
  vTaskDelay(pdMS_TO_TICKS(1000));
  esp_restart();
  return ESP_OK;
}

// GET /reset or /nuke - Nuke configuration and restart
static esp_err_t handle_reset(httpd_req_t *req)
{
  ESP_LOGI(TAG_HANDLERS, "Reset endpoint called. Nuking configuration...");
  keystore.nuke();
  httpd_resp_sendstr(req, "Nuked configuration and restarting...");
  vTaskDelay(pdMS_TO_TICKS(1000));
  esp_restart();
  return ESP_OK;
}

// 404 handler - Handle /rec/{kid} by routing to handle_rec
static esp_err_t handle_not_found(httpd_req_t *req, httpd_err_code_t err)
{
  // Check if it's a POST to /rec/{kid}
  if (req->method == HTTP_POST && strncmp(req->uri, "/rec/", 5) == 0)
  {
    return handle_rec(req);
  }

  httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
  return ESP_FAIL;
}

#endif // TANG_HANDLERS_H
