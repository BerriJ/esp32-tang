#ifndef TANG_HANDLERS_H
#define TANG_HANDLERS_H

#include "crypto.h"
#include "encoding.h"
#include "tang_storage.h"
#include <cJSON.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <mbedtls/sha256.h>
#include <string.h>

static const char *TAG_HANDLERS = "tang_handlers";

// Forward declarations
extern httpd_handle_t server_http;
extern TangKeyStore keystore;
extern bool unlocked;

// GET /adv - Advertisement endpoint (signed JWK set)
// Available once signing key + exchange key exist (public keys are public).
// Does NOT require activation — only /rec requires unlocked.
static esp_err_t handle_adv(httpd_req_t *req) {
  if (!keystore.sig_loaded || !keystore.exc_pub_loaded) {
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_sendstr(req, "Server not configured");
    return ESP_FAIL;
  }

  char sig_x_b64[64] = {0}, sig_y_b64[64] = {0};
  char rec_x_b64[64] = {0}, rec_y_b64[64] = {0};

  b64url_encode_buf(&keystore.sig_pub[0], 32, sig_x_b64, sizeof(sig_x_b64));
  b64url_encode_buf(&keystore.sig_pub[32], 32, sig_y_b64, sizeof(sig_y_b64));
  b64url_encode_buf(&keystore.exc_pub[0], 32, rec_x_b64, sizeof(rec_x_b64));
  b64url_encode_buf(&keystore.exc_pub[32], 32, rec_y_b64, sizeof(rec_y_b64));

  // Build JWK set payload
  cJSON *payload_root = cJSON_CreateObject();
  cJSON *keys = cJSON_CreateArray();

  // Signing/verification key
  cJSON *sig_key = cJSON_CreateObject();
  cJSON_AddStringToObject(sig_key, "kty", "EC");
  cJSON_AddStringToObject(sig_key, "alg", "ES256");
  cJSON_AddStringToObject(sig_key, "crv", "P-256");
  cJSON_AddStringToObject(sig_key, "x", sig_x_b64);
  cJSON_AddStringToObject(sig_key, "y", sig_y_b64);
  cJSON *sig_key_ops = cJSON_CreateArray();
  cJSON_AddItemToArray(sig_key_ops, cJSON_CreateString("verify"));
  cJSON_AddItemToObject(sig_key, "key_ops", sig_key_ops);
  cJSON_AddItemToArray(keys, sig_key);

  // Exchange/recovery key
  cJSON *rec_key = cJSON_CreateObject();
  cJSON_AddStringToObject(rec_key, "alg", "ECMR");
  cJSON_AddStringToObject(rec_key, "kty", "EC");
  cJSON_AddStringToObject(rec_key, "crv", "P-256");
  cJSON_AddStringToObject(rec_key, "x", rec_x_b64);
  cJSON_AddStringToObject(rec_key, "y", rec_y_b64);
  cJSON *rec_key_ops = cJSON_CreateArray();
  cJSON_AddItemToArray(rec_key_ops, cJSON_CreateString("deriveKey"));
  cJSON_AddItemToObject(rec_key, "key_ops", rec_key_ops);
  cJSON_AddItemToArray(keys, rec_key);

  cJSON_AddItemToObject(payload_root, "keys", keys);

  // Encode payload to base64url
  char *payload_json = cJSON_PrintUnformatted(payload_root);
  size_t payload_len = strlen(payload_json);
  size_t payload_b64_size = ((payload_len + 2) / 3) * 4 + 1;
  char *payload_b64 = (char *)malloc(payload_b64_size);
  b64url_encode_buf((uint8_t *)payload_json, payload_len, payload_b64,
                    payload_b64_size);
  free(payload_json);
  cJSON_Delete(payload_root);

  // Create protected header
  cJSON *protected_root = cJSON_CreateObject();
  cJSON_AddStringToObject(protected_root, "alg", "ES256");
  cJSON_AddStringToObject(protected_root, "cty", "jwk-set+json");

  char *protected_json = cJSON_PrintUnformatted(protected_root);
  size_t protected_len = strlen(protected_json);
  size_t protected_b64_size = ((protected_len + 2) / 3) * 4 + 1;
  char *protected_b64 = (char *)malloc(protected_b64_size);
  b64url_encode_buf((uint8_t *)protected_json, protected_len, protected_b64,
                    protected_b64_size);
  free(protected_json);
  cJSON_Delete(protected_root);

  // Sign: SHA-256(protected_b64 "." payload_b64) with software P-256
  size_t signing_input_size =
      strlen(protected_b64) + 1 + strlen(payload_b64) + 1;
  char *signing_input = (char *)malloc(signing_input_size);
  snprintf(signing_input, signing_input_size, "%s.%s", protected_b64,
           payload_b64);

  uint8_t hash[32];
  mbedtls_sha256((const uint8_t *)signing_input, strlen(signing_input), hash,
                 0);
  free(signing_input);

  uint8_t signature[64]; // r(32) + s(32)
  if (!P256::sign(hash, 32, keystore.sig_priv, signature)) {
    ESP_LOGE(TAG_HANDLERS, "Software signing failed");
    free(payload_b64);
    free(protected_b64);
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Signing failed");
    return ESP_FAIL;
  }

  char sig_b64[128] = {0};
  b64url_encode_buf(signature, sizeof(signature), sig_b64, sizeof(sig_b64));

  cJSON *jws_root = cJSON_CreateObject();
  cJSON_AddStringToObject(jws_root, "payload", payload_b64);
  cJSON_AddStringToObject(jws_root, "protected", protected_b64);
  cJSON_AddStringToObject(jws_root, "signature", sig_b64);

  char *response = cJSON_PrintUnformatted(jws_root);
  cJSON_Delete(jws_root);

  free(payload_b64);
  free(protected_b64);

  httpd_resp_set_type(req, "application/jose+json");
  httpd_resp_sendstr(req, response);
  free(response);

  ESP_LOGI(TAG_HANDLERS, "Served /adv");
  return ESP_OK;
}

// POST /rec or /rec/{kid} - Recovery endpoint (requires activation)
static esp_err_t handle_rec(httpd_req_t *req) {
  if (!unlocked) {
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_sendstr(req, "Server not active");
    return ESP_FAIL;
  }

  char *buf = (char *)malloc(req->content_len + 1);
  if (!buf) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Memory allocation failed");
    return ESP_FAIL;
  }

  int ret = httpd_req_recv(req, buf, req->content_len);
  if (ret <= 0) {
    free(buf);
    if (ret == HTTPD_SOCK_ERR_TIMEOUT)
      httpd_resp_send_408(req);
    return ESP_FAIL;
  }
  buf[ret] = '\0';

  cJSON *req_doc = cJSON_Parse(buf);
  free(buf);

  if (!req_doc) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *x_item = cJSON_GetObjectItem(req_doc, "x");
  cJSON *y_item = cJSON_GetObjectItem(req_doc, "y");

  if (!x_item || !y_item || !cJSON_IsString(x_item) ||
      !cJSON_IsString(y_item)) {
    cJSON_Delete(req_doc);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                        "Missing x or y coordinates");
    return ESP_FAIL;
  }

  uint8_t client_pub_key[P256_PUBLIC_KEY_SIZE];

  if (!b64url_decode_buf(x_item->valuestring, &client_pub_key[0],
                         P256_COORDINATE_SIZE) ||
      !b64url_decode_buf(y_item->valuestring,
                         &client_pub_key[P256_COORDINATE_SIZE],
                         P256_COORDINATE_SIZE)) {
    cJSON_Delete(req_doc);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid key coordinates");
    return ESP_FAIL;
  }

  cJSON_Delete(req_doc);

  // Software ECDH
  uint8_t shared_point[P256_PUBLIC_KEY_SIZE];
  if (!P256::ecdh_compute_shared_point(client_pub_key, keystore.exc_priv,
                                       shared_point, true)) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "ECDH computation failed");
    return ESP_FAIL;
  }

  char shared_x_b64[64] = {0};
  char shared_y_b64[64] = {0};

  b64url_encode_buf(&shared_point[0], P256_COORDINATE_SIZE, shared_x_b64,
                    sizeof(shared_x_b64));
  b64url_encode_buf(&shared_point[P256_COORDINATE_SIZE], P256_COORDINATE_SIZE,
                    shared_y_b64, sizeof(shared_y_b64));

  cJSON *resp_root = cJSON_CreateObject();
  cJSON_AddStringToObject(resp_root, "alg", "ECMR");
  cJSON_AddStringToObject(resp_root, "kty", "EC");
  cJSON_AddStringToObject(resp_root, "crv", "P-256");
  cJSON_AddStringToObject(resp_root, "x", shared_x_b64);
  cJSON_AddStringToObject(resp_root, "y", shared_y_b64);
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

// GET /reboot - Reboot device
static esp_err_t handle_reboot(httpd_req_t *req) {
  httpd_resp_sendstr(req, "Rebooting...");
  vTaskDelay(pdMS_TO_TICKS(1000));
  esp_restart();
  return ESP_OK;
}

// 404 handler - Route /rec/{kid} to handle_rec
static esp_err_t handle_not_found(httpd_req_t *req, httpd_err_code_t err) {
  if (req->method == HTTP_POST && strncmp(req->uri, "/rec/", 5) == 0) {
    return handle_rec(req);
  }

  httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
  return ESP_FAIL;
}

#endif // TANG_HANDLERS_H
