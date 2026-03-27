#ifndef TANG_HANDLERS_H
#define TANG_HANDLERS_H

#include "crypto.h"
#include "encoding.h"
#include "tang_storage.h"
#include <cJSON.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <string.h>

static const char *TAG_HANDLERS = "tang_handlers";

// Forward declarations
extern httpd_handle_t server_http;
extern TangKeyStore keystore;
extern bool unlocked;

// GET /adv - Advertisement endpoint (signed JWK set)
// Advertises only the newest exchange key (gen, at slot gen%NUM_EXCHANGE_KEYS).
// Requires activation since signing key is derived on-demand.
static esp_err_t handle_adv(httpd_req_t *req) {
  if (!keystore.sig_loaded || !keystore.exc_pub_loaded || !keystore.activated) {
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_sendstr(req, "Server not configured");
    return ESP_FAIL;
  }

  int adv_slot = TangKeyStore::slot(keystore.gen);

  // P-521 coordinates are 66 bytes → base64url ≈ 88 chars
  char sig_x_b64[96] = {0}, sig_y_b64[96] = {0};
  char rec_x_b64[96] = {0}, rec_y_b64[96] = {0};

  b64url_encode_buf(&keystore.sig_pub[0], EC_COORDINATE_SIZE, sig_x_b64,
                    sizeof(sig_x_b64));
  b64url_encode_buf(&keystore.sig_pub[EC_COORDINATE_SIZE], EC_COORDINATE_SIZE,
                    sig_y_b64, sizeof(sig_y_b64));
  b64url_encode_buf(&keystore.exc_pub[adv_slot][0], EC_COORDINATE_SIZE,
                    rec_x_b64, sizeof(rec_x_b64));
  b64url_encode_buf(&keystore.exc_pub[adv_slot][EC_COORDINATE_SIZE],
                    EC_COORDINATE_SIZE, rec_y_b64, sizeof(rec_y_b64));

  // Build JWK set payload
  cJSON *payload_root = cJSON_CreateObject();
  cJSON *keys = cJSON_CreateArray();

  // Signing/verification key
  cJSON *sig_key = cJSON_CreateObject();
  cJSON_AddStringToObject(sig_key, "kty", "EC");
  cJSON_AddStringToObject(sig_key, "alg", "ES512");
  cJSON_AddStringToObject(sig_key, "crv", "P-521");
  cJSON_AddStringToObject(sig_key, "x", sig_x_b64);
  cJSON_AddStringToObject(sig_key, "y", sig_y_b64);
  cJSON *sig_key_ops = cJSON_CreateArray();
  cJSON_AddItemToArray(sig_key_ops, cJSON_CreateString("verify"));
  cJSON_AddItemToObject(sig_key, "key_ops", sig_key_ops);
  cJSON_AddItemToArray(keys, sig_key);

  // Exchange/recovery key (newest generation only)
  cJSON *rec_key = cJSON_CreateObject();
  cJSON_AddStringToObject(rec_key, "alg", "ECMR");
  cJSON_AddStringToObject(rec_key, "kty", "EC");
  cJSON_AddStringToObject(rec_key, "crv", "P-521");
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
  cJSON_AddStringToObject(protected_root, "alg", "ES512");
  cJSON_AddStringToObject(protected_root, "cty", "jwk-set+json");

  char *protected_json = cJSON_PrintUnformatted(protected_root);
  size_t protected_len = strlen(protected_json);
  size_t protected_b64_size = ((protected_len + 2) / 3) * 4 + 1;
  char *protected_b64 = (char *)malloc(protected_b64_size);
  b64url_encode_buf((uint8_t *)protected_json, protected_len, protected_b64,
                    protected_b64_size);
  free(protected_json);
  cJSON_Delete(protected_root);

  // Sign: SHA-512(protected_b64 "." payload_b64) with P-521
  size_t signing_input_size =
      strlen(protected_b64) + 1 + strlen(payload_b64) + 1;
  char *signing_input = (char *)malloc(signing_input_size);
  snprintf(signing_input, signing_input_size, "%s.%s", protected_b64,
           payload_b64);

  uint8_t hash[64];
  mbedtls_sha512((const uint8_t *)signing_input, strlen(signing_input), hash,
                 0);
  free(signing_input);

  // Derive signing key on-demand, sign, then wipe
  uint8_t sig_priv[EC_PRIVATE_KEY_SIZE];
  if (!keystore.derive_signing_key(sig_priv)) {
    ESP_LOGE(TAG_HANDLERS, "Failed to derive signing key");
    free(payload_b64);
    free(protected_b64);
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Key derivation failed");
    return ESP_FAIL;
  }

  uint8_t signature[EC_PUBLIC_KEY_SIZE]; // r(66) + s(66)
  bool sign_ok = EC::sign(hash, sizeof(hash), sig_priv, signature);
  mbedtls_platform_zeroize(sig_priv, sizeof(sig_priv));

  if (!sign_ok) {
    ESP_LOGE(TAG_HANDLERS, "Software signing failed");
    free(payload_b64);
    free(protected_b64);
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Signing failed");
    return ESP_FAIL;
  }

  char sig_b64[192] = {0};
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

  ESP_LOGI(TAG_HANDLERS, "Served /adv (gen %u)", keystore.gen);
  return ESP_OK;
}

// Core recovery handler for a specific exchange key generation.
static esp_err_t perform_rec(httpd_req_t *req, unsigned int generation) {
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

  uint8_t client_pub_key[EC_PUBLIC_KEY_SIZE];

  if (!b64url_decode_buf(x_item->valuestring, &client_pub_key[0],
                         EC_COORDINATE_SIZE) ||
      !b64url_decode_buf(y_item->valuestring,
                         &client_pub_key[EC_COORDINATE_SIZE],
                         EC_COORDINATE_SIZE)) {
    cJSON_Delete(req_doc);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid key coordinates");
    return ESP_FAIL;
  }

  cJSON_Delete(req_doc);

  // Derive exchange key for the matched generation
  uint8_t exc_priv[EC_PRIVATE_KEY_SIZE];
  if (!keystore.derive_exchange_key(generation, exc_priv)) {
    ESP_LOGE(TAG_HANDLERS, "Failed to derive exchange key gen %u", generation);
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Key derivation failed");
    return ESP_FAIL;
  }

  uint8_t shared_point[EC_PUBLIC_KEY_SIZE];
  bool ecdh_ok = EC::ecdh_compute_shared_point(client_pub_key, exc_priv,
                                                shared_point, true);
  mbedtls_platform_zeroize(exc_priv, sizeof(exc_priv));

  if (!ecdh_ok) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "ECDH computation failed");
    return ESP_FAIL;
  }

  char shared_x_b64[96] = {0};
  char shared_y_b64[96] = {0};

  b64url_encode_buf(&shared_point[0], EC_COORDINATE_SIZE, shared_x_b64,
                    sizeof(shared_x_b64));
  b64url_encode_buf(&shared_point[EC_COORDINATE_SIZE], EC_COORDINATE_SIZE,
                    shared_y_b64, sizeof(shared_y_b64));

  cJSON *resp_root = cJSON_CreateObject();
  cJSON_AddStringToObject(resp_root, "alg", "ECMR");
  cJSON_AddStringToObject(resp_root, "kty", "EC");
  cJSON_AddStringToObject(resp_root, "crv", "P-521");
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

  ESP_LOGI(TAG_HANDLERS, "Served %s (gen %u)", req->uri, generation);
  return ESP_OK;
}

// POST /rec - Recovery endpoint using newest generation
static esp_err_t handle_rec(httpd_req_t *req) {
  return perform_rec(req, keystore.gen);
}

// GET /reboot - Reboot device
static esp_err_t handle_reboot(httpd_req_t *req) {
  httpd_resp_sendstr(req, "Rebooting...");
  vTaskDelay(pdMS_TO_TICKS(1000));
  esp_restart();
  return ESP_OK;
}

// Compute JWK Thumbprint (RFC 7638) for the exchange key in a given slot.
// For EC P-521: SHA-256({"crv":"P-521","kty":"EC","x":"...","y":"..."})
// Writes base64url-encoded thumbprint to out_buf (must be >= 44 bytes).
static bool compute_exchange_key_thumbprint(int s, char *out_buf,
                                            size_t out_buf_size) {
  if (!keystore.exc_pub_loaded || s < 0 || s >= NUM_EXCHANGE_KEYS)
    return false;

  char x_b64[96] = {0}, y_b64[96] = {0};
  b64url_encode_buf(&keystore.exc_pub[s][0], EC_COORDINATE_SIZE, x_b64,
                    sizeof(x_b64));
  b64url_encode_buf(&keystore.exc_pub[s][EC_COORDINATE_SIZE],
                    EC_COORDINATE_SIZE, y_b64, sizeof(y_b64));

  // RFC 7638: members in lexicographic order, no whitespace
  char canonical[384];
  int len =
      snprintf(canonical, sizeof(canonical),
               "{\"crv\":\"P-521\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}",
               x_b64, y_b64);
  if (len <= 0 || (size_t)len >= sizeof(canonical))
    return false;

  // RFC 7638 thumbprint always uses SHA-256
  uint8_t hash[32];
  mbedtls_sha256((const uint8_t *)canonical, (size_t)len, hash, 0);

  return b64url_encode_buf(hash, 32, out_buf, out_buf_size);
}

// 404 handler - Route /rec/{kid} to perform_rec after matching kid
// against all active exchange key generations.
static esp_err_t handle_not_found(httpd_req_t *req, httpd_err_code_t err) {
  if (req->method == HTTP_POST && strncmp(req->uri, "/rec/", 5) == 0) {
    const char *request_kid = req->uri + 5;

    // Try all active generations: gen, gen-1, ... gen-(NUM_EXCHANGE_KEYS-1)
    for (int offset = 0; offset < NUM_EXCHANGE_KEYS; offset++) {
      unsigned int g = keystore.gen - offset;
      int s = TangKeyStore::slot(g);

      char kid[64] = {0};
      if (compute_exchange_key_thumbprint(s, kid, sizeof(kid)) &&
          strcmp(request_kid, kid) == 0) {
        return perform_rec(req, g);
      }
    }

    ESP_LOGW(TAG_HANDLERS, "Key ID mismatch for %s", req->uri);
  }

  httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
  return ESP_FAIL;
}

#endif // TANG_HANDLERS_H
