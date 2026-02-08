#ifndef TANG_HANDLERS_H
#define TANG_HANDLERS_H

#include <WebServer.h>
#include <ArduinoJson.h>
#include <mbedtls/sha512.h>
#include "crypto.h"
#include "encoding.h"
#include "jwe.h"
#include "tang_storage.h"

#ifndef DEBUG_PRINTLN
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#endif

// Forward declarations
extern WebServer server_http;
extern TangKeyStore keystore;
extern bool is_active;

// --- Tang Protocol Handlers ---

// GET /adv - Advertisement endpoint (signed JWK set)
void handle_adv()
{
  if (!is_active)
  {
    server_http.send(503, "text/plain", "Server not active");
    return;
  }

  // Build JWK set payload
  DynamicJsonDocument payload_doc(768);
  JsonArray keys = payload_doc.createNestedArray("keys");

  // Signing/verification key
  JsonObject sig_key = keys.createNestedObject();
  sig_key["alg"] = "ES512";
  sig_key["kty"] = "EC";
  sig_key["crv"] = "P-521";
  sig_key["x"] = Base64URL::encode(keystore.sig_pub, P521_COORDINATE_SIZE);
  sig_key["y"] = Base64URL::encode(keystore.sig_pub + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
  sig_key.createNestedArray("key_ops").add("verify");

  // Recovery/exchange key
  JsonObject rec_key = keys.createNestedObject();
  rec_key["alg"] = "ECMR";
  rec_key["kty"] = "EC";
  rec_key["crv"] = "P-521";
  rec_key["x"] = Base64URL::encode(keystore.exc_pub, P521_COORDINATE_SIZE);
  rec_key["y"] = Base64URL::encode(keystore.exc_pub + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
  rec_key.createNestedArray("key_ops").add("deriveKey");

  String payload_json;
  serializeJson(payload_doc, payload_json);
  String payload_b64 = Base64URL::encode((uint8_t *)payload_json.c_str(), payload_json.length());

  // Create protected header
  DynamicJsonDocument protected_doc(128);
  protected_doc["alg"] = "ES512";
  protected_doc["cty"] = "jwk-set+json";

  String protected_json;
  serializeJson(protected_doc, protected_json);
  String protected_b64 = Base64URL::encode((uint8_t *)protected_json.c_str(), protected_json.length());

  // Sign the payload
  String signing_input = protected_b64 + "." + payload_b64;
  uint8_t hash[64];
  mbedtls_sha512((uint8_t *)signing_input.c_str(), signing_input.length(), hash, 0);

  uint8_t signature[P521_PUBLIC_KEY_SIZE];
  if (!P521::sign(hash, 64, keystore.sig_priv, signature))
  {
    server_http.send(500, "text/plain", "Signing failed");
    return;
  }

  // Build JWS response
  DynamicJsonDocument jws_doc(1024);
  jws_doc["payload"] = payload_b64;
  jws_doc["protected"] = protected_b64;
  jws_doc["signature"] = Base64URL::encode(signature, P521_PUBLIC_KEY_SIZE);

  String response;
  serializeJson(jws_doc, response);
  server_http.send(200, "application/json", response);
  DEBUG_PRINTLN("Served /adv");
}

// POST /rec or /rec/{kid} - Recovery endpoint
void handle_rec()
{
  if (!is_active)
  {
    server_http.send(503, "text/plain", "Server not active");
    return;
  }

  if (!server_http.hasArg("plain"))
  {
    server_http.send(400, "text/plain", "Missing request body");
    return;
  }

  DynamicJsonDocument req_doc(512);
  if (deserializeJson(req_doc, server_http.arg("plain")))
  {
    server_http.send(400, "text/plain", "Invalid JSON");
    return;
  }

  // Extract client's ephemeral public key
  const char *x_b64 = req_doc["x"];
  const char *y_b64 = req_doc["y"];
  if (!x_b64 || !y_b64)
  {
    server_http.send(400, "text/plain", "Missing x or y coordinates");
    return;
  }

  uint8_t client_pub_key[P521_PUBLIC_KEY_SIZE];
  if (Base64URL::decode(String(x_b64), client_pub_key, P521_COORDINATE_SIZE) != P521_COORDINATE_SIZE ||
      Base64URL::decode(String(y_b64), client_pub_key + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE) != P521_COORDINATE_SIZE)
  {
    server_http.send(400, "text/plain", "Invalid key coordinates");
    return;
  }

  // Perform ECDH to get shared point
  uint8_t shared_point[P521_PUBLIC_KEY_SIZE];
  if (!P521::ecdh_compute_shared_point(client_pub_key, keystore.exc_priv, shared_point, true))
  {
    server_http.send(500, "text/plain", "ECDH computation failed");
    return;
  }

  // Return shared point as JWK
  DynamicJsonDocument resp_doc(512);
  resp_doc["alg"] = "ECMR";
  resp_doc["kty"] = "EC";
  resp_doc["crv"] = "P-521";
  resp_doc["x"] = Base64URL::encode(shared_point, P521_COORDINATE_SIZE);
  resp_doc["y"] = Base64URL::encode(shared_point + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
  resp_doc.createNestedArray("key_ops").add("deriveKey");

  String response;
  serializeJson(resp_doc, response);
  server_http.send(200, "application/jose+json", response);
  DEBUG_PRINTF("Served %s\n", server_http.uri().c_str());
}

// --- Administration Handlers ---

// GET /pub - Get admin public key
void handle_pub()
{
  DynamicJsonDocument doc(512);
  doc["kty"] = "EC";
  doc["crv"] = "P-521";
  doc["x"] = Base64URL::encode(keystore.admin_pub, P521_COORDINATE_SIZE);
  doc["y"] = Base64URL::encode(keystore.admin_pub + P521_COORDINATE_SIZE, P521_COORDINATE_SIZE);
  doc["alg"] = "ECDH-ES";

  String response;
  serializeJson(doc, response);
  server_http.send(200, "application/json", response);
  DEBUG_PRINTLN("Served /pub");
}

// POST /activate - Activate server with password
void handle_activate()
{
  if (is_active)
  {
    server_http.send(400, "text/plain", "Already active");
    return;
  }

  if (!server_http.hasArg("plain"))
  {
    server_http.send(400, "text/plain", "Missing request body");
    return;
  }

  DEBUG_PRINTLN("Activation request (decryption may take 20-30s)...");

  DynamicJsonDocument req_doc(1024);
  if (deserializeJson(req_doc, server_http.arg("plain")))
  {
    server_http.send(400, "text/plain", "Invalid JSON");
    return;
  }

  // Decrypt password from JWE
  char password[65] = {0};
  if (!JWE::decrypt_password(req_doc, keystore.admin_priv, password, sizeof(password)))
  {
    server_http.send(401, "text/plain", "Decryption failed");
    return;
  }

  // Decrypt Tang keys using password
  if (!keystore.decrypt_and_load_tang_keys(password))
  {
    server_http.send(401, "text/plain", "Invalid password");
    return;
  }

  is_active = true;
  DEBUG_PRINTLN("Server ACTIVATED");
  server_http.send(200, "text/plain", "Server activated");
}

// GET /reboot - Reboot device
void handle_reboot()
{
  server_http.send(200, "text/plain", "Rebooting...");
  delay(1000);
  ESP.restart();
}

// 404 handler
void handle_not_found()
{
  String uri = server_http.uri();
  if (uri.startsWith("/rec/") && server_http.method() == HTTP_POST)
  {
    handle_rec();
  }
  else
  {
    server_http.send(404, "text/plain", "Not found");
  }
}

#endif // TANG_HANDLERS_H
