#ifndef ZK_HANDLERS_H
#define ZK_HANDLERS_H

#include <WebServer.h>
#include "zk_auth.h"
#include "zk_web_page.h"

// Global ZK Auth instance (to be initialized in main)
extern ZKAuth zk_auth;
extern WebServer server_http;

// Serve the main web interface
void handle_zk_root()
{
  // Server decides what page to show based on unlock state
  // This way incognito/new windows always get the correct page
  server_http.send(200, "text/html", ZK_WEB_PAGE);
}

// API endpoint: Get device identity
void handle_zk_identity()
{
  String json_response;
  zk_auth.get_identity_json(json_response);

  server_http.sendHeader("Access-Control-Allow-Origin", "*");
  server_http.send(200, "application/json", json_response);
}

// API endpoint: Process unlock request
void handle_zk_unlock()
{
  if (server_http.method() != HTTP_POST)
  {
    server_http.send(405, "application/json", "{\"error\":\"Method not allowed\"}");
    return;
  }

  String payload = server_http.arg("plain");
  String response;

  bool success = zk_auth.process_unlock(payload.c_str(), response);

  int status_code = success ? 200 : 400;
  server_http.sendHeader("Access-Control-Allow-Origin", "*");
  server_http.send(status_code, "application/json", response);
}

// API endpoint: Check session status
void handle_zk_status()
{
  unsigned long uptime_ms = millis();
  String response = "{\"unlocked\":";
  response += zk_auth.is_unlocked() ? "true" : "false";
  response += ",\"uptime\":";
  response += String(uptime_ms);
  response += "}";
  server_http.sendHeader("Access-Control-Allow-Origin", "*");
  server_http.send(200, "application/json", response);
}

// API endpoint: Lock the device
void handle_zk_lock()
{
  zk_auth.lock();
  server_http.sendHeader("Access-Control-Allow-Origin", "*");
  server_http.send(200, "application/json", "{\"unlocked\":false}");
}

// Handle CORS preflight
void handle_zk_options()
{
  server_http.sendHeader("Access-Control-Allow-Origin", "*");
  server_http.sendHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  server_http.sendHeader("Access-Control-Allow-Headers", "Content-Type");
  server_http.send(204);
}

// Register all ZK auth routes
void setup_zk_routes()
{
  // Move Tang server to port 8080 (or different path)
  // Main interface on port 80 for ZK auth
  server_http.on("/", HTTP_GET, handle_zk_root);
  server_http.on("/api/identity", HTTP_GET, handle_zk_identity);
  server_http.on("/api/status", HTTP_GET, handle_zk_status);
  server_http.on("/api/unlock", HTTP_POST, handle_zk_unlock);
  server_http.on("/api/unlock", HTTP_OPTIONS, handle_zk_options);
  server_http.on("/api/lock", HTTP_POST, handle_zk_lock);

  Serial.println("ZK Auth routes registered:");
  Serial.println("  GET  /            - Web interface");
  Serial.println("  GET  /api/identity - Device identity");
  Serial.println("  POST /api/unlock   - Unlock request");
}

#endif // ZK_HANDLERS_H
