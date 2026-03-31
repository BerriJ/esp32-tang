# ESP32 Tang Security Hardening Plan

## TL;DR

Security analysis of the ESP32-C6 Tang server reveals 4 critical, 7 high, 6 medium, and 5 low-severity vulnerabilities. **Flash Encryption and Secure Boot V2 have been activated**, and **JTAG is disabled automatically** when Secure Boot is enabled. **TEE Secure Storage has been activated.** **PBKDF2 iterations have been increased to 600,000.** The remaining urgent issues are: no TLS (HTTP plaintext), unauthenticated destructive endpoints, and no brute-force protection. The recommended approach continues with transport security (HTTPS), then application-layer hardening (rate limiting, authentication, CSP).

---

## Security Analysis

### CRITICAL (P0) — Must fix before any production use

**V1. No TLS/HTTPS — all traffic is plaintext HTTP**
- Files: `main/TangServer.h` (setup_http_server), `main/zk_web_page.h` (all fetch calls)
- Impact: Even though ECIES protects the password hash, all response bodies (`/adv` JWS, `/rec` ECDH results, `/api/status`, `/api/identity`) are transmitted in cleartext. A network observer sees Tang protocol messages, device state, and can perform active MITM on the ECIES tunnel (replace device pubkey in `/api/identity` response).
- The ECIES tunnel is a custom protocol and cannot authenticate the server — a MITM can serve their own ephemeral key and relay.

**V2. ~~No Secure Boot — unsigned firmware executes freely~~ FIXED**
- **Status: Secure Boot V2 has been activated.**
- Files: `sdkconfig` (`CONFIG_SECURE_BOOT`)
- ~~Impact: Physical attacker can flash rogue firmware that replaces TEE code, exfiltrates master_key via a modified `_ss_tang_tee_activate()`, or installs a keylogger on the web UI.~~

**V3. ~~No Flash Encryption — firmware and NVS readable from flash~~ FIXED**
- **Status: Flash Encryption has been activated.**
- Files: `sdkconfig` (`CONFIG_SECURE_FLASH_ENC_ENABLED`)
- ~~Impact: Physical attacker can dump flash to extract: WiFi credentials (SSID/password in plaintext), KDF salt (enables offline password brute-force against the HMAC-locked eFuse), public keys, and full firmware for reverse engineering.~~

**V4. ~~Unauthenticated destructive endpoints~~ ACCEPTED**
- **Status: Accepted risk. Design decision: the Tang server should be easy to deactivate (lock/reboot) but hard to activate (unlock requires password + ECIES + rate limiting). Lock/reboot are DoS-only — exchange keys remain safely in TEE NVS.**
- Files: `main/tang_handlers.h` (`handle_reboot`), `main/zk_handlers.h` (`handle_zk_lock`), `main/provision_handlers.h` (`handle_provision_api`)

### HIGH (P1)

**V5. ~~No rate limiting on password attempts~~ FIXED**
- **Status: Exponential backoff rate limiting added to `process_unlock` and `process_change_password`. Backoff doubles per failure (1s, 2s, 4s...) capped at 5 minutes. Resets on successful auth. HTTP 429 returned when rate-limited.**
- Files: `main/zk_auth.h` (`process_unlock`, `process_change_password`)
- ~~Impact: Unlimited brute-force attempts. PBKDF2 iterations have been increased to 600,000 (OWASP 2023 recommended minimum for SHA-256), but rate limiting is still needed to prevent online brute-force.~~

**V6. ~~PBKDF2 iteration count too low (10,000)~~ FIXED**
- **Status: PBKDF2 iterations increased to 600,000.**
- Files: `main/zk_web_page.h` (JavaScript PBKDF2 call)
- ~~Impact: Modern GPUs can test billions of SHA-256 hashes/second. 10k iterations offers minimal protection.~~

**V7. ~~CORS wildcard (`Access-Control-Allow-Origin: *`)~~ FIXED**
- **Status: All CORS headers and OPTIONS preflight handlers removed. Web UI is same-origin; no cross-origin access is permitted.**
- Files: `main/provision_handlers.h`, `main/zk_handlers.h`
- ~~Impact: Any website can make cross-origin API calls to the device if it's on a reachable network. Enables CSRF-like attacks from malicious web pages.~~

**V8. CDN-loaded crypto libraries without SRI**
- Files: `main/zk_web_page.h` (script tags for crypto-js and elliptic.js)
- Impact: CDN compromise → injected JS → password exfiltration. There are no Subresource Integrity hashes.

**V9. ~~MAC address as PBKDF2 salt is weak~~ FIXED**
- **Status: Replaced with eFuse Unique ID (128-bit, factory-burned, not network-observable).**
- Files: `main/zk_web_page.h` (PBKDF2 salt), `main/zk_auth.h` (get_identity_json)
- ~~Impact: MAC addresses are only 6 bytes, predictable, and often known. A dedicated attacker could pre-compute rainbow tables per-MAC.~~

**V10. ~~TEE Secure Storage in development mode~~ FIXED**
- **Status: TEE Secure Storage has been activated.**
- Files: `sdkconfig` (`CONFIG_SECURE_TEE_SEC_STG_MODE_DEVELOPMENT=y`)
- ~~Impact: Development mode may relax security guarantees of TEE secure storage.~~

**V11. ~~No JTAG protection~~ FIXED**
- **Status: JTAG is disabled automatically when Secure Boot is enabled.**
- Files: `sdkconfig`
- ~~Impact: Physical attacker can attach JTAG debugger to inspect REE memory, set breakpoints during ECIES decryption to capture password_hash.~~

### MEDIUM (P2)

**V12. No Content-Security-Policy headers on web UI**
- Files: `main/zk_web_page.h` (HTML), `main/zk_handlers.h` (`handle_zk_root`)
- Impact: XSS vectors if any user input is reflected. Also allows loading of arbitrary external resources.

**V13. Console.log exposes cryptographic secrets in browser**
- Files: `main/zk_web_page.h` (JavaScript: "Session Key", "Shared Secret", "Encryption Key", "MAC Key" all logged)
- Impact: Any browser extension or devtools access leaks all session secrets.

**V14. DPA protection at LOW level**
- Files: `sdkconfig` (`CONFIG_ESP_CRYPTO_DPA_PROTECTION_LEVEL_LOW=y`)
- Impact: Side-channel attacks on the hardware crypto accelerator. For a key server, MEDIUM or HIGH is warranted.

**V15. No secure OTA update mechanism**
- Impact: No way to patch vulnerabilities in deployed devices.

**V16. `/reboot` is an unauthenticated GET (CSRF via img/link)**
- Files: `main/tang_handlers.h` (`handle_reboot`)
- Impact: `<img src="http://esp-tang/reboot">` in any page triggers reboot.

**V17. WiFi reconnect without backoff enables deauth DoS**
- Files: `main/TangServer.h` (`wifi_event_handler` — immediate reconnect)
- Impact: Attacker sends deauth frames; device enters tight reconnect loop, consuming CPU.

### LOW (P3)

**V18. ~~NVS not encrypted~~ FIXED**
- **Status: Flash Encryption encrypts all NVS partitions on flash. TEE NVS partition (`secure_storage`) is additionally encrypted by eFuse KEY3.**
- ~~Impact: KDF salt and exchange private keys readable from flash dump.~~

**V19. Debug build configuration**
- Files: `sdkconfig` (`CONFIG_COMPILER_OPTIMIZATION_DEBUG=y`)
- Impact: Larger, slower binaries. No security hardening flags (ASLR equivalent, stack canaries are enabled though).

**V20. `exc_pub_nvs_key()` uses static buffer — not thread-safe**
- Files: `main/tang_storage.h` (`exc_pub_nvs_key`)
- Impact: Unlikely issue given single-threaded HTTP server, but poor practice.

**V21. WiFi credentials in sdkconfig**
- Files: `sdkconfig` (`CONFIG_WIFI_SSID`, `CONFIG_WIFI_PASSWORD`)
- Impact: Credentials visible in source control and flash dumps.

**V22. No mDNS/hostname collision protection**
- Files: `main/TangServer.h` (hostname "esp-tang-lol")
- Impact: Hostname spoofing on local network.

---

## Implementation Plan

### Phase 1: Hardware Security Foundation (Secure Boot + Flash Encryption)
*These are partially irreversible (eFuse burns). Must be done carefully.*

**Step 1.1: ~~Enable Secure Boot V2 (ECDSA)~~ DONE**
- ✅ Secure Boot V2 has been activated.
- Fixes: V2

**Step 1.2: ~~Enable Flash Encryption (AES-XTS-256)~~ DONE**
- ✅ Flash Encryption has been activated.
- Fixes: V3, V18, V21 (WiFi creds in flash)

**Step 1.3: ~~Disable JTAG via eFuse~~ DONE**
- ✅ JTAG is disabled automatically when Secure Boot is enabled.
- Fixes: V11

**Step 1.4: ~~Activate TEE Secure Storage~~ DONE**
- ✅ TEE Secure Storage has been activated.
- Fixes: V10

**Step 1.5: Increase DPA Protection Level**
- Change `CONFIG_ESP_CRYPTO_DPA_PROTECTION_LEVEL_LOW=n` → `CONFIG_ESP_CRYPTO_DPA_PROTECTION_LEVEL_MEDIUM=y`
- Fixes: V14

**Step 1.6: Set Release Build Optimization**
- Change `CONFIG_COMPILER_OPTIMIZATION_DEBUG=n` → `CONFIG_COMPILER_OPTIMIZATION_SIZE=y`
- Fixes: V19

**Verification:**
- `espefuse.py summary` to verify eFuse state
- Flash encrypted image, verify device boots and all functions work
- Attempt to read flash with `esptool.py read_flash` — should return encrypted data
- Attempt to flash unsigned firmware — should be rejected

---

### Phase 2: Transport Security (HTTPS)
*Depends on: nothing (can be done in parallel with Phase 1)*

**Step 2.1: Enable HTTPS with self-signed certificate**
- Replace `httpd_start()` with `httpd_ssl_start()` from `esp_https_server` component
- Generate a self-signed EC P-256 certificate at first boot (or embed one)
- Store cert+key in NVS (encrypted after Phase 1) or derive from TEE
- Modify `main/TangServer.h`: `setup_http_server()` to use `httpd_ssl_config_t`
- Add `esp_https_server` to `REQUIRES` in `main/CMakeLists.txt`
- Update all `fetch()` calls in `zk_web_page.h` - they'll work as-is over HTTPS
- Fixes: V1

**Step 2.2: Redirect HTTP to HTTPS (optional)**
- Keep port 80 open only to redirect to 443
- Or simply close port 80 entirely

**Verification:**
- `curl -k https://<ip>/api/status` works
- `curl http://<ip>/api/status` fails or redirects
- Wireshark capture shows TLS handshake, no plaintext payloads

---

### Phase 3: Application-Layer Hardening
*Depends on: nothing (can be done in parallel)*

**Step 3.1: ~~Add rate limiting to authentication endpoints~~ DONE**
- ✅ Global exponential backoff in `ZKAuth`: 1s, 2s, 4s, 8s... capped at 5 minutes.
- Applied to `process_unlock` and `process_change_password`.
- HTTP 429 returned with `retry_after` seconds when rate-limited.
- Status endpoint (`/api/status`) exposes `failed_attempts` and `retry_after`.
- Resets on successful authentication.
- Fixes: V5

**Step 3.2: ~~Increase PBKDF2 iterations to 600,000~~ DONE**
- ✅ Changed all PBKDF2 calls in `main/zk_web_page.h` from 10,000 to 600,000 iterations.
- NOTE: This is a breaking change — existing password hashes will differ. Requires password re-enrollment.
- Fixes: V6

**Step 3.3: ~~Authenticate destructive endpoints~~ REMOVED**
- Design decision: Tang server should be easy to deactivate but hard to activate.
- Lock/reboot are DoS-only — keys remain safe in TEE NVS.
- ~~Fixes: V4, V16~~

**Step 3.4: ~~Restrict CORS~~ DONE**
- ✅ Removed all `Access-Control-Allow-Origin: *` headers and OPTIONS preflight handlers.
- Web UI is same-origin (served from `/`); cross-origin requests are now blocked by browsers.
- Fixes: V7

**Step 3.5: ~~Use stronger PBKDF2 salt~~ DONE**
- ✅ Replaced MAC address with eFuse Unique ID (128-bit) as PBKDF2 salt.
- Served via `/api/identity` `salt` field; no NVS storage needed (read from eFuse).
- Fixes: V9

**Step 3.6: Add Content-Security-Policy headers**
- Add CSP header to `handle_zk_root`: `default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'`
- Better: bundle crypto-js and elliptic.js inline (already partially done) and use strict CSP
- Fixes: V12

**Step 3.7: Add SRI to CDN script tags**
- Add `integrity="sha384-..."` and `crossorigin="anonymous"` to both `<script>` tags
- Or better: bundle the libraries into the embedded HTML to eliminate CDN dependency entirely
- Fixes: V8

**Step 3.8: Remove console.log of secrets**
- Remove all `console.log` lines that output Session Key, Shared Secret, Encryption Key, MAC Key
- Modify: `main/zk_web_page.h` (JavaScript section)
- Fixes: V13

**Step 3.9: Add WiFi reconnect backoff**
- In `wifi_event_handler` for `WIFI_EVENT_STA_DISCONNECTED`: add exponential backoff (1s, 2s, 4s... up to 60s)
- Modify: `main/TangServer.h`
- Fixes: V17

**Step 3.10: Fix thread-safety of `exc_pub_nvs_key()`**
- Change static buffer to caller-provided buffer
- Modify: `main/tang_storage.h`
- Fixes: V20

**Verification:**
- Test 10+ rapid failed unlock attempts → verify rate limiting kicks in
- Attempt CORS request from external origin → verify rejection
- Inspect browser console → no secret material logged
- Test `GET /reboot` unauthenticated → should fail
- Test `POST /api/lock` unauthenticated → should fail

---

### Phase 4: Operational Security (Nice-to-have)
*Lower priority, can be done incrementally*

**Step 4.1: Implement secure OTA**
- Add ESP-IDF OTA component with signature verification
- Pair with Secure Boot to ensure only signed updates are accepted
- Fixes: V15

**Step 4.2: Externalize WiFi credentials**
- Use ESP-IDF provisioning (BLE or SoftAP) instead of hardcoded sdkconfig values
- Or use NVS-stored credentials set via a provisioning endpoint
- Fixes: V21

**Step 4.3: Use mDNS with unique hostname**
- Use device MAC or serial in hostname to avoid collisions
- Fixes: V22

---

## Prioritized Action List

| Priority | Action                                          | Vuln | Effort  | Reversible?      |
| -------- | ----------------------------------------------- | ---- | ------- | ---------------- |
| ~~1~~    | ~~Enable Secure Boot V2~~ ✅                     | V2   | —       | Done             |
| ~~2~~    | ~~Enable Flash Encryption~~ ✅                   | V3   | —       | Done             |
| 3        | Enable HTTPS                                    | V1   | Medium  | Yes              |
| ~~4~~    | ~~Authenticate destructive endpoints~~ Accepted | V4   | —       | N/A (accepted)   |
| ~~5~~    | ~~Add rate limiting~~ ✅                         | V5   | —       | Done             |
| ~~6~~    | ~~Increase PBKDF2 to 600k iterations~~ ✅        | V6   | —       | Done (breaking)  |
| 7        | Remove console.log secrets                      | V13  | Trivial | Yes              |
| 8        | Add SRI / bundle crypto libs                    | V8   | Low     | Yes              |
| ~~9~~    | ~~Restrict CORS~~ ✅                             | V7   | —       | Done             |
| ~~10~~   | ~~Disable JTAG~~ ✅                              | V11  | —       | Done (automatic) |
| ~~11~~   | ~~TEE Secure Storage~~ ✅                        | V10  | —       | Done             |
| ~~12~~   | ~~Stronger PBKDF2 salt~~ ✅                      | V9   | —       | Done (breaking)  |
| 13       | Add CSP headers                                 | V12  | Trivial | Yes              |
| 14       | Increase DPA protection                         | V14  | Trivial | Yes              |
| 15       | WiFi backoff                                    | V17  | Low     | Yes              |
| 16       | Release build optimization                      | V19  | Trivial | Yes              |
| 17       | Thread-safe NVS key                             | V20  | Trivial | Yes              |
| 18       | Secure OTA                                      | V15  | High    | Yes              |
| 19       | WiFi provisioning                               | V21  | Medium  | Yes              |
| 20       | Unique mDNS hostname                            | V22  | Trivial | Yes              |

---

## Relevant Files

- `sdkconfig` / `sdkconfig.defaults` — Secure Boot, Flash Encryption, JTAG, DPA, TEE mode, build optimization
- `main/TangServer.h` — HTTP→HTTPS migration, WiFi backoff, endpoint authentication
- `main/CMakeLists.txt` — add `esp_https_server` dependency
- `main/zk_auth.h` — rate limiting, PBKDF2 salt change
- `main/zk_handlers.h` — endpoint authentication for lock, CORS restriction
- `main/zk_web_page.h` — PBKDF2 iterations, SRI, CSP, console.log removal, salt change
- `main/tang_handlers.h` — authenticate /reboot, CORS
- `main/provision_handlers.h` — guard /api/provision, CORS
- `main/tang_storage.h` — thread-safe NVS key helper
- `components/tang_tee_service/tang_tee_service.c` — TEE secure services: ECDH, key derivation, exchange key persistence in TEE NVS, password verification (constant-time comparison inside TEE)

---

## Decisions

- **ESP32-C5 vs C6**: Staying on C6 is recommended. The C5 has comparable security features and switching would add migration effort with minimal security gain.
- **ECIES tunnel vs TLS**: With HTTPS enabled (Phase 2), the ECIES tunnel becomes defense-in-depth rather than the sole transport protection. Both can coexist; the ECIES tunnel still adds value (end-to-end encryption past any TLS-terminating proxy).
- **PBKDF2 iteration increase is breaking**: Existing passwords will produce different hashes. A migration path (try 600k first, fall back to 10k, then force re-enrollment) could ease transition.
- **SRI vs bundling**: Bundling crypto-js + elliptic.js inline eliminates the CDN dependency entirely — preferred for an embedded device that may not always have internet access.

## Further Considerations

1. **Monotonic counter for anti-rollback**: Consider using an eFuse-based monotonic counter to prevent firmware rollback attacks. ESP-IDF supports this via `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`. Recommendation: enable after Secure Boot is stable.
2. **NVS key attestation**: After HTTPS + TEE production mode, consider adding TEE attestation of the NVS contents to detect tampering at the storage layer.
3. **Client certificate authentication**: For machine-to-machine Tang protocol usage (no browser), mTLS could replace the password-based auth for automated unlock scenarios.
