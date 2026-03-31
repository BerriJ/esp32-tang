# ESP32 Tang Security Hardening Plan

## TL;DR

Security analysis of the ESP32-C6 Tang server reveals 4 critical, 7 high, 6 medium, and 5 low-severity vulnerabilities. **Flash Encryption and Secure Boot V2 have been activated**, **JTAG is disabled automatically** when Secure Boot is enabled, **TEE Secure Storage has been activated**, **PBKDF2 iterations have been increased to 600,000**, **HTTPS has been enabled**, **release build optimization has been configured**, and **WiFi reconnection backoff has been implemented**. All critical and high-severity vulnerabilities have been addressed. The remaining items are medium and low-priority operational improvements (secure OTA, WiFi provisioning, unique mDNS hostname, CSRF protection for /reboot).

---

## Security Analysis

### CRITICAL (P0) — Must fix before any production use

**V1. ~~No TLS/HTTPS — all traffic is plaintext HTTP~~ FIXED**
- **Status: HTTPS enabled via `esp_https_server` with embedded self-signed P-256 certificate. All traffic is TLS-encrypted. Web UI uses native Web Crypto API (requires secure context). Browser shows certificate warning on first visit (expected for self-signed).**
- Files: `main/TangServer.h` (httpd_ssl_start), `main/CMakeLists.txt` (EMBED_TXTFILES https_server.crt/https_server.key), `sdkconfig` (CONFIG_ESP_HTTPS_SERVER_ENABLE)
- ~~Impact: Even though ECIES protects the password hash, all response bodies (`/adv` JWS, `/rec` ECDH results, `/api/status`, `/api/identity`) are transmitted in cleartext. A network observer sees Tang protocol messages, device state, and can perform active MITM on the ECIES tunnel (replace device pubkey in `/api/identity` response).~~
- ~~The ECIES tunnel is a custom protocol and cannot authenticate the server — a MITM can serve their own ephemeral key and relay.~~

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

**V8. ~~CDN-loaded crypto libraries without SRI~~ FIXED**
- **Status: CryptoJS and elliptic.js completely removed. All cryptography now uses the browser's native Web Crypto API (`crypto.subtle`). HTTPS provides the required secure context. Zero external dependencies. ~194KB firmware savings.**
- Files: `main/zk_web_page.h` (Web Crypto API), `main/TangServer.h` (HTTPS)
- ~~Impact: CDN compromise → injected JS → password exfiltration. There are no Subresource Integrity hashes.~~

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

**V12. ~~No Content-Security-Policy headers on web UI~~ FIXED**
- **Status: Strict hash-based CSP added to `handle_zk_root`. Policy uses `'sha256-...'` hashes for inline script and style blocks — no `'unsafe-inline'` needed. `default-src 'none'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'`. Hashes must be recomputed if JS/CSS changes (`python3 compute_csp_hashes.py`).**
- Files: `main/zk_handlers.h` (`handle_zk_root`)
- ~~Impact: XSS vectors if any user input is reflected. Also allows loading of arbitrary external resources.~~

**V13. ~~Console.log exposes cryptographic secrets in browser~~ FIXED**
- **Status: All console.log statements exposing secrets removed during Web Crypto API migration. Only non-sensitive status messages remain.**
- Files: `main/zk_web_page.h`
- ~~Impact: Any browser extension or devtools access leaks all session secrets.~~

**V14. ~~DPA protection at LOW level~~ FIXED**
- **Status: DPA protection increased to MEDIUM. `CONFIG_ESP_CRYPTO_DPA_PROTECTION_LEVEL_MEDIUM=y` set in sdkconfig.defaults.**
- Files: `sdkconfig`, `sdkconfig.defaults`
- ~~Impact: Side-channel attacks on the hardware crypto accelerator. For a key server, MEDIUM or HIGH is warranted.~~

**V15. No secure OTA update mechanism**
- Impact: No way to patch vulnerabilities in deployed devices.

**V16. `/reboot` is an unauthenticated GET (CSRF via img/link)**
- Files: `main/tang_handlers.h` (`handle_reboot`)
- Impact: `<img src="http://esp-tang/reboot">` in any page triggers reboot.

**V17. ~~WiFi reconnect without backoff enables deauth DoS~~ FIXED**
- **Status: Exponential backoff implemented in `wifi_event_handler`. Reconnection delays: 1s, 2s, 4s, 8s, 16s, 32s, up to 60s maximum. Uses FreeRTOS timer for delayed reconnection attempts. Counter resets on successful connection.**
- Files: `main/TangServer.h` (`wifi_event_handler`, `wifi_reconnect_timer_callback`)
- ~~Impact: Attacker sends deauth frames; device enters tight reconnect loop, consuming CPU.~~

### LOW (P3)

**V18. ~~NVS not encrypted~~ FIXED**
- **Status: Flash Encryption encrypts all NVS partitions on flash. TEE NVS partition (`secure_storage`) is additionally encrypted by eFuse KEY3.**
- ~~Impact: KDF salt and exchange private keys readable from flash dump.~~

**V19. ~~Debug build configuration~~ FIXED**

- **Status: Changed to release build optimization. `CONFIG_COMPILER_OPTIMIZATION_SIZE=y` and `CONFIG_OPTIMIZATION_LEVEL_RELEASE=y` set in sdkconfig and sdkconfig.defaults.**
- Files: `sdkconfig`, `sdkconfig.defaults`
- ~~Impact: Larger, slower binaries. No security hardening flags (ASLR equivalent, stack canaries are enabled though).~~

**V20. ~~`exc_pub_nvs_key()` uses static buffer — not thread-safe~~ FIXED**

- **Status: Fixed to use caller-provided buffer instead of static buffer.**
- Files: `main/tang_storage.h` (`exc_pub_nvs_key`)
- ~~Impact: Unlikely issue given single-threaded HTTP server, but poor practice.~~

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

**Step 1.5: ~~Increase DPA Protection Level~~ DONE**
- ✅ Changed `CONFIG_ESP_CRYPTO_DPA_PROTECTION_LEVEL_MEDIUM=y` in sdkconfig and sdkconfig.defaults.
- Fixes: V14

**Step 1.6: ~~Set Release Build Optimization~~ DONE**
- ✅ Changed from `CONFIG_COMPILER_OPTIMIZATION_DEBUG=y` to `CONFIG_COMPILER_OPTIMIZATION_SIZE=y`
- ✅ Changed from `CONFIG_OPTIMIZATION_LEVEL_DEBUG=y` to `CONFIG_OPTIMIZATION_LEVEL_RELEASE=y`
- ✅ Added to `sdkconfig.defaults` for persistent configuration
- Fixes: V19

**Verification:**
- `espefuse.py summary` to verify eFuse state
- Flash encrypted image, verify device boots and all functions work
- Attempt to read flash with `esptool.py read_flash` — should return encrypted data
- Attempt to flash unsigned firmware — should be rejected

---

### Phase 2: Transport Security (HTTPS)
*Depends on: nothing (can be done in parallel with Phase 1)*

**Step 2.1: ~~Enable HTTPS with self-signed certificate~~ DONE**
- ✅ Replaced `httpd_start()` with `httpd_ssl_start()` from `esp_https_server` component.
- ✅ Self-signed EC P-256 certificate and key embedded in firmware.
- ✅ `esp_https_server` added to `REQUIRES` in `main/CMakeLists.txt`.
- ✅ All `fetch()` calls in `zk_web_page.h` work over HTTPS.
- ✅ Web UI requires secure context for Web Crypto API.
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

**Step 3.6: ~~Add Content-Security-Policy headers~~ DONE**
- ✅ Hash-based CSP header added to `handle_zk_root` using SHA-256 hashes of inline `<script>` and `<style>` content. No `'unsafe-inline'` — only exact-match hashes are permitted.
- Policy: `default-src 'none'; script-src 'sha256-...'; style-src 'sha256-...'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'`.
- **Important**: if the inline JS or CSS changes, the hashes must be recomputed and updated in `zk_handlers.h`.
- Fixes: V12

**Step 3.7: ~~Add SRI to CDN script tags~~ DONE (bundled instead)**
- ✅ Bundled crypto-js 4.2.0 and elliptic 6.5.4 into firmware using ESP-IDF `EMBED_TXTFILES`.
- Served from local endpoints `/js/crypto-js.min.js` and `/js/elliptic.min.js` with immutable cache headers.
- Eliminates CDN dependency entirely — device works offline.
- Factory partition expanded from 1MB to 1216KB to accommodate the additional ~195KB.
- Fixes: V8

**Step 3.8: ~~Remove console.log of secrets~~ DONE**
- ✅ All `console.log` statements exposing secrets removed during Web Crypto API migration.
- ✅ Only non-sensitive status messages remain (e.g., "Device Public Key loaded").
- Fixes: V13

**Step 3.9: ~~Add WiFi reconnect backoff~~ DONE**
- ✅ Implemented exponential backoff timer in `wifi_event_handler` for `WIFI_EVENT_STA_DISCONNECTED`
- ✅ Backoff sequence: 1s, 2s, 4s, 8s, 16s, 32s, capped at 60s maximum
- ✅ Uses FreeRTOS one-shot timer (`xTimerCreate`, `xTimerChangePeriod`)
- ✅ Automatically resets backoff counter on successful IP acquisition
- Fixes: V17

**Step 3.10: ~~Fix thread-safety of `exc_pub_nvs_key()`~~ DONE**

- ✅ Changed function signature to accept caller-provided buffer: `exc_pub_nvs_key(int s, char *buf, size_t buf_size)`
- ✅ Updated all call sites in `save_exchange_pubs()`, `load_exchange_pubs()`, and `rotate_exchange_key()` to provide local stack buffers
- Fixes: V20

**Verification:**
- Test 10+ rapid failed unlock attempts → verify rate limiting kicks in
- Attempt CORS request from external origin → verify rejection
- Inspect browser console → no secret material logged
- Test WiFi deauth attack → verify exponential backoff prevents CPU exhaustion

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
| ~~3~~    | ~~Enable HTTPS~~ ✅                              | V1   | —       | Done             |
| ~~4~~    | ~~Authenticate destructive endpoints~~ Accepted | V4   | —       | N/A (accepted)   |
| ~~5~~    | ~~Add rate limiting~~ ✅                         | V5   | —       | Done             |
| ~~6~~    | ~~Increase PBKDF2 to 600k iterations~~ ✅        | V6   | —       | Done (breaking)  |
| ~~7~~    | ~~Remove console.log secrets~~ ✅                | V13  | —       | Done             |
| ~~8~~    | ~~Add SRI / bundle crypto libs~~ ✅              | V8   | —       | Done             |
| ~~9~~    | ~~Restrict CORS~~ ✅                             | V7   | —       | Done             |
| ~~10~~   | ~~Disable JTAG~~ ✅                              | V11  | —       | Done (automatic) |
| ~~11~~   | ~~TEE Secure Storage~~ ✅                        | V10  | —       | Done             |
| ~~12~~   | ~~Stronger PBKDF2 salt~~ ✅                      | V9   | —       | Done (breaking)  |
| ~~13~~   | ~~Add CSP headers~~ ✅                           | V12  | —       | Done             |
| ~~14~~   | ~~Increase DPA protection~~ ✅                   | V14  | —       | Done             |
| ~~15~~   | ~~WiFi backoff~~ ✅                              | V17  | —       | Done             |
| ~~16~~   | ~~Release build optimization~~ ✅                | V19  | —       | Done             |
| ~~17~~   | ~~Thread-safe NVS key~~ ✅                       | V20  | —       | Done             |
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
