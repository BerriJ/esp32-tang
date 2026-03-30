# Plan: OTA Firmware Updates for ESP32-C6 Tang Server

Add over-the-air firmware update capability. Switch from 2MB to 4MB flash config, replace the single `factory` partition with dual OTA slots (`ota_0`/`ota_1`), and add an authenticated `/api/ota` HTTP endpoint that accepts signed firmware binaries. Secure Boot V2 validates every OTA image automatically — no custom signature verification needed.

---

**Steps**

### Phase 1: Flash & Partition Configuration

1. **Add flash size config to sdkconfig.defaults** — add `CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y`

2. **Update partitions.csv for OTA dual-slot layout** — replace `factory` with `otadata` + `ota_0` + `ota_1`, move data partitions up:

   | Name           | Type | SubType  | Offset   | Size  |
   | -------------- | ---- | -------- | -------- | ----- |
   | tee_0          | app  | tee_0    | 0x20000  | 192K  |
   | secure_storage | data | nvs      | 0x50000  | 64K   |
   | otadata        | data | ota      | 0x60000  | 8K    |
   | ota_0          | app  | ota_0    | 0x70000  | 1216K |
   | ota_1          | app  | ota_1    | 0x1A0000 | 1216K |
   | nvs            | data | nvs      | 0x2D0000 | 24K   |
   | phy_init       | data | phy      | 0x2D6000 | 4K    |
   | nvs_keys       | data | nvs_keys | 0x2D7000 | 4K    |

### Phase 2: OTA Handler Implementation

3. **Create `main/ota_handlers.h`** (new file) — OTA HTTP handlers:
   - `POST /api/ota` — receives firmware binary via streaming chunked upload, writes directly to inactive OTA partition using `esp_ota_begin()`/`esp_ota_write()`/`esp_ota_end()`. Requires device to be unlocked (`activated == true`), reusing the auth gate pattern from `main/tang_handlers.h`. Returns JSON success/failure, reboots on success.
   - `GET /api/ota/status` — returns current boot partition, firmware version (`esp_app_get_description()`), and OTA slot info.
   - Secure Boot V2 handles signature verification at next boot — no app-level check needed.

4. **Add firmware version tracking** (*parallel with step 3*)
   - Set `PROJECT_VER` in root `CMakeLists.txt`
   - Expose version in `/api/ota/status` and existing `/api/status`

5. **Register OTA handlers in `main/TangServer.h`** (*depends on 3*)
   - `#include "ota_handlers.h"` + `register_ota_handlers(server)` in `setup_http_server()`

### Phase 3: Build System & Dependencies

6. **Update `main/CMakeLists.txt`** — add `app_update` to `REQUIRES` (*parallel with step 3*)

7. **Update flash commands** (*depends on 1-2*)
   - `--flash_size 4MB` in `Makefile`, `PROVISIONING.md`
   - Initial flash goes to `0x70000` (ota_0) instead of `0x60000` (factory)
   - Update flash layout table in PROVISIONING.md

### Phase 4: Rollback Support

8. **Enable ESP-IDF rollback** (*depends on 3*)
   - Add `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` to `sdkconfig.defaults`
   - After OTA reboot, new firmware calls `esp_ota_mark_app_valid_cancel_rollback()` in `setup()` after WiFi connects — if it crashes before that, bootloader auto-rolls back to previous slot

---

**Relevant files**
- `sdkconfig.defaults` — flash size, rollback config
- `partitions.csv` — new OTA partition layout
- `main/ota_handlers.h` — **new**: OTA upload + status endpoints
- `main/TangServer.h` — register handlers, rollback confirmation
- `main/CMakeLists.txt` — add `app_update` dependency
- `CMakeLists.txt` — `PROJECT_VER`
- `PROVISIONING.md` — updated flash commands and layout
- `main/tang_handlers.h` — reference for `activated` auth gate pattern

**Verification**
1. `idf.py fullclean && idf.py build` succeeds with new partition table
2. `idf.py size` confirms binary fits in 1216K slot (964K current, ~250K headroom)
3. Flash to fresh chip → monitor shows `Running partition: ota_0`
4. `curl -X POST --data-binary @build/esp32-tang.bin http://<ip>/api/ota` (after unlock) → device reboots into `ota_1`
5. Second OTA → writes back to `ota_0` (alternating)
6. OTA with broken firmware → bootloader rolls back automatically
7. `curl http://<ip>/api/ota/status` returns partition + version
8. OTA without unlock → returns 403

**Decisions**
- **HTTP, not HTTPS** — Secure Boot V2 verifies the signed binary at boot, so MITM can't install tampered firmware. Adding TLS is significant overhead for a LAN device.
- **Auth: unlock required** — Same protection as key rotation / password change. Consistent with existing model.
- **Full binary upload** — No delta/compressed OTA. Slots have plenty of headroom.
- **Rollback triggers on WiFi connect** — If new firmware gets WiFi up, it's confirmed valid.
- **TEE not OTA-updatable** — `tee_0` stays USB-flash-only. TEE changes should require physical access.
- **No web UI for OTA** — `curl` upload only for now. Web upload page can be added later.

**Further Considerations**
1. **Streaming upload pattern**: The OTA handler must stream chunks to flash (4K at a time), not buffer the entire ~1MB binary in RAM. ESP-IDF's `esp_ota_write()` supports this natively.
2. **TEE partition**: Currently not covered by OTA — requires physical USB access to update. This is a deliberate security boundary.
