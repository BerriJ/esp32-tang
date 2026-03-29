# ESP32-C6 Tang Server — Provisioning Guide

## Overview

This device uses Secure Boot V2 (ECDSA), Flash Encryption, and TEE with secure storage.

`CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS=y` is set, which means the bootloader will **not** write-protect `RD_DIS` on first boot. This allows HMAC keys to be burned and read-protected **after** secure boot is enabled, giving more flexibility in provisioning order.

**Recommended order:**
1. Flash firmware (triggers secure boot + flash encryption on first boot)
2. Burn TEE HMAC keys into eFuse (can be done after first boot)

> **Security note:** This option means an attacker with physical access could theoretically read-protect the secure boot digest block (KEY0) to cause a denial of service. If this is a concern for your threat model, burn HMAC keys before first boot and remove `CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS` from sdkconfig.defaults.

## Prerequisites

- `esptool.py`, `espefuse.py`, `espsecure.py` (included in ESP-IDF)
- Signing key: `secure_boot_signing_key.pem` (ECDSA P-256)
- Built firmware (`idf.py build` completed successfully)

## eFuse Key Block Allocation

| Block | Purpose                                   | When Burned                         |
| ----- | ----------------------------------------- | ----------------------------------- |
| 0     | `SECURE_BOOT_DIGEST0`                     | Auto — first boot                   |
| 1     | `XTS_AES_128_KEY` (flash encryption)      | Auto — first boot                   |
| 2     | `HMAC_UP` (TEE secure storage encryption) | Manual — before first boot          |
| 3     | `HMAC_UP` (TEE PBKDF2 key derivation)     | Manual — before first boot          |
| 4     | Unused                                    | —                                   |
| 5     | `HMAC_UP` (application HMAC)              | Auto — firmware first boot (SS 206) |

## Flash Layout

| Region          | Offset   | Size            | Contents                 |
| --------------- | -------- | --------------- | ------------------------ |
| Bootloader      | 0x00000  | ~48 KB (signed) | 2nd stage bootloader     |
| Partition table | 0x10000  | ~3 KB           | Partition table          |
| tee_0           | 0x20000  | 192 KB          | TEE application          |
| secure_storage  | 0x50000  | 64 KB           | TEE NVS (secure storage) |
| factory         | 0x60000  | 1 MB            | Main application         |
| nvs             | 0x160000 | 24 KB           | Application NVS          |
| phy_init        | 0x166000 | 4 KB            | PHY calibration data     |
| nvs_keys        | 0x167000 | 4 KB            | NVS encryption keys      |

## Production Provisioning Steps

### 1. Switch sdkconfig.defaults to release mode

```ini
CONFIG_SECURE_TEE_SEC_STG_MODE_RELEASE=y
CONFIG_SECURE_TEE_SEC_STG_EFUSE_HMAC_KEY_ID=2
CONFIG_SECURE_TEE_PBKDF2_EFUSE_HMAC_KEY_ID=3
```

Comment out the development mode lines:

```ini
# CONFIG_SECURE_TEE_SEC_STG_MODE_DEVELOPMENT=y
# CONFIG_SECURE_TEE_SEC_STG_EFUSE_HMAC_KEY_ID=-1
# CONFIG_SECURE_TEE_PBKDF2_EFUSE_HMAC_KEY_ID=-1
```

Also switch flash encryption to release mode:

```ini
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y
```

### 2. Build firmware

```bash
idf.py fullclean && idf.py build
```

### 3. Generate HMAC keys

```bash
dd if=/dev/urandom of=tee_sec_stg_hmac.bin bs=32 count=1
dd if=/dev/urandom of=tee_pbkdf2_hmac.bin bs=32 count=1
```

**Back up both files securely.** If lost, the device's TEE secure storage cannot be reproduced.

### 4. Burn HMAC keys into eFuse

With `CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS=y`, this can be done before or after first boot.

> **WARNING: This is irreversible.**

```bash
espefuse.py --port /dev/ttyACM1 \
  burn_key BLOCK_KEY2 tee_sec_stg_hmac.bin HMAC_UP

espefuse.py --port /dev/ttyACM1 \
  burn_key BLOCK_KEY3 tee_pbkdf2_hmac.bin HMAC_UP
```

### 5. Verify eFuse state

```bash
espefuse.py --port /dev/ttyACM1 summary | grep KEY_PURPOSE
```

Expected output should show blocks 2 and 3 as `HMAC_UP`.

### 6. Flash all images at once

```bash
esptool.py --chip esp32c6 -p /dev/ttyACM1 --baud 460800 \
  --before=default_reset --after=no_reset --no-stub \
  write_flash --flash_mode dio --flash_freq 80m --flash_size 2MB \
  0x0 build/bootloader/bootloader.bin \
  0x10000 build/partition_table/partition-table.bin \
  0x20000 build/esp_tee/esp_tee.bin \
  0x60000 build/esp32-tang.bin
```

### 7. First boot

On first boot, the bootloader will automatically:
- Burn the secure boot key digest into eFuse block 0
- Burn the flash encryption key into eFuse block 1
- Encrypt flash contents in-place
- Enable secure boot permanently

> Note: `RD_DIS` is **not** locked thanks to `CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS=y`, so you can still burn and read-protect HMAC keys after this point.

### 8. Monitor

```bash
idf.py -p /dev/ttyACM1 monitor
```

Verify:
- `ECDSA secure boot verification succeeded`
- `secure boot v2 is already enabled`
- `flash encryption is enabled`
- `eFuse KEY5 already provisioned with HMAC_UP` (or `First boot — provisioning eFuse HMAC key...` on first boot)
- TEE initializes without reset loop
- Application starts and WiFi connects

> **Note:** KEY5 (application HMAC) is automatically provisioned by the firmware's TEE service (SS 206) on first app boot. No manual burning is needed for this block.

### 9. Lock RD_DIS (final hardening)

After all eFuse keys are provisioned and read-protected, permanently lock `RD_DIS` to prevent any further read-protection changes:

```bash
espefuse.py --port /dev/ttyACM1 write_protect_efuse RD_DIS
```

This burns `WR_DIS_RD_DIS`, giving the same final security posture as the default (without `ALLOW_EFUSE_RD_DIS`). Verify with:

```bash
espefuse.py --port /dev/ttyACM1 summary 2>&1 | grep RD_DIS
```

> **WARNING: This is irreversible.** Only do this after confirming all HMAC key blocks are correctly provisioned and read-protected.

## Development Workflow (Current Chip)

For the current dev chip where `RD_DIS` is already locked, use development mode:

```ini
CONFIG_SECURE_TEE_SEC_STG_MODE_DEVELOPMENT=y
CONFIG_SECURE_TEE_SEC_STG_EFUSE_HMAC_KEY_ID=-1
CONFIG_SECURE_TEE_PBKDF2_EFUSE_HMAC_KEY_ID=-1
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y
```

Since flash encryption is active (`SPI_BOOT_CRYPT_CNT` has odd bits set), you **must** use `--encrypt` when flashing. `idf.py flash` skips the bootloader when secure boot is enabled, so use esptool directly:

```bash
esptool.py --chip esp32c6 -p /dev/ttyACM1 --baud 460800 \
  --before=default_reset --after=no_reset --no-stub \
  write_flash --encrypt --flash_mode dio --flash_freq 80m --flash_size 2MB \
  0x0 build/bootloader/bootloader.bin \
  0x10000 build/partition_table/partition-table.bin \
  0x20000 build/esp_tee/esp_tee.bin \
  0x60000 build/esp32-tang.bin
```

> **Note:** Without `--encrypt`, plaintext data is written to flash but the hardware decryption layer is active, causing reads to return garbage (e.g., partition table magic becomes 0x9115 instead of 0x50AA).

## Signing Key Management

- **File:** `secure_boot_signing_key.pem` (ECDSA P-256)
- **Generate:** `espsecure.py generate_signing_key --version 2 --scheme ecdsa256 secure_boot_signing_key.pem`
- **Never commit to git** — add to `.gitignore`
- **Back up** in Bitwarden (as attachment) and on an offline USB drive
- **If lost**, the device cannot receive firmware updates

## Gotchas

- **Lock `RD_DIS` after provisioning** — with `ALLOW_EFUSE_RD_DIS`, RD_DIS stays writable; run `espefuse.py write_protect_efuse RD_DIS` as a final hardening step after all keys are burned
- **`idf.py flash` skips the bootloader** when secure boot is enabled — use `esptool.py write_flash` directly with the bootloader address
- **Signing scheme must match** — `CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME=y` for ECDSA keys; the default is RSA even if you generated an ECDSA key
- **Partition table offset 0x10000** is required because the signed bootloader exceeds 32 KB (default 0x8000)
- **TEE app partition must be 0x10000-aligned** (0x20000, not 0x18000)
