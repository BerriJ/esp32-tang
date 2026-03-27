# ESP32 Tang Server — Architecture Overview

This document describes the architecture of the ESP32 Tang server implementation: how
the system is structured, how keys are derived and stored, and how the security
boundaries between the TEE and REE are enforced.

## What Is This?

An embedded [Tang](https://github.com/latchset/tang) server running on an
**ESP32-C6** microcontroller. Tang is a network-based key escrow protocol that
allows clients to encrypt secrets and later recover them by contacting the Tang
server, which performs an ECDH exchange to release the decryption material.

This implementation targets **ESP-IDF** with the **ESP-TEE** (Trusted Execution
Environment) on the C6's RISC-V core. All private key material is confined to
TEE (M-mode) memory and is never exposed to the application (REE / U-mode).

---

## Project Structure

```
main/
  main.cpp             Entry point (setup + loop)
  TangServer.h         WiFi, HTTP server, boot sequence
  encoding.h           Base64url encode/decode helpers
  tang_storage.h       TangKeyStore — public key cache, NVS persistence, rotation
  tang_handlers.h      HTTP handlers for /adv and /rec (Tang protocol)
  provision.h          eFuse KEY5 provisioning logic
  provision_handlers.h HTTP handlers for /api/provision/*
  zk_auth.h            ZKAuth — ECIES tunnel, unlock/change-password/rotate
  zk_handlers.h        HTTP handlers for /api/identity, /api/unlock, etc.
  zk_web_page.h        Embedded HTML/JS web interface
  Kconfig.projbuild    Menuconfig: WiFi creds, NUM_EXCHANGE_KEYS

components/
  tang_tee_service/
    tang_tee_service.c              TEE secure service implementations
    include/tang_tee_service.h      REE-side inline wrappers (esp_tee_service_call)
    sec_srv_tbl_tang.yml            Secure service table definition
```

---

## Boot Sequence

On each power-on the device executes these steps (in `setup()`):

1. **NVS init** — initialize non-volatile storage.
2. **eFuse KEY5 provisioning** — if KEY5 is unused, the TEE generates a random
   256-bit HMAC key, burns it into eFuse block KEY5 with purpose `HMAC_UP`, and
   sets read/write protections. This is a **one-time, irreversible** operation.
3. **Load signing public key** from NVS (if previously stored). This lets the
   device advertise its JWK identity before activation.
4. **Load exchange public keys** and generation counter from NVS.
5. **Initialize ZKAuth** — generate a fresh ephemeral ECDH tunnel keypair
   (P-256) for the ECIES channel. This keypair is **per-boot** and not persisted.
6. **Start WiFi + HTTP server** — register all route handlers.

After boot the server advertises keys via `/adv` but will refuse `/rec` requests
until the device is unlocked with the correct password.

---

## Key Hierarchy

The system has a three-level key hierarchy. Each level is derived deterministically
from the one above, enabling password-based recovery of all keys.

```
User Password (plaintext, browser-only)
  │
  ├─ PBKDF2-HMAC-SHA256(password, MAC-address, 10 000 iterations)
  │    → password_hash (32 bytes, sent to device via ECIES tunnel)
  │
  └─ [Inside TEE] HMAC-SHA256(eFuse KEY5, password_hash)
       → master_key (32 bytes, TEE-only, never exported)
       │
       ├─ HKDF-Expand: HMAC-SHA256(master_key, "tang-signing-key" || 0x01)
       │    → signing private key (P-256 scalar, 32 bytes)
       │    → signing public key = d × G
       │
       ├─ HKDF-Expand: HMAC-SHA256(master_key, "tang-exchange-key-{gen}" || 0x01)
       │    → exchange private key for generation {gen} (P-256 scalar)
       │    → exchange public key = d × G
       │
       └─ (one exchange key per active generation)
```

### 1. PBKDF2 Password Hash (Client Side)

The user's plaintext password never leaves the browser. The embedded web UI
performs **PBKDF2-HMAC-SHA256** with:

| Parameter  | Value                                              |
| ---------- | -------------------------------------------------- |
| Password   | User-supplied string                               |
| Salt       | Device MAC address (6 bytes, from `/api/identity`) |
| Iterations | 10 000                                             |
| Key length | 256 bits (32 bytes)                                |

The resulting 32-byte `password_hash` is the only secret that crosses the
network boundary; it is protected in transit by the ECIES tunnel (see below).

### 2. Master Key (TEE Only)

Inside the TEE, the master key is derived using the **hardware HMAC peripheral**
tied to the one-time-programmable eFuse KEY5:

```
master_key = HMAC-SHA256(eFuse_KEY5, password_hash)
```

- The eFuse KEY5 is **read-protected**: even the TEE firmware cannot read the
  raw key bytes; it can only invoke the HMAC peripheral.
- The master key exists only in TEE SRAM and is wiped on lock or reboot.
- A wrong password produces a different master key, which produces different
  public keys that don't match NVS — the device rejects the attempt.

### 3. Signing Key (ECDSA P-256)

Derived from the master key via a single-step HKDF-Expand:

```
signing_priv = HMAC-SHA256(master_key, "tang-signing-key" || 0x01)
```

- **Curve**: NIST P-256 (secp256r1)
- **Purpose**: signs the `/adv` JWS response (ES256) so clients can verify
  authenticity of the advertised key set.
- **Lifetime**: stable as long as the password doesn't change. A password
  change re-derives all keys.
- The private key never leaves the TEE. Signing is performed by `tang_tee_sign()`.

### 4. Exchange Keys (ECDH P-256, Generational)

Each exchange key is derived with a generation-specific info string:

```
exchange_priv[gen] = HMAC-SHA256(master_key, "tang-exchange-key-{gen}" || 0x01)
```

- **Curve**: NIST P-256
- **Purpose**: ECDH key agreement for the Tang `/rec` (recovery) endpoint.
  Clients encrypt secrets to the exchange public key; recovery requires the
  server to perform the ECDH computation with the corresponding private key.
- **Algorithm tag**: `ECMR` (Elliptic Curve McRae — the Tang recovery algorithm).
- **Generation counter**: monotonically increasing integer. The device keeps
  `NUM_EXCHANGE_KEYS` (default 3) active generations in a ring buffer.
- Private keys are re-derived on demand inside the TEE; they are never stored.

---

## Key Storage

### eFuse KEY5 (Hardware, One-Time)

| Property       | Value                                                 |
| -------------- | ----------------------------------------------------- |
| Block          | `EFUSE_BLK_KEY5`                                      |
| Purpose        | `HMAC_UP` (upstream HMAC)                             |
| Size           | 256 bits                                              |
| Protections    | Read-disabled, write-disabled, purpose-write-disabled |
| Provisioned by | `tang_tee_provision_efuse()` on first boot            |

The raw key cannot be read by software. It is only accessible through the
hardware HMAC peripheral (`esp_hmac_calculate()`).

### NVS (Non-Volatile Storage)

The `tang-server` NVS namespace stores **public keys only**:

| NVS Key     | Type | Size | Description                     |
| ----------- | ---- | ---- | ------------------------------- |
| `sig_pub`   | blob | 64 B | Signing public key (x ∥ y)      |
| `exc_pub_0` | blob | 64 B | Exchange public key, slot 0     |
| `exc_pub_1` | blob | 64 B | Exchange public key, slot 1     |
| …           | …    | …    | … up to `NUM_EXCHANGE_KEYS - 1` |
| `gen`       | u32  | 4 B  | Current generation counter      |

Public keys are loaded at boot for `/adv` responses and are updated when keys
are rotated or the password is changed.

### TEE SRAM (Volatile)

The TEE maintains in-memory state that is lost on reboot or lock:

- `master_key[32]` — derived from eFuse + password hash
- `activated` flag
- `current_gen`, `num_exchange_keys`

Private keys are **never stored**; they are re-derived from `master_key` on
every sign/ECDH/rotate operation and immediately wiped.

---

## ECIES Tunnel (Password Transport)

To protect the PBKDF2 hash in transit (the device does not use TLS), the web
interface establishes an **ECIES** (Elliptic Curve Integrated Encryption Scheme)
tunnel to the device:

1. **Device** generates an ephemeral P-256 keypair on each boot and serves the
   public key at `GET /api/identity`.
2. **Browser** generates its own ephemeral P-256 keypair and computes:
   ```
   shared_secret = ECDH(client_priv, device_pub)   // x-coordinate only
   enc_key = SHA-256("encryption"  || shared_secret)
   mac_key = SHA-256("authentication" || shared_secret)
   ```
3. **Browser** encrypts the PBKDF2 hash:
   - AES-256-CBC with a random 16-byte IV, using `enc_key`
   - HMAC-SHA256 over `IV || ciphertext`, using `mac_key`
   - Blob = `IV(16) || Ciphertext(N) || HMAC(32)`
4. **Browser** sends `{ clientPub: "hex", blob: "hex" }` to the device.
5. **Device** (REE) performs the reverse ECDH + Encrypt-then-MAC verification
   to recover the 32-byte `password_hash`, passes it to the TEE, then
   immediately zeroizes it from REE memory.

---

## Exchange Key Rotation

Exchange keys are managed in a **ring buffer** of `NUM_EXCHANGE_KEYS` slots
(configurable, default 3). The generation counter (`gen`) increases
monotonically; the active slot is `gen % NUM_EXCHANGE_KEYS`.

### Rotation Flow

1. User triggers rotation via the web UI (`POST /api/rotate` with ECIES blob).
2. REE verifies the password (re-derive + compare public keys in NVS).
3. `gen` is incremented; the TEE derives the new exchange key for the new
   generation and returns its public key.
4. The new public key overwrites the oldest slot in the ring buffer.
5. NVS is updated: the new slot's public key and the `gen` counter.

Clients that encrypted to an older (but still active) generation can still
recover as long as that generation is still within the ring buffer window.

### Recovery Endpoint (`POST /rec/{kid}`)

The `{kid}` path component is the **JWK Thumbprint** (RFC 7638, SHA-256) of
the target exchange key. The server iterates over all active generations,
computes each thumbprint, and performs ECDH with the matching key. If no `kid`
is provided, the newest generation is used.

---

## Password Change

A password change re-derives the entire key hierarchy:

1. Browser computes `old_hash` and `new_hash` (both PBKDF2) and sends both
   in a single 64-byte ECIES blob to `POST /api/change-password`.
2. TEE verifies `HMAC(eFuse KEY5, old_hash) == current master_key`
   (constant-time comparison). If it fails, the request is rejected.
3. TEE derives `new_master_key = HMAC(eFuse KEY5, new_hash)` and replaces the
   old master key.
4. All signing and exchange keys are re-derived from the new master key;
   the generation counter resets to `NUM_EXCHANGE_KEYS - 1`.
5. New public keys are stored in NVS, replacing the old ones.

**Important**: a password change invalidates all existing client bindings —
clients that encrypted to old exchange keys will no longer be able to recover.

---

## Tang Protocol Endpoints

| Endpoint                | Method | Description                                         |
| ----------------------- | ------ | --------------------------------------------------- |
| `/adv`                  | GET    | JWS-signed advertisement of signing + exchange keys |
| `/rec`                  | POST   | Recovery (ECDH) using the newest exchange key       |
| `/rec/{kid}`            | POST   | Recovery using a specific key (by JWK Thumbprint)   |
| `/api/identity`         | GET    | Device tunnel public key + MAC address              |
| `/api/status`           | GET    | Unlock/configuration status, gen counter, uptime    |
| `/api/unlock`           | POST   | Submit ECIES-encrypted password hash                |
| `/api/lock`             | POST   | Wipe TEE secrets, disable `/rec`                    |
| `/api/change-password`  | POST   | Change password (ECIES blob: old + new hash)        |
| `/api/rotate`           | POST   | Rotate to next exchange key generation              |
| `/api/provision/status` | GET    | eFuse KEY5 provisioning status                      |
| `/api/provision`        | POST   | Trigger eFuse KEY5 provisioning                     |
| `/reboot`               | GET    | Reboot the device                                   |
| `/`                     | GET    | Embedded web UI (HTML/JS)                           |

---

## Security Boundaries

```
┌──────────────────────────────────────────────┐
│  Browser (REE - untrusted network)           │
│  • Plaintext password (never transmitted)    │
│  • PBKDF2 hash (encrypted in ECIES tunnel)   │
│  • Ephemeral ECDH keypair                    │
└──────────────┬───────────────────────────────┘
               │ ECIES-encrypted blob (HTTP)
┌──────────────▼───────────────────────────────┐
│  ESP32 REE (U-mode, main application)        │
│  • ECIES decryption (ephemeral tunnel key)   │
│  • password_hash in memory < 1 ms, zeroized  │
│  • Public keys, NVS, HTTP server             │
│  • NO access to private keys or master_key   │
└──────────────┬───────────────────────────────┘
               │ esp_tee_service_call()
┌──────────────▼───────────────────────────────┐
│  ESP32 TEE (M-mode, hardware-isolated)       │
│  • master_key (SRAM, volatile)               │
│  • Private key derivation + sign + ECDH      │
│  • eFuse KEY5 HMAC peripheral                │
│  • Keys wiped on lock / reboot               │
└──────────────────────────────────────────────┘
               │ Hardware HMAC
┌──────────────▼───────────────────────────────┐
│  eFuse KEY5 (read-protected, immutable)      │
│  • 256-bit HMAC key                          │
│  • Accessible only via HMAC peripheral       │
└──────────────────────────────────────────────┘
```

### Key Guarantees

- **Private keys never leave the TEE.** Sign and ECDH operations are performed
  entirely in TEE SRAM; only public keys and signatures are returned.
- **The password never leaves the browser.** Only a salted PBKDF2 derivative
  is transmitted, and only under ECIES encryption.
- **The eFuse key is hardware-protected.** Even a full firmware compromise
  (REE or TEE) cannot extract the raw eFuse key — only the HMAC peripheral can
  use it.
- **Wrong passwords are detectable.** A wrong password produces a different
  master key, which produces different public keys that fail to match the ones
  stored in NVS.
- **Ephemeral tunnel keys** change on every boot, providing forward secrecy
  for the password transport channel.
