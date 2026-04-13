# ESP32-C6 Tang Server

A hardware-secured [Tang](https://github.com/latchset/tang) server running on an **ESP32-C6** microcontroller with ESP-TEE (Trusted Execution Environment).

Tang is a network-based key escrow protocol — clients encrypt secrets to the server's public key and later recover them via an ECDH exchange. This implementation confines all private key material to the TEE; the application (REE) never sees secret keys.

## Features

- **Full Tang protocol** — `/adv` (JWS-signed key advertisement) and `/rec` (ECDH recovery), compatible with [clevis](https://github.com/latchset/clevis)
- **Hardware-isolated keys** — signing and exchange private keys live exclusively in the ESP32-C6 TEE (M-mode). Key derivation uses the hardware HMAC peripheral tied to a one-time-programmable eFuse key
- **Zero-knowledge unlock** — password never leaves the browser; only a PBKDF2 derivative is transmitted inside an ECIES-encrypted tunnel
- **Key rotation** — exchange keys are managed in a generational ring buffer with password-verified rotation
- **Password change** — re-derives the entire key hierarchy with forward secrecy (fresh KDF salt per change)
- **Web UI** — embedded HTML/JS interface using the native Web Crypto API (no external dependencies)
- **Secure Boot V2 + Flash Encryption** — firmware integrity and flash confidentiality
- **WiFi provisioning** — SoftAP captive portal for initial WiFi setup (SSID, password, hostname)
- **Rate limiting** — exponential backoff on failed password attempts (up to 5 min)

## Quick Start

### Prerequisites

- ESP-IDF v5.5+ with ESP-TEE support
- ESP32-C6 development board
- Nix (optional, for reproducible builds via `flake.nix`)

### Build & Flash

```bash
# With Nix
nix develop
idf.py build

# Without Nix (ensure ESP-IDF is sourced)
idf.py build
```

See [PROVISIONING.md](PROVISIONING.md) for production deployment steps including Secure Boot, Flash Encryption, and eFuse key burning.

### Usage

1. **First boot** — if no WiFi is configured, the device starts a SoftAP (`ESP-Tang-Setup`). Connect and visit `https://192.168.4.1` to enter WiFi credentials.
2. **Unlock** — open `https://<device-ip>/` in a browser and enter the password. On first use this initializes the Tang keys; on subsequent boots it activates the server.
3. **Bind a client** — once unlocked, use clevis or curl:
   ```bash
   clevis luks bind -d /dev/sdX tang '{"url":"http://<device-ip>"}'
   ```
4. **Recover** — standard Tang clients (`clevis luks unlock`) work automatically via the `/adv` and `/rec` endpoints on port 80.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a detailed description of the key hierarchy, TEE security boundaries, ECIES tunnel design, and endpoint reference.

## Provisioning

See [PROVISIONING.md](PROVISIONING.md) for step-by-step production provisioning: eFuse key burning, Secure Boot, Flash Encryption, and development flashing with encryption.

## Security

- Private keys never leave the TEE
- eFuse HMAC key is hardware-protected (read-disabled, accessible only via HMAC peripheral)
- PBKDF2 with 600,000 iterations (OWASP 2023 minimum for SHA-256)
- ECIES tunnel provides end-to-end encryption independent of TLS
- Strict Content-Security-Policy with hash-based allowlists (no `unsafe-inline`)
- Exponential backoff rate limiting on authentication attempts
- Ephemeral tunnel keys regenerated after every use (per-operation forward secrecy)

See [SECURITY_HARDENING.md](SECURITY_HARDENING.md) for the full vulnerability analysis and remediation log.
