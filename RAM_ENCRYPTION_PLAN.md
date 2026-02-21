# RAM Encryption Implementation Plan

## Goal
Encrypt Tang private keys in RAM using ESP32 hardware-bound secrets to prevent key extraction via memory dumps or exploits.

## ESP32 Hardware Features

### eFuse Key Storage
- 6 key blocks available (256-bit each)
- Can be read-protected (hardware access only)
- Permanent once written and locked

### HMAC Peripheral
- Computes HMAC using eFuse keys without exposing them to software
- API: `esp_hmac_calculate()` in `esp_hmac.h`
- Derives encryption keys that are hardware-bound

## Implementation Steps

### 1. eFuse Setup (One-time, per device)
```bash
# Generate random 256-bit key
python3 -c "import os; print(os.urandom(32).hex())" > efuse_key.txt

# Burn key to eFuse block (e.g., BLOCK_KEY0)
espefuse.py --port /dev/ttyUSB0 burn_key BLOCK_KEY0 efuse_key.txt HMAC_UP

# Lock the key (make it read-protected)
espefuse.py --port /dev/ttyUSB0 burn_efuse WR_DIS_KEY0 1
```

### 2. Create RAM Encryption Module (`ram_crypto.h`)

```cpp
#include <esp_hmac.h>
#include "crypto.h"

class RAMCrypto {
private:
    static constexpr hmac_key_id_t KEY_SLOT = HMAC_KEY0;
    static constexpr const char* CONTEXT = "tang_ram_keys_v1";
    
    uint8_t ram_key[32];
    bool key_derived;

public:
    RAMCrypto() : key_derived(false) {}
    
    // Derive encryption key from eFuse
    bool derive_key() {
        esp_err_t err = esp_hmac_calculate(KEY_SLOT,
                                          (const uint8_t*)CONTEXT,
                                          strlen(CONTEXT),
                                          ram_key);
        key_derived = (err == ESP_OK);
        return key_derived;
    }
    
    // Encrypt private key for RAM storage
    bool encrypt(const uint8_t* plaintext, size_t len,
                 uint8_t* ciphertext, uint8_t* tag) {
        if (!key_derived) return false;
        
        uint8_t nonce[12];
        RNG::generate(nonce, sizeof(nonce));
        
        return AESGCM::encrypt(ram_key, nonce, nullptr, 0,
                              plaintext, len, ciphertext, tag);
    }
    
    // Decrypt private key from RAM
    bool decrypt(const uint8_t* ciphertext, size_t len,
                 const uint8_t* tag, uint8_t* plaintext) {
        if (!key_derived) return false;
        
        uint8_t nonce[12]; // Store nonce alongside ciphertext
        return AESGCM::decrypt(ram_key, nonce, nullptr, 0,
                              ciphertext, len, tag, plaintext);
    }
    
    ~RAMCrypto() {
        memset(ram_key, 0, sizeof(ram_key));
    }
};
```

### 3. Modify `TangKeyStore` Structure

```cpp
// Instead of plaintext keys in RAM:
struct EncryptedRAMKey {
    uint8_t ciphertext[P256_PRIVATE_KEY_SIZE];
    uint8_t tag[16];
    uint8_t nonce[12];
};

EncryptedRAMKey sig_priv_enc;
EncryptedRAMKey exc_priv_enc;

// Only decrypt when needed for operations
bool use_signing_key(std::function<void(uint8_t*)> operation) {
    uint8_t temp_key[P256_PRIVATE_KEY_SIZE];
    if (!ram_crypto.decrypt(sig_priv_enc.ciphertext, sizeof(temp_key),
                           sig_priv_enc.tag, temp_key)) {
        return false;
    }
    operation(temp_key);
    memset(temp_key, 0, sizeof(temp_key));
    return true;
}
```

### 4. Update Activation Flow

**In `handle_activate()`:**
```cpp
// After successful password verification:
if (keystore.decrypt_and_load_tang_keys(password)) {
    // Encrypt keys for RAM storage
    if (!keystore.encrypt_keys_in_ram()) {
        // Fallback or error
    }
    is_active = true;
}
```

### 5. Update Handler Operations

**In `handle_rec()`:**
```cpp
// Instead of direct access:
bool success = keystore.use_exchange_key([&](uint8_t* priv) {
    P256::ecdh_exchange(client_pub, priv, shared_secret);
});
```

## Security Benefits

1. **Hardware-bound**: Keys can only be decrypted on the specific ESP32 chip
2. **RAM dumps useless**: Encrypted keys in RAM, decryption key never stored
3. **Minimal exposure**: Private keys only in plaintext during actual crypto operations
4. **Zero-copy safe**: Temporary plaintext keys zeroed immediately after use

## Testing Checklist

- [ ] Burn test key to development ESP32
- [ ] Verify HMAC derivation works
- [ ] Test key encryption/decryption roundtrip
- [ ] Verify `/rec` endpoint still functions
- [ ] Verify `/adv` signing still works
- [ ] Performance test (expect ~5-10ms overhead per operation)
- [ ] Memory dump test (verify no plaintext keys visible)

## Deployment Notes

- **One-time setup required per device** - eFuse burning is permanent
- Keep a backup of the eFuse key value (for device replacement scenarios)
- Consider factory provisioning workflow for multiple devices
- Flash encryption still recommended as additional layer

## References

- [ESP32 eFuse Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/efuse.html)
- [HMAC Peripheral API](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/peripherals/hmac.html)
- [espefuse.py Tool](https://docs.espressif.com/projects/esptool/en/latest/esp32/espefuse/index.html)
