## Plan: TEE Secure Storage Key Persistence

Store derived private keys in TEE Secure Storage (encrypted NVS partition) so `master_key` can be zeroized from TEE RAM after activation. Move password verification inside the TEE by comparing derived private keys with stored ones (replacing REE-side public key comparison). Private keys are read from flash on each sign/ECDH operation (no RAM cache). eFuse KEY2 encrypts the Secure Storage NVS partition.

**Decisions**
- Storage: Direct NVS blobs on the `secure_storage` partition, namespace `"tang_keys"` — partition-level encryption is sufficient, no AEAD wrapping layer
- Password verification: Re-derive signing key, constant-time compare with stored signing private key (inside TEE)
- No RAM cache — read from flash per sign/ECDH, zeroize from stack immediately
- eFuse: KEY3 for Secure Storage NVS encryption, KEY5 stays for HMAC derivation
- Rotate/change_password re-derive master_key on stack (since it's no longer in static RAM)

**Steps**

*Phase 1 — TEE service rewrite* (`components/tang_tee_service/tang_tee_service.c`)

1. **Remove `static uint8_t master_key[32]`** — the core goal
2. **Add NVS infrastructure**: `static nvs_handle_t tang_nvs`, lazy `ensure_nvs()` opening `"secure_storage"` partition / `"tang_keys"` namespace. NVS keys: `"sig_priv"`, `"exc_0"`…`"exc_15"`
3. **Modify `derive_signing_key` / `derive_exchange_key`**: take explicit `const uint8_t *mk` parameter instead of reading static `master_key`
4. **Rewrite `_ss_tang_tee_activate`** (SS 200, signature unchanged):
   - Derive master_key on stack via `esp_hmac_calculate(HMAC_KEY5, ...)`
   - Check if `"sig_priv"` exists in NVS:
     - **First activation**: derive all keys → write to NVS → compute pubkeys → output
     - **Subsequent**: derive signing key on stack → read stored from NVS → constant-time compare → mismatch = wrong password (`ESP_ERR_INVALID_ARG`) → match = load exchange keys from NVS → compute pubkeys → output
   - Zeroize master_key and all temporaries from stack
5. **Rewrite `_ss_tang_tee_sign`** (SS 201, unchanged signature): read `"sig_priv"` from NVS → sign → zeroize
6. **Rewrite `_ss_tang_tee_ecdh`** (SS 202, unchanged signature): read `"exc_N"` from NVS → ECDH → zeroize
7. **Rewrite `_ss_tang_tee_rotate`** (SS 203, **signature change**): `(keying_material, new_gen, pub_key_out)` — derive master_key on stack → verify password via signing key comparison → derive new exchange key → write NVS → compute pubkey → zeroize
8. **Simplify `_ss_tang_tee_lock`** (SS 204): just set `activated=false` — no RAM secrets to wipe
9. **Rewrite `_ss_tang_tee_change_password`** (SS 205, unchanged): verify old via signing key comparison → derive all new keys → overwrite NVS → compute pubkeys → zeroize

*Phase 2 — Header + registration* (*parallel with Phase 3*)

10. `components/tang_tee_service/include/tang_tee_service.h`: update `tang_tee_rotate` — add `keying_material` param, arg count → 4
11. `components/tang_tee_service/sec_srv_tbl_tang.yml`: rotate args `2` → `3`
12. `components/tang_tee_service/CMakeLists.txt`: add `nvs_flash` to `PRIV_REQUIRES`

*Phase 3 — REE-side changes* (*parallel with Phase 2*)

13. `main/tang_storage.h`: remove `verify_public_keys()`, update `rotate(const uint8_t *password_hash)` to build keying_material and pass to `tang_tee_rotate`
14. `main/zk_auth.h` `process_unlock`: remove `keystore.verify_public_keys()` — TEE's return code is the source of truth
15. `main/zk_auth.h` `process_rotate`: remove re-activation dance, build keying_material, call `keystore.rotate(password_hash)`
16. `main/zk_auth.h` `process_change_password`: no major changes (still stores public keys in REE NVS for `/adv`)

*Phase 4 — Configuration*

17. `sdkconfig.defaults`: set `CONFIG_SECURE_TEE_SEC_STG_EFUSE_HMAC_KEY_ID=2` in the production comment section

*Phase 5 — Verification*

18. Build + fix compilation errors

**Verification**
1. `idf.py build` succeeds (TEE + REE)
2. Grep `master_key` in tang_tee_service.c → zero static/global occurrences (only stack `mk` variables)
3. Grep `verify_public_keys` in zk_auth.h → zero occurrences
4. YAML arg count matches header `esp_tee_service_call` arg count for rotate
5. Manual: first boot → password → activates → /adv + /rec work → reboot → re-enter password → same keys → /rec works
6. Manual: wrong password after reboot → TEE returns error → device stays locked

**Further Considerations**
1. **Partial-write recovery**: Power loss mid-first-activation could leave partial keys in NVS. On next boot, `"sig_priv"` exists but some exchange keys may be missing. Suggestion: if any exchange key read fails during subsequent activation, erase all `tang_keys` entries and retry as first activation.
2. **Dev vs release mode**: Currently `SECURE_TEE_SEC_STG_MODE_DEVELOPMENT=y` (constant NVS encryption keys). Private keys in NVS are only truly protected in release mode with eFuse-based encryption. This is pre-existing and unchanged by this plan.
