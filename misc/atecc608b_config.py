# %%
from pandas import DataFrame

# 1. Standard Factory Defaults (Clean Slate)
# Most slots are "Open Read/Write" or "Disabled" by default.
# We start with a blank template to avoid accidental locks on other slots.
slot_config = [0x00] * 32  # 16 slots * 2 bytes
key_config = [0x00] * 32  # 16 slots * 2 bytes


# Helper to pack bytes (Little Endian)
def set_slot_config(
    slot,
    read_key,
    no_mac,
    limited_use,
    encrypt_read,
    is_secret,
    write_key,
    write_config,
):
    """
    Generates the 2-byte SlotConfig for a specific slot on the ATECC608B.

    Args:
        slot (int): The slot number (0-15) being configured.

        read_key (int): [4 bits] Defines read access requirements.
            - If IsSecret=1: This has a different meaning, see Table 2-5 in the datasheet.
            - If IsSecret=0:
                - 0-15: The Slot ID of the key required to encrypt/authorize the read.
                - 0: (If EncryptRead=0) Allows public clear-text reads.

        no_mac (int): [1 bit] Controls if a MAC (signature) is required for reads.
            - 0: MAC is required (Read is authenticated).
            - 1: No MAC required (Clear text read allowed if not Secret).

        limited_use (int): [1 bit] Controls usage limits.
            - 0: Unlimited use.
            - 1: Use is limited by the Monotonic Counter attached to this slot.

        encrypt_read (int): [1 bit] Controls read encryption.
            - 0: Clear text reads allowed (if IsSecret=0).
            - 1: Reads must be encrypted using the key in 'read_key' slot.

        is_secret (int): [1 bit] The most critical security bit.
            - 0: Public. The slot can be read in the clear (subject to other bits).
            - 1: Secret. The slot allows NO clear reads. Used for Private Keys, AES keys, etc.

        write_key (int): [4 bits] Defines write access requirements.
            - 0-15: The Slot ID of the key required to encrypt/authorize the write.
            - 0: (If WriteConfig=Always) Allows clear-text writes.

        write_config (int): [4 bits] Defines the write policy. (Crucial!)
            - 0 (0x0): Always. Clear text writes allowed (if not locked).
            - 1 (0x1): PubInvalid. Used for invalidating public keys.
            - 2 (0x2): Never. Writes are permanently forbidden (after Data Zone lock).
            - 4 (0x4): Encrypt. Writes must be encrypted with the key in 'write_key'.

    Returns:
        tuple: (Byte0, Byte1) as integers.
    """
    # Byte 0: Read Config
    # Structure: [IsSecret | EncryptRead | LimitedUse | NoMac | ReadKey(4)]
    b0 = (
        (read_key & 0x0F)
        | ((no_mac & 1) << 4)
        | ((limited_use & 1) << 5)
        | ((encrypt_read & 1) << 6)
        | ((is_secret & 1) << 7)
    )

    # Byte 1: Write Config
    # Structure: [WriteConfig(4) | WriteKey(4)]
    b1 = (write_key & 0x0F) | ((write_config & 0x0F) << 4)

    print("=================================================================")

    # Format: reverse bits and group by 4 for readability
    b0_bin = f"{b0:08b}"[::-1]
    b1_bin = f"{b1:08b}"[::-1]
    print(
        f"Slot {slot} Config: {b1_bin[:4]}_{b1_bin[4:]}_{b0_bin[:4]}_{b0_bin[4:]} ({hex(b0)} {hex(b1)}):\n"
    )

    # Detailed breakdown
    print(f"  Bits 0-3 (ReadKey): {b0_bin[:4]} = {read_key}")
    print(f"  Bit 4 (NoMac): {b0_bin[4]}{' ✓' if no_mac else ''}")
    print(f"  Bit 5 (LimitedUse): {b0_bin[5]}{' ✓' if limited_use else ''}")
    print(f"  Bit 6 (EncryptRead): {b0_bin[6]}{' ✓' if encrypt_read else ''}")
    print(f"  Bit 7 (IsSecret): {b0_bin[7]}{' ✓' if is_secret else ''}")
    print(f"  Bits 8-11 (WriteKey): {b1_bin[:4]} = {write_key}")
    print(f"  Bits 12-15 (WriteConfig): {b1_bin[4:]} = {write_config}")
    print("=================================================================\n")

    idx = slot * 2
    slot_config[idx] = b0
    slot_config[idx + 1] = b1

    return (b0, b1)


def set_key_config(
    slot,
    private,
    pub_info,
    key_type,
    req_random,
    req_auth,
    auth_key,
    lockable=0,
    persistent_disable=0,
    x509_id=0,
):
    """
    Generates the 2-byte KeyConfig for a specific slot on the ATECC608B.

    Args:
        slot (int): The slot number (0-15) being configured.

        private (int): [1 bit] Marks the slot as a Private Key.
            - 0: Standard data or Public Key.
            - 1: Private Key. (Chip will refuse to output this data).

        pub_info (int): [1 bit] Public Key Info (For ECC P256 keys).
            - 0: Standard.
            - 1: The slot contains an ECC P256 private key and allows public key generation.

        key_type (int): [3 bits] Defines the cryptographic type of the data.
            - 4 (0x4): ECC (Elliptic Curve) Key.
            - 6 (0x6): AES (Advanced Encryption Standard) Key.
            - 7 (0x7): SHA (Secure Hash Algorithm) or HMAC Key or General Data.

        lockable (int): [1 bit] Controls individual slot locking.
            - 0: Slot is not lockable (or locked by global lock).
            - 1: Slot can be individually locked.

        req_random (int): [1 bit] Random Nonce requirement.
            - 0: No random nonce required (Replay attacks possible).
            - 1: Commands using this key require a random nonce (Prevents replay).

        req_auth (int): [1 bit] Authorization requirement.
            - 0: No authorization required to use this key.
            - 1: Usage requires an authorization (password) from 'auth_key'.

        auth_key (int): [4 bits] The Authorizing Slot.
            - 0-15: ID of the slot containing the password/key needed if req_auth=1.

        persistent_disable (int): [1 bit] Persistent Latch dependency.
            - 0: Usage of this key is independent of the Persistent Latch state.
            - 1: Use of this key is prohibited (except for GenKey) if the Persistent Latch is 0.

        x509_id (int): [2 bits] X.509 Format mapping.
            - 0: Not an X.509 certificate.
            - 1: Public Key format.
            - 2: Data format.
            - 3: Full Certificate format.

    Returns:
        tuple: (Byte0, Byte1) as integers.
    """
    # Byte 0
    # Structure: [ReqAuth | ReqRandom | Lockable | KeyType(3) | PubInfo | Private]
    b0 = (
        (private & 1)
        | ((pub_info & 1) << 1)
        | ((key_type & 0x07) << 2)
        | ((lockable & 1) << 5)
        | ((req_random & 1) << 6)
        | ((req_auth & 1) << 7)
    )

    # Byte 1
    # Structure: [X509Id(2) | Reserved(1) | PersistentDisable(1) | AuthKey(4)]
    b1 = (
        (auth_key & 0x0F)
        | ((persistent_disable & 1) << 4)
        | ((x509_id & 0x03) << 6)  # Bit 5 is reserved 0
    )

    idx = slot * 2
    key_config[idx] = b0
    key_config[idx + 1] = b1

    print("=================================================================")

    # Format: reverse bits and group by 4 for readability
    b0_bin = f"{b0:08b}"[::-1]
    b1_bin = f"{b1:08b}"[::-1]
    print(
        f"Slot {slot} KeyConfig: {b1_bin[:4]}_{b1_bin[4:]}_{b0_bin[:4]}_{b0_bin[4:]} ({hex(b0)} {hex(b1)}):\n"
    )

    # Key type mapping
    key_type_names = {4: "ECC", 6: "AES", 7: "SHA/Data"}
    key_type_name = key_type_names.get(key_type, "Unknown")

    # Detailed breakdown
    print(f"  Bit 0 (Private): {b0_bin[0]}{' ✓' if private else ''}")
    print(f"  Bit 1 (PubInfo): {b0_bin[1]}{' ✓' if pub_info else ''}")
    print(f"  Bits 2-4 (KeyType): {b0_bin[2:5]} = {key_type} ({key_type_name})")
    print(f"  Bit 5 (Lockable): {b0_bin[5]}{' ✓' if lockable else ''}")
    print(f"  Bit 6 (ReqRandom): {b0_bin[6]}{' ✓' if req_random else ''}")
    print(f"  Bit 7 (ReqAuth): {b0_bin[7]}{' ✓' if req_auth else ''}")
    print(f"  Bits 8-11 (AuthKey): {b1_bin[:4]} = {auth_key}")
    print(
        f"  Bit 12 (PersistentDisable): {b1_bin[4]}{' ✓' if persistent_disable else ''}"
    )
    print(f"  Bit 13 (Reserved): {b1_bin[5]}")
    print(f"  Bits 14-15 (X509Id): {b1_bin[6:]} = {x509_id}")
    print("=================================================================\n")
    return (b0, b1)


# %%

# For ReadKey you may want to write the value in binary first:

# Note that you need to reverse the order


# For private keys (IsSecret=1), the ReadKey bits have a different meaning.
def set_read_key(Bit0, Bit1, Bit2, Bit3):
    """
    Bit 0: External signatures of arbitrary messages are enabled.
    Bit 1: Internal signatures of messages generated by GenDig or GenKey are enabled.
    Bit 2: ECDH operation is permitted for this key.
    Bit 3: If clear, then ECDH master secret will be output in the clear. If set, then master secret will be written into slot N|1. Ignored if Bit 2 is zero.
    """
    return (Bit0 << 0) | (Bit1 << 1) | (Bit2 << 2) | (Bit3 << 3)


set_read_key(1, 0, 0, 0)


# ==========================================
# 2. YOUR CUSTOM CONFIGURATION (Slot 6)
# ==========================================

# Make a Dtaframe for the slotconfig inputs to visualize the bits more easily
slot_df = DataFrame(
    {
        "ReadKey": [0] * 16,
        "NoMac": [0] * 16,
        "LimitedUse": [0] * 16,
        "EncryptRead": [0] * 16,
        "IsSecret": [0] * 16,
        "WriteKey": [0] * 16,
        "WriteConfig": [0] * 16,
    }
)

# Look at Table 2-3 in the datasheet for the size of the slots

# %%

# TODO: Create ReqAuth and AuthKey
# TODO: Look if we can utilize 'WriteKey' for an AES key that requires updates
# TODO: Look if we really need pub_info
# TODO: Look if we can utilize ReadKey Bit 3 (writing master secret into
# anotother slot) for ECDH use cases

Config = {
    # -------------------------------------------------------------------------
    # SLOT 0: ECDSA Private Key (Permanent Identity, Locked)
    # Standard Signing Key.
    # -------------------------------------------------------------------------
    0: {
        "SlotConfig": {
            "read_key": 1,
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 0,
            "is_secret": 1,
            "write_key": 0,
            "write_config": 0,  # Don't allow PrivWrite or GenKey
        },
        "KeyConfig": {
            "private": 1,
            "pub_info": 1,
            "key_type": 4,
            "lockable": 1,
            "req_random": 0,
            "req_auth": 0,
            "auth_key": 0,
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 0: ECDSA Private Key (Standard, Genkey Allowed)
    # Standard Signing Key.
    # -------------------------------------------------------------------------
    1: {
        "SlotConfig": {
            "read_key": 1,
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 0,
            "is_secret": 1,
            "write_key": 0,
            "write_config": 2,  # Allow GenKey but not PrivWrite
        },
        "KeyConfig": {
            "private": 1,
            "pub_info": 1,
            "key_type": 4,
            "lockable": 0,
            "req_random": 0,
            "req_auth": 0,
            "auth_key": 0,
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 2: "Protected" ECDSA Key (Requires ECC Auth - Slot 9)
    # -------------------------------------------------------------------------
    2: {
        "SlotConfig": {
            "read_key": 1,
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 0,
            "is_secret": 1,
            "write_key": 0,
            "write_config": 2,
        },
        "KeyConfig": {
            "private": 1,
            "pub_info": 1,
            "key_type": 4,
            "lockable": 0,
            "req_random": 1,
            "req_auth": 1,  # Auth Required
            "auth_key": 9,  # Must authorize with Slot 9 (Public Key)
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 3: "Protected" ECDSA Key (Requires AES Auth - Slot 10)
    # -------------------------------------------------------------------------
    3: {
        "SlotConfig": {
            "read_key": 1,
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 0,
            "is_secret": 1,
            "write_key": 0,
            "write_config": 2,  # Allow GenKey but not PrivWrite
        },
        "KeyConfig": {
            "private": 1,
            "pub_info": 1,
            "key_type": 4,
            "lockable": 0,
            "req_random": 0,
            "req_auth": 1,  # Auth Required
            "auth_key": 10,  # Must authorize with Slot 10 (AES)
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 4: ECDH Private Key (Base)
    # -------------------------------------------------------------------------
    4: {
        "SlotConfig": {
            "read_key": 4,  # ECDH Enabled (Output in Clear)
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 0,
            "is_secret": 1,
            "write_key": 4,
            "write_config": 2,  # Allow GenKey but not PrivWrite
        },
        "KeyConfig": {
            "private": 1,
            "pub_info": 1,
            "key_type": 4,
            "lockable": 0,
            "req_random": 1,
            "req_auth": 0,
            "auth_key": 0,
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 5: ECDH with Persisent Latch Dependency
    # -------------------------------------------------------------------------
    5: {
        "SlotConfig": {
            "read_key": 4,  # ECDH Enabled (Output in Clear)
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 0,  # Reads never permitted for private keys
            "is_secret": 1,
            "write_key": 0,
            "write_config": 2,  # Allow GenKey but not PrivWrite
        },
        "KeyConfig": {
            "private": 1,
            "pub_info": 1,
            "key_type": 4,
            "lockable": 0,
            "req_random": 1,
            "req_auth": 0,
            "auth_key": 0,
            "persistent_disable": 1,
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 6: IO Protection Key (SHA-256)
    # -------------------------------------------------------------------------
    6: {
        "SlotConfig": {
            "read_key": 6,  # Points to self (standard convention)
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 1,
            "is_secret": 1,
            "write_key": 6,
            "write_config": 4,  # Never allow Write command
        },
        "KeyConfig": {
            "private": 0,
            "pub_info": 0,
            "key_type": 7,  # SHA-256 Key
            "lockable": 1,
            "req_random": 1,
            "req_auth": 0,
            "auth_key": 0,
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 9: Public Key (Admin / Root)
    # Used to authorize Slot 3 via Verify command.
    # -------------------------------------------------------------------------
    9: {
        "SlotConfig": {
            "read_key": 0,  # Publicly readable
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 0,
            "is_secret": 0,  # Not Secret
            "write_key": 0,
            "write_config": 2,  # Never
        },
        "KeyConfig": {
            "private": 0,  # Not a Private Key
            "pub_info": 0,  # We lock after provisioning so we can trust it.
            "key_type": 4,  # P-256
            "lockable": 0,
            "req_random": 0,
            "req_auth": 0,
            "auth_key": 0,
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 10: Authorization Key (Standard)
    # Used to authorize CheckMac command.
    # REQUIRES Nonce command first (ReqRandom=1).
    # -------------------------------------------------------------------------
    10: {
        "SlotConfig": {
            "read_key": 10,  # Points to self (Disable CheckMac Copy)
            "no_mac": 1,
            "limited_use": 0,
            "encrypt_read": 0, # Reads never permitted if is_secret=1
            "is_secret": 1,
            "write_key": 10,
            "write_config": 4,  # Write with MAC (Table 2-7)
        },
        "KeyConfig": {
            "private": 0,
            "pub_info": 0,
            "key_type": 7,  # SHA-256 Key
            "lockable": 0,  # Maybe make that lockable if it works with ESP Efuse
            "req_random": 1,
            "req_auth": 0,
            "auth_key": 0,
            "x509_id": 0,
        },
    },
    # -------------------------------------------------------------------------
    # SLOT 5: ECDH with Persisent Latch Dependency and ECDSA auth requirement
    # -------------------------------------------------------------------------
    11: {
        "SlotConfig": {
            "read_key": 4,  # ECDH Enabled (Output in Clear)
            "no_mac": 0,
            "limited_use": 0,
            "encrypt_read": 0,  # Reads never permitted for private keys
            "is_secret": 1,
            "write_key": 0,
            "write_config": 2,  # Allow GenKey but not PrivWrite
        },
        "KeyConfig": {
            "private": 1,
            "pub_info": 1,
            "key_type": 4,
            "lockable": 0,
            "req_random": 1,
            "req_auth": 1,
            "auth_key": 9,  # Must authorize with Slot 9 (Public Key)
            "persistent_disable": 1,
            "x509_id": 0,
        },
    },
}

# %%
# set_slot_config(
#     slot=0,
#     read_key=1,
#     no_mac=0,
#     limited_use=0,
#     encrypt_read=0,
#     is_secret=1,
#     write_key=0,
#     write_config=2,
# )

# set_key_config(
#     slot=0,
#     private=1,
#     pub_info=1,
#     key_type=4,
#     lockable=1,
#     req_random=1,
#     req_auth=0,
#     auth_key=0,
#     x509_id=0,
# )

# Configure all slots from the Config dictionary
for slot_num, slot_data in Config.items():
    set_slot_config(slot=slot_num, **slot_data["SlotConfig"])
    set_key_config(slot=slot_num, **slot_data["KeyConfig"])

# Print the resulting bytes for verification
# print("--- Generated Configuration ---")
# print(f"SlotConfig (Bytes 20- 51): {[hex(x) for x in slot_config]}")
# print(f"KeyConfig  (Bytes 96-127): {[hex(x) for x in key_config]}")

# # %%
# slot_df = DataFrame(
#     {
#         "SlotConfig": [
#             f"{hex(slot_config[i*2])} {hex(slot_config[i*2+1])}" for i in range(16)
#         ],
#         "KeyConfig": [
#             f"{hex(key_config[i*2])} {hex(key_config[i*2+1])}" for i in range(16)
#         ],
#     }
# )
# print(slot_df)
# %%

# ==========================================
# 3. HOW TO APPLY (Pseudo-code)
# ==========================================
"""
ATCA_STATUS status;
// 1. Write the computed bytes to the Configuration Zone
status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 20, slot_config, 32);
status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 96, key_config, 32);

// 2. Lock Configuration Zone
status = atcab_lock_config_zone();

// 3. PROVISIONING (The Golden Window)
// Now that Config is locked, but Data is Unlocked, we can write the key!
uint8_t aes_key[32] = { ... your 16 bytes key padded with 0 ... };
status = atcab_write_zone(ATCA_ZONE_DATA, 6, 0, 0, aes_key, 32);

// 4. Lock Data Zone
status = atcab_lock_data_zone();
"""

# %%
