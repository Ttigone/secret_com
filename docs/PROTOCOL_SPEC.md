# secret_com — Wire Protocol Specification

> Version 1.0 · March 2026  
> All multi-byte integers are **little-endian** unless noted.

---

## 1. Frame Format

Every message is wrapped in a frame with the following layout:

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0       1     Start byte 0  (0xAA)
1       1     Start byte 1  (0x55)
2       1     MsgType       (see §2)
3       2     SeqNum        uint16 LE — wraps at 0xFFFF
5       2     PayloadLen    uint16 LE — max 512
7       N     Payload       raw bytes
7+N     2     CRC16         CRC16-CCITT over bytes [0 .. 7+N-1]
```

**Total overhead**: 9 bytes (7 header + 2 CRC).

**CRC16-CCITT**: polynomial `0x1021`, initial value `0xFFFF`.

---

## 2. Message Types

| Value | Name              | Direction         | Description                        |
|-------|-------------------|-------------------|------------------------------------|
| 0x01  | KEY_EXCHANGE_REQ  | Client → Server   | Ephemeral pubkey + nonce           |
| 0x02  | KEY_EXCHANGE_RSP  | Server → Client   | Ephemeral pubkey + device signature|
| 0x03  | AUTH_REQUEST      | Client → Server   | Encrypted authorization request    |
| 0x04  | AUTH_RESPONSE     | Server → Client   | Encrypted authorization response   |
| 0x05  | HEARTBEAT         | Either direction  | Keep-alive (empty payload)         |
| 0x06  | DISCONNECT        | Either direction  | Graceful disconnect                |
| 0xFF  | ERROR             | Either direction  | 1-byte error code payload          |

---

## 3. Message Payloads

### 3.1 KEY_EXCHANGE_REQ (89 bytes)

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0       65    cli_eph_pub    Client's ephemeral ECDH public key
                             (uncompressed P-256: 0x04 ‖ X ‖ Y)
65      8     cli_timestamp  Client Unix time (uint64 LE, seconds)
73      16    cli_random     Cryptographically random nonce
```

### 3.2 KEY_EXCHANGE_RSP (90 + sig_len bytes, max 162)

```
Offset  Size      Field
──────  ────      ─────────────────────────────────────────────────
0       65        srv_eph_pub     Server's ephemeral ECDH public key
65      8         srv_timestamp   Server Unix time (uint64 LE)
73      16        srv_random      Cryptographically random nonce
89      1         sig_len         Length of following signature (≤ 72)
90      sig_len   signature       DER-encoded ECDSA-SHA256 signature
```

**Signed data** (server signs with the device static private key):

```
signed_data = SHA256(
    "secret_com_kex_v1\0"   // 18 bytes — domain separation
    ‖ srv_eph_pub            // 65 bytes
    ‖ cli_eph_pub            // 65 bytes
    ‖ srv_timestamp          //  8 bytes LE
    ‖ cli_timestamp          //  8 bytes LE
    ‖ srv_random             // 16 bytes
    ‖ cli_random             // 16 bytes
)                            // total input = 196 bytes → SHA256 = 32 bytes
```

### 3.3 AUTH_REQUEST (encrypted payload, 80 bytes)

Outer payload (transmitted):
```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0       12    nonce        Random AES-GCM nonce (96-bit)
12      52    ciphertext   AES-256-GCM encrypted plaintext
64      16    tag          AES-GCM authentication tag
```

Inner plaintext (52 bytes, before encryption):
```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0       4     request_id       Unique per-session request ID (uint32 LE)
4       4     client_device_id Requesting device's unique ID (uint32 LE)
8       32    product_name     Null-terminated ASCII string
40      1     feature_flags    Requested FeatureFlags bitmask
41      8     timestamp        Client Unix time (uint64 LE) — anti-replay
49      3     padding          Zero bytes
```

### 3.4 AUTH_RESPONSE — Authorized (encrypted, 28 + plaintext bytes)

Outer payload:
```
Offset  Size         Field
──────  ────         ─────────────────────────────────────────────
0       12           nonce
12      pt_len       ciphertext
12+pt   16           tag
```

Inner plaintext for **authorized** response:
```
Offset  Size      Field
──────  ────      ─────────────────────────────────────────────────
0       4         request_id    Echo of AUTH_REQUEST request_id
4       1         status        0x00 = authorized
5       3         padding       Zero bytes
8       58        license       Serialized LicenseInfo (see §4)
66      1         sig_len       Length of following signature (≤ 72)
67      sig_len   signature     ECDSA-SHA256 over license token
```

Inner plaintext for **denied** response:
```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0       4     request_id    Echo of AUTH_REQUEST request_id
4       1     status        0x01 = denied
5       3     padding       Zero bytes
```

**License token signature** (server signs with device static private key):

```
lic_signed = SHA256(
    "secret_com_lic_v1\0"  // 18 bytes — domain separation
    ‖ serialized_license    // 58 bytes (see §4)
)                           // total input = 76 bytes → SHA256 = 32 bytes
```

---

## 4. LicenseInfo Serialization (58 bytes)

Fixed-layout, all integers little-endian, explicit padding bytes:

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0       1     type              LicenseType enum (uint8)
1       3     _pad              Zero bytes
4       4     device_id         uint32 LE
8       8     issue_timestamp   uint64 LE, Unix seconds
16      8     expiry_timestamp  uint64 LE; 0 = never expires
24      4     remaining_uses    uint32 LE
28      1     feature_flags     FeatureFlags bitmask
29      3     _pad2             Zero bytes
32      26    product_name      UTF-8 / ASCII, null-terminated
58              (end)
```

---

## 5. Session Key Derivation

After ECDH, both sides independently compute:

```
shared_secret = ECDH(local_eph_priv, remote_eph_pub)  // 32-byte P-256 X coord
salt          = cli_random ‖ srv_random                // 32 bytes

session_key   = HKDF-SHA256(
                    IKM  = shared_secret,
                    salt = salt,
                    info = "secret_com_session_key_v1",
                    L    = 32                           // AES-256
                )
```

All subsequent encryption uses `AES-256-GCM(session_key, random_nonce)`.

---

## 6. Full Exchange Sequence

```
Client                                    Server (ESC Device)
  │                                              │
  │── KEY_EXCHANGE_REQ ────────────────────────►│
  │   [cli_eph_pub | cli_ts | cli_random]        │
  │                                              │ gen srv_eph_key, srv_random
  │                                              │ sign(kex_data, device_priv)
  │◄─── KEY_EXCHANGE_RSP ──────────────────────│
  │   [srv_eph_pub | srv_ts | srv_random | sig]  │
  │                                              │
  │ verify sig with device_pub_key               │
  │ ECDH → shared_secret                         │ ECDH → shared_secret
  │ HKDF → session_key                           │ HKDF → session_key
  │                                              │
  │── AUTH_REQUEST (AES-GCM encrypted) ────────►│
  │   [nonce | Enc(request) | tag]               │
  │                                              │ decrypt
  │                                              │ call verify_callback()
  │                                              │ sign license token
  │◄── AUTH_RESPONSE (AES-GCM encrypted) ──────│
  │   [nonce | Enc(status+license+sig) | tag]    │
  │                                              │
  │ decrypt                                      │
  │ verify license signature                     │
  │ store license                                │
  │                                              │
  │── DISCONNECT ───────────────────────────────►│
```

---

## 7. Error Codes (kMsgError payload)

| Code | Meaning |
|------|---------|
| 0x01 | Protocol version mismatch |
| 0x02 | Invalid frame / CRC error |
| 0x03 | Key exchange failed |
| 0x04 | Decryption failed |
| 0x05 | Internal server error |
