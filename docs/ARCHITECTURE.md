# secret_com — Architecture Overview

> Version 1.0 · March 2026

## 1. Design Goals

| Goal | Decision |
|------|----------|
| Cross-platform | C++14, no OS-specific code in the core; platform details isolated to transport layer |
| Embedded-friendly | No heap allocation in the hot path (protocol layer uses stack buffers); C API wrapper for bare-metal |
| Replay-safe | Per-session ephemeral ECDH keys; random nonces; timestamp anti-replay |
| Sniff-resistant | All authorization data encrypted with AES-256-GCM after ECDH key exchange |
| Forgery-resistant | License tokens signed by the device's static ECDSA private key |
| Maintainable | Google C++ Style; layered architecture; unit-testable components |

---

## 2. Layer Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Application / Visualization                      │
│              (C++ API)  AuthClient / AuthServer                      │
│              (C API)    secret_com.h extern "C" shim                 │
├─────────────────────────────────────────────────────────────────────┤
│                        Authorization Logic                           │
│          src/auth_client.cc        src/auth_server.cc               │
│      State machine · Challenge/Response · Callback dispatch          │
├───────────────────────────┬─────────────────────────────────────────┤
│     Protocol Layer        │         Crypto Layer                    │
│  src/protocol/            │    src/crypto/                          │
│  · message_framer.cc      │    · mbedtls_provider.cc                │
│    CRC16 framing          │      ECDH key exchange                  │
│    stream parser          │      ECDSA sign / verify                │
│    blocking send/recv     │      AES-256-GCM encrypt/decrypt        │
│                           │      HKDF-SHA256 key derivation         │
├───────────────────────────┴─────────────────────────────────────────┤
│                        Transport Layer                               │
│   include/secret_com/transport.h  (abstract interface)              │
│   src/transport/serial_transport.cc   — POSIX / Win32 UART          │
│   src/transport/tcp_transport.cc      — POSIX / Winsock TCP         │
│   CallbackTransport (in transport.h)  — user-supplied I/O callbacks │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Descriptions

### 3.1 Transport Layer (`include/secret_com/transport.h`)

Abstract base class `Transport` with four virtual methods:
`Connect()`, `Disconnect()`, `IsConnected()`, `Send()`, `Receive()`.

Concrete implementations:

| Class | File | Notes |
|-------|------|-------|
| `SerialTransport` | `src/transport/serial_transport.cc` | termios (Linux/macOS) + Win32 COMPORT |
| `TcpTransport`    | `src/transport/tcp_transport.cc` | BSD sockets + Winsock |
| `CallbackTransport` | `include/secret_com/transport.h` | User-supplied function objects; ideal for FreeRTOS / bare-metal |

### 3.2 Protocol Layer (`src/protocol/`)

**`protocol.h`** — Wire-format constants, payload size bounds, domain-separation strings, serialization helpers for `LicenseInfo`.

**`message_framer.h/.cc`** — Two responsibilities:
1. `MessageFramer` class: incremental byte-stream parser (state machine) that emits complete, CRC16-CCITT validated frames via a callback.
2. `SendFrame()` / `RecvFrame()` free functions: blocking helpers for the auth state machines.

Frame wire format:
```
[0xAA][0x55][TYPE:1][SEQ:2 LE][LEN:2 LE][PAYLOAD:N][CRC16:2 LE]
```

### 3.3 Crypto Layer (`src/crypto/`)

**`mbedtls_provider.cc`** implements `CryptoProvider` using mbedTLS 2.x/3.x:

| Operation | Algorithm | Purpose |
|-----------|-----------|---------|
| Key exchange | ECDH P-256 | Derive ephemeral shared secret |
| Key derivation | HKDF-SHA256 | Shared secret → AES session key |
| Signing | ECDSA P-256 | Authenticate key exchange + license tokens |
| Encryption | AES-256-GCM | Encrypt all auth data; provides AEAD |
| Hashing | SHA-256 | Pre-hash for ECDSA; sign/verify coverage |
| RNG | CTR-DRBG | Ephemeral keys, nonces, randoms |

Custom backends (wolfSSL, PSA, HSM) can be substituted by implementing `CryptoProvider`.

### 3.4 Authorization Logic (`src/auth_client.cc`, `src/auth_server.cc`)

Both use internal state machines (`enum class State`) and run the auth flow on a dedicated `std::thread`.  Public methods are thread-safe via `std::mutex` + `std::atomic<State>`.

---

## 4. Security Properties

| Threat | Mitigation |
|--------|-----------|
| Passive serial sniffing | All auth payloads encrypted with ephemeral AES-256-GCM session key |
| Active MITM | Server's ECDH ephemeral key is ECDSA-signed with the device's static private key; client verifies before trusting |
| Replay attack | Per-session random nonces + timestamps; each session uses a fresh ECDH key pair |
| License forgery | License tokens are ECDSA-signed with the device's private key; client verifies before accepting |
| Private key extraction | Private key lives only on the ESC device (server); clients never see it |
| Brute-force | P-256 provides ~128-bit security; AES-256-GCM provides 256-bit |

---

## 5. Key-Pair Lifecycle

```
Manufacturing:
  1. Generate P-256 key pair for the ESC device model (or per-device).
  2. Burn private key into secure flash / OTP (write-once, read-protected).
  3. Distribute the public key to the client library (compile-time constant
     or signed certificate chain for multi-model support).

Field Operation:
  1. Client embeds device_public_key at build time.
  2. ESC loads device_private_key from secure storage at boot.
  3. Each authorization session uses fresh ephemeral keys → forward secrecy.

Key Rotation:
  1. Issue a new key pair; distribute new public key in a firmware update.
  2. Old licenses remain verifiable with the old public key (keep a chain).
```

---

## 6. Threading Model

```
Application thread          auth_thread_ (per client/server)
─────────────────           ───────────────────────────────
RequestAuthorization()  ──► RunAuthFlow()
  returns kOk               ├── PerformKeyExchange()
  (non-blocking)            ├── SendAuthRequest()
                            ├── ReceiveAuthResponse()
IsAuthorized()  ◄── mutex   └── invoke AuthCallback
GetLicenseInfo() ◄── mutex
```

The application may call `IsAuthorized()` / `GetLicenseInfo()` concurrently; they are protected by `mutex_`.  The callback is invoked on `auth_thread_` — do not call `RequestAuthorization()` again from inside the callback.

---

## 7. Adding a New Transport

1. Derive a class from `Transport`.
2. Implement the five virtual methods.
3. Optionally add a source file under `src/transport/`.
4. No changes needed to the auth or crypto layers.

```cpp
class MyBleTransport : public secret_com::Transport {
 public:
  secret_com::Status Connect() override { /* BLE connect */ }
  void Disconnect() override { /* BLE disconnect */ }
  bool IsConnected() const override { return ble_is_connected(); }
  secret_com::Status Send(const uint8_t* d, size_t n) override { /* write */ }
  secret_com::Status Receive(uint8_t* b, size_t n, size_t* r,
                              uint32_t t) override { /* read */ }
};
```
