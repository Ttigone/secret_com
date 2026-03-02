# secret_com

> A cross-platform C/C++ authorization library for embedded and desktop targets.  
> Cryptographic challenge-response over UART, TCP, BLE, or any custom transport.

---

## Overview

`secret_com` enables a device (client) to request authorization from a trusted hardware device (server, e.g. an ESC — Electronic Speed Controller).  All communication is protected by:

- **ECDH (P-256) key exchange** — session key derived on both ends; never transmitted
- **AES-256-GCM** — all authorization payloads encrypted and authenticated
- **ECDSA (P-256)** — server's identity and issued license tokens are signed; prevents forgery even if serial traffic is fully captured

---

## Features

| Feature | Details |
|---------|---------|
| Cryptography | mbedTLS 2.x / 3.x (ECDH, ECDSA, AES-256-GCM, HKDF-SHA256) |
| Transports | Serial (POSIX + Win32), TCP, Callback (bare-metal / RTOS) |
| API | Clean C++14 API; `extern "C"` wrapper for bare-metal / mixed C projects |
| Platforms | Linux, Windows, macOS, embedded Linux, FreeRTOS (via CallbackTransport) |
| Build | CMake 3.16+ with FetchContent for mbedTLS |
| Style | Google C++ Style Guide; `.clang-format` provided |

---

## Quick Start

### Build

```bash
git clone https://github.com/yourorg/secret_com.git
cd secret_com
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Run the demos

```bash
# Terminal 1 — Server (ESC device side)
./build/examples/server_demo /dev/ttyUSB0 115200

# Terminal 2 — Client (user device)
./build/examples/client_demo /dev/ttyUSB1 115200
```

---

## Directory Structure

```
secret_com/
├── include/secret_com/       Public API headers
│   ├── types.h               Status codes, LicenseInfo, AuthRequest
│   ├── transport.h           Abstract Transport + CallbackTransport
│   ├── crypto_provider.h     Abstract CryptoProvider interface
│   ├── auth_client.h         AuthClient class
│   ├── auth_server.h         AuthServer class
│   └── secret_com.h          C API (extern "C")
│
├── src/
│   ├── auth_client.cc        Client state machine implementation
│   ├── auth_server.cc        Server state machine implementation
│   ├── secret_com_c_api.cc   C shim over C++ classes
│   ├── protocol/
│   │   ├── protocol.h        Wire constants & serialization
│   │   ├── message_framer.h
│   │   └── message_framer.cc CRC16 framer + stream parser
│   ├── crypto/
│   │   ├── mbedtls_provider.h
│   │   └── mbedtls_provider.cc  ECDH/ECDSA/AES-GCM/HKDF
│   └── transport/
│       ├── serial_transport.h/.cc   POSIX + Win32 UART
│       └── tcp_transport.h/.cc      POSIX + Winsock TCP
│
├── examples/
│   ├── client_demo.cc
│   ├── server_demo.cc
│   └── c_api_demo.c
│
├── docs/
│   ├── ARCHITECTURE.md       Layered design, security properties
│   ├── PROTOCOL_SPEC.md      Wire format, message types, crypto derivation
│   ├── API_REFERENCE.md      Full function reference
│   └── INTEGRATION_GUIDE.md  Step-by-step for ESC and client developers
│
├── CMakeLists.txt
└── .clang-format             Google style preset
```

---

## Security Model (Summary)

```
Client (user device)                  Server (ESC device)
────────────────────                  ───────────────────
Embeds device_public_key          ←── holds device_private_key (secret)
at build time                         stored in OTP / secure flash

Per-session:
  client_eph_key + client_random  ──► verify with device_public_key
                                  ◄── srv_eph_key + srv_random + ECDSA sig
  shared_secret = ECDH(both)          shared_secret = ECDH(both)
  session_key  = HKDF(shared)         session_key  = HKDF(shared)
  ──────────── AES-256-GCM ──────────────────────────────────────
  send encrypted auth request     ──► decrypt, call verify_callback
                                  ◄── encrypt(license + ECDSA sig)
  verify license signature             sign with device_private_key
  store license
```

Captured serial bytes reveal nothing: the session key is derived via ECDH and never transmitted.

---

## Documentation

| Document | Contents |
|----------|---------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layer diagram, threading model, security properties |
| [PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md) | Wire format, byte layout, crypto derivation |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | All public classes and functions |
| [INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) | Key generation, ESC firmware integration, client setup |

---

## License

Apache 2.0 — see `LICENSE`.
