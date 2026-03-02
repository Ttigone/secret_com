# secret_com — API Reference

> Version 1.0 · March 2026

---

## C++ API

### Namespace `secret_com`

---

#### `enum class Status`

```cpp
enum class Status : int32_t {
  kOk             = 0,
  kPending        = 1,
  kTimeout        = 2,
  kAuthDenied     = 3,   // Server explicitly denied the request.
  kAuthFailed     = 4,   // Signature verification failed.
  kCryptoError    = 5,
  kTransportError = 6,
  kInvalidParam   = 7,
  kNotInitialized = 8,
  kAlreadyBusy    = 9,
  kLicenseExpired = 10,
  kProtocolError  = 11,
  kBufferTooSmall = 12,
};

const char* StatusToString(Status status);
```

---

#### `struct LicenseInfo`

```cpp
struct LicenseInfo {
  LicenseType type;               // kPermanent / kTimeLimited / kUsageLimited / kTrial
  uint32_t    device_id;
  uint64_t    issue_timestamp;    // Unix seconds
  uint64_t    expiry_timestamp;   // Unix seconds; 0 = permanent
  uint32_t    remaining_uses;
  uint8_t     feature_flags;      // FeatureFlags bitmask
  char        product_name[32];

  bool IsValid(uint64_t now_sec) const;
};
```

---

#### `struct AuthRequest`

```cpp
struct AuthRequest {
  uint32_t client_device_id;
  char     product_name[32];
  uint8_t  feature_flags;
};
```

---

#### `class AuthClient`

##### `Status Initialize(unique_ptr<Transport>, const CryptoConfig&, unique_ptr<CryptoProvider> = nullptr)`

Initialize the client.  Must be called before any other method.  
`config.device_public_key` must contain the ESC's 65-byte static public key.  
`crypto` is optional; if `nullptr`, the built-in mbedTLS provider is used.

##### `Status RequestAuthorization(const AuthRequest&, AuthCallback, uint32_t timeout_ms = 10000)`

Start the asynchronous authorization exchange.  Returns `kOk` immediately if the request was accepted; the callback is invoked on a background thread.

| Return value | Meaning |
|---|---|
| `kOk` | Request accepted; callback will be invoked. |
| `kNotInitialized` | `Initialize()` has not been called. |
| `kAlreadyBusy` | A request is already in flight. |
| `kInvalidParam` | `callback` is null. |

**Callback signature**:
```cpp
void callback(Status status, const LicenseInfo& license);
```
`license` is valid only when `status == kOk`.

##### `bool IsAuthorized() const`

Thread-safe.  Returns `true` if the last exchange succeeded and the license `IsValid(now)`.

##### `LicenseInfo GetLicenseInfo() const`

Thread-safe.  Returns the license from the most recent successful exchange, or a zero-initialized `LicenseInfo` if not authorized.

##### `void Shutdown()`

Stop the background thread and disconnect the transport.  Blocks until the thread exits.

---

#### `class AuthServer`

##### `Status Initialize(unique_ptr<Transport>, const CryptoConfig&, unique_ptr<CryptoProvider> = nullptr)`

Initialize the server.  `config.is_server` must be `true`.  Both `device_public_key` and `device_private_key` must be non-zero.

##### `void SetAuthVerifyCallback(AuthVerifyCallback)`

Register the decision callback.  Must be called before `HandleOneRequest()`.

```cpp
using AuthVerifyCallback =
    function<bool(const AuthRequest& req, LicenseInfo* out_lic)>;
```

Return `true` to grant; fill in `*out_lic`.  Return `false` to deny.

##### `Status HandleOneRequest(uint32_t timeout_ms = 30000)`

Perform one complete key-exchange + authorization exchange synchronously.  Blocks until done or timeout.

##### `Status StartListening()`

Launch a background thread that calls `HandleOneRequest()` in a loop.

##### `void Shutdown()`

Stop the listener thread and disconnect.

---

#### `class Transport` (abstract)

```cpp
virtual Status Connect()   = 0;
virtual void   Disconnect() = 0;
virtual bool   IsConnected() const = 0;
virtual Status Send(const uint8_t* data, size_t length) = 0;
virtual Status Receive(uint8_t* buffer, size_t max_length,
                        size_t* bytes_read, uint32_t timeout_ms) = 0;
```

---

#### `class SerialTransport : public Transport`

```cpp
SerialTransport(std::string port_name, uint32_t baud_rate);
```

Port name: `/dev/ttyUSB0` (Linux), `\\\\.\\COM3` (Windows).

---

#### `class TcpTransport : public Transport`

```cpp
TcpTransport(std::string host, uint16_t port);
```

---

#### `class CallbackTransport : public Transport`

```cpp
struct Callbacks {
  function<bool()>                                    connect;
  function<void()>                                    disconnect;
  function<bool()>                                    is_connected;
  function<int(const uint8_t* data, size_t len)>      send;
  function<int(uint8_t* buf, size_t len, uint32_t ms)> receive;
};
explicit CallbackTransport(const Callbacks&);
```

---

#### `class CryptoProvider` (abstract)

See `include/secret_com/crypto_provider.h` for the full interface.  
Factory: `std::unique_ptr<CryptoProvider> CreateMbedTlsCryptoProvider()`.

---

## C API (`secret_com.h`)

### Types

```c
typedef enum SecretComStatus { kSecretComOk=0, ... } SecretComStatus;
typedef struct SecretComLicenseInfo { ... } SecretComLicenseInfo;
typedef struct SecretComAuthRequest { ... } SecretComAuthRequest;
typedef struct SecretComIoCbs { ... } SecretComIoCbs;
```

### Client functions

```c
SecretComClient* SecretComClientCreate(void);
void             SecretComClientDestroy(SecretComClient*);
SecretComStatus  SecretComClientInit(SecretComClient*, const SecretComIoCbs*,
                                      const uint8_t device_pub[65]);
SecretComStatus  SecretComClientRequestAuth(SecretComClient*,
                                             const SecretComAuthRequest*,
                                             SecretComAuthCallback cb,
                                             void* user_data,
                                             uint32_t timeout_ms);
int              SecretComClientIsAuthorized(const SecretComClient*);
SecretComStatus  SecretComClientGetLicense(const SecretComClient*,
                                            SecretComLicenseInfo* out);
void             SecretComClientShutdown(SecretComClient*);
```

### Server functions

```c
SecretComServer* SecretComServerCreate(void);
void             SecretComServerDestroy(SecretComServer*);
SecretComStatus  SecretComServerInit(SecretComServer*, const SecretComIoCbs*,
                                      const uint8_t pub[65],
                                      const uint8_t priv[32]);
void             SecretComServerSetVerifyCb(SecretComServer*,
                                             SecretComVerifyCb, void*);
SecretComStatus  SecretComServerHandleOne(SecretComServer*, uint32_t ms);
SecretComStatus  SecretComServerStartListening(SecretComServer*);
void             SecretComServerShutdown(SecretComServer*);
```

### Callbacks

```c
// Authorization result callback (client).
typedef void (*SecretComAuthCallback)(SecretComStatus,
                                       const SecretComLicenseInfo*,
                                       void* user_data);

// Authorization decision callback (server).
// Return 1 = grant, 0 = deny.
typedef int (*SecretComVerifyCb)(const SecretComAuthRequest*,
                                  SecretComLicenseInfo* out,
                                  void* user_data);
```

### Utility

```c
const char* SecretComStatusString(SecretComStatus);
```
