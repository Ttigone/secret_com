// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// secret_com.h — C-compatible public API (extern "C" wrapper).
//
// Use this header on any platform that does not support C++11 or where a
// stable ABI is required.  It wraps the C++ AuthClient / AuthServer classes
// behind opaque handles and plain C function signatures.

#ifndef SECRET_COM_INCLUDE_SECRET_COM_SECRET_COM_H_
#define SECRET_COM_INCLUDE_SECRET_COM_SECRET_COM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Status codes (mirrors secret_com::Status)
// ---------------------------------------------------------------------------
typedef enum SecretComStatus {
  kSecretComOk             = 0,
  kSecretComPending        = 1,
  kSecretComTimeout        = 2,
  kSecretComAuthDenied     = 3,
  kSecretComAuthFailed     = 4,
  kSecretComCryptoError    = 5,
  kSecretComTransportError = 6,
  kSecretComInvalidParam   = 7,
  kSecretComNotInitialized = 8,
  kSecretComAlreadyBusy    = 9,
  kSecretComLicenseExpired = 10,
  kSecretComProtocolError  = 11,
} SecretComStatus;

// ---------------------------------------------------------------------------
// License info (mirrors secret_com::LicenseInfo)
// ---------------------------------------------------------------------------
typedef struct SecretComLicenseInfo {
  uint8_t  license_type;        /* 0=permanent,1=time,2=usage,3=trial */
  uint32_t device_id;
  uint64_t issue_timestamp;     /* Unix seconds */
  uint64_t expiry_timestamp;    /* Unix seconds; 0 = no expiry */
  uint32_t remaining_uses;
  uint8_t  feature_flags;
  char     product_name[32];
} SecretComLicenseInfo;

// ---------------------------------------------------------------------------
// Authorization request (mirrors secret_com::AuthRequest)
// ---------------------------------------------------------------------------
typedef struct SecretComAuthRequest {
  uint32_t client_device_id;
  char     product_name[32];
  uint8_t  feature_flags;
} SecretComAuthRequest;

// ---------------------------------------------------------------------------
// User-provided I/O callbacks (mirrors CallbackTransport::Callbacks)
// ---------------------------------------------------------------------------
typedef struct SecretComIoCbs {
  void* user_ctx;  /* Passed as first arg to every callback. */

  /** Open channel; return 1 on success, 0 on failure. */
  int (*connect)(void* ctx);
  /** Close channel. */
  void (*disconnect)(void* ctx);
  /** Return 1 if open, 0 if closed. */
  int (*is_connected)(void* ctx);
  /** Write len bytes; return bytes written or -1. */
  int (*send)(void* ctx, const uint8_t* data, size_t len);
  /** Read up to max_len bytes with timeout_ms; return bytes read, 0 on
      timeout, -1 on error. */
  int (*receive)(void* ctx, uint8_t* buf, size_t max_len, uint32_t timeout_ms);
} SecretComIoCbs;

// ---------------------------------------------------------------------------
// Client API
// ---------------------------------------------------------------------------

typedef struct SecretComClient_ SecretComClient;

/// @brief Allocate a new client handle.  Must be freed with
///        SecretComClientDestroy().
SecretComClient* SecretComClientCreate(void);

/// @brief Free a client handle.  Calls Shutdown() first if needed.
void SecretComClientDestroy(SecretComClient* client);

/// @brief Initialize the client.
///
/// @param client             Handle returned by SecretComClientCreate().
/// @param io                 User I/O callbacks for the transport layer.
/// @param device_public_key  65-byte ESC static ECDH public key.
/// @return SecretComStatus code.
SecretComStatus SecretComClientInit(SecretComClient*       client,
                                    const SecretComIoCbs*  io,
                                    const uint8_t          device_public_key[65]);

/// @brief Completion callback for SecretComClientRequestAuth().
///
/// @param status   Result of the authorization.
/// @param license  Valid only when status == kSecretComOk.
/// @param user_data  Pointer supplied to SecretComClientRequestAuth().
typedef void (*SecretComAuthCallback)(SecretComStatus              status,
                                      const SecretComLicenseInfo*  license,
                                      void*                        user_data);

/// @brief Begin asynchronous authorization (non-blocking).
///
/// @param client      Initialized client handle.
/// @param request     What to authorize.
/// @param callback    Invoked on completion.
/// @param user_data   Opaque pointer forwarded to @p callback.
/// @param timeout_ms  0 = use default (10 000 ms).
/// @return kSecretComOk if the request was enqueued.
SecretComStatus SecretComClientRequestAuth(
    SecretComClient*          client,
    const SecretComAuthRequest* request,
    SecretComAuthCallback       callback,
    void*                       user_data,
    uint32_t                    timeout_ms);

/// @brief Return 1 if the client is currently authorized, 0 otherwise.
int SecretComClientIsAuthorized(const SecretComClient* client);

/// @brief Copy the current license into @p out.  Returns kSecretComOk or
///        kSecretComAuthFailed if not authorized.
SecretComStatus SecretComClientGetLicense(const SecretComClient*  client,
                                          SecretComLicenseInfo*   out);

/// @brief Shut down the client (stops background thread, disconnects).
void SecretComClientShutdown(SecretComClient* client);

// ---------------------------------------------------------------------------
// Server API
// ---------------------------------------------------------------------------

typedef struct SecretComServer_ SecretComServer;

/// @brief Allocate a new server handle.
SecretComServer* SecretComServerCreate(void);

/// @brief Free a server handle.
void SecretComServerDestroy(SecretComServer* server);

/// @brief Initialize the server.
///
/// @param server              Handle returned by SecretComServerCreate().
/// @param io                  User I/O callbacks.
/// @param device_public_key   65-byte ESC static public key.
/// @param device_private_key  32-byte ESC static private key (secret!).
/// @return SecretComStatus code.
SecretComStatus SecretComServerInit(SecretComServer*      server,
                                    const SecretComIoCbs* io,
                                    const uint8_t device_public_key[65],
                                    const uint8_t device_private_key[32]);

/// @brief Authorization-decision callback for the server.
///
/// @param request    Incoming auth request.
/// @param out_lic    Application fills this when granting access.
/// @param user_data  Opaque pointer registered with
///                   SecretComServerSetVerifyCb().
/// @return 1 = authorize; 0 = deny.
typedef int (*SecretComVerifyCb)(const SecretComAuthRequest* request,
                                  SecretComLicenseInfo*       out_lic,
                                  void*                       user_data);

/// @brief Register the authorization-decision callback.
void SecretComServerSetVerifyCb(SecretComServer* server,
                                 SecretComVerifyCb cb,
                                 void*             user_data);

/// @brief Handle one authorization exchange synchronously (blocking).
SecretComStatus SecretComServerHandleOne(SecretComServer* server,
                                          uint32_t         timeout_ms);

/// @brief Start the background listener thread.
SecretComStatus SecretComServerStartListening(SecretComServer* server);

/// @brief Shut down the server.
void SecretComServerShutdown(SecretComServer* server);

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// @brief Human-readable string for a status code.
const char* SecretComStatusString(SecretComStatus status);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SECRET_COM_INCLUDE_SECRET_COM_SECRET_COM_H_
