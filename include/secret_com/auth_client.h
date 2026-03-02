// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// auth_client.h — Authorization client (runs on the user-facing device).

#ifndef SECRET_COM_INCLUDE_SECRET_COM_AUTH_CLIENT_H_
#define SECRET_COM_INCLUDE_SECRET_COM_AUTH_CLIENT_H_

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

#include "secret_com/crypto_provider.h"
#include "secret_com/transport.h"
#include "secret_com/types.h"

namespace secret_com {

// ---------------------------------------------------------------------------
// AuthClient
// ---------------------------------------------------------------------------

/// @brief Client-side authorization engine.
///
/// Typical usage:
/// @code
///   // 1. Configure crypto (embed the ESC device's static public key).
///   CryptoConfig crypto_cfg;
///   memcpy(crypto_cfg.device_public_key, kEscPublicKey, kEcPublicKeySize);
///
///   // 2. Create a transport (e.g. serial port).
///   auto transport = std::make_unique<SerialTransport>("/dev/ttyUSB0", 115200);
///
///   // 3. Initialize and request authorization.
///   AuthClient client;
///   client.Initialize(std::move(transport), crypto_cfg);
///
///   AuthRequest req;
///   req.client_device_id = GetDeviceId();
///   strncpy(req.product_name, "MyESC", sizeof(req.product_name));
///   req.feature_flags = kFeatureAll;
///
///   client.RequestAuthorization(req, [](Status s, const LicenseInfo& lic) {
///     if (s == Status::kOk) { /* use product */ }
///   });
/// @endcode
///
/// Thread-safety: RequestAuthorization() may be called from any thread once.
/// IsAuthorized() and GetLicenseInfo() may be called concurrently.
class AuthClient {
 public:
  AuthClient();
  ~AuthClient();

  // Not copyable or movable.
  AuthClient(const AuthClient&) = delete;
  AuthClient& operator=(const AuthClient&) = delete;

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /// @brief Initialize the client with a transport and crypto configuration.
  ///
  /// Must be called before any other method.
  ///
  /// @param transport  Ownership is transferred.  Not yet connected here.
  /// @param config     Must contain the ESC device's static public key.
  /// @param crypto     Optional custom crypto backend; nullptr → mbedTLS.
  /// @return kOk or kInvalidParam.
  Status Initialize(std::unique_ptr<Transport> transport,
                    const CryptoConfig&         config,
                    std::unique_ptr<CryptoProvider> crypto = nullptr);

  /// @brief Shut down the client, stopping the background thread.
  ///
  /// Blocks until the thread exits.  Safe to call from any thread.
  void Shutdown();

  // -------------------------------------------------------------------------
  // Authorization
  // -------------------------------------------------------------------------

  /// @brief Begin an asynchronous authorization exchange.
  ///
  /// 1. Connects the transport.
  /// 2. Performs ECDH key exchange and verifies the device's identity.
  /// 3. Encrypts and sends the AuthRequest.
  /// 4. Decrypts the response and verifies the license token signature.
  /// 5. Invokes @p callback on the internal thread.
  ///
  /// @param request     What to authorize.
  /// @param callback    Invoked when the operation completes (success or error).
  /// @param timeout_ms  Total timeout in milliseconds (default: 10 s).
  /// @return kOk if the request was accepted; kAlreadyBusy / kNotInitialized
  ///         if the call was rejected without starting.
  Status RequestAuthorization(const AuthRequest& request,
                               AuthCallback       callback,
                               uint32_t           timeout_ms = 10000);

  // -------------------------------------------------------------------------
  // State queries (thread-safe)
  // -------------------------------------------------------------------------

  /// @brief True if the last authorization succeeded and the license is valid.
  bool IsAuthorized() const;

  /// @brief Return the license granted by the most recent successful auth.
  ///
  /// Returns a default-constructed LicenseInfo if not authorized.
  LicenseInfo GetLicenseInfo() const;

 private:
  // ---- Internal state machine --------------------------------------------
  enum class State : int {
    kUninitialized,
    kIdle,
    kConnecting,
    kKeyExchange,
    kAuthorizing,
    kAuthorized,
    kError,
  };

  // ---- Auth flow (runs on auth_thread_) -----------------------------------
  void  RunAuthFlow(AuthRequest req, AuthCallback callback, uint32_t timeout_ms);
  Status PerformKeyExchange(uint32_t deadline_ms);
  Status SendAuthRequest(const AuthRequest& req, uint32_t request_id,
                         uint32_t deadline_ms);
  Status ReceiveAuthResponse(uint32_t request_id, LicenseInfo* out,
                             uint32_t deadline_ms);

  // ---- Helpers ------------------------------------------------------------
  Status SendFrame(uint8_t msg_type, uint16_t seq,
                   const uint8_t* payload, uint16_t payload_len);
  Status RecvFrame(uint8_t expected_type, uint16_t expected_seq,
                   uint8_t* payload_buf, uint16_t* payload_len,
                   uint32_t timeout_ms);

  // ---- Members ------------------------------------------------------------
  mutable std::mutex  mutex_;
  std::atomic<State>  state_{State::kUninitialized};

  std::unique_ptr<Transport>      transport_;
  std::unique_ptr<CryptoProvider> crypto_;
  CryptoConfig                    crypto_config_;

  LicenseInfo license_info_;         // Protected by mutex_.
  std::thread auth_thread_;

  // Ephemeral session state (valid only during an active auth flow).
  uint8_t  session_key_[kAesKeySize];
  uint8_t  local_eph_pub_[kEcPublicKeySize];
  uint8_t  local_eph_priv_[kEcPrivateKeySize];
  uint8_t  client_random_[kRandomSize];
  uint16_t send_seq_ = 0;
};

}  // namespace secret_com

#endif  // SECRET_COM_INCLUDE_SECRET_COM_AUTH_CLIENT_H_
