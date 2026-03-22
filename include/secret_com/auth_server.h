// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// auth_server.h — Authorization server (typically runs on RK3506 side).

#ifndef SECRET_COM_INCLUDE_SECRET_COM_AUTH_SERVER_H_
#define SECRET_COM_INCLUDE_SECRET_COM_AUTH_SERVER_H_

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#include "secret_com/crypto_provider.h"
#include "secret_com/transport.h"
#include "secret_com/types.h"

namespace secret_com {

// ---------------------------------------------------------------------------
// Authorization-verification callback
// ---------------------------------------------------------------------------

/// @brief Callback the application registers to decide whether to grant auth.
///
/// Called on the server's internal thread for every incoming auth request.
/// The application inspects @p request and, if approved, fills in @p license
/// and returns true.  Returning false sends a "denied" response.
///
/// @param request  Deserialized request from the client.
/// @param license  Caller should populate this when returning true.
/// @return true = authorize; false = deny.
using AuthVerifyCallback =
    std::function<bool(const AuthRequest& request, LicenseInfo* license)>;

// ---------------------------------------------------------------------------
// AuthServer
// ---------------------------------------------------------------------------

/// @brief Server-side authorization engine.
///
/// Typical usage (on RK3506 authorization host):
/// @code
///   CryptoConfig cfg;
///   cfg.is_server = true;
///   memcpy(cfg.device_public_key,  kMyPublicKey,  kEcPublicKeySize);
///   memcpy(cfg.device_private_key, kMyPrivateKey, kEcPrivateKeySize);
///
///   auto transport = std::make_unique<SerialTransport>("COM3", 115200);
///
///   AuthServer server;
///   server.Initialize(std::move(transport), cfg);
///   server.SetAuthVerifyCallback([](const AuthRequest& req, LicenseInfo* lic){
///       if (IsValidCustomer(req.client_device_id)) {
///           lic->type          = LicenseType::kPermanent;
///           lic->device_id     = req.client_device_id;
///           lic->feature_flags = kFeatureAll;
///           strncpy(lic->product_name, req.product_name, 32);
///           lic->issue_timestamp = time(nullptr);
///           return true;
///       }
///       return false;
///   });
///   server.StartListening();  // Non-blocking background loop.
/// @endcode
class AuthServer {
 public:
  AuthServer();
  ~AuthServer();

  // Not copyable or movable.
  AuthServer(const AuthServer&) = delete;
  AuthServer& operator=(const AuthServer&) = delete;

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /// @brief Initialize the server with a transport and full device key-pair.
  ///
  /// @p config.is_server must be true; both public and private keys are
  /// required.  Returns kInvalidParam if either key is all-zeros.
  Status Initialize(std::unique_ptr<Transport>      transport,
                    const CryptoConfig&              config,
                    std::unique_ptr<CryptoProvider>  crypto = nullptr);

  /// @brief Register the callback that decides whether to grant authorization.
  ///
  /// Must be called before HandleOneRequest() or StartListening().
  void SetAuthVerifyCallback(AuthVerifyCallback callback);

  // -------------------------------------------------------------------------
  // Request handling
  // -------------------------------------------------------------------------

  /// @brief Perform one complete authorization exchange synchronously.
  ///
  /// Blocks until the full handshake completes, the client disconnects, or
  /// @p timeout_ms elapses.
  ///
  /// @return kOk, kTimeout, kTransportError, kProtocolError, etc.
  Status HandleOneRequest(uint32_t timeout_ms = 30000);

  /// @brief Start accepting requests in a background thread.
  ///
  /// The thread calls HandleOneRequest() in a loop.  Use Shutdown() to stop.
  Status StartListening();

  /// @brief Stop the background listener thread and release resources.
  void Shutdown();

 private:
  enum class State : int {
    kUninitialized,
    kIdle,
    kKeyExchange,
    kVerifying,
    kDone,
    kError,
  };

  // ---- Internal helpers ---------------------------------------------------
  Status PerformKeyExchange(uint32_t timeout_ms);
  Status ProcessAuthRequest(uint32_t timeout_ms);
  Status SendFrame(uint8_t msg_type, uint16_t seq,
                   const uint8_t* payload, uint16_t payload_len);
  Status RecvFrame(uint8_t expected_type, uint16_t expected_seq,
                   uint8_t* payload_buf, uint16_t* payload_len,
                   uint32_t timeout_ms);
  void   ListenLoop();

  // ---- Members ------------------------------------------------------------
  mutable std::mutex  mutex_;
  std::atomic<State>  state_{State::kUninitialized};

  std::unique_ptr<Transport>      transport_;
  std::unique_ptr<CryptoProvider> crypto_;
  CryptoConfig                    crypto_config_;
  AuthVerifyCallback              verify_callback_;

  std::thread  listen_thread_;
  bool         stop_requested_ = false;

  // Ephemeral session state.
  uint8_t  session_key_[kAesKeySize];
  uint8_t  local_eph_pub_[kEcPublicKeySize];
  uint8_t  local_eph_priv_[kEcPrivateKeySize];
  uint8_t  client_random_[kRandomSize];
  uint8_t  server_random_[kRandomSize];
  uint16_t send_seq_ = 0;
};

}  // namespace secret_com

#endif  // SECRET_COM_INCLUDE_SECRET_COM_AUTH_SERVER_H_
