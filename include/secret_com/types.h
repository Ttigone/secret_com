// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// types.h — Core types, status codes, and data structures.

#ifndef SECRET_COM_INCLUDE_SECRET_COM_TYPES_H_
#define SECRET_COM_INCLUDE_SECRET_COM_TYPES_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>

namespace secret_com {

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

/// @brief Return codes for all library operations.
enum class Status : int32_t {
  kOk             = 0,   ///< Operation succeeded.
  kPending        = 1,   ///< Operation is still in progress.
  kTimeout        = 2,   ///< Operation timed out waiting for a response.
  kAuthDenied     = 3,   ///< Authorization was explicitly denied by the device.
  kAuthFailed     = 4,   ///< Authorization failed (bad signature or protocol).
  kCryptoError    = 5,   ///< A cryptographic operation failed.
  kTransportError = 6,   ///< An I/O transport error occurred.
  kInvalidParam   = 7,   ///< A required parameter was NULL or out-of-range.
  kNotInitialized = 8,   ///< Initialize() has not been called yet.
  kAlreadyBusy    = 9,   ///< A request is already in flight.
  kLicenseExpired = 10,  ///< The stored license has expired.
  kProtocolError  = 11,  ///< Unexpected or malformed protocol message received.
  kBufferTooSmall = 12,  ///< The caller-supplied buffer is too small.
};

/// @brief Convert a Status code to a human-readable C string.
const char* StatusToString(Status status);

// ---------------------------------------------------------------------------
// License types and feature flags
// ---------------------------------------------------------------------------

/// @brief How the license expiration is determined.
enum class LicenseType : uint8_t {
  kPermanent    = 0x00,  ///< License never expires.
  kTimeLimited  = 0x01,  ///< License expires at a wall-clock time.
  kUsageLimited = 0x02,  ///< License expires after N activations.
  kTrial        = 0x03,  ///< Trial license, limited features + time.
};

/// @brief Bit-flags for optional product features.
enum FeatureFlags : uint8_t {
  kFeatureNone     = 0x00,
  kFeatureBasic    = 0x01,  ///< Core functionality.
  kFeatureAdvanced = 0x02,  ///< Extended algorithms / parameter sets.
  kFeaturePremium  = 0x04,  ///< Full premium unlock.
  kFeatureAll      = 0xFF,  ///< All features enabled.
};

// ---------------------------------------------------------------------------
// Core data structures
// ---------------------------------------------------------------------------

/// @brief License information granted after a successful authorization.
///
/// The structure is designed to be serialised to a flat byte array for
/// signing; do NOT rearrange fields or add padding.
struct LicenseInfo {
  LicenseType type;               ///< Expiration policy.
  uint8_t     _pad[3];            ///< Explicit padding — keep layout stable.
  uint32_t    device_id;          ///< Unique identifier of the ESC device.
  uint64_t    issue_timestamp;    ///< Unix seconds when the license was issued.
  uint64_t    expiry_timestamp;   ///< Unix seconds until expiry; 0 = never.
  uint32_t    remaining_uses;     ///< For kUsageLimited; ignored otherwise.
  uint8_t     feature_flags;      ///< Bitmask of FeatureFlags.
  uint8_t     _pad2[3];           ///< Explicit padding.
  char        product_name[32];   ///< Null-terminated product identifier.

  LicenseInfo() { memset(this, 0, sizeof(*this)); }

  /// @brief Return true if the license is currently valid.
  /// @param now_sec  Current UTC time as Unix seconds.
  bool IsValid(uint64_t now_sec) const {
    switch (type) {
      case LicenseType::kTimeLimited:
        return expiry_timestamp > 0 && now_sec < expiry_timestamp;
      case LicenseType::kUsageLimited:
        return remaining_uses > 0;
      default:
        return true;  // kPermanent / kTrial (time-check is caller's job).
    }
  }
};

/// @brief Parameters sent by the client when requesting authorization.
struct AuthRequest {
  uint32_t client_device_id;   ///< Unique ID of the requesting device.
  char     product_name[32];   ///< Product to authorize (null-terminated).
  uint8_t  feature_flags;      ///< Requested FeatureFlags bitmask.

  AuthRequest() { memset(this, 0, sizeof(*this)); }
};

// ---------------------------------------------------------------------------
// Callback type
// ---------------------------------------------------------------------------

/// @brief Callback invoked when RequestAuthorization() completes.
///
/// Invoked on the library's internal thread — do not call any blocking
/// AuthClient methods from inside the callback.
///
/// @param status   kOk on success; other values indicate the failure reason.
/// @param license  Valid only when status == kOk.
using AuthCallback =
    std::function<void(Status status, const LicenseInfo& license)>;

// ---------------------------------------------------------------------------
// Cryptographic size constants  (NIST P-256 / AES-256-GCM)
// ---------------------------------------------------------------------------

constexpr size_t kEcPublicKeySize  = 65;  ///< Uncompressed: 0x04 ‖ X ‖ Y.
constexpr size_t kEcPrivateKeySize = 32;  ///< Raw 256-bit scalar.
constexpr size_t kEcSignatureSize  = 72;  ///< Maximum DER-encoded ECDSA sig.
constexpr size_t kAesKeySize       = 32;  ///< AES-256 key.
constexpr size_t kGcmNonceSize     = 12;  ///< AES-GCM 96-bit nonce.
constexpr size_t kGcmTagSize       = 16;  ///< AES-GCM authentication tag.
constexpr size_t kSha256Size       = 32;  ///< SHA-256 digest.
constexpr size_t kRandomSize       = 16;  ///< Per-session random nonce.
constexpr size_t kMaxPayloadSize   = 512; ///< Maximum protocol payload.

// ---------------------------------------------------------------------------
// Crypto configuration
// ---------------------------------------------------------------------------

/// @brief Cryptographic identity used by both client and server.
///
/// - Client fills only device_public_key (the ESC's static public key).
/// - Server fills both keys (its own static key-pair).
struct CryptoConfig {
  uint8_t device_public_key[kEcPublicKeySize];    ///< Device static pub key.
  uint8_t device_private_key[kEcPrivateKeySize];  ///< Device static priv key (server only).
  bool    is_server;                              ///< True on the ESC side.

  CryptoConfig() { memset(this, 0, sizeof(*this)); }
};

}  // namespace secret_com

#endif  // SECRET_COM_INCLUDE_SECRET_COM_TYPES_H_
