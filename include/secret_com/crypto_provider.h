// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// crypto_provider.h — Abstract cryptographic operations interface.

#ifndef SECRET_COM_INCLUDE_SECRET_COM_CRYPTO_PROVIDER_H_
#define SECRET_COM_INCLUDE_SECRET_COM_CRYPTO_PROVIDER_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "secret_com/types.h"

namespace secret_com {

// ---------------------------------------------------------------------------
// Abstract crypto provider
// ---------------------------------------------------------------------------

/// @brief Pure-virtual interface for all cryptographic operations.
///
/// The default implementation is MbedTlsCryptoProvider (mbedTLS 2.x / 3.x).
/// You may substitute another backend — e.g. a hardware security module, a
/// platform-native crypto API, or wolfSSL — by deriving from this class.
///
/// All operations on NIST P-256 (secp256r1) and AES-256-GCM.
class CryptoProvider {
 public:
  virtual ~CryptoProvider() = default;

  // -------------------------------------------------------------------------
  // ECDH — Elliptic-Curve Diffie-Hellman (ephemeral key exchange)
  // -------------------------------------------------------------------------

  /// @brief Generate an ephemeral ECDH key pair.
  /// @param[out] public_key   65-byte uncompressed public point.
  /// @param[out] private_key  32-byte private scalar.
  /// @return kOk or kCryptoError.
  virtual Status GenerateEcdhKeyPair(
      uint8_t public_key[kEcPublicKeySize],
      uint8_t private_key[kEcPrivateKeySize]) = 0;

  /// @brief Compute the ECDH shared secret Z = local_priv * remote_pub.
  /// @param[in]  local_private_key  32-byte private scalar.
  /// @param[in]  remote_public_key  65-byte remote public point.
  /// @param[out] shared_secret      32-byte output.
  /// @return kOk or kCryptoError.
  virtual Status ComputeEcdhSharedSecret(
      const uint8_t local_private_key[kEcPrivateKeySize],
      const uint8_t remote_public_key[kEcPublicKeySize],
      uint8_t       shared_secret[kEcPrivateKeySize]) = 0;

  // -------------------------------------------------------------------------
  // Key derivation — HKDF-SHA256
  // -------------------------------------------------------------------------

  /// @brief Derive a session key from the ECDH shared secret.
  ///
  /// Uses HKDF-SHA256 (RFC 5869):
  ///   PRK = HMAC-SHA256(salt, shared_secret)
  ///   session_key = HKDF-Expand(PRK, "secret_com_session_key_v1", 32)
  ///
  /// @param[in]  shared_secret  32-byte ECDH output.
  /// @param[in]  salt           Concatenated client_random ‖ server_random.
  /// @param[in]  salt_len       Length of salt (typically 2 * kRandomSize).
  /// @param[out] session_key    32-byte derived AES-256 key.
  /// @return kOk or kCryptoError.
  virtual Status DeriveSessionKey(
      const uint8_t shared_secret[kEcPrivateKeySize],
      const uint8_t* salt, size_t salt_len,
      uint8_t session_key[kAesKeySize]) = 0;

  // -------------------------------------------------------------------------
  // ECDSA — signing and verification
  // -------------------------------------------------------------------------

  /// @brief Sign @p data with ECDSA (internally hashes with SHA-256).
  /// @param[in]  private_key  32-byte P-256 private key.
  /// @param[in]  data         Message to sign.
  /// @param[in]  data_len     Message length.
  /// @param[out] signature    DER-encoded signature buffer (kEcSignatureSize).
  /// @param[out] sig_len      Actual byte length written.
  /// @return kOk or kCryptoError.
  virtual Status EcdsaSign(const uint8_t  private_key[kEcPrivateKeySize],
                            const uint8_t* data, size_t data_len,
                            uint8_t        signature[kEcSignatureSize],
                            size_t*        sig_len) = 0;

  /// @brief Verify an ECDSA signature.
  /// @param[in]  public_key  65-byte P-256 public key.
  /// @param[in]  data        Signed message.
  /// @param[in]  data_len    Message length.
  /// @param[in]  signature   DER-encoded signature.
  /// @param[in]  sig_len     Signature length.
  /// @return kOk if valid; kAuthFailed if the signature does not match.
  virtual Status EcdsaVerify(const uint8_t  public_key[kEcPublicKeySize],
                              const uint8_t* data, size_t data_len,
                              const uint8_t* signature, size_t sig_len) = 0;

  // -------------------------------------------------------------------------
  // AES-256-GCM — authenticated encryption
  // -------------------------------------------------------------------------

  /// @brief Encrypt and authenticate a message with AES-256-GCM.
  /// @param[in]  key            32-byte AES key.
  /// @param[in]  nonce          12-byte GCM nonce (must be unique per key).
  /// @param[in]  aad            Additional authenticated data (may be NULL).
  /// @param[in]  aad_len        Length of AAD.
  /// @param[in]  plaintext      Input plaintext.
  /// @param[in]  plaintext_len  Length of plaintext.
  /// @param[out] ciphertext     Output buffer (same size as plaintext).
  /// @param[out] tag            16-byte authentication tag.
  /// @return kOk or kCryptoError.
  virtual Status AesGcmEncrypt(const uint8_t  key[kAesKeySize],
                                const uint8_t  nonce[kGcmNonceSize],
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* plaintext, size_t plaintext_len,
                                uint8_t*       ciphertext,
                                uint8_t        tag[kGcmTagSize]) = 0;

  /// @brief Decrypt and verify a message with AES-256-GCM.
  /// @param[in]  key             32-byte AES key.
  /// @param[in]  nonce           12-byte GCM nonce.
  /// @param[in]  aad             Additional authenticated data (may be NULL).
  /// @param[in]  aad_len         Length of AAD.
  /// @param[in]  ciphertext      Input ciphertext.
  /// @param[in]  ciphertext_len  Length of ciphertext.
  /// @param[in]  tag             16-byte authentication tag.
  /// @param[out] plaintext       Output buffer (same size as ciphertext).
  /// @return kOk on success; kCryptoError if authentication tag mismatches.
  virtual Status AesGcmDecrypt(const uint8_t  key[kAesKeySize],
                                const uint8_t  nonce[kGcmNonceSize],
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* ciphertext,
                                size_t         ciphertext_len,
                                const uint8_t  tag[kGcmTagSize],
                                uint8_t*       plaintext) = 0;

  // -------------------------------------------------------------------------
  // Utilities
  // -------------------------------------------------------------------------

  /// @brief Fill @p buffer with cryptographically secure random bytes.
  virtual Status GenerateRandom(uint8_t* buffer, size_t length) = 0;

  /// @brief Compute SHA-256 hash.
  virtual void Sha256(const uint8_t* data, size_t data_len,
                      uint8_t digest[kSha256Size]) = 0;
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// @brief Create the built-in mbedTLS-based crypto provider.
///
/// Requires mbedTLS 2.16+ or 3.x to be linked.
/// Returns nullptr if initialization fails.
std::unique_ptr<CryptoProvider> CreateMbedTlsCryptoProvider();

}  // namespace secret_com

#endif  // SECRET_COM_INCLUDE_SECRET_COM_CRYPTO_PROVIDER_H_
