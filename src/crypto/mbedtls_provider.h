// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// mbedtls_provider.h — mbedTLS 2.x / 3.x CryptoProvider implementation.

#ifndef SECRET_COM_SRC_CRYPTO_MBEDTLS_PROVIDER_H_
#define SECRET_COM_SRC_CRYPTO_MBEDTLS_PROVIDER_H_

#include "secret_com/crypto_provider.h"
#include "secret_com/types.h"

// Forward-declare mbedTLS context types to keep this header self-contained.
struct mbedtls_entropy_context;
struct mbedtls_ctr_drbg_context;

namespace secret_com {

/// @brief CryptoProvider implementation backed by mbedTLS 2.x / 3.x.
///
/// Supports both mbedTLS 2.16+ and 3.x via compile-time #ifdef guards.
/// Required mbedTLS configuration macros (mbedtls_config.h / config.h):
///   MBEDTLS_ECP_C, MBEDTLS_ECDH_C, MBEDTLS_ECDSA_C,
///   MBEDTLS_AES_C,  MBEDTLS_GCM_C,
///   MBEDTLS_SHA256_C, MBEDTLS_HKDF_C (or built-in fallback),
///   MBEDTLS_CTR_DRBG_C, MBEDTLS_ENTROPY_C,
///   MBEDTLS_ECP_DP_SECP256R1_ENABLED.
class MbedTlsCryptoProvider : public CryptoProvider {
 public:
  MbedTlsCryptoProvider();
  ~MbedTlsCryptoProvider() override;

  // Not copyable.
  MbedTlsCryptoProvider(const MbedTlsCryptoProvider&)            = delete;
  MbedTlsCryptoProvider& operator=(const MbedTlsCryptoProvider&) = delete;

  /// @brief Initialize entropy and DRBG.  Must be called before use.
  /// @return kOk or kCryptoError.
  Status Init();

  // ---- CryptoProvider overrides -------------------------------------------
  Status GenerateEcdhKeyPair(uint8_t public_key[kEcPublicKeySize],
                              uint8_t private_key[kEcPrivateKeySize]) override;

  Status ComputeEcdhSharedSecret(
      const uint8_t local_private_key[kEcPrivateKeySize],
      const uint8_t remote_public_key[kEcPublicKeySize],
      uint8_t       shared_secret[kEcPrivateKeySize]) override;

  Status DeriveSessionKey(const uint8_t shared_secret[kEcPrivateKeySize],
                           const uint8_t* salt, size_t salt_len,
                           uint8_t session_key[kAesKeySize]) override;

  Status EcdsaSign(const uint8_t  private_key[kEcPrivateKeySize],
                   const uint8_t* data, size_t data_len,
                   uint8_t        signature[kEcSignatureSize],
                   size_t*        sig_len) override;

  Status EcdsaVerify(const uint8_t  public_key[kEcPublicKeySize],
                     const uint8_t* data, size_t data_len,
                     const uint8_t* signature, size_t sig_len) override;

  Status AesGcmEncrypt(const uint8_t  key[kAesKeySize],
                        const uint8_t  nonce[kGcmNonceSize],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* plaintext, size_t plaintext_len,
                        uint8_t*       ciphertext,
                        uint8_t        tag[kGcmTagSize]) override;

  Status AesGcmDecrypt(const uint8_t  key[kAesKeySize],
                        const uint8_t  nonce[kGcmNonceSize],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* ciphertext, size_t ciphertext_len,
                        const uint8_t  tag[kGcmTagSize],
                        uint8_t*       plaintext) override;

  Status GenerateRandom(uint8_t* buffer, size_t length) override;

  void Sha256(const uint8_t* data, size_t data_len,
              uint8_t digest[kSha256Size]) override;

 private:
  mbedtls_entropy_context*   entropy_ = nullptr;
  mbedtls_ctr_drbg_context*  drbg_    = nullptr;
  bool                       ready_   = false;
};

}  // namespace secret_com

#endif  // SECRET_COM_SRC_CRYPTO_MBEDTLS_PROVIDER_H_
