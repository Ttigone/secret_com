// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

#include "src/crypto/mbedtls_provider.h"

#include <cstring>
#include <memory>

// mbedTLS headers (must be installed / present as a submodule).
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/version.h"

namespace secret_com {

// ---------------------------------------------------------------------------
// Internal HKDF fallback for mbedTLS < 2.16 (no MBEDTLS_HKDF_C)
// ---------------------------------------------------------------------------

#ifndef MBEDTLS_HKDF_C
static int HkdfSha256Fallback(const uint8_t* salt, size_t salt_len,
                               const uint8_t* ikm, size_t ikm_len,
                               const uint8_t* info, size_t info_len,
                               uint8_t* okm, size_t okm_len) {
  const mbedtls_md_info_t* md =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) return -1;

  // Extract
  uint8_t prk[32];
  if (mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk) != 0)
    return -1;

  // Expand
  const size_t hash_len = 32;
  uint8_t T[32]  = {0};
  uint8_t buf[32 + 256 + 1];
  size_t  T_len  = 0;
  size_t  out_pos = 0;

  for (uint8_t i = 1; out_pos < okm_len; ++i) {
    memcpy(buf,          T,    T_len);
    memcpy(buf + T_len,  info, info_len);
    buf[T_len + info_len] = i;
    if (mbedtls_md_hmac(md, prk, hash_len, buf, T_len + info_len + 1, T) != 0)
      return -1;
    T_len = hash_len;

    size_t copy = (okm_len - out_pos < hash_len) ? (okm_len - out_pos)
                                                  : hash_len;
    memcpy(okm + out_pos, T, copy);
    out_pos += copy;
  }
  return 0;
}
#endif  // !MBEDTLS_HKDF_C

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

MbedTlsCryptoProvider::MbedTlsCryptoProvider()
    : entropy_(new mbedtls_entropy_context),
      drbg_(new mbedtls_ctr_drbg_context) {
  mbedtls_entropy_init(entropy_);
  mbedtls_ctr_drbg_init(drbg_);
}

MbedTlsCryptoProvider::~MbedTlsCryptoProvider() {
  if (drbg_) {
    mbedtls_ctr_drbg_free(drbg_);
    delete drbg_;
  }
  if (entropy_) {
    mbedtls_entropy_free(entropy_);
    delete entropy_;
  }
}

Status MbedTlsCryptoProvider::Init() {
  const char* personalization = "secret_com_v1";
  int ret = mbedtls_ctr_drbg_seed(drbg_, mbedtls_entropy_func, entropy_,
                                   reinterpret_cast<const unsigned char*>(
                                       personalization),
                                   strlen(personalization));
  if (ret != 0) return Status::kCryptoError;
  ready_ = true;
  return Status::kOk;
}

// ---------------------------------------------------------------------------
// GenerateEcdhKeyPair
// ---------------------------------------------------------------------------

Status MbedTlsCryptoProvider::GenerateEcdhKeyPair(
    uint8_t public_key[kEcPublicKeySize],
    uint8_t private_key[kEcPrivateKeySize]) {
  if (!ready_) return Status::kNotInitialized;

  mbedtls_ecp_group grp;
  mbedtls_mpi       d;
  mbedtls_ecp_point Q;

  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);

  Status result = Status::kCryptoError;

  do {
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) break;
    if (mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                 mbedtls_ctr_drbg_random, drbg_) != 0)
      break;

    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(&grp, &Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &olen, public_key,
                                        kEcPublicKeySize) != 0)
      break;

    if (mbedtls_mpi_write_binary(&d, private_key, kEcPrivateKeySize) != 0)
      break;

    result = Status::kOk;
  } while (false);

  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return result;
}

// ---------------------------------------------------------------------------
// ComputeEcdhSharedSecret
// ---------------------------------------------------------------------------

Status MbedTlsCryptoProvider::ComputeEcdhSharedSecret(
    const uint8_t local_private_key[kEcPrivateKeySize],
    const uint8_t remote_public_key[kEcPublicKeySize],
    uint8_t       shared_secret[kEcPrivateKeySize]) {
  if (!ready_) return Status::kNotInitialized;

  mbedtls_ecp_group grp;
  mbedtls_mpi       d, Z;
  mbedtls_ecp_point Q_remote;

  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&Z);
  mbedtls_ecp_point_init(&Q_remote);

  Status result = Status::kCryptoError;

  do {
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) break;

    if (mbedtls_mpi_read_binary(&d, local_private_key,
                                  kEcPrivateKeySize) != 0)
      break;

    if (mbedtls_ecp_point_read_binary(&grp, &Q_remote, remote_public_key,
                                        kEcPublicKeySize) != 0)
      break;

    if (mbedtls_ecdh_compute_shared(&grp, &Z, &Q_remote, &d,
                                     mbedtls_ctr_drbg_random, drbg_) != 0)
      break;

    if (mbedtls_mpi_write_binary(&Z, shared_secret,
                                   kEcPrivateKeySize) != 0)
      break;

    result = Status::kOk;
  } while (false);

  mbedtls_ecp_point_free(&Q_remote);
  mbedtls_mpi_free(&Z);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return result;
}

// ---------------------------------------------------------------------------
// DeriveSessionKey  (HKDF-SHA256)
// ---------------------------------------------------------------------------

Status MbedTlsCryptoProvider::DeriveSessionKey(
    const uint8_t shared_secret[kEcPrivateKeySize],
    const uint8_t* salt, size_t salt_len,
    uint8_t session_key[kAesKeySize]) {
  const uint8_t info[] = "secret_com_session_key_v1";
  const size_t  info_len = sizeof(info) - 1;

#ifdef MBEDTLS_HKDF_C
  const mbedtls_md_info_t* md =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  int ret = mbedtls_hkdf(md,
                          salt, salt_len,
                          shared_secret, kEcPrivateKeySize,
                          info, info_len,
                          session_key, kAesKeySize);
  return (ret == 0) ? Status::kOk : Status::kCryptoError;
#else
  int ret = HkdfSha256Fallback(salt, salt_len,
                                shared_secret, kEcPrivateKeySize,
                                info, info_len,
                                session_key, kAesKeySize);
  return (ret == 0) ? Status::kOk : Status::kCryptoError;
#endif
}

// ---------------------------------------------------------------------------
// EcdsaSign
// ---------------------------------------------------------------------------

Status MbedTlsCryptoProvider::EcdsaSign(
    const uint8_t  private_key[kEcPrivateKeySize],
    const uint8_t* data, size_t data_len,
    uint8_t        signature[kEcSignatureSize],
    size_t*        sig_len) {
  if (!ready_) return Status::kNotInitialized;

  // Hash the data with SHA-256 first.
  uint8_t hash[32];
  Sha256(data, data_len, hash);

  mbedtls_ecdsa_context ecdsa;
  mbedtls_ecdsa_init(&ecdsa);

  Status result = Status::kCryptoError;

  do {
    if (mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp),
                                MBEDTLS_ECP_DP_SECP256R1) != 0)
      break;
    if (mbedtls_mpi_read_binary(&ecdsa.MBEDTLS_PRIVATE(d), private_key,
                                  kEcPrivateKeySize) != 0)
      break;

#if MBEDTLS_VERSION_MAJOR >= 3
    int ret = mbedtls_ecdsa_write_signature(
        &ecdsa, MBEDTLS_MD_SHA256,
        hash, sizeof(hash),
        signature, kEcSignatureSize, sig_len,
        mbedtls_ctr_drbg_random, drbg_);
#else
    int ret = mbedtls_ecdsa_write_signature(
        &ecdsa, MBEDTLS_MD_SHA256,
        hash, sizeof(hash),
        signature, sig_len,
        mbedtls_ctr_drbg_random, drbg_);
#endif
    if (ret != 0) break;
    result = Status::kOk;
  } while (false);

  mbedtls_ecdsa_free(&ecdsa);
  return result;
}

// ---------------------------------------------------------------------------
// EcdsaVerify
// ---------------------------------------------------------------------------

Status MbedTlsCryptoProvider::EcdsaVerify(
    const uint8_t  public_key[kEcPublicKeySize],
    const uint8_t* data, size_t data_len,
    const uint8_t* signature, size_t sig_len) {
  if (!ready_) return Status::kNotInitialized;

  uint8_t hash[32];
  Sha256(data, data_len, hash);

  mbedtls_ecdsa_context ecdsa;
  mbedtls_ecdsa_init(&ecdsa);

  Status result = Status::kCryptoError;

  do {
    mbedtls_ecp_group* grp = &ecdsa.MBEDTLS_PRIVATE(grp);
    mbedtls_ecp_point* Q   = &ecdsa.MBEDTLS_PRIVATE(Q);

    if (mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1) != 0) break;
    if (mbedtls_ecp_point_read_binary(grp, Q, public_key,
                                        kEcPublicKeySize) != 0)
      break;

    int ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, sizeof(hash),
                                            signature, sig_len);
    if (ret != 0) {
      result = Status::kAuthFailed;
      break;
    }
    result = Status::kOk;
  } while (false);

  mbedtls_ecdsa_free(&ecdsa);
  return result;
}

// ---------------------------------------------------------------------------
// AesGcmEncrypt
// ---------------------------------------------------------------------------

Status MbedTlsCryptoProvider::AesGcmEncrypt(
    const uint8_t  key[kAesKeySize],
    const uint8_t  nonce[kGcmNonceSize],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t*       ciphertext,
    uint8_t        tag[kGcmTagSize]) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  Status result = Status::kCryptoError;
  do {
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                            key, kAesKeySize * 8) != 0)
      break;
    if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                   plaintext_len,
                                   nonce, kGcmNonceSize,
                                   aad, aad_len,
                                   plaintext, ciphertext,
                                   kGcmTagSize, tag) != 0)
      break;
    result = Status::kOk;
  } while (false);

  mbedtls_gcm_free(&gcm);
  return result;
}

// ---------------------------------------------------------------------------
// AesGcmDecrypt
// ---------------------------------------------------------------------------

Status MbedTlsCryptoProvider::AesGcmDecrypt(
    const uint8_t  key[kAesKeySize],
    const uint8_t  nonce[kGcmNonceSize],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t  tag[kGcmTagSize],
    uint8_t*       plaintext) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  Status result = Status::kCryptoError;
  do {
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                            key, kAesKeySize * 8) != 0)
      break;
    int ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len,
                                        nonce, kGcmNonceSize,
                                        aad, aad_len,
                                        tag, kGcmTagSize,
                                        ciphertext, plaintext);
    if (ret != 0) {
      result = Status::kCryptoError;  // Authentication tag mismatch.
      break;
    }
    result = Status::kOk;
  } while (false);

  mbedtls_gcm_free(&gcm);
  return result;
}

// ---------------------------------------------------------------------------
// GenerateRandom
// ---------------------------------------------------------------------------

Status MbedTlsCryptoProvider::GenerateRandom(uint8_t* buffer, size_t length) {
  if (!ready_) return Status::kNotInitialized;
  int ret = mbedtls_ctr_drbg_random(drbg_, buffer, length);
  return (ret == 0) ? Status::kOk : Status::kCryptoError;
}

// ---------------------------------------------------------------------------
// Sha256
// ---------------------------------------------------------------------------

void MbedTlsCryptoProvider::Sha256(const uint8_t* data, size_t data_len,
                                    uint8_t digest[kSha256Size]) {
#if MBEDTLS_VERSION_MAJOR >= 3
  mbedtls_sha256(data, data_len, digest, 0 /* is224 = false */);
#else
  mbedtls_sha256_ret(data, data_len, digest, 0);
#endif
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

std::unique_ptr<CryptoProvider> CreateMbedTlsCryptoProvider() {
  auto provider = std::make_unique<MbedTlsCryptoProvider>();
  if (provider->Init() != Status::kOk) return nullptr;
  return provider;
}

}  // namespace secret_com
