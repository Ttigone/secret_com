// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// auth_client.cc — Authorization client implementation.
//
// Protocol flow (executed on auth_thread_):
//
//   1. transport_->Connect()
//   2. KEY EXCHANGE
//      a. crypto_->GenerateEcdhKeyPair(local_eph_pub_, local_eph_priv_)
//      b. crypto_->GenerateRandom(client_random_)
//      c. Send KEY_EXCHANGE_REQ: [eph_pub(65) | ts(8) | random(16)]
//      d. Recv KEY_EXCHANGE_RSP: [srv_eph_pub(65) | ts(8) | random(16) |
//                                  sig_len(1) | sig(≤72)]
//      e. Verify ECDSA sig over SHA256(kKexDomain || srv_pub || cli_pub ||
//                                       srv_ts || cli_ts || srv_rnd || cli_rnd)
//         with device_public_key_  → prevents MITM / rogue device
//      f. ECDH: shared_secret = local_eph_priv_ * srv_eph_pub
//      g. HKDF: session_key_ = HKDF-SHA256(shared_secret,
//                                           client_random_ || server_random_)
//   3. AUTH REQUEST (all encrypted with AES-256-GCM(session_key_))
//      a. Build plaintext: [req_id(4) | dev_id(4) | product(32) | flags(1) |
//                           ts(8) | pad(3)]
//      b. Encrypt: nonce = random(12); ciphertext + tag
//      c. Send AUTH_REQUEST: [nonce(12) | ciphertext | tag(16)]
//   4. AUTH RESPONSE (encrypted)
//      a. Recv and decrypt
//      b. Parse: [req_id(4) | status(1) | pad(3) | license(58) | sig_len(1) |
//                 sig(≤72)]
//      c. Verify license token signature with device_public_key_
//   5. Invoke callback, zero out ephemeral secrets.

#include "secret_com/auth_client.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <memory>

#include "src/crypto/mbedtls_provider.h"
#include "src/protocol/message_framer.h"
#include "src/protocol/protocol.h"

namespace secret_com {

using protocol::MsgType;
using protocol::kKeyExchangeReqLen;

// ---------------------------------------------------------------------------
// Helpers — little-endian encode / decode
// ---------------------------------------------------------------------------

static void WriteU32Le(uint8_t* out, uint32_t v) {
  out[0] = static_cast<uint8_t>(v & 0xFF);
  out[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  out[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
  out[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

static void WriteU64Le(uint8_t* out, uint64_t v) {
  for (int i = 0; i < 8; ++i)
    out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

static uint32_t ReadU32Le(const uint8_t* in) {
  return static_cast<uint32_t>(in[0])
       | (static_cast<uint32_t>(in[1]) << 8)
       | (static_cast<uint32_t>(in[2]) << 16)
       | (static_cast<uint32_t>(in[3]) << 24);
}

static uint64_t NowSec() {
  using namespace std::chrono;
  return static_cast<uint64_t>(
      duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

static uint64_t NowMs() {
  using namespace std::chrono;
  return static_cast<uint64_t>(
      duration_cast<milliseconds>(
          steady_clock::now().time_since_epoch())
          .count());
}

// ---------------------------------------------------------------------------
// AuthClient
// ---------------------------------------------------------------------------

AuthClient::AuthClient() {
  memset(session_key_,    0, sizeof(session_key_));
  memset(local_eph_pub_,  0, sizeof(local_eph_pub_));
  memset(local_eph_priv_, 0, sizeof(local_eph_priv_));
  memset(client_random_,  0, sizeof(client_random_));
}

AuthClient::~AuthClient() { Shutdown(); }

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

Status AuthClient::Initialize(std::unique_ptr<Transport>       transport,
                               const CryptoConfig&              config,
                               std::unique_ptr<CryptoProvider>  crypto) {
  if (!transport) return Status::kInvalidParam;
  // Verify that device_public_key is not all zeros.
  bool all_zero = true;
  for (size_t i = 0; i < kEcPublicKeySize; ++i) {
    if (config.device_public_key[i] != 0) { all_zero = false; break; }
  }
  if (all_zero) return Status::kInvalidParam;

  std::lock_guard<std::mutex> lock(mutex_);
  transport_    = std::move(transport);
  crypto_config_ = config;

  if (crypto) {
    crypto_ = std::move(crypto);
  } else {
    crypto_ = CreateMbedTlsCryptoProvider();
    if (!crypto_) return Status::kCryptoError;
  }

  state_ = State::kIdle;
  return Status::kOk;
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

void AuthClient::Shutdown() {
  if (auth_thread_.joinable()) {
    // Signal the thread to stop by disconnecting the transport.
    if (transport_) transport_->Disconnect();
    auth_thread_.join();
  }
  state_ = State::kUninitialized;
}

// ---------------------------------------------------------------------------
// RequestAuthorization
// ---------------------------------------------------------------------------

Status AuthClient::RequestAuthorization(const AuthRequest& request,
                                         AuthCallback       callback,
                                         uint32_t           timeout_ms) {
  State expected = State::kIdle;
  if (!state_.compare_exchange_strong(expected, State::kConnecting)) {
    if (state_ == State::kUninitialized) return Status::kNotInitialized;
    return Status::kAlreadyBusy;
  }

  if (auth_thread_.joinable()) auth_thread_.join();

  auth_thread_ = std::thread(&AuthClient::RunAuthFlow, this,
                              request, std::move(callback), timeout_ms);
  return Status::kOk;
}

// ---------------------------------------------------------------------------
// IsAuthorized / GetLicenseInfo
// ---------------------------------------------------------------------------

bool AuthClient::IsAuthorized() const {
  if (state_ != State::kAuthorized) return false;
  std::lock_guard<std::mutex> lock(mutex_);
  return license_info_.IsValid(NowSec());
}

LicenseInfo AuthClient::GetLicenseInfo() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return license_info_;
}

// ---------------------------------------------------------------------------
// RunAuthFlow  (private, runs on auth_thread_)
// ---------------------------------------------------------------------------

void AuthClient::RunAuthFlow(AuthRequest  request,
                              AuthCallback callback,
                              uint32_t     timeout_ms) {
  const uint64_t deadline = NowMs() + timeout_ms;

  auto finish = [&](Status s, const LicenseInfo& lic) {
    // Zero out all ephemeral secrets before calling back.
    memset(session_key_,    0, sizeof(session_key_));
    memset(local_eph_priv_, 0, sizeof(local_eph_priv_));
    send_seq_ = 0;
    transport_->Disconnect();
    if (s == Status::kOk) {
      std::lock_guard<std::mutex> lock(mutex_);
      license_info_ = lic;
      state_        = State::kAuthorized;
    } else {
      state_ = State::kIdle;
    }
    if (callback) callback(s, lic);
  };

  // Step 1: Connect.
  Status s = transport_->Connect();
  if (s != Status::kOk) { finish(s, LicenseInfo{}); return; }

  // Step 2: Key exchange.
  state_ = State::kKeyExchange;
  uint32_t remaining = static_cast<uint32_t>(deadline - NowMs());
  s = PerformKeyExchange(remaining);
  if (s != Status::kOk) { finish(s, LicenseInfo{}); return; }

  // Step 3: Authorization request/response.
  state_ = State::kAuthorizing;
  remaining = static_cast<uint32_t>(deadline - NowMs());
  uint32_t request_id = static_cast<uint32_t>(NowMs() & 0xFFFFFFFF);
  s = SendAuthRequest(request, request_id, remaining);
  if (s != Status::kOk) { finish(s, LicenseInfo{}); return; }

  remaining = static_cast<uint32_t>(deadline - NowMs());
  LicenseInfo lic;
  s = ReceiveAuthResponse(request_id, &lic, remaining);
  finish(s, lic);
}

// ---------------------------------------------------------------------------
// PerformKeyExchange  (private)
// ---------------------------------------------------------------------------

Status AuthClient::PerformKeyExchange(uint32_t timeout_ms) {
  // Generate ephemeral ECDH key pair and client nonce.
  Status s = crypto_->GenerateEcdhKeyPair(local_eph_pub_, local_eph_priv_);
  if (s != Status::kOk) return s;

  s = crypto_->GenerateRandom(client_random_, kRandomSize);
  if (s != Status::kOk) return s;

  uint64_t client_ts = NowSec();

  // Build KEY_EXCHANGE_REQ payload.
  uint8_t req[kKeyExchangeReqLen];
  memcpy(req, local_eph_pub_, kEcPublicKeySize);
  WriteU64Le(req + kEcPublicKeySize, client_ts);
  memcpy(req + kEcPublicKeySize + 8, client_random_, kRandomSize);

  // Send.
  s = protocol::SendFrame(transport_.get(), protocol::kMsgKeyExchangeReq,
                           send_seq_++, req, kKeyExchangeReqLen);
  if (s != Status::kOk) return s;

  // Receive KEY_EXCHANGE_RSP.
  uint8_t  rsp[protocol::kKeyExchangeRspMaxLen];
  uint16_t rsp_len = 0;
  s = protocol::RecvFrame(transport_.get(), protocol::kMsgKeyExchangeRsp,
                           /*seq=*/0,  // server echoes seq 0 for first response
                           rsp, protocol::kKeyExchangeRspMaxLen,
                           &rsp_len, timeout_ms);
  if (s != Status::kOk) return s;
  if (rsp_len < protocol::kKeyExchangeRspMinLen) return Status::kProtocolError;

  const uint8_t* srv_eph_pub  = rsp;
  const uint8_t* srv_ts_bytes = rsp + kEcPublicKeySize;
  const uint8_t* srv_random   = rsp + kEcPublicKeySize + 8;
  uint8_t        sig_len      = rsp[kEcPublicKeySize + 8 + kRandomSize];
  const uint8_t* sig          = rsp + kEcPublicKeySize + 8 + kRandomSize + 1;

  if (rsp_len < static_cast<uint16_t>(protocol::kKeyExchangeRspMinLen + sig_len))
    return Status::kProtocolError;

  uint64_t srv_ts = 0;
  for (int b = 0; b < 8; ++b)
    srv_ts |= static_cast<uint64_t>(srv_ts_bytes[b]) << (8 * b);

  // Build the data buffer that was signed by the server.
  // domain(18) + srv_eph_pub(65) + cli_eph_pub(65) +
  // srv_ts(8) + cli_ts(8) + srv_random(16) + cli_random(16) = 196 bytes
  uint8_t signed_data[200];
  size_t  off = 0;
  memcpy(signed_data + off, protocol::kKexDomain,
         sizeof(protocol::kKexDomain));               off += sizeof(protocol::kKexDomain);
  memcpy(signed_data + off, srv_eph_pub, kEcPublicKeySize); off += kEcPublicKeySize;
  memcpy(signed_data + off, local_eph_pub_, kEcPublicKeySize); off += kEcPublicKeySize;
  WriteU64Le(signed_data + off, srv_ts);  off += 8;
  // client_ts was already serialised into the req message
  uint64_t stored_client_ts = 0;
  for (int b = 0; b < 8; ++b)
    stored_client_ts |= static_cast<uint64_t>(req[kEcPublicKeySize + b]) << (8*b);
  WriteU64Le(signed_data + off, stored_client_ts); off += 8;
  memcpy(signed_data + off, srv_random, kRandomSize); off += kRandomSize;
  memcpy(signed_data + off, client_random_, kRandomSize); off += kRandomSize;

  // Verify signature with the device's static public key.
  s = crypto_->EcdsaVerify(crypto_config_.device_public_key,
                             signed_data, off, sig, sig_len);
  if (s != Status::kOk) return Status::kAuthFailed;

  // Derive session key via ECDH + HKDF.
  uint8_t shared_secret[kEcPrivateKeySize];
  s = crypto_->ComputeEcdhSharedSecret(local_eph_priv_, srv_eph_pub,
                                         shared_secret);
  if (s != Status::kOk) { memset(shared_secret, 0, sizeof(shared_secret)); return s; }

  // salt = client_random || server_random
  uint8_t salt[kRandomSize * 2];
  memcpy(salt,             client_random_, kRandomSize);
  memcpy(salt + kRandomSize, srv_random,   kRandomSize);

  s = crypto_->DeriveSessionKey(shared_secret, salt, sizeof(salt), session_key_);
  memset(shared_secret, 0, sizeof(shared_secret));
  return s;
}

// ---------------------------------------------------------------------------
// SendAuthRequest  (private)
// ---------------------------------------------------------------------------

Status AuthClient::SendAuthRequest(const AuthRequest& req,
                                    uint32_t           request_id,
                                    uint32_t           timeout_ms) {
  (void)timeout_ms;

  // Build plaintext (52 bytes).
  uint8_t pt[protocol::kAuthReqPlaintextLen];
  memset(pt, 0, sizeof(pt));
  WriteU32Le(pt + 0,  request_id);
  WriteU32Le(pt + 4,  req.client_device_id);
  memcpy(pt + 8,  req.product_name, 32);
  pt[40] = req.feature_flags;
  WriteU64Le(pt + 41, NowSec());
  // pt[49..51] = padding zeros

  // Encrypt.
  uint8_t nonce[kGcmNonceSize];
  Status s = crypto_->GenerateRandom(nonce, kGcmNonceSize);
  if (s != Status::kOk) return s;

  uint8_t ciphertext[protocol::kAuthReqPlaintextLen];
  uint8_t tag[kGcmTagSize];
  s = crypto_->AesGcmEncrypt(session_key_, nonce,
                               nullptr, 0,
                               pt, sizeof(pt),
                               ciphertext, tag);
  if (s != Status::kOk) return s;

  // Wire: [nonce(12) | ciphertext(52) | tag(16)] = 80 bytes
  uint8_t payload[kGcmNonceSize + sizeof(ciphertext) + kGcmTagSize];
  size_t  off = 0;
  memcpy(payload + off, nonce,      kGcmNonceSize);  off += kGcmNonceSize;
  memcpy(payload + off, ciphertext, sizeof(ciphertext)); off += sizeof(ciphertext);
  memcpy(payload + off, tag,        kGcmTagSize);

  return protocol::SendFrame(transport_.get(), protocol::kMsgAuthRequest,
                              send_seq_++,
                              payload, static_cast<uint16_t>(sizeof(payload)));
}

// ---------------------------------------------------------------------------
// ReceiveAuthResponse  (private)
// ---------------------------------------------------------------------------

Status AuthClient::ReceiveAuthResponse(uint32_t    request_id,
                                        LicenseInfo* out,
                                        uint32_t     timeout_ms) {
  uint8_t  payload[kMaxPayloadSize];
  uint16_t payload_len = 0;

  Status s = protocol::RecvFrame(transport_.get(),
                                  protocol::kMsgAuthResponse,
                                  static_cast<uint16_t>(send_seq_ - 1),
                                  payload, sizeof(payload),
                                  &payload_len, timeout_ms);
  if (s != Status::kOk) return s;

  // Minimum: nonce(12) + 8 bytes plaintext + tag(16)
  if (payload_len < kGcmNonceSize + 8 + kGcmTagSize)
    return Status::kProtocolError;

  const uint8_t* nonce      = payload;
  const uint8_t* ciphertext = payload + kGcmNonceSize;
  size_t         ct_len     = payload_len - kGcmNonceSize - kGcmTagSize;
  const uint8_t* tag        = payload + kGcmNonceSize + ct_len;

  uint8_t pt[kMaxPayloadSize];
  s = crypto_->AesGcmDecrypt(session_key_, nonce,
                               nullptr, 0,
                               ciphertext, ct_len, tag,
                               pt);
  if (s != Status::kOk) return Status::kCryptoError;

  // Parse plaintext.
  if (ct_len < 8) return Status::kProtocolError;
  uint32_t resp_id = ReadU32Le(pt);
  if (resp_id != request_id) return Status::kProtocolError;
  uint8_t status_byte = pt[4];

  if (status_byte != 0) return Status::kAuthDenied;

  // Authorized: parse license + signature.
  // [req_id(4) | status(1) | pad(3) | license(58) | sig_len(1) | sig(≤72)]
  const size_t kMinAuthRspLen = 4 + 1 + 3 + protocol::kLicenseSerialLen + 1;
  if (ct_len < kMinAuthRspLen) return Status::kProtocolError;

  const uint8_t* lic_bytes = pt + 8;
  uint8_t        sig_len_b = pt[8 + protocol::kLicenseSerialLen];
  const uint8_t* sig       = pt + 8 + protocol::kLicenseSerialLen + 1;

  if (ct_len < kMinAuthRspLen + sig_len_b) return Status::kProtocolError;

  // Verify license token signature with the device's static public key.
  // data = domain(18) || serialized_license(58)
  uint8_t lic_signed[sizeof(protocol::kLicDomain) + protocol::kLicenseSerialLen];
  memcpy(lic_signed, protocol::kLicDomain, sizeof(protocol::kLicDomain));
  memcpy(lic_signed + sizeof(protocol::kLicDomain), lic_bytes,
         protocol::kLicenseSerialLen);

  s = crypto_->EcdsaVerify(crypto_config_.device_public_key,
                             lic_signed, sizeof(lic_signed),
                             sig, sig_len_b);
  if (s != Status::kOk) return Status::kAuthFailed;

  // Deserialize license.
  protocol::DeserializeLicense(lic_bytes, out);
  return Status::kOk;
}

// ---------------------------------------------------------------------------
// StatusToString
// ---------------------------------------------------------------------------

const char* StatusToString(Status status) {
  switch (status) {
    case Status::kOk:             return "Ok";
    case Status::kPending:        return "Pending";
    case Status::kTimeout:        return "Timeout";
    case Status::kAuthDenied:     return "AuthDenied";
    case Status::kAuthFailed:     return "AuthFailed";
    case Status::kCryptoError:    return "CryptoError";
    case Status::kTransportError: return "TransportError";
    case Status::kInvalidParam:   return "InvalidParam";
    case Status::kNotInitialized: return "NotInitialized";
    case Status::kAlreadyBusy:    return "AlreadyBusy";
    case Status::kLicenseExpired: return "LicenseExpired";
    case Status::kProtocolError:  return "ProtocolError";
    case Status::kBufferTooSmall: return "BufferTooSmall";
    default:                      return "Unknown";
  }
}

}  // namespace secret_com
