// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// auth_server.cc — Authorization server implementation.
//
// Server-side protocol flow (mirrors auth_client.cc):
//
//   1. Recv KEY_EXCHANGE_REQ:  [cli_eph_pub(65) | cli_ts(8) | cli_random(16)]
//   2. Generate srv_eph_pub, srv_eph_priv, srv_random.
//   3. Compute sign_data = SHA256(kKexDomain || srv_eph_pub || cli_eph_pub ||
//                                  srv_ts || cli_ts || srv_random || cli_random)
//      Sign with device_private_key.
//   4. Send KEY_EXCHANGE_RSP: [srv_eph_pub | srv_ts | srv_random |
//                               sig_len | sig]
//   5. ECDH + HKDF → session_key (same derivation as client).
//   6. Recv AUTH_REQUEST, decrypt with session_key.
//   7. Call verify_callback_; if denied → encrypt & send denied response.
//   8. Serialize & sign license token with device_private_key.
//   9. Encrypt & send AUTH_RESPONSE.

#include "secret_com/auth_server.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <memory>

#include "src/crypto/mbedtls_provider.h"
#include "src/protocol/message_framer.h"
#include "src/protocol/protocol.h"

namespace secret_com {

using protocol::MsgType;

// ---------------------------------------------------------------------------
// Helpers (same as auth_client.cc)
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

// ---------------------------------------------------------------------------
// AuthServer
// ---------------------------------------------------------------------------

AuthServer::AuthServer() {
  memset(session_key_,    0, sizeof(session_key_));
  memset(local_eph_pub_,  0, sizeof(local_eph_pub_));
  memset(local_eph_priv_, 0, sizeof(local_eph_priv_));
  memset(client_random_,  0, sizeof(client_random_));
  memset(server_random_,  0, sizeof(server_random_));
}

AuthServer::~AuthServer() { Shutdown(); }

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

Status AuthServer::Initialize(std::unique_ptr<Transport>       transport,
                               const CryptoConfig&              config,
                               std::unique_ptr<CryptoProvider>  crypto) {
  if (!transport)    return Status::kInvalidParam;
  if (!config.is_server) return Status::kInvalidParam;

  // Both keys must be non-zero.
  bool pub_zero = true, priv_zero = true;
  for (size_t i = 0; i < kEcPublicKeySize;  ++i)
    if (config.device_public_key[i])  { pub_zero  = false; break; }
  for (size_t i = 0; i < kEcPrivateKeySize; ++i)
    if (config.device_private_key[i]) { priv_zero = false; break; }
  if (pub_zero || priv_zero) return Status::kInvalidParam;

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

void AuthServer::SetAuthVerifyCallback(AuthVerifyCallback callback) {
  std::lock_guard<std::mutex> lock(mutex_);
  verify_callback_ = std::move(callback);
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

void AuthServer::Shutdown() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stop_requested_ = true;
  }
  if (transport_) transport_->Disconnect();
  if (listen_thread_.joinable()) listen_thread_.join();
  state_ = State::kUninitialized;
}

// ---------------------------------------------------------------------------
// StartListening
// ---------------------------------------------------------------------------

Status AuthServer::StartListening() {
  if (state_ == State::kUninitialized) return Status::kNotInitialized;
  if (listen_thread_.joinable())       return Status::kAlreadyBusy;
  stop_requested_ = false;
  listen_thread_  = std::thread(&AuthServer::ListenLoop, this);
  return Status::kOk;
}

void AuthServer::ListenLoop() {
  while (!stop_requested_) {
    // Reset ephemeral state between connections.
    memset(session_key_,    0, sizeof(session_key_));
    memset(local_eph_pub_,  0, sizeof(local_eph_pub_));
    memset(local_eph_priv_, 0, sizeof(local_eph_priv_));
    send_seq_ = 0;
    state_    = State::kIdle;

    Status s = HandleOneRequest(30000);
    (void)s;  // Log or dispatch as needed.
  }
}

// ---------------------------------------------------------------------------
// HandleOneRequest
// ---------------------------------------------------------------------------

Status AuthServer::HandleOneRequest(uint32_t timeout_ms) {
  if (state_ == State::kUninitialized) return Status::kNotInitialized;

  state_ = State::kKeyExchange;
  Status s = PerformKeyExchange(timeout_ms);
  if (s != Status::kOk) {
    transport_->Disconnect();
    state_ = State::kError;
    return s;
  }

  state_ = State::kVerifying;
  s = ProcessAuthRequest(timeout_ms);
  transport_->Disconnect();
  state_ = (s == Status::kOk) ? State::kDone : State::kError;

  // Zero ephemeral secrets.
  memset(session_key_,    0, sizeof(session_key_));
  memset(local_eph_priv_, 0, sizeof(local_eph_priv_));
  return s;
}

// ---------------------------------------------------------------------------
// PerformKeyExchange  (private)
// ---------------------------------------------------------------------------

Status AuthServer::PerformKeyExchange(uint32_t timeout_ms) {
  // Receive KEY_EXCHANGE_REQ.
  uint8_t  req[protocol::kKeyExchangeReqLen];
  uint16_t req_len = 0;
  Status s = protocol::RecvFrame(transport_.get(),
                                  protocol::kMsgKeyExchangeReq,
                                  /*seq=*/0,
                                  req, sizeof(req), &req_len, timeout_ms);
  if (s != Status::kOk) return s;
  if (req_len != protocol::kKeyExchangeReqLen) return Status::kProtocolError;

  const uint8_t* cli_eph_pub   = req;
  const uint8_t* cli_ts_bytes  = req + kEcPublicKeySize;
  const uint8_t* cli_random    = req + kEcPublicKeySize + 8;

  uint64_t cli_ts = 0;
  for (int b = 0; b < 8; ++b)
    cli_ts |= static_cast<uint64_t>(cli_ts_bytes[b]) << (8 * b);

  memcpy(client_random_, cli_random, kRandomSize);

  // Generate server ephemeral key pair and random.
  s = crypto_->GenerateEcdhKeyPair(local_eph_pub_, local_eph_priv_);
  if (s != Status::kOk) return s;

  s = crypto_->GenerateRandom(server_random_, kRandomSize);
  if (s != Status::kOk) return s;

  uint64_t srv_ts = NowSec();

  // Sign: domain(18) || srv_eph_pub(65) || cli_eph_pub(65) ||
  //       srv_ts(8)  || cli_ts(8)       || srv_random(16)  || cli_random(16)
  uint8_t signed_data[200];
  size_t  off = 0;
  memcpy(signed_data + off, protocol::kKexDomain,
         sizeof(protocol::kKexDomain));               off += sizeof(protocol::kKexDomain);
  memcpy(signed_data + off, local_eph_pub_, kEcPublicKeySize); off += kEcPublicKeySize;
  memcpy(signed_data + off, cli_eph_pub,    kEcPublicKeySize); off += kEcPublicKeySize;
  WriteU64Le(signed_data + off, srv_ts);  off += 8;
  WriteU64Le(signed_data + off, cli_ts);  off += 8;
  memcpy(signed_data + off, server_random_, kRandomSize); off += kRandomSize;
  memcpy(signed_data + off, client_random_, kRandomSize); off += kRandomSize;

  uint8_t sig[kEcSignatureSize];
  size_t  sig_len = 0;
  s = crypto_->EcdsaSign(crypto_config_.device_private_key,
                          signed_data, off, sig, &sig_len);
  if (s != Status::kOk) return s;

  // Build KEY_EXCHANGE_RSP payload.
  // [srv_eph_pub(65) | srv_ts(8) | srv_random(16) | sig_len(1) | sig(≤72)]
  uint8_t rsp[protocol::kKeyExchangeRspMaxLen];
  size_t  rsp_off = 0;
  memcpy(rsp + rsp_off, local_eph_pub_, kEcPublicKeySize); rsp_off += kEcPublicKeySize;
  WriteU64Le(rsp + rsp_off, srv_ts);                        rsp_off += 8;
  memcpy(rsp + rsp_off, server_random_, kRandomSize);       rsp_off += kRandomSize;
  rsp[rsp_off++] = static_cast<uint8_t>(sig_len);
  memcpy(rsp + rsp_off, sig, sig_len);                      rsp_off += sig_len;

  s = protocol::SendFrame(transport_.get(), protocol::kMsgKeyExchangeRsp,
                           send_seq_++,
                           rsp, static_cast<uint16_t>(rsp_off));
  if (s != Status::kOk) return s;

  // Derive session key.
  uint8_t shared_secret[kEcPrivateKeySize];
  s = crypto_->ComputeEcdhSharedSecret(local_eph_priv_, cli_eph_pub,
                                         shared_secret);
  if (s != Status::kOk) { memset(shared_secret, 0, sizeof(shared_secret)); return s; }

  uint8_t salt[kRandomSize * 2];
  memcpy(salt,             client_random_, kRandomSize);
  memcpy(salt + kRandomSize, server_random_, kRandomSize);

  s = crypto_->DeriveSessionKey(shared_secret, salt, sizeof(salt), session_key_);
  memset(shared_secret, 0, sizeof(shared_secret));
  return s;
}

// ---------------------------------------------------------------------------
// ProcessAuthRequest  (private)
// ---------------------------------------------------------------------------

Status AuthServer::ProcessAuthRequest(uint32_t timeout_ms) {
  uint8_t  payload[kMaxPayloadSize];
  uint16_t payload_len = 0;

  Status s = protocol::RecvFrame(transport_.get(),
                                  protocol::kMsgAuthRequest,
                                  /*seq=*/1,
                                  payload, sizeof(payload),
                                  &payload_len, timeout_ms);
  if (s != Status::kOk) return s;

  // Decrypt.
  if (payload_len < kGcmNonceSize + protocol::kAuthReqPlaintextLen + kGcmTagSize)
    return Status::kProtocolError;

  const uint8_t* nonce      = payload;
  const uint8_t* ciphertext = payload + kGcmNonceSize;
  size_t         ct_len     = payload_len - kGcmNonceSize - kGcmTagSize;
  const uint8_t* tag        = payload + kGcmNonceSize + ct_len;

  uint8_t pt[kMaxPayloadSize];
  s = crypto_->AesGcmDecrypt(session_key_, nonce,
                               nullptr, 0,
                               ciphertext, ct_len, tag, pt);
  if (s != Status::kOk) return Status::kCryptoError;

  // Parse AuthRequest plaintext.
  uint32_t request_id = ReadU32Le(pt + 0);
  AuthRequest req;
  req.client_device_id = ReadU32Le(pt + 4);
  memcpy(req.product_name, pt + 8, 32);
  req.product_name[31] = '\0';
  req.feature_flags    = pt[40];

  // Call application verification callback.
  LicenseInfo license;
  bool granted = false;
  if (verify_callback_) {
    granted = verify_callback_(req, &license);
  }

  if (!granted) {
    // Send denied response (8 bytes).
    uint8_t denied_pt[8] = {0};
    WriteU32Le(denied_pt, request_id);
    denied_pt[4] = 0x01;  // status = denied

    uint8_t nonce_out[kGcmNonceSize];
    crypto_->GenerateRandom(nonce_out, kGcmNonceSize);

    uint8_t ct_out[8], tag_out[kGcmTagSize];
    crypto_->AesGcmEncrypt(session_key_, nonce_out, nullptr, 0,
                            denied_pt, sizeof(denied_pt),
                            ct_out, tag_out);

    uint8_t resp[kGcmNonceSize + 8 + kGcmTagSize];
    memcpy(resp,                            nonce_out, kGcmNonceSize);
    memcpy(resp + kGcmNonceSize,            ct_out,    8);
    memcpy(resp + kGcmNonceSize + 8,        tag_out,   kGcmTagSize);
    protocol::SendFrame(transport_.get(), protocol::kMsgAuthResponse,
                         send_seq_++, resp, sizeof(resp));
    return Status::kAuthDenied;
  }

  // Fill in server-side license fields if not set.
  if (license.issue_timestamp == 0) license.issue_timestamp = NowSec();
  if (license.device_id == 0)       license.device_id = req.client_device_id;
  if (license.product_name[0] == '\0')
    memcpy(license.product_name, req.product_name, 32);

  // Serialize and sign the license.
  uint8_t lic_serial[protocol::kLicenseSerialLen];
  protocol::SerializeLicense(license, lic_serial);

  uint8_t lic_signed[sizeof(protocol::kLicDomain) + protocol::kLicenseSerialLen];
  memcpy(lic_signed, protocol::kLicDomain, sizeof(protocol::kLicDomain));
  memcpy(lic_signed + sizeof(protocol::kLicDomain), lic_serial,
         protocol::kLicenseSerialLen);

  uint8_t sig[kEcSignatureSize];
  size_t  sig_len = 0;
  s = crypto_->EcdsaSign(crypto_config_.device_private_key,
                          lic_signed, sizeof(lic_signed),
                          sig, &sig_len);
  if (s != Status::kOk) return s;

  // Build AUTH_RESPONSE plaintext.
  // [req_id(4) | status=0(1) | pad(3) | license(58) | sig_len(1) | sig(≤72)]
  const size_t pt_len = 4 + 1 + 3 + protocol::kLicenseSerialLen + 1 + sig_len;
  uint8_t resp_pt[protocol::kAuthRspMaxPlainLen];
  memset(resp_pt, 0, sizeof(resp_pt));
  WriteU32Le(resp_pt, request_id);
  resp_pt[4] = 0;  // status = ok
  memcpy(resp_pt + 8, lic_serial, protocol::kLicenseSerialLen);
  resp_pt[8 + protocol::kLicenseSerialLen] = static_cast<uint8_t>(sig_len);
  memcpy(resp_pt + 8 + protocol::kLicenseSerialLen + 1, sig, sig_len);

  // Encrypt.
  uint8_t nonce_out[kGcmNonceSize];
  s = crypto_->GenerateRandom(nonce_out, kGcmNonceSize);
  if (s != Status::kOk) return s;

  uint8_t ct_out[protocol::kAuthRspMaxPlainLen];
  uint8_t tag_out[kGcmTagSize];
  s = crypto_->AesGcmEncrypt(session_key_, nonce_out, nullptr, 0,
                               resp_pt, pt_len,
                               ct_out, tag_out);
  if (s != Status::kOk) return s;

  const size_t resp_len = kGcmNonceSize + pt_len + kGcmTagSize;
  uint8_t resp[kMaxPayloadSize];
  memcpy(resp,                        nonce_out, kGcmNonceSize);
  memcpy(resp + kGcmNonceSize,        ct_out,    pt_len);
  memcpy(resp + kGcmNonceSize + pt_len, tag_out, kGcmTagSize);

  return protocol::SendFrame(transport_.get(), protocol::kMsgAuthResponse,
                              send_seq_++,
                              resp, static_cast<uint16_t>(resp_len));
}

}  // namespace secret_com
