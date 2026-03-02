// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// protocol.h — Wire-protocol constants, message types, and payload layouts.
//
// Wire frame layout (all integers little-endian):
//
//   ┌────────┬────────┬──────────┬──────────────┬──────────────┬──────────────────────────────┬────────┬────────┐
//   │ 0xAA   │ 0x55   │ MsgType  │  SeqNum[1:0] │ PayLen[1:0]  │  Payload[0..PayLen-1]        │CRC16_L │CRC16_H │
//   │ (1 B)  │ (1 B)  │ (1 B)    │  (2 B LE)    │ (2 B LE)     │                              │ (1 B)  │ (1 B)  │
//   └────────┴────────┴──────────┴──────────────┴──────────────┴──────────────────────────────┴────────┴────────┘
//
//   Header = bytes [0..6], Footer = CRC16-CCITT over [0..6+PayLen-1].
//
// Encrypted payload format (AUTH_REQUEST, AUTH_RESPONSE):
//
//   [ NONCE (12 B) | CIPHERTEXT (N B) | TAG (16 B) ]
//
// Signature coverage for KEY_EXCHANGE_RSP:
//
//   domain_sep = "secret_com_kex_v1\0"  (18 bytes)
//   signed_data = SHA256(domain_sep
//                        || server_eph_pub (65)
//                        || client_eph_pub (65)
//                        || server_ts      (8 LE)
//                        || client_ts      (8 LE)
//                        || server_random  (16)
//                        || client_random  (16))
//
// License token signature coverage:
//
//   domain_sep = "secret_com_lic_v1\0"  (18 bytes)
//   signed_data = SHA256(domain_sep || serialized_license (58 bytes))

#ifndef SECRET_COM_SRC_PROTOCOL_PROTOCOL_H_
#define SECRET_COM_SRC_PROTOCOL_PROTOCOL_H_

#include <cstdint>
#include "secret_com/types.h"

namespace secret_com {
namespace protocol {

// ---------------------------------------------------------------------------
// Frame constants
// ---------------------------------------------------------------------------

constexpr uint8_t  kStartByte0     = 0xAA;
constexpr uint8_t  kStartByte1     = 0x55;
constexpr size_t   kHeaderSize     = 7;   // [0xAA][0x55][type][seq:2][len:2]
constexpr size_t   kFooterSize     = 2;   // CRC16
constexpr size_t   kFrameOverhead  = kHeaderSize + kFooterSize;
constexpr uint16_t kMaxPayloadLen  = static_cast<uint16_t>(kMaxPayloadSize);

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

enum MsgType : uint8_t {
  kMsgKeyExchangeReq = 0x01,  // Client → Server: ephemeral pubkey + nonce
  kMsgKeyExchangeRsp = 0x02,  // Server → Client: ephemeral pubkey + sig
  kMsgAuthRequest    = 0x03,  // Client → Server: encrypted auth request
  kMsgAuthResponse   = 0x04,  // Server → Client: encrypted auth response
  kMsgHeartbeat      = 0x05,  // Either direction: keep-alive
  kMsgDisconnect     = 0x06,  // Graceful disconnect
  kMsgError          = 0xFF,  // Protocol error; payload = 1-byte error code
};

// ---------------------------------------------------------------------------
// Payload sizes (all fixed or bounded)
// ---------------------------------------------------------------------------

//  KEY_EXCHANGE_REQ: [eph_pub:65][timestamp:8][random:16] = 89 bytes
constexpr uint16_t kKeyExchangeReqLen = kEcPublicKeySize + 8 + kRandomSize;

//  KEY_EXCHANGE_RSP: [eph_pub:65][timestamp:8][random:16][sig_len:1][sig:≤72]
//                                                                    max = 162
constexpr uint16_t kKeyExchangeRspMinLen =
    kEcPublicKeySize + 8 + kRandomSize + 1;  // Without signature bytes
constexpr uint16_t kKeyExchangeRspMaxLen =
    kKeyExchangeRspMinLen + kEcSignatureSize;

//  AUTH_REQUEST / AUTH_RESPONSE: encrypted, variable length.
//  Plaintext sizes (before AES-GCM overhead):
//  AUTH_REQUEST plaintext: [req_id:4][dev_id:4][product:32][flags:1][ts:8][pad:3] = 52
//  AUTH_RESPONSE plaintext (ok): [req_id:4][status:1][pad:3][lic:58][sig_len:1][sig:≤72] = ≤139
//  AUTH_RESPONSE plaintext (denied): [req_id:4][status:1][pad:3] = 8
constexpr size_t kAuthReqPlaintextLen  = 52;
constexpr size_t kLicenseSerialLen     = 58;  // Serialised LicenseInfo size
constexpr size_t kAuthRspMaxPlainLen   = 4 + 1 + 3 + kLicenseSerialLen + 1 + kEcSignatureSize;

// Encryption overhead per message = kGcmNonceSize + kGcmTagSize = 28 bytes.
constexpr size_t kEncryptionOverhead = kGcmNonceSize + kGcmTagSize;

// ---------------------------------------------------------------------------
// Domain-separation strings for signing
// ---------------------------------------------------------------------------

constexpr char kKexDomain[] = "secret_com_kex_v1";   // 18 bytes incl. NUL
constexpr char kLicDomain[] = "secret_com_lic_v1";   // 18 bytes incl. NUL

// ---------------------------------------------------------------------------
// Low-level frame helpers
// ---------------------------------------------------------------------------

/// @brief Compute CRC16-CCITT (poly 0x1021, init 0xFFFF) over @p data.
uint16_t Crc16(const uint8_t* data, size_t length);

/// @brief Encode a frame into @p out_buf.
///
/// @param msg_type    One of the MsgType constants.
/// @param seq         Sequence number (wraps at 0xFFFF).
/// @param payload     Payload bytes; may be nullptr if payload_len == 0.
/// @param payload_len Payload length; must be ≤ kMaxPayloadLen.
/// @param out_buf     Output buffer; must be ≥ payload_len + kFrameOverhead.
/// @return Total frame size written, or 0 on error.
size_t EncodeFrame(uint8_t        msg_type,
                   uint16_t       seq,
                   const uint8_t* payload, uint16_t payload_len,
                   uint8_t*       out_buf,  size_t   out_buf_size);

// ---------------------------------------------------------------------------
// Serialization helpers for structured payloads
// ---------------------------------------------------------------------------

/// @brief Serialise a LicenseInfo to a 58-byte flat buffer for signing.
void SerializeLicense(const LicenseInfo& lic, uint8_t out[kLicenseSerialLen]);

/// @brief Deserialise a LicenseInfo from a 58-byte flat buffer.
void DeserializeLicense(const uint8_t data[kLicenseSerialLen], LicenseInfo* out);

}  // namespace protocol
}  // namespace secret_com

#endif  // SECRET_COM_SRC_PROTOCOL_PROTOCOL_H_
