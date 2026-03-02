// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

#include "src/protocol/message_framer.h"

#include <cstring>

#include "src/protocol/protocol.h"

namespace secret_com {
namespace protocol {

// ---------------------------------------------------------------------------
// CRC16-CCITT helpers  (polynomial 0x1021, initial value 0xFFFF)
// ---------------------------------------------------------------------------

uint16_t Crc16(const uint8_t* data, size_t length) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < length; ++i) {
    crc ^= static_cast<uint16_t>(data[i]) << 8;
    for (int bit = 0; bit < 8; ++bit) {
      if (crc & 0x8000u) {
        crc = static_cast<uint16_t>((crc << 1) ^ 0x1021u);
      } else {
        crc <<= 1;
      }
    }
  }
  return crc;
}

// ---------------------------------------------------------------------------
// EncodeFrame
// ---------------------------------------------------------------------------

size_t EncodeFrame(uint8_t        msg_type,
                   uint16_t       seq,
                   const uint8_t* payload, uint16_t payload_len,
                   uint8_t*       out_buf,  size_t   out_buf_size) {
  const size_t total = static_cast<size_t>(payload_len) + kFrameOverhead;
  if (out_buf_size < total) return 0;

  size_t i = 0;
  out_buf[i++] = kStartByte0;
  out_buf[i++] = kStartByte1;
  out_buf[i++] = msg_type;
  out_buf[i++] = static_cast<uint8_t>(seq & 0xFF);
  out_buf[i++] = static_cast<uint8_t>((seq >> 8) & 0xFF);
  out_buf[i++] = static_cast<uint8_t>(payload_len & 0xFF);
  out_buf[i++] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);

  if (payload_len > 0 && payload != nullptr) {
    memcpy(out_buf + i, payload, payload_len);
    i += payload_len;
  }

  uint16_t crc = Crc16(out_buf, i);
  out_buf[i++] = static_cast<uint8_t>(crc & 0xFF);
  out_buf[i++] = static_cast<uint8_t>((crc >> 8) & 0xFF);
  return i;
}

// ---------------------------------------------------------------------------
// License serialization
// ---------------------------------------------------------------------------
// Layout (58 bytes, all LE):
//   [0]      type        (1)
//   [1..3]   _pad        (3) zero
//   [4..7]   device_id   (4 LE)
//   [8..15]  issue_ts    (8 LE)
//   [16..23] expiry_ts   (8 LE)
//   [24..27] rem_uses    (4 LE)
//   [28]     feat_flags  (1)
//   [29..31] _pad2       (3) zero
//   [32..63] product     (32)

void SerializeLicense(const LicenseInfo& lic, uint8_t out[kLicenseSerialLen]) {
  memset(out, 0, kLicenseSerialLen);
  out[0] = static_cast<uint8_t>(lic.type);
  // device_id
  out[4] = static_cast<uint8_t>(lic.device_id & 0xFF);
  out[5] = static_cast<uint8_t>((lic.device_id >> 8) & 0xFF);
  out[6] = static_cast<uint8_t>((lic.device_id >> 16) & 0xFF);
  out[7] = static_cast<uint8_t>((lic.device_id >> 24) & 0xFF);
  // issue_timestamp
  for (int b = 0; b < 8; ++b)
    out[8  + b] = static_cast<uint8_t>((lic.issue_timestamp  >> (8 * b)) & 0xFF);
  // expiry_timestamp
  for (int b = 0; b < 8; ++b)
    out[16 + b] = static_cast<uint8_t>((lic.expiry_timestamp >> (8 * b)) & 0xFF);
  // remaining_uses
  out[24] = static_cast<uint8_t>(lic.remaining_uses & 0xFF);
  out[25] = static_cast<uint8_t>((lic.remaining_uses >> 8) & 0xFF);
  out[26] = static_cast<uint8_t>((lic.remaining_uses >> 16) & 0xFF);
  out[27] = static_cast<uint8_t>((lic.remaining_uses >> 24) & 0xFF);
  out[28] = lic.feature_flags;
  // product_name
  memcpy(out + 32, lic.product_name, 26);  // 26 chars + 6 bytes spare = 32
}

void DeserializeLicense(const uint8_t data[kLicenseSerialLen], LicenseInfo* out) {
  out->type = static_cast<LicenseType>(data[0]);
  out->device_id = static_cast<uint32_t>(data[4])
                 | (static_cast<uint32_t>(data[5]) << 8)
                 | (static_cast<uint32_t>(data[6]) << 16)
                 | (static_cast<uint32_t>(data[7]) << 24);
  out->issue_timestamp = 0;
  for (int b = 0; b < 8; ++b)
    out->issue_timestamp |= static_cast<uint64_t>(data[8 + b]) << (8 * b);
  out->expiry_timestamp = 0;
  for (int b = 0; b < 8; ++b)
    out->expiry_timestamp |= static_cast<uint64_t>(data[16 + b]) << (8 * b);
  out->remaining_uses = static_cast<uint32_t>(data[24])
                      | (static_cast<uint32_t>(data[25]) << 8)
                      | (static_cast<uint32_t>(data[26]) << 16)
                      | (static_cast<uint32_t>(data[27]) << 24);
  out->feature_flags = data[28];
  memcpy(out->product_name, data + 32, 26);
  out->product_name[31] = '\0';
}

// ---------------------------------------------------------------------------
// MessageFramer
// ---------------------------------------------------------------------------

MessageFramer::MessageFramer() {
  memset(payload_buf_, 0, sizeof(payload_buf_));
  memset(header_buf_,  0, sizeof(header_buf_));
}

void MessageFramer::SetFrameCallback(FrameCallback callback) {
  callback_ = callback;
}

void MessageFramer::Reset() {
  state_       = ParseState::kWaitStart0;
  payload_len_ = 0;
  payload_idx_ = 0;
  rx_crc_      = 0;
}

void MessageFramer::FeedBytes(const uint8_t* data, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    ProcessByte(data[i]);
  }
}

void MessageFramer::ProcessByte(uint8_t byte) {
  switch (state_) {
    // -----------------------------------------------------------------------
    case ParseState::kWaitStart0:
      if (byte == kStartByte0) {
        state_ = ParseState::kWaitStart1;
        header_buf_[0] = byte;
      }
      break;

    case ParseState::kWaitStart1:
      if (byte == kStartByte1) {
        header_buf_[1] = byte;
        state_ = ParseState::kReadType;
      } else if (byte == kStartByte0) {
        // Consecutive 0xAA — stay in state, update buffer.
        header_buf_[0] = byte;
      } else {
        state_ = ParseState::kWaitStart0;
      }
      break;

    case ParseState::kReadType:
      msg_type_      = byte;
      header_buf_[2] = byte;
      state_         = ParseState::kReadSeqLo;
      break;

    case ParseState::kReadSeqLo:
      seq_           = byte;
      header_buf_[3] = byte;
      state_         = ParseState::kReadSeqHi;
      break;

    case ParseState::kReadSeqHi:
      seq_           |= static_cast<uint16_t>(byte) << 8;
      header_buf_[4]  = byte;
      state_          = ParseState::kReadLenLo;
      break;

    case ParseState::kReadLenLo:
      payload_len_   = byte;
      header_buf_[5] = byte;
      state_         = ParseState::kReadLenHi;
      break;

    case ParseState::kReadLenHi: {
      payload_len_   |= static_cast<uint16_t>(byte) << 8;
      header_buf_[6]  = byte;
      if (payload_len_ > kMaxPayloadLen) {
        // Oversized: treat as framing error.
        Reset();
      } else if (payload_len_ == 0) {
        state_ = ParseState::kReadCrcLo;
      } else {
        payload_idx_ = 0;
        state_       = ParseState::kReadPayload;
      }
      break;
    }

    case ParseState::kReadPayload:
      payload_buf_[payload_idx_++] = byte;
      if (payload_idx_ >= payload_len_) {
        state_ = ParseState::kReadCrcLo;
      }
      break;

    case ParseState::kReadCrcLo:
      rx_crc_ = byte;
      state_  = ParseState::kReadCrcHi;
      break;

    case ParseState::kReadCrcHi:
      rx_crc_ |= static_cast<uint16_t>(byte) << 8;
      EmitFrame();
      state_ = ParseState::kWaitStart0;
      break;
  }
}

void MessageFramer::EmitFrame() {
  // Compute CRC over header + payload.
  uint16_t computed = Crc16(header_buf_, kHeaderSize);
  if (payload_len_ > 0) {
    // We must chain the CRC over the payload.  Since Crc16() is stateless,
    // concatenate into a temporary buffer or re-feed.
    // Simple approach: build a temp buffer (max kFrameOverhead + payload).
    uint8_t tmp[kHeaderSize + kMaxPayloadSize];
    memcpy(tmp, header_buf_, kHeaderSize);
    memcpy(tmp + kHeaderSize, payload_buf_, payload_len_);
    computed = Crc16(tmp, kHeaderSize + payload_len_);
  }

  if (computed != rx_crc_) {
    // CRC mismatch — discard silently, re-sync.
    return;
  }

  if (callback_) {
    callback_(msg_type_, seq_, payload_buf_, payload_len_);
  }
}

// ---------------------------------------------------------------------------
// Blocking SendFrame
// ---------------------------------------------------------------------------

Status SendFrame(Transport* transport,
                 uint8_t    msg_type,
                 uint16_t   seq,
                 const uint8_t* payload, uint16_t payload_len) {
  uint8_t frame_buf[kMaxPayloadSize + kFrameOverhead];
  size_t frame_len = EncodeFrame(msg_type, seq, payload, payload_len,
                                  frame_buf, sizeof(frame_buf));
  if (frame_len == 0) return Status::kBufferTooSmall;
  return transport->Send(frame_buf, frame_len);
}

// ---------------------------------------------------------------------------
// Blocking RecvFrame
// ---------------------------------------------------------------------------

Status RecvFrame(Transport*  transport,
                 uint8_t     expected_type,
                 uint16_t    expected_seq,
                 uint8_t*    payload_buf,  uint16_t  payload_buf_cap,
                 uint16_t*   payload_len,
                 uint32_t    timeout_ms) {
  MessageFramer framer;
  Status        result      = Status::kTimeout;
  bool          frame_found = false;

  framer.SetFrameCallback(
      [&](uint8_t type, uint16_t seq, const uint8_t* data, uint16_t len) {
        if (type != expected_type || seq != expected_seq) return;
        if (len > payload_buf_cap) {
          result = Status::kBufferTooSmall;
          frame_found = true;
          return;
        }
        if (len > 0) memcpy(payload_buf, data, len);
        *payload_len = len;
        result       = Status::kOk;
        frame_found  = true;
      });

  // Read raw bytes until the expected frame is assembled or timeout expires.
  // We poll in small chunks and accumulate.
  uint8_t chunk[64];
  // A simple deadline approach using remaining time slices.
  const uint32_t kSliceMs = 10;
  uint32_t elapsed = 0;

  while (!frame_found) {
    uint32_t slice = (timeout_ms == 0)
                         ? kSliceMs
                         : ((timeout_ms - elapsed) < kSliceMs
                                ? (timeout_ms - elapsed)
                                : kSliceMs);
    size_t  bytes_read = 0;
    Status  s = transport->Receive(chunk, sizeof(chunk), &bytes_read, slice);

    if (s == Status::kTransportError) return Status::kTransportError;

    if (bytes_read > 0) {
      framer.FeedBytes(chunk, bytes_read);
    }

    if (timeout_ms != 0) {
      elapsed += kSliceMs;
      if (elapsed >= timeout_ms && !frame_found) return Status::kTimeout;
    }
  }
  return result;
}

}  // namespace protocol
}  // namespace secret_com
