// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// message_framer.h — Streaming frame parser and blocking send/receive helpers.

#ifndef SECRET_COM_SRC_PROTOCOL_MESSAGE_FRAMER_H_
#define SECRET_COM_SRC_PROTOCOL_MESSAGE_FRAMER_H_

#include <cstdint>
#include <functional>

#include "secret_com/transport.h"
#include "secret_com/types.h"
#include "src/protocol/protocol.h"

namespace secret_com {
namespace protocol {

// ---------------------------------------------------------------------------
// MessageFramer — streaming parser
// ---------------------------------------------------------------------------

/// @brief Incremental byte-stream parser that emits complete frames.
///
/// Feed raw bytes from any source into FeedBytes().  Whenever a complete,
/// CRC-valid frame is assembled, the registered callback is invoked.
///
/// The parser is a simple state machine; it can handle fragmented input and
/// automatically recovers from framing errors by re-synchronizing on the
/// next 0xAA 0x55 sequence.
class MessageFramer {
 public:
  /// @brief Callback invoked for each validated frame.
  ///
  /// @param msg_type    Decoded message type.
  /// @param seq         Sequence number from the frame header.
  /// @param payload     Pointer into internal buffer — valid only during
  ///                    the callback.  Copy data if you need it later.
  /// @param payload_len Payload length in bytes.
  using FrameCallback = std::function<void(uint8_t        msg_type,
                                            uint16_t       seq,
                                            const uint8_t* payload,
                                            uint16_t       payload_len)>;

  MessageFramer();

  /// @brief Register the callback to receive complete frames.
  void SetFrameCallback(FrameCallback callback);

  /// @brief Feed raw bytes into the parser.
  ///
  /// May invoke the registered callback zero or more times.
  void FeedBytes(const uint8_t* data, size_t length);

  /// @brief Reset the parser state (e.g. after a transport reconnect).
  void Reset();

 private:
  enum class ParseState : uint8_t {
    kWaitStart0,   // Waiting for 0xAA
    kWaitStart1,   // Waiting for 0x55
    kReadType,     // 1 byte: message type
    kReadSeqLo,    // 1 byte: sequence low
    kReadSeqHi,    // 1 byte: sequence high
    kReadLenLo,    // 1 byte: payload length low
    kReadLenHi,    // 1 byte: payload length high
    kReadPayload,  // variable: payload bytes
    kReadCrcLo,    // 1 byte: CRC low
    kReadCrcHi,    // 1 byte: CRC high
  };

  void ProcessByte(uint8_t byte);
  void EmitFrame();

  ParseState     state_      = ParseState::kWaitStart0;
  uint8_t        msg_type_   = 0;
  uint16_t       seq_        = 0;
  uint16_t       payload_len_= 0;
  uint16_t       payload_idx_= 0;
  uint8_t        payload_buf_[kMaxPayloadSize];
  uint8_t        header_buf_[kHeaderSize];  // For CRC coverage
  uint16_t       rx_crc_     = 0;

  FrameCallback  callback_;
};

// ---------------------------------------------------------------------------
// Blocking send / receive helpers
// ---------------------------------------------------------------------------

/// @brief Encode and transmit a single frame over @p transport.
///
/// @return kOk or kTransportError.
Status SendFrame(Transport* transport,
                 uint8_t    msg_type,
                 uint16_t   seq,
                 const uint8_t* payload, uint16_t payload_len);

/// @brief Receive bytes until a valid frame matching @p expected_type and
///        @p expected_seq is assembled, or the timeout elapses.
///
/// Frames with unexpected type or sequence number are silently discarded.
///
/// @param[out] payload_buf      Caller-supplied buffer.
/// @param[in]  payload_buf_cap  Buffer capacity.
/// @param[out] payload_len      Bytes written into @p payload_buf.
/// @return kOk, kTimeout, kTransportError, or kProtocolError.
Status RecvFrame(Transport*  transport,
                 uint8_t     expected_type,
                 uint16_t    expected_seq,
                 uint8_t*    payload_buf,  uint16_t  payload_buf_cap,
                 uint16_t*   payload_len,
                 uint32_t    timeout_ms);

}  // namespace protocol
}  // namespace secret_com

#endif  // SECRET_COM_SRC_PROTOCOL_MESSAGE_FRAMER_H_
