// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// transport.h — Abstract transport interface and built-in callback transport.

#ifndef SECRET_COM_INCLUDE_SECRET_COM_TRANSPORT_H_
#define SECRET_COM_INCLUDE_SECRET_COM_TRANSPORT_H_

#include <cstddef>
#include <cstdint>
#include <functional>

#include "secret_com/types.h"

namespace secret_com {

// ---------------------------------------------------------------------------
// Abstract transport interface
// ---------------------------------------------------------------------------

/// @brief Pure-virtual interface representing a bidirectional byte channel.
///
/// Implement this class to support any physical transport layer:
/// serial (UART), TCP/IP, BLE, CAN, etc.  Two concrete implementations
/// are provided by this library:
///
///   - SerialTransport  — POSIX / Win32 serial port.
///   - TcpTransport     — POSIX / Winsock TCP client.
///   - CallbackTransport — user-provided function pointers (bare-metal / RTOS).
///
/// Thread-safety: the library calls Send() and Receive() from a single
/// background thread.  Implementations need not be internally thread-safe.
class Transport {
 public:
  virtual ~Transport() = default;

  /// @brief Open the channel to the remote endpoint.
  /// @return kOk on success; kTransportError otherwise.
  virtual Status Connect() = 0;

  /// @brief Close the channel and release OS resources.
  virtual void Disconnect() = 0;

  /// @brief True if the channel is currently open.
  virtual bool IsConnected() const = 0;

  /// @brief Transmit exactly @p length bytes.
  ///
  /// Implementations must block until all bytes are sent or an error occurs.
  ///
  /// @param data    Source buffer; must not be NULL.
  /// @param length  Number of bytes to send; must be > 0.
  /// @return kOk on success; kTransportError on I/O error.
  virtual Status Send(const uint8_t* data, size_t length) = 0;

  /// @brief Receive up to @p max_length bytes with a timeout.
  ///
  /// Implementations must block until at least one byte is received, the
  /// timeout expires, or an error occurs.
  ///
  /// @param buffer      Destination buffer; must not be NULL.
  /// @param max_length  Capacity of @p buffer; must be > 0.
  /// @param bytes_read  Set to the number of bytes actually written into
  ///                    @p buffer; set to 0 on timeout.
  /// @param timeout_ms  Milliseconds to wait; 0 = block indefinitely.
  /// @return kOk, kTimeout, or kTransportError.
  virtual Status Receive(uint8_t* buffer, size_t max_length,
                         size_t* bytes_read, uint32_t timeout_ms) = 0;
};

// ---------------------------------------------------------------------------
// Callback-based transport  (bare-metal / RTOS / custom HAL)
// ---------------------------------------------------------------------------

/// @brief Transport backed by caller-supplied function objects.
///
/// Use this for targets where the standard SerialTransport / TcpTransport do
/// not compile (e.g. bare-metal ARM, FreeRTOS, custom DMA ring buffers).
///
/// Example:
/// @code
///   CallbackTransport::Callbacks cbs;
///   cbs.connect      = []{ return uart_open(UART1) == 0; };
///   cbs.disconnect   = []{ uart_close(UART1); };
///   cbs.is_connected = []{ return uart_is_open(UART1); };
///   cbs.send = [](const uint8_t* d, size_t n){ return (int)uart_write(d,n); };
///   cbs.receive = [](uint8_t* b, size_t n, uint32_t t){
///       return (int)uart_read_timeout(b, n, t);
///   };
///   auto transport = std::make_unique<CallbackTransport>(cbs);
/// @endcode
class CallbackTransport : public Transport {
 public:
  struct Callbacks {
    /// Open the channel.  Return true on success.
    std::function<bool()> connect;
    /// Close the channel.
    std::function<void()> disconnect;
    /// Return true if the channel is open.
    std::function<bool()> is_connected;
    /// Write @p len bytes from @p data.
    /// Return number of bytes written, or -1 on error.
    std::function<int(const uint8_t* data, size_t len)> send;
    /// Read up to @p max_len bytes into @p buf within @p timeout_ms.
    /// Return bytes read (>= 1), 0 on timeout, or -1 on error.
    std::function<int(uint8_t* buf, size_t max_len, uint32_t timeout_ms)>
        receive;
  };

  explicit CallbackTransport(const Callbacks& callbacks);

  Status Connect() override;
  void   Disconnect() override;
  bool   IsConnected() const override;
  Status Send(const uint8_t* data, size_t length) override;
  Status Receive(uint8_t* buffer, size_t max_length, size_t* bytes_read,
                 uint32_t timeout_ms) override;

 private:
  Callbacks callbacks_;
  bool      connected_ = false;
};

}  // namespace secret_com

#endif  // SECRET_COM_INCLUDE_SECRET_COM_TRANSPORT_H_
