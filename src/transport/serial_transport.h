// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// serial_transport.h — UART/serial-port transport (POSIX + Win32).

#ifndef SECRET_COM_SRC_TRANSPORT_SERIAL_TRANSPORT_H_
#define SECRET_COM_SRC_TRANSPORT_SERIAL_TRANSPORT_H_

#include <cstdint>
#include <string>

#include "secret_com/transport.h"
#include "secret_com/types.h"

// Platform detection.
#if defined(_WIN32) || defined(_WIN64)
  #define SECRETCOM_PLATFORM_WINDOWS
  #include <windows.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
  #define SECRETCOM_PLATFORM_POSIX
#else
  // Bare-metal: use CallbackTransport instead.
  #error "SerialTransport requires POSIX or Windows. \
Use CallbackTransport for bare-metal targets."
#endif

namespace secret_com {

/// @brief Serial-port transport for POSIX (Linux/macOS) and Windows.
///
/// Opens the port on Connect() and closes it on Disconnect().
/// Baud rate and other parameters are configured in the constructor.
///
/// Example:
/// @code
///   // Linux
///   auto t = std::make_unique<SerialTransport>("/dev/ttyUSB0", 115200);
///   // Windows
///   auto t = std::make_unique<SerialTransport>("\\\\.\\COM3", 115200);
/// @endcode
class SerialTransport : public Transport {
 public:
  /// @brief Construct a serial transport.
  /// @param port_name  Device path (e.g. "/dev/ttyUSB0" or "\\\\.\\COM3").
  /// @param baud_rate  Baud rate (e.g. 9600, 115200, 230400).
  SerialTransport(std::string port_name, uint32_t baud_rate);
  ~SerialTransport() override;

  // Not copyable.
  SerialTransport(const SerialTransport&) = delete;
  SerialTransport& operator=(const SerialTransport&) = delete;

  Status Connect() override;
  void   Disconnect() override;
  bool   IsConnected() const override;
  Status Send(const uint8_t* data, size_t length) override;
  Status Receive(uint8_t* buffer, size_t max_length, size_t* bytes_read,
                 uint32_t timeout_ms) override;

 private:
  std::string port_name_;
  uint32_t    baud_rate_;
  bool        connected_ = false;

#if defined(SECRETCOM_PLATFORM_WINDOWS)
  HANDLE handle_ = INVALID_HANDLE_VALUE;
#elif defined(SECRETCOM_PLATFORM_POSIX)
  int fd_ = -1;
#endif
};

}  // namespace secret_com

#endif  // SECRET_COM_SRC_TRANSPORT_SERIAL_TRANSPORT_H_
