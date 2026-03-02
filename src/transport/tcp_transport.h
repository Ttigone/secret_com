// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// tcp_transport.h — TCP client transport (POSIX + Winsock).

#ifndef SECRET_COM_SRC_TRANSPORT_TCP_TRANSPORT_H_
#define SECRET_COM_SRC_TRANSPORT_TCP_TRANSPORT_H_

#include <cstdint>
#include <string>

#include "secret_com/transport.h"
#include "secret_com/types.h"

#if defined(_WIN32) || defined(_WIN64)
  #define SECRETCOM_TCP_WINDOWS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  using SocketFd = SOCKET;
  static constexpr SocketFd kInvalidSocket = INVALID_SOCKET;
#else
  #define SECRETCOM_TCP_POSIX
  using SocketFd = int;
  static constexpr SocketFd kInvalidSocket = -1;
#endif

namespace secret_com {

/// @brief TCP/IP client transport.
///
/// Connects to a remote server (e.g., an authorization relay) at
/// construction-specified address and port.
///
/// Example:
/// @code
///   auto t = std::make_unique<TcpTransport>("192.168.1.100", 7777);
///   client.Initialize(std::move(t), cfg);
/// @endcode
class TcpTransport : public Transport {
 public:
  TcpTransport(std::string host, uint16_t port);
  ~TcpTransport() override;

  TcpTransport(const TcpTransport&)            = delete;
  TcpTransport& operator=(const TcpTransport&) = delete;

  Status Connect() override;
  void   Disconnect() override;
  bool   IsConnected() const override;
  Status Send(const uint8_t* data, size_t length) override;
  Status Receive(uint8_t* buffer, size_t max_length, size_t* bytes_read,
                 uint32_t timeout_ms) override;

 private:
  std::string host_;
  uint16_t    port_;
  SocketFd    sock_      = kInvalidSocket;
  bool        connected_ = false;
};

}  // namespace secret_com

#endif  // SECRET_COM_SRC_TRANSPORT_TCP_TRANSPORT_H_
