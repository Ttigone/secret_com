// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

#include "src/transport/tcp_transport.h"

#include <cstring>

#if defined(SECRETCOM_TCP_POSIX)
  #include <arpa/inet.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

namespace secret_com {

// ---------------------------------------------------------------------------
// Common helpers
// ---------------------------------------------------------------------------

#if defined(SECRETCOM_TCP_WINDOWS)
static void CloseSocket(SocketFd s) { closesocket(s); }
#else
static void CloseSocket(SocketFd s) { close(s); }
#endif

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

TcpTransport::TcpTransport(std::string host, uint16_t port)
    : host_(std::move(host)), port_(port) {}

TcpTransport::~TcpTransport() { Disconnect(); }

bool TcpTransport::IsConnected() const { return connected_; }

// ---------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------

Status TcpTransport::Connect() {
  if (connected_) return Status::kOk;

#if defined(SECRETCOM_TCP_WINDOWS)
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return Status::kTransportError;
#endif

  struct addrinfo hints;
  struct addrinfo* res = nullptr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", port_);

  if (getaddrinfo(host_.c_str(), port_str, &hints, &res) != 0)
    return Status::kTransportError;

  Status result = Status::kTransportError;
  for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
    sock_ = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock_ == kInvalidSocket) continue;

    // Enable TCP_NODELAY for low-latency serial emulation.
    int nodelay = 1;
    setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    if (connect(sock_, p->ai_addr,
                static_cast<int>(p->ai_addrlen)) == 0) {
      result = Status::kOk;
      break;
    }
    CloseSocket(sock_);
    sock_ = kInvalidSocket;
  }
  freeaddrinfo(res);

  if (result == Status::kOk) connected_ = true;
  return result;
}

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

void TcpTransport::Disconnect() {
  if (sock_ != kInvalidSocket) {
    CloseSocket(sock_);
    sock_ = kInvalidSocket;
  }
  connected_ = false;
#if defined(SECRETCOM_TCP_WINDOWS)
  WSACleanup();
#endif
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

Status TcpTransport::Send(const uint8_t* data, size_t length) {
  if (!connected_) return Status::kTransportError;
  size_t sent = 0;
  while (sent < length) {
#if defined(SECRETCOM_TCP_WINDOWS)
    int n = send(sock_, reinterpret_cast<const char*>(data + sent),
                  static_cast<int>(length - sent), 0);
#else
    ssize_t n = send(sock_, data + sent, length - sent, MSG_NOSIGNAL);
#endif
    if (n <= 0) {
      connected_ = false;
      return Status::kTransportError;
    }
    sent += static_cast<size_t>(n);
  }
  return Status::kOk;
}

// ---------------------------------------------------------------------------
// Receive
// ---------------------------------------------------------------------------

Status TcpTransport::Receive(uint8_t* buffer, size_t max_length,
                              size_t* bytes_read, uint32_t timeout_ms) {
  if (!connected_) return Status::kTransportError;
  *bytes_read = 0;

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sock_, &rfds);

  struct timeval tv;
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

#if defined(SECRETCOM_TCP_WINDOWS)
  int nfds = 0;  // Ignored on Windows.
#else
  int nfds = static_cast<int>(sock_) + 1;
#endif

  int ret = select(nfds, &rfds, nullptr, nullptr,
                   timeout_ms == 0 ? nullptr : &tv);
  if (ret == 0) return Status::kTimeout;
  if (ret < 0)  return Status::kTransportError;

#if defined(SECRETCOM_TCP_WINDOWS)
  int n = recv(sock_, reinterpret_cast<char*>(buffer),
                static_cast<int>(max_length), 0);
#else
  ssize_t n = recv(sock_, buffer, max_length, 0);
#endif
  if (n <= 0) {
    connected_ = false;
    return Status::kTransportError;
  }
  *bytes_read = static_cast<size_t>(n);
  return Status::kOk;
}

}  // namespace secret_com
