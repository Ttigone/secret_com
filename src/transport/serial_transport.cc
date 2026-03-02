// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

#include "src/transport/serial_transport.h"

#include <cstring>

#if defined(SECRETCOM_PLATFORM_POSIX)
  #include <errno.h>
  #include <fcntl.h>
  #include <sys/select.h>
  #include <termios.h>
  #include <unistd.h>
#endif

namespace secret_com {

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

SerialTransport::SerialTransport(std::string port_name, uint32_t baud_rate)
    : port_name_(std::move(port_name)), baud_rate_(baud_rate) {}

SerialTransport::~SerialTransport() { Disconnect(); }

bool SerialTransport::IsConnected() const { return connected_; }

// ===========================================================================
// POSIX implementation
// ===========================================================================
#if defined(SECRETCOM_PLATFORM_POSIX)

static speed_t BaudToSpeed(uint32_t baud) {
  switch (baud) {
    case 9600:   return B9600;
    case 19200:  return B19200;
    case 38400:  return B38400;
    case 57600:  return B57600;
    case 115200: return B115200;
    case 230400: return B230400;
#ifdef B460800
    case 460800: return B460800;
#endif
#ifdef B921600
    case 921600: return B921600;
#endif
    default:     return B115200;
  }
}

Status SerialTransport::Connect() {
  if (connected_) return Status::kOk;

  fd_ = open(port_name_.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (fd_ < 0) return Status::kTransportError;

  // Configure raw mode.
  struct termios tty;
  memset(&tty, 0, sizeof(tty));
  if (tcgetattr(fd_, &tty) != 0) {
    close(fd_);
    fd_ = -1;
    return Status::kTransportError;
  }

  speed_t speed = BaudToSpeed(baud_rate_);
  cfsetospeed(&tty, speed);
  cfsetispeed(&tty, speed);

  cfmakeraw(&tty);              // 8N1, no flow control, raw I/O
  tty.c_cc[VMIN]  = 0;          // Non-blocking read
  tty.c_cc[VTIME] = 0;

  if (tcsetattr(fd_, TCSANOW, &tty) != 0) {
    close(fd_);
    fd_ = -1;
    return Status::kTransportError;
  }

  // Switch to blocking (we use select() for timeout).
  int flags = fcntl(fd_, F_GETFL, 0);
  fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);

  tcflush(fd_, TCIOFLUSH);
  connected_ = true;
  return Status::kOk;
}

void SerialTransport::Disconnect() {
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
  connected_ = false;
}

Status SerialTransport::Send(const uint8_t* data, size_t length) {
  if (!connected_) return Status::kTransportError;
  size_t written = 0;
  while (written < length) {
    ssize_t n = write(fd_, data + written, length - written);
    if (n < 0) return Status::kTransportError;
    written += static_cast<size_t>(n);
  }
  return Status::kOk;
}

Status SerialTransport::Receive(uint8_t* buffer, size_t max_length,
                                 size_t* bytes_read, uint32_t timeout_ms) {
  if (!connected_) return Status::kTransportError;
  *bytes_read = 0;

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd_, &rfds);

  struct timeval tv;
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  int ret = select(fd_ + 1, &rfds, nullptr, nullptr,
                   timeout_ms == 0 ? nullptr : &tv);
  if (ret == 0) return Status::kTimeout;
  if (ret < 0)  return Status::kTransportError;

  ssize_t n = read(fd_, buffer, max_length);
  if (n < 0) return Status::kTransportError;
  *bytes_read = static_cast<size_t>(n);
  return Status::kOk;
}

// ===========================================================================
// Windows implementation
// ===========================================================================
#elif defined(SECRETCOM_PLATFORM_WINDOWS)

Status SerialTransport::Connect() {
  if (connected_) return Status::kOk;

  handle_ = CreateFileA(port_name_.c_str(),
                         GENERIC_READ | GENERIC_WRITE,
                         0, nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle_ == INVALID_HANDLE_VALUE) return Status::kTransportError;

  DCB dcb;
  memset(&dcb, 0, sizeof(dcb));
  dcb.DCBlength = sizeof(dcb);
  if (!GetCommState(handle_, &dcb)) {
    CloseHandle(handle_);
    handle_ = INVALID_HANDLE_VALUE;
    return Status::kTransportError;
  }

  dcb.BaudRate = static_cast<DWORD>(baud_rate_);
  dcb.ByteSize = 8;
  dcb.StopBits = ONESTOPBIT;
  dcb.Parity   = NOPARITY;
  dcb.fBinary  = TRUE;
  dcb.fParity  = FALSE;
  dcb.fOutxCtsFlow = FALSE;
  dcb.fOutxDsrFlow = FALSE;
  dcb.fDtrControl  = DTR_CONTROL_DISABLE;
  dcb.fRtsControl  = RTS_CONTROL_DISABLE;

  if (!SetCommState(handle_, &dcb)) {
    CloseHandle(handle_);
    handle_ = INVALID_HANDLE_VALUE;
    return Status::kTransportError;
  }

  COMMTIMEOUTS timeouts;
  memset(&timeouts, 0, sizeof(timeouts));
  // Timeouts set per-call via ReadFile; configure to return immediately.
  timeouts.ReadIntervalTimeout         = MAXDWORD;
  timeouts.ReadTotalTimeoutMultiplier  = 0;
  timeouts.ReadTotalTimeoutConstant    = 0;
  SetCommTimeouts(handle_, &timeouts);

  PurgeComm(handle_, PURGE_RXCLEAR | PURGE_TXCLEAR);
  connected_ = true;
  return Status::kOk;
}

void SerialTransport::Disconnect() {
  if (handle_ != INVALID_HANDLE_VALUE) {
    CloseHandle(handle_);
    handle_ = INVALID_HANDLE_VALUE;
  }
  connected_ = false;
}

Status SerialTransport::Send(const uint8_t* data, size_t length) {
  if (!connected_) return Status::kTransportError;
  DWORD written = 0;
  if (!WriteFile(handle_, data, static_cast<DWORD>(length), &written,
                  nullptr))
    return Status::kTransportError;
  return (written == static_cast<DWORD>(length)) ? Status::kOk
                                                  : Status::kTransportError;
}

Status SerialTransport::Receive(uint8_t* buffer, size_t max_length,
                                 size_t* bytes_read, uint32_t timeout_ms) {
  if (!connected_) return Status::kTransportError;
  *bytes_read = 0;

  // Use WaitCommEvent + ReadFile for timed read.
  COMMTIMEOUTS ct;
  ct.ReadIntervalTimeout         = 0;
  ct.ReadTotalTimeoutMultiplier  = 0;
  ct.ReadTotalTimeoutConstant    = (timeout_ms == 0) ? 0 : timeout_ms;
  ct.WriteTotalTimeoutMultiplier = 0;
  ct.WriteTotalTimeoutConstant   = 0;
  SetCommTimeouts(handle_, &ct);

  DWORD n = 0;
  if (!ReadFile(handle_, buffer, static_cast<DWORD>(max_length), &n, nullptr))
    return Status::kTransportError;

  *bytes_read = static_cast<size_t>(n);
  return (n == 0) ? Status::kTimeout : Status::kOk;
}

#endif  // Platform implementations

// ---------------------------------------------------------------------------
// CallbackTransport implementation (shared, platform-independent)
// ---------------------------------------------------------------------------

CallbackTransport::CallbackTransport(const Callbacks& callbacks)
    : callbacks_(callbacks) {}

Status CallbackTransport::Connect() {
  if (!callbacks_.connect) return Status::kInvalidParam;
  connected_ = callbacks_.connect();
  return connected_ ? Status::kOk : Status::kTransportError;
}

void CallbackTransport::Disconnect() {
  if (callbacks_.disconnect) callbacks_.disconnect();
  connected_ = false;
}

bool CallbackTransport::IsConnected() const {
  if (callbacks_.is_connected) return callbacks_.is_connected();
  return connected_;
}

Status CallbackTransport::Send(const uint8_t* data, size_t length) {
  if (!callbacks_.send) return Status::kInvalidParam;
  int ret = callbacks_.send(data, length);
  return (ret >= 0 && static_cast<size_t>(ret) == length) ? Status::kOk
                                                           : Status::kTransportError;
}

Status CallbackTransport::Receive(uint8_t* buffer, size_t max_length,
                                   size_t* bytes_read,
                                   uint32_t timeout_ms) {
  if (!callbacks_.receive) return Status::kInvalidParam;
  int ret = callbacks_.receive(buffer, max_length, timeout_ms);
  if (ret < 0) return Status::kTransportError;
  if (ret == 0) {
    *bytes_read = 0;
    return Status::kTimeout;
  }
  *bytes_read = static_cast<size_t>(ret);
  return Status::kOk;
}

}  // namespace secret_com
