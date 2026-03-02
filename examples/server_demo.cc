// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// server_demo.cc — Example: authorization server running on the ESC device.
//
// Build: cmake --build . --target server_demo
// Run:   ./server_demo /dev/ttyUSB0 115200
//
// IMPORTANT: The device private key MUST be kept secret.  In production,
// store it in a hardware secure element or a protected flash region.

#include <cstdio>
#include <cstring>
#include <memory>

#include "secret_com/auth_server.h"
#include "secret_com/types.h"
#include "src/transport/serial_transport.h"

// ---------------------------------------------------------------------------
// Device key-pair — load from secure storage in production!
// For this demo, placeholder keys are embedded inline.
// Generate a real key pair with:
//   openssl ecparam -name prime256v1 -genkey -noout -out device.pem
//   openssl ec -in device.pem -pubout -out device_pub.pem
// Then convert to raw bytes (see docs/INTEGRATION_GUIDE.md §5).
// ---------------------------------------------------------------------------
static const uint8_t kDevicePublicKey[secret_com::kEcPublicKeySize] = {
  0x04,
  // X (32 B) placeholder
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  // Y (32 B) placeholder
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

static const uint8_t kDevicePrivateKey[secret_com::kEcPrivateKeySize] = {
  // 32-byte scalar placeholder
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
};

// ---------------------------------------------------------------------------
// Simple allow-list (replace with a real database in production)
// ---------------------------------------------------------------------------
static bool IsApprovedDevice(uint32_t device_id) {
  const uint32_t kApproved[] = { 0xDEADBEEF, 0x12345678 };
  for (auto id : kApproved) if (id == device_id) return true;
  return false;
}

int main(int argc, char* argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <serial_port> <baud_rate>\n", argv[0]);
    return 1;
  }

  auto transport = std::make_unique<secret_com::SerialTransport>(
      argv[1], static_cast<uint32_t>(atoi(argv[2])));

  secret_com::CryptoConfig cfg;
  cfg.is_server = true;
  memcpy(cfg.device_public_key,  kDevicePublicKey,  secret_com::kEcPublicKeySize);
  memcpy(cfg.device_private_key, kDevicePrivateKey, secret_com::kEcPrivateKeySize);

  secret_com::AuthServer server;
  secret_com::Status s = server.Initialize(std::move(transport), cfg);
  if (s != secret_com::Status::kOk) {
    fprintf(stderr, "Initialize failed: %s\n", secret_com::StatusToString(s));
    return 1;
  }

  // Register authorization decision callback.
  server.SetAuthVerifyCallback(
      [](const secret_com::AuthRequest& req,
         secret_com::LicenseInfo*       lic) -> bool {
        printf("[Server] Auth request from device 0x%08X for '%s'\n",
               req.client_device_id, req.product_name);

        if (!IsApprovedDevice(req.client_device_id)) {
          printf("[Server] ✗ Device not in allow-list — denying.\n");
          return false;
        }

        // Grant a permanent license.
        lic->type             = secret_com::LicenseType::kPermanent;
        lic->device_id        = req.client_device_id;
        lic->feature_flags    = req.feature_flags & secret_com::kFeatureAll;
        strncpy(lic->product_name, req.product_name, 32);
        // issue_timestamp and device_id are filled by the server automatically.
        printf("[Server] ✓ Authorization granted.\n");
        return true;
      });

  printf("[Server] Listening on %s @ %s baud...\n", argv[1], argv[2]);

  // Handle requests in a blocking loop.
  while (true) {
    s = server.HandleOneRequest(30000);
    if (s == secret_com::Status::kOk) {
      printf("[Server] Exchange complete.\n");
    } else {
      printf("[Server] Exchange failed: %s\n", secret_com::StatusToString(s));
    }
  }

  server.Shutdown();
  return 0;
}
