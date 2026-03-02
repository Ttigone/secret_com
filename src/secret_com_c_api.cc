// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// secret_com_c_api.cc — C shim over the C++ AuthClient / AuthServer.

#include "secret_com/secret_com.h"

#include <cstring>
#include <memory>

#include "secret_com/auth_client.h"
#include "secret_com/auth_server.h"
#include "src/transport/callback_transport_helper.h"

using namespace secret_com;

// ---------------------------------------------------------------------------
// Internal helper — build a CallbackTransport from SecretComIoCbs
// ---------------------------------------------------------------------------
static std::unique_ptr<Transport> MakeTransport(const SecretComIoCbs* io) {
  CallbackTransport::Callbacks cbs;
  void* ctx = io->user_ctx;

  cbs.connect      = [io, ctx]() -> bool {
    return io->connect && io->connect(ctx) != 0;
  };
  cbs.disconnect   = [io, ctx]() {
    if (io->disconnect) io->disconnect(ctx);
  };
  cbs.is_connected = [io, ctx]() -> bool {
    return io->is_connected && io->is_connected(ctx) != 0;
  };
  cbs.send = [io, ctx](const uint8_t* d, size_t n) -> int {
    return io->send ? io->send(ctx, d, n) : -1;
  };
  cbs.receive = [io, ctx](uint8_t* b, size_t n, uint32_t t) -> int {
    return io->receive ? io->receive(ctx, b, n, t) : -1;
  };

  return std::make_unique<CallbackTransport>(cbs);
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct SecretComClient_ {
  AuthClient cpp;
};

SecretComClient* SecretComClientCreate(void) {
  return new SecretComClient_();
}

void SecretComClientDestroy(SecretComClient* c) {
  if (c) { c->cpp.Shutdown(); delete c; }
}

SecretComStatus SecretComClientInit(SecretComClient*       client,
                                    const SecretComIoCbs*  io,
                                    const uint8_t          device_public_key[65]) {
  if (!client || !io || !device_public_key) return kSecretComInvalidParam;

  CryptoConfig cfg;
  memcpy(cfg.device_public_key, device_public_key, kEcPublicKeySize);
  cfg.is_server = false;

  Status s = client->cpp.Initialize(MakeTransport(io), cfg);
  return static_cast<SecretComStatus>(static_cast<int>(s));
}

SecretComStatus SecretComClientRequestAuth(
    SecretComClient*            client,
    const SecretComAuthRequest* request,
    SecretComAuthCallback       callback,
    void*                       user_data,
    uint32_t                    timeout_ms) {
  if (!client || !request || !callback) return kSecretComInvalidParam;

  AuthRequest req;
  req.client_device_id = request->client_device_id;
  memcpy(req.product_name, request->product_name, 32);
  req.feature_flags = request->feature_flags;

  Status s = client->cpp.RequestAuthorization(
      req,
      [callback, user_data](Status st, const LicenseInfo& lic) {
        SecretComLicenseInfo out;
        memset(&out, 0, sizeof(out));
        out.license_type      = static_cast<uint8_t>(lic.type);
        out.device_id         = lic.device_id;
        out.issue_timestamp   = lic.issue_timestamp;
        out.expiry_timestamp  = lic.expiry_timestamp;
        out.remaining_uses    = lic.remaining_uses;
        out.feature_flags     = lic.feature_flags;
        memcpy(out.product_name, lic.product_name, 32);
        callback(static_cast<SecretComStatus>(static_cast<int>(st)),
                 &out, user_data);
      },
      timeout_ms == 0 ? 10000 : timeout_ms);
  return static_cast<SecretComStatus>(static_cast<int>(s));
}

int SecretComClientIsAuthorized(const SecretComClient* client) {
  return client && client->cpp.IsAuthorized() ? 1 : 0;
}

SecretComStatus SecretComClientGetLicense(const SecretComClient* client,
                                           SecretComLicenseInfo*  out) {
  if (!client || !out) return kSecretComInvalidParam;
  if (!client->cpp.IsAuthorized()) return kSecretComAuthFailed;
  LicenseInfo lic = client->cpp.GetLicenseInfo();
  out->license_type     = static_cast<uint8_t>(lic.type);
  out->device_id        = lic.device_id;
  out->issue_timestamp  = lic.issue_timestamp;
  out->expiry_timestamp = lic.expiry_timestamp;
  out->remaining_uses   = lic.remaining_uses;
  out->feature_flags    = lic.feature_flags;
  memcpy(out->product_name, lic.product_name, 32);
  return kSecretComOk;
}

void SecretComClientShutdown(SecretComClient* client) {
  if (client) client->cpp.Shutdown();
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct SecretComServer_ {
  AuthServer cpp;
  SecretComVerifyCb verify_cb  = nullptr;
  void*             verify_ctx = nullptr;
};

SecretComServer* SecretComServerCreate(void) {
  return new SecretComServer_();
}

void SecretComServerDestroy(SecretComServer* s) {
  if (s) { s->cpp.Shutdown(); delete s; }
}

SecretComStatus SecretComServerInit(SecretComServer*      server,
                                    const SecretComIoCbs* io,
                                    const uint8_t device_public_key[65],
                                    const uint8_t device_private_key[32]) {
  if (!server || !io || !device_public_key || !device_private_key)
    return kSecretComInvalidParam;

  CryptoConfig cfg;
  cfg.is_server = true;
  memcpy(cfg.device_public_key,  device_public_key,  kEcPublicKeySize);
  memcpy(cfg.device_private_key, device_private_key, kEcPrivateKeySize);

  Status s = server->cpp.Initialize(MakeTransport(io), cfg);
  return static_cast<SecretComStatus>(static_cast<int>(s));
}

void SecretComServerSetVerifyCb(SecretComServer* server,
                                 SecretComVerifyCb cb, void* user_data) {
  if (!server) return;
  server->verify_cb  = cb;
  server->verify_ctx = user_data;
  server->cpp.SetAuthVerifyCallback(
      [server](const AuthRequest& req, LicenseInfo* lic) -> bool {
        if (!server->verify_cb) return false;
        SecretComAuthRequest creq;
        creq.client_device_id = req.client_device_id;
        memcpy(creq.product_name, req.product_name, 32);
        creq.feature_flags = req.feature_flags;
        SecretComLicenseInfo clic;
        memset(&clic, 0, sizeof(clic));
        int granted = server->verify_cb(&creq, &clic, server->verify_ctx);
        if (granted) {
          lic->type             = static_cast<LicenseType>(clic.license_type);
          lic->device_id        = clic.device_id;
          lic->issue_timestamp  = clic.issue_timestamp;
          lic->expiry_timestamp = clic.expiry_timestamp;
          lic->remaining_uses   = clic.remaining_uses;
          lic->feature_flags    = clic.feature_flags;
          memcpy(lic->product_name, clic.product_name, 32);
        }
        return granted != 0;
      });
}

SecretComStatus SecretComServerHandleOne(SecretComServer* server,
                                          uint32_t         timeout_ms) {
  if (!server) return kSecretComInvalidParam;
  Status s = server->cpp.HandleOneRequest(timeout_ms == 0 ? 30000 : timeout_ms);
  return static_cast<SecretComStatus>(static_cast<int>(s));
}

SecretComStatus SecretComServerStartListening(SecretComServer* server) {
  if (!server) return kSecretComInvalidParam;
  Status s = server->cpp.StartListening();
  return static_cast<SecretComStatus>(static_cast<int>(s));
}

void SecretComServerShutdown(SecretComServer* server) {
  if (server) server->cpp.Shutdown();
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

const char* SecretComStatusString(SecretComStatus status) {
  return StatusToString(static_cast<Status>(static_cast<int>(status)));
}
