/* Copyright 2026 secret_com Authors. All rights reserved.
 * Use of this source code is governed by an Apache-2.0 license.
 *
 * c_api_demo.c — Demonstrates the plain-C API for bare-metal / RTOS targets.
 */

#include <stdio.h>
#include <string.h>
#include "secret_com/secret_com.h"

/* ---------------------------------------------------------------------------
 * Stub I/O callbacks — replace with real HAL calls on your target.
 * -------------------------------------------------------------------------*/

static int uart_connect(void* ctx) {
  (void)ctx;
  printf("[HAL] UART opened\n");
  return 1;
}

static void uart_disconnect(void* ctx) {
  (void)ctx;
  printf("[HAL] UART closed\n");
}

static int uart_is_connected(void* ctx) {
  (void)ctx;
  return 1;
}

static int uart_send(void* ctx, const uint8_t* data, size_t len) {
  (void)ctx;
  (void)data;
  printf("[HAL] Sending %zu bytes\n", len);
  return (int)len;  /* stub: pretend all bytes sent */
}

static int uart_recv(void* ctx, uint8_t* buf, size_t max_len,
                     uint32_t timeout_ms) {
  (void)ctx; (void)buf; (void)max_len; (void)timeout_ms;
  return 0;  /* stub: return timeout */
}

/* ---------------------------------------------------------------------------
 * Authorization callback
 * -------------------------------------------------------------------------*/

static void on_auth_done(SecretComStatus       status,
                         const SecretComLicenseInfo* license,
                         void*                 user_data) {
  (void)user_data;
  if (status == kSecretComOk) {
    printf("Authorization granted!\n");
    printf("  Product  : %s\n", license->product_name);
    printf("  DeviceID : 0x%08X\n", license->device_id);
    printf("  Features : 0x%02X\n", license->feature_flags);
  } else {
    printf("Authorization failed: %s\n", SecretComStatusString(status));
  }
}

/* ---------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------*/

int main(void) {
  /* Placeholder device public key (65 bytes, uncompressed P-256). */
  uint8_t device_pub[65];
  memset(device_pub, 0, sizeof(device_pub));
  device_pub[0] = 0x04;  /* Uncompressed marker */

  /* Set up I/O callbacks. */
  SecretComIoCbs io;
  memset(&io, 0, sizeof(io));
  io.user_ctx    = NULL;
  io.connect     = uart_connect;
  io.disconnect  = uart_disconnect;
  io.is_connected= uart_is_connected;
  io.send        = uart_send;
  io.receive     = uart_recv;

  /* Create and initialize client. */
  SecretComClient* client = SecretComClientCreate();
  if (!client) { fprintf(stderr, "Failed to create client\n"); return 1; }

  SecretComStatus s = SecretComClientInit(client, &io, device_pub);
  printf("Init: %s\n", SecretComStatusString(s));

  /* Build authorization request. */
  SecretComAuthRequest req;
  memset(&req, 0, sizeof(req));
  req.client_device_id = 0xDEADBEEF;
  strncpy(req.product_name, "ESC-Pro-X1", sizeof(req.product_name) - 1);
  req.feature_flags = 0xFF;

  /* Request authorization (will fail in this stub since recv returns 0). */
  s = SecretComClientRequestAuth(client, &req, on_auth_done, NULL, 5000);
  printf("RequestAuth: %s\n", SecretComStatusString(s));

  /* In a real application, wait for the callback here (RTOS event flag, etc.)*/

  SecretComClientShutdown(client);
  SecretComClientDestroy(client);
  return 0;
}
