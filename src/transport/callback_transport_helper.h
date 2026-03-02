// Copyright 2026 secret_com Authors. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license.

// callback_transport_helper.h — thin include bridge so secret_com_c_api.cc
// can construct a CallbackTransport without depending on the platform headers
// pulled in by serial_transport.h.

#ifndef SECRET_COM_SRC_TRANSPORT_CALLBACK_TRANSPORT_HELPER_H_
#define SECRET_COM_SRC_TRANSPORT_CALLBACK_TRANSPORT_HELPER_H_

// CallbackTransport is declared in transport.h (no platform headers needed).
#include "secret_com/transport.h"

#endif  // SECRET_COM_SRC_TRANSPORT_CALLBACK_TRANSPORT_HELPER_H_
