# secret_com

> 这是一个为嵌入式和桌面平台设计的跨平台 C/C++ 授权组件库。
> 通过 UART、TCP、BLE 或任何自定义通信接口（Transport）实现基于密码学的挑战-应答（Challenge-Response）授权认证。

---

## 架构概述 (RK3506 -> ESC 授权架构)

`secret_com` 提供了一套完整的设备间的授权验证机制。在我们的典型应用场景中，**RK3506 作为授权管理设备（AuthServer/Signer）**，而 **ESC（电调）作为请求授权的设备（AuthClient/Verifier）**。

- **RK3506 (AuthServer/签发端)**：持有私钥，负责审批 ESC 的授权请求，并签发并下发授权凭证（License Token）。
- **ESC (AuthClient/验证端)**：出厂时内置 RK3506 的公钥，启动时向 RK3506 发起授权请求。仅在成功验证 RK3506 下发且经过其私钥签名的授权凭证后，ESC 才会解锁运行权限。

所有的通信均受以下安全机制保护：

- **ECDH (P-256) 密钥交换**：收发两端通过算法协商出临时的会话密钥，该密钥绝不再链路上明文传输。
- **AES-256-GCM 加密机制**：所有的授权负荷（Payload）都经过加密与防篡改认证。
- **ECDSA (P-256) 数字签名**：服务器（RK3506）的身份以及下发的授权凭证均经过强密码学签名，即使串口数据遭到完全监听，攻击者也无法伪造授权。

---

## 核心特性

| 特性 | 描述 |
|---------|---------|
| 密码学核心 | 基于 mbedTLS 2.x / 3.x (涵盖 ECDH, ECDSA, AES-256-GCM, HKDF-SHA256) |
| 传输层接口 | 支持 串口 (POSIX + Win32)、TCP 以及 回调接口 (适用于裸机/RTOS 自定义传输) |
| API 支持 | 简洁的 C++14 API；提供 `extern "C"` 封装，方便纯 C 或裸机项目接入 |
| 跨平台支持 | Linux, Windows, macOS, 嵌入式 Linux, FreeRTOS (通过 CallbackTransport) |
| 构建系统 | CMake 3.16+，使用 FetchContent 自动拉取 mbedTLS |
| 代码规范 | 遵循 Google C++ 标准；自带 `.clang-format` 配置文件 |

---

## 快速上手

### 编译构建

```bash
git clone https://github.com/yourorg/secret_com.git
cd secret_com
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### 运行 Demo

```bash
# 终端 1 — 服务端 (RK3506 授权控制端)
./build/examples/server_demo /dev/ttyUSB0 115200

# 终端 2 — 客户端 (ESC 电调端)
./build/examples/client_demo /dev/ttyUSB1 115200
```

---

## 目录结构

```
secret_com/
├── include/secret_com/       对外开放的 API 头文件
│   ├── types.h               状态码, 授权信息, 授权请求定义
│   ├── transport.h           抽象传输层接口及回调传输实现
│   ├── crypto_provider.h     抽象密码学算法接口
│   ├── auth_client.h         AuthClient 客户端类 (ESC端)
│   ├── auth_server.h         AuthServer 服务端类 (RK3506端)
│   └── secret_com.h          提供给 C 语言的接口 (extern "C")
│
├── src/
│   ├── auth_client.cc        客户端状态机实现
│   ├── auth_server.cc        服务端状态机实现
│   ├── secret_com_c_api.cc   基于 C++ 类的 C 语言适配层
│   ├── protocol/
│   │   ├── protocol.h        协议报文常量与序列化
│   │   ├── message_framer.h
│   │   └── message_framer.cc CRC16 帧定界与比特流解析
│   ├── crypto/
│   │   ├── mbedtls_provider.h
│   │   └── mbedtls_provider.cc  基于 mbedTLS 的底层密码学实现
│   └── transport/
│       ├── serial_transport.h/.cc   POSIX + Win32 串口支持
│       └── tcp_transport.h/.cc      POSIX + Winsock TCP 支持
│
├── examples/
│   ├── client_demo.cc        客户端示例
│   ├── server_demo.cc        服务端示例
│   └── c_api_demo.c          C API 示例
│
├── docs/
│   ├── ARCHITECTURE.md       架构分层设计与安全属性
│   ├── PROTOCOL_SPEC.md      通讯协议格式与密钥派生规范
│   ├── API_REFERENCE.md      完整的 API 参考手册
│   └── INTEGRATION_GUIDE.md  ESC 与客户端的逐步集成指南
│
├── CMakeLists.txt
└── .clang-format             Google 代码格式化预设
```

---

## 安全模型（摘要）

```
客户端 (ESC 电调端)                    服务端 (RK3506 授权控制端)
────────────────────                  ────────────────────────
编译时内置 RK3506 的公钥 (public_key)    ←── 硬件级安全存储私钥 (private_key)(如 OTP/Secure Flash)

每次连接会话 (Per-session):
  生成 客户端临时公钥 + 随机数    ──►    使用 服务端硬件公钥 进行身份校验
                                  ◄──    下发 服务端临时公钥 + 随机数 + ECDSA 签名
  共享密钥 = ECDH(双方公钥)               共享密钥 = ECDH(双方公钥)
  会话密钥 = HKDF(共享密钥)               会话密钥 = HKDF(共享密钥)
  ──────────── 开启 AES-256-GCM 安全隧道 ────────────────────────────
  发送加密的授权请求              ──►    解密请求，回调上层业务逻辑判断是否授权
                                  ◄──    加密下发授权凭证(License) + ECDSA 签名
  使用内置公钥验证凭证签名             
  校验通过则解锁电调功能
```

**防重放与防监听的设计**：由于每次会话的密钥都是通过 ECDH 动态协商派生的，且从未在数据链路中发送，即便是攻击者截获了所有的串口通讯数据，也无法解密出任何明文内容或重放旧的授权。

---

## 技术文档推荐

| 文档 | 内容描述 |
|----------|---------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | 分层架构图、线程安全模型以及深度的安全机制解析 |
| [PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md) | 报文字节排列、消息类型定义、密码学派生细节 |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | 所有对外公开的类与函数速查 |
| [INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) | 手把手教你如何生成密钥并整合到 ESC 固件中 |

---

## 开源协议

Apache 2.0 — 详情请参见 `LICENSE`。
