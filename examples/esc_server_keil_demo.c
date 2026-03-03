/* =============================================================================
 * esc_server_keil_demo.c
 *
 * 电调（ESC）端授权服务 —— Keil MDK / ARM Cortex-M 裸机示例
 *
 * 覆盖三种典型授权场景:
 *  [A] 在线授权   (Online)  — 飞控上电后，通过 UART 实时握手，每次上电验一次
 *  [B] 离线预授权 (Offline) — 出厂烧录时，工具将签名凭证写入内部 Flash/OTP，
 *                             运行时仅做本地签名校验，无需连线
 *  [C] 远程激活   (Remote)  — 飞控首次连网后，从云端获取授权包并写入 Flash，
 *                             此后等同场景 B
 *
 * 文件角色:
 *   本文件运行在 ESC 芯片上（服务端 / AuthServer 侧）。
 *   飞控（客户端）运行对应的 AuthClient。
 *
 * 编译要求:
 *   - 将 secret_com 库的 .lib / .a 加入 Keil 工程
 *   - Options → C/C++ → Define: SCENARIO_ONLINE=1 (或 OFFLINE/REMOTE)
 *   - 包含路径添加 secret_com/include
 *   - 目标芯片: Cortex-M4/M7 (3.3V UART, 内部 Flash 可写)
 *
 * Copyright 2026 secret_com Authors. Apache-2.0 License.
 * =============================================================================
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "secret_com/secret_com.h"

/* ---------------------------------------------------------------------------
 * 场景选择 —— 在 Keil Options → C/C++ → Preprocessor Symbols 中定义其中一个
 * -------------------------------------------------------------------------*/
#if !defined(SCENARIO_ONLINE) && !defined(SCENARIO_OFFLINE) && !defined(SCENARIO_REMOTE)
#  define SCENARIO_ONLINE  1   /* 默认: 在线授权 */
#endif

/* ===========================================================================
 * 1. 硬件 / HAL 抽象层（替换成你的实际外设驱动）
 * =========================================================================*/

/* ----------  UART (飞控 ↔ ESC 通信 UART，通常 UART2 或 UART3)  ---------- */
#include "stm32f4xx_hal.h"   /* 替换为你的 MCU HAL 头文件 */

extern UART_HandleTypeDef huart2;  /* 在 main.c / CubeMX 生成文件中声明 */

/* 单字节轮询超时发送（在中断/DMA 版本中替换此函数） */
static int hal_uart_send(void* ctx, const uint8_t* data, size_t len)
{
    (void)ctx;
    HAL_StatusTypeDef r = HAL_UART_Transmit(&huart2, (uint8_t*)data,
                                             (uint16_t)len, 50U);
    return (r == HAL_OK) ? (int)len : -1;
}

static int hal_uart_recv(void* ctx, uint8_t* buf, size_t max_len,
                         uint32_t timeout_ms)
{
    (void)ctx;
    HAL_StatusTypeDef r = HAL_UART_Receive(&huart2, buf,
                                            (uint16_t)max_len, timeout_ms);
    if (r == HAL_OK)      return (int)max_len;
    if (r == HAL_TIMEOUT) return 0;   /* 超时返回 0 */
    return -1;
}

static int  hal_uart_connect(void* ctx)    { (void)ctx; return 1; }
static void hal_uart_disconnect(void* ctx) { (void)ctx; }
static int  hal_uart_is_connected(void* ctx) { (void)ctx; return 1; }

/* ----------  内部 Flash（存储预烧授权凭证）  ----------
 *
 * 布局示例（STM32F4, 扇区 11, 128 KB）:
 *   地址 0x080E0000 — 授权凭证魔数  (4 B)
 *   地址 0x080E0004 — 序列化 LicenseInfo (58 B)
 *   地址 0x080E003A — ECDSA 签名长度  (1 B)
 *   地址 0x080E003B — ECDSA 签名数据  (≤72 B)
 *
 * 根据你的 MCU 替换扇区号和基址。
 */
#define VOUCHER_FLASH_BASE   ((uint32_t)0x080E0000U)
#define VOUCHER_MAGIC        (0x5343564FU)  /* "SCVO" */
#define VOUCHER_MAX_SIZE     (128U)

/* 从 Flash 读取预烧凭证，填入 out_lic 和 out_sig。
 * 返回 1=成功, 0=没有有效凭证。 */
static int flash_read_voucher(SecretComLicenseInfo* out_lic,
                              uint8_t* out_sig, uint8_t* out_sig_len)
{
    const uint8_t* p = (const uint8_t*)VOUCHER_FLASH_BASE;

    /* 检查魔数 */
    uint32_t magic = (uint32_t)p[0]
                   | ((uint32_t)p[1] << 8)
                   | ((uint32_t)p[2] << 16)
                   | ((uint32_t)p[3] << 24);
    if (magic != VOUCHER_MAGIC) return 0;

    /* LicenseInfo 偏移 4，大小 58 字节（序列化布局与 protocol.h 一致） */
    const uint8_t* lic_bytes = p + 4;
    out_lic->license_type     = lic_bytes[0];
    out_lic->device_id        = (uint32_t)lic_bytes[4]
                              | ((uint32_t)lic_bytes[5] << 8)
                              | ((uint32_t)lic_bytes[6] << 16)
                              | ((uint32_t)lic_bytes[7] << 24);
    /* issue / expiry / remaining_uses / feature_flags / product_name ... */
    /* 此处简化：直接 memcpy（host 工具写入时须按相同布局序列化）*/
    memcpy(out_lic, lic_bytes, sizeof(SecretComLicenseInfo));

    /* 签名 */
    *out_sig_len = p[4 + 58];
    if (*out_sig_len == 0 || *out_sig_len > 72U) return 0;
    memcpy(out_sig, p + 4 + 58 + 1, *out_sig_len);

    return 1;
}

/* 将授权凭证写入内部 Flash（远程激活场景使用）。
 * lic_bytes: 58 字节序列化 LicenseInfo
 * sig      : ECDSA 签名
 * sig_len  : 签名长度（≤72）
 * 返回 1=成功, 0=失败。 */
static int flash_write_voucher(const uint8_t* lic_bytes, size_t lic_len,
                               const uint8_t* sig, uint8_t sig_len)
{
    uint8_t buf[VOUCHER_MAX_SIZE];
    memset(buf, 0xFF, sizeof(buf));

    /* 写入魔数 */
    buf[0] = (uint8_t)(VOUCHER_MAGIC & 0xFF);
    buf[1] = (uint8_t)((VOUCHER_MAGIC >> 8)  & 0xFF);
    buf[2] = (uint8_t)((VOUCHER_MAGIC >> 16) & 0xFF);
    buf[3] = (uint8_t)((VOUCHER_MAGIC >> 24) & 0xFF);

    if (lic_len > 58U || sig_len > 72U) return 0;

    memcpy(buf + 4,           lic_bytes, lic_len);
    buf[4 + 58]             = sig_len;
    memcpy(buf + 4 + 58 + 1, sig,       sig_len);

    /* ---- STM32 内部 Flash 解锁 → 擦除扇区 11 → 写入 → 上锁 ---- */
    HAL_FLASH_Unlock();

    FLASH_EraseInitTypeDef erase;
    uint32_t sector_error = 0;
    erase.TypeErase    = FLASH_TYPEERASE_SECTORS;
    erase.Sector       = FLASH_SECTOR_11;
    erase.NbSectors    = 1;
    erase.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    if (HAL_FLASHEx_Erase(&erase, &sector_error) != HAL_OK) {
        HAL_FLASH_Lock();
        return 0;
    }

    /* 按 4 字节对齐写入 */
    for (size_t i = 0; i < VOUCHER_MAX_SIZE; i += 4) {
        uint32_t word = (uint32_t)buf[i]
                      | ((uint32_t)buf[i+1] << 8)
                      | ((uint32_t)buf[i+2] << 16)
                      | ((uint32_t)buf[i+3] << 24);
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD,
                              VOUCHER_FLASH_BASE + i, word) != HAL_OK) {
            HAL_FLASH_Lock();
            return 0;
        }
    }

    HAL_FLASH_Lock();
    return 1;
}

/* ----------  设备唯一 ID（STM32 96-bit UID → 折叠为 32-bit）  ---------- */
static uint32_t hal_get_device_id(void)
{
    /* STM32 UID 寄存器地址（F4 系列）*/
    const uint32_t* uid = (const uint32_t*)0x1FFF7A10U;
    return uid[0] ^ uid[1] ^ uid[2];
}

/* ----------  简易调试输出（UART1 / semihosting）  ---------- */
#include <stdio.h>
static void esc_log(const char* msg) { (void)msg; /* 接 printf / ITM */ }

/* ===========================================================================
 * 2. 密钥材料（替换为真实密钥）
 *
 * !! 重要安全说明 !!
 *   - 私钥（device_priv_key）绝不能出现在源代码或版本控制中。
 *   - 推荐在量产工具中通过 SWD/JTAG 单独烧录到读保护的 OTP/安全 Flash 扇区。
 *   - 此处仅用全零占位演示接口，运行时从安全存储加载。
 *   - 公钥（device_pub_key）可嵌入飞控端固件，无需保密。
 * =========================================================================*/

/* 工厂生成的 ESC 设备静态 P-256 公钥（65 字节，非压缩格式 0x04|X|Y） */
static const uint8_t device_pub_key[65] = {
    0x04,
    /* X (32 bytes) — 替换为真实值 */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /* Y (32 bytes) — 替换为真实值 */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

/* ----------  从安全 Flash 扇区加载私钥（运行时读取，不存源码）  ---------- */
#define PRIVKEY_SECURE_FLASH_BASE  ((uint32_t)0x080C0000U)  /* 扇区 9 举例 */

static void load_device_priv_key(uint8_t out_priv[32])
{
    /* 读取受保护扇区。若启用了 RDP Level 2，调试器无法访问此区域。 */
    const uint8_t* stored = (const uint8_t*)PRIVKEY_SECURE_FLASH_BASE;
    memcpy(out_priv, stored, 32);
}

/* ===========================================================================
 * 3. 授权策略（AuthVerifyCallback）
 *
 * ESC 侧的 verify 回调是整个授权逻辑的核心：
 *   - 检查飞控的 client_device_id 是否在白名单中
 *   - 决定授予哪些功能 / 授权时限
 *   - 可对接 CAN 总线上的其他节点查询 / 上报
 * =========================================================================*/

/* 简单白名单示例（量产时替换为 Flash 中的绑定表或加密数据库） */
typedef struct {
    uint32_t fc_device_id;   /* 飞控设备 ID */
    uint8_t  feature_flags;  /* 允许的功能 */
} AllowListEntry;

static const AllowListEntry kAllowList[] = {
    { 0x11223344U, 0x07U },  /* 飞控 A → Basic+Advanced+Premium */
    { 0xAABBCCDDU, 0x01U },  /* 飞控 B → Basic only */
    { 0xDEADBEEFU, 0xFFU },  /* 飞控 C → 所有功能（开发测试用） */
};
static const size_t kAllowListSize =
    sizeof(kAllowList) / sizeof(kAllowList[0]);

static int esc_verify_callback(const SecretComAuthRequest* req,
                                SecretComLicenseInfo*       out_lic,
                                void*                       user_data)
{
    (void)user_data;

    /* 1. 在白名单中查找该飞控 ID */
    size_t i;
    for (i = 0; i < kAllowListSize; ++i) {
        if (kAllowList[i].fc_device_id == req->client_device_id) break;
    }
    if (i == kAllowListSize) {
        esc_log("[AUTH] DENIED — unknown FC device");
        return 0;  /* 拒绝授权 */
    }

    /* 2. 检查请求的功能是否在允许范围内 */
    uint8_t allowed = kAllowList[i].feature_flags;
    if ((req->feature_flags & ~allowed) != 0) {
        esc_log("[AUTH] DENIED — requested features exceed allowance");
        return 0;
    }

    /* 3. 填写授权信息 */
    memset(out_lic, 0, sizeof(*out_lic));
    out_lic->license_type   = 0;           /* 0 = kPermanent（永久） */
    out_lic->device_id      = hal_get_device_id();  /* ESC 自身 ID */
    out_lic->feature_flags  = allowed;
    out_lic->expiry_timestamp = 0;         /* 0 = 不过期 */
    strncpy(out_lic->product_name, req->product_name,
            sizeof(out_lic->product_name) - 1);

    esc_log("[AUTH] GRANTED");
    return 1;
}

/* ===========================================================================
 * 4. 场景 A — 在线授权（Online）
 *
 * 流程:
 *   上电 → 初始化 UART → SecretComServerInit → StartListening
 *   飞控连接后自动完成 ECDH 握手 + 授权
 *   飞控拿到签名 LicenseInfo 后可自行缓存（写本地 Flash）
 * =========================================================================*/

#ifdef SCENARIO_ONLINE

static SecretComServer* g_server = NULL;

void esc_auth_online_init(void)
{
    /* 配置 I/O 回调 */
    SecretComIoCbs io;
    memset(&io, 0, sizeof(io));
    io.user_ctx      = NULL;
    io.connect       = hal_uart_connect;
    io.disconnect    = hal_uart_disconnect;
    io.is_connected  = hal_uart_is_connected;
    io.send          = hal_uart_send;
    io.receive       = hal_uart_recv;

    /* 从安全存储加载私钥 */
    uint8_t priv_key[32];
    load_device_priv_key(priv_key);

    /* 创建并初始化服务端 */
    g_server = SecretComServerCreate();
    SecretComStatus s = SecretComServerInit(g_server, &io,
                                             device_pub_key, priv_key);
    /* 私钥用后立即清零 */
    memset(priv_key, 0, sizeof(priv_key));

    if (s != kSecretComOk) {
        esc_log("[AUTH] Server init failed");
        return;
    }

    /* 注册授权决策回调 */
    SecretComServerSetVerifyCb(g_server, esc_verify_callback, NULL);

    /* 启动监听（内部开线程；裸机版本见 esc_auth_online_poll 轮询）*/
    SecretComServerStartListening(g_server);
    esc_log("[AUTH] Online server listening...");
}

/* 裸机轮询版本（无 OS 时每次主循环调用一次） */
void esc_auth_online_poll(uint32_t timeout_ms)
{
    if (!g_server) return;
    /* HandleOne 是阻塞的，timeout_ms 控制等待时长 */
    SecretComStatus s = SecretComServerHandleOne(g_server, timeout_ms);
    if (s == kSecretComOk) {
        esc_log("[AUTH] One session completed OK");
    } else if (s != kSecretComTimeout) {
        /* 超时以外的错误才打印 */
        esc_log(SecretComStatusString(s));
    }
}

#endif /* SCENARIO_ONLINE */


/* ===========================================================================
 * 5. 场景 B — 离线预授权（Offline Voucher）
 *
 * 授权流程（工厂 / 一次性）:
 *   ① 工厂工具（PC 端）用 ESC 私钥对该飞控的 LicenseInfo 签名
 *   ② 生成凭证文件（结构: 魔数 + LicenseInfo序列化 + ECDSA签名）
 *   ③ 用烧录器/JLink 将凭证文件写入 ESC 的内部 Flash（只烧一次）
 *
 * 运行时:
 *   上电后读取 Flash 凭证，用内置公钥验签。
 *   验签成功 → 授权通过，ESC 开始正常工作。
 *   无需飞控连线，无需网络。
 *
 * 注意: 此场景下 secret_com 库不需要运行完整的握手协议，
 *       仅需调用 CryptoProvider 的 EcdsaVerify。
 *       如果你不想依赖 C++ 库，也可以直接调用 mbedTLS API。
 * =========================================================================*/

#ifdef SCENARIO_OFFLINE

/* 返回 1=授权有效, 0=授权无效（拒绝工作） */
int esc_auth_offline_verify(void)
{
    SecretComLicenseInfo lic;
    uint8_t  sig[72];
    uint8_t  sig_len = 0;

    /* 读取 Flash 中的凭证 */
    if (!flash_read_voucher(&lic, sig, &sig_len)) {
        esc_log("[AUTH-OFFLINE] No voucher in Flash");
        return 0;
    }

    /* -----------------------------------------------------------------------
     * 用 mbedTLS 直接验证签名（无需完整 secret_com 握手）
     *
     * 签名覆盖内容（与 protocol.h 一致）:
     *   "secret_com_lic_v1\0" (18 B) || serialized_license (58 B)
     *
     * 如果你嫌依赖 mbedTLS 太重，可以用 micro-ecc 或 tiny-ecdsa 替代。
     * ---------------------------------------------------------------------*/
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

    /* 构造被签名的数据 */
    static const char kLicDomain[] = "secret_com_lic_v1";
    uint8_t signed_buf[18 + 58];
    memcpy(signed_buf, kLicDomain, 18);
    /* 将 SecretComLicenseInfo 序列化到 signed_buf+18（58 字节）*/
    /* 此处用 memcpy 简化；实际要与 protocol::SerializeLicense 对齐 */
    memcpy(signed_buf + 18, &lic, 58);

    /* SHA-256 哈希 */
    uint8_t hash[32];
    mbedtls_sha256(signed_buf, sizeof(signed_buf), hash, 0);

    /* 加载公钥并验签 */
    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);

    int ret = mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) { mbedtls_ecdsa_free(&ecdsa); return 0; }

    ret = mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q,
                                         device_pub_key, 65);
    if (ret != 0) { mbedtls_ecdsa_free(&ecdsa); return 0; }

    ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, 32, sig, sig_len);
    mbedtls_ecdsa_free(&ecdsa);

    if (ret != 0) {
        esc_log("[AUTH-OFFLINE] Signature INVALID");
        return 0;
    }

    /* 检查过期时间 */
    if (lic.expiry_timestamp != 0) {
        /* 从 RTC 获取当前时间（替换为你的 RTC 驱动） */
        extern uint64_t rtc_get_unix_sec(void);
        uint64_t now = rtc_get_unix_sec();
        if (now >= lic.expiry_timestamp) {
            esc_log("[AUTH-OFFLINE] License EXPIRED");
            return 0;
        }
    }

    esc_log("[AUTH-OFFLINE] Voucher OK");
    return 1;
}

#endif /* SCENARIO_OFFLINE */


/* ===========================================================================
 * 6. 场景 C — 远程激活（Remote Activation）
 *
 * 使用场景:
 *   ESC 出厂时不含任何凭证，首次上电后通过 CAN/UART/蓝牙 连接到
 *   飞控，飞控将从云端服务器拉取的授权包转发给 ESC，ESC 验签后
 *   写入内部 Flash，之后断网工作（等同场景 B）。
 *
 * 分包协议（简单示例，可替换为你的私有协议）:
 *   CMD_ACTIVATE_REQ  (0xA1): 飞控 → ESC，携带设备ID
 *   CMD_ACTIVATE_DATA (0xA2): 飞控 → ESC，携带 LicenseInfo + 签名
 *   CMD_ACTIVATE_ACK  (0xA3): ESC → 飞控，结果 (0=OK, 1=FAIL)
 * =========================================================================*/

#ifdef SCENARIO_REMOTE

#define CMD_ACTIVATE_REQ  0xA1U
#define CMD_ACTIVATE_DATA 0xA2U
#define CMD_ACTIVATE_ACK  0xA3U

/* 激活数据包最大长度:
 *   1 (cmd) + 58 (lic) + 1 (sig_len) + 72 (sig) = 132 字节 */
#define ACT_PKT_MAX  132U

/* 解析 CMD_ACTIVATE_DATA 包并写入 Flash */
static int remote_handle_activate_data(const uint8_t* pkt, size_t pkt_len,
                                        uint8_t* ack_status)
{
    /* 最小包长校验: 1(cmd) + 58(lic) + 1(sig_len) + 1(sig>=1) */
    if (pkt_len < 61U || pkt[0] != CMD_ACTIVATE_DATA) {
        *ack_status = 1;
        return 0;
    }

    const uint8_t* lic_bytes = pkt + 1;
    uint8_t        sig_len   = pkt[59];
    const uint8_t* sig       = pkt + 60;

    /* 边界检查 */
    if (sig_len == 0 || sig_len > 72U || (size_t)(60U + sig_len) > pkt_len) {
        *ack_status = 1;
        return 0;
    }

    /* ---- 先验签，再写 Flash ---- */
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

    static const char kLicDomain[] = "secret_com_lic_v1";
    uint8_t signed_buf[18 + 58];
    memcpy(signed_buf, kLicDomain, 18);
    memcpy(signed_buf + 18, lic_bytes, 58);

    uint8_t hash[32];
    mbedtls_sha256(signed_buf, sizeof(signed_buf), hash, 0);

    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, device_pub_key, 65);
    int ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, 32, sig, sig_len);
    mbedtls_ecdsa_free(&ecdsa);

    if (ret != 0) {
        esc_log("[AUTH-REMOTE] Signature invalid, activation denied");
        *ack_status = 1;
        return 0;
    }

    /* 写入 Flash */
    if (!flash_write_voucher(lic_bytes, 58, sig, sig_len)) {
        esc_log("[AUTH-REMOTE] Flash write failed");
        *ack_status = 1;
        return 0;
    }

    esc_log("[AUTH-REMOTE] Activated & saved to Flash");
    *ack_status = 0;
    return 1;
}

/* UART 接收缓冲（简单状态机，按需替换为 DMA ring buffer） */
static uint8_t  s_rx_buf[ACT_PKT_MAX];
static uint16_t s_rx_pos = 0;

/* 每次主循环调用，处理远程激活握手 */
void esc_auth_remote_poll(void)
{
    /* 尝试接收一字节 */
    uint8_t byte;
    int r = hal_uart_recv(NULL, &byte, 1, 5);
    if (r <= 0) return;

    /* 简单帧同步: 遇到 CMD_ACTIVATE_REQ 重置缓冲 */
    if (byte == CMD_ACTIVATE_REQ) {
        s_rx_pos = 0;
    }

    if (s_rx_pos < ACT_PKT_MAX) {
        s_rx_buf[s_rx_pos++] = byte;
    }

    /* 收到 CMD_ACTIVATE_DATA 帧（最小 61 字节，以 sig_len 计算实际长度） */
    if (s_rx_pos >= 60U && s_rx_buf[0] == CMD_ACTIVATE_DATA) {
        uint8_t sig_len   = s_rx_buf[59];
        uint16_t expected = 60U + sig_len;
        if (s_rx_pos >= expected) {
            uint8_t ack_status = 1;
            remote_handle_activate_data(s_rx_buf, expected, &ack_status);

            /* 发送 ACK */
            uint8_t ack[2] = { CMD_ACTIVATE_ACK, ack_status };
            hal_uart_send(NULL, ack, sizeof(ack));

            s_rx_pos = 0;
        }
    }
}

#endif /* SCENARIO_REMOTE */


/* ===========================================================================
 * 7. ESC 主业务保护门控
 *
 * 无论哪种授权场景，ESC 核心逻辑（FOC 控制/换相）都通过
 * g_esc_authorized 标志来决定是否运行。
 * =========================================================================*/

static volatile int g_esc_authorized = 0;

/* 由各场景授权完成后调用 */
void esc_set_authorized(int granted)
{
    g_esc_authorized = granted;
}

/* 在 FOC/PWM 中断中调用，未授权则强制停机 */
int esc_is_authorized(void)
{
    return g_esc_authorized;
}

/* ===========================================================================
 * 8. main() — 整合演示
 *
 * 实际项目中 main() 通常在 CubeMX 生成的 main.c 中，
 * 将下面的调用嵌入到对应的初始化和主循环位置即可。
 * =========================================================================*/

int main(void)
{
    /* ---- 系统初始化（HAL / 时钟 / 外设，由 CubeMX 生成）---- */
    /* HAL_Init(); SystemClock_Config(); MX_GPIO_Init(); MX_USART2_UART_Init(); */

    /* ---- 场景 A: 在线授权（RTOS 线程或裸机轮询）---- */
#ifdef SCENARIO_ONLINE
    esc_auth_online_init();
    /* 如果有 RTOS（FreeRTOS）: 直接走 StartListening，已内置后台线程 */
    /* 如果裸机: 在主循环中调用 esc_auth_online_poll(100) */
#endif

    /* ---- 场景 B: 离线验签 ---- */
#ifdef SCENARIO_OFFLINE
    if (esc_auth_offline_verify()) {
        esc_set_authorized(1);
    } else {
        /* 未授权: 可闪烁 LED 报警，禁止电机启动 */
        esc_set_authorized(0);
    }
#endif

    /* ---- 场景 C: 远程激活（首次上电尝试激活，成功后下次走场景 B）---- */
#ifdef SCENARIO_REMOTE
    /* 先检查是否已有 Flash 凭证（防止重复激活） */
    {
        SecretComLicenseInfo lic_dummy;
        uint8_t sig_dummy[72];
        uint8_t sig_len_dummy = 0;
        if (flash_read_voucher(&lic_dummy, sig_dummy, &sig_len_dummy)) {
            /* 已激活，直接走离线验签 */
            /* esc_auth_offline_verify(); ... */
            esc_set_authorized(1);
        }
        /* 否则等待飞控发来激活包（在主循环调用 esc_auth_remote_poll）*/
    }
#endif

    /* ---- 主循环 ---- */
    while (1) {

#ifdef SCENARIO_ONLINE
        /* 裸机版本: 轮询等待一次授权，100ms 超时即返回 */
        esc_auth_online_poll(100);
        /* 授权完成后服务端会通过 verify_callback 修改 g_esc_authorized */
        /* 注意: StartListening 版本下此行可省略 */
#endif

#ifdef SCENARIO_REMOTE
        if (!esc_is_authorized()) {
            esc_auth_remote_poll();
        }
#endif

        if (esc_is_authorized()) {
            /* 运行电机控制 / FOC 主任务 */
            /* motor_foc_task(); */
        } else {
            /* 禁止电机，等待授权 */
            /* motor_stop(); */
        }
    }
}
