# moonsctp

**纯 MoonBit、零 C/FFI 依赖、Sans-I/O 架构的 IETF RFC 9260（SCTP）与 RFC 3758（PR-SCTP）多流可靠传输协议栈**

> MoonBit 生态首个完整覆盖 **Castagnoli CRC-32C（4 路切片查表）+ 无状态抗 SYN Flood HMAC-SHA256 4-Way Cookie 握手 + 全部 14 类 RFC 9260/3758 Chunk 编解码 + 多流独立交付（彻底消除队头阻塞）+ RFC 1982 32-bit TSN 回绕算术 + SACK / 拥塞控制 / RTO + RFC 3758 PR-SCTP `FORWARD_TSN` 部分可靠跳帧** 的纯 MoonBit 传输层协议栈。填补 MoonBit **WebRTC DataChannel** 缺失的核心传输层拼图，一套核心代码原生运行于 **Wasm / JS / Native** 三端。

---

## 核心特性

- **零外部依赖、零 FFI、零 `unsafe`、纯 Sans-I/O**：状态机仅消费/产出 `Bytes` 报文与显式 `now_ms : UInt64` 时钟，不耦合任何 OS Socket 或线程模型，无缝适配 `moonbitlang/async`、Wasm 浏览器、边缘网关与确定性仿真测试。
- **高速 4 路切片查表 Castagnoli CRC-32C（`crc32c`）**：严格遵循 RFC 9260 Appendix B 小端校验和，Native 端吞吐高达 **875 MB/s**，Wasm 端 **652 MB/s**。
- **无状态抗 SYN Flood 4-Way Cookie 握手（`cookie`）**：`process_stateless_init` 在收到合法 `COOKIE_ECHO` 前**零会话内存分配**，64 字节状态 Cookie 由纯 MoonBit HMAC-SHA256 保护、恒定时间验 MAC 并强制过期与防重放校验。
- **全部 14 类 Chunk 精确线级编解码（`packet`）**：覆盖 `DATA`, `INIT`（含 `0xC000` Forward-TSN TLV）, `INIT_ACK`（含 `0x0007` Cookie TLV）, `SACK`, `HEARTBEAT`, `HEARTBEAT_ACK`, `ABORT`, `SHUTDOWN`, `SHUTDOWN_ACK`, `ERROR`, `COOKIE_ECHO`, `COOKIE_ACK`, `SHUTDOWN_COMPLETE` 与 `FORWARD_TSN`（`0xC0`），完整实现 RFC 9260 §3.2 未知 Chunk 高 2 位处理与 RFC 1982 32-bit TSN / 16-bit SSN 回绕算术。
- **多流无队头阻塞 + RFC 3758 PR-SCTP（`association`）**：
  - 每条 `stream_id` 独立维护 `next_ssn` 与 `B`/`E` 分片重组队列，同时支持 `U=1` 无序交付，单流丢包绝不阻塞其他并发流；
  - 完整 `SACK`（Cumulative TSN + Gap Ack Blocks + Duplicate TSNs）、3-dup 快速重传、Jacobson/Karels RTO 指数退避、Slow Start / Congestion Avoidance 拥塞控制；
  - 支持 `Reliable`、`MaxRetransmits(n)`、`TimedMs(ms)` 三种可靠性策略，超限自动放弃分片并发送 `FORWARD_TSN` 即时解锁接收端。

---

## 快速体验（一键运行）

### 1. 运行 5 阶段端到端 CLI 实景演示
```bash
moon run cmd/main
```
演示依次执行：
1. RFC 9260 Appendix B Castagnoli CRC-32C、RFC 4231 HMAC-SHA256 Cookie 与 RFC 1982 TSN 回绕自检；
2. 无状态抗 SYN Flood 4-Way Cookie 握手与 `HEARTBEAT` 保活；
3. **跨流无队头阻塞实景对比**：故意丢弃 Stream 0 首包，Stream 1 三条消息零阻塞立即交付，快速重传补齐后 Stream 0 完整交付；
4. **15% 丢包 + 乱序 + 重复包混沌仿真**（20/20 多分片无损收敛）与 **RFC 3758 PR-SCTP `FORWARD_TSN` 跳帧解锁**；
5. 实时安全对抗演练：单比特 CRC-32C 篡改拦截、单比特 HMAC Cookie 篡改拦截、错 VTag 伪造 `ABORT` 静默免疫。

### 2. 运行全量三端测试（0 警告）
```bash
moon test --target wasm -d
moon test --target js -d
moon test --target native -d   # Windows 下需先加载 VS MSVC vcvars64.bat
```

### 3. 运行零依赖 Python RFC 9260 线级报文双向对拍
```bash
python harness/interop_wire.py
```
使用纯标准库 Python 3 独立实现的无表按位 Castagnoli CRC-32C 与 14 类 Chunk 字节级解包器，完成 **10/10 双向字节级互验**（含非 4 倍数载荷填充、TSN 回绕与规范重编码逐字节一致）。

### 4. 代码调用示例（Sans-I/O 无状态握手与多流通信）
```moonbit nocheck
let c_cfg = @moonsctp.client_config(5000U, 5001U, 0x11223344U, 1000U)
let s_cfg = @moonsctp.server_config(
  5001U,
  5000U,
  0x55667788U,
  2000U,
  b"server-hmac-cookie-secret-key-01",
)
let client = @moonsctp.new_client(c_cfg)
let server = @moonsctp.new_server(s_cfg)
let (_c_pkts, _s_pkts) = @moonsctp.run_handshake_loop(client, server, 1000UL)

client.send(b"hello stream 0", @moonsctp.reliable_opts(0U), 1010UL)
client.send(b"hello stream 1", @moonsctp.partial_retransmit_opts(1U, 2), 1010UL)
for pkt in client.poll_outbound() {
  let _events = server.handle_packet(pkt[:], 1020UL)
}
```

---

## 三端实测性能基准（`moon bench`）

以下为本机（Windows AMD64，MoonBit `v0.10.22`，MSVC `14.44`）12 项基准实测结果（可通过 `moon bench bench` 复现）：

| # | 基准项 | Wasm (`mean ± σ`) | JS (`mean ± σ`) | Native MSVC (`mean ± σ`) |
| :---: | :--- | ---: | ---: | ---: |
| 1 | Castagnoli CRC-32C (1KB) | 1.57 µs (~652 MB/s) | 1.73 µs (~592 MB/s) | **1.17 µs (~875 MB/s)** |
| 2 | Castagnoli CRC-32C (16KB) | 23.61 µs (~694 MB/s) | 27.59 µs (~594 MB/s) | **21.03 µs (~779 MB/s)** |
| 3 | HMAC-SHA256 Cookie `seal` | 3.73 µs ± 252 ns | 7.95 µs ± 498 ns | **2.82 µs ± 159 ns** |
| 4 | HMAC-SHA256 Cookie `open` | 4.12 µs ± 293 ns | 10.83 µs ± 1.44 µs | **3.03 µs ± 191 ns** |
| 5 | `Packet::encode_packet` (1KB DATA) | **9.97 µs ± 467 ns** | 42.65 µs ± 4.42 µs | 10.00 µs ± 598 ns |
| 6 | `Packet::decode_packet` (1KB + CRC-32C) | 3.37 µs ± 172 ns | 10.61 µs ± 1.33 µs | **2.48 µs ± 171 ns** |
| 7 | 多 Chunk 捆绑编解码 (DATA+SACK+HB) | 8.24 µs ± 208 ns | 47.84 µs ± 8.42 µs | **7.00 µs ± 449 ns** |
| 8 | 无状态 `process_stateless_init` | 5.63 µs ± 151 ns | 15.54 µs ± 1.63 µs | **5.14 µs (~195K/s)** |
| 9 | 完整 4-Way Cookie 握手端到端 | 22.20 µs (~45K/s) | 45.37 µs (~22K/s) | **16.65 µs (~60K/s)** |
| 10 | 单条 1KB DATA `send+handle+SACK` | 17.41 µs ± 814 ns | 73.63 µs ± 6.61 µs | **10.28 µs ± 336 ns** |
| 11 | 多分片 8KB (7 分片) 端到端重组交付 | 177.89 µs ± 17.65 µs | 558.66 µs ± 25.33 µs | **76.38 µs (~107 MB/s)** |
| 12 | 4 并发流 16 消息多流交付 | 227.89 µs ± 15.30 µs | 427.93 µs ± 35.23 µs | **78.44 µs (~204K msgs/s)** |

---

## 仓库架构与文档导航

```text
moonsctp/
├── crc32c/         # 4 路切片查表 Castagnoli CRC-32C (RFC 9260 Appendix B)
├── cookie/         # 纯 MoonBit HMAC-SHA256 无状态抗 SYN Flood 状态 Cookie
├── packet/         # 12B 公共头 + 全部 14 类 RFC 9260/3758 Chunk + RFC 1982 序列算术
├── association/    # Sans-I/O SCTP/PR-SCTP 状态机 + 5 大混沌网络仿真 + 30 项安全对抗测试
├── cmd/main/       # 5 阶段一键可运行实景演示 CLI
├── bench/          # 12 项三端性能基准套件 (moon bench)
├── harness/        # 零依赖 Python 独立 RFC 9260 解包器与按位 CRC-32C 双向对拍
└── docs/
    ├── ARCHITECTURE.md      # 分层架构、RFC 9260/3758/1982 逐条款覆盖矩阵与范围边界
    └── VERIFICATION_LOG.md  # 五层验证闭环、混沌仿真与双向线级对拍实录
```

- 详细架构设计、RFC 逐条款覆盖矩阵与非目标边界说明：见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。
- 五层验证闭环与工程防错实录：见 [`docs/VERIFICATION_LOG.md`](docs/VERIFICATION_LOG.md)。

---

## 开源协议

本项目采用 [Apache-2.0](LICENSE) 开源协议。
