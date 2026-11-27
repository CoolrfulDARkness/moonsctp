# MoonSCTP 评审与答辩核心问答速记（Defense Q&A）

## Q1：如何防止 TSN/SSN 32-bit 与 16-bit 回绕导致队列错乱？
- 严格采用 **RFC 1982 半空间序列算术**（`tsn_lt(a, b)` 通过无符号差值高比特判断严格先后），并专门构造了跨越 `0xFFFFFFFE -> 0x00000001` 的多包乱序、SACK Gap 与 `FORWARD_TSN` 回归测试。
- 在安全审计中额外补齐了**未来 TSN 上界守卫**（拒绝 `cum_tsn_ack >= next_tsn` 的恶意伪造 SACK）与 `MAX_TSN_LOOKAHEAD = 4096` 乱序窗口上限，杜绝跨半空间回绕投毒与 OOM。

## Q2：无状态 4-Way Cookie 握手如何真正抗 SYN Flood？
- `process_stateless_init` 在收到合法 `COOKIE_ECHO` 前**零会话内存分配**：直接将对端参数（端口、VTag、初始 TSN、时间戳）打包为 64 字节 Cookie，经纯 MoonBit HMAC-SHA256 签名并随 `INIT_ACK` 发回。
- 仅在收到 `COOKIE_ECHO` 后执行恒定时间 MAC 校验、TTL 过期校验、FIFO 重放缓存校验（`MAX_CONSUMED_COOKIES = 256`）与 **`assoc_state == Closed` 防劫持校验**，全部通过才分配发送/接收队列。

## Q3：SCTP 多流无队头阻塞（HOL）与 PR-SCTP 跳帧是如何验证的？
- 每条 `stream_id` 独立维护 `next_ssn` 与 `B`/`E` 分片重组缓冲。在 CLI 阶段 3 与混沌仿真中，显式丢弃 Stream 0 首包后，Stream 1 三条消息立即以 0ms 跨流阻塞交付；而 PR-SCTP `MaxRetransmits(n)` / `TimedMs(ms)` 在超限后立即放弃失效分片并发送 `FORWARD_TSN` 解锁接收端。

## Q4：如何证明线格式严格符合 RFC 9260，而不是“自写自测”？
- `harness/interop_wire.py` 使用纯 Python 标准库独立实现了**无查表按位 Castagnoli CRC-32C** 与全部 **14 类 Chunk 字节级解包器/合成器**，在 Wasm 与 JS 双端完成 **10/10 双向字节级互验**（包括非 4 字节对齐填充、TSN 回绕与规范重编码逐字节一致）。

## Q5：Threat Model 与 Non-Goals 是什么？
- **已覆盖**：纯内存安全 Sans-I/O 单路径 SCTP + PR-SCTP 协议栈、抗 SYN Flood、CRC-32C/VTag/Port 校验、未来 SACK 与 `RecvTracker` OOM 防护。
- **明确 Non-Goals**：不直接操作 OS Raw IP Socket（需由上层通过 UDP/DTLS 封装传输，如 WebRTC RFC 8261/6951）、暂未实现多宿主（Multi-Homing）路径切换、不承诺 JIT 下的硬件级微架构恒定时间。
