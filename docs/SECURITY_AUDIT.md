# MoonSCTP 安全对抗审计实录（Security Audit Log）

本文档记录对 `CoolrfulDARkness/moonsctp`（RFC 9260 SCTP + RFC 3758 PR-SCTP）执行全仓红队对抗审计所检出并完成回归验证的全部安全与协议缺陷（对应加固提交 `c492275`）。

---

## 审计范围

- 校验和层：`crc32c/crc32c.mbt`（Castagnoli CRC-32C 4 路切片查表）
- 无状态 Cookie 层：`cookie/cookie.mbt`（纯 MoonBit HMAC-SHA256 抗 SYN Flood 状态 Cookie）
- 线格式编解码层：`packet/`（12B 公共头 + 全部 14 类 Chunk + RFC 1982 序列算术）
- Sans-I/O 关联状态机：`association/assoc.mbt`、`association/send_queue.mbt`、`association/recv_queue.mbt`

---

## 已闭环修复的 7 项缺陷（3 个 P0 + 4 个 P1）

| 编号 | 级别 | 问题描述 | 修复方案 | 回归测试 |
| :---: | :---: | :--- | :--- | :--- |
| **P0-1** | **P0** | `process_stateless_init` 与 `handle_packet` 缺少端口校验；`COOKIE_ECHO` 未限定 `assoc_state == Closed`，已建连服务端可被新 Cookie 劫持；`consumed_cookies` 无容量上限 | 强制校验 `dst_port`/`src_port`；`COOKIE_ECHO` 仅在 `Closed` 态接受；为 `consumed_cookies` 增加 `MAX_CONSUMED_COOKIES = 256` FIFO 上限 | `adv 26`, `adv 27` |
| **P0-2** | **P0** | `on_sack` / `ack_up_to` 未拒绝指向未来的 `cum_tsn_ack >= next_tsn` 与越界 Gap Ack Block，恶意对端可静默破坏未发送队列 | 增加 `!tsn_lt(cum_tsn, self.next_tsn)` 与 Gap 边界校验，非法未来确认直接丢弃 | `adv 28` |
| **P0-3** | **P0** | `RecvTracker` 存在无界 OOM DoS 面（`out_of_order_tsns`、全局 `buffered_bytes`、单流 `pending_ordered`、`build_sack` 数组均无上限） | 增设 5 项硬上限：`MAX_TSN_LOOKAHEAD = 4096`、`MAX_OOO_TSNS = 1024`、`MAX_PENDING_ORDERED_PER_STREAM = 128`、`MAX_SACK_GAPS = 64`、`MAX_SACK_DUPS = 64` 与 `max_recv_buf` | `adv 30` |
| **P1-1** | **P1** | 过时/倒退 `FORWARD_TSN` 的 `ft.streams` 更新位于 `tsn_gt(ft.new_cum_tsn, self.cum_tsn)` 判断外部，可误推有序流 `next_ssn` | 将 `ft.streams` 循环移入 `tsn_gt(...) && tsn_diff(...) <= MAX_TSN_LOOKAHEAD` 守卫内部 | `adv 29` |
| **P1-2** | **P1** | `a_rwnd >= 0x80000000U` 经 `reinterpret_as_int()` 溢出为负有符号整数，导致拥塞窗口锁死 | 引入 `u32_to_i32_sat` 饱和钳位，应用于 `peer_rwnd` 与 `base_arwnd` | `adv 30` |
| **P1-3** | **P1** | `Crc32c.state` 缺少 `priv` 封装，外部可篡改校验寄存器 | 改为 `priv mut state : UInt32`，刷新 `crc32c/pkg.generated.mbti` | `.mbti` 契约 |
| **P1-4** | **P1** | 热路径重复计算两次 CRC-32C，且捆绑 `ABORT` 未清空 `send_q`/`recv_t` | 移除 `assoc.mbt` 冗余校验（仅由 `packet::decode_packet` 单次校验），降级 `crc32c` 为 `for "test"` 依赖；捆绑 `ABORT` 清空发送/接收队列 | 全量 52 项回归 |

---

## 验证门禁结果

- `moon fmt --check` & `moon check -d`：**0 warnings, 0 errors**
- `moon test --target wasm -d` / `--target js -d` / `--target native -d`（MSVC）：**52/52 PASS（含 30 项独立安全对抗测试 + 5 大混沌网络仿真）**
- `python harness/interop_wire.py`：**10/10 PASSED**（零依赖 Python 独立 RFC 9260 解包器与无表按位 CRC-32C 双向对拍）
- GitHub Actions CI（Linux + Windows MSVC）：**100% PASS**
