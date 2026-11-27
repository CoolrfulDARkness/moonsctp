# MoonSCTP RFC 6951 SCTP-over-UDP Loopback Tunnel (`examples/udp_tunnel`)

本目录是完全独立的 Native MoonBit 子模块（拥有独立 `moon.mod`），与核心 Sans-I/O 协议栈（根目录 `moon.mod` 零外部依赖）完全隔离，演示如何将 `CoolrfulDARkness/moonsctp` 接入 `moonbitlang/async/socket`（`UdpServer` / `UdpClient`）构建真实操作系统 `127.0.0.1` UDP 套接字环回隧道。

## 覆盖的 RFC 6951 / RFC 9260 / RFC 3758 场景

1. **无状态抗 SYN Flood 4-Way Cookie 握手**：服务端在收到合法 `COOKIE_ECHO` 前仅通过 `@sctp.process_stateless_init` 签发 64B HMAC-SHA256 Cookie（零 `Association` 内存分配），并在真实 UDP 报文中拒绝单比特篡改 Cookie。
2. **多流（Stream 0/1/2）并发有序/无序 DATA + SACK 与 3-Dup 快速重传**：故意丢弃 Stream 0 首包 UDP 数据报，验证 Stream 1（有序）与 Stream 2（`U=1` 无序）零队头阻塞立即交付，随后由真实 UDP SACK 触发 3-missing-report 快速重传恢复 Stream 0 并完成双向通信。
3. **RFC 3758 PR-SCTP `FORWARD_TSN` 跳帧解锁**：覆盖 `MaxRetransmits(0)` 与 `TimedMs(60ms)` 两种部分可靠策略，在真实墙钟时间推进后经 UDP 发送 `FORWARD_TSN` 立即解锁后续可靠消息。
4. **`HEARTBEAT` 保活、4KB 多分片双向重组与优雅 3-Way `SHUTDOWN`**：验证端到端保活、MTU 分片 B/E 标志重组以及 `SHUTDOWN -> SHUTDOWN_ACK -> SHUTDOWN_COMPLETE` 双向平滑关闭。

## 运行与测试（Native 后端）

> 注：本机 `moon 0.1.20261119`（`moonc v0.10.22`）工具链下固定使用 `moonbitlang/async@0.22.10`（`0.22.11` 依赖更新版本 `core` 的 `SortedSet::insert` 方法）。

```bash
cd examples/udp_tunnel
moon update
moon check --target native -d
moon test --target native -d
moon run cmd --target native
```

Windows MSVC 环境请先加载 `vcvars64.bat`：

```powershell
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul && moon test --target native -d && moon run cmd --target native'
```
