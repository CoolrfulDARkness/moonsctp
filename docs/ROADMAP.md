# MoonSCTP 开发路线图（Roadmap）

本路线图面向后续接续开发者与 AI 工程会话，明确各阶段边界与零回退验收门禁。

## 已完成基线：`v0.1.0`
- 纯 MoonBit、零 FFI、零 `unsafe`、Sans-I/O RFC 9260 SCTP + RFC 3758 PR-SCTP 协议栈；
- 4 路切片查表 Castagnoli CRC-32C + 无状态抗 SYN Flood HMAC-SHA256 Cookie 握手 + 全部 14 类 Chunk 编解码 + RFC 1982 回绕算术；
- Wasm / JS / Native（MSVC）三端 52 项零警告回归测试（含 5 大混沌仿真与 30 项对抗安全测试）+ 独立 Python 10/10 线级双向对拍 + 双平台 CI。

## `v0.2.0`：生态消费与可视化工作台
- [ ] 新增独立 `examples/consumer` 验证 `mooncakes.io` 已发布包零报错运行，接入双周定时 CI；
- [ ] 新增 `examples/web-demo` 浏览器零安装混沌网络可视化实验室（滑块调节丢包/乱序，实时对比 SCTP 多流 + PR-SCTP 跳帧 vs 单流 HOL 阻塞）并上线 GitHub Pages；
- [ ] 保持核心包（`crc32c`、`cookie`、`packet`、`association`）零外部依赖、三端全兼容。

## `v0.3.0`：真实 UDP 封装通道与工具链演进
- [ ] 在独立 `examples/udp_demo/` 中实现 RFC 6951 SCTP-over-UDP 本机双进程收发演示（隔离在核心 Sans-I/O 包之外）；
- [ ] 适配 MoonBit `1.0.0-rc1` / `1.0` 稳定版，确保三端 `-d` 零警告。

## `v0.5.0 → v1.0.0`：性能与形式化验证
- [ ] 评估 `v128` SIMD 加速 `crc32c`（保持标量参考实现与位级一致测试，`.mbti` 零破坏）；
- [ ] 探索对 `packet/serial.mbt`（RFC 1982 回绕算术）增加形式化边界验证；
- [ ] 冻结公开 `.mbti` ABI，补齐 WebRTC DataChannel PPID 映射子集，发布 `v1.0.0`。
