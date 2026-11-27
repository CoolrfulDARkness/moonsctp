# MoonSCTP 前瞻开发路线图（Roadmap: `v0.4.0 → v1.0.0+`）

本路线图严格仅记录尚未进入主干的后续演进方向与验收门禁，便于后续开发者或 AI 工程会话按阶段接续推进，同时始终守住核心协议栈（`crc32c`、`cookie`、`packet`、`association`）**零外部依赖、零 FFI、三端全兼容**的架构底线。

---

## `v0.4.0`：WebRTC DataChannel（RFC 8831 / 8832）上层适配与可观测性增强

- [ ] 新增可选上层适配子包，支持 **RFC 8832 DCEP（Data Channel Establishment Protocol）** 与标准 **WebRTC DataChannel PPID**（`50` DCEP、`51` String、`53` Binary、`56` Empty String、`57` Empty Binary）编解码与通道生命周期管理；
- [ ] 为 Sans-I/O 关联状态机补充零侵入可观测性事件/计数器快照（如拥塞窗口演进、RTO 采样、各流积压深度与分片重组延迟），方便宿主接入 Prometheus / OpenTelemetry 与前端实时仪表盘；
- [ ] 扩展 `examples/udp_tunnel/` 支持双进程 CLI 模式（独立 `server` / `client` 子命令、可配置监听地址与丢包/抖动注入参数），便于跨机房或容器网络实测 RFC 6951 SCTP-over-UDP。

---

## `v0.6.0`：CRC-32C 向量化加速与高并发大报文性能基准

- [ ] 评估在 Wasm / Native 后端引入 `v128` SIMD / 8 路切片查表加速 `crc32c`（保持现有标量 4 路切片查表参考实现与全量位级等价回归测试，`.mbti` 公共接口零破坏）；
- [ ] 扩充 `bench/` 基准套件，新增大报文分片（32KB–64KB）、高并发流（16 / 64 流）及高频 PR-SCTP 丢包跳帧场景的吞吐与内存分配对比数据；
- [ ] 评估针对 `encode_packet` / `decode_packet` 的零拷贝切片与缓冲区复用优化，进一步降低热路径内存分配开销。

---

## `v0.8.0`：序列算术形式化边界验证、模糊测试与跨实现互操作

- [ ] 对 `packet/serial.mbt`（RFC 1982 32-bit TSN / 16-bit SSN 回绕算术）与 `association/recv_queue.mbt`（Gap Ack Block 合并与边界截断）补充基于属性测试 / 穷举边界模型的形式化性质检验；
- [ ] 为 `packet/decode_packet` 与 `association/handle_packet` 增加确定性种子驱动的变异模糊测试（Fuzz Corpus），覆盖畸形 TLV、嵌套填充、极端窗口与边界分片重组，确保全路径零 panic、零 OOM；
- [ ] 扩充 `harness/interop_wire.py` 跨实现线级互操作覆盖面，对接 `usrsctp` / `pion/sctp` 真实抓包向量做只读回放互验。

---

## `v1.0.0`：ABI 冻结与生产级稳定发布

- [ ] 审查并冻结根门面 `moonsctp` 及核心子包（`crc32c`、`cookie`、`packet`、`association`）全部 `pkg.generated.mbti` 公开 ABI，发布语义化版本兼容承诺；
- [ ] 补齐英文与中文双语 API 文档示例、错误码排障手册与 Sans-I/O 宿主集成指南（涵盖 `moonbitlang/async` Native UDP 隧道与浏览器 Web Worker 集成范式）；
- [ ] 完成发布前全量安全复审与三端长稳压测，正式发布 `v1.0.0`。

---

## `v1.0.0+`：远期可选扩展（按社区需求评估）

- [ ] **RFC 6525（Stream Reconfiguration）**：评估在独立扩展层支持运行时动态流重置（`RE-CONFIG` Chunk）与流扩容；
- [ ] **RFC 8260（Stream Schedulers & User Message Interleaving / I-DATA）**：评估支持大消息交错分片与加权公平流调度，消除同关联内大消息对小消息的发送端排队延迟；
- [ ] **RFC 4895（SCTP-AUTH）与路径 MTU 探测（RFC 8899 DPLPMTUD）**：在保持 Sans-I/O 纯度与零外部依赖前提下按需评估。
