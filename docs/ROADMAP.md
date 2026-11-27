# MoonSCTP 前瞻开发路线图（Roadmap: `v0.3.0 → v1.0.0+`）

本路线图仅记录尚未进入主干的后续演进方向与验收门禁，便于后续开发者或 AI 工程会话按阶段接续推进，同时严格守住核心协议栈（`crc32c`、`cookie`、`packet`、`association`）**零外部依赖、零 FFI、三端全兼容**的架构底线。

---

## `v0.3.0`：真实 UDP 封装通道与工具链稳定版适配

- [ ] 在独立示例目录 `examples/udp_demo/` 中实现 **RFC 6951（SCTP over UDP）** 本机双进程真实收发演示（隔离在核心 Sans-I/O 模块之外，不向根 `moon.mod` 引入任何外部依赖）；
- [ ] 在 `examples/udp_demo/` 中提供可配置端口与弱网代理脚本，验证真实 UDP 套接字承载多流有序/无序消息与 PR-SCTP 跳帧；
- [ ] 跟进并适配 MoonBit `1.0.0-rc1` / `1.0` 正式工具链，确保 `wasm` / `js` / `native`（Linux + Windows MSVC）三端 `-d` 严格零警告、`moon publish --dry-run` 持续返回 `202 Accepted`。

---

## `v0.5.0`：WebRTC DataChannel（RFC 8831 / 8832）子集与性能优化

- [ ] 新增可选上层适配子包，支持 **RFC 8832 DCEP（Data Channel Establishment Protocol）** 与标准 **WebRTC DataChannel PPID**（`50` DCEP、`51` String、`53` Binary、`56` Empty String、`57` Empty Binary）编解码与通道生命周期管理；
- [ ] 评估在 Wasm / Native 后端引入 `v128` SIMD / 8 路切片查表加速 `crc32c`（保持现有标量 4 路切片查表参考实现与全量位级等价回归测试，`.mbti` 公共接口零破坏）；
- [ ] 扩充 `bench/` 基准套件，新增大报文分片（32KB–64KB）与高并发流（16/64 流）吞吐与内存分配对比数据。

---

## `v0.8.0`：序列算术形式化边界验证与模糊测试加固

- [ ] 对 `packet/serial.mbt`（RFC 1982 32-bit TSN / 16-bit SSN 回绕算术）与 `association/recv_queue.mbt`（Gap Ack Block 合并与边界截断）补充基于属性测试 / 穷举边界模型的形式化性质检验；
- [ ] 为 `packet/decode_packet` 与 `association/handle_packet` 增加确定性种子驱动的变异模糊测试（Fuzz Corpus），覆盖畸形 TLV、嵌套填充、极端窗口与边界分片重组，确保全路径零 panic、零 OOM；
- [ ] 扩充 `harness/interop_wire.py` 跨实现线级互操作覆盖面，探索对接 `usrsctp` / `pion/sctp` 真实抓包向量做只读回放互验。

---

## `v1.0.0`：ABI 冻结与生产级稳定发布

- [ ] 审查并冻结根门面 `moonsctp` 及核心子包（`crc32c`、`cookie`、`packet`、`association`）全部 `pkg.generated.mbti` 公开 ABI，发布语义化版本兼容承诺；
- [ ] 补齐英文与中文双语 API 文档示例、错误码排障手册与 Sans-I/O 宿主集成指南（含 `moonbitlang/async` 与浏览器 Worker 集成范式）；
- [ ] 完成发布前全量安全复审与三端长稳压测，正式发布 `v1.0.0`。

---

## `v1.0.0+`：远期可选扩展（按社区需求评估）

- [ ] **RFC 6525（Stream Reconfiguration）**：评估在独立扩展层支持运行时动态流重置（`RE-CONFIG` Chunk）与流扩容；
- [ ] **RFC 8260（Stream Schedulers & User Message Interleaving / I-DATA）**：评估支持大消息交错分片与加权公平流调度，消除同关联内大消息对小消息的发送端排队延迟；
- [ ] **RFC 4895（SCTP-AUTH）与路径 MTU 探测（RFC 8899 DPLPMTUD）**：在保持 Sans-I/O 纯度与零外部依赖前提下按需评估。
