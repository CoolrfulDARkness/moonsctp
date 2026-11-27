# Contributing to MoonSCTP

感谢你参与 `CoolrfulDARkness/moonsctp` 的持续建设！为确保多会话、多贡献者协作零回退，请遵循以下规范：

## 1. 冷启动必读顺序
1. `AGENTS.md`（块风格 `///|` 与工具链命令）
2. `moon.mod` 与全包 `pkg.generated.mbti`（公开 ABI 契约）
3. `docs/ARCHITECTURE.md`（分层架构与 Non-Goals）
4. `docs/SECURITY_AUDIT.md`（历史 P0/P1 安全防线红线）
5. `docs/ROADMAP.md` 与 GitHub Open Issues

## 2. 核心设计红线
- 核心协议包（`crc32c`、`cookie`、`packet`、`association`）必须永久保持 **纯 MoonBit、零外部依赖、零 FFI、零 `unsafe`、Sans-I/O**；
- 任何外部网络 I/O 示例一律隔离在 `examples/` 下；
- 绝不可移除或放宽端口绑定、`COOKIE_ECHO` 仅限 `Closed` 态、未来 SACK 守卫、`RecvTracker` 5 项 OOM 上限或过时 `FORWARD_TSN` 校验；
- `Crc32c`、状态队列等敏感内部字段必须保持 `priv`（在 `.mbti` 中显示 `// private fields`）。

## 3. 提交 PR 前必跑门禁（全部 0 警告通过）
```bash
moon fmt --check
moon info && git diff --exit-code -- '*.mbti'   # 若有意新增导出请在 PR 中说明
moon check -d
moon test --target wasm -d
moon test --target js -d
moon test --target native -d
python harness/interop_wire.py
```
