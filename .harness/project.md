# 项目上下文

- 技术栈：Rust 2024 workspace；Axum/Tokio Coordinator，Serde 版本化协议，Clap CLI，Quinn/QUIC 数据面，TLS/TCP peer 与 opaque relay。
- 目录：`crates/mini-tunnel-protocol` wire types；`mini-tunnel-coordinator` 控制面；`mini-tunnel-agent` 客户端数据面；`mini-tunnel-relay` relay；`mini-tunnel-cli` 命令行；`docs/architecture.md` 架构。
- Coordinator 状态通过版本化 JSON 快照持久化，原子替换并限制 Unix 文件权限；同一状态文件使用 OS 文件锁避免多进程并发写。地址分配与邀请状态仍是单进程/单节点能力，不是分布式数据库。
- 网络边界：Coordinator 默认只监听 `127.0.0.1:8080`；非 loopback 监听必须配置 TLS。控制 API 有 per-source-IP 速率限制和请求体限制。token 经环境变量或受保护配置传递，不写入日志。
- Relay 通过 Coordinator 签发的短期 ticket 配对 peer，具备全局/单源连接上限、会话字节上限、握手/配对超时和优雅关闭；peer payload 通过端到端 TLS 传输。
- Agent 具备 IPv4/IPv6 ULA overlay、双栈包校验与多 peer mesh、活动 IPv4/IPv6 interface host candidate 收集、STUN server-reflexive 映射发现、双方同时 UDP 拨号和确定性连接选举、TCP/Relay fallback、路径质量探测与重连。单 peer 和 mesh 提供 opt-in 的 RFC 8445 ICE Agent；仍缺特权真实 TUN 验收、Windows TUN/route 配置和实网 NAT/QoS 矩阵。
- 质量门禁见 `.harness/config.json`：`cargo fmt --all -- --check`、`cargo test --workspace`、`cargo clippy --workspace --all-targets -- -D warnings`。推送前必须通过门禁并检查 `git diff --check`。
- 用户已明确授权每个阶段通过测试后提交并推送到 `origin/main`；不要部署，也不要发送外部消息。
