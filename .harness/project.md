# 项目上下文

- 技术栈：Rust 2024 workspace；Axum/Tokio coordinator，Serde 版本化协议，Clap CLI。当前地址分配和邀请状态仅为内存态。
- 目录：`crates/mini-tunnel-protocol` wire types；`mini-tunnel-coordinator` 控制面；`mini-tunnel-agent` 客户端数据面；`mini-tunnel-relay` relay；`mini-tunnel-cli` 命令行；`docs/architecture.md` 架构。
- 命令：`cargo run -p mini-tunnel -- --help`；`cargo fmt --all -- --check`；`cargo check --workspace`。
- 网络边界：Coordinator 默认仅绑定 `127.0.0.1:8080`；目前无生产认证/限流，不得暴露公网。token 仅通过环境变量传递，不加入日志。
- 当前缺少测试/构建质量门禁；不要把无 gates 的 Harness check 当作代码验证。
- 本地 git 分支 `main`，origin 为用户给出的 GitHub SSH 地址；未经指示不提交、不推送、不部署。
