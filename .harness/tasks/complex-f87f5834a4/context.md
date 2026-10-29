# 续接上下文

记录发现、决策、证据、阻塞和下一步。
# 续接上下文

## Observe

- 基线 commit `3324507` 已实现双栈 overlay 和 IPv6 TUN 路由，但 TUN MTU 是 1150，peer frame payload 上限 1175；IPv6 最小链路 MTU 1280 无法通过单个 QUIC DATAGRAM 承载。
- QUIC DATAGRAM 不会做 IP 分片；放大单帧上限会破坏底层 path MTU 兼容性。

## 实现

- Peer data frame 保留 v1 小包编码；大包使用 v2 fragment frame，保留网络 tag 和每片 replay sequence，包含 packet ID、index/count、总长和 chunk size。
- 发送时受当前 `max_datagram_size()` 限制切片，并对同一 peer 的片序列化，避免 replay window 被并发 packet 推出窗口。
- 每 peer 重组最多保留 4 个不完整 packet、每 packet 最多 64 片/9000 bytes，5 秒后清理；重复片、元数据不一致和超限输入会拒绝。
- 默认 TUN MTU 1280，配置范围 576–9000；使用 IPv6 时强制不低于 1280。
- 大于单帧的 packet 需要对端支持 v2 fragment frame；MTU 动态探测/反馈及丢片恢复仍未实现。丢任意一片时 packet 过期丢弃。

## 验证

- agent lib tests：UDP 真实 QUIC loopback 传输 4096-byte payload，并重组；重组单元测试覆盖乱序、重复和 oversized metadata。
- Harness check `c0528fac5478`：fmt、workspace tests、workspace clippy 全通过；`git diff --check` 通过。
