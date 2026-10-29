# 续接上下文

## Observe

- 基线 `a228519`，工作区干净。
- 当前协议只传 `assigned_ipv4`；Coordinator 分配/persist IPv4 lease；TUN builder 只配置 IPv4；packet parser 和 mesh 路由只识别 IPv4。
- `tun-rs 2.8.16` 的 `DeviceBuilder` 同时支持 `.ipv4()` 和 `.ipv6()`。

## 方案

先避免改动 Enrollment/PeerInfo wire schema：由 network UUID 派生 ULA `/64`，以已分配的 IPv4 address 低 32 位形成 IID。Coordinator 建网时检查派生 prefix 的本地唯一性。客户端根据同样纯函数推导地址。随后逐层实现 TUN、IP 包验证和 mesh dual-stack routing。

## 当前阶段

里程碑 A/B/C 已在工作区实现；当前需要先提交这阶段的可审查代码与文档。它仍是总目标中的一个中间模块，不将此提交视为目标结束。

## 里程碑 A 证据

- protocol `overlay_ipv6_prefix`/`overlay_ipv6_address` 使用 UUID ULA `/64` 和 IPv4 lease IID；测试了稳定性、地址唯一性和 UUID 前缀变化。
- Coordinator 会拒绝本地已有网络的相同派生 ULA prefix；冲突/唯一前缀选择测试通过。
- Harness check `f75c14d273a4`：fmt、workspace tests、workspace clippy 全通过。

## 里程碑 B/C 证据

- TUN 配置支持 IPv4 + 可选 IPv6 `/64`，IPv4/IPv6 均在读写边界验证头部长度、MTU、源/目的地址。
- 单 peer forwarding 与 mesh forwarding 按 IPv4/IPv6 目的地址投递；mesh 校验入站地址归属并支持动态加入/移除 IPv6 路由。
- Linux `ip -6 route` 与 macOS `/sbin/route -inet6` 支持 `/128` host route lease，测试覆盖命令参数及清理。
- CLI connect/listen/mesh 建立 IPv6 TUN 地址并显示 ULA；可选路由管理会同时配置 IPv4 `/32` 和 IPv6 `/128`。
- 限制：现有 peer frame 上限 1175 bytes、默认 TUN MTU 1150；尚未实现 IPv6 packet fragmentation/reassembly，因此不能满足 IPv6 最小 1280-byte 链路 MTU。当前实现仅在封装上限内转发 IPv6 包；完成标准 IPv6 MTU 保障仍待后续模块。
- 当前工作区完整门禁 Harness check `70e8cd37bfca`：fmt、workspace tests、workspace clippy 全通过；提交前将重新运行并记录。
