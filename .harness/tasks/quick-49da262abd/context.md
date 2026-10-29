# 上下文

- Microsoft Learn `netsh interface` 文档确认 IPv4/IPv6 均支持 add/delete route，prefix、interface alias 和 `store=active` 参数；Windows routes 使用 netsh 直传参数，不经 shell。
- 新增 Windows RoutingPlatform，自动选择当前 Windows backend；安装 IPv4 `/32` 和 IPv6 `/128` peer routes，限定在当前 TUN alias，且仅写入 active store。RouteLease 仍只删除本进程成功添加的精确路由。
- 单元测试通过 FakeRunner 检查 Windows IPv4/IPv6 add/delete 命令和含空格的 interface alias。
- 限制：当前工作环境不是 Windows，没有真实 netsh/TUN 特权运行环境；Windows runtime acceptance remains outstanding.
