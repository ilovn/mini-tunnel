# 上下文

- Quinn 官方 `Connection::max_datagram_size` 文档说明该值可能随 path MTU estimate 在连接期间变化。参考：https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.max_datagram_size
- mini-tunnel 每次 `send_packet` 查询该值并计算单帧/fragment payload capacity；已受限于协议 1175-byte 帧 payload cap。
- 文档更新区分已实现的 API 适配与仍待完成的真实网络 MTU 变化/丢片验证、Windows/macOS 特权 TUN 测试和生产运维加固。
