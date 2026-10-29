# 上下文

- Review 发现 Quinn 的 `max_datagram_size()` 可随路径 MTU 上升而大于协议支持的单帧大小；发送端此前只按路径值计算，可能生成接收端拒绝的 v1 frame。
- 现增加独立的 payload limit helpers，统一将单帧 payload cap 到 1175 bytes、片段 payload cap 到 1159 bytes，同时继续服从 Quinn 当前 datagram limit。
- 单元测试覆盖巨大路径上限、较小路径上限和无法容纳 fragment header 的边界。
