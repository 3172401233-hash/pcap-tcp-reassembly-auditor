# pcap-tcp-reassembly-auditor

离线 TCP 重组审计库：从 PCAP 中解析 IPv4/IPv6 + TCP 头与载荷（**不解析任何应用层协议**），按四元组维护流，输出完整重组区段、缺口列表和异常事件，用于判断抓包差异究竟来自丢段、重传还是两端对重叠片段采用了不同策略。

## 用法

```python
from tcpaudit import audit_pcap

for conn in audit_pcap("capture.pcap"):
    for d in conn["directions"]:
        print(d["src"], "->", d["dst"])
        print("  regions:", d["regions"])  # [(流偏移, bytes), ...]
        print("  gaps:   ", d["gaps"])     # [(start, end), ...]
        print("  events: ", d["events"])   # 异常事件列表
```

## 重组冲突策略

- **先到者优先（first-seen-wins）**：同一字节范围出现内容冲突时，保留先收到的字节，**绝不**用后到数据覆盖。
- 每次冲突记录一条 `conflict` 事件，包含：
  - `packet`：PCAP 中的包序号（0 起）；
  - `offset`：冲突在流中的起始位置（相对首个数据字节）；
  - `old` / `new`：旧字节与新字节的 hex；
  - `diffs`：逐字节差异 `[{offset, old, new}, ...]`。
- 内容一致的重叠记为 `retransmission` 事件（不算冲突）。

## 处理能力

- **流跟踪**：按无序四元组归并双向连接，每个方向独立重组。
- **序号回绕**：所有序号以 ISN+1（无 SYN 时以首个数据序号）为基准做 mod 2^32 换算为绝对流偏移。
- **纯 ACK**：无载荷包不参与重组。
- **乱序 / 重传**：乱序新数据记 `out_of_order`；完全重复记 `retransmission`。
- **FIN/RST**：记录 `fin`/`rst` 事件；RST 后到达的数据拒绝重组并记 `data_after_rst`；FIN 之后的数据记 `data_after_fin`。
- **连接未建立**：未观察到 SYN 就出现数据时记 `data_before_syn`，以首个数据序号为基准继续重组。
- **缺口**：`gaps` 给出从未收到的字节范围（截至最大已见偏移或 FIN 位置）。

## PCAP 支持

经典 pcap 格式（大小端均可），LINKTYPE_ETHERNET，支持 802.1Q VLAN、IPv4（含选项）、IPv6（跳过逐跳/路由/分片/目的选项扩展头）、TCP（含选项）。不校验校验和。

## 测试

测试用代码合成 PCAP，覆盖：换序、重复、重叠内容一致、重叠内容冲突、序号回绕、连接未建立、RST 截断，以及缺口、纯 ACK、FIN 后数据、双向流、IPv6。

```bash
python -m unittest
```
