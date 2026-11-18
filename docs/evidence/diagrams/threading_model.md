# 线程通信与抓包刷新（示意图）

> 注意：本文件为**设计示意图**，非运行截图。可编辑源即下方 Mermaid 文本。

## 线程与信号模型

```mermaid
flowchart LR
    subgraph WT[抓包线程 QThread]
      W[CaptureWorker.run<br/>conf.L2listen + select 轮询 0.2s]
    end
    subgraph MT[主线程 GUI]
      S[槽 _on_packet]
      B[(BoundedPacketBuffer<br/>maxlen=20000 丢最旧)]
      T[QTimer 200ms _flush]
      M[PacketTableModel<br/>行上限 5000 淘汰最旧]
      V[QTableView]
    end
    W -- "packetCaptured(PacketRecord)<br/>排队连接(跨线程)" --> S
    S -- append --> B
    T -- drain 批量 --> M
    B --> T
    M --> V
    MT -- "request_stop() / 关窗" --> W
```

## 关键点

- 子线程只发信号，**不触碰任何 Widget**。
- 包→记录的解析在子线程完成，主线程只收轻量 `PacketRecord`。
- 两级有界：缓冲层（丢最旧）+ 表格行上限（淘汰最旧），高流量下内存不无限涨。
- GUI 不逐包刷新：QTimer 每 200ms 批量 drain 一次。
- 停止：`request_stop()` 置位 Event，select 轮询最多 0.2s 内退出循环，finally 关 socket。

## 两种过滤的层级区别（示意）

```mermaid
flowchart TB
    K[内核 BPF 抓包过滤<br/>sniff filter= / conf.L2listen filter=] -->|不匹配的包内核即丢弃| U[用户态已抓到的包]
    U --> D[显示过滤（第三阶段）<br/>在界面上对已抓到的包筛选，可反复开关]
```
