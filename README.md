# 网络嗅探器（《软件与系统安全》实验 1A）

一个带 GUI 的网络嗅探器。技术栈：**macOS + Python + Scapy + PySide6**。
本仓库按阶段推进，当前处于 **第三阶段完成 + 可选扩展（TCP 流追踪）**。

## 阶段计划

- 第一阶段（已完成）：环境搭建、项目骨架、命令行工具——网卡枚举、最小抓包、Scapy 后端探测、权限处理。
- 第二阶段（已完成）：抓包线程化（QObject worker + moveToThread）+ 跨线程 Qt 信号传包 + 有界缓存 + QTimer 批量刷新，最简 GUI 实时显示包列表。
- 第三阶段(a)（已完成）：类 Wireshark 三栏——Packet List + 协议分层详情树 + 十六进制/ASCII 视图。
- 第三阶段(b)(c)（已完成）：GUI 显示过滤（界面层，区别于 BPF 内核层）+ 应用层审慎推测（HTTP/TLS/DNS，端口≠证据、结论标「推测」）。
- **可选扩展（已完成）**：基于 IP+Port 的 TCP 流追踪（Follow TCP Stream，方向无关；不按进程归流）+ 从简的流内容重组。

## 环境要求（本机实测）

- macOS（arm64 / Apple Silicon，实测 `uname -m` = `arm64`）
- Python 3.12（Homebrew `/opt/homebrew/bin/python3.12`，实测 3.12.15）
  - 系统自带 `python3` 为 3.9.6，也能跑 scapy；选 3.12 是为了与后续 PySide6 更好地匹配。
- libpcap：macOS 自带 libpcap 1.10.1（随 `/usr/sbin/tcpdump` 一同提供）。
  - 注意：该 dylib 位于 dyld 共享缓存中，`ls /usr/lib/libpcap*` 看不到实体文件，属正常现象。

## 创建 venv 与安装依赖

```bash
cd "/Users/yuxinxin/软件与系统安全/实验1"

# 1) 用 Homebrew Python 3.12 创建虚拟环境（venv 不提交，已在 .gitignore 中）
/opt/homebrew/bin/python3.12 -m venv .venv

# 2) 激活
source .venv/bin/activate

# 3) 安装依赖
python -m pip install --upgrade pip
pip install -r requirements.txt
```

> 说明：`scapy` 与 `PySide6-Essentials` 为项目运行依赖（GUI 只用 QtCore/QtGui/QtWidgets）。
> 第二阶段已实际安装并 import 验证 `PySide6-Essentials==6.12.0`（PySide6 的精简子集，
> 本机 arm64 + Python 3.12 + macOS）。若需完整套件可改装 `PySide6==6.12.0`。
> 注：国内网络从 pythonhosted 下载较慢，可加镜像，如
> `pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt`。

## 运行方式

```bash
# 环境自检（Python/架构/Scapy 后端/网卡，一次看全）
python scripts/check_env.py

# 列出本机网络接口
python -m sniffer ifaces

# 打印 Scapy 实际启用的抓包后端（libpcap 还是原生 BPF）
python -m sniffer backend

# 启动最简 GUI（实时包列表）——抓包需 root，见下
sudo .venv/bin/python -m sniffer gui

# 命令行最小抓包验证（需要抓包权限，见下）
sudo .venv/bin/python -m sniffer capture -i en0 -c 5 -t 10 -f "tcp"
```

## 无头自动化验证（合成包，无需 root/GUI）

```bash
python tests/test_packet_model.py                               # 纯逻辑：判定/字段/有界缓存
python tests/test_dissect.py                                    # 纯逻辑：协议分层解析 + hex
python tests/test_appid.py                                      # 纯逻辑：应用层推测 + 反例
python tests/test_display_filter.py                             # 纯逻辑：显示过滤语法/筛选
python tests/test_tcpflow.py                                    # 纯逻辑：TCP 流键/索引/有界/重组
QT_QPA_PLATFORM=offscreen python tests/test_gui_headless.py     # 表格模型 + 跨线程信号管线
```

## 抓包权限说明

macOS 抓包需要访问 `/dev/bpf*` 设备，通常需要 **root 权限**：

- **GUI**：用 `sudo .venv/bin/python -m sniffer gui` 启动；若不加 sudo，点「开始」后会弹出权限错误对话框，界面不崩溃。
  - macOS 上 sudo 拉起 GUI 偶有坑（窗口服务器/焦点问题）。若遇到，可先 `sudo -v` 预授权，或改用已安装 ChmodBPF（Wireshark 自带）放宽 `/dev/bpf*` 权限后免 sudo 运行。**此项需用户在本机手动验证。**
- 不加 sudo 运行 `capture` 一般会失败，程序会捕获权限错误并打印清晰提示。
- 正确做法是用 **venv 里的解释器 + sudo**：`sudo .venv/bin/python -m sniffer ...`
  直接 `sudo python -m sniffer` 可能走到系统 python 而找不到 scapy。
- `ifaces` 与 `backend` 两个子命令**不需要** root，可直接运行。

## 抓包后端与过滤的概念区分

- **libpcap vs 原生 BPF**：本项目优先让 Scapy 走 libpcap（通过环境变量
  `SCAPY_USE_LIBPCAP=yes`，已在 `sniffer/__init__.py` 中设置）。若本机 libpcap
  provider 不可用，Scapy 会自动回退到 macOS 原生 BPF。实际结果以
  `python -m sniffer backend` 的运行时检测为准，不臆测。
- **BPF 抓包过滤 vs GUI 显示过滤**：
  - BPF 抓包过滤在**内核层**生效，通过 `capture(..., bpf_filter=...)` 或 GUI 顶部「BPF 抓包过滤(内核层)」框传给 Scapy 的 `filter=`，语法同 tcpdump（如 `tcp port 80`）。**不匹配的包在内核即被丢弃、不可逆**。
  - GUI **显示过滤（界面层）**作用于**已抓到的包**：不丢数据、可随时改/清空、立即重筛（清空即恢复全部）。底层有界缓存始终保留全量。
  - 两者层级、时机、可逆性都不同，代码（`sniffer/gui/display_filter.py` 独立于抓包）与讲解中分别对待。

### 显示过滤语法（本实现真正支持的子集，不是 Wireshark 全套）

- 协议关键字：`tcp` | `udp` | `icmp` | `arp` | `ip` | `ipv6`
- 地址：`ip==<addr>` | `ip!=<addr>` | `src==<addr>` | `dst==<addr>`（`ip` 匹配源或目的）
- 端口：`port <n>` | `port==<n>` | `port!=<n>` | `sport==<n>` | `dport==<n>`（`port` 匹配源或目的）
- 组合：`and` / `or` 连接，优先级 **and 高于 or**（无括号）；大小写不敏感；空表达式=显示全部。
- 示例：`tcp`、`tcp and port 443`、`ip==172.22.124.230`、`udp and port 53`、`icmp or arp`
- 语法非法时界面给出「语法错误」提示并保持当前视图不变（不乱筛）。

### 应用层识别：审慎「推测」（端口≠证据）

- 逻辑在 `sniffer/gui/appid.py`（无 Qt 纯函数），本阶段识别 **HTTP / TLS/HTTPS 握手 / DNS**。
- **判定依据载荷特征**，不是端口：HTTP 看请求行/响应行（`... HTTP/1.` / `HTTP/1. ...`）、TLS 看 record 头（`0x16/0x14-0x17` + `0x03 0xXX`）、DNS 看 scapy 解析出的 DNS 结构。
- **端口只作提示并显式标注**：端口与载荷一致会注明；不一致（如 80 上是 TLS、443 上非 TLS）**以载荷为准**并标注冲突；载荷无特征时即使端口常见也只显示「仅端口提示、未证实」，不下结论。
- 所有结论在 UI 上均带「**推测**」字样；列表协议列对已识别的追加 `(疑似X?)` 带问号，详情栏末尾有「应用层(推测)」节点列出依据/端口提示/置信度。识别不出显示「未识别」。

### TCP 流追踪（Follow TCP Stream，可选扩展）

- 逻辑在 `sniffer/gui/tcpflow.py`（无 Qt 纯函数 + 轻量有界状态类）。**只按 {IP, Port} 归流，不按进程归流**。
- **会话键定义**：取 TCP 两端 `(ip, port)` 排序得到规范化键，**方向无关**——`A→B` 与 `B→A` 归为同一条流；非 TCP / 缺端口无流键。
- **用法**：选中一个 TCP 包 → 点「追踪此 TCP 流」→ 列表只显示该会话（两个方向）的包；第三行显示流概要 `ipA:portA ↔ ipB:portB | 包数(双向) | 双向字节`。点「查看流内容(重组)」弹窗按方向(A→B / B→A)拼接 TCP 载荷，可切换 文本/Hex。点「清除流追踪」恢复。
- **与显示过滤的关系**：流追踪是**视图层的一个附加过滤**，与显示过滤**叠加**（可见 = 显示过滤 ∩ 当前流）；两者独立、都可一键清除，底层 `_all` 全量不丢。
- **内存有界**：流数量有上限（超限按 LRU 淘汰最久未活跃的流）、每条流只保留最近 N 个包序号(`seq`，int)，不持有大对象；与 `_all` 有界缓存协调，不会无界增长。
- **重组的局限（务必知悉）**：当前为**从简重组**——按**抓包顺序**+方向拼接载荷，跳过无载荷包（握手/纯 ACK）。**未实现**完整 TCP 重组：不处理重传、乱序、按 TCP seq 重排、缺包补零。仅用于直观查看会话内容，不等价于 Wireshark 的 Follow Stream。

## 目录结构

```
.
├── sniffer/            # 核心包
│   ├── __init__.py     #   设置 libpcap 偏好（须在导入 scapy 前）
│   ├── __main__.py     #   python -m sniffer 入口
│   ├── backend.py      #   Scapy 后端探测（libpcap / 原生 BPF）
│   ├── interfaces.py   #   网卡枚举
│   ├── capture.py      #   命令行最小抓包 + 权限错误处理
│   ├── cli.py          #   argparse 子命令：ifaces / backend / capture / gui
│   └── gui/            #   GUI
│       ├── packet_model.py    # 纯逻辑(无Qt)：包→记录(含raw/端口/l3/应用层推测)、有界缓存
│       ├── dissect.py         # 纯逻辑(无Qt)：协议分层解析 + 十六进制/ASCII 格式化
│       ├── display_filter.py  # 纯逻辑(无Qt)：显示过滤(界面层) 语法解析与判定
│       ├── appid.py           # 纯逻辑(无Qt)：应用层审慎推测(HTTP/TLS/DNS，端口≠证据)
│       ├── tcpflow.py         # 纯逻辑(无Qt)：TCP 流键/有界流索引/流内容重组
│       ├── capture_worker.py  # QObject worker + moveToThread 抓包线程
│       ├── packet_table.py    # QAbstractTableModel：全量有界 + 显示过滤/流过滤视图 + 序号映射
│       ├── main_window.py     # 三栏窗口 + 显示过滤 + 应用层推测节点 + TCP 流追踪/重组窗口
│       └── app.py             # QApplication 启动入口
├── scripts/check_env.py       # 环境自检脚本
├── tests/                     # 无头自动化验证（合成包）
├── docs/                      # 证据/示意图/录屏脚本（见 AGENTS.md）
├── requirements.txt
├── README.md
└── 实验 1 讲解 2026.pdf        # 实验讲义（未纳入 Git，保持 untracked）
```

