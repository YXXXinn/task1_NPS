# 演示录屏脚本（demo_script.md）

持续更新：录屏步骤、讲解要点、对应证据。本阶段=第二阶段（最简 GUI 实时包列表）。

## 第二阶段录屏步骤（待录制）

1. 环境说明（口播）：macOS arm64 + venv(Python 3.12) + Scapy(libpcap 后端) + PySide6。
2. 启动：终端执行 `sudo .venv/bin/python -m sniffer gui`，展示主界面。
   - 讲解：为何需要 sudo（抓包要访问 /dev/bpf*）。
3. 选网卡（如 en0），BPF 过滤框演示：
   - 先留空点「开始」，看全量实时抓包；状态「● 运行中」。
   - 讲解：BPF 抓包过滤在**内核层**，不匹配的包内核即丢弃；与第三阶段「显示过滤」区别。
4. 制造可控流量：另开终端 `curl http://example.com` 或 `ping` 本网关，观察表格实时增行。
5. 停止：点「停止」，状态回到「■ 已停止」，按钮恢复；再「开始」验证可重入。
6. 关窗：验证无异常、进程干净退出。
7. 错误处理（可选）：不加 sudo 启动并点「开始」，展示权限错误弹窗。

## 讲解要点（答辩）

- 线程模型：QObject worker + moveToThread；子线程只发信号、不碰 Widget。
- 停止干净：select 轮询 0.2s 检查 stop 事件，空闲也能及时退出；finally 关 socket。
- 有界缓存 + QTimer 200ms 批量刷新：高流量不卡、内存不无限涨（缓冲丢最旧 + 表格行上限）。
- 协议列只做链路/网络/传输层标识，不按端口臆断应用层（协议判定审慎）。

## 对应证据

- 自动化验证：`evidence/logs/stage2_headless_tests.log`
- 截图：`evidence/screenshots/stage2_*.png`（**待手动采集**，见 index.md）
- 设计示意图：`evidence/diagrams/threading_model.md`

## 第三阶段子阶段 a 录屏步骤（详情栏 + 十六进制，待录制）

1. `sudo .venv/bin/python -m sniffer gui` 启动，选 en0，点「开始」抓包。
2. 展示三栏：上=Packet List，下左=详情（协议分层树），下右=十六进制/ASCII。
3. 点选一个 TCP 包 → 详情栏逐层展开 Ethernet / IP / TCP（讲：字段来自 scapy 已解析的层）。
   - 强调：端口显示为**数字**，**不**把端口臆断成 HTTP 等应用层（应用层识别留待后续子阶段）。
4. 右下看该包十六进制 + ASCII（偏移/hex/ASCII 对齐，不可见字节 '.'），与 Wireshark 对照。
5. 再点一个 UDP / ICMP / ARP 包，展示分层随包类型变化。
6. 讲"选中映射用序号(seq)而非行号"：抓包滚动时点旧包仍能取回正确包对象。

### 讲解要点（答辩）
- 三栏用 QSplitter 组合；详情/hex 仅在选中时渲染，不影响列表实时刷新、不阻塞主线程。
- 数据留存：有界缓存里连原始字节 raw=bytes(pkt) 一起存；raw 随记录被表格行上限淘汰而释放，内存有界。
- 详情树只反映 scapy 的 dissection，不加应用层判定；端口用数字避免"端口→应用层"臆断。

### 对应证据（第三阶段）
- 自动化：`evidence/logs/stage3_headless_tests.log`
- 截图：`evidence/screenshots/stage3_{three_pane,detail_tree,hexdump}.png`（**待手动采集**）

## 第三阶段子阶段 b+c 录屏步骤（显示过滤 + 应用层推测，待录制）

1. 启动抓包，产生可控流量：`curl http://example.com`（HTTP）、访问一个 https 站点（TLS）、`dig example.com`（DNS）。
2. **显示过滤 vs BPF**（讲义第 9 页思考题的"层次"考点）：
   - 顶部「BPF 抓包过滤(内核层)」：演示重启抓包用 `tcp` 过滤——内核层丢包、不可逆。
   - 第二行「显示过滤(界面层)」：输入 `tcp and port 443` → 列表**即时**只显示匹配；清空 → 立刻恢复（底层全量没丢）。强调可逆、作用于已抓到的包。
   - 展示状态栏「全量保留 N / 显示过滤后可见 M」。
3. **应用层推测（严守端口≠证据）**：
   - 点一个 HTTP 包 → 详情栏末尾「应用层(推测)」节点：`疑似 HTTP（推测，依据载荷）`，展开看"判定依据(载荷)=HTTP 请求行"。
   - 点一个 TLS 包 → `疑似 TLS（推测）`，依据 TLS record 头 0x16 0x03。
   - **反例**：找一个 443 上并非 TLS 的包（或自造）→ 节点显示「未识别（仅端口提示，载荷未证实）」，强调没把端口当证据。
   - 若遇到端口与载荷冲突（如 80 上是 TLS）→ 节点 notes 标注"以载荷为准"。
4. 列表「协议」列对已识别的包追加 `(疑似HTTP?)` 带问号标注——强调是推测不是确证。

### 讲解要点（答辩）
- 显示过滤=界面层、可逆、作用于已抓到的包；BPF=内核层、丢包不可逆。两者实现与数据路径不同。
- 应用层判定**只认载荷特征**，端口仅作提示并显式标注；端口/载荷冲突时以载荷为准——正是讲义第 9 页思考题的答案。
- 过滤/识别逻辑都是无 Qt 纯函数（`display_filter.py` / `appid.py`），有无头测试与反例覆盖。

### 对应证据（第三阶段 b+c）
- 自动化：`evidence/logs/stage3b_filter_appid_tests.log`
- 截图：`evidence/screenshots/stage3b_display_filter.png`、`stage3b_filter_vs_bpf.png`、`stage3c_appid_http_tls.png`、`stage3c_appid_counterexample.png`（**待手动采集**）

## 可选扩展：TCP 流追踪（Follow TCP Stream，待录制）

1. 抓包并产生一次 HTTP 请求（`curl http://example.com`）。
2. 在列表里选中该会话的任意一个 TCP 包 → 点「追踪此 TCP 流」：
   - 列表立即只剩这条会话的包（请求/响应两个方向都在）；第三行显示流概要 `ipA:portA ↔ ipB:portB | 包数 | 双向字节`。
   - 讲：会话键=两端 {IP, Port}、**方向无关**；**不按进程归流**。
3. 点「查看流内容(重组)」→ 弹窗：A→B（请求）与 B→A（响应）按方向+抓包顺序拼接，可切换 文本/Hex。
   - 诚实说明：这是从简重组（按抓包顺序），**未做**完整 TCP 重排（重传/乱序/缺包不处理）。
4. 点「清除流追踪」→ 列表恢复（若此前有显示过滤，显示过滤仍生效，证明两者叠加、互不破坏）。

### 讲解要点（答辩）
- 会话键规范化：对两端 (ip, port) 排序，A→B 与 B→A 得到同一键 → 同一条流。
- 内存有界：流数量上限（LRU 淘汰最久未活跃流）、每流只存最近 N 个包序号(seq，int)，不持有大对象，与 `_all` 有界缓存协调。
- 「当前流」过滤在视图层与显示过滤**叠加**，一键清除恢复；选中仍用 seq 稳定映射。

### 对应证据（可选扩展）
- 自动化：`evidence/logs/stage4_tcpflow_tests.log`
- 截图：`evidence/screenshots/stage4_follow_stream_list.png`、`stage4_follow_stream_reassembly.png`（**待手动采集**）
