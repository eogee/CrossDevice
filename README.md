# CrossDevice

局域网内 Windows ↔ Windows 的跨设备控制命令行工具：一台机器上的 `xd` 控制端，可以发现在同一局域网内运行了 `node` 执行器的其他 Windows 机器，并对它们执行远程命令、截屏、键鼠操作、文件传输与执行器热更新。双端均为 Python 单文件实现，运行时零第三方依赖。

| 项目 | 内容 |
|---|---|
| 形态 | 控制端 CLI（`xd.py`）+ 被控端常驻执行器（`node/node.py`）+ 回滚看门狗（`watchdog.py`） |
| 平台 | Windows 10+（双端；锁屏/服务会话下 GUI 能力受限，见"常见问题"） |
| 运行时 | Python ≥ 3.10，仅标准库（证书初始化使用内置 PowerShell，不引入 openssl） |
| 协议 | HTTPS（TLS 1.3，自签证书 + TOFU 指纹固定）+ UDP 发现广播（51889） |
| 许可证 | MIT（见 [LICENSE](./LICENSE)） |

**与 a4agent 的关系**：本项目是一期独立仓库先行——先在本仓库冻结协议（[接口契约](./docs/接口契约.md) 为控制端与被控端的唯一耦合面）并完成设备运行时内核与安全验证；协议冻结后作为独立子进程模块并入 [a4agent](https://github.com/eogee/a4agent)（Windows 本地 AI 编程工具管理台）控制台，控制台 UI 在 a4agent 侧开发（决策 D2/D20/D29）。当前阶段面向使用者的入口就是本 README 描述的 CLI。

## 架构一览（对照需求文档第 8 章）

```
控制端（一期：xd CLI；二期：a4agent 控制台）
   ├─ 设备池（发现广播 + 扫描结果；广播是未认证信息，不自动信任）
   ├─ 多控制端身份与审计
   └─ 任务/文件/截屏编排
                 │  发现：UDP 广播（未认证，端口 51889）      控制：HTTPS（TLS 1.3，端口 51888）
                 ▼
设备运行时（node.py，独立子进程，可单独部署）
   ├─ 身份守卫（令牌/证书 + 私网来源 + 防重放 + 审计）
   ├─ 命令任务（线程 + sqlite 任务历史 + 留存清理）
   ├─ 图形能力（GDI 截屏 / SendInput 键鼠注入）
   ├─ 文件能力（读不限 / 写删白名单 / 流式大文件）
   ├─ 高权限驻留（计划任务）
   └─ 自更新（签名 → 备份 → 替换 → 看门狗探活 → 回滚）
```

要点：

- **发现与授权分离**：UDP 广播只解决"看得见"，报文不含任何凭据，设备池绝不自动 `add`、不写注册表（唯一例外：广播端口变化经完整 TLS+令牌 probe 通过后才校正注册表端口）。
- **控制端不监听控制面**：`xd` 仅为接收发现广播绑定 UDP 51889（`xd pool` 运行期间），不接收任何控制指令。
- **看门狗独立**：`watchdog.py` 永不参与热更新（`push-node` 只替换 `node/node.py`），专职"启动 → 探活 → 失败用 `.bak` 回滚"。

## 环境要求

- 双端均为 **Windows 10 及以上**（开发验证环境为 Windows 11）；被控端不支持 Linux/macOS。
- **Python ≥ 3.10**（`py` 启动器）；双端运行时零第三方依赖，证书初始化使用系统内置 Windows PowerShell 5.1。
- 同一局域网（私网网段）；跨网段/跨路由的发现与连通性不保证，可按"端口与防火墙"节手动指定地址。

## a4agent 集成形态（M4 起）

a4agent（Windows 本地 AI 编程工具管理台）双端安装后，CrossDevice 的设备运行时以子进程形态随控制台工作，免手工部署：

- **自动发现**：两台机器各装 a4agent 后即互相"看得见"——发现复用本仓广播机制（UDP 51889，node 启动即发 1 帧 + 每 10 秒 1 帧心跳，30 秒无帧判离线）。广播只是连接线索，**不会自动建立信任**（见下节"设备配对"）。
- **node 随 a4agent 安装并守护**：a4agent 安装包内嵌本仓 `node/node.py` 与 `tools/gen_cert.ps1`（位于 a4agent 安装目录 `node_runtime/`），由 a4agent 以**独立子进程**拉起本机 node 并守护（进程退出自动拉起；连续快速崩溃停止守护并如实提示，D29），TLS 证书缺失时自动调 `gen_cert.ps1` 生成。此形态下 node 配置落在 a4agent 的数据目录下，不在 `%LOCALAPPDATA%\CrossDevice`。
- **独立部署不受影响**：不使用 a4agent 的场景仍按下方"安装（三步）"手工部署（cert init → node → xd add），两种形态协议与行为同源。
- **协议口径不变**：控制端与被控端的唯一耦合面仍是 [接口契约](./docs/接口契约.md)；a4agent 侧只做编排与界面，不引入私有协议。

## 设备配对（一次确认，M4 新增）

配对解决"首次连接要手工传令牌"的问题：两端装了 a4agent 的机器在设备页发起，被控端**本地一次确认**后建立长期信任，此后连接免手工。

**流程（两端视角）**：

1. 控制端 a4agent 在设备页对被控端发起配对；
2. 被控端 a4agent 弹出确认窗（显示"来自 <来源 IP> 的配对请求"），由设备所有者**点确认或拒绝**——确认是"人为建立信任"的动作（R7 前提不变）；
3. 确认后被控端同屏展示**一次性 6 位配对码 + 倒计时**（控制端无需看码，等待输码）；
4. 控制端输入配对码完成建立，被控端向控制端签发专属身份令牌并持久化——**该设备对长期自动连接**（令牌持久化，设备改名/IP 漂移自愈沿用既有机制）；
5. 被控端点**拒绝**（或超时未确认）则连接不建立。

**防滥用三件套（如实陈述）**：配对码**一次性**（消费即失效）；**短时效**（等待确认 120 秒、配对码 ≤5 分钟）；**猜码上限**（默认 5 次输错即作废本次会话）；发起端另受来源限频（默认 10 秒）。

**边界（务必知悉）**：

- 发现广播仍是**未认证信息**：配对不会因"同网段、看得见"而自动发生（D38）；
- 未配对设备对被控端既有端点的请求一律 **401**；非私网来源一律拒绝（且不落审计）；
- **不提供同网段静默互信**：每台新设备都需要被控端本地一次确认（配对建立的是单个身份的信任，新设备仍需各自确认）；
- `xd add` 手工令牌路径**完整保留**（E-02）：偏好手工注册的仍按"安装（三步）"第 ③ 步执行；
- 配对确认窗由 a4agent 提供（协议端点规格见契约 §23，`xd` CLI 不新增配对子命令）；a4agent 设备页的三块布局（本机被控端 / 已配对设备 / 发现的设备）与配对失败提示（按错误码如实显示，如限频、会话超时、猜码超限）以其实际实现为准。

配对前后如需在控制端观察设备池（独立部署或排障场景），可用 `py xd.py pool --seconds 5` 采样 5 秒输出快照（需本机入站放行 UDP 51889，见"端口与防火墙"）。

## 安装（三步）

以下命令在被控端与控制端分别执行；示例统一用 `py xd.py …` / `py node\node.py …` 形态（无包安装器，直接以源码运行）。

**① 被控端：初始化证书**

```
py xd.py cert init
```

生成自签证书与私钥 PEM，默认输出到 `%LOCALAPPDATA%\CrossDevice\tls\`（即 node 默认 TLS 目录，生成后对 node 直接生效），打印证书路径与 SHA-256 指纹。目标目录已有证书时需 `--force` 才覆盖；可选参数 `--out <目录>`、`--days <N>`、`--host <CN>`。PowerShell 不可用时会明确报错并给出手动运行 `tools/gen_cert.ps1` 的完整命令行。

**② 被控端：启动 node 执行器**

```
py node\node.py
```

首次启动自动生成 32 位十六进制令牌（写入 `%LOCALAPPDATA%\CrossDevice\node.json`，并在横幅「令牌」行显示），绑定默认端口 51888，横幅给出 `https://<IP>:51888` 访问地址。常用选项：`--token <令牌>`（设置/覆盖 default 身份令牌）、`--workspace "D:\Shared"`（写/删白名单根，逗号分隔可多个）、`--port <N>`、`--instance <名>`（多实例）。首次运行如触发 Windows 防火墙弹窗，请按"端口与防火墙"节放行。

**③ 控制端：注册设备**

```
py xd.py add <被控端IP> --token <被控端令牌>
```

注册前会校验令牌与连通性，成功输出设备名（缺省取被控端 hostname，可 `--name <名>` 指定）、主机名、系统、交互/锁屏/提权状态与 TOFU 证书指纹。可选 `--port <N>`（默认 51888）。控制端注册表位于仓库 `data/devices.json`（明文存储为过渡方案，**含令牌，请勿提交或外发**，见"安全须知"）。

之后所有命令以设备名调用：`py xd.py ping <设备名>` 应返回「在线 往返 N ms」。

## 快速上手

### 设备池（`pool`）：发现与授权分离

```
py xd.py pool
py xd.py pool --seconds 15
```

默认持续监听并每 2 秒重印设备池表格（Ctrl+C 退出）；`--seconds 15` 为采样 15 秒后输出一次快照退出。

表格列：在线/离线（30 秒无帧判离线）、device_id、源 IP、端口、版本、主机名、已收帧数、首见/最近时间。**广播只是连接线索**：设备不会自动进入注册表，看到新设备后仍需 `xd add <IP> --token <令牌>` 显式注册。若设备改了端口，池会经完整 TLS+令牌 probe 通过后自动校正注册表端口（输出「端口同步：…」）。注意：`xd pool` 需要本机入站放行 UDP 51889（见"端口与防火墙"）。

### 远程命令与任务历史（`exec` / `task`）

```
py xd.py exec nb echo hello
py xd.py exec --shell powershell nb Get-Process python
py xd.py exec --timeout 30 nb ping -n 100 127.0.0.1
py xd.py exec --detach nb notepad
py xd.py task ls nb
py xd.py task ls nb --status done --limit 20
py xd.py task show nb <任务ID>
```

`--detach` 启动 GUI 程序后立即返回 PID；任务历史（`task ls`/`task show`）在执行器重启后仍可查，`task show` 详情含 stdout/stderr。

注意：`exec` 的选项（`--shell` / `--cwd` / `--timeout` / `--detach`）**必须写在设备名之前**——设备名之后的全部内容按原样作为命令（`--shell` 支持 `cmd`/`powershell`/`none`，默认 `cmd`）。命令默认超时 60 秒（超时终止子进程，状态 `timeout`）；任务记录持久化（默认保留 30 天或 100,000 条，先到先清），一期任务仅发起身份本人可见。

### 截屏（`shot`）

```
py xd.py shot nb
py xd.py shot nb -o C:\temp\desk.png
py xd.py shot nb --monitor 0
```

输出默认保存为 `shot_<设备名>_<时分秒>.png`（`-o` 指定路径，`--monitor N` 指定显示器）。

被控端默认输出**原始分辨率**（全像素、不缩放，FR-05/D18）整幅虚拟桌面的 PNG；带宽受限场景可显式传 `--max-width <N>`（如 `--max-width 1600`）让超宽画面等比缩小以省流量。

### 键鼠与输入租约（`click` / `move` / `type` / `key` / `wheel` + `--take` / `release`）

```
py xd.py click nb 960 540
py xd.py click --double nb 200 300
py xd.py click --button right nb 200 300
py xd.py move nb 500 500
py xd.py type nb "hello 你好"
py xd.py key nb ctrl+s
py xd.py wheel nb -3
py xd.py release nb
```

坐标按虚拟桌面物理像素归一化；`wheel` 的滚动量负值向上。同一被控端同一时刻只有一个控制端持有输入权（60 秒租约自动续期）：他人持有时输入命令返回 `INPUT_LEASE_TAKEN`；需要抢占时显式加 `--take`（如 `py xd.py click --take nb 960 540`），被抢占方下一次输入请求会收到一次 `INPUT_LEASE_TAKEN` 提示；`release` 主动释放租约。被控端处于锁屏或非交互会话时，输入不会生效并明确提示（见"常见问题"）。

### 宏（macro rec/run）

把本机（控制端）录下的一段键鼠操作存成宏文件，再按原节奏回放到任意已注册设备。宏是**白名单动作类型序列**——**不允许任意脚本**（D30 红线：不支持循环、条件、变量、表达式、外部命令）；宏文件只在控制端本地解析与严格校验，不进入被控端执行面，加载校验失败即整体拒绝、不执行任何动作。

**录制（纯本地命令：不触网络、不写被控端）**：

```
py xd.py macro rec demo.json               # 录 10 秒（Ctrl+C 提前结束）
py xd.py macro rec demo.json --seconds 20
```

录制期间控制台提示「正在录制 …，Ctrl+C 结束」并每 2 秒显示事件计数；结束时输出宏文件路径与动作数。录制经 Windows 低级键鼠钩子（WH_MOUSE_LL/WH_KEYBOARD_LL，纯标准库 ctypes）捕获**控制端本机**键鼠；忽略注入事件（回放不会被自录进去）；钩子安装失败（被安全软件拦截等）会明确报错。录制完成后**不自动回放**。

**回放（经既有 /v1/input 分段发送，全程持输入租约）**：

```
py xd.py macro run nb demo.json
py xd.py macro run nb demo.json --speed 2   # 2 倍速：所有 delay_ms 等比减半
```

回放按宏内延迟**分段**发送（连续无延迟的动作合成一段一请求，段间由控制端等待）。全程持输入租约：首段请求带头 `X-Input-Lease: acquire`、其后各段无头（隐式续期，契约 §21.2）；他人持有时返回 `INPUT_LEASE_TAKEN` 且不执行（首段被占则整单不执行；中途被抢占则中止剩余动作并如实报错）。**Ctrl+C 或异常中断会立即 best-effort 释放输入租约**（FR-06"中断即释放"）；正常回放结束也会自动释放（不等 60 秒过期）。支持 `--json`（输出摘要 JSON）与 `--trust`（TOFU 指纹变更确认）。

**宏文件格式（JSON，UTF-8）示例**：

```json
{
  "version": 1,
  "name": "示例宏",
  "actions": [
    {"type": "move", "x": 960, "y": 540},
    {"delay_ms": 500},
    {"type": "click", "x": 200, "y": 300, "button": "left"},
    {"type": "doubleclick", "x": 200, "y": 300},
    {"type": "wheel", "delta": -360},
    {"type": "type", "text": "hello 你好"},
    {"type": "key", "key": "ctrl+s", "delay_ms": 200}
  ]
}
```

- `version` 必须 == 1；`actions` 为数组（可为空）；`name` 可选、仅展示用。
- 动作与 `/v1/input` 的 actions 同构：`click`/`doubleclick`（x/y/button，button ∈ left/right/middle，默认 left）、`move`（x/y）、`wheel`（delta，可负，120 为一格）、`type`（text）、`key`（key，如 `ctrl+a`）；另有独立延迟步 `{"delay_ms": <毫秒>}`，动作内也可带可选 `delay_ms`（该动作执行前等待）。
- **严格校验（加载即报错、整体拒绝）**：未知动作类型、缺必填字段、类型不对、数值越界、未知字段均明确报错。数值边界：x/y 为非负整数且 ≤ 100000（宽松护栏防误填，非桌面物理边界）；delay_ms 取 0–600000（10 分钟）；wheel delta 为整数且绝对值 ≤ 100000；type 的 text 为 1–10000 字符；key 为 1–64 字符非空字符串；动作条数 ≤ 10000。
- `--speed` 为正浮点 0.01–100（默认 1.0），等比缩放所有 delay_ms。

**录制去抖与聚合阈值**：鼠标移动按「位移 ≥ 8 像素或距上次保留事件 ≥ 300 毫秒」采样（连续微移不会塞满宏）；同一键 500 毫秒内、位移 ≤ 8 像素的两次点击合并为 `doubleclick`（取第一次点击坐标）；连续可打印字符合并为 `type`（间隔 > 1.5 秒拆分）；修饰键组合（ctrl/alt/shift/win）聚合为 `key` 动作（如 `ctrl+c`）；相邻保留事件的间隔写入 `delay_ms`。被控端按键白名单不含的按键（F 功能键、媒体键、输入法组字键等）**不会被录制**，结束时如实提示跳过数量；中文等经输入法组字的文本建议用 `xd type` 补足。

**人工核对提示（真钩子路径）**：自动冒烟（smoke_s6）只白盒验证事件映射，真实录制请人工核对一次——在空闲桌面运行 `py xd.py macro rec manual.json --seconds 8`，期间缓慢移动鼠标、单击/双击、滚动滚轮、输入几个字符并按一次 `ctrl+s`；打开 manual.json 核对去抖/聚合/delay 后，用 `py xd.py macro run <测试设备> manual.json` 回放比对动作顺序与节奏。注意录制会捕获本机所有键鼠输入（含终端窗口的键盘输入）。

### 文件传输与受限操作（`ls` / `cat` / `put` / `get` / `del` / `mkdir` / `mv`）

```
py xd.py ls nb D:\Shared
py xd.py cat nb D:\Shared\readme.txt
py xd.py put nb D:\local\big.zip D:\Shared\big.zip
py xd.py get nb D:\Shared\big.zip D:\local\big.zip
py xd.py mkdir nb D:\Shared\logs
py xd.py mv nb D:\Shared\a.txt D:\Shared\b.txt
py xd.py del nb D:\Shared\old.log --yes
```

- **读取不限路径**（`ls`/`cat`/`get` 不受白名单约束）；`cat` 遇二进制文件会拒绝并提示改用 `get`；`put` 的目标路径受白名单约束（见下一条）。
- **写入/删除/建目录/移动/上传仅在白名单根内允许**（越界返回 `SANDBOX_DENIED`）；白名单默认空 = 仅**默认暂存目录**可写（`<config 目录>/tmp`，node 启动自动创建、恒可用，不计入 16 根上限）——自动化脚本/临时产物推荐先 `put` 到暂存目录再 `exec` 执行该文件（规避 cmd 单条 8191 字符上限与引号转义，见[契约 §14.1](./docs/接口契约.md)）；扩大范围见"首次配置"。
- `put`/`get` 为流式分块传输（4MB 分块），无文件大小上限，**断点续传**：上传中断后重跑同一命令自动续传（`--fresh` 丢弃断点重来）；下载断点保存在 `<本地文件>.crosspart`，下载完成后按 MD5 校验。
- 文件删除定名 `del`（`rm` 保留为"移除设备"语义）。

### 审计（`audit`）

```
py xd.py audit ls nb
py xd.py audit ls nb --identity default --limit 50
py xd.py audit ls nb --since 2026-11-14 --until 2026-11-15
py xd.py audit export nb --out audit_nb.json
```

`audit ls` 表格列为时间/身份/动作/目标/结果（默认查看当日）。

审计在被控端按天落盘（`%LOCALAPPDATA%\CrossDevice\audit\`），记录身份、动作、目标、结果、时间，默认留存 180 天；查询串中的令牌一律脱敏为 `token=***`，令牌本体永不落任何日志。一期任意有效身份可查询全部审计（按身份收窄属二期控制台角色）。

### 执行器热更新（`push-node`）与 rollback.flag 人工处置

```
py xd.py push-node nb
py xd.py push-node nb --file <新版node.py路径>
```

默认推送本仓库的 `node/node.py` 并让被控端自动重启；`--file` 可指定其他新版源码。

流程：条目无签名密钥时自动执行 enroll 获取密钥（输出「已获取更新签名密钥」）→ 本地计算 sha256 + HMAC-SHA256 签名后推送 → node 校验通过才落盘（替换前备份 `.bak`）→ 延迟自重启 → 控制端探活并报「重启完成，当前版本 v…」。校验失败（哈希/签名/白名单不符）返回 `UPDATE_REJECTED`，**不落盘**。

**rollback.flag 人工处置**：若新包无法运行，独立看门狗会在 60 秒内用 `.bak` 自动回滚并重启旧版，同时在 node.py 同目录写入 `rollback.flag`（**常驻不自动删**）。`/v1/health` 的 `rollback_flag` 与下一次 `push-node` 都会提示「rollback.flag 已写入，请人工处置」。处置流程：确认回滚原因（`watchdog.log`、`rollback.flag` 的 reason 字段）→ 修复新包 → 重新 `push-node` 成功后人工删除 `rollback.flag`。注意：坏包完整回滚约 19 秒，可能超出推送端 15 秒探活窗而报"执行器重启后无响应"——回滚事实以 `rollback_flag` 健康字段为准，勿因此重复推送。

### 高权限驻留（`elevate`）

```
py xd.py elevate nb
py xd.py elevate nb --remove
```

在被控端注册计划任务（默认名 `CrossDeviceNode`，`--task-name` 可改名）；`--remove` 移除计划任务（幂等）。

安装在被控端经 UAC 授权（设备所有者确认），注册"登录触发 + 最高权限运行"的计划任务；此后 node 随登录自动以高权限启动，免重复 UAC（横幅与 `xd info` 显示「驻留：是」）。未驻留为正常状态，仅标注不告警。边界：UAC 安全桌面、锁屏界面、系统级受保护进程不可注入；若计划任务/看门狗被安全软件拦截，驻留或自动回滚可能失效（见"安全须知"）。安装成功后按"首次配置"节完成工作空间白名单的本地配置。

### 多实例（`--instance`）

```
py node\node.py --instance alpha
py node\node.py --instance beta --port 51901
```

同机并行多实例（多登录会话/灰度场景）。

实例各自使用 `node-<名>.json` 配置与独立端口、身份、白名单、审计目录、任务库；TLS 证书目录共享。控制端按设备名正常连接即可（注册时以实际端口为准）。

## 端口与防火墙

| 端口 | 用途 | 说明 |
|---|---|---|
| 51888/TCP | node 控制通道（HTTPS/TLS 1.3） | 被占用自动 +1 顺延（最多尝试 51 个候选），成功后持久化到 `node.json` 并优先复用；全部占用报 `PORT_EXHAUSTED` 以非零码退出（可用 `--port` 手动指定） |
| 51889/UDP | 发现广播（node 发送；`xd pool` 接收） | **`xd pool` 需要本机入站放行 UDP 51889**——Windows 首次运行会弹防火墙询问，允许即可；跨机实测常用规则：`netsh advfirewall firewall add rule name="CrossDevice-Pool-UDP51889" dir=in action=allow protocol=UDP localport=51889`（需管理员权限执行一次）。未放行时设备池收不到任何帧 |

- node 发送广播（启动即 1 帧 + 每 10 秒 1 帧）不受此限制；被控端的 51888/TCP 首次被控制端访问时同样可能弹防火墙询问，放行"专用网络"即可。
- 已知现象：启用 Hyper-V 的机器存在系统**端口排除区间**（如观测到 52804–52903 被排除），期望端口落在区间内时 node 会自动顺延到区间之后，属正常行为。
- 发现依赖同网段广播；跨网段设备请直接 `xd add <IP> --token <令牌> --port <端口>` 手动注册。

## 首次配置（工作空间白名单，被控端本地完成）

写/删/建目录/移动/上传受**工作空间白名单**约束：

- 白名单默认**空 = 仅默认暂存目录可写**（`<config 目录>/tmp`，`--instance` 时 `tmp-<名>`；node 启动自动创建、恒可用、不计 16 根上限），其余写/删/建目录/移动/上传全拒（读取不受限）。
- **当前允许根可查询**：`xd info <设备> --json` 的 `workspace_roots` / `workspace_staging` 字段（node v0.5.1+）；a4agent 集成下另有 `GET /api/v1/devices/{name}/workspaces` 查询端点（只读）。
- 白名单是**被控端本地配置**，控制端无法远程扩大它；每台设备需要一次本地授权（安装器或 `xd elevate` 引导，D40）。
- 配置方式二选一（与 `xd elevate` 安装成功输出的指引行同口径）：
  1. 编辑被控端 `%LOCALAPPDATA%\CrossDevice\node.json`，加 `"workspace"` 键（字符串数组，绝对路径，最多 16 个根）——JSON 文件中路径用双反斜杠转义：
     ```
     "workspace": ["D:\\Shared"]
     ```
  2. 或启动 node 时加 `--workspace`（逗号分隔，覆盖配置文件值）——命令行写单反斜杠即可：
     ```
     py node\node.py --workspace "D:\Shared"
     ```
- `xd elevate` 安装成功时会在被控端输出如下指引行（与本节同口径）：

  > 白名单首次配置：编辑被控端 node.json（默认 %LOCALAPPDATA%\CrossDevice\node.json）的 "workspace" 键（字符串数组，默认空=仅默认暂存目录可写），如 "workspace": ["D:\\Shared"]；或启动 node 时加 --workspace "D:\\Shared"。
- 语义说明：白名单防的是**误操作**（越界写删被拒、删除需显式确认），不构成安全边界——`exec` 可执行任意命令从而绕过白名单（见"安全须知" R8/D7）。白名单根目录不存在时请求报错，node 不会自动创建根。

## 安全须知（务必阅读）

- **传输**：HTTPS TLS 1.3 + 自签证书 + TOFU（首次使用即信任）：首次连接记录证书指纹，之后指纹变更会被本地拒绝（错误以 `TOFU` 开头，不发任何业务数据），确认是被控端换证书后加 `--trust` 接受。明文 HTTP 默认关闭，仅 `--debug-plaintext` 调试可用（横幅明示告警）。
- **身份**：每控制端一个独立令牌（32 位十六进制，比较使用常量时间函数）；每个请求带防重放头（时间戳 ±300 秒窗口 + nonce 查重）。令牌经查询串传递为过渡兼容，审计一律脱敏为 `token=***`。
- **访问范围**：仅私网来源可访问（非私网来源请求被拒绝且不落审计）；不要将 51888 端口映射到公网。
- **R7（高危，务必知悉）**：`exec` 可执行任意命令，**令牌泄露 = 被控机完全控制**。安全前提是**可信私网 + 强身份**：妥善保管 `data/devices.json`（控制端）与 `node.json`（被控端）中的令牌，泄露后立即在被控端换令牌并轮换（`--token` 覆盖）；配合审计追溯。本工具不提供对"已授权操作者误用"的阻止手段。
- **R8/D7（务必知悉）**：写/删白名单防误操作，**不是安全边界**——`exec` 可绕过白名单，不能据此认为被控机被隔离出写入能力。
- **审计**：所有通过来源校验的请求（含失败请求）落审计，默认留存 180 天；审计是事后追溯手段，不阻止操作发生。
- **R12（热更新签名边界）**：`push-node` 的 HMAC-SHA256 签名与哈希白名单仅防**误推与传输篡改**，不防已取得被控端文件权限的攻击者（密钥在被控端本地）；非对称签名（Ed25519 + 密钥轮换）计划于二期。
- **R15（看门狗边界）**：回滚看门狗是独立脚本，**可能被杀毒/EDR 软件拦截或终止**，导致自动回滚失效；届时按 `watchdog.log` 与 `node.py.bak` 人工恢复。
- **能力边界（如实声明）**：一期为"接管"定位——操作期间被控端用户的桌面与输入被占用；锁屏/非交互会话下截屏与键鼠注入不可用（`exec`、文件等非 GUI 能力仍可用，详见"常见问题"）；UAC 安全桌面与系统级受保护进程不可注入。无干扰模式为二期目标。

## 常见问题

**锁屏/非交互会话下哪些功能不可用？**
截屏与全部键鼠注入不可用（提示明确：`info` 显示「锁屏：是/非交互」，输入命令报「目标机不在交互式桌面会话，输入未生效」）。`exec`、文件读写、任务历史等非 GUI 能力不受影响。请勿把 node 注册为 Windows 服务（会脱离交互式桌面会话）。

**防火墙弹窗与首次放行**
被控端首启（51888/TCP）与控制端首次 `xd pool`（入站 UDP 51889）都会触发 Windows 防火墙询问；允许"专用网络"即可。`xd pool` 收不到任何设备帧时，先检查 51889 入站是否放行。

**push-node 之后 node 是后台进程**
`push-node` 的重启由 bat 拉起一个 **detached 隐藏进程**：原控制台窗口里的 node 已自退，旧窗口按 Ctrl+C 杀不到新进程（还会造成"两个 node 并存"的假象）。判定存活请用 `py xd.py ping <设备名>`，或在被控端用任务管理器/`netstat -ano | findstr 51888` 核对；确需在旧窗口停止，请按 PID 结束隐藏进程。

**端口报 `PORT_EXHAUSTED` 怎么办？**
说明期望端口起连续 51 个候选全被占用（含 Hyper-V 排除区间现象）。处理：换 `py node\node.py --port <N>` 显式指定可用端口，或清理占用者。启动期该错误以非零码退出，不会静默失败。

**rollback.flag 出现了怎么处置？**
含义：某次更新被看门狗回滚过且**尚未人工确认**（标记常驻不自动删）。流程：读被控端 node.py 同目录的 `rollback.flag`（reason/old/new sha256）与 `watchdog.log` 还原现场 → 修复新包后重新 `push-node` → 推送成功、新版本运行稳定后，**人工删除 `rollback.flag` 文件**（该文件实时判断存在性，删除后 `/v1/health` 的 `rollback_flag` 即恢复 false，无需重启）。

## 文档与开发

- [docs/需求文档.md](./docs/需求文档.md)：需求与验收标准（11.2 指标汇总表）。
- [docs/接口契约.md](./docs/接口契约.md)：控制端与被控端唯一耦合面（协议规格、错误码、schema）。
- [docs/测试要求.md](./docs/测试要求.md)：三层测试体系与回归门槛（冒烟层六脚本：s1 8/8、s2 10/10、s3 10/10、s4 14/14、s5 5/5、s6 5/5）。
- [docs/验收记录.md](./docs/验收记录.md)：11.2 逐行验收记录（签署依据）。
- [docs/发布流程.md](./docs/发布流程.md)：tag 对齐 NODE_VERSION、打包清单与发布前门槛（`py tools/release_check.py --tag v0.4.0`）。
- [SECURITY.md](./SECURITY.md)：安全问题报告渠道与已知边界。

## 许可证

本项目以 [MIT License](./LICENSE) 发布；安全漏洞报告与披露政策见 [SECURITY.md](./SECURITY.md)。
