# Multi VPN

<img src="assets/icon.png" width="112" alt="Multi VPN icon">

Python + Qt 编写的独立 SSL VPN 多连接桌面工具，主要用于个人与小范围团队的授权内网访问。每条连接使用独立会话、系统网卡和内网路由，其他软件可直接使用内网 IP，无须设置代理。本项目与任何设备厂商无隶属或背书关系。

## 下载和安装

在 [Releases](https://github.com/addsubmuldiv/multi_vpn/releases) 下载，无须安装 Python。

| 系统 | 文件 | 安装方式 |
| --- | --- | --- |
| Windows x64 | `MultiVPN-0.2.0-windows-x64-setup.exe` | 安装向导，自动创建桌面和开始菜单快捷方式，支持卸载 |
| macOS Apple Silicon | `MultiVPN-0.2.0-macos-arm64.pkg` | 安装向导，安装到「应用程序」 |
| macOS Intel | `MultiVPN-0.2.0-macos-x86_64.pkg` / `.dmg` | 安装向导或拖入 Applications；当前依赖要求 macOS 14+ |
| macOS Apple Silicon | `MultiVPN-0.2.0-macos-arm64.dmg` | 将应用拖到 Applications |

应用创建系统网卡需要管理员授权。macOS 连接时由系统弹出授权提示，程序不收集系统密码。初版安装包没有商业代码签名或 Apple 公证，系统可能提示开发者未验证；有签名和公证要求的环境请等待后续签名版本。

## 使用

新增网关、端口和账号，选择后点击「连接」。首次连接核对并确认网关证书指纹；短信网关会要求输入本次验证码。显示「已连接」代表系统地址及路由已经就绪。

- 每条配置可以独立连接、断开；「复制配置」用于创建相似配置。
- 不同 VPN 可同时连接，要求下发网段不重叠；冲突会报错。
- 同一账号可能被网关限制为单会话，重复登录可能顶掉官方客户端。不要用正在运行重要任务的账号做实验。
- Windows 和 macOS 均可选择把密码保存到系统凭据库。
- 配置不随软件发布，首次安装列表为空。点击窗口右上角「×」会隐藏到系统托盘，VPN 继续运行；「－」保持最小化行为。单击托盘图标可恢复窗口，悬停可查看连接数量及链路异常状态。
- 需要退出时，点击主界面右下角「退出程序」、按 Ctrl+Q，或在托盘右键菜单选择「退出程序」。程序会先断开本程序的全部连接并清理网卡及路由，再退出；托盘菜单也可单独「断开全部连接」并保留程序。系统托盘不可用时会保留窗口。
- 当前不支持自动重连、开机自启。
- 配置默认在 Windows `%APPDATA%/MultiVPN` 或 macOS `~/Library/Application Support/MultiVPN`。卸载保留个人配置及系统凭据。

### 连接诊断（0.1.7）

连接事件与每秒流量、发送队列、接收队列及网卡重试计数保存在配置目录的
`logs/multi-vpn.log`，使用 UTF-8 JSON Lines。每个文件上限 2 MiB，保留三个备份。
界面会显示日志位置；程序退出或重新连接不会清空磁盘日志。
日志不记录密码、令牌、证书、原始报文、网关地址或账号；分享日志前仍应检查内容。

发出内网数据后 30 秒没有内网数据回包，会显示链路异常提示；收到内网数据后自动恢复状态。
这只是诊断提示，不能据此确定是客户端、网关还是上游网络故障，也不会自动重登账号。
网卡短暂繁忙时先排队重试，接收队列有界；长时间无法投递导致队列耗尽时会明确报错。

### 长时间运行优化（0.1.8）

健康的空闲连接没有固定寿命，也不会为了“保活”定时断线重登。TCP keepalive
用于辅助操作系统发现失效连接，不代表已验证网关应用层心跳应答。

发送连续 30 秒无进展、同一发送报文排队超过 120 秒、同一网卡待投递报文积压
超过 60 秒或同一隧道帧超过 120 秒仍不完整时，会明确报错并清理本次连接，
而不是无限积压旧数据。短暂拥塞在限额内自动重试；超时后需用户重新连接。
内网目标不回包只触发异常提示，不直接判定认证失效。

诊断写入与网络转发分离。磁盘很慢或不可写时可能丢失日志，但不会因此阻塞
隧道；`log_dropped` 与界面“日志未保存”可用于识别该情况。退出时最多等待
日志线程两秒，不保证突然关机或磁盘故障时最后一批日志完整。

新增诊断字段：`run_id`（每次连接）、`rx_queue_age` / `tx_queue_age`（秒）、
`last_receive_age`（内网数据）、`last_gateway_age`（隧道任意接收）、
`partial_frame_bytes`（尚未拼完整的帧）及 `log_dropped`。
`SendStallError`、`SendQueueAgeError`、`AdapterStallError`、`FrameStallError`
分别表示发送无进展、发送积压、网卡投递积压和帧不完整。

离线测试包含模拟 72 小时的报文处理及重复队列周转，不代表已完成真实 VPN
的 72 小时测试。上线前应验证持续 SSH/VS Code、下载、双连接并行、短时断网
恢复以及睡眠唤醒；网关要求重新认证、短信或证书确认时仍需用户参与。

## 支持范围和验证情况

目前实现两种特定 SSL 网关报文格式和 IPv4 内网分流，兼容范围以实测为准，不是通用的 OpenVPN、WireGuard 或 IPSec 客户端。请仅使用本人或组织授权的账号与网关；程序仍需正常账号认证及网关要求的二次验证。

Windows 已完成真实网关端到端验收：独立认证、系统网卡和目标路由、普通 socket 读取 SSH banner、系统 SSH 工具完成公钥交换、断开清理。没有登录远程主机或执行远程命令。

短信 V1 协议已在命令行原型验证；本版 GUI 没有重连正在使用的短信环境。双网关同时连接尚未完成真实环境验收。macOS 安装包由 GitHub Apple Silicon runner 构建并检查架构，GUI、权限提示及 VPN 网络仍需要真实 Mac 验收。

旧版协议默认优先尝试 UDP 数据通道，协商或探测失败时回退到 TLS。可在连接配置中关闭 UDP 优先。V1 协议使用 TLS 数据通道。

暂不支持 IPv6、默认路由接管、重叠网段映射、证书登录及网关特有终端检查。macOS 初版不设置 VPN DNS，请使用内网 IP 访问。

## 源码运行

要求 Python 3.11+。Windows：

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
.venv\Scripts\python scripts/install_wintun.py
start_windows.cmd
```

macOS ARM：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
chmod +x start_macos.command
./start_macos.command
```

开发启动脚本的配置位于忽略的 `local-user/`；可用 `--data-dir` 或 `MULTIVPN_DATA_DIR` 指定目录。Windows Wintun 从官方站点下载并校验固定 SHA256，许可证见 `vendor/WINTUN-LICENSE.txt`。

## 构建

[GitHub Actions](https://github.com/addsubmuldiv/multi_vpn/actions) 在 `windows-2022` 和原生 ARM `macos-15` 构建。PR 或手动触发会保存安装包为 Actions artifacts；推送 `v*` 标签会创建 GitHub Release 并上传安装包和 SHA256 校验值。CI 不包含账号配置、不连接 VPN。

Windows CI 验证安装、桌面快捷方式、打包后的依赖加载和卸载；Mac CI 检查 arm64 架构、应用临时签名及打包后的依赖加载。

```sh
python -m pip install -e '.[dev]'
python -m pytest -q
python scripts/make_icons.py
```

Windows 执行 `python scripts/build_app.py`，再用 Inno Setup 6 编译 `packaging/windows.iss`。Mac 执行 `bash packaging/build_macos.sh`，生成 PKG 和 DMG。图标源文件为 `assets/icon.svg`，可重复导出 PNG、ICO 和 ICNS。
