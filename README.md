# OpenVPN客户端插件

[![Validate plugin](https://github.com/BearHero520/openvpn-client-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/BearHero520/openvpn-client-plugin/actions/workflows/ci.yml)

为 **UFI-TOOLS / Android ARM64 热点设备**重做的 OpenVPN 客户端插件。支持导入 `.ovpn`，修复 Android 策略路由、musl DNS 和连接状态误报等问题。

**下载：** [最新发布版本](https://github.com/BearHero520/openvpn-client-plugin/releases/latest)，选择 `OpenVPN-client-plugin.js`。仓库中的中文文件位于 [`dist/OpenVPN客户端插件.js`](dist/OpenVPN客户端插件.js)。它是可直接导入 UFI-TOOLS 的完整插件，不需要在设备上安装 Node.js。

## 使用前提

- 已开启 UFI-TOOLS 高级功能并取得 root。
- 原版 OpenVPN ARM64 二进制包已安装在 `/data/kano_openvpn`，包含 `openvpn`、`ld-musl-aarch64.so.1`、`lib/`；设备具有 `/dev/net/tun`、`ip`、`iptables` 和 IPv6 防火墙。
- 目标为 OpenVPN 2.6 / 2.7 的 TUN、IPv4 TCP/UDP 客户端。当前仓库不重新分发第三方二进制，也不自动下载未知安装包。
- 从家庭服务器导出含内嵌 CA / 客户端证书的配置，服务器已开启 VPN 客户端访问互联网和转发/NAT。

## 安装与导入

1. 先在旧插件关闭看门狗、开机自启，停止旧 OpenVPN。之后禁用旧版 JS，避免同时运行两个控制面板。
2. 在 UFI-TOOLS 插件管理中导入新版 JS，刷新页面，点击 **安装 / 更新连接组件**。
3. 填写热点接口，通常为 `br0`；家庭 DNS 填 **VPN 内可达的家庭 DNS 地址**，例如家庭路由器 LAN 地址。点击保存网络设置。
4. 点击 **导入 .ovpn**，检查服务器地址和提示，再点击 **校验并保存**。也支持粘贴配置。
5. 如果配置使用 `auth-user-pass`，填写 VPN 用户名、密码并单独保存。
6. 点击启动，等待 **隧道已建立**，再从连热点的终端验证访问家庭内网和公网出口。
7. 确认可用后再开启开机自启。手动点 **停止并恢复直连**会解除本插件的断线保护。

导入支持 BOM、Windows CRLF、多条 remote、内嵌 `ca/cert/key/tls-auth/tls-crypt/tls-crypt-v2`。外部证书文件、加密私钥、`<connection>` 区块、脚本、动态插件和管理端口会给出错误；请重新导出单文件配置。不会执行导入文件中的任意 root 脚本，也不会通过关闭证书校验来“修复”连接。

## 流量范围

接管**选定热点接口转发的全部外网 IPv4 流量**。家庭 DNS 强制走通道，热点 IPv6 外网暂时阻断，避免从蜂窝 IPv6 绕行。热点本地子网、设备管理页面保持可达。

**Android 设备自身应用的出站流量不在此版本接管范围内**，否则可能把 VPN 的连接和系统 DNS 一并绕回隧道。这不是 Android 全局 VPN API 实现。需要设备自身 App 全隧道时，应单独设计 UID / socket 标记策略。

建立连接前、断线重试中，热点外网会被阻断；认证失败时也保留保护。明确停止才恢复原有路由。IPv6 被阻断，不代表已经实现 IPv6 VPN。

## 主要修复

| 原问题 | 新行为 |
| --- | --- |
| musl 找不到系统 DNS，DDNS 一直解析失败 | 用 Android 原生 `ping` 的解析结果生成运行时副本，每次重连重新解析，源配置保留域名 |
| 主路由表被 Android / WireGuard 策略覆盖 | 独立路由表 `18100`、优先级 `70`，仅匹配所选热点入口 |
| 抓取 PUSH_REPLY 失败导致路由缺失 | 使用 OpenVPN 的 route-up / down 生命周期钩子，不再从日志猜路由 |
| 蜂窝接口被当作热点 | 用户明确指定一个热点接口，拒绝常见蜂窝和 VPN 接口 |
| 误把 musl 或其他 VPN 进程当连接成功 | 核对 PID 的命令参数、独立隧道 `ovpnc0`、连接钩子状态与路由 |
| 页面关闭，看门狗失效 | 设备端后台守护进程、OpenVPN keepalive、异常重连；证书/认证错误不无限重试 |
| 配置保存混入 JSON、路径注入、证书丢失 | 后端结果拆包、命令退出码、配置允许列表、原子替换、600 权限 |
| VPN 断线后自动从蜂窝上网 | 不可达默认路由和独立转发保护，IPv6 转发阻断 |

网络规则使用独立 `OC2_*` 链；启动时检查保留路由表和规则优先级冲突。不会清空系统防火墙、停止 WireGuard、修改 `/system` 或覆盖旧版配置。

## 诊断与恢复

点击 **诊断**，查看隧道地址、策略路由和防火墙计数，再查看连接日志。状态不是公网连通性证明；最终用连热点的终端检查出口，并对比家庭网络出口。家庭网络上另有代理时，出口可能是该代理地址。

- `AUTH_FAILED`：检查账号密码、服务端用户权限。
- `VERIFY ERROR`：重新导出与当前服务端匹配的证书配置，检查设备时间。
- 系统 DNS 解析失败：检查蜂窝/上级网络 DNS 和 DDNS 是否生效；可临时使用真实公网 IPv4 验证。
- 超时：检查 remote 端口/协议、公网可达性、端口转发。
- 显示隧道已建立但终端不通：核对热点接口和家庭 DNS、家庭服务器转发/NAT；查看 `OC2_FWD` / `OC2_DNS` 计数。
- 切换 VPN 后，请让热点终端重新连接 Wi-Fi，清理已有连接缓存；其他 VPN/防火墙软件若随后重写规则，应重新诊断并重连。

新数据位于 `/data/kano_openvpn/client-v2`，旧版配置仍在原处。升级或改配置前先停止。保存配置保留上一份运行配置 `profile.previous.ovpn`；账号密码不会读回界面。不要把该目录、日志、真实 `.ovpn`、私钥或截图中的配置公开上传。

紧急恢复原有网络（设备 root 终端）：

```sh
/data/kano_openvpn/client-v2/service.sh stop
```

移除插件前先停止并关闭它的开机自启。只删除网页 JS 不会终止设备后台服务。

## 开发与验证

```sh
npm ci
npm run check
# Linux 上使用真实内核路由/防火墙进行隔离集成测试：
bash test/netns.sh
```

`src/core.mjs` 为配置检查；`src/ui.js` 为 UFI 面板；shell / awk 负责设备端服务。`npm run build` 生成一个完整 JS。GitHub Actions 检查配置导入、前端交互、脚本语法，以及真实 Linux network namespace 中的路由优先级、断线保护、DNS、IPv6 和规则清理。

Linux 隔离测试不能代替具体 Android 固件的实际验证。此版本尚未完成 U30 Air 的端到端部署验收，尤其应检查固件的 iptables 后端、SELinux、热点管理规则和二进制版本。

实现参考：[OpenVPN 2.7 官方手册](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)中的脚本生命周期、`route-noexec`、`remap-usr1` 和客户端配置选项。

## 来源

项目由用户提供的“OpenVPN客户端插件.js”问题场景重构，兼容 MiniKano / UFI-TOOLS 插件接口。原始文件仅在本地以 `original.local.js` 备份并被 Git 忽略；不包含真实连接配置或第三方二进制。原项目及 OpenVPN 等第三方组件的权利和许可属于各自作者；本项目不代表其官方发布。
