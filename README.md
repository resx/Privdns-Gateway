# PrivDNS Gateway

**面向专用移动网络的私密 DNS 流量治理网关**。终端只需配置系统私密 DNS(DoT),网关根据域名策略将业务流量调度到指定出口或本机直连。

> 🚀 **第一次部署?** 跟着 **[新手图文教程 →](docs/QUICKSTART.md)** 一步步来(从准备服务器到手机连上,全程带图)。

```
 手机 (Android 私密 DNS / iOS 描述文件,仅 DoT)
   │  DoT :853
   ▼
 网关服务器 ── mosdns ──► 直连域名:返回真实 IP
   │                     策略域名:A 记录改写为网关 IP,AAAA/HTTPS 置空
   │  :80/:443 识别 SNI
   ▼
 sing-box ──► 按域名调度:业务 A→出口 A  业务 B→出口 B  默认→本机直出
```

核心思想:**把 DNS 当策略引擎**。
策略域名的 A 记录被改写成网关自己的 IP,流量回到网关后由 sing-box 根据 SNI/Host 选择合规出口。
终端全程只需一条「私密 DNS」设置,无需安装额外网络客户端。

---

## ⚠️ 适用场景 / 部署前提

本项目面向具有固定私有源地址段的专用移动网络,不提供开放互联网接入服务。部署需要:

- 一台能被运营商私网访问的**网关服务器**。
- 一张运营商「**内网卡 / 定向内网 SIM**」,手机流量经运营商私网到达网关,且**源 IP 是固定私有段**(如 `172.x`)。
  网关使用这个私有源段识别授权查询来源。
  - 没有这种内网卡时,策略响应会影响其他查询来源,不适用本项目。
- 一个你能修改 DNS 记录的**域名**(用于 DoT 和 Let's Encrypt 证书)。
- 一个 **Telegram bot**(可选,用于快捷管理出口和分流)。
- 一个或多个经过授权的**远程业务出口**(可选,未匹配流量默认从网关服务器直出)。出口由 sing-box 管理,bot 能直接识别的链接见下。

---

## 一键安装 (Debian 12+ / Ubuntu 22+)

```bash
curl -fsSL https://raw.githubusercontent.com/resx/Privdns-Gateway/main/install.sh | sudo bash
```

入口脚本只负责自举,实际安装会自动切到最新 `v*` 发布 tag,不安装 main 上未发布的中间提交。

或克隆后运行(便于先看代码):

```bash
git clone https://github.com/resx/Privdns-Gateway.git
cd privdns-gateway
git fetch --tags
git checkout "$(git tag -l 'v*' --sort=-v:refname | head -1)"
sudo ./install.sh
```

脚本会装好 mosdns、sing-box(1.12)、管理 bot、内网 HTTPS 管理面板、防火墙和证书,自动识别公网 IP 和内网卡段,再交互填 DoT 域名(**bot token 可留空**,装完随时 `sudo pdg-set-token` 再设并启用)。
域名 A 记录这步留给你自己做(脚本会等你确认指向本机后再签证书)。
详见 [docs/INSTALL.md](docs/INSTALL.md)。

卸载:`sudo ./uninstall.sh`(加 `--purge` 连配置一起删)。

## 装完之后

1. 手机【私密 DNS / DoT】填你的域名(如 `dot.example.com`)。
2. Telegram 给 bot 发 `/start`:
   - **📤 出口管理 → 添加**:直接粘贴节点链接。
     > **bot 能直接粘**:`ss:// / vmess:// / trojan:// / vless://(含 reality)/ hysteria2:// / tuic:// / anytls:// / socks5:// / http://`,以及 Surge 的 `名字 = ss, …` 行。
     > sing-box 还支持 **shadowtls / ssh / hysteria(v1)/ wireguard(endpoint)** 等——这些手写 `/etc/sing-box/config.json`,或开 issue 让 bot 加解析。
   - **📑 分流管理**:把域名、`.list` / `.txt` 等规则集指到出口(默认其余国际走 VPS 直出)。
   - **🔀 故障切换组**:多落地自动选最快 / 坏了自动切。
3. 管理面板:bot **📱 客户端 → 🖥 管理面板**,手机走内网卡时打开 `https://你的DoT域名:9443/`。PWA 集成节点订阅与结构化覆写、分类组自动/固定节点、三目标测速、分流与远程规则集、连接和日志、Geosite/项目在线更新。节点订阅支持 Base64/纯 URI 列表和 SIP008，可预览差异并每日自动刷新。管理端要求独立令牌，不是只靠来源 IP。
4. iOS:bot **📱 客户端 → iOS 描述文件**;**不用 bot 的话** `sudo pdg ios` 会直接在终端打出二维码,手机(走内网卡)扫码 → Safari → 装。
   Wi-Fi/蜂窝都按 `:81` 探测自动判定启不启用(已有自定义路由的普通 Wi-Fi 自动直连、互不干扰);
   bot 生成时还可指定「强制直连」的 Wi-Fi 名单(SSID,治 captive portal 误判)。
5. 换域名:bot **🌐 DoT 自定义域名**,自动签证书并切换。

## 日常管理

```bash
sudo pdg            # 进管理菜单
sudo pdg doctor     # 自检(只读); --json 可脚本化; --deep 加端到端检查(DoT握手/:81/DNS/clash)
sudo pdg status     # 状态
sudo pdg admin      # 显示管理面板地址和令牌链接(敏感,不要分享);加 --rotate 轮换令牌
sudo pdg update     # 更新(更新前自动快照, 失败自动回滚; --dry-run 看待更新)
sudo pdg snapshot   # 手动留一份配置快照
sudo pdg rollback   # 回滚到最近快照
sudo pdg token      # 设置 / 更换 bot token
sudo pdg restart    # 重启服务
sudo pdg log [n]    # 看日志
sudo pdg traffic    # 网卡流量(vnstat)
sudo pdg ios        # 不用 bot, 直接出 iOS 描述文件二维码
sudo pdg report     # 脱敏诊断报告(隐藏 token/密码/uuid); --redact-ip 连IP/域名也隐藏; --full 不脱敏
sudo pdg detect-cidr # 抓包重新识别内网卡来源段, 与现配不符可一键写回并重启
sudo pdg uninstall [--purge]   # 卸载(--purge 连配置删)
```

> 健康自检每 10 分钟自动跑,服务挂 / DNS 不应答 / 证书快到期会 Telegram 私信你。

> 分工:`pdg` 管生命周期;PWA 管常用出口/分流;Telegram bot 管快捷操作、规则集、DNS 上游和面板入口。

## 组成

| 层 | 用什么 | 说明 |
|---|---|---|
| DNS | **mosdns v5** | 国内直连 / 策略域名 A 记录改写到本机 + AAAA/HTTPS 置空 / 按来源 IP 分支 / ECS 分治 / 缓存。DoT(853) |
| 流量 | **sing-box 1.12** | `direct` 监听 + `sniff_override_destination`(**不用 tproxy**);多出口 urltest 故障切换;clash_api 测速/流量 |
| 管理 | **Web PWA + Telegram bot** | PWA 管节点/订阅覆写/测速/分流/资源/连接；Bot 提供快捷操作；配置事务先 `check`、失败回滚 |
| 证书 | **certbot standalone** | Let's Encrypt,自动续期(已处理 80 口被 sing-box 占的坑) |
| 防火墙 | **nftables** | 对全网只留 SSH;DNS/数据/探测口只放行内网卡来源段 |

> ⚠️ sing-box **必须 1.12.x** —— 1.13 移除了 `sniff_override_destination`,本网关会失效。install.sh 已固定版本。

## 文档

- [docs/INSTALL.md](docs/INSTALL.md) — 安装细节 / DNS 配置 / 端口 / 版本注意
- [docs/MANAGEMENT.md](docs/MANAGEMENT.md) — PWA 管理端 / API / 认证 / 前端开发
- [docs/TROUBLESHOOTING-PLAYBOOK.md](docs/TROUBLESHOOTING-PLAYBOOK.md) — 排障手册(症状 → 查 → 修)
- [docs/production-notes.md](docs/production-notes.md) — 实战记录与踩坑(sing-box 版本坑、QUIC 自环、ECS、安全加固等)
- [CHANGELOG.md](CHANGELOG.md) — 更新日志

## 致谢

- [misaka-cpu/privdns-gateway](https://github.com/misaka-cpu/privdns-gateway):本项目的原始项目。
- [IrineSistiana/mosdns](https://github.com/IrineSistiana/mosdns) 与 [SagerNet/sing-box](https://github.com/SagerNet/sing-box):核心 DNS 和流量调度组件。
- [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat):mosdns Geosite 数据来源。
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 与 [DustinWin/ruleset_geodata](https://github.com/DustinWin/ruleset_geodata):管理面板规则集预设来源。
- [Twemoji Mozilla](https://github.com/mozilla/twemoji-colr):管理面板 flags-only 字体来源，字体代码采用 Apache-2.0，图形采用 CC BY 4.0。

第三方项目和数据遵循各自的开源许可证与使用条款。

## 免责声明

本项目仅供**学习与合法网络管理**用途。请遵守你所在地的法律法规;使用者自行承担责任。作者不对任何使用后果负责。

## License

[MIT](LICENSE)
