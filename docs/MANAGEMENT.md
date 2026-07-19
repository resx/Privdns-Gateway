# 管理端

PrivDNS Gateway 提供移动端优先的独立 PWA，与 Telegram Bot 共用配置控制层。节点、订阅覆写、测速、分流、远程资源和连接管理均通过受控 API 完成；sing-box Clash API 继续只监听 `127.0.0.1:9090`，不对外暴露。

## 访问与认证

管理服务 `pdg-admin` 监听 `0.0.0.0:9443`，复用 DoT 证书。nftables 只允许 IP 白名单中的来源访问该端口；`PDG_INTERNAL_CIDR` 仅用于 8111 首次登记入口。所有 `/api/v1/*` 请求还必须携带：

```http
Authorization: Bearer <admin.token>
```

安装时自动生成 `/etc/privdns-gateway/admin.token`，目录权限 700、文件权限 600。获取入口：

```bash
sudo pdg admin
sudo pdg admin --rotate  # 令牌泄露时轮换;旧链接立即失效
```

也可在 Telegram Bot 中选择「📱 客户端 → 🖥 管理面板」。首次接入时先在「📱 客户端 → IP 白名单」开启登记窗口，再从目标设备打开登记入口；iOS 也可通过「iOS 二维码/文件」生成短时下载链接完成登记。链接默认 10 分钟失效，并在首次访问时绑定客户端 IP。白名单 IP、登记窗口和移除操作统一在「IP 白名单」中管理。令牌放在 URL fragment (`#token=...`) 中，浏览器首次打开后保存到本地存储并立即从地址栏移除；fragment 不会出现在 HTTP 请求和服务端访问日志中。

管理链接拥有完整配置权限。不要分享、截图或放入公开书签。PWA 的默认出口与组内固定节点都会写入 sing-box 配置并通过事务控制层应用；Clash API 必须继续监听 `127.0.0.1:9090`。

## 功能与 API

| 功能 | API |
|---|---|
| 概览和服务状态 | `GET /api/v1/overview` |
| IP 白名单登记与管理 | `GET /api/v1/allowlist`, `POST .../open`, `POST .../close`, `DELETE .../hosts/{ip}`, `DELETE /api/v1/allowlist` |
| 出口列表/预览/添加 | `GET /api/v1/exits`, `POST /api/v1/exits/preview`, `POST /api/v1/exits` |
| 出口影响/删除 | `GET /api/v1/exits/{tag}/impact`, `DELETE /api/v1/exits/{tag}` |
| 批量测速/默认出口 | `POST /api/v1/exits/test`, `PUT /api/v1/final` |
| 节点组保存/选择/删除 | `POST /api/v1/groups`, `PUT .../{tag}/selection`, `DELETE .../{tag}` |
| 节点订阅 | `GET/POST /api/v1/subscriptions`, `POST .../preview`, `PUT/DELETE .../{id}`, `POST .../{id}/refresh` |
| 分流列表/保存/排序/删除 | `GET/POST /api/v1/rules`, `POST .../rules/batch`, `PUT .../rules/order`, `DELETE .../rules/{domain}`, `DELETE .../cidrs/{cidr}` |
| 路由模拟 | `POST /api/v1/route/test` |
| 规则集管理 | `GET/POST /api/v1/rulesets`, `PUT/DELETE /api/v1/rulesets/{tag}`, `POST .../{tag}/refresh`, `POST .../refresh` |
| 资源状态/Geosite | `GET /api/v1/resources`, `POST /api/v1/resources/geosite/refresh` |
| 项目更新 | `POST /api/v1/resources/project/check`, `POST .../project/update` |
| 活动连接 | `GET/DELETE /api/v1/connections`, `DELETE /api/v1/connections/{id}` |
| 服务日志 | `GET /api/v1/logs` |
| 进程存活 | `GET /healthz`（不返回配置） |

API 从不返回节点密码、UUID、原始订阅令牌或未脱敏订阅 URL。持久化出口、组内节点、订阅分类和分流由 PWA/Bot 调用 `deploy/bot/pdg_control.py`，执行锁定、候选校验、原子替换和失败回滚。项目更新 API 只启动现有 `pdg update` 瞬时任务，不直接修改安装文件。

分流管理支持一次提交最多 200 个域名或 CIDR，并可调整手工域名、CIDR 和规则集的匹配顺序；系统入站与拒绝规则始终固定在最前，自定义顺序会持久保留。节点订阅支持 Clash YAML `proxies`、Base64 URI 列表、纯文本 URI 列表和 SIP008 JSON，单订阅限制 8MB/500 个节点。Clash 导入覆盖 SS、VMess、Trojan、VLESS、Hysteria v1/v2、TUIC、AnyTLS、ShadowTLS、SSH、SOCKS5 和 HTTP；策略组、规则、不支持的节点及带 plugin 的 SS 不会导入，并计入跳过数量。添加和修改必须先预览新增、更新、移除与跳过数量。结构化覆写支持协议过滤、正则重命名、名称排序、TCP Fast Open 和 UDP 分片属性；不执行远程脚本，也不开放任意 JSON Patch。每个订阅拥有稳定标签前缀、一个全节点自动组，并可用最多 12 条“分类名=正则”生成地区/线路组；自动组可持久化固定到成员节点，再恢复自动优选。每日规则更新任务会逐个刷新订阅和规则集，失败时保留旧配置并记录错误。订阅元数据保存在权限为 600 的 `/opt/pdg-bot/subscriptions.json`。规则集下载仅接受 HTTP/HTTPS，单文件限制 16MB；文本规则支持 Surge `.list` 和 Clash classical provider 的 `payload` 列表，只转换 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`/`IP-CIDR6`，进程名、用户代理等客户端专属条件会被忽略。管理端内置推荐目录聚焦国外服务的二次分流，不重复承担已有的国内/国际基础分流；`.mrs` 不兼容，二进制规则集需使用与 sing-box 1.12.x 匹配的 `.srs`。

## 前端开发

源码在 `web/`，部署产物在 `deploy/admin/web/`。VPS 运行时不需要 Node.js。

```bash
npm ci --prefix web
npm run dev --prefix web
npm run build --prefix web
```

提交前应确保 `web/dist/` 与 `deploy/admin/web/` 内容一致。CI 会重新构建并比较两者。前端使用 Vue 3、TypeScript 和 Vite；不要在静态资源中写入令牌、节点或真实域名。

## 运维

```bash
systemctl status pdg-admin
journalctl -u pdg-admin -n 100 --no-pager
curl -k https://127.0.0.1:9443/healthz
```

更换 DoT 域名后，Bot 会同时重启 mosdns 和 `pdg-admin` 以加载新证书。
