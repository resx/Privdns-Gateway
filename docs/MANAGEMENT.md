# 管理端

PrivDNS Gateway 提供移动端优先的独立 PWA。它与 Telegram Bot 共用配置控制层，不直接暴露 sing-box Clash API。

## 访问与认证

管理服务 `pdg-admin` 监听 `0.0.0.0:9443`，复用 DoT 证书。nftables 只允许 `PDG_INTERNAL_CIDR` 访问该端口；所有 `/api/v1/*` 请求还必须携带：

```http
Authorization: Bearer <admin.token>
```

安装时自动生成 `/etc/privdns-gateway/admin.token`，目录权限 700、文件权限 600。获取入口：

```bash
sudo pdg admin
sudo pdg admin --rotate  # 令牌泄露时轮换;旧链接立即失效
```

也可在 Telegram Bot 中选择「📱 客户端 → 🖥 管理面板」。令牌放在 URL fragment (`#token=...`) 中，浏览器首次打开后保存到本地存储并立即从地址栏移除；fragment 不会出现在 HTTP 请求和服务端访问日志中。

管理链接拥有完整配置权限。不要分享、截图或放入公开书签。Clash API 必须继续监听 `127.0.0.1:9090`。

## 功能与 API

| 功能 | API |
|---|---|
| 概览和服务状态 | `GET /api/v1/overview` |
| 出口列表/预览/添加 | `GET /api/v1/exits`, `POST /api/v1/exits/preview`, `POST /api/v1/exits` |
| 出口影响/删除 | `GET /api/v1/exits/{tag}/impact`, `DELETE /api/v1/exits/{tag}` |
| 批量测速/默认出口 | `POST /api/v1/exits/test`, `PUT /api/v1/final` |
| 故障组保存/删除 | `POST /api/v1/groups`, `DELETE /api/v1/groups/{tag}` |
| 分流列表/保存/删除 | `GET /api/v1/rules`, `POST /api/v1/rules`, `DELETE /api/v1/rules/{domain}` |
| 路由模拟 | `POST /api/v1/route/test` |
| 规则集管理 | `GET/POST /api/v1/rulesets`, `PUT/DELETE /api/v1/rulesets/{tag}`, `POST .../{tag}/refresh` |
| 活动连接 | `GET/DELETE /api/v1/connections`, `DELETE /api/v1/connections/{id}` |
| 服务日志 | `GET /api/v1/logs` |
| 进程存活 | `GET /healthz`（不返回配置） |

API 从不返回节点密码、UUID 或完整服务器地址。连接和日志可能包含访问域名/IP,只应在可信设备查看。所有 sing-box 变更通过 `deploy/bot/pdg_control.py` 执行锁定、候选校验、原子替换和失败回滚。规则集下载仅接受 HTTP/HTTPS,单文件限制 16MB。

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
