# 架构

## 约束与路线选择

当前网络条件（已确认）：

1. 手机不开 VPN
2. 手机只能通过【一个内网地址】访问 JP
3. 手机不能直接访问 HK/TW
4. JP 与 HK/TW 之间无内网，只能走公网
5. HK/TW 已部署 SS2022

因此**不能**采用：手机端 Tailscale/WireGuard/Clash/sing-box、fake-ip 本地接管、
手机直连 HK/TW 内网、DNS 返回多个策略 VIP、依赖 fake-ip 池。

正确路线：

> 所有需要代理的域名，DNS 都返回 **JP 唯一内网 IP**；
> JP 上的 sing-box 根据 sniff 到的域名，再分流到 HK / TW / JP 出口。

## DNS 层 (dnsdist)

JP 用 dnsdist 对外提供加密 DNS：Android DoT 853，iOS DoH 8443。

| 域名分类 | DNS 行为 |
|---|---|
| 命中代理规则 | 返回 JP 唯一内网 IP (A)，AAAA → NODATA，HTTPS/SVCB → 空 |
| DIRECT | 返回真实 IP（手机直连，不经 JP） |
| BLOCK | NXDOMAIN |

- 代理域名只返回 A；屏蔽 AAAA 避免 IPv6 绕过，屏蔽 HTTPS/SVCB 降低 ECH/HTTP3/QUIC 复杂度。
- TTL 60–120s，方便改规则后快速生效（`pdg.conf` 默认 120）。

dnsdist 适合对外提供 DoT/DoH，也方便做 DNS 层规则控制 —— 因此 DNS 层继续用它。

## 流量层 (sing-box)

```
手机访问 chatgpt.com
  → DNS 返回 JP 唯一内网 IP
  → 手机连 JP:443, TLS SNI = chatgpt.com
  → JP sing-box sniff 域名
  → 匹配 AI 策略 → 转发到 TW SS2022 outbound
```

### 为什么直接用 sing-box（而非 HAProxy → sniproxy）
HK/TW 已部署 SS2022，直接 `JP sing-box → HK/TW SS2022` 即可：
链路全程加密、HK/TW 不必开放 sniproxy 80/443、不易变成 open SNI proxy、
规则/UDP/QUIC/fallback 更好扩展、复用现有 SS2022、后续 TG Bot 管理更自然。

### 关键：透明入口，不是代理协议入口
手机访问 `JP:443` 时**不是**在使用 HTTP/SOCKS 代理协议，
所以 sing-box **不能**用普通 `mixed` inbound 当客户端代理入口。
必须用透明入口：`tproxy` / `redirect` 配合 `nftables`。

```
手机 → JP内网IP:443
  → nftables TPROXY 把连接交给 sing-box
  → sing-box sniff TLS SNI / HTTP Host
  → 按规则转发到 hk-ss2022 / tw-ss2022 / jp / direct
```

分工：dnsdist 负责 DNS 引导；nftables/tproxy 负责把普通连接送进 sing-box；
sing-box 负责 sniff 与分流。**务必验证**普通 HTTPS 连接没被误当成代理连接处理。

## 规则系统

- 上层规则兼容 Surge 风格（`DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `DOMAIN-REGEX` / `RULE-SET` / `FINAL`）。
- Surge `.list` ≠ sing-box 原生 rule-set，本项目做**转换**：Surge `.list` → 解析 → 同时生成 dnsdist DNS 规则与 sing-box route 规则。
- V1 暂不支持客户端侧能力（`PROCESS-NAME` / `USER-AGENT` / `URL-REGEX` / `IP-CIDR` / `GEOIP` / `DEST-PORT` / `SRC-IP`）——
  手机不开 VPN，服务端 DNS/SNI 网关无法可靠处理这些。解析时这类规则会被跳过并计数告警。

### 单一规则源（核心）
DNS 与 sing-box 必须由同一份 `rules.conf` 生成，否则两者会不一致。
`pdg` 的编译器把 `rules.conf`（含展开后的 RULE-SET）编译成一张有序表 `CompiledTable`，
再分别投影成 dnsdist 的 dns_mode 分组（spoof/direct/block）与 sing-box 的出口分组。

### 出口与 DNS 行为 (dns_mode)
每个出口有一个 `dns_mode`，决定其域名的 DNS 行为：

- `spoof`：返回 JP 内网 IP，流量进 JP 再分流（远程 SS2022 出口 + 默认 `jp`）
- `direct`：返回真实 IP，手机直连，不经 JP
- `block`：NXDOMAIN

> 默认 `Final → jp (spoof)` 意味着**未命中域名也走 JP**（JP 自身 IP 出网，full-tunnel）。
> 若只想代理白名单、其余直连，把 `policies.conf` 的 `Final` 改为 `direct`
> （或在 `pdg.conf [dns_modes]` 把 `jp` 改为 `direct`）。

## 端口规划 (V1 建议)

| 端口 | 服务 | 用途 |
|---|---|---|
| 853/tcp | dnsdist DoT | Android Private DNS |
| 8443/tcp | dnsdist DoH | iOS DoH |
| 80/tcp | sing-box (经 nftables TPROXY) | HTTP 透明入口 |
| 443/tcp | sing-box (经 nftables TPROXY) | HTTPS 透明入口 |

DoH 不要与流量入口抢同一个 443（除非用独立 IP / 独立域名 + 明确反代）。

## UDP / QUIC (V1 策略)
先跑稳 TCP 80/443；UDP 443 暂不处理或在 JP 侧丢弃让客户端回落 TCP。
确认 HK/TW SS2022 的 UDP 能力后，V5 再做透明 UDP / QUIC。
