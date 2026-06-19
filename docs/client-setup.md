# 客户端设置

手机端**只设置私密 DNS / 描述文件**，不安装 VPN / Clash / sing-box。

## Android (Private DNS / DoT)

设置 → 网络和互联网 → 私人 DNS（不同机型路径略异）→ 选「私人 DNS 提供商主机名」→ 填：

```
dns.example.com
```

- 走 DoT，端口固定 853（系统不可改，与服务端一致即可）。
- 主机名必须与 dnsdist 证书的 SAN 匹配，否则握手失败。

## iOS / iPadOS (DoH 描述文件)

iOS 不能像 Android 那样只填主机名，需要安装 DoH 描述文件（mobileconfig）：

1. 用 `deploy/ios/doh.mobileconfig.tmpl` 生成描述文件：替换 `{{DNS_HOSTNAME}}` 与两个 UUID
   （`uuidgen`）。V3 阶段 `pdg` 会自动生成并给下载链接。
2. 通过 Safari 打开描述文件下载链接，或用 AirDrop / 邮件发到设备。
3. 设置 → 通用 → VPN 与设备管理 → 安装描述文件。

DoH 地址（与本项目端口规划一致）：

```
https://dns.example.com:8443/dns-query
```

必要时可再提供 DoT 备用（同 Android 主机名）。

## 服务端应对外提供

```
Android DoT 主机名 : dns.example.com            (:853)
iOS DoH            : https://dns.example.com:8443/dns-query
iOS 描述文件        : https://dns.example.com/ios/doh.mobileconfig   (V3 自动生成)
```

## 验证
设置好后，在服务端：

```bash
pdg test chatgpt.com     # 期望 Outbound=tw-ss2022, DNS=JP 内网 IP
pdg test youtube.com     # 期望 Outbound=hk-ss2022, DNS=JP 内网 IP
pdg doctor               # DoT/DoH 端口、出口连通、分流抽样
```

手机侧打开对应站点，确认走的是预期出口（如 IP 归属地 / 解锁状态）。
