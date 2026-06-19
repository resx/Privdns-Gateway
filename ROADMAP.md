# Roadmap

阶段划分，与设计草案一致。控制面 (`pdg`) 已实现 V2 内核；V0/V1 为 JP 机上的链路实跑验证。

## V0 — 验证当前链路
- [ ] Android Private DNS / DoT 能访问 JP
- [ ] iOS DoH / mobileconfig 能访问 JP
- [ ] DNS 命中规则后返回 JP 唯一内网 IP
- [ ] 手机访问代理域名确实进入 JP 80/443

## V1 — 最小 sing-box 分流闭环
- [ ] 透明入口正确 (tproxy/redirect, 不可误用 mixed inbound 当代理入口)
- [ ] sing-box 能 sniff 到 SNI / Host
- [ ] AI/Binance → TW，YouTube/Netflix/X/IG → HK，默认 → JP
- [ ] 先跑稳 TCP 80/443

## V2 — 规则编译器  ✅ (内核完成)
- [x] Surge 风格本地规则解析 (DOMAIN / -SUFFIX / -KEYWORD / -REGEX)
- [x] 远程 RULE-SET 下载 + 缓存 + 失败回退
- [x] 单一规则源生成 dnsdist + sing-box (+ nftables)
- [x] 校验 + reload + rollback
- [x] `pdg test` / `doctor` / `status`

## V3 — iOS 完整支持
- [ ] 自动生成 iOS DoH mobileconfig (现有模板见 `deploy/ios/`)
- [ ] 提供安装链接 / status 页展示 Android·iOS 设置方式
- [ ] doctor 检查 DoH / DoT 可用性 (已有端口探测雏形)

## V4 — TG Bot
- [ ] `/rule add|del|move|list`、`/ruleset refresh`、`/test`、`/reload`、`/doctor`、`/rollback`、`/status`
- [ ] Bot 只操作上层规则，不直接动底层配置 (复用 `pdg` 同一套逻辑)

## V5 — UDP / QUIC 增强
- [ ] sing-box transparent UDP
- [ ] SS2022 UDP outbound
- [ ] 决定支持 QUIC 还是阻断回落 TCP
- [ ] 非标准端口能力
