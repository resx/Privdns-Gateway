# 从原项目迁移

本文适用于当前运行原项目 `v1.1.16` 或相近旧版本的设备，迁移到 PrivDNS Gateway 当前发布版本。

迁移目标是保留现有服务配置、出口、分流规则、订阅、令牌、证书和防火墙自定义内容，只替换项目代码并执行必要的兼容迁移。

## 迁移前确认

迁移需要 root 权限，并建议从 SSH 连接执行。确认当前服务正常：

```bash
sudo pdg status
sing-box version
```

项目要求 sing-box 使用 `1.12.x`。不要在迁移过程中升级到 `1.13+`，该版本移除了项目依赖的目标地址覆盖行为。

确认实际运行仓库的位置。标准安装目录是：

```text
/opt/privdns-gateway
```

不要只更新用户家目录下的另一个代码副本；`pdg` 默认使用 `/opt/privdns-gateway`。

## 1. 创建快照

先创建项目快照：

```bash
sudo pdg snapshot
```

建议再保存一份独立备份：

```bash
sudo mkdir -p /root/pdg-migration-backup
sudo cp -a /etc/mosdns /etc/sing-box /etc/nftables.conf \
  /etc/privdns-gateway /opt/pdg-bot \
  /root/pdg-migration-backup/
```

快照和备份包括：

- mosdns 配置
- sing-box 配置
- nftables 配置
- Bot 环境文件和管理令牌
- 管理端配置
- 证书及相关服务文件

## 2. 切换代码仓库

查看当前远端：

```bash
git -C /opt/privdns-gateway remote -v
```

如果仍然指向原项目，切换到当前项目仓库：

```bash
sudo git -C /opt/privdns-gateway remote set-url origin \
  https://github.com/resx/Privdns-Gateway.git
```

只修改 Git 远端地址，不会修改现有网关配置。

## 3. 执行代码升级

使用生命周期命令升级，不要直接用普通 `install.sh` 覆盖已有安装：

```bash
sudo pdg update
```

更新流程会：

1. 创建升级前快照。
2. 拉取当前发布 tag。
3. 替换 Bot、管理服务和 PWA 代码。
4. 保留 `/etc/mosdns`、`/etc/sing-box`、令牌、证书和现有服务配置。
5. 校验 Python、sing-box 和核心服务。
6. 校验失败时恢复升级前快照。

从原项目 `v1.1.16` 迁移时，当前稳定发布版本为 `v2.0.0`。

## 4. 执行一次性兼容迁移

旧版 `pdg update` 运行期间，当前进程仍然是旧脚本，因此第一次更新完成后，部分新迁移会留到下一次管理命令。升级完成后再运行一次：

```bash
sudo pdg update
```

必要时也可以使用其他管理类命令触发迁移，例如：

```bash
sudo pdg restart
```

迁移包括：

- 将旧 Bot unit 中的 token 迁移到权限更严格的环境文件。
- 将旧 `inet filter` 防火墙迁移到独立的 `inet pdg` 表。
- 补齐 mosdns `concurrent` 配置。
- 补齐 GMS/FCM `5228-5230` 入站及内网防火墙放行。
- 补齐 `8111` IP 登记与 iOS 描述文件下载、过期文件清理和白名单同步服务。
- 将 DNS `53/853` 与管理端 `9443` 收紧为动态 IP 白名单，其他数据端口继续限制在内网卡段。
- 调整手工分流规则，使其优先于远程规则集。

这些迁移是幂等的，已经完成时会自动跳过。

## 自定义防火墙

如果旧系统修改过 `/etc/nftables.conf`，增加了额外端口、额外 table 或自定义匹配规则，迁移程序会识别并跳过自动重建，避免覆盖用户规则。

这种情况下：

1. 旧防火墙配置会保持不动。
2. 需要人工检查 `inet filter` 与项目新表 `inet pdg` 的差异。
3. 确认规则后再手动加载配置。

不要为了强制迁移而删除原防火墙配置。无法确认规则含义时，保留快照并先执行 `sudo pdg doctor`。

## 5. 验证迁移结果

```bash
sudo pdg status
sudo pdg doctor
sudo sing-box check -c /etc/sing-box/config.json
sudo systemctl --no-pager --full status \
  mosdns sing-box pdg-bot pdg-admin pdg-probe81
sudo nft list table inet pdg
```

重点确认：

- 代码版本为稳定发布 `v2.0.0`。
- mosdns、sing-box、管理端和探测服务均为 `active`。
- sing-box 配置检查通过。
- 原有出口、订阅和分流规则仍存在。
- DoT 域名和证书未改变。
- 内网管理端 `9443` 可以访问。
- 自定义防火墙规则没有被覆盖。

## 更新失败时

先不要重复覆盖安装，保留错误输出并检查 Git 状态：

```bash
git -C /opt/privdns-gateway status
git -C /opt/privdns-gateway remote -v
git -C /opt/privdns-gateway fetch origin main
```

如果设备本地残留了已经移动或删除的旧发布 tag，可清理本地引用后再更新。只删除 Git tag，不会删除配置：

```bash
sudo git -C /opt/privdns-gateway tag -d \
  v2.0.0-rc.1 v2.0.0-rc.2 2>/dev/null || true
sudo pdg update
```

如果新版本校验失败，回滚到最近快照：

```bash
sudo pdg rollback
```

不要在已有安装上直接执行以下命令，除非明确要做覆盖式重装：

```bash
sudo PDG_FORCE_REINSTALL=1 ./install.sh
```

## 迁移完成后的日常操作

迁移成功后，后续使用普通更新流程即可：

```bash
sudo pdg update
sudo pdg status
```

PWA、Telegram Bot、出口、订阅、规则集和管理令牌均继续使用原有配置。
