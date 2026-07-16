#!/usr/bin/env bash
# 卸载 PrivDNS Gateway (保留 certbot 证书与二进制; 加 --purge 一并删)。
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

systemctl disable --now pdg-bot pdg-admin pdg-probe81 mosdns sing-box pdg-rules-update.timer pdg-health.timer 2>/dev/null || true
systemctl disable --now pdg-ios-profile.socket pdg-ios-profile-sync.service pdg-ios-profile-cleanup.timer 2>/dev/null || true
rm -f /etc/systemd/system/{pdg-bot,pdg-admin,pdg-probe81,mosdns,sing-box,pdg-rules-update,pdg-health}.service \
      /etc/systemd/system/pdg-ios-profile.socket /etc/systemd/system/pdg-ios-profile@.service \
      /etc/systemd/system/pdg-ios-profile-sync.service \
      /etc/systemd/system/pdg-ios-profile-cleanup.service /etc/systemd/system/pdg-ios-profile-cleanup.timer \
      /etc/systemd/system/pdg-rules-update.timer /etc/systemd/system/pdg-health.timer \
      /etc/systemd/system/journald.conf.d/50-pdg.conf
systemctl daemon-reload
systemctl restart systemd-journald 2>/dev/null || true

# 防火墙: 删本项目独立表 inet pdg(不碰 Docker/fail2ban 等其它表); 有备份则还原 /etc/nftables.conf
command -v nft >/dev/null 2>&1 && nft delete table inet pdg 2>/dev/null || true
if [[ -e /etc/nftables.conf.pdg-orig ]]; then
  mv -f /etc/nftables.conf.pdg-orig /etc/nftables.conf
  nft -f /etc/nftables.conf 2>/dev/null || true
fi
# DNS: 还原 systemd-resolved 与 resolv.conf
systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved' && systemctl enable --now systemd-resolved 2>/dev/null || true
if [[ -e /etc/resolv.conf.pdg-orig ]]; then
  rm -f /etc/resolv.conf; mv /etc/resolv.conf.pdg-orig /etc/resolv.conf
elif [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
  ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi

# 内核参数: 删除项目持久化配置；新安装有原值备份时立即恢复。
rm -f /etc/sysctl.d/99-pdg-keepalive.conf
if [[ -f /etc/privdns-gateway/sysctl-keepalive.orig ]]; then
  sysctl -p /etc/privdns-gateway/sysctl-keepalive.orig >/dev/null 2>&1 || true
fi

echo "已停止并移除 systemd 单元、防火墙表(inet pdg)，并尽量还原 DNS 与 TCP keepalive。"
echo "保留: /etc/mosdns /etc/sing-box /opt/pdg-bot /opt/pdg-admin 与 Let's Encrypt 证书。"

if [[ "${1:-}" == "--purge" ]]; then
  echo "[--purge] 删除配置与数据…"
  rm -rf /etc/mosdns /etc/sing-box /opt/pdg-bot /opt/pdg-admin /etc/privdns-gateway   # 含管理令牌与 bot token
  rm -f /usr/local/bin/mosdns /usr/local/bin/sing-box \
        /usr/local/bin/pdg /usr/local/bin/pdg-set-token \
        /usr/local/bin/proxy-gateway-open-cert-http.sh \
        /usr/local/bin/proxy-gateway-restore-firewall.sh \
        /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
  rm -rf /opt/privdns-gateway /var/lib/privdns-gateway   # 仓库副本 + 快照 (放最后, 脚本已载入内存, 删它安全)
  echo "已 purge。apt 依赖与证书目录 /etc/letsencrypt 仍保留；证书可按需手动 certbot delete。"
fi
