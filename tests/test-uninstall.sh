#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="$ROOT/install.sh"
UNINSTALL="$ROOT/uninstall.sh"

ok(){ echo "  OK $*"; }
bad(){ echo "  FAIL $*" >&2; exit 1; }

if grep -q 'pdg-bot pdg-admin pdg-probe81 mosdns sing-box' "$UNINSTALL" \
  && grep -q '{pdg-bot,pdg-admin,pdg-probe81,mosdns,sing-box' "$UNINSTALL"; then
  ok "卸载会停止 pdg-admin 并删除其 unit"
else
  bad "卸载遗漏 pdg-admin 生命周期"
fi

if grep -q 'rm -rf /etc/mosdns /etc/sing-box /opt/pdg-bot /opt/pdg-admin /etc/privdns-gateway' "$UNINSTALL"; then
  ok "purge 会删除管理端部署目录"
else
  bad "purge 遗漏 /opt/pdg-admin"
fi

if grep -q 'sysctl-keepalive.orig' "$INSTALL" \
  && grep -q 'rm -f /etc/sysctl.d/99-pdg-keepalive.conf' "$INSTALL" \
  && grep -q 'rm -f /etc/sysctl.d/99-pdg-keepalive.conf' "$UNINSTALL" \
  && grep -q 'sysctl -p /etc/privdns-gateway/sysctl-keepalive.orig' "$UNINSTALL"; then
  ok "安装失败与卸载都会撤销 TCP keepalive 持久化配置"
else
  bad "TCP keepalive 缺少备份或清理链路"
fi

if grep -q 'systemctl restart systemd-journald' "$INSTALL" \
  && grep -q 'systemctl restart systemd-journald' "$UNINSTALL"; then
  ok "回滚或卸载删除 journald drop-in 后会重新加载"
else
  bad "journald drop-in 删除后未重新加载"
fi

if [[ "$(grep -c '/etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh' "$INSTALL")" -ge 2 ]] \
  && grep -q '/etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh' "$UNINSTALL"; then
  ok "安装回滚与 purge 都会删除证书部署 hook"
else
  bad "证书部署 hook 生命周期不完整"
fi
