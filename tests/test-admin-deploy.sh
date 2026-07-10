#!/usr/bin/env bash
# 管理端部署回归:9443 仅内网放行、迁移幂等、失败回滚、安装资产齐全。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

eval "$(sed -n '/^migrate_fw_admin(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh")"
c_g(){ :; }; c_y(){ :; }
NFT_RC=0
nft(){ return "$NFT_RC"; }

pass=0; fail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; fail=$((fail+1)); }

cat > "$WORK/fw" <<'EOF'
table inet pdg {
  chain input {
    ip saddr 172.22.0.0/16 tcp dport { 53, 80, 81, 443, 853, 5228-5230, 8445 } accept
  }
}
EOF
migrate_fw_admin "$WORK/fw"
grep -q '8445, 9443 } accept' "$WORK/fw" && ok "老装内网端口集追加 9443" || bad "未追加 9443"
snap="$(cat "$WORK/fw")"
migrate_fw_admin "$WORK/fw"
[[ "$(cat "$WORK/fw")" == "$snap" ]] && ok "9443 迁移幂等" || bad "二次迁移改动配置"

cat > "$WORK/custom" <<'EOF'
table inet pdg { chain input { ip saddr 172.22.0.0/16 tcp dport { 53, 443, 9000 } accept } }
EOF
snap="$(cat "$WORK/custom")"
migrate_fw_admin "$WORK/custom"
[[ "$(cat "$WORK/custom")" == "$snap" ]] && ok "自定义端口集保持不动" || bad "误改自定义端口集"

sed 's/, 9443//' "$WORK/fw" > "$WORK/fail"
snap="$(cat "$WORK/fail")"
NFT_RC=1; migrate_fw_admin "$WORK/fail"; NFT_RC=0
[[ "$(cat "$WORK/fail")" == "$snap" ]] && ok "nft 校验失败回滚" || bad "nft 失败未回滚"

grep -q '9443' "$ROOT/deploy/firewall/nftables.conf" \
  && grep -q 'ip saddr __INTERNAL_CIDR__' "$ROOT/deploy/firewall/nftables.conf" \
  && ok "模板仅内网放行 9443" || bad "防火墙模板缺 9443 内网规则"
grep -q 'pdg-admin.py' "$ROOT/install.sh" \
  && grep -q 'admin.token' "$ROOT/install.sh" \
  && grep -q 'pdg-admin.service' "$ROOT/install.sh" \
  && ok "安装脚本包含管理端、令牌和 unit" || bad "安装脚本缺管理端资产"
grep -q 'NoNewPrivileges=true' "$ROOT/deploy/admin/pdg-admin.service" \
  && grep -q '/etc/privdns-gateway/admin.token' "$ROOT/deploy/admin/pdg-admin.service" \
  && ok "systemd unit 使用受限令牌文件" || bad "systemd unit 安全项缺失"
grep -q 'admin \[--rotate\]' "$ROOT/deploy/bot/pdg.sh" \
  && grep -q '旧链接立即失效' "$ROOT/deploy/bot/pdg.sh" \
  && ok "CLI 支持管理令牌轮换" || bad "CLI 缺令牌轮换"
for endpoint in groups rulesets route/test resources connections logs; do
  grep -q "/api/v1/$endpoint" "$ROOT/web/src/App.vue" || bad "PWA 缺 $endpoint API"
done
if grep -q '/api/v1/rulesets' "$ROOT/web/src/App.vue" && grep -q '/api/v1/connections' "$ROOT/web/src/App.vue"; then
  ok "PWA 已接入规则集和连接页面"
fi
if ! grep -Rqi 'panel/zashboard\|dashboard-root' "$ROOT/install.sh" "$ROOT/deploy/bot/pdg.sh" "$ROOT/deploy/admin/pdg-admin.service" \
  && grep -q 'rm -rf /opt/pdg-admin/web /opt/pdg-admin/zashboard' "$ROOT/deploy/bot/pdg.sh" \
  && grep -q '127.0.0.1:9090' "$ROOT/deploy/singbox/config.json.tmpl"; then
  ok "Zashboard 功能已移除、旧资产会清理且 Clash API 保持本机"
else
  bad "Zashboard 功能残留、旧资产未清理或 Clash API 安全边界缺失"
fi
grep -q 'set_group_selection' "$ROOT/deploy/bot/pdg_service.py" \
  && grep -q 'SubscriptionOverrides' "$ROOT/web/src/App.vue" \
  && grep -q '/api/v1/resources/project/update' "$ROOT/web/src/App.vue" \
  && ok "PWA 已接入节点固定选择、结构化覆写和在线更新" || bad "PWA 节点管控能力缺失"
grep -q '/api/v1/subscriptions' "$ROOT/web/src/App.vue" \
  && grep -q '/api/v1/subscriptions' "$ROOT/deploy/admin/pdg-admin.py" \
  && grep -q 'refresh_subscriptions' "$ROOT/deploy/bot/scheduled-update.sh" \
  && ok "节点订阅已接入 PWA/API/定时刷新" || bad "节点订阅部署链路缺失"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $fail"
[[ "$fail" == 0 ]]
