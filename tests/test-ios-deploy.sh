#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="$root/install.sh"
firewall="$root/deploy/firewall/nftables.conf"
pdg="$root/deploy/bot/pdg.sh"
admin_service="$root/deploy/admin/pdg-admin.service"
work="$root/.local/test-ios-deploy.$$"
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

[[ -f "$root/deploy/ios/profile-http.py" ]]
[[ -f "$root/deploy/ios/pdg-ios-profile.socket" ]]
[[ -f "$root/deploy/ios/pdg-ios-profile@.service" ]]
grep -q 'IOS_PROFILE_PORT=8111' "$install"
grep -q 'generate_ios_profile()' "$install"
grep -q 'write_ios_profile_allowlist()' "$install"
grep -q '.ios-profile-allowlist' "$install"
grep -q 'PDG_IOS_ALLOWED_CIDRS' "$install"
grep -q 'qrencode -t ANSIUTF8' "$install"
grep -q 'pdg-ios-profile.socket' "$install"
grep -q 'tcp dport { 53, 80, 81, 443, 853, 8111,' "$firewall"
grep -q 'migrate_fw_ios_profile()' "$pdg"
grep -q 'ensure_ios_profile' "$pdg"
grep -q 'write_ios_profile_allowlist()' "$pdg"
grep -q 'ensure_ios_profile_access()' "$pdg"
grep -q 'PDG_IOS_ALLOWED_CIDRS' "$pdg"
grep -q '常驻 8111' "$pdg"
grep -q 'pdg-ios-profile.socket' "$root/uninstall.sh"
grep -q 'migrate-ios-profile' "$admin_service"
grep -q 'migrate-ios-profile) cmd_migrate_ios_profile' "$pdg"
grep -q 'install -m755 "$src/profile-http.py"' "$pdg"
grep -q 'EnvironmentFile=-/etc/privdns-gateway/ios-profile.env' "$root/deploy/ios/pdg-ios-profile@.service"
grep -q 'DynamicUser=yes' "$root/deploy/ios/pdg-ios-profile@.service"
grep -q 'ProtectSystem=strict' "$root/deploy/ios/pdg-ios-profile@.service"

eval "$(sed -n '/^ensure_ios_profile_access(){/,/^}/p' "$pdg")"
c_y(){ :; }
cat > "$work/mosdns.yaml" <<'EOF'
- tag: npn_clients
  type: ip_set
  args: { ips: ["172.22.0.0/16"] }
EOF
# shellcheck disable=SC2218
ensure_ios_profile_access "$work/mosdns.yaml" "$work/env"
grep -qx 'PDG_IOS_ALLOWED_CIDRS=172.22.0.0/16' "$work/env/ios-profile.env"
printf '%s\n' 'args: { ips: [] }' > "$work/mosdns.yaml"
# shellcheck disable=SC2218
ensure_ios_profile_access "$work/mosdns.yaml" "$work/env"
[[ ! -e "$work/env/ios-profile.env" ]]

# 模拟 rc.2 旧更新器：新 admin unit 的 ExecStartPre 调用新 pdg，补齐旧安装器不知道的 iOS 运行时。
eval "$(sed -n '/^ensure_ios_profile_runtime(){/,/^}/p' "$pdg")"
REPO_DIR="$work/repo"
runtime_root="$work/runtime"
runtime_log="$work/runtime.log"
mkdir -p "$REPO_DIR/deploy/ios"
for name in profile-http.py pdg-ios-profile.socket pdg-ios-profile@.service pdg-dot-ondemand.mobileconfig.tmpl; do
  printf '%s\n' "$name" > "$REPO_DIR/deploy/ios/$name"
done
install(){
  if [[ "$1" == "-d" ]]; then
    shift; [[ "${1:-}" == -m* ]] && shift
    mkdir -p "$@"
  else
    mode="$1"; shift
    cp "$1" "$2"
    [[ "$mode" == "-m755" ]] && chmod +x "$2"
    return 0
  fi
}
ensure_ios_profile(){
  mkdir -p "$runtime_root/opt/pdg-bot/ios-www"
  printf '%s\n' profile > "$runtime_root/opt/pdg-bot/ios-www/ios-dot.mobileconfig"
  printf '%s\n' ios-dot.mobileconfig > "$runtime_root/opt/pdg-bot/ios-www/.ios-profile-allowlist"
}
ensure_ios_profile_access(){
  mkdir -p "$2"
  printf '%s\n' PDG_IOS_ALLOWED_CIDRS=172.22.0.0/16 > "$2/ios-profile.env"
}
migrate_fw_ios_profile(){ printf 'firewall %s\n' "$1" >> "$runtime_log"; }
systemctl(){ printf 'systemctl %s\n' "$*" >> "$runtime_log"; }
ensure_ios_profile_runtime "$runtime_root"
[[ -f "$runtime_root/opt/pdg-bot/profile-http.py" ]]
[[ -f "$runtime_root/etc/systemd/system/pdg-ios-profile.socket" ]]
[[ -f "$runtime_root/etc/systemd/system/pdg-ios-profile@.service" ]]
grep -q '^systemctl daemon-reload$' "$runtime_log"
grep -q '^systemctl enable --now pdg-ios-profile.socket$' "$runtime_log"
rm -f "$REPO_DIR/deploy/ios/profile-http.py"
! ensure_ios_profile_runtime "$runtime_root"

python -m py_compile "$root/deploy/ios/profile-http.py"
echo "ios-deploy policy OK"
