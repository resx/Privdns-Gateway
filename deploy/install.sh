#!/usr/bin/env bash
# PrivDNS Gateway 安装脚本 (JP 生产机, Debian 12)。需 root。
# 安装控制面 pdg + 目录骨架 + systemd 单元。dnsdist / sing-box 请单独安装。
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行: sudo $0" >&2
  exit 1
fi

echo "==> 创建目录骨架"
install -d -m 0755 /opt/pdg /etc/pdg /etc/pdg/tls
install -d -m 0750 /var/lib/pdg /var/lib/pdg/rulesets/cache /var/lib/pdg/backup /var/lib/pdg/out
install -d -m 0750 /var/log/pdg /etc/sing-box /etc/dnsdist

echo "==> 安装 pdg (venv: /opt/pdg/venv)"
python3 -m venv /opt/pdg/venv
/opt/pdg/venv/bin/pip install --quiet --upgrade pip
/opt/pdg/venv/bin/pip install --quiet "$REPO_DIR"
ln -sf /opt/pdg/venv/bin/pdg /usr/local/bin/pdg

echo "==> 安装配置样例 (已存在则不覆盖)"
for f in pdg.conf rules.conf policies.conf; do
  if [[ -e /etc/pdg/$f ]]; then
    echo "    跳过 /etc/pdg/$f (已存在)"
  else
    install -m 0640 "$REPO_DIR/config/$f" "/etc/pdg/$f"
    echo "    安装 /etc/pdg/$f"
  fi
done

if [[ ! -e /etc/dnsdist/dnsdist.conf ]]; then
  install -m 0640 "$REPO_DIR/deploy/dnsdist/dnsdist.conf" /etc/dnsdist/dnsdist.conf
  echo "    安装 /etc/dnsdist/dnsdist.conf"
fi

echo "==> 安装 systemd 单元"
install -m 0644 "$REPO_DIR/deploy/systemd/sing-box.service" /etc/systemd/system/
install -m 0644 "$REPO_DIR/deploy/systemd/pdg-tproxy.service" /etc/systemd/system/
systemctl daemon-reload

cat <<'EOF'

==> 完成。下一步:
  1. 编辑 /etc/pdg/pdg.conf  (jp_internal_ip / HK/TW SS2022 server/port/method/password)
  2. 放置 DoT/DoH 证书到 /etc/pdg/tls/{fullchain,privkey}.pem
  3. 安装 dnsdist 与 sing-box 二进制
  4. pdg compile     # 生成 /etc/dnsdist/pdg-generated.lua 与 /etc/sing-box/config.json
  5. pdg reload      # 校验 + reload 服务
  6. systemctl enable --now dnsdist sing-box pdg-tproxy
  7. pdg doctor      # 体检
EOF
