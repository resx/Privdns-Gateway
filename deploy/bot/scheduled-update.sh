#!/usr/bin/env bash
# 定时刷新规则库和节点订阅: geosite + Surge 规则集 + GatewayService 节点订阅。
# 由 pdg-rules-update.timer 每日触发。失败不致命, 保留旧规则。
set -uo pipefail
/bin/bash /opt/pdg-bot/update-rules.sh || echo "geosite 更新失败, 保留旧库"
cd /opt/pdg-bot && /usr/bin/python3 -c \
  "from pdg_service import GatewayService; service=GatewayService(); print('rulesets refreshed:', service.refresh_rulesets()); print('subscriptions refreshed:', service.refresh_subscriptions())" \
  || echo "远程规则集或节点订阅刷新失败, 保留旧资源"
