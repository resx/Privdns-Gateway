#!/usr/bin/env bash
# Pure regression checks for the old PrivDNS Gateway -> 5gpn compatibility bridge.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/.local/legacy-migration-test.$$"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK"

cat > "$WORK/old.json" <<'EOF'
{
  "experimental": {
    "clash_api": {"external_controller": "127.0.0.1:9090"},
    "cache_file": {"enabled": true, "path": "/etc/sing-box/cache.db"}
  },
  "inbounds": [
    {"type": "direct", "tag": "in-https", "listen_port": 443},
    {"type": "direct", "tag": "in-gms-5228", "listen_port": 5228},
    {"type": "mixed", "tag": "tg-proxy", "listen": "0.0.0.0", "listen_port": 8445}
  ],
  "outbounds": [
    {"type": "direct", "tag": "jp"},
    {"type": "direct", "tag": "gms-mtalk"}
  ],
  "route": {
    "rules": [
      {"inbound": ["in-gms-5228"], "outbound": "gms-mtalk", "override_address": "mtalk.google.com"},
      {"inbound": ["tg-proxy"], "outbound": "jp"},
      {"domain_suffix": ["example.com"], "outbound": "jp"}
    ],
    "final": "jp"
  }
}
EOF

bash -n "$ROOT/scripts/migrate-privdns-gateway.sh"
"$ROOT/scripts/migrate-privdns-gateway.sh" --convert "$WORK/old.json" "$WORK/new.json"

jq -e '
  (.inbounds | length == 2)
  and ([.inbounds[].tag] | sort == ["legacy-egress", "tg-proxy"])
  and ([.inbounds[].listen_port] | sort == [8445, 18081])
  and (.experimental.clash_api.external_controller == "127.0.0.1:9091")
  and (.route.rules[0].inbound == ["legacy-egress"])
  and (.route.rules[0].domain == ["mtalk.google.com"])
  and (.route.rules[0].port == [5228, 5229, 5230])
  and ([.route.rules[].inbound[]?] | index("in-gms-5228") == null)
  and ([.route.rules[].inbound[]?] | index("tg-proxy") != null)
' "$WORK/new.json" >/dev/null

printf '%s\n' '{"outbounds": [], "route": {}}' > "$WORK/invalid.json"
if "$ROOT/scripts/migrate-privdns-gateway.sh" --convert "$WORK/invalid.json" "$WORK/invalid-out.json"; then
  echo 'invalid legacy config was accepted' >&2
  exit 1
fi

printf 'legacy migration regression OK\n'
