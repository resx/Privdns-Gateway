#!/usr/bin/env bash
# Migrate an existing PrivDNS Gateway v2 deployment to the 5gpn runtime.
# The old sing-box remains as a compatibility egress backend until its nodes
# are explicitly moved to mihomo. No old state is deleted by this script.
set -Eeuo pipefail

OLD_CONFIG_DIR=/etc/privdns-gateway
OLD_SINGBOX=/etc/sing-box/config.json
OLD_MOSDNS=/etc/mosdns
OLD_BOT=/opt/pdg-bot
OLD_ADMIN=/opt/pdg-admin
MIGRATION_ROOT=/var/lib/5gpn/migrations
LEGACY_PORT=18081
LEGACY_CLASH_PORT=9091

log() { printf '[5gpn migration] %s\n' "$*"; }
warn() { printf '[5gpn migration] WARNING: %s\n' "$*" >&2; }
fail() { printf '[5gpn migration] ERROR: %s\n' "$*" >&2; return 1; }

require_root() {
    [[ "$(id -u)" == 0 ]] || fail 'run this command as root'
}

require_cmds() {
    local command
    for command in jq systemctl install cp mv rm; do
        command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
    done
}

# Convert the old JSON config into a loopback-only sing-box egress service.
# This is intentionally a pure jq transformation so the input remains an
# auditable JSON document and invalid shapes fail before any publication.
convert_config() {
    local input="$1" output="$2"
    [[ -f "$input" && ! -L "$input" ]] || fail "sing-box config is missing: $input"
    jq -e '
        type == "object"
        and (.outbounds | type == "array" and length > 0)
        and (.route | type == "object")
    ' "$input" >/dev/null || fail 'old sing-box config has an unsupported shape'

    jq --argjson legacy_port "$LEGACY_PORT" --argjson clash_port "$LEGACY_CLASH_PORT" '
        .inbounds = (
            ([.inbounds[]? | select(.tag == "tg-proxy")] + [{
                "type": "mixed",
                "tag": "legacy-egress",
                "listen": "127.0.0.1",
                "listen_port": $legacy_port
            }])
        )
        | .experimental = ((.experimental // {})
            | .clash_api = ((.clash_api // {})
                | .external_controller = ("127.0.0.1:" + ($clash_port | tostring))))
        | .route.rules = (
            [{
                "inbound": ["legacy-egress"],
                "domain": ["mtalk.google.com"],
                "port": [5228, 5229, 5230],
                "outbound": "gms-mtalk"
            }]
            + [.route.rules[]?
                | select((((.inbound // []) | index("tg-proxy")) != null) or (.inbound == null))]
        )
    ' "$input" > "$output" || fail 'could not render the legacy sing-box candidate'

    jq -e '.inbounds | all(.[]; (.listen_port == 18081) or (.tag == "tg-proxy"))' "$output" \
        >/dev/null || fail 'legacy config still exposes an old public data inbound'
    jq -e '.experimental.clash_api.external_controller == "127.0.0.1:9091"' "$output" \
        >/dev/null || fail 'legacy clash API was not moved off mihomo controller port'
}

copy_if_present() {
    local source="$1" destination="$2"
    [[ -e "$source" || -L "$source" ]] || return 0
    [[ ! -L "$source" ]] || fail "refusing symlinked legacy path: $source"
    cp -a -- "$source" "$destination"
}

capture_state() {
    local directory="$1" unit active enabled
    install -d -m 0700 "$directory"
    : > "$directory/units.state"
    for unit in mosdns sing-box pdg-bot pdg-admin pdg-health.timer pdg-rules-update.timer \
                pdg-ios-profile.socket pdg-ios-profile-cleanup.timer; do
        active=0; enabled=0
        systemctl is-active --quiet "$unit" 2>/dev/null && active=1 || true
        case "$(systemctl is-enabled "$unit" 2>/dev/null || true)" in
            enabled|enabled-runtime) enabled=1 ;;
        esac
        printf '%s %s %s\n' "$unit" "$active" "$enabled" >> "$directory/units.state"
    done
}

restore_state() {
    local directory="$1" unit active enabled
    [[ -f "$directory/units.state" ]] || return 0
    while read -r unit active enabled; do
        [[ "$unit" =~ ^[a-zA-Z0-9@_.-]+$ && "$active" =~ ^[01]$ && "$enabled" =~ ^[01]$ ]] || continue
        systemctl stop "$unit" >/dev/null 2>&1 || true
        if [[ "$enabled" == 1 ]]; then
            systemctl enable "$unit" >/dev/null 2>&1 || true
        else
            systemctl disable "$unit" >/dev/null 2>&1 || true
        fi
        [[ "$active" == 1 ]] && systemctl start "$unit" >/dev/null 2>&1 || true
    done < "$directory/units.state"
}

stop_legacy_services() {
    local unit
    for unit in pdg-health.timer pdg-rules-update.timer pdg-bot pdg-admin pdg-ios-profile-cleanup.timer \
                pdg-ios-profile.socket sing-box mosdns; do
        systemctl stop "$unit" >/dev/null 2>&1 || true
    done
}

restore_legacy_files() {
    local directory="$1"
    [[ -d "$directory/old" && ! -L "$directory/old" ]] || fail "migration backup is incomplete: $directory/old"
    for item in mosdns sing-box privdns-gateway pdg-bot pdg-admin; do
        case "$item" in
            mosdns) copy_if_present "$directory/old/mosdns" /etc/ ;;
            sing-box) copy_if_present "$directory/old/sing-box" /etc/ ;;
            privdns-gateway) copy_if_present "$directory/old/privdns-gateway" /etc/ ;;
            pdg-bot) copy_if_present "$directory/old/pdg-bot" /opt/ ;;
            pdg-admin) copy_if_present "$directory/old/pdg-admin" /opt/ ;;
        esac
    done
    if [[ -d "$directory/units" ]]; then
        cp -a -- "$directory/units/." /etc/systemd/system/
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
}

rollback() {
    local directory="$1"
    warn 'migration failed; stopping new services and restoring the old deployment'
    for unit in 5gpn-dns.service 5gpn-intercept.service mihomo.service; do
        systemctl stop "$unit" >/dev/null 2>&1 || true
    done
    restore_legacy_files "$directory" || warn 'legacy files could not be fully restored; backup retained at $directory'
    restore_state "$directory"
}

patch_legacy_clash_clients() {
    local file
    for file in "$OLD_BOT"/pdg-bot.py "$OLD_BOT"/pdg_service.py "$OLD_BOT"/checks.py; do
        [[ -f "$file" && ! -L "$file" ]] || continue
        sed -i 's#127\.0\.0\.1:9090#127.0.0.1:9091#g' "$file"
    done
}

read_dns_env() {
    local key="$1" file=/etc/5gpn/dns.env raw
    [[ -f "$file" && ! -L "$file" ]] || return 1
    raw="$(sed -n "s/^${key}=//p" "$file" | tail -1)"
    raw="${raw#\"}"; raw="${raw%\"}"
    printf '%s' "$raw"
}

apply_mihomo_legacy_bridge() {
    local config=/etc/5gpn/mihomo/config.yaml gateway candidate
    [[ -f "$config" && ! -L "$config" ]] || fail "mihomo config is missing: $config"
    gateway="$(read_dns_env DNS_GATEWAY_IP)"
    [[ "$gateway" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 'DNS_GATEWAY_IP is unavailable'
    candidate="$(mktemp /etc/5gpn/.config.yaml.legacy.XXXXXX)"
    if ! awk -v gateway="$gateway" '
        $0 == "proxy-providers: {}" {
            print "  - name: LEGACY-SINGBOX"
            print "    type: socks5"
            print "    server: 127.0.0.1"
            print "    port: 18081"
            print "    udp: true"
        }
        $0 == "proxy-groups:" {
            seen_groups=1
        }
        seen_groups && $0 ~ /proxies: \[DIRECT\]/ {
            sub(/proxies: \[DIRECT\]/, "proxies: [LEGACY-SINGBOX]")
            seen_groups=0
        }
        $0 == "sniffer:" {
            print "  - name: legacy-gms-5228"
            print "    type: tunnel"
            print "    listen: " gateway
            print "    port: 5228"
            print "    network: [tcp]"
            print "    target: mtalk.google.com:5228"
            print "  - name: legacy-gms-5229"
            print "    type: tunnel"
            print "    listen: " gateway
            print "    port: 5229"
            print "    network: [tcp]"
            print "    target: mtalk.google.com:5229"
            print "  - name: legacy-gms-5230"
            print "    type: tunnel"
            print "    listen: " gateway
            print "    port: 5230"
            print "    network: [tcp]"
            print "    target: mtalk.google.com:5230"
        }
        { print }
    ' "$config" > "$candidate"; then
        rm -f "$candidate"
        fail 'could not render mihomo legacy bridge'
    fi
    grep -Fq 'name: LEGACY-SINGBOX' "$candidate" || { rm -f "$candidate"; fail 'mihomo legacy proxy missing'; }
    grep -Fq 'proxies: [LEGACY-SINGBOX]' "$candidate" || { rm -f "$candidate"; fail 'mihomo terminal group was not redirected'; }
    /opt/5gpn/bin/mihomo -t -f "$candidate" -d /etc/5gpn/mihomo \
        >/tmp/5gpn-migration-mihomo-check.log 2>&1 \
        || { cat /tmp/5gpn-migration-mihomo-check.log >&2; rm -f "$candidate"; fail 'mihomo rejected the compatibility bridge'; }
    install -o root -g mihomo -m 0640 "$candidate" "$config"
    rm -f "$candidate"
}

main() {
    require_root
    require_cmds
    [[ -f "$OLD_SINGBOX" && -d "$OLD_MOSDNS" ]] || fail 'no existing PrivDNS Gateway deployment was found'
    [[ -f /opt/privdns-gateway/README.md || -f "$OLD_CONFIG_DIR/bot.env" ]] \
        || fail 'legacy ownership markers were not found'

    local stamp directory candidate old_dot
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    directory="$MIGRATION_ROOT/$stamp"
    install -d -m 0700 "$directory" "$directory/old" "$directory/units"
    capture_state "$directory"
    cp -a -- "$OLD_MOSDNS" "$directory/old/mosdns"
    cp -a -- "$(dirname "$OLD_SINGBOX")" "$directory/old/sing-box"
    cp -a -- "$OLD_CONFIG_DIR" "$directory/old/privdns-gateway"
    copy_if_present "$OLD_BOT" "$directory/old/"
    copy_if_present "$OLD_ADMIN" "$directory/old/"
    for unit in mosdns.service sing-box.service pdg-bot.service pdg-admin.service; do
        [[ -f "/etc/systemd/system/$unit" && ! -L "/etc/systemd/system/$unit" ]] \
            && cp -p -- "/etc/systemd/system/$unit" "$directory/units/$unit"
    done
    cp -p -- /etc/nftables.conf "$directory/old/nftables.conf" 2>/dev/null || true
    old_dot="$(cat "$OLD_BOT/dot-domain" 2>/dev/null || true)"
    printf 'legacy_dot_domain=%s\nlegacy_clash_port=%s\n' "$old_dot" "$LEGACY_CLASH_PORT" > "$directory/manifest"

    candidate="$directory/legacy-sing-box.json"
    convert_config "$OLD_SINGBOX" "$candidate"
    sing-box check -c "$candidate" >/dev/null 2>&1 \
        || fail 'sing-box rejected the compatibility candidate; no services were changed'

    log "backup captured at $directory"
    [[ -z "$old_dot" ]] || log "keep the same base domain so the new DoT name remains dot.${old_dot#dot.}"
    warn 'the next command runs the new 5gpn installer and may require certificate/DNS confirmation'

    stop_legacy_services
    trap 'rollback "$directory"' ERR INT TERM

    # Local source trees must not silently delegate this migration to an older
    # release. The release bundle still supplies the verified 5gpn artifacts.
    PDG_MIGRATION_BACKUP="$directory" PDG_LOCAL_INSTALL=1 \
        bash "$(dirname "$0")/../quick-install.sh"

    install -d -m 0700 /etc/sing-box
    install -o root -g root -m 0600 "$candidate" "$OLD_SINGBOX"
    patch_legacy_clash_clients
    apply_mihomo_legacy_bridge
    systemctl daemon-reload
    systemctl start sing-box.service
    systemctl is-active --quiet sing-box.service || fail 'legacy sing-box egress did not start'
    systemctl restart mihomo.service
    systemctl is-active --quiet mihomo.service || fail 'mihomo did not restart with the legacy bridge'
    systemctl stop mosdns.service >/dev/null 2>&1 || true
    systemctl disable mosdns.service >/dev/null 2>&1 || true
    trap - ERR INT TERM
    log 'migration completed; 5gpn owns DoT and gateway ingress, legacy sing-box owns compatibility egress'
    log "old state is retained at $directory"
}

if [[ "${1:-}" == --convert ]]; then
    [[ $# == 3 ]] || fail 'usage: migrate-privdns-gateway.sh --convert INPUT OUTPUT'
    convert_config "$2" "$3"
else
    [[ $# == 0 ]] || fail 'usage: migrate-privdns-gateway.sh [--convert INPUT OUTPUT]'
    main
fi
