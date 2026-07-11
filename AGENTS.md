# Repository Guidelines

## Project Structure & Module Organization

`install.sh` provisions the gateway. DNS and traffic templates are `deploy/mosdns/config.yaml` and `deploy/singbox/config.json.tmpl`. `deploy/bot/` contains the Telegram UI, shared control/services, lifecycle CLI, and diagnostics. `deploy/admin/` holds the HTTPS API, unit, and built PWA; Vue/TypeScript source is in `web/`. Shell helpers are in `lib/`, tests in `tests/`, and operator docs are in `docs/`. Avoid `docs/images/` and `lib/versions.sh` unless changing assets or pinned binaries.

## Core Business Workflows

1. Phones send DoT queries to mosdns on port 853. It checks the carrier CIDR, resolves direct domains through configured upstreams, and rewrites proxy-domain A records to the gateway while suppressing AAAA/HTTPS responses.
2. Rewritten traffic reaches sing-box on ports 80/443. SNI or Host selects a direct or node outbound; GMS ports 5228–5230 use `gms-mtalk`. nftables restricts these entries to the internal CIDR.
3. Telegram and the PWA manage subscriptions, exits, and routing through shared services; sing-box writes follow lock → validate → atomic replace → restart → rollback. `pdg` handles lifecycle. HTTPS 9443 is CIDR-restricted.

## Build and Development Commands

There is no compile step. Run CI checks:

```bash
python3 -m py_compile deploy/{bot,admin}/*.py tests/*.py
bash -n install.sh uninstall.sh deploy/bot/*.sh deploy/cert/*.sh lib/*.sh
shellcheck --severity=warning -e SC1091 install.sh deploy/bot/*.sh lib/*.sh tests/*.sh
npm ci --prefix web && npm run build --prefix web
bash tests/functional-test.sh
```

Run the affected `tests/test-*.py` or `tests/test-*.sh` files for each change. Installation testing requires a disposable Debian 12+ or Ubuntu 22+ host with root access.

## Coding Style & Naming Conventions

Use four spaces for Python and two for shell. Prefer Bash with `set -euo pipefail` where safe. Use `snake_case` for Python, `UPPER_CASE` for constants, and kebab-case scripts. TypeScript is strict; keep Vue components mobile-first. Validate PWA changes at 320px, 390px, 768px, and desktop widths; dynamic names must wrap or truncate inside their containers, and mobile edit forms must remain within the visual viewport. The policy master-detail and expandable rule interactions adapt MIT-licensed MetaCubeXD and Zashboard resources; preserve `web/public/third-party/` licenses and attribution when changing them.

## Configuration & Environment

Noninteractive installs use `PDG_NONINTERACTIVE=1`, server/CIDR/domain values, and optional Bot credentials. `PDG_ADMIN_TOKEN` may preseed the 9443 API token; otherwise installation generates it. Never commit tokens, node credentials, keys, or generated configs. Keep sing-box at 1.12.x; 1.13 removes required destination override behavior.

## Release Versioning

Project releases use SemVer tags. During an unfinished major release, keep the base version fixed and advance `-alpha.N`, `-beta.N`, then `-rc.N`; only tag `vMAJOR.MINOR.PATCH` after stability acceptance. Published tags are immutable: never force-move or reuse a tag, and increment the prerelease or patch number for every follow-up fix. Patch releases contain compatible fixes, minor releases add backward-compatible functionality, and major releases may break compatibility. Do not use version numbers to count features or same-day iterations.

## Architecture Overview

mosdns is the policy engine, sing-box the data plane, `pdg_service.py` the management layer, Telegram/PWA the control surfaces, and `pdg` the lifecycle layer.

## Agent-Specific Instructions

Keep changes minimal. Never write sing-box configuration outside `pdg_control.py` or expose port 9090. Rebuild `deploy/admin/web/` after `web/` changes. Test migrations, API authentication, and routing; preserve unrelated edits.
