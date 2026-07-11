#!/usr/bin/env bash
# Regression checks for the tag-only release/update path.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail(){ echo "[FAIL] $*" >&2; exit 1; }

grep -q 'pdg_checkout_latest_tag' "$ROOT/install.sh" \
  || fail "install.sh bootstrap must checkout the latest v* tag"
grep -q "alpha|beta|rc" "$ROOT/install.sh" \
  || fail "install.sh must only select canonical SemVer prerelease tags"
grep -q -- '--prune-tags' "$ROOT/install.sh" \
  || fail "install.sh must prune rewritten release tags"
! grep -q 'git clone -q --depth 1 "$REPO_URL"' "$ROOT/install.sh" \
  || fail "install.sh must not seed /opt/privdns-gateway as a shallow main clone"
grep -q 'git -C "$dir" checkout -q "$tag"' "$ROOT/install.sh" \
  || fail "install.sh must checkout the selected release tag before re-exec"

grep -q 'pdg_fetch_release_tags' "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must share a release-tag fetch helper"
grep -q 'pdg_latest_release_tag' "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must exclude migration bridge tags from release selection"
grep -q -- '--prune-tags' "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must prune rewritten release tags after migration"
grep -q 'fetch -q --unshallow --tags origin main' "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must unshallow old installs before comparing tags"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git init -q "$work/repo"
git -C "$work/repo" -c user.name=test -c user.email=test@example.invalid commit -q --allow-empty -m init
for tag in v1.1.16 v2.0.0-beta.12 v2.0.0-rc.1 v2.4.11-migrate-to-v2.0.0-rc.1; do
  git -C "$work/repo" tag "$tag"
done
selector=$(awk '/^pdg_latest_release_tag\(\)/,/^}/' "$ROOT/deploy/bot/pdg.sh")
selected=$(REPO_DIR="$work/repo" bash -c "$selector; pdg_latest_release_tag")
[[ "$selected" == "v2.0.0-rc.1" ]] \
  || fail "canonical selector must choose rc.1 and ignore migration bridge, got $selected"
git -C "$work/repo" tag v2.0.0
selected=$(REPO_DIR="$work/repo" bash -c "$selector; pdg_latest_release_tag")
[[ "$selected" == "v2.0.0" ]] \
  || fail "stable release must sort above prereleases, got $selected"

grep -q '_fetch_release_tags' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must fetch release tags through a helper"
grep -q '_release_tags' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must exclude migration bridge tags"
grep -q -- '--prune-tags' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must prune rewritten release tags"
grep -q 'mb.returncode == 0' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must distinguish merge-base success"
grep -q 'mb.returncode == 1' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must distinguish not-ancestor from git errors"
grep -q 'merge-base 判断失败' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must report merge-base git errors instead of treating them as up-to-date"

! grep -q '1\.12\.9' "$ROOT/docs/INSTALL.md" \
  || fail "INSTALL.md must not mention stale sing-box 1.12.9"
