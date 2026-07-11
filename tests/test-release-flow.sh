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
grep -q -- "refs/tags/\*:refs/tags/\*" "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must explicitly synchronize and prune rewritten release tags"
grep -q "fetch --unshallow origin main '+refs/tags/\*:refs/tags/\*'" "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must force tag synchronization while unshallowing old installs"

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

# 模拟旧 v2.4.10 设备：远端已删除旧 tag，本地仍残留；同步后必须删掉旧 tag。
git init -q --bare "$work/origin.git"
git -C "$work/repo" remote add origin "$work/origin.git"
git -C "$work/repo" push -q origin HEAD:refs/heads/main v2.0.0-rc.1
git -C "$work/repo" tag -d v2.0.0 >/dev/null
git -C "$work/repo" tag v2.4.10
fetcher=$(awk '/^pdg_fetch_release_tags\(\)/,/^}/' "$ROOT/deploy/bot/pdg.sh")
REPO_DIR="$work/repo" bash -c "$fetcher; pdg_fetch_release_tags"
! git -C "$work/repo" rev-parse -q --verify refs/tags/v2.4.10 >/dev/null \
  || fail "deleted legacy v2.4.10 tag must be pruned locally"
selected=$(REPO_DIR="$work/repo" bash -c "$selector; pdg_latest_release_tag")
[[ "$selected" == "v2.0.0-rc.1" ]] \
  || fail "migrated client must stay on rc.1, got $selected"

# 旧安装通常是浅克隆；已移动的 RC tag 不能让第二阶段 unshallow 失败。
git clone -q --depth 1 --branch main "file://$work/origin.git" "$work/shallow"
git -C "$work/shallow" tag -f v2.0.0-rc.1 HEAD >/dev/null
REPO_DIR="$work/shallow" bash -c "$fetcher; pdg_fetch_release_tags"
[[ "$(git -C "$work/shallow" rev-parse --is-shallow-repository)" == "false" ]] \
  || fail "legacy shallow install must be unshallowed"
[[ "$(git -C "$work/shallow" rev-parse v2.0.0-rc.1^{commit})" == "$(git -C "$work/repo" rev-parse v2.0.0-rc.1^{commit})" ]] \
  || fail "moved rc tag must be force-synchronized while unshallowing"

grep -q '_fetch_release_tags' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must fetch release tags through a helper"
grep -q '_release_tags' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must exclude migration bridge tags"
grep -q -- "--exclude.*migrate" "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot current version must not display the migration bridge tag"
grep -q -- "--exclude.*migrate" "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg status must not display the migration bridge tag"
grep -q -- "--exclude.*migrate" "$ROOT/deploy/bot/pdg_service.py" \
  || fail "PWA project status must not display the migration bridge tag"
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
