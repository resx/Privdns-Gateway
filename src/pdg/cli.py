"""pdg 命令行入口。

  pdg status                         查看配置与产物
  pdg doctor                         体检 (服务/端口/出口/分流)
  pdg compile [--no-download]        编译生成配置 (不 reload)
  pdg reload                         编译 + 校验 + reload 服务 (失败回滚)
  pdg update-rules [--force]         刷新远程 RULE-SET 后 reload
  pdg rollback                       回滚到上一次产物
  pdg test <domain>                  查某域名命中的规则/策略/出口/DNS 行为
  pdg ruleset list                   列出 RULE-SET 及缓存状态
  pdg ruleset refresh <name|url>     刷新指定 RULE-SET 缓存
  pdg rule add <TYPE> <value> <pol>  追加一条规则到 rules.conf
  pdg rule del <value>               删除匹配该域名的规则
  pdg rule move <value> <policy>     改变匹配该域名规则的策略
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import Paths, load_config, resolve_paths
from .model import RULE_TYPES
from .rules import ruleset
from .rules.parser import parse_rules_conf
from . import services


def _load():
    paths = resolve_paths()
    config = load_config(paths)
    return paths, config


def _print_checks(checks) -> bool:
    ok = True
    for c in checks:
        print(c.render())
        if c.ok is False:
            ok = False
    return ok


# ── 编译/应用流程 ───────────────────────────────────────────
def _apply(paths: Paths, config, *, do_reload: bool,
           force_download: bool, allow_download: bool) -> int:
    table = services.build_table(config, paths,
                                 force_download=force_download,
                                 allow_download=allow_download)
    for w in table.warnings:
        print(f"  ! {w}")
    texts = services.render_all(table, config)
    targets = services.write_outputs(paths, texts)
    print(f"已生成 {len(table.rules)} 条规则 →")
    for label, path in targets.items():
        print(f"  {label:<9} {path}")

    print("校验:")
    vchecks = services.validate(paths)
    if not _print_checks(vchecks):
        print("校验失败 → 回滚")
        _print_checks(services.rollback(paths))
        return 1

    if do_reload:
        print("reload:")
        if not _print_checks(services.reload_services(paths)):
            return 1
    return 0


# ── 子命令 ──────────────────────────────────────────────────
def cmd_status(args) -> int:
    paths, config = _load()
    for line in services.status(config, paths):
        print(line)
    return 0


def cmd_doctor(args) -> int:
    paths, config = _load()
    print("doctor:")
    return 0 if _print_checks(services.doctor(config, paths)) else 1


def cmd_compile(args) -> int:
    paths, config = _load()
    return _apply(paths, config, do_reload=False,
                  force_download=False, allow_download=not args.no_download)


def cmd_reload(args) -> int:
    paths, config = _load()
    return _apply(paths, config, do_reload=True,
                  force_download=False, allow_download=True)


def cmd_update_rules(args) -> int:
    paths, config = _load()
    return _apply(paths, config, do_reload=True,
                  force_download=args.force, allow_download=True)


def cmd_rollback(args) -> int:
    paths = resolve_paths()
    _print_checks(services.rollback(paths))
    return 0


def cmd_test(args) -> int:
    paths, config = _load()
    table = services.build_table(config, paths, allow_download=False)
    cr = table.match(args.domain)
    if cr.rule.type == "FINAL":
        matched = f"FINAL,{cr.policy}"
    else:
        matched = f"{cr.rule.type},{cr.rule.value},{cr.policy}"
    answer = {
        "spoof": f"{config.jp_internal_ip}  (返回 JP 唯一内网 IP)",
        "direct": "真实 IP  (手机直连, 不经 JP)",
        "block": "NXDOMAIN",
    }[cr.dns_mode]
    print(f"Domain   : {args.domain}")
    print(f"Matched  : {matched}")
    print(f"Policy   : {cr.policy}")
    print(f"Outbound : {cr.outbound}")
    print(f"DNS      : {answer}")
    print(f"Mode     : private-dns + sing-box sniff ({cr.dns_mode})")
    return 0


def cmd_ruleset(args) -> int:
    paths, config = _load()
    text = paths.rules_conf.read_text(encoding="utf-8")
    refs = parse_rules_conf(text).rulesets
    if args.action == "list":
        if not refs:
            print("(rules.conf 中没有 RULE-SET)")
            return 0
        for ref in refs:
            cp = ruleset.cache_path(paths.cache_dir, ref.url)
            state = "cached" if cp.exists() else "未缓存"
            print(f"  [{ref.policy}] {ref.url}  ({state})")
        return 0
    if args.action == "refresh":
        sel = args.name
        hit = [r for r in refs if sel in r.url or sel == r.policy]
        if not hit:
            print(f"未找到匹配 '{sel}' 的 RULE-SET")
            return 1
        for ref in hit:
            try:
                dest = ruleset.refresh(paths.cache_dir, ref.url)
                print(f"  ✓ 刷新 {ref.policy}: {dest}")
            except Exception as exc:  # noqa: BLE001
                print(f"  ✗ 刷新 {ref.url} 失败: {exc}")
                return 1
        return 0
    return 1


def cmd_rule(args) -> int:
    paths = resolve_paths()
    rc = paths.rules_conf
    lines = rc.read_text(encoding="utf-8").splitlines()

    if args.action == "add":
        rtype = args.type.upper()
        if rtype not in RULE_TYPES:
            print(f"不支持的规则类型: {rtype} (可用: {', '.join(RULE_TYPES)})")
            return 1
        new = f"{rtype},{args.value},{args.policy}"
        if any(l.strip() == new for l in lines):
            print(f"已存在: {new}")
            return 0
        idx = next((i for i, l in enumerate(lines)
                    if l.strip().upper().startswith("FINAL,")), len(lines))
        lines.insert(idx, new)
        rc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"已添加: {new}  (运行 `pdg reload` 生效)")
        return 0

    if args.action in ("del", "move"):
        val = args.value.lower()
        changed = 0
        out = []
        for l in lines:
            s = l.split("#", 1)[0].strip()
            parts = [p.strip() for p in s.split(",")]
            is_target = (len(parts) >= 2 and parts[0].upper() in RULE_TYPES
                         and parts[1].lower() == val)
            if not is_target:
                out.append(l)
                continue
            if args.action == "del":
                changed += 1  # 丢弃该行
            else:  # move
                out.append(f"{parts[0]},{parts[1]},{args.policy}")
                changed += 1
        if changed == 0:
            print(f"未找到匹配 '{args.value}' 的规则")
            return 1
        rc.write_text("\n".join(out) + "\n", encoding="utf-8")
        verb = "删除" if args.action == "del" else "改策略"
        print(f"已{verb} {changed} 条匹配 '{args.value}' 的规则  (运行 `pdg reload` 生效)")
        return 0
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pdg", description="PrivDNS Gateway 控制面")
    p.add_argument("--version", action="version", version=f"pdg {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="查看配置与产物").set_defaults(func=cmd_status)
    sub.add_parser("doctor", help="体检").set_defaults(func=cmd_doctor)

    c = sub.add_parser("compile", help="编译生成配置 (不 reload)")
    c.add_argument("--no-download", action="store_true", help="不下载远程 RULE-SET, 只用缓存")
    c.set_defaults(func=cmd_compile)

    sub.add_parser("reload", help="编译 + 校验 + reload").set_defaults(func=cmd_reload)
    sub.add_parser("rollback", help="回滚到上次产物").set_defaults(func=cmd_rollback)

    u = sub.add_parser("update-rules", help="刷新远程 RULE-SET 后 reload")
    u.add_argument("--force", action="store_true", help="强制重新下载")
    u.set_defaults(func=cmd_update_rules)

    t = sub.add_parser("test", help="测试某域名分流")
    t.add_argument("domain")
    t.set_defaults(func=cmd_test)

    rs = sub.add_parser("ruleset", help="远程 RULE-SET 管理")
    rs_sub = rs.add_subparsers(dest="action", required=True)
    rs_sub.add_parser("list", help="列出 RULE-SET")
    rref = rs_sub.add_parser("refresh", help="刷新指定 RULE-SET")
    rref.add_argument("name", help="策略名或 url 子串")
    rs.set_defaults(func=cmd_ruleset)

    r = sub.add_parser("rule", help="编辑 rules.conf")
    r_sub = r.add_subparsers(dest="action", required=True)
    radd = r_sub.add_parser("add", help="添加规则")
    radd.add_argument("type"); radd.add_argument("value"); radd.add_argument("policy")
    rdel = r_sub.add_parser("del", help="删除规则")
    rdel.add_argument("value")
    rmove = r_sub.add_parser("move", help="改变规则策略")
    rmove.add_argument("value"); rmove.add_argument("policy")
    r.set_defaults(func=cmd_rule)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except (ValueError, RuntimeError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
