"""Surge 风格规则解析。

两种来源:
  - rules.conf      每行带策略列: `DOMAIN-SUFFIX,openai.com,AI`
  - 远程 RULE-SET   每行【不带】策略列: `DOMAIN-SUFFIX,openai.com` (策略来自引用)
"""

from __future__ import annotations

from dataclasses import dataclass

from ..model import RULE_TYPES, Rule, RuleSetRef


@dataclass
class ParseResult:
    rules: list[Rule]
    rulesets: list[RuleSetRef]
    final_policy: str | None
    unsupported: dict[str, int]            # 规则类型 -> 跳过次数
    entries: list[Rule | RuleSetRef]       # 保留原始顺序 (首个命中生效)


def _clean(line: str) -> str:
    # 去掉 # 与 // 注释, 去空白
    line = line.split("#", 1)[0]
    line = line.split("//", 1)[0]
    return line.strip()


def parse_rules_conf(text: str, source: str = "local") -> ParseResult:
    """解析 rules.conf (每行带策略列, 含 RULE-SET / FINAL)。"""
    rules: list[Rule] = []
    rulesets: list[RuleSetRef] = []
    entries: list[Rule | RuleSetRef] = []
    final_policy: str | None = None
    unsupported: dict[str, int] = {}

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _clean(raw)
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        rtype = parts[0].upper()

        if rtype == "FINAL":
            if len(parts) < 2:
                raise ValueError(f"rules.conf:{lineno} FINAL 缺少策略")
            final_policy = parts[1]
        elif rtype == "RULE-SET":
            if len(parts) < 3:
                raise ValueError(f"rules.conf:{lineno} RULE-SET 需要 url 与策略")
            ref = RuleSetRef(url=parts[1], policy=parts[2])
            rulesets.append(ref)
            entries.append(ref)
        elif rtype in RULE_TYPES:
            if len(parts) < 3:
                raise ValueError(f"rules.conf:{lineno} {rtype} 缺少策略列")
            rule = Rule(type=rtype, value=parts[1], policy=parts[2], source=source)
            rules.append(rule)
            entries.append(rule)
        else:
            unsupported[rtype] = unsupported.get(rtype, 0) + 1

    return ParseResult(rules=rules, rulesets=rulesets, final_policy=final_policy,
                       unsupported=unsupported, entries=entries)


def parse_ruleset_list(text: str, policy: str, source: str) -> ParseResult:
    """解析远程 Surge .list (每行不带策略列, 策略由引用提供)。"""
    rules: list[Rule] = []
    unsupported: dict[str, int] = {}

    for raw in text.splitlines():
        line = _clean(raw)
        if not line or line.lower().startswith("payload:"):
            continue
        parts = [p.strip() for p in line.split(",")]
        rtype = parts[0].upper()
        if rtype in RULE_TYPES and len(parts) >= 2:
            rules.append(Rule(type=rtype, value=parts[1], policy=policy, source=source))
        else:
            unsupported[rtype] = unsupported.get(rtype, 0) + 1

    return ParseResult(rules=rules, rulesets=[], final_policy=None,
                       unsupported=unsupported, entries=list(rules))
