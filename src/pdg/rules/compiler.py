"""规则编译器: 把单一规则源解析、展开 RULE-SET、绑定策略/出口/DNS 行为,
得到一张有序的 CompiledTable, 供 dnsdist / sing-box 生成器与 `pdg test` 使用。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..model import CompiledRule, Config, Rule, RuleSetRef
from . import ruleset
from .parser import parse_rules_conf


@dataclass
class CompiledTable:
    rules: list[CompiledRule]          # 有序, 首个命中生效
    final_policy: str
    final_outbound: str
    final_dns_mode: str
    config: Config
    warnings: list[str] = field(default_factory=list)

    # ---- 供 `pdg test` 用 ----
    def match(self, domain: str) -> CompiledRule:
        domain = domain.rstrip(".").lower()
        for cr in self.rules:
            if _rule_matches(cr.rule, domain):
                return cr
        return CompiledRule(
            rule=Rule(type="FINAL", value="*", policy=self.final_policy, source="local"),
            policy=self.final_policy,
            outbound=self.final_outbound,
            dns_mode=self.final_dns_mode,
        )

    # ---- 供 sing-box 生成器用: 出口 -> 各类匹配器 ----
    def matchers_by_outbound(self) -> dict[str, dict[str, list[str]]]:
        out: dict[str, dict[str, list[str]]] = {}
        order: list[str] = []
        for cr in self.rules:
            bucket = out.setdefault(cr.outbound, {
                "domain": [], "domain_suffix": [],
                "domain_keyword": [], "domain_regex": [],
            })
            if cr.outbound not in order:
                order.append(cr.outbound)
            key = {
                "DOMAIN": "domain",
                "DOMAIN-SUFFIX": "domain_suffix",
                "DOMAIN-KEYWORD": "domain_keyword",
                "DOMAIN-REGEX": "domain_regex",
            }[cr.rule.type]
            if cr.rule.value not in bucket[key]:
                bucket[key].append(cr.rule.value)
        # 按出口首次出现顺序返回
        return {tag: out[tag] for tag in order}

    # ---- 供 dnsdist 生成器用: 按 dns_mode 分组 ----
    def matchers_by_dns_mode(self) -> dict[str, dict[str, list[str]]]:
        out: dict[str, dict[str, list[str]]] = {
            m: {"domain": [], "domain_suffix": [],
                "domain_keyword": [], "domain_regex": []}
            for m in ("spoof", "direct", "block")
        }
        key_map = {
            "DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix",
            "DOMAIN-KEYWORD": "domain_keyword", "DOMAIN-REGEX": "domain_regex",
        }
        for cr in self.rules:
            bucket = out[cr.dns_mode]
            key = key_map[cr.rule.type]
            if cr.rule.value not in bucket[key]:
                bucket[key].append(cr.rule.value)
        return out


def _rule_matches(rule: Rule, domain: str) -> bool:
    val = rule.value.lower()
    if rule.type == "DOMAIN":
        return domain == val
    if rule.type == "DOMAIN-SUFFIX":
        return domain == val or domain.endswith("." + val)
    if rule.type == "DOMAIN-KEYWORD":
        return val in domain
    if rule.type == "DOMAIN-REGEX":
        try:
            return re.search(rule.value, domain) is not None
        except re.error:
            return False
    return False


def compile_rules(config: Config, rules_text: str, cache_dir: Path, *,
                  force_download: bool = False,
                  allow_download: bool = True) -> CompiledTable:
    """主入口: 文本规则 → CompiledTable, 并做完整性校验。"""
    parsed = parse_rules_conf(rules_text)
    warnings: list[str] = []

    if parsed.unsupported:
        for rtype, n in sorted(parsed.unsupported.items()):
            warnings.append(f"跳过 {n} 条暂不支持的规则类型 {rtype} (V1 仅支持域名类规则)")

    if not parsed.final_policy:
        raise ValueError("rules.conf 缺少 FINAL 兜底策略")

    # 展开 entries (保留顺序), RULE-SET 就地替换为其域名规则
    expanded: list[Rule] = []
    for entry in parsed.entries:
        if isinstance(entry, RuleSetRef):
            rs = ruleset.load(cache_dir, entry.url, entry.policy,
                              force=force_download, allow_download=allow_download)
            expanded.extend(rs.rules)
            if rs.unsupported:
                total = sum(rs.unsupported.values())
                warnings.append(f"RULE-SET {entry.url}: 跳过 {total} 条非域名规则")
        else:
            expanded.append(entry)

    compiled = [_bind(rule, config) for rule in expanded]

    final_outbound = _resolve_outbound(parsed.final_policy, config)
    final_mode = config.outbounds[final_outbound].dns_mode

    return CompiledTable(
        rules=compiled,
        final_policy=parsed.final_policy,
        final_outbound=final_outbound,
        final_dns_mode=final_mode,
        config=config,
        warnings=warnings,
    )


def _bind(rule: Rule, config: Config) -> CompiledRule:
    outbound = _resolve_outbound(rule.policy, config)
    return CompiledRule(rule=rule, policy=rule.policy, outbound=outbound,
                        dns_mode=config.outbounds[outbound].dns_mode)


def _resolve_outbound(policy: str, config: Config) -> str:
    if policy not in config.policies:
        raise ValueError(f"策略 '{policy}' 未在 policies.conf 中映射出口")
    tag = config.policies[policy]
    if tag not in config.outbounds:
        raise ValueError(f"策略 '{policy}' 指向未知出口 '{tag}' (检查 pdg.conf [outbounds.*])")
    return tag
