#!/usr/bin/env python3
"""用户手动域名规则始终优先于规则集，系统规则仍保持最前。"""
import copy
import importlib.util
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pdg_bot_rule_priority", ROOT / "deploy/bot/pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

config = {
    "outbounds": [
        {"type": "direct", "tag": "jp"},
        {"type": "shadowsocks", "tag": "hk", "server": "hk.example", "server_port": 443},
    ],
    "route": {
        "rules": [
            {"inbound": ["in-gms-5228"], "outbound": "jp"},
            {"action": "reject", "ip_cidr": ["203.0.113.1/32"]},
            {"ip_cidr": ["10.0.0.0/8"], "outbound": "hk"},
            {"rule_set": "rs_media", "outbound": "hk"},
            {"domain_suffix": ["manual.example"], "outbound": "hk"},
        ],
        "rule_set": [{"tag": "rs_media"}],
        "final": "jp",
    },
}

applied = []
def fake_apply(modify):
    modify(config)
    applied.append(copy.deepcopy(config))
    return True, ""

tempdir = tempfile.TemporaryDirectory()
bot.RS_DIR = tempdir.name
bot.load = lambda: config
bot.apply_sb = fake_apply
bot._gateway.control.load = lambda: config
bot._gateway.control.apply = fake_apply
bot._fetch_bytes = lambda url: b"DOMAIN-SUFFIX,duplicate.example\n"
bot._build_source = lambda url, path: (1, False)
bot._rs_meta = lambda: {}
bot._save_rs_meta = lambda value: None

ok, message = bot.add_ruleset("https://rules.example/new.list", "hk", "新增规则集")
assert ok, message
rules = config["route"]["rules"]
assert rules[0].get("inbound") and rules[1].get("action") == "reject"
manual_index = next(index for index, rule in enumerate(rules) if rule.get("domain_suffix"))
ip_index = next(index for index, rule in enumerate(rules) if rule.get("ip_cidr"))
assert ip_index < manual_index
assert all(index > manual_index for index, rule in enumerate(rules) if rule.get("rule_set"))

ruleset_index = next(index for index, rule in enumerate(rules) if rule.get("rule_set") == "rs_media")
ok, message = bot.reassign_rule(ruleset_index, "jp")
assert ok, message
rules = config["route"]["rules"]
manual_index = next(index for index, rule in enumerate(rules) if rule.get("domain_suffix"))
ip_index = next(index for index, rule in enumerate(rules) if rule.get("ip_cidr"))
assert ip_index < manual_index
assert all(index > manual_index for index, rule in enumerate(rules) if rule.get("rule_set"))

tempdir.cleanup()
print("rule-priority regression OK")
