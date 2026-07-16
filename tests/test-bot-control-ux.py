#!/usr/bin/env python3
"""Bot 出口预览、删除确认和输入重试回归。"""
import copy
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "deploy/bot/pdg-bot.py"

spec = importlib.util.spec_from_file_location("pdg_bot_control_ux", BOT)
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)
from pdg_control import delete_outbound

cfg = {
    "outbounds": [
        {"type": "direct", "tag": "jp"},
        {"type": "shadowsocks", "tag": "hk", "server": "hk.example.com", "server_port": 443},
        {"type": "shadowsocks", "tag": "tw", "server": "tw.example.com", "server_port": 443},
        {"type": "urltest", "tag": "auto", "outbounds": ["hk", "tw"]},
    ],
    "route": {
        "final": "hk",
        "rules": [
            {"inbound": ["tg-proxy"], "outbound": "hk"},
            {"domain_suffix": ["example.com"], "outbound": "hk"},
        ],
    },
}

sent = []
edited = []
bot.load = lambda: copy.deepcopy(cfg)
bot.send = lambda chat, text, kb=None: sent.append((chat, text, kb))
bot.send_plain = lambda chat, text: sent.append((chat, text, None))
bot.edit = lambda chat, mid, text, kb=None: edited.append((chat, mid, text, kb))
bot.status_text = lambda: "status"

# 无效节点不退出输入态，用户可直接修正重试。
bot.state[1] = "add_exit"
bot.handle_text(1, "not-a-link")
assert bot.state[1] == "add_exit"
assert "仍在当前操作" in sent[-1][1]

# 有效节点只生成脱敏预览，不立即写配置。
sent.clear()
bot.handle_text(1, "socks5://user:pass@node.example.com:1080#new-exit")
assert 1 not in bot.state
assert bot.pending_outbound[1]["tag"] == "new-exit"
preview = sent[-1][1]
assert "确认添加出口" in preview and "nod***.com:1080" in preview
assert "user" not in preview and "pass" not in preview
assert sent[-1][2]["inline_keyboard"][0][0]["callback_data"] == "addxok"

# 确认后才调用配置事务。
applied = []
def fake_apply(modify):
    value = copy.deepcopy(cfg)
    modify(value)
    applied.append(value)
    return True, ""
def fake_add(outbound):
    def modify(value):
        value["outbounds"] = [item for item in value["outbounds"] if item.get("tag") != outbound["tag"]]
        value["outbounds"].append(outbound)
    fake_apply(modify)
bot._gateway.add_outbound = fake_add
bot._gateway.remove_exit = lambda tag: fake_apply(lambda value: delete_outbound(value, tag))
bot.handle_cb(1, 9, "addxok")
assert 1 not in bot.pending_outbound
assert applied and any(item.get("tag") == "new-exit" for item in applied[-1]["outbounds"])

# 第一次点删除只展示影响，第二次确认才修改。
applied.clear(); edited.clear()
bot.handle_cb(2, 10, "delx:hk")
assert not applied
assert "确认删除出口" in edited[-1][2]
assert "分流引用" in edited[-1][2] and "策略组" in edited[-1][2]
assert edited[-1][3]["inline_keyboard"][0][0]["callback_data"] == "delxok:hk"

bot.handle_cb(2, 10, "delxok:hk")
assert applied
changed = applied[-1]
assert all(item.get("tag") != "hk" for item in changed["outbounds"])
assert changed["route"]["final"] == "jp"
assert all(rule.get("outbound") == "jp" for rule in changed["route"]["rules"])

# 返回菜单会清理未确认出口，避免旧确认按钮误操作。
bot.pending_outbound[3] = {"tag": "stale"}
bot.state[3] = "add_exit"
bot.handle_cb(3, 11, "menu")
assert 3 not in bot.pending_outbound and 3 not in bot.state

# 批量域名和 CIDR 使用共享服务，最后一个参数作为目标出口。
rule_calls = []
bot._gateway.set_rules = lambda values, target: rule_calls.append(("domain", values, target)) or {
    "count": len(values), "target": target,
}
bot._gateway.set_cidrs = lambda values, target: rule_calls.append(("cidr", values, target)) or {
    "count": len(values), "target": target,
}
bot.state[4] = "add_rule"
bot.handle_text(4, "one.example\ntwo.example hk")
assert rule_calls[-1] == ("domain", ["one.example", "two.example"], "hk")
bot.state[5] = "add_rule"
bot.handle_text(5, "10.0.0.0/8 jp")
assert rule_calls[-1] == ("cidr", ["10.0.0.0/8"], "jp")

print("bot-control-ux regression OK")
