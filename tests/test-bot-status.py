#!/usr/bin/env python3
"""Telegram 状态与出口信息分区、换行和策略组术语回归。"""
import copy
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pdg_bot_status", ROOT / "deploy/bot/pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

config = {
    "outbounds": [
        {"type": "direct", "tag": "jp"},
        {"type": "shadowsocks", "tag": "hk&vip", "server": "hk.example.com", "server_port": 443},
        {"type": "trojan", "tag": "tokyo", "server": "jp.example.com", "server_port": 443},
        {"type": "urltest", "tag": "负载均衡", "outbounds": ["jp", "tokyo"]},
        {"type": "selector", "tag": "channel", "outbounds": ["hk&vip", "tokyo"], "default": "tokyo"},
    ],
    "route": {
        "final": "负载均衡",
        "rules": [{"domain_suffix": ["example.com"], "outbound": "channel"}],
    },
}

bot.load = lambda: copy.deepcopy(config)
bot.sh = lambda command: type("Result", (), {"stdout": "active\nactive\nactive\nactive\n"})()
bot._dot_host = lambda: "dot.example.com"
bot._server_ip = lambda: "203.0.113.10"
bot._rs_meta = lambda: {"rs_one": {}, "rs_two": {}}

status = bot.status_text()
assert "📤 <b>具体出口（3）</b>" in status
assert "• <code>jp</code>\n• <code>hk&amp;vip</code>\n• <code>tokyo</code>" in status
assert "🔀 <b>策略组（2）</b>" in status
assert "<b>负载均衡</b> · 自动优选\n  ↳ <code>jp</code>\n  ↳ <code>tokyo</code>" in status
assert "<b>channel</b> · 固定：tokyo\n  ↳ <code>hk&amp;vip</code>\n  ↳ <code>tokyo</code>" in status
assert "故障组" not in status
assert "🎯 <b>默认策略</b>\n• 负载均衡（其余流量）" in status
assert "📚 <b>规则集</b>：2 个" in status

exits = bot.exits_text()
assert "📤 <b>具体出口（3）</b>" in exits
assert "<b>hk&amp;vip</b>\n  <code>shadowsocks</code>" in exits
assert "🔀 <b>策略组（2）</b>" in exits
assert "故障组" not in exits

print("bot-status regression OK")
