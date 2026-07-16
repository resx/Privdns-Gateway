#!/usr/bin/env python3
"""Telegram transport regression: per-thread poll/API keep-alive sockets."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pdg_bot_transport", ROOT / "deploy/bot" / "pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)


class FakeSocket:
    def settimeout(self, value):
        self.timeout = value

    def setsockopt(self, *args):
        pass


class FakeResponse:
    def read(self):
        return b'{"ok": true, "result": []}'


class FakeConnection:
    fail_next = False

    def __init__(self, host, timeout):
        self.host = host
        self.timeout = timeout
        self.sock = FakeSocket()
        self.closed = False

    def request(self, method, path, data, headers):
        if FakeConnection.fail_next:
            FakeConnection.fail_next = False
            raise OSError("stale socket")

    def getresponse(self):
        return FakeResponse()

    def close(self):
        self.closed = True


now = [100.0]
bot.http.client.HTTPSConnection = FakeConnection
bot.time.monotonic = lambda: now[0]
bot._TG_LOCAL = type("Local", (), {})()

assert bot.post("getUpdates", {"timeout": 25})["ok"]
poll_conn = bot._TG_LOCAL.poll_conn
assert bot.post("sendMessage", {"chat_id": 1, "text": "one"})["ok"]
api_conn = bot._TG_LOCAL.api_conn
assert poll_conn is not api_conn

now[0] += 10
assert bot.post("editMessageText", {"chat_id": 1, "message_id": 1, "text": "two"})["ok"]
assert bot._TG_LOCAL.api_conn is api_conn

now[0] += bot._TG_API_IDLE_SECONDS + 1
assert bot.post("sendMessage", {"chat_id": 1, "text": "three"})["ok"]
assert api_conn.closed
assert bot._TG_LOCAL.api_conn is not api_conn
assert bot._TG_LOCAL.poll_conn is poll_conn

failed_conn = bot._TG_LOCAL.api_conn
FakeConnection.fail_next = True
assert bot.post("sendMessage", {"chat_id": 1, "text": "retry"})["ok"]
assert failed_conn.closed
assert bot._TG_LOCAL.api_conn is not failed_conn

print("bot-transport regression OK")
