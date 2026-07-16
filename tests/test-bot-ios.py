#!/usr/bin/env python3
"""Telegram iOS QR/file delivery regression."""
import importlib.util
import json
import re
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pdg_bot_ios", ROOT / "deploy/bot" / "pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

bot_source = (ROOT / "deploy" / "bot" / "pdg-bot.py").read_text(encoding="utf-8")
registered_commands = re.findall(r'\{"command": "([^"]+)"', bot_source)
assert registered_commands and all(re.fullmatch(r"[a-z0-9_]{1,32}", command) for command in registered_commands)
assert {"ios", "ios_allow", "allowlist", "allowlist_revoke"} <= set(registered_commands)

_, client_keyboard = bot._nav("client")
client_callbacks = {
    button["callback_data"]
    for row in client_keyboard["inline_keyboard"]
    for button in row
    if "callback_data" in button
}
assert "ios_access" in client_callbacks
assert any(button["callback_data"] == "ios" for row in client_keyboard["inline_keyboard"] for button in row)

with tempfile.TemporaryDirectory() as work:
    bot.IOS_WWW_DIR = work
    bot._ios_download_host = lambda: "dot.example.com"
    bot._gateway.ios_access_status = lambda: {
        "open": True, "remaining_seconds": 120, "hosts": ["172.22.1.9"]
    }
    bot._gateway.open_ios_access = lambda minutes: {"open": True, "remaining_seconds": minutes * 60, "hosts": []}
    text, access_keyboard = bot._ip_allowlist_view()
    access_callbacks = {
        button["callback_data"]
        for row in access_keyboard["inline_keyboard"]
        for button in row
        if "callback_data" in button
    }
    assert "IP 白名单" in text
    assert any(
        button.get("url") == "http://dot.example.com:8111/"
        for row in access_keyboard["inline_keyboard"] for button in row
    )
    assert {"iosopen:5", "iosopen:10", "iosopen:30", "iosrevoke:172.22.1.9", "iosrevoke:ask"} <= access_callbacks
    photos = []
    documents = []
    notices = []
    bot.send_photo = lambda chat, filename, data, caption="": photos.append(
        (chat, filename, data, caption)
    ) or True
    bot.send_document = lambda chat, filename, data, caption="": documents.append(
        (chat, filename, data, caption)
    ) or {"ok": True}
    bot.send_plain = lambda chat, text: notices.append(text)

    real_run = bot.subprocess.run

    def fake_run(argv, **kwargs):
        Path(argv[2]).write_bytes(b"png")
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    bot.subprocess.run = fake_run
    try:
        url = bot._send_ios_assets(7, b"profile", "caption", custom=True)
    finally:
        bot.subprocess.run = real_run

    assert re.fullmatch(r"http://dot\.example\.com:8111/ios-[0-9a-f]{12}\.mobileconfig", url)
    assert photos and photos[0][0] == 7 and photos[0][2] == b"png"
    assert url in photos[0][3]
    assert documents and documents[0][2] == b"profile"
    assert not notices
    custom_name = url.rsplit("/", 1)[-1]
    assert (Path(work) / custom_name).read_bytes() == b"profile"
    assert (Path(work) / ".ios-profile-allowlist").read_text(encoding="ascii") == custom_name + "\n"
    metadata = json.loads((Path(work) / (custom_name + ".meta")).read_text(encoding="ascii"))
    assert 590 < metadata["expires_at"] - time.time() <= 600
    assert not [
        path for path in Path(work).glob(".ios-profile-*")
        if path.name != ".ios-profile-allowlist"
    ]
    assert not list(Path(work).glob(".ios-allowlist-*"))

print("bot-ios regression OK")
