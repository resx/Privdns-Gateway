#!/usr/bin/env python3
"""Telegram iOS QR/file delivery regression."""
import importlib.util
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pdg_bot_ios", ROOT / "deploy/bot" / "pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

with tempfile.TemporaryDirectory() as work:
    bot.IOS_WWW_DIR = work
    bot._ios_download_host = lambda: "dot.example.com"
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
    assert not [
        path for path in Path(work).glob(".ios-profile-*")
        if path.name != ".ios-profile-allowlist"
    ]
    assert not list(Path(work).glob(".ios-allowlist-*"))

print("bot-ios regression OK")
