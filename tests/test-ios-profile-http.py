#!/usr/bin/env python3
"""iOS profile socket responder policy regression."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "ios" / "profile-http.py"

with tempfile.TemporaryDirectory() as work:
    root = Path(work)
    (root / "index.html").write_text("index", encoding="utf-8")
    (root / "ios-dot.mobileconfig").write_text("profile", encoding="utf-8")
    (root / "ios-0123456789ab.mobileconfig").write_text("custom", encoding="utf-8")
    (root / "ios-ffffffffffff.mobileconfig").write_text("unlisted", encoding="utf-8")
    (root / ".ios-profile-allowlist").write_text(
        "ios-dot.mobileconfig\nios-0123456789ab.mobileconfig\n", encoding="ascii"
    )
    env = {
        **os.environ,
        "WWW_DIR": str(root),
        "PDG_IOS_ALLOWED_CIDRS": "172.22.0.0/16",
        "REMOTE_ADDR": "172.22.1.9",
    }

    def request(path, request_env=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=f"GET {path} HTTP/1.1\r\nHost: gateway\r\n\r\n",
            text=True,
            capture_output=True,
            env=request_env or env,
            check=True,
        ).stdout

    denied_env = {**env, "REMOTE_ADDR": "198.51.100.9"}
    denied = request("/ios-dot.mobileconfig", denied_env)
    assert "HTTP/1.1 403 Forbidden" in denied
    assert "profile" not in denied

    response = request("/ios-dot.mobileconfig")
    normalized = response.replace("\r\n", "\n")
    assert "HTTP/1.1 200 OK" in normalized
    assert "application/x-apple-aspen-config" in normalized
    assert normalized.endswith("\n\nprofile")

    custom = request("/ios-0123456789ab.mobileconfig").replace("\r\n", "\n")
    assert custom.endswith("\n\ncustom")
    assert "Content-Disposition: attachment" in custom

    unlisted = request("/ios-ffffffffffff.mobileconfig")
    assert "HTTP/1.1 404 Not Found" in unlisted
    assert "unlisted" not in unlisted

    missing = request("/../ios-dot.mobileconfig")
    assert "HTTP/1.1 404 Not Found" in missing

    (root / ".ios-profile-allowlist").unlink()
    no_allowlist = request("/ios-dot.mobileconfig")
    assert "HTTP/1.1 404 Not Found" in no_allowlist

    no_cidr_env = {**env}
    no_cidr_env.pop("PDG_IOS_ALLOWED_CIDRS")
    no_cidr = request("/", no_cidr_env)
    assert "HTTP/1.1 403 Forbidden" in no_cidr

print("ios-profile-http regression OK")
