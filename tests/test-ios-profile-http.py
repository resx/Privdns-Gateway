#!/usr/bin/env python3
"""iOS profile TTL, temporary access and first-client IP pinning regression."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "ios" / "profile-http.py"

with tempfile.TemporaryDirectory() as work:
    root = Path(work)
    (root / "index.html").write_text("index", encoding="utf-8")
    (root / "ios-dot.mobileconfig").write_text("profile", encoding="utf-8")
    custom_name = "ios-0123456789ab.mobileconfig"
    (root / custom_name).write_text("custom", encoding="utf-8")
    (root / "ios-ffffffffffff.mobileconfig").write_text("unlisted", encoding="utf-8")
    (root / ".ios-profile-allowlist").write_text(
        f"ios-dot.mobileconfig\n{custom_name}\n", encoding="ascii"
    )
    state_path = root / ".ios-access.json"
    state_path.write_text(json.dumps({"open_until": time.time() + 600, "hosts": []}), encoding="ascii")
    (root / (custom_name + ".meta")).write_text(
        json.dumps({"expires_at": time.time() + 600, "bound_ip": ""}), encoding="ascii"
    )
    env = {
        **os.environ,
        "WWW_DIR": str(root),
        "ALLOWLIST_FILE": str(root / ".ios-profile-allowlist"),
        "ACCESS_STATE_FILE": str(state_path),
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
        ).stdout.replace("\r\n", "\n")

    # The temporary window allows the first valid custom-profile client only.
    first = request("/" + custom_name)
    assert "HTTP/1.1 200 OK" in first and first.endswith("\n\ncustom")
    state = json.loads(state_path.read_text(encoding="ascii"))
    assert state["hosts"] == ["172.22.1.9"] and state["open_until"] == 0
    metadata = json.loads((root / (custom_name + ".meta")).read_text(encoding="ascii"))
    assert metadata["bound_ip"] == "172.22.1.9"

    other_ip = {**env, "REMOTE_ADDR": "172.22.1.10"}
    denied = request("/" + custom_name, other_ip)
    assert "HTTP/1.1 403 Forbidden" in denied
    assert request("/" + custom_name).endswith("\n\ncustom")

    # A pinned host can use the permanent default profile; an unregistered host cannot.
    default = request("/ios-dot.mobileconfig")
    assert "HTTP/1.1 200 OK" in default and default.endswith("\n\nprofile")
    outside = {**env, "REMOTE_ADDR": "198.51.100.9"}
    assert "HTTP/1.1 403 Forbidden" in request("/ios-dot.mobileconfig", outside)

    unlisted = request("/ios-ffffffffffff.mobileconfig")
    assert "HTTP/1.1 404 Not Found" in unlisted and "unlisted" not in unlisted
    assert "HTTP/1.1 404 Not Found" in request("/../ios-dot.mobileconfig")

    # Expired custom files are removed from disk, metadata and the file allowlist.
    expired_name = "ios-abcdefabcdef.mobileconfig"
    (root / expired_name).write_text("expired", encoding="utf-8")
    (root / (expired_name + ".meta")).write_text(
        json.dumps({"expires_at": time.time() - 1, "bound_ip": "172.22.1.9"}), encoding="ascii"
    )
    (root / ".ios-profile-allowlist").write_text(
        f"ios-dot.mobileconfig\n{custom_name}\n{expired_name}\n", encoding="ascii"
    )
    expired = request("/" + expired_name)
    assert "HTTP/1.1 404 Not Found" in expired
    assert not (root / expired_name).exists() and not (root / (expired_name + ".meta")).exists()
    assert expired_name not in (root / ".ios-profile-allowlist").read_text(encoding="ascii")

    # Cleanup mode removes expired files without requiring an HTTP request.
    cleanup_name = "ios-fedcbafedcba.mobileconfig"
    (root / cleanup_name).write_text("cleanup", encoding="utf-8")
    (root / (cleanup_name + ".meta")).write_text(
        json.dumps({"expires_at": time.time() - 1, "bound_ip": ""}), encoding="ascii"
    )
    (root / ".ios-profile-allowlist").write_text(
        f"ios-dot.mobileconfig\n{custom_name}\n{cleanup_name}\n", encoding="ascii"
    )
    subprocess.run([sys.executable, str(SCRIPT), "--cleanup"], env=env, check=True)
    assert not (root / cleanup_name).exists()
    assert cleanup_name not in (root / ".ios-profile-allowlist").read_text(encoding="ascii")

    no_state = {**env}
    state_path.unlink()
    assert "HTTP/1.1 403 Forbidden" in request("/ios-dot.mobileconfig", no_state)

    # The generic root path registers Android and other non-iOS clients.
    state_path.write_text(
        json.dumps({"open_until": time.time() + 600, "hosts": []}), encoding="ascii"
    )
    generic_client = {**env, "REMOTE_ADDR": "172.22.1.11"}
    assert request("/", generic_client).endswith("\n\nindex")
    state = json.loads(state_path.read_text(encoding="ascii"))
    assert state["hosts"] == ["172.22.1.11"] and state["open_until"] == 0
    assert "HTTP/1.1 200 OK" in request("/ios-dot.mobileconfig", generic_client)

    # Boot-time sync rebuilds the nft set from persisted registered hosts.
    saved_env = {name: os.environ.get(name) for name in (
        "WWW_DIR", "ALLOWLIST_FILE", "ACCESS_STATE_FILE", "PDG_IOS_ALLOWED_CIDRS",
    )}
    os.environ.update({
        "WWW_DIR": str(root),
        "ALLOWLIST_FILE": str(root / ".ios-profile-allowlist"),
        "ACCESS_STATE_FILE": str(state_path),
        "PDG_IOS_ALLOWED_CIDRS": "172.22.0.0/16",
    })
    spec = importlib.util.spec_from_file_location("profile_http_sync", SCRIPT)
    profile_http = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(profile_http)
    for name, value in saved_env.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    nft_calls = []
    real_run = profile_http.subprocess.run
    profile_http.subprocess.run = lambda command, **kwargs: (
        nft_calls.append((command, kwargs.get("input", "")))
        or subprocess.CompletedProcess(command, 0, "", "")
    )
    try:
        profile_http.sync_firewall()
    finally:
        profile_http.subprocess.run = real_run
    assert nft_calls[0][0] == ["nft", "-f", "-"]
    assert "flush set inet pdg pdg_dns_panel_hosts" in nft_calls[0][1]
    assert "add element inet pdg pdg_dns_panel_hosts { 172.22.1.11 }" in nft_calls[0][1]

print("ios-profile-http TTL/IP regression OK")
