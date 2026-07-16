#!/usr/bin/env python3
"""Socket-activated responder for IP registration and short-lived iOS DoT profiles."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows test environment
    fcntl = None
from urllib.parse import unquote

WWW_DIR = Path(os.environ.get("WWW_DIR", "/opt/pdg-bot/ios-www"))
ALLOWLIST_FILE = Path(os.environ.get(
    "ALLOWLIST_FILE", str(WWW_DIR / ".ios-profile-allowlist")
))
ACCESS_STATE_FILE = Path(os.environ.get(
    "ACCESS_STATE_FILE", str(WWW_DIR / ".ios-access.json")
))
PROFILE_NAME_RE = re.compile(r"^(?:ios-dot|ios-[0-9a-f]{12})\.mobileconfig$")
CUSTOM_PROFILE_RE = re.compile(r"^ios-[0-9a-f]{12}\.mobileconfig$")
NFT_SET = "pdg_dns_panel_hosts"
SYNC_SERVICE = os.environ.get("PDG_IOS_SYNC_SERVICE", "")
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(value, strict=False)
    for value in os.environ.get("PDG_IOS_ALLOWED_CIDRS", "").replace(",", " ").split()
)
ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8", ""),
    "/index.html": ("index.html", "text/html; charset=utf-8", ""),
}


def _atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".ios-state-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


@contextmanager
def _locked_access_state():
    ACCESS_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(str(ACCESS_STATE_FILE) + ".lock", "a+", encoding="ascii") as lock:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _load_json(path: Path, default: dict) -> dict:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError):
        return dict(default)
    return value if isinstance(value, dict) else dict(default)


def _access_state() -> dict:
    value = _load_json(ACCESS_STATE_FILE, {"open_until": 0, "hosts": []})
    hosts = []
    for raw in value.get("hosts", []):
        try:
            hosts.append(str(ipaddress.ip_address(raw)))
        except ValueError:
            continue
    try:
        open_until = max(0.0, float(value.get("open_until", 0)))
    except (TypeError, ValueError):
        open_until = 0.0
    return {"open_until": open_until, "hosts": sorted(set(hosts))}


def _save_access_state(value: dict) -> None:
    _atomic_write(ACCESS_STATE_FILE, json.dumps(value, separators=(",", ":")) + "\n")


def sync_firewall() -> None:
    with _locked_access_state():
        hosts = [host for host in _access_state()["hosts"]
                 if ipaddress.ip_address(host).version == 4]
    rules = [f"flush set inet pdg {NFT_SET}"]
    if hosts:
        rules.append(f"add element inet pdg {NFT_SET} {{ {', '.join(hosts)} }}")
    result = subprocess.run(
        ["nft", "-f", "-"], input="\n".join(rules) + "\n",
        text=True, capture_output=True, timeout=10,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "nft 执行失败").strip()
        raise RuntimeError(message[:300])


def _sync_firewall_service() -> None:
    if not SYNC_SERVICE:
        return
    result = subprocess.run(
        ["systemctl", "start", "--wait", SYNC_SERVICE],
        text=True, capture_output=True, timeout=15,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "白名单同步服务失败").strip()
        raise RuntimeError(message[:300])


def _metadata_path(filename: str) -> Path:
    return WWW_DIR / (filename + ".meta")


def _allowed_profiles() -> set[str]:
    try:
        names = ALLOWLIST_FILE.read_text(encoding="ascii").splitlines()
    except OSError:
        return set()
    return {name for name in names if PROFILE_NAME_RE.fullmatch(name)}


def _write_allowlist(names: set[str]) -> None:
    valid = sorted(name for name in names if PROFILE_NAME_RE.fullmatch(name))
    _atomic_write(ALLOWLIST_FILE, "".join(name + "\n" for name in valid), 0o644)


def _remove_profile(filename: str) -> None:
    try:
        (WWW_DIR / filename).unlink(missing_ok=True)
        _metadata_path(filename).unlink(missing_ok=True)
    finally:
        names = _allowed_profiles()
        if filename in names:
            names.remove(filename)
            _write_allowlist(names)


def cleanup_expired(now: float | None = None) -> list[str]:
    now = time.time() if now is None else now
    removed = []
    for meta_path in WWW_DIR.glob("ios-*.mobileconfig.meta"):
        filename = meta_path.name[:-5]
        if not CUSTOM_PROFILE_RE.fullmatch(filename):
            continue
        metadata = _load_json(meta_path, {})
        try:
            expires_at = float(metadata.get("expires_at", 0))
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at <= now:
            _remove_profile(filename)
            removed.append(filename)
    return removed


def _peer_address() -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    remote_address = os.environ.get("REMOTE_ADDR", "")
    if not remote_address:
        try:
            with socket.socket(fileno=os.dup(sys.stdin.fileno())) as connection:
                remote_address = connection.getpeername()[0]
        except OSError:
            return None
    try:
        return ipaddress.ip_address(remote_address)
    except ValueError:
        return None


def _in_allowed_network(client) -> bool:
    return client is not None and any(client in network for network in ALLOWED_NETWORKS)


def _route(path: str):
    path = unquote(path.split("?", 1)[0])
    route = ROUTES.get(path)
    if route:
        return route
    if path.startswith("/") and "/" not in path[1:]:
        name = path[1:]
        if PROFILE_NAME_RE.fullmatch(name) and name in _allowed_profiles():
            return (name, "application/x-apple-aspen-config",
                    "attachment; filename=PrivDNS-Gateway.mobileconfig")
    return None


def _authorize_profile(filename: str, client, now: float) -> bool:
    if not _in_allowed_network(client):
        return False
    client_text = str(client)
    with _locked_access_state():
        state = _access_state()
        known = client_text in state["hosts"]
        if not CUSTOM_PROFILE_RE.fullmatch(filename):
            if known:
                return True
            if state["open_until"] <= now:
                return False
            state["hosts"].append(client_text)
            state["hosts"] = sorted(set(state["hosts"]))
            state["open_until"] = 0
            _save_access_state(state)
            return True

        meta_path = _metadata_path(filename)
        metadata = _load_json(meta_path, {})
        try:
            expires_at = float(metadata.get("expires_at", 0))
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at <= now:
            _remove_profile(filename)
            return False

        bound_ip = str(metadata.get("bound_ip", ""))
        if bound_ip:
            return known and bound_ip == client_text
        if not known and state["open_until"] <= now:
            return False

        metadata["bound_ip"] = client_text
        _atomic_write(meta_path, json.dumps(metadata, separators=(",", ":")) + "\n")
        if not known:
            state["hosts"].append(client_text)
        state["hosts"] = sorted(set(state["hosts"]))
        state["open_until"] = 0
        _save_access_state(state)
        return True


def _write_response(status: str, content_type: str, body: bytes, disposition: str = "") -> None:
    headers = [
        f"HTTP/1.1 {status}\r\n",
        f"Content-Type: {content_type}\r\n",
        f"Content-Length: {len(body)}\r\n",
        "Cache-Control: no-store\r\n",
        "Connection: close\r\n",
    ]
    if disposition:
        headers.append(f"Content-Disposition: {disposition}\r\n")
    sys.stdout.buffer.write("".join(headers).encode("ascii") + b"\r\n" + body)
    sys.stdout.buffer.flush()


def main() -> None:
    if "--sync" in sys.argv:
        sync_firewall()
        return
    if "--cleanup" in sys.argv:
        cleanup_expired()
        return
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, lambda *_: raise_timeout())
        signal.alarm(10)
    request = sys.stdin.buffer.readline(8192).decode("latin1", "replace").split()
    if len(request) < 2 or request[0] not in {"GET", "HEAD"}:
        _write_response("400 Bad Request", "text/plain; charset=utf-8", b"bad request\n")
        return
    route = _route(request[1])
    if route is None:
        _write_response("404 Not Found", "text/plain; charset=utf-8", b"not found\n")
        return
    filename, content_type, disposition = route
    path = WWW_DIR / filename
    try:
        if path.resolve().parent != WWW_DIR.resolve():
            raise OSError("profile path escaped WWW_DIR")
    except OSError:
        _write_response("404 Not Found", "text/plain; charset=utf-8", b"not found\n")
        return
    now = time.time()
    if CUSTOM_PROFILE_RE.fullmatch(filename):
        metadata = _load_json(_metadata_path(filename), {})
        try:
            expires_at = float(metadata.get("expires_at", 0))
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at <= now:
            _remove_profile(filename)
            _write_response("404 Not Found", "text/plain; charset=utf-8", b"not found\n")
            return
    if not _authorize_profile(filename, _peer_address(), now):
        _write_response("403 Forbidden", "text/plain; charset=utf-8", b"forbidden\n")
        return
    try:
        _sync_firewall_service()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        _write_response("503 Service Unavailable", "text/plain; charset=utf-8", b"temporarily unavailable\n")
        raise RuntimeError("IP 白名单同步失败") from error
    try:
        body = path.read_bytes()
    except OSError:
        _write_response("404 Not Found", "text/plain; charset=utf-8", b"not found\n")
        return
    if request[0] == "HEAD":
        body = b""
    _write_response("200 OK", content_type, body, disposition)


def raise_timeout() -> None:
    raise TimeoutError("HTTP request timed out")


if __name__ == "__main__":
    main()
