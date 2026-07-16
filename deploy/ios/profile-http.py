#!/usr/bin/env python3
"""socket-activated HTTP server for iOS DoT profiles.

The listener only exposes the generated profile and a tiny landing page.  A
published-file allowlist and the configured internal client CIDR both guard it;
the firewall provides the outer network boundary.
"""
from __future__ import annotations

import ipaddress
import os
import re
import signal
import socket
import sys
from pathlib import Path
from urllib.parse import unquote

WWW_DIR = Path(os.environ.get("WWW_DIR", "/opt/pdg-bot/ios-www"))
ALLOWLIST_FILE = Path(os.environ.get(
    "ALLOWLIST_FILE", str(WWW_DIR / ".ios-profile-allowlist")
))
PROFILE_NAME_RE = re.compile(r"^(?:ios-dot|ios-[0-9a-f]{12})\.mobileconfig$")
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(value, strict=False)
    for value in os.environ.get("PDG_IOS_ALLOWED_CIDRS", "").replace(",", " ").split()
)
ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8", ""),
    "/index.html": ("index.html", "text/html; charset=utf-8", ""),
}


def _client_allowed() -> bool:
    remote_address = os.environ.get("REMOTE_ADDR", "")
    if not remote_address:
        try:
            with socket.socket(fileno=os.dup(sys.stdin.fileno())) as connection:
                remote_address = connection.getpeername()[0]
        except OSError:
            return False
    try:
        client = ipaddress.ip_address(remote_address)
    except ValueError:
        return False
    return any(client in network for network in ALLOWED_NETWORKS)


def _allowed_profiles() -> set[str]:
    try:
        names = ALLOWLIST_FILE.read_text(encoding="ascii").splitlines()
    except OSError:
        return set()
    return {name for name in names if PROFILE_NAME_RE.fullmatch(name)}


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


def _write_response(status: str, content_type: str, body: bytes, disposition: str = "") -> None:
    headers = [
        f"HTTP/1.1 {status}\r\n",
        f"Content-Type: {content_type}\r\n",
        f"Content-Length: {len(body)}\r\n",
        "Connection: close\r\n",
    ]
    if disposition:
        headers.append(f"Content-Disposition: {disposition}\r\n")
    sys.stdout.buffer.write("".join(headers).encode("ascii") + b"\r\n" + body)
    sys.stdout.buffer.flush()


def main() -> None:
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, lambda *_: raise_timeout())
        signal.alarm(10)
    if not _client_allowed():
        _write_response("403 Forbidden", "text/plain; charset=utf-8", b"forbidden\n")
        return
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
    if path.parent != WWW_DIR:
        _write_response("404 Not Found", "text/plain; charset=utf-8", b"not found\n")
        return
    try:
        if path.resolve().parent != WWW_DIR.resolve():
            raise OSError("profile path escaped WWW_DIR")
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
