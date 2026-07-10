#!/usr/bin/env python3
"""pdg-admin HTTP 鉴权、路由与静态资源回归。"""
import base64
import hashlib
import http.client
import importlib.util
import json
import socket
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))

spec = importlib.util.spec_from_file_location("pdg_admin", ROOT / "deploy/admin/pdg-admin.py")
admin = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(admin)


class FakeService:
    def __init__(self, clash_url="http://127.0.0.1:9090"):
        self.calls = []
        self.clash_url = clash_url

    def overview(self): return {"default_exit": "jp"}
    def list_exits(self): return [{"tag": "jp"}]
    def preview_link(self, link): self.calls.append(("preview", link)); return {"tag": "new"}
    def add_exit(self, link): self.calls.append(("add", link)); return {"tag": "new"}
    def test_exits(self): return [{"tag": "jp", "ok": True, "delay": 8}]
    def set_final(self, tag): self.calls.append(("final", tag)); return {"default_exit": tag}
    def save_group(self, name, members): self.calls.append(("group", name, members)); return {"tag": name}
    def remove_group(self, tag): self.calls.append(("del-group", tag)); return {"deleted": tag}
    def list_rules(self): return [{"kind": "domain", "value": "x.test", "target": "jp"}]
    def set_rule(self, domain, target): self.calls.append(("rule", domain, target)); return {"domain": domain}
    def remove_rule(self, domain): self.calls.append(("del-rule", domain)); return {"deleted": domain}
    def test_route(self, domain): self.calls.append(("test-route", domain)); return {"target": "jp"}
    def list_subscriptions(self): return [{"id": "sub_one", "label": "机场 A", "count": 2}]
    def preview_subscription(self, url, label, include, exclude, group, categories=None):
        self.calls.append(("preview-sub", url, label, include, exclude, group, categories)); return {"id": "sub_one", "count": 2}
    def save_subscription(self, url, label, include, exclude, group, categories=None):
        self.calls.append(("save-sub", url, label, include, exclude, group, categories)); return {"id": "sub_one", "count": 2}
    def preview_subscription_update(self, identifier, **changes):
        self.calls.append(("preview-put-sub", identifier, changes)); return {"id": identifier, **changes}
    def update_subscription(self, identifier, **changes):
        self.calls.append(("put-sub", identifier, changes)); return {"id": identifier, **changes}
    def refresh_subscription(self, identifier): self.calls.append(("refresh-sub", identifier)); return {"id": identifier}
    def refresh_subscriptions(self): self.calls.append(("refresh-subs",)); return [{"id": "sub_one", "ok": True}]
    def remove_subscription(self, identifier): self.calls.append(("del-sub", identifier)); return {"deleted": identifier}
    def list_rulesets(self): return [{"tag": "rs_one"}]
    def save_ruleset(self, url, target, label): self.calls.append(("ruleset", url, target, label)); return {"tag": "rs_one"}
    def update_ruleset(self, tag, target, label): self.calls.append(("put-ruleset", tag, target, label)); return {"tag": tag}
    def refresh_ruleset(self, tag): self.calls.append(("refresh-ruleset", tag)); return {"tag": tag}
    def remove_ruleset(self, tag): self.calls.append(("del-ruleset", tag)); return {"deleted": tag}
    def list_connections(self): return {"connections": []}
    def close_connection(self, connection_id=None): self.calls.append(("close", connection_id)); return {"closed": connection_id or "all"}
    def logs(self): return {"lines": ["ok"]}
    def exit_impact(self, tag): self.calls.append(("impact", tag)); return {"groups": [], "rules": []}
    def remove_exit(self, tag): self.calls.append(("delete", tag)); return {"deleted": tag}


def request(port, method, path, token=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        encoded = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(encoded))
    else:
        encoded = None
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    data = response.read()
    result = (response.status, dict(response.getheaders()), data)
    connection.close()
    return result


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    web = root / "web"; web.mkdir()
    dashboard = root / "dashboard"; dashboard.mkdir()
    web.joinpath("index.html").write_text("<h1>PDG</h1>", encoding="utf-8")
    dashboard.joinpath("index.html").write_text("<h1>Zashboard</h1>", encoding="utf-8")

    class ClashHandler(admin.BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.calls.append((self.path, None))
            if self.headers.get("Upgrade", "").lower() == "websocket":
                key = self.headers["Sec-WebSocket-Key"]
                accept = base64.b64encode(hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                ).digest()).decode()
                self.send_response(101); self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade"); self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers(); self.wfile.write(b"\x81\x02{}"); self.wfile.flush()
                return
            payload = json.dumps({"proxies": {"auto": {"type": "Selector", "now": "hk"}}}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
        def do_PUT(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.server.calls.append((self.path, json.loads(body)))
            self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers()
        def log_message(self, *_): pass

    clash = admin.ThreadingHTTPServer(("127.0.0.1", 0), ClashHandler); clash.calls = []
    clash_thread = threading.Thread(target=clash.serve_forever, daemon=True); clash_thread.start()
    service = FakeService(f"http://127.0.0.1:{clash.server_address[1]}")
    token = "a" * 64
    server = admin.create_server("127.0.0.1", 0, token, str(web), service, str(dashboard))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        status, _, payload = request(port, "GET", "/api/v1/overview")
        assert status == 401 and json.loads(payload)["error"]["code"] == "unauthorized"

        status, headers, payload = request(port, "GET", "/api/v1/overview", token)
        assert status == 200 and json.loads(payload)["data"]["default_exit"] == "jp"
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Frame-Options"] == "DENY"

        status, _, payload = request(port, "POST", "/api/v1/exits/preview", token, {"link": "socks5://x"})
        assert status == 200 and json.loads(payload)["data"]["tag"] == "new"
        assert service.calls[-1] == ("preview", "socks5://x")

        status, _, _ = request(port, "GET", "/api/v1/exits/hk%20one/impact", token)
        assert status == 200 and service.calls[-1] == ("impact", "hk one")
        status, _, _ = request(port, "DELETE", "/api/v1/exits/hk%20one", token)
        assert status == 200 and service.calls[-1] == ("delete", "hk one")

        status, _, payload = request(port, "POST", "/api/v1/rules", token, {"domain": "x.test", "target": "jp"})
        assert status == 200 and service.calls[-1] == ("rule", "x.test", "jp")
        status, _, _ = request(port, "POST", "/api/v1/groups", token, {"name": "auto", "members": ["hk", "tw"]})
        assert status == 200 and service.calls[-1] == ("group", "auto", ["hk", "tw"])
        status, _, _ = request(port, "POST", "/api/v1/route/test", token, {"domain": "x.test"})
        assert status == 200 and service.calls[-1] == ("test-route", "x.test")
        status, _, payload = request(port, "GET", "/api/v1/subscriptions", token)
        assert status == 200 and json.loads(payload)["data"][0]["id"] == "sub_one"
        status, _, _ = request(port, "POST", "/api/v1/subscriptions/preview", token,
                               {"url": "https://sub.example/x", "label": "A", "include": "HK",
                                "categories": [{"name": "香港", "pattern": "HK"}]})
        assert status == 200 and service.calls[-1][0] == "preview-sub"
        assert service.calls[-1][-1] == [{"name": "香港", "pattern": "HK"}]
        status, _, _ = request(port, "POST", "/api/v1/subscriptions", token,
                               {"url": "https://sub.example/x", "label": "A", "group": "airport-a"})
        assert status == 200 and service.calls[-1][0] == "save-sub"
        status, _, _ = request(port, "POST", "/api/v1/subscriptions/sub_one/preview", token, {"exclude": "expired"})
        assert status == 200 and service.calls[-1] == ("preview-put-sub", "sub_one", {"exclude": "expired"})
        status, _, _ = request(port, "PUT", "/api/v1/subscriptions/sub_one", token, {"exclude": "expired"})
        assert status == 200 and service.calls[-1] == ("put-sub", "sub_one", {"exclude": "expired"})
        status, _, _ = request(port, "POST", "/api/v1/subscriptions/sub_one/refresh", token, {})
        assert status == 200 and service.calls[-1] == ("refresh-sub", "sub_one")
        status, _, _ = request(port, "DELETE", "/api/v1/subscriptions/sub_one", token)
        assert status == 200 and service.calls[-1] == ("del-sub", "sub_one")

        status, _, _ = request(port, "POST", "/api/v1/rulesets", token,
                               {"url": "https://x/r.list", "target": "jp", "label": "R"})
        assert status == 200 and service.calls[-1][0] == "ruleset"
        status, _, _ = request(port, "PUT", "/api/v1/rulesets/rs_one", token, {"target": "hk"})
        assert status == 200 and service.calls[-1] == ("put-ruleset", "rs_one", "hk", None)
        status, _, _ = request(port, "POST", "/api/v1/rulesets/rs_one/refresh", token, {})
        assert status == 200 and service.calls[-1] == ("refresh-ruleset", "rs_one")
        status, _, _ = request(port, "DELETE", "/api/v1/connections/c1", token)
        assert status == 200 and service.calls[-1] == ("close", "c1")
        status, _, payload = request(port, "GET", "/api/v1/logs", token)
        assert status == 200 and json.loads(payload)["data"]["lines"] == ["ok"]

        status, headers, _ = request(port, "GET", "/zashboard")
        assert status == 308 and headers["Location"] == "/zashboard/"
        status, _, payload = request(port, "GET", "/zashboard/")
        assert status == 200 and payload == b"<h1>Zashboard</h1>"
        status, _, payload = request(port, "GET", "/zashboard/api/proxies")
        assert status == 401
        status, _, payload = request(port, "GET", f"/zashboard/api/proxies?token={token}")
        assert status == 200 and clash.calls[-1] == ("/proxies", None)
        status, _, payload = request(port, "GET", "/zashboard/api/proxies", token)
        assert status == 200 and json.loads(payload)["proxies"]["auto"]["now"] == "hk"
        status, _, _ = request(port, "GET", "/zashboard/api/proxies/hk/delay?timeout=5000", token)
        assert status == 200 and clash.calls[-1] == ("/proxies/hk/delay?timeout=5000", None)
        status, _, _ = request(port, "PUT", "/zashboard/api/proxies/auto", token, {"name": "tw"})
        assert status == 204 and clash.calls[-1] == ("/proxies/auto", {"name": "tw"})
        status, _, _ = request(port, "PUT", "/zashboard/api/proxies/GLOBAL", token, {"name": "tw"})
        assert status == 204 and service.calls[-1] == ("final", "tw")
        status, _, payload = request(port, "PUT", "/zashboard/api/configs", token, {"mode": "direct"})
        assert status == 403 and json.loads(payload)["error"]["code"] == "proxy_denied"
        status, _, payload = request(port, "POST", "/zashboard/api/restart", token, {})
        assert status == 403

        websocket = socket.create_connection(("127.0.0.1", port), timeout=5)
        websocket.sendall((
            f"GET /zashboard/api/traffic?token={token} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        handshake = bytearray()
        while b"\x81\x02{}" not in handshake:
            chunk = websocket.recv(4096)
            if not chunk: break
            handshake.extend(chunk)
        websocket.close()
        assert b" 101 " in handshake
        assert clash.calls[-1] == ("/traffic", None)

        status, _, payload = request(port, "GET", "/healthz")
        assert status == 200 and json.loads(payload)["status"] == "ok"
        status, headers, payload = request(port, "GET", "/")
        assert status == 200 and payload == b"<h1>PDG</h1>"
        assert "default-src 'self'" in headers["Content-Security-Policy"]

        status, _, _ = request(port, "GET", "/../../etc/passwd")
        assert status == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        clash.shutdown()
        clash.server_close()
        clash_thread.join(timeout=5)

print("admin-api regression OK")
