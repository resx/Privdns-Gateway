#!/usr/bin/env python3
"""pdg-admin HTTP 鉴权、路由与静态资源回归。"""
import http.client
import importlib.util
import json
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
    def __init__(self):
        self.calls = []

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
    web = Path(directory)
    web.joinpath("index.html").write_text("<h1>PDG</h1>", encoding="utf-8")
    service = FakeService()
    token = "a" * 64
    server = admin.create_server("127.0.0.1", 0, token, str(web), service)
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

print("admin-api regression OK")
