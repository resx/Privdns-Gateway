#!/usr/bin/env python3
"""PrivDNS Gateway 内网 HTTPS 管理 API 与 PWA 静态服务。"""
from __future__ import annotations

import argparse
import hmac
import json
import mimetypes
import os
import select
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BOT_DIR = os.environ.get("PDG_BOT_DIR", "/opt/pdg-bot")
sys.path.insert(0, BOT_DIR)

from pdg_service import GatewayService, ServiceError  # noqa: E402


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "pdg-admin/1"
    service: GatewayService
    token: str
    web_root: Path
    dashboard_root: Path

    def _security_headers(self, dashboard: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        csp = ("default-src 'self'; connect-src 'self' https://api.github.com; img-src 'self' data: blob:; "
               "style-src 'self' 'unsafe-inline'; script-src 'self' 'sha256-ZS0vkhcl113ly98eGGUNDhkTSpJH5poUYTIXHqXmIts='; worker-src 'self' blob:; "
               "base-uri 'none'; frame-ancestors 'none'") if dashboard else (
               "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; "
               "script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("Strict-Transport-Security", "max-age=31536000")

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        supplied = header[7:] if header.startswith("Bearer ") else ""
        return bool(supplied) and hmac.compare_digest(supplied, self.token)

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        self._json(401, {"error": {"code": "unauthorized", "message": "管理令牌无效"}})
        return False

    def _require_clash_auth(self) -> bool:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        supplied = query.get("token", [""])[0]
        if self._authorized() or (supplied and hmac.compare_digest(supplied, self.token)):
            return True
        self._json(401, {"error": {"code": "unauthorized", "message": "管理令牌无效"}})
        return False

    @staticmethod
    def _without_token(query: str) -> str:
        return urllib.parse.urlencode([
            (name, value) for name, value in urllib.parse.parse_qsl(query, keep_blank_values=True)
            if name not in {"token", "secret"}
        ])

    def log_request(self, code="-", size="-") -> None:
        parsed = urllib.parse.urlsplit(self.path)
        safe_query = self._without_token(parsed.query)
        safe_path = parsed.path + (("?" + safe_query) if safe_query else "")
        self.log_message('"%s %s %s" %s %s', self.command, safe_path, self.request_version, str(code), str(size))

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ServiceError("Content-Length 无效") from error
        if length <= 0 or length > 65536:
            raise ServiceError("请求正文为空或超过 64KB")
        try:
            value = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as error:
            raise ServiceError("JSON 格式不正确") from error
        if not isinstance(value, dict):
            raise ServiceError("请求正文必须是 JSON 对象")
        return value

    def _raw_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ServiceError("Content-Length 无效") from error
        if length < 0 or length > 1024 * 1024:
            raise ServiceError("代理请求正文超过 1MB")
        return self.rfile.read(length) if length else b""

    @staticmethod
    def _clash_proxy_allowed(method: str, path: str) -> bool:
        part = path.lstrip("/").split("/", 1)[0]
        if method == "GET":
            return part in {"version", "proxies", "rules", "connections", "traffic", "logs", "memory", "providers", "configs", "group"} \
                or path == "/storage/zashboard"
        if method == "PUT":
            return path.startswith("/proxies/") or path == "/storage/zashboard"
        return method == "DELETE" and (path == "/connections" or path.startswith("/connections/"))

    def _proxy_websocket(self, target_path: str, query: str) -> None:
        endpoint = urllib.parse.urlsplit(self.service.clash_url)
        if endpoint.scheme != "http" or not endpoint.hostname:
            raise ServiceError("Clash API 地址无效", 502)
        backend = socket.create_connection((endpoint.hostname, endpoint.port or 80), timeout=10)
        try:
            safe_query = self._without_token(query)
            request_target = target_path + (("?" + safe_query) if safe_query else "")
            lines = [f"GET {request_target} HTTP/1.1", f"Host: {endpoint.hostname}:{endpoint.port or 80}"]
            for name in ("Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version",
                         "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"):
                value = self.headers.get(name)
                if value:
                    lines.append(f"{name}: {value}")
            backend.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            response = bytearray()
            while b"\r\n\r\n" not in response:
                chunk = backend.recv(4096)
                if not chunk or len(response) > 65536:
                    raise ServiceError("Clash WebSocket 握手失败", 502)
                response.extend(chunk)
            self.connection.sendall(response)
            if not response.startswith(b"HTTP/1.1 101"):
                return
            self.close_connection = True
            backend.settimeout(None)
            self.connection.settimeout(None)
            try:
                while True:
                    readable, _, _ = select.select((self.connection, backend), (), (), 300)
                    if not readable:
                        break
                    for source in readable:
                        payload = source.recv(65536)
                        if not payload:
                            return
                        (backend if source is self.connection else self.connection).sendall(payload)
            except (OSError, ssl.SSLError):
                return
        finally:
            backend.close()

    def _handle_clash_proxy(self, method: str, path: str, query: str = "") -> None:
        if not self._require_clash_auth():
            return
        try:
            suffix = path[len("/zashboard/api"):]
            target_path = suffix if suffix.startswith("/") else "/"
            if not self._clash_proxy_allowed(method, target_path):
                raise ServiceError("Zashboard 不允许此 Clash API 操作", 403)
            if self.headers.get("Upgrade", "").lower() == "websocket":
                if method != "GET":
                    raise ServiceError("WebSocket 方法无效", 405)
                self._proxy_websocket(target_path, query)
                return
            body = self._raw_body()
            if method == "PUT" and target_path == "/proxies/GLOBAL":
                try:
                    selected = str(json.loads(body or b"{}").get("name", ""))
                except (json.JSONDecodeError, AttributeError) as error:
                    raise ServiceError("GLOBAL 切换请求无效") from error
                self.service.set_final(selected)
                self.send_response(204)
                self._security_headers(dashboard=True)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            headers = {"Accept": self.headers.get("Accept", "application/json")}
            if body:
                headers["Content-Type"] = self.headers.get("Content-Type", "application/json")
            request = urllib.request.Request(
                self.service.clash_url.rstrip("/") + target_path + (("?" + self._without_token(query)) if self._without_token(query) else ""),
                data=body if body else None,
                headers=headers,
                method=method,
            )
            try:
                with urllib.request.urlopen(request, timeout=20) as response:
                    status, content_type, payload = response.status, response.headers.get("Content-Type"), response.read()
            except urllib.error.HTTPError as error:
                status, content_type, payload = error.code, error.headers.get("Content-Type"), error.read()
            self.send_response(status)
            self._security_headers(dashboard=True)
            self.send_header("Content-Type", content_type or "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except ServiceError as error:
            self._json(error.status, {"error": {"code": "proxy_denied", "message": str(error)}})
        except urllib.error.URLError:
            self._json(502, {"error": {"code": "clash_unavailable", "message": "本机 Clash API 不可用"}})
        except Exception as error:  # noqa: BLE001
            self.log_error("Clash proxy error: %r", error)
            self._json(500, {"error": {"code": "proxy_error", "message": "Clash API 代理失败"}})

    def _api(self, method: str, path: str):
        if method == "GET" and path == "/api/v1/overview":
            return self.service.overview()
        if method == "GET" and path == "/api/v1/exits":
            return self.service.list_exits()
        if method == "POST" and path == "/api/v1/exits/preview":
            return self.service.preview_link(str(self._body().get("link", "")))
        if method == "POST" and path == "/api/v1/exits":
            return self.service.add_exit(str(self._body().get("link", "")))
        if method == "POST" and path == "/api/v1/exits/test":
            return self.service.test_exits()
        if method == "PUT" and path == "/api/v1/final":
            return self.service.set_final(str(self._body().get("tag", "")))
        if method == "POST" and path == "/api/v1/groups":
            body = self._body()
            return self.service.save_group(str(body.get("name", "")), body.get("members", []))
        if method == "GET" and path == "/api/v1/rules":
            return self.service.list_rules()
        if method == "POST" and path == "/api/v1/rules":
            body = self._body()
            return self.service.set_rule(str(body.get("domain", "")), str(body.get("target", "")))
        if method == "POST" and path == "/api/v1/route/test":
            return self.service.test_route(str(self._body().get("domain", "")))
        if method == "GET" and path == "/api/v1/rulesets":
            return self.service.list_rulesets()
        if method == "POST" and path == "/api/v1/rulesets":
            body = self._body()
            return self.service.save_ruleset(
                str(body.get("url", "")), str(body.get("target", "")), str(body.get("label", "")),
            )
        if method == "GET" and path == "/api/v1/connections":
            return self.service.list_connections()
        if method == "DELETE" and path == "/api/v1/connections":
            return self.service.close_connection()
        if method == "GET" and path == "/api/v1/logs":
            return self.service.logs()

        exit_prefix = "/api/v1/exits/"
        if path.startswith(exit_prefix):
            tail = urllib.parse.unquote(path[len(exit_prefix):])
            if method == "GET" and tail.endswith("/impact"):
                tag = tail[:-7]
                if not tag or "/" in tag:
                    raise ServiceError("出口名称无效")
                return self.service.exit_impact(tag)
            if not tail or "/" in tail:
                raise ServiceError("出口名称无效")
            if method == "DELETE":
                return self.service.remove_exit(tail)

        group_prefix = "/api/v1/groups/"
        if method == "DELETE" and path.startswith(group_prefix):
            tag = urllib.parse.unquote(path[len(group_prefix):])
            return self.service.remove_group(tag)

        ruleset_prefix = "/api/v1/rulesets/"
        if path.startswith(ruleset_prefix):
            tail = urllib.parse.unquote(path[len(ruleset_prefix):])
            if method == "POST" and tail.endswith("/refresh"):
                return self.service.refresh_ruleset(tail[:-8])
            if method == "PUT":
                body = self._body()
                target = str(body["target"]) if "target" in body else None
                label = str(body["label"]) if "label" in body else None
                return self.service.update_ruleset(tail, target, label)
            if method == "DELETE":
                return self.service.remove_ruleset(tail)

        connection_prefix = "/api/v1/connections/"
        if method == "DELETE" and path.startswith(connection_prefix):
            connection_id = urllib.parse.unquote(path[len(connection_prefix):])
            if not connection_id or "/" in connection_id:
                raise ServiceError("连接 ID 无效")
            return self.service.close_connection(connection_id)

        rule_prefix = "/api/v1/rules/"
        if method == "DELETE" and path.startswith(rule_prefix):
            domain = urllib.parse.unquote(path[len(rule_prefix):])
            return self.service.remove_rule(domain)
        raise ServiceError("接口不存在", 404)

    def _handle_api(self, method: str, path: str) -> None:
        if not self._require_auth():
            return
        try:
            data = self._api(method, path)
            self._json(200, {"data": data})
        except ServiceError as error:
            self._json(error.status, {"error": {"code": "request_failed", "message": str(error)}})
        except ValueError as error:
            self._json(400, {"error": {"code": "invalid_value", "message": str(error)}})
        except Exception as error:  # noqa: BLE001
            self.log_error("API error: %r", error)
            self._json(500, {"error": {"code": "internal_error", "message": "服务器内部错误"}})

    def _static(self, path: str, head_only: bool = False) -> None:
        relative = urllib.parse.unquote(path).lstrip("/") or "index.html"
        candidate = (self.web_root / relative).resolve()
        root = self.web_root.resolve()
        if root not in candidate.parents and candidate != root:
            self.send_error(404)
            return
        if not candidate.is_file():
            candidate = root / "index.html"
        if not candidate.is_file():
            self.send_error(404)
            return
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "public, max-age=31536000, immutable" if "/assets/" in path else "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _dashboard_static(self, path: str, head_only: bool = False) -> None:
        root = self.dashboard_root.resolve()
        relative = urllib.parse.unquote(path[len("/zashboard"):]).lstrip("/") or "index.html"
        candidate = (root / relative).resolve()
        if root not in candidate.parents and candidate != root:
            self.send_error(404)
            return
        if not candidate.is_file():
            candidate = root / "index.html"
        if not candidate.is_file():
            self.send_error(404)
            return
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(200)
        self._security_headers(dashboard=True)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "public, max-age=31536000, immutable" if "/assets/" in path else "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path == "/zashboard":
            self.send_response(308)
            self._security_headers(dashboard=True)
            self.send_header("Location", "/zashboard/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/healthz":
            self._json(200, {"status": "ok"})
        elif path.startswith("/zashboard/api/") or path == "/zashboard/api":
            self._handle_clash_proxy("GET", path, parsed.query)
        elif path == "/zashboard" or path.startswith("/zashboard/"):
            self._dashboard_static(path)
        elif path.startswith("/api/"):
            self._handle_api("GET", path)
        else:
            self._static(path)

    def do_HEAD(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/api/") or path.startswith("/zashboard/api"):
            self.send_error(405)
        elif path == "/zashboard" or path.startswith("/zashboard/"):
            self._dashboard_static(path, head_only=True)
        else:
            self._static(path, head_only=True)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path.startswith("/zashboard/api/") or path == "/zashboard/api":
            self._handle_clash_proxy("POST", path, parsed.query)
        else:
            self._handle_api("POST", path)

    def do_PUT(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path.startswith("/zashboard/api/") or path == "/zashboard/api":
            self._handle_clash_proxy("PUT", path, parsed.query)
        else:
            self._handle_api("PUT", path)

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path.startswith("/zashboard/api/") or path == "/zashboard/api":
            self._handle_clash_proxy("DELETE", path, parsed.query)
        else:
            self._handle_api("DELETE", path)


def create_server(host: str, port: int, token: str, web_root: str, service=None, dashboard_root: str = "/opt/pdg-admin/zashboard") -> ThreadingHTTPServer:
    handler = type("ConfiguredAdminHandler", (AdminHandler,), {
        "token": token,
        "web_root": Path(web_root),
        "dashboard_root": Path(dashboard_root),
        "service": service or GatewayService(),
    })
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--token-file", default="/etc/privdns-gateway/admin.token")
    parser.add_argument("--web-root", default="/opt/pdg-admin/web")
    parser.add_argument("--dashboard-root", default="/opt/pdg-admin/zashboard")
    parser.add_argument("--cert", default="/etc/mosdns/certs/fullchain.pem")
    parser.add_argument("--key", default="/etc/mosdns/certs/privkey.pem")
    args = parser.parse_args()

    token = Path(args.token_file).read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise SystemExit("admin token 缺失或过短")
    server = create_server(args.listen, args.port, token, args.web_root, dashboard_root=args.dashboard_root)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"pdg-admin listening on https://{args.listen}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
