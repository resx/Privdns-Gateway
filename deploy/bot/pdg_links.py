#!/usr/bin/env python3
"""节点分享链接解析器，供 Telegram Bot 与 Web 管理 API 共用。"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse


def normalize_tag(name, host="", port=""):
    return re.sub(r"[^A-Za-z0-9_.-]", "-", (name or f"{host}:{port}"))[:40] or "exit"


def parse_link(link):
    link = link.strip()
    if link.startswith("ss://"):
        return _parse_ss(link)
    if link.startswith("vmess://"):
        return _parse_vmess(link)
    if link.startswith("trojan://"):
        return _parse_trojan(link)
    if link.startswith("vless://"):
        return _parse_vless(link)
    if link.startswith(("hysteria2://", "hy2://")):
        return _parse_hysteria2(link)
    if link.startswith("tuic://"):
        return _parse_tuic(link)
    if link.startswith("anytls://"):
        return _parse_anytls(link)
    if link.startswith(("socks://", "socks5://")):
        return _parse_socks(link)
    if link.startswith(("http://", "https://")):
        return _parse_http(link)
    if re.search(r"=\s*ss\s*,", link, re.I):
        return _parse_surge(link)
    raise ValueError("支持 ss/vmess/trojan/vless/hysteria2/tuic/anytls/socks5/http 分享链接或 Surge ss 行")


def _b64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "ignore")


def _parse_ss(link):
    body = link[5:]
    tag = ""
    if "#" in body:
        body, tag = body.split("#", 1)
        tag = urllib.parse.unquote(tag).strip()
    body = body.split("?", 1)[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            method, password = _b64(userinfo).split(":", 1)
        except Exception:
            method, password = urllib.parse.unquote(userinfo).split(":", 1)
        host, port = hostport.rsplit(":", 1)
    else:
        head, hostport = _b64(body).rsplit("@", 1)
        method, password = head.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    host = host.strip("[]")
    return {
        "type": "shadowsocks", "tag": normalize_tag(tag, host, port),
        "server": host, "server_port": int(port.split("/")[0]),
        "method": method, "password": password,
    }


def _parse_surge(line):
    name, _, rest = line.partition("=")
    parts = [part.strip() for part in rest.split(",")]
    if not parts or parts[0].lower() != "ss":
        raise ValueError("Surge 行暂只支持 ss")
    if len(parts) < 3:
        raise ValueError("Surge ss 行格式错误")
    server = parts[1].strip("[]")
    port = int(parts[2].split("/")[0])
    values = {}
    for part in parts[3:]:
        if "=" in part:
            key, value = part.split("=", 1)
            values[key.strip().lower()] = value.strip().strip('"').strip("'")
    method = values.get("encrypt-method") or values.get("method")
    password = values.get("password")
    if not method or not password:
        raise ValueError("Surge ss 行缺 encrypt-method 或 password")
    outbound = {
        "type": "shadowsocks", "tag": normalize_tag(name.strip(), server, port),
        "server": server, "server_port": port, "method": method, "password": password,
    }
    if values.get("tfo", "").lower() in ("true", "1"):
        outbound["tcp_fast_open"] = True
    return outbound


def _tls_block(server_name, insecure=False):
    block = {"enabled": True}
    if server_name:
        block["server_name"] = server_name
    if insecure:
        block["insecure"] = True
    return block


def _transport(network, host, path, service=None):
    if network in ("ws", "websocket"):
        transport = {"type": "ws", "path": path or "/"}
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if network == "grpc":
        return {"type": "grpc", "service_name": service or (path or "").lstrip("/")}
    return None


def _parse_vmess(link):
    value = json.loads(_b64(link[8:]))
    host, port = value["add"], int(value["port"])
    outbound = {
        "type": "vmess", "tag": normalize_tag(value.get("ps"), host, port),
        "server": host, "server_port": port, "uuid": value["id"],
        "alter_id": int(value.get("aid", 0) or 0), "security": value.get("scy") or "auto",
    }
    if str(value.get("tls", "")).lower() in ("tls", "true", "1"):
        outbound["tls"] = _tls_block(value.get("sni") or value.get("host") or host)
    transport = _transport(value.get("net", "tcp"), value.get("host"), value.get("path"))
    if transport:
        outbound["transport"] = transport
    return outbound


def _query(url):
    return {key: value[0] for key, value in urllib.parse.parse_qs(url.query).items()}


def _parse_trojan(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    outbound = {
        "type": "trojan", "tag": normalize_tag(urllib.parse.unquote(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 443,
        "password": urllib.parse.unquote(url.username or ""),
        "tls": _tls_block(query.get("sni") or query.get("peer") or url.hostname,
                          query.get("allowInsecure") in ("1", "true")),
    }
    transport = _transport(query.get("type", "tcp"), query.get("host"), query.get("path"),
                           query.get("serviceName") or query.get("service_name"))
    if transport:
        outbound["transport"] = transport
    return outbound


def _parse_vless(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    outbound = {
        "type": "vless", "tag": normalize_tag(urllib.parse.unquote(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 443, "uuid": url.username,
        "flow": query.get("flow", ""),
    }
    if not outbound["flow"]:
        outbound.pop("flow")
    security = query.get("security")
    if security in ("tls", "reality", "xtls"):
        outbound["tls"] = _tls_block(query.get("sni") or url.hostname,
                                     query.get("allowInsecure") in ("1", "true"))
        if security == "reality":
            outbound["tls"]["reality"] = {
                "enabled": True, "public_key": query.get("pbk", ""), "short_id": query.get("sid", ""),
            }
        if query.get("fp"):
            outbound["tls"]["utls"] = {"enabled": True, "fingerprint": query["fp"]}
    transport = _transport(query.get("type", "tcp"), query.get("host"), query.get("path"),
                           query.get("serviceName") or query.get("service_name"))
    if transport:
        outbound["transport"] = transport
    return outbound


def _userinfo(url):
    value = url.username or ""
    if url.password is not None:
        value += ":" + url.password
    return urllib.parse.unquote(value)


def _insecure(query):
    return any(query.get(key) in ("1", "true") for key in ("insecure", "allowInsecure", "allow_insecure"))


def _parse_hysteria2(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    outbound = {
        "type": "hysteria2", "tag": normalize_tag(urllib.parse.unquote(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 443, "password": _userinfo(url),
        "tls": _tls_block(query.get("sni") or query.get("peer") or url.hostname, _insecure(query)),
    }
    if query.get("obfs"):
        outbound["obfs"] = {"type": query["obfs"], "password": query.get("obfs-password", "")}
    return outbound


def _parse_tuic(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    outbound = {
        "type": "tuic", "tag": normalize_tag(urllib.parse.unquote(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 443,
        "uuid": urllib.parse.unquote(url.username or ""), "password": urllib.parse.unquote(url.password or ""),
        "tls": _tls_block(query.get("sni") or url.hostname, _insecure(query)),
    }
    if query.get("alpn"):
        outbound["tls"]["alpn"] = query["alpn"].split(",")
    if query.get("congestion_control"):
        outbound["congestion_control"] = query["congestion_control"]
    if query.get("udp_relay_mode"):
        outbound["udp_relay_mode"] = query["udp_relay_mode"]
    return outbound


def _parse_anytls(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    return {
        "type": "anytls", "tag": normalize_tag(urllib.parse.unquote(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 443, "password": _userinfo(url),
        "tls": _tls_block(query.get("sni") or url.hostname, _insecure(query)),
    }


def _parse_socks(link):
    url = urllib.parse.urlparse(link)
    outbound = {
        "type": "socks", "tag": normalize_tag(urllib.parse.unquote(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 1080, "version": "5",
    }
    username = urllib.parse.unquote(url.username) if url.username else None
    password = urllib.parse.unquote(url.password) if url.password else None
    if username and password is None and ":" not in username:
        try:
            decoded = _b64(username)
            if ":" in decoded:
                username, password = decoded.split(":", 1)
        except Exception:
            pass
    if username:
        outbound["username"] = username
    if password:
        outbound["password"] = password
    return outbound


def _parse_http(link):
    url = urllib.parse.urlparse(link)
    outbound = {
        "type": "http", "tag": normalize_tag(urllib.parse.unquote(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or (443 if url.scheme == "https" else 80),
    }
    if url.username:
        outbound["username"] = urllib.parse.unquote(url.username)
    if url.password:
        outbound["password"] = urllib.parse.unquote(url.password)
    if url.scheme == "https":
        outbound["tls"] = _tls_block(url.hostname)
    return outbound
