#!/usr/bin/env python3
"""节点分享链接解析器，供 Telegram Bot 与 Web 管理 API 共用。"""
from __future__ import annotations

import base64
import json
import re
import unicodedata
import urllib.parse


def _truncate_utf8(value: str, max_bytes: int) -> str:
    while len(value.encode("utf-8")) > max_bytes:
        value = value[:-1]
    return value


def normalize_tag(name, host="", port=""):
    value = unicodedata.normalize("NFKC", str(name or f"{host}:{port}").strip())
    output = []
    for character in value:
        category = unicodedata.category(character)
        if character.isalnum() or character in "_.-" or category.startswith(("M", "S")):
            output.append(character)
        elif character.isspace():
            output.append("-")
        else:
            output.append("-")
    tag = re.sub(r"-+", "-", "".join(output)).strip("-.") or "exit"
    return _truncate_utf8(tag, 64)


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
    if link.startswith("hysteria://"):
        return _parse_hysteria(link)
    if link.startswith(("hysteria2://", "hy2://")):
        return _parse_hysteria2(link)
    if link.startswith("tuic://"):
        return _parse_tuic(link)
    if link.startswith("anytls://"):
        return _parse_anytls(link)
    if link.startswith("shadowtls://"):
        return _parse_shadowtls(link)
    if link.startswith("ssh://"):
        return _parse_ssh(link)
    if link.startswith(("socks://", "socks5://")):
        return _parse_socks(link)
    if link.startswith(("http://", "https://")):
        return _parse_http(link)
    if re.search(r"=\s*ss\s*,", link, re.I):
        return _parse_surge(link)
    raise ValueError("支持 ss/vmess/trojan/vless/hysteria/hysteria2/tuic/anytls/shadowtls/ssh/socks5/http 分享链接或 Surge ss 行")


def parse_subscription(data: bytes) -> tuple[list[dict], list[str]]:
    """解析 Clash YAML、Base64/纯文本 URI 列表或 SIP008 JSON。"""
    text = data.decode("utf-8-sig", "ignore").strip()
    if not text:
        raise ValueError("订阅内容为空")
    if text.lstrip().startswith(("<html", "<!doctype")):
        raise ValueError("订阅返回了 HTML 页面")

    if text.startswith("{"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError("订阅 JSON 格式错误") from error
        servers = value.get("servers") if isinstance(value, dict) else None
        if isinstance(servers, list):
            output, errors = [], []
            for index, item in enumerate(servers, 1):
                try:
                    host = str(item["server"])
                    port = int(item.get("server_port") or item["port"])
                    output.append({
                        "type": "shadowsocks",
                        "tag": normalize_tag(item.get("remarks") or item.get("tag"), host, port),
                        "server": host,
                        "server_port": port,
                        "method": str(item["method"]),
                        "password": str(item["password"]),
                    })
                except (KeyError, TypeError, ValueError):
                    errors.append(f"SIP008 第 {index} 项格式错误")
            if output:
                return output, errors
            raise ValueError("SIP008 没有可用节点")
        proxies = value.get("proxies") if isinstance(value, dict) else None
        if isinstance(proxies, list):
            return _parse_clash_proxies(proxies)

    if re.search(r"(?m)^proxies\s*:", text):
        return _parse_clash_proxies(_parse_clash_yaml(text))

    output, errors = _parse_subscription_lines(text)
    if output:
        return output, errors

    compact = re.sub(r"\s+", "", text)
    try:
        decoded = _b64(compact)
    except Exception as error:
        raise ValueError("订阅不是支持的 Clash YAML、URI/Base64 列表或 SIP008 JSON") from error
    output, decoded_errors = _parse_subscription_lines(decoded)
    if not output:
        raise ValueError("订阅中没有支持的节点")
    return output, decoded_errors


def _parse_subscription_lines(text: str) -> tuple[list[dict], list[str]]:
    output, errors = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line == "proxy-groups:" or line.startswith("proxy-groups:"):
            raise ValueError("订阅只有 Clash 策略组，没有可导入的 proxies 节点")
        try:
            output.append(parse_link(line))
        except Exception as error:  # 每行独立容错，错误文本不包含原始链接
            errors.append(f"第 {number} 行: {str(error)[:80]}")
    return output, errors


def _yaml_comment(value: str) -> str:
    quote = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if character in ("'", '"'):
            if quote == character:
                quote = None
            elif quote is None:
                quote = character
            continue
        if character == "#" and quote is None and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value.rstrip()


def _flow_parts(value: str, delimiter: str = ",") -> list[str]:
    parts, start, quote, escaped, depth = [], 0, None, False, 0
    pairs = {"[": "]", "{": "}"}
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if character in ("'", '"'):
            if quote == character:
                quote = None
            elif quote is None:
                quote = character
            continue
        if quote is not None:
            continue
        if character in pairs:
            depth += 1
        elif character in pairs.values():
            depth -= 1
        elif character == delimiter and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def _yaml_key_value(value: str) -> tuple[str, str]:
    quote, escaped, depth = None, False, 0
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if character in ("'", '"'):
            if quote == character:
                quote = None
            elif quote is None:
                quote = character
            continue
        if quote is not None:
            continue
        if character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
        elif character == ":" and depth == 0:
            return value[:index].strip(), value[index + 1:].strip()
    raise ValueError("Clash YAML 字段缺少冒号")


def _yaml_scalar(value: str):
    value = _yaml_comment(value).strip()
    if not value:
        return ""
    if value.startswith("{") and value.endswith("}"):
        output = {}
        for part in _flow_parts(value[1:-1]):
            if not part:
                continue
            key, item = _yaml_key_value(part)
            output[str(_yaml_scalar(key))] = _yaml_scalar(item)
        return output
    if value.startswith("[") and value.endswith("]"):
        return [_yaml_scalar(part) for part in _flow_parts(value[1:-1]) if part]
    if value.startswith('"') and value.endswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "~"):
        return None
    if re.fullmatch(r"[-+]?\d+", value):
        return int(value)
    return value


def _parse_yaml_mapping(lines: list[tuple[int, str]], list_indent: int) -> dict:
    first_indent, first = lines[0]
    if first.startswith("{"):
        value = _yaml_scalar(first)
        if not isinstance(value, dict):
            raise ValueError("Clash YAML 节点必须是对象")
        return value
    root = {}
    stack: list[tuple[int, dict | list]] = [(list_indent, root)]
    normalized = [(first_indent, first)] + lines[1:]
    for position, (indent, content) in enumerate(normalized):
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if content.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError("Clash YAML 列表缩进错误")
            parent.append(_yaml_scalar(content[2:].strip()))
            continue
        if not isinstance(parent, dict):
            raise ValueError("Clash YAML 对象缩进错误")
        key, raw = _yaml_key_value(content)
        key = str(_yaml_scalar(key))
        if raw:
            parent[key] = _yaml_scalar(raw)
            continue
        next_content = normalized[position + 1][1] if position + 1 < len(normalized) else ""
        child: dict | list = [] if next_content.startswith("- ") else {}
        parent[key] = child
        stack.append((indent, child))
    return root


def _parse_clash_yaml(text: str) -> list[dict]:
    raw_lines = text.splitlines()
    start = None
    base_indent = 0
    inline = ""
    for index, raw in enumerate(raw_lines):
        content = _yaml_comment(raw).strip()
        if re.fullmatch(r"proxies\s*:.*", content):
            key, inline = _yaml_key_value(content)
            if key != "proxies":
                continue
            start = index
            base_indent = len(raw) - len(raw.lstrip(" "))
            break
    if start is None:
        raise ValueError("Clash YAML 缺少 proxies")
    if inline:
        value = _yaml_scalar(inline)
        if not isinstance(value, list):
            raise ValueError("Clash YAML proxies 必须是数组")
        return value

    section: list[tuple[int, str]] = []
    for raw in raw_lines[start + 1:]:
        stripped = _yaml_comment(raw).strip()
        if not stripped:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= base_indent:
            break
        section.append((indent, stripped))
    if not section:
        raise ValueError("Clash YAML proxies 为空")
    list_indents = [indent for indent, content in section if content.startswith("- ")]
    if not list_indents:
        raise ValueError("Clash YAML proxies 格式错误")
    list_indent = min(list_indents)
    chunks: list[list[tuple[int, str]]] = []
    for indent, content in section:
        if indent == list_indent and content.startswith("- "):
            chunks.append([(indent + 2, content[2:].strip())])
        elif chunks:
            chunks[-1].append((indent, content))
    if not chunks:
        raise ValueError("Clash YAML proxies 格式错误")
    return [_parse_yaml_mapping(chunk, list_indent) for chunk in chunks]


def _clash_tls(item: dict, default: bool = False) -> dict | None:
    reality = item.get("reality-opts") if isinstance(item.get("reality-opts"), dict) else {}
    enabled = bool(item.get("tls", default) or reality)
    if not enabled:
        return None
    tls = _tls_block(
        str(item.get("servername") or item.get("sni") or item.get("peer") or item.get("server") or ""),
        bool(item.get("skip-cert-verify", False)),
    )
    alpn = item.get("alpn")
    if isinstance(alpn, str):
        alpn = [value.strip() for value in alpn.split(",") if value.strip()]
    if isinstance(alpn, list) and alpn:
        tls["alpn"] = [str(value) for value in alpn]
    fingerprint = item.get("client-fingerprint") or item.get("fingerprint")
    if reality:
        if not reality.get("public-key"):
            raise ValueError("Reality 缺少 public-key")
        tls["reality"] = {
            "enabled": True, "public_key": str(reality["public-key"]),
            "short_id": str(reality.get("short-id", "")),
        }
        fingerprint = fingerprint or "chrome"
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": str(fingerprint)}
    return tls


def _clash_transport(item: dict) -> dict | None:
    network = str(item.get("network") or item.get("net") or "tcp").lower()
    if network in ("ws", "websocket"):
        options = item.get("ws-opts") if isinstance(item.get("ws-opts"), dict) else {}
        headers = options.get("headers") if isinstance(options.get("headers"), dict) else {}
        host = headers.get("Host") or headers.get("host")
        return _transport("ws", str(host or ""), str(options.get("path") or "/"))
    if network == "grpc":
        options = item.get("grpc-opts") if isinstance(item.get("grpc-opts"), dict) else {}
        service = options.get("grpc-service-name") or options.get("service-name")
        return _transport("grpc", "", "", str(service or ""))
    return None


def _clash_rate(value, name: str) -> int | None:
    if value in (None, ""):
        return None
    matched = re.fullmatch(r"\s*(\d+)(?:\s*mbps)?\s*", str(value), re.I)
    if not matched:
        raise ValueError(f"Clash {name} 必须是 Mbps 整数")
    return int(matched.group(1))


def _clash_outbound(item: dict) -> dict:
    if not isinstance(item, dict):
        raise ValueError("节点不是对象")
    kind = str(item.get("type", "")).lower()
    aliases = {"ss": "shadowsocks", "socks5": "socks", "hy2": "hysteria2"}
    kind = aliases.get(kind, kind)
    server = str(item.get("server", "")).strip()
    name = str(item.get("name", "")).strip()
    if not kind or not server or not name:
        raise ValueError("缺少 name/type/server")
    try:
        port = int(item.get("port") or item.get("server-port"))
    except (TypeError, ValueError) as error:
        raise ValueError("port 格式错误") from error
    if not 1 <= port <= 65535:
        raise ValueError("port 超出范围")
    outbound = {"type": kind, "tag": normalize_tag(name, server, port), "server": server, "server_port": port}

    if kind == "shadowsocks":
        if item.get("plugin"):
            raise ValueError("暂不支持带 plugin 的 Shadowsocks 节点")
        outbound.update({"method": str(item.get("cipher", "")), "password": str(item.get("password", ""))})
    elif kind == "vmess":
        outbound.update({
            "uuid": str(item.get("uuid", "")), "alter_id": int(item.get("alterId") or item.get("alter-id") or 0),
            "security": str(item.get("cipher") or "auto"),
        })
        tls = _clash_tls(item)
        if tls:
            outbound["tls"] = tls
        transport = _clash_transport(item)
        if transport:
            outbound["transport"] = transport
    elif kind in ("trojan", "vless"):
        outbound["password" if kind == "trojan" else "uuid"] = str(
            (item.get("password") or "") if kind == "trojan" else (item.get("uuid") or "")
        )
        if kind == "vless" and item.get("flow"):
            outbound["flow"] = str(item["flow"])
        tls = _clash_tls(item, default=kind == "trojan")
        if tls:
            outbound["tls"] = tls
        transport = _clash_transport(item)
        if transport:
            outbound["transport"] = transport
    elif kind == "hysteria":
        auth = item.get("auth-str") or item.get("auth") or item.get("password")
        if auth:
            outbound["auth_str"] = str(auth)
        for field, source in (("up_mbps", "up"), ("down_mbps", "down")):
            rate = _clash_rate(item.get(source) or item.get(source + "-mbps"), source)
            if rate is not None:
                outbound[field] = rate
        if item.get("obfs"):
            outbound["obfs"] = str(item["obfs"])
        outbound["tls"] = _clash_tls(item, default=True)
    elif kind == "hysteria2":
        outbound["password"] = str(item.get("password") or item.get("auth") or "")
        if item.get("obfs"):
            outbound["obfs"] = {
                "type": str(item["obfs"]), "password": str(item.get("obfs-password", "")),
            }
        outbound["tls"] = _clash_tls(item, default=True)
    elif kind == "tuic":
        outbound.update({"uuid": str(item.get("uuid", "")), "password": str(item.get("password", ""))})
        if item.get("congestion-controller"):
            outbound["congestion_control"] = str(item["congestion-controller"])
        if item.get("udp-relay-mode"):
            outbound["udp_relay_mode"] = str(item["udp-relay-mode"])
        outbound["tls"] = _clash_tls(item, default=True)
    elif kind == "anytls":
        outbound["password"] = str(item.get("password", ""))
        outbound["tls"] = _clash_tls(item, default=True)
    elif kind == "shadowtls":
        outbound["version"] = int(item.get("version") or 3)
        if item.get("password"):
            outbound["password"] = str(item["password"])
        outbound["tls"] = _clash_tls(item, default=True)
    elif kind == "ssh":
        outbound.update({"user": str(item.get("username") or item.get("user") or ""),
                         "password": str(item.get("password", ""))})
        if not outbound["user"] or not outbound["password"]:
            raise ValueError("SSH 节点只支持用户名和密码认证")
    elif kind == "socks":
        outbound["version"] = "5"
        if item.get("username"):
            outbound["username"] = str(item["username"])
        if item.get("password"):
            outbound["password"] = str(item["password"])
    elif kind == "http":
        if item.get("username"):
            outbound["username"] = str(item["username"])
        if item.get("password"):
            outbound["password"] = str(item["password"])
        tls = _clash_tls(item)
        if tls:
            outbound["tls"] = tls
    else:
        raise ValueError(f"不支持 {kind or '未知'} 协议")

    required = {
        "shadowsocks": ("method", "password"), "vmess": ("uuid",), "trojan": ("password",),
        "vless": ("uuid",), "hysteria2": ("password",), "tuic": ("uuid", "password"),
        "anytls": ("password",),
    }.get(kind, ())
    missing = [field for field in required if not outbound.get(field)]
    if missing:
        raise ValueError("缺少 " + "/".join(missing))
    return outbound


def _parse_clash_proxies(proxies: list) -> tuple[list[dict], list[str]]:
    output, errors = [], []
    for index, item in enumerate(proxies, 1):
        try:
            output.append(_clash_outbound(item))
        except (TypeError, ValueError) as error:
            name = item.get("name") if isinstance(item, dict) else None
            label = normalize_tag(name) if name else f"第 {index} 项"
            errors.append(f"Clash {label}: {str(error)[:80]}")
    if not output:
        raise ValueError("Clash YAML 没有可用节点")
    return output, errors


def _b64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "ignore")


def _decode_tag(value):
    return urllib.parse.unquote_plus(str(value or "")).strip()


def _parse_ss(link):
    body = link[5:]
    tag = ""
    if "#" in body:
        body, tag = body.split("#", 1)
        tag = _decode_tag(tag)
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
        "type": "trojan", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
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
        "type": "vless", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
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
            outbound["tls"]["utls"] = {
                "enabled": True, "fingerprint": query.get("fp") or query.get("fingerprint") or "chrome",
            }
        elif query.get("fp") or query.get("fingerprint"):
            outbound["tls"]["utls"] = {
                "enabled": True, "fingerprint": query.get("fp") or query["fingerprint"],
            }
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


def _parse_hysteria(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    auth = _userinfo(url) or query.get("auth") or query.get("auth_str") or ""
    outbound = {
        "type": "hysteria", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 443,
        "tls": _tls_block(query.get("sni") or query.get("peer") or url.hostname, _insecure(query)),
    }
    if auth:
        outbound["auth_str"] = auth
    aliases = {
        "up_mbps": ("upmbps", "up_mbps"),
        "down_mbps": ("downmbps", "down_mbps"),
        "recv_window_conn": ("recv_window_conn", "recvwindowconn"),
        "recv_window": ("recv_window", "recvwindow"),
    }
    for field, names in aliases.items():
        value = next((query[name] for name in names if query.get(name)), None)
        if value is not None:
            try:
                outbound[field] = int(value)
            except ValueError as error:
                raise ValueError(f"hysteria {field} 必须是整数") from error
    if query.get("obfs"):
        outbound["obfs"] = query["obfs"]
    if query.get("alpn"):
        outbound["tls"]["alpn"] = query["alpn"].split(",")
    if query.get("disable_mtu_discovery") in ("1", "true"):
        outbound["disable_mtu_discovery"] = True
    return outbound


def _parse_hysteria2(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    outbound = {
        "type": "hysteria2", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
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
        "type": "tuic", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
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
        "type": "anytls", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 443, "password": _userinfo(url),
        "tls": _tls_block(query.get("sni") or url.hostname, _insecure(query)),
    }


def _parse_shadowtls(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    try:
        version = int(query.get("version", "3"))
    except ValueError as error:
        raise ValueError("shadowtls version 必须是整数") from error
    outbound = {
        "type": "shadowtls", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 443, "version": version,
        "tls": _tls_block(query.get("sni") or query.get("peer") or url.hostname, _insecure(query)),
    }
    password = _userinfo(url) or query.get("password", "")
    if password:
        outbound["password"] = password
    fingerprint = query.get("fp") or query.get("fingerprint")
    if fingerprint:
        outbound["tls"]["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if query.get("alpn"):
        outbound["tls"]["alpn"] = query["alpn"].split(",")
    return outbound


def _parse_ssh(link):
    url = urllib.parse.urlparse(link)
    query = _query(url)
    user = urllib.parse.unquote(url.username or "")
    password = urllib.parse.unquote(url.password or "")
    if not user or not password:
        raise ValueError("ssh 链接必须包含用户名和密码")
    outbound = {
        "type": "ssh", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or 22, "user": user, "password": password,
    }
    if query.get("host_key"):
        outbound["host_key"] = [value for value in query["host_key"].split(",") if value]
    if query.get("client_version"):
        outbound["client_version"] = query["client_version"]
    return outbound


def _parse_socks(link):
    url = urllib.parse.urlparse(link)
    outbound = {
        "type": "socks", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
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
        "type": "http", "tag": normalize_tag(_decode_tag(url.fragment), url.hostname, url.port),
        "server": url.hostname, "server_port": url.port or (443 if url.scheme == "https" else 80),
    }
    if url.username:
        outbound["username"] = urllib.parse.unquote(url.username)
    if url.password:
        outbound["password"] = urllib.parse.unquote(url.password)
    if url.scheme == "https":
        outbound["tls"] = _tls_block(url.hostname)
    return outbound
