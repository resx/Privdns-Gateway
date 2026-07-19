#!/usr/bin/env python3
"""PrivDNS Gateway 管理业务服务，供 Bot 与 Web API 复用。"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows test environment
    fcntl = None

from pdg_control import (
    SingBoxControl,
    GROUP_TYPES,
    PROXY_TYPES,
    concrete_tags,
    deletable_tags,
    delete_outbound,
    exit_tags,
    outbound_impact,
    proxy_outbounds,
)
from pdg_links import normalize_tag, parse_link, parse_subscription


URLTEST_URL = "https://www.gstatic.com/generate_204"
TEST_TARGETS = {
    "google": URLTEST_URL,
    "cloudflare": "https://cp.cloudflare.com/generate_204",
    "apple": "https://www.apple.com/library/test/success.html",
}
OVERRIDE_PROPERTIES = {"tcp_fast_open", "udp_fragment"}
IOS_ACCESS_TTL = 600
IOS_ACCESS_STATE = "/opt/pdg-bot/ios-www/.ios-access.json"
IOS_NFT_SET = "pdg_dns_panel_hosts"


class ServiceError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class GatewayService:
    def __init__(
        self,
        control: SingBoxControl | None = None,
        direct_path: str = "/etc/mosdns/rules/custom_direct.txt",
        ruleset_meta_path: str = "/opt/pdg-bot/rulesets.json",
        clash_url: str = "http://127.0.0.1:9090",
        ruleset_dir: str = "/etc/sing-box/rs",
        subscription_meta_path: str = "/opt/pdg-bot/subscriptions.json",
        rule_order_marker_path: str = "/etc/privdns-gateway/rule-order.custom",
        ios_access_path: str = IOS_ACCESS_STATE,
    ) -> None:
        self.control = control or SingBoxControl()
        self.direct_path = direct_path
        self.ruleset_meta_path = ruleset_meta_path
        self.clash_url = clash_url.rstrip("/")
        self.ruleset_dir = ruleset_dir
        self.subscription_meta_path = subscription_meta_path
        self.rule_order_marker_path = rule_order_marker_path
        self.ios_access_path = ios_access_path
        self._metadata_lock = threading.RLock()

    def _run(self, command):
        return self.control.runner(command)

    @staticmethod
    def _mask_host(host) -> str:
        host = str(host or "?")
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            parts = host.split(".")
            return f"{parts[0]}.*.*.{parts[-1]}"
        parts = host.split(".")
        if len(parts) >= 2:
            return parts[0][:3] + "***." + parts[-1]
        return host[:3] + "***"

    @staticmethod
    def _check_result(result: tuple[bool, str]) -> None:
        ok, message = result
        if not ok:
            raise ServiceError(message, 409)

    def overview(self) -> dict:
        config = self.control.load()
        services = {}
        for name in ("mosdns", "sing-box", "pdg-bot", "pdg-admin"):
            result = self._run(["systemctl", "is-active", name])
            services[name] = result.stdout.strip() or "unknown"
        proxy_count = len(proxy_outbounds(config))
        groups = sum(1 for item in config.get("outbounds", []) if item.get("type") in GROUP_TYPES)
        rules = len(self.list_rules())
        return {
            "services": services,
            "default_exit": config.get("route", {}).get("final"),
            "proxy_count": proxy_count,
            "group_count": groups,
            "rule_count": rules,
        }

    @contextmanager
    def _locked_ios_access(self):
        path = Path(self.ios_access_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._metadata_lock, open(str(path) + ".lock", "a+", encoding="ascii") as lock:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _load_ios_access(self) -> dict:
        try:
            value = json.loads(Path(self.ios_access_path).read_text(encoding="ascii"))
        except (OSError, json.JSONDecodeError):
            value = {}
        hosts = []
        for raw in value.get("hosts", []) if isinstance(value, dict) else []:
            try:
                hosts.append(str(ipaddress.ip_address(raw)))
            except ValueError:
                continue
        try:
            open_until = max(0.0, float(value.get("open_until", 0))) if isinstance(value, dict) else 0.0
        except (TypeError, ValueError):
            open_until = 0.0
        return {"open_until": open_until, "hosts": sorted(set(hosts))}

    def _save_ios_access(self, value: dict) -> None:
        path = Path(self.ios_access_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".ios-access-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                json.dump(value, handle, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    @staticmethod
    def _ios_access_result(state: dict, now: float) -> dict:
        return {
            "open": state["open_until"] > now,
            "open_until": state["open_until"],
            "remaining_seconds": max(0, int(state["open_until"] - now)),
            "hosts": state["hosts"],
        }

    def ios_access_status(self) -> dict:
        with self._locked_ios_access():
            state = self._load_ios_access()
            now = time.time()
            if state["open_until"] <= now and state["open_until"] != 0:
                state["open_until"] = 0
                self._save_ios_access(state)
            return self._ios_access_result(state, now)

    def open_ios_access(self, minutes: int = 10) -> dict:
        try:
            minutes = int(minutes)
        except (TypeError, ValueError) as error:
            raise ServiceError("放行时长必须是整数") from error
        if not 1 <= minutes <= 30:
            raise ServiceError("放行时长必须在 1-30 分钟之间")
        with self._locked_ios_access():
            state = self._load_ios_access()
            now = time.time()
            state["open_until"] = now + minutes * 60
            self._save_ios_access(state)
            return self._ios_access_result(state, now)

    def close_ios_access(self) -> dict:
        with self._locked_ios_access():
            state = self._load_ios_access()
            state["open_until"] = 0
            self._save_ios_access(state)
            return self._ios_access_result(state, time.time())

    def _sync_ios_firewall(self, state: dict) -> None:
        if os.environ.get("PDG_IOS_NFT_SYNC") != "1":
            return
        hosts = [host for host in state["hosts"] if ipaddress.ip_address(host).version == 4]
        rules = [f"flush set inet pdg {IOS_NFT_SET}"]
        if hosts:
            rules.append(f"add element inet pdg {IOS_NFT_SET} {{ {', '.join(hosts)} }}")
        try:
            result = subprocess.run(
                ["nft", "-f", "-"], input="\n".join(rules) + "\n",
                text=True, capture_output=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ServiceError("DNS/管理面板白名单同步失败", 503) from error
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "nft 执行失败").strip()
            raise ServiceError("DNS/管理面板白名单同步失败: " + message[:200], 503)

    def revoke_ios_host(self, host: str) -> dict:
        if host.lower() == "all":
            with self._locked_ios_access():
                state = {"open_until": 0, "hosts": []}
                self._sync_ios_firewall(state)
                self._save_ios_access(state)
                return self._ios_access_result(state, time.time())
        try:
            normalized = str(ipaddress.ip_address(host))
        except ValueError as error:
            raise ServiceError("IP 地址无效") from error
        with self._locked_ios_access():
            state = self._load_ios_access()
            state["hosts"] = [item for item in state["hosts"] if item != normalized]
            self._sync_ios_firewall(state)
            self._save_ios_access(state)
            return self._ios_access_result(state, time.time())

    def list_exits(self) -> list[dict]:
        config = self.control.load()
        final = config.get("route", {}).get("final")
        ownership = {}
        for identifier, info in self._subscription_meta().items():
            owner = {
                "source": "subscription", "subscription_id": identifier,
                "subscription_label": info.get("label") or identifier,
            }
            aliases = info.get("node_aliases", {}) if isinstance(info.get("node_aliases", {}), dict) else {}
            for tag in info.get("nodes", []):
                ownership[tag] = {**owner, "source_group": None, "custom_name": tag in aliases.values()}
            for group in info.get("groups", []):
                if group.get("tag"):
                    ownership[group["tag"]] = {**owner, "source_group": group.get("label")}
            if info.get("group"):
                ownership.setdefault(info["group"], {**owner, "source_group": "全部节点"})
        output = []
        for item in config.get("outbounds", []):
            tag = item.get("tag")
            if tag not in exit_tags(config):
                continue
            impact = outbound_impact(config, tag)
            owner = ownership.get(tag, {})
            source = owner.get("source") or ("system" if item.get("type") == "direct" else "manual")
            output.append({
                "tag": tag,
                "type": item.get("type"),
                "source": source,
                "subscription_id": owner.get("subscription_id"),
                "subscription_label": owner.get("subscription_label"),
                "source_group": owner.get("source_group"),
                "custom_name": bool(owner.get("custom_name", False)),
                "name_source": "订阅自定义" if owner.get("custom_name") else ("订阅原名" if source == "subscription" else ("系统" if source == "system" else "手动")),
                "server": self._mask_host(item.get("server")) if item.get("server") else None,
                "server_port": item.get("server_port"),
                "tls": bool(item.get("tls", {}).get("enabled")),
                "members": item.get("outbounds", []) if item.get("type") in GROUP_TYPES else [],
                "mode": "manual" if item.get("type") == "selector" else ("auto" if item.get("type") == "urltest" else None),
                "selected": item.get("default") if item.get("type") == "selector" else None,
                "default": tag == final,
                "deletable": tag in deletable_tags(config),
                "references": len(impact["groups"]) + len(impact["rules"])
                              + int(impact["final"]) + int(impact["telegram"]),
            })
        return output

    @staticmethod
    def _display_name(value: str, fallback: str) -> str:
        name = normalize_tag(value.strip() or fallback)
        if name in {"direct", "block", "dns-out"}:
            raise ServiceError(f"节点名称 {name} 是保留名称")
        return name

    def _outbound_preview(self, outbound: dict) -> dict:
        config = self.control.load()
        return {
            "tag": outbound["tag"],
            "type": outbound["type"],
            "server": self._mask_host(outbound.get("server")),
            "server_port": outbound.get("server_port"),
            "tls": bool(outbound.get("tls", {}).get("enabled")),
            "replacing": any(item.get("tag") == outbound["tag"] for item in config.get("outbounds", [])),
        }

    def preview_link(self, link: str, name: str = "") -> dict:
        outbound = parse_link(link)
        if name.strip():
            outbound["tag"] = self._display_name(name, str(outbound["tag"]))
        return self._outbound_preview(outbound)

    def add_outbound(self, outbound: dict, name: str = "") -> dict:
        outbound = json.loads(json.dumps(outbound))
        if outbound.get("type") not in PROXY_TYPES or not outbound.get("tag"):
            raise ServiceError("出口类型或名称无效")
        if name.strip():
            outbound["tag"] = self._display_name(name, str(outbound["tag"]))
        preview = self._outbound_preview(outbound)

        def modify(config):
            config["outbounds"] = [
                item for item in config.get("outbounds", []) if item.get("tag") != outbound["tag"]
            ]
            config["outbounds"].append(outbound)

        self._check_result(self.control.apply(modify))
        return preview

    def add_exit(self, link: str, name: str = "") -> dict:
        return self.add_outbound(parse_link(link), name)

    def _subscription_meta(self) -> dict:
        try:
            value = json.loads(Path(self.subscription_meta_path).read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_subscription_meta(self, value: dict) -> None:
        path = Path(self.subscription_meta_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".pdg-subscriptions-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    @staticmethod
    def _subscription_url(url: str) -> str:
        url = url.strip()
        if len(url) > 4096 or any(ord(character) < 32 for character in url):
            raise ServiceError("节点订阅 URL 格式不正确")
        try:
            parsed = urllib.parse.urlparse(url)
            host = (parsed.hostname or "").lower()
            parsed.port
        except ValueError as error:
            raise ServiceError("节点订阅 URL 格式不正确") from error
        if parsed.scheme not in ("http", "https") or not host:
            raise ServiceError("节点订阅 URL 只支持 http/https")
        if host == "localhost" or host.endswith(".localhost"):
            raise ServiceError("节点订阅 URL 不允许本机地址")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address and (address.is_private or address.is_loopback or address.is_link_local
                        or address.is_multicast or address.is_reserved or address.is_unspecified):
            raise ServiceError("节点订阅 URL 不允许私有或保留地址")
        return url

    @staticmethod
    def _require_public_subscription_host(url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        try:
            addresses = {
                item[4][0] for item in socket.getaddrinfo(
                    parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM,
                )
            }
        except OSError as error:
            raise ServiceError("节点订阅域名解析失败") from error
        if not addresses:
            raise ServiceError("节点订阅域名没有可用地址")
        for value in addresses:
            address = ipaddress.ip_address(value)
            if (address.is_private or address.is_loopback or address.is_link_local
                    or address.is_multicast or address.is_reserved or address.is_unspecified):
                raise ServiceError("节点订阅域名解析到私有或保留地址")

    @staticmethod
    def _masked_subscription_url(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "?"
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or "/"
        return urllib.parse.urlunparse((parsed.scheme, host + port, path, "", "***" if parsed.query else "", ""))

    @staticmethod
    def _subscription_id(url: str) -> str:
        return "sub_" + hashlib.sha1(url.encode()).hexdigest()[:8]

    @staticmethod
    def _subscription_regex(value: str, label: str) -> re.Pattern | None:
        value = value.strip()
        if not value:
            return None
        if len(value) > 200:
            raise ServiceError(f"{label}正则过长")
        try:
            return re.compile(value, re.I)
        except re.error as error:
            raise ServiceError(f"{label}正则无效: {error}") from error

    def _normalize_subscription_overrides(self, overrides: dict | None) -> dict:
        if overrides in (None, {}):
            return {"types": [], "rename": [], "sort": "source", "properties": {}}
        if not isinstance(overrides, dict):
            raise ServiceError("订阅覆写必须是对象")
        raw_types = overrides.get("types", [])
        if not isinstance(raw_types, list):
            raise ServiceError("协议过滤必须是数组")
        types = list(dict.fromkeys(str(value).strip() for value in raw_types if str(value).strip()))
        unknown = [value for value in types if value not in PROXY_TYPES]
        if unknown:
            raise ServiceError("不支持的协议过滤: " + ", ".join(unknown))
        raw_rename = overrides.get("rename", [])
        if not isinstance(raw_rename, list) or len(raw_rename) > 12:
            raise ServiceError("重命名覆写必须是数组且最多 12 项")
        rename = []
        for item in raw_rename:
            if not isinstance(item, dict):
                raise ServiceError("重命名覆写格式错误")
            pattern = str(item.get("pattern", "")).strip()
            replacement = str(item.get("replacement", ""))
            if not pattern:
                raise ServiceError("重命名正则不能为空")
            self._subscription_regex(pattern, "重命名")
            if len(replacement) > 100:
                raise ServiceError("重命名替换文本过长")
            rename.append({"pattern": pattern, "replacement": replacement})
        sort = str(overrides.get("sort", "source"))
        if sort not in {"source", "name"}:
            raise ServiceError("节点排序仅支持 source 或 name")
        raw_properties = overrides.get("properties", {})
        if not isinstance(raw_properties, dict):
            raise ServiceError("节点属性覆写必须是对象")
        properties = {}
        for name, value in raw_properties.items():
            if name not in OVERRIDE_PROPERTIES or not isinstance(value, bool):
                raise ServiceError(f"节点属性覆写无效: {name}")
            properties[name] = value
        return {"types": types, "rename": rename, "sort": sort, "properties": properties}

    @staticmethod
    def _subscription_title(headers) -> str:
        raw = str(headers.get("profile-title", "")).strip()
        if not raw:
            return ""
        if raw.lower().startswith("base64:"):
            encoded = raw[7:].strip()
            try:
                raw = base64.b64decode(
                    encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True,
                ).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                return ""
        return urllib.parse.unquote(raw).strip()[:40]

    def _fetch_subscription(self, url: str) -> tuple[bytes, str]:
        self._require_public_subscription_host(url)
        request = urllib.request.Request(url, headers={"User-Agent": "privdns-gateway-subscription"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                final_url = self._subscription_url(response.geturl())
                self._require_public_subscription_host(final_url)
                title = self._subscription_title(response.headers)
                data = response.read(8 * 1024 * 1024 + 1)
        except ServiceError:
            raise
        except Exception as error:
            raise ServiceError("节点订阅下载失败") from error
        if not data:
            raise ServiceError("节点订阅响应为空")
        if len(data) > 8 * 1024 * 1024:
            raise ServiceError("节点订阅超过 8MB 限制")
        return data, title

    @staticmethod
    def _outbound_digest(outbound: dict) -> str:
        value = {key: item for key, item in outbound.items() if key != "tag"}
        return hashlib.sha1(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    @staticmethod
    def _outbound_identity(outbound: dict) -> str:
        tls = outbound.get("tls") if isinstance(outbound.get("tls"), dict) else {}
        transport = outbound.get("transport") if isinstance(outbound.get("transport"), dict) else {}
        identity = {
            "type": outbound.get("type"), "server": outbound.get("server"),
            "server_port": outbound.get("server_port"),
            "tls_server_name": tls.get("server_name"),
            "transport_type": transport.get("type"),
            "transport_path": transport.get("path"),
            "transport_service_name": transport.get("service_name"),
        }
        return hashlib.sha1(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    @staticmethod
    def _tag_with_suffix(base: str, suffix: str) -> str:
        while len((base + suffix).encode("utf-8")) > 64:
            base = base[:-1]
        return base.rstrip("-.") + suffix

    @classmethod
    def _subscription_tag(cls, outbound: dict, used: dict[str, str | None]) -> str:
        base = normalize_tag(str(outbound.get("tag", "node")))
        digest = cls._outbound_digest(outbound)
        if base not in used:
            used[base] = digest
            return base
        if used[base] == digest:
            return base
        tag = cls._tag_with_suffix(base, "-" + digest[:6])
        sequence = 2
        while tag in used and used[tag] != digest:
            tag = cls._tag_with_suffix(base, f"-{digest[:6]}-{sequence}")
            sequence += 1
        used[tag] = digest
        return tag

    def _normalize_categories(self, categories: list[dict] | None) -> list[dict]:
        if categories in (None, []):
            return []
        if not isinstance(categories, list) or len(categories) > 12:
            raise ServiceError("节点分类必须是数组且最多 12 项")
        output, names = [], set()
        for item in categories:
            if not isinstance(item, dict):
                raise ServiceError("节点分类格式错误")
            name = str(item.get("name", "")).strip()[:30]
            pattern = str(item.get("pattern", "")).strip()
            if not name or not pattern:
                raise ServiceError("节点分类名称和正则不能为空")
            normalized = name.casefold()
            if normalized in names:
                raise ServiceError(f"节点分类名称重复: {name}")
            self._subscription_regex(pattern, f"分类 {name} ")
            names.add(normalized)
            output.append({"name": name, "pattern": pattern})
        return output

    @staticmethod
    def _group_tag(value: str, fallback: str = "") -> str:
        value = unicodedata.normalize("NFKC", value.strip() or fallback.strip())
        output = []
        for character in value:
            category = unicodedata.category(character)
            if character.isalnum() or character in "_.-" or category.startswith("S"):
                output.append(character)
            elif character.isspace():
                output.append("-")
            elif category.startswith("M") and output:
                output.append(character)
            else:
                output.append("-")
        tag = re.sub(r"-+", "-", "".join(output)).strip("-.")
        if not tag:
            raise ServiceError("节点组名称必须包含文字或数字")
        while len(tag.encode("utf-8")) > 64:
            tag = tag[:-1]
        return tag

    def _subscription_groups(
        self, identifier: str, master_tag: str, outbounds: list[dict], named_tags: list[tuple[str, str]],
        categories: list[dict] | None,
    ) -> list[dict]:
        groups = [{
            "tag": master_tag, "label": "全部节点",
            "members": [item["tag"] for item in outbounds], "count": len(outbounds), "master": True,
        }]
        occupied = {master_tag, *(item["tag"] for item in outbounds)}
        for category in self._normalize_categories(categories):
            base = self._group_tag(f"{master_tag}-{category['name']}")
            tag = base
            sequence = 2
            while tag in occupied:
                tag = self._tag_with_suffix(base, f"-{sequence}")
                sequence += 1
            occupied.add(tag)
            matcher = self._subscription_regex(category["pattern"], f"分类 {category['name']} ")
            members = [node_tag for original, node_tag in named_tags if matcher and matcher.search(original)]
            groups.append({
                "tag": tag, "label": category["name"], "members": members,
                "count": len(members), "master": False,
            })
        return groups

    @staticmethod
    def _group_outbound(tag: str, members: list[str], existing: dict | None = None) -> dict:
        if existing and existing.get("type") == "selector" and existing.get("default") in members:
            return {
                "type": "selector", "tag": tag, "outbounds": members,
                "default": existing["default"], "interrupt_exist_connections": True,
            }
        return {
            "type": "urltest", "tag": tag, "outbounds": members,
            "url": URLTEST_URL, "interval": "3m", "tolerance": 50,
        }

    def _prepare_subscription(
        self,
        url: str,
        label: str = "",
        include: str = "",
        exclude: str = "",
        group: str = "",
        identifier: str | None = None,
        categories: list[dict] | None = None,
        overrides: dict | None = None,
        fallback_label: str = "",
    ) -> dict:
        url = self._subscription_url(url)
        identifier = identifier or self._subscription_id(url)
        include_re = self._subscription_regex(include, "包含")
        exclude_re = self._subscription_regex(exclude, "排除")
        normalized_overrides = self._normalize_subscription_overrides(overrides)
        try:
            subscription_data, remote_label = self._fetch_subscription(url)
            parsed, errors = parse_subscription(subscription_data)
        except ValueError as error:
            raise ServiceError(str(error)) from error
        if len(parsed) > 500:
            raise ServiceError("单个订阅最多允许 500 个节点")

        meta = self._subscription_meta()
        previous = meta.get(identifier, {})
        aliases = previous.get("node_aliases", {})
        if not isinstance(aliases, dict):
            aliases = {}
        selected = []
        for outbound in parsed:
            original_name = str(outbound.get("tag", ""))
            if normalized_overrides["types"] and outbound.get("type") not in normalized_overrides["types"]:
                continue
            if include_re and not include_re.search(original_name):
                continue
            if exclude_re and exclude_re.search(original_name):
                continue
            name = original_name
            for rule in normalized_overrides["rename"]:
                replacement = re.sub(r"\$(\d+)", r"\\g<\1>", rule["replacement"])
                name = re.sub(rule["pattern"], replacement, name, flags=re.I)
            name = name.strip() or original_name
            selected.append((outbound, name))
        if normalized_overrides["sort"] == "name":
            selected.sort(key=lambda item: item[1].casefold())
        if not selected:
            raise ServiceError("订阅过滤后没有可用节点，未修改现有配置")

        old_nodes = set(previous.get("nodes", []))
        current_outbounds = self.control.load().get("outbounds", [])
        used: dict[str, str | None] = {
            str(item.get("tag")): None for item in current_outbounds
            if item.get("tag") and item.get("tag") not in old_nodes
        }
        outbounds, named_tags = [], []
        for outbound, display_name in selected:
            value = json.loads(json.dumps(outbound))
            value["tag"] = display_name
            for property_name, enabled in normalized_overrides["properties"].items():
                if property_name == "tcp_fast_open" and enabled and value.get("type") == "anytls":
                    continue
                value[property_name] = enabled
            alias = aliases.get(self._outbound_identity(value))
            if alias:
                display_name = self._display_name(str(alias), display_name)
            value["tag"] = display_name
            tag = self._subscription_tag(value, used)
            if any(item.get("tag") == tag for item in outbounds):
                continue
            value["tag"] = tag
            outbounds.append(value)
            named_tags.append((display_name, tag))
        if not outbounds:
            raise ServiceError("订阅没有可应用的唯一节点")

        label_input = label.strip()[:40]
        clean_label = (
            label_input or remote_label or fallback_label.strip()[:40]
            or urllib.parse.urlparse(url).hostname or identifier
        )
        group_input = group.strip()
        group_tag = self._group_tag(group_input, clean_label)
        if group_tag in {item["tag"] for item in outbounds}:
            raise ServiceError("订阅分类组名称与节点冲突")

        current = {item.get("tag"): item for item in current_outbounds}
        new_nodes = {item["tag"]: item for item in outbounds}
        added = sorted(tag for tag in new_nodes if tag not in current)
        updated = sorted(tag for tag, item in new_nodes.items() if tag in current and current[tag] != item)
        removed = sorted(old_nodes - set(new_nodes))
        previews = [{
            "tag": item["tag"], "type": item.get("type"),
            "server": self._mask_host(item.get("server")), "server_port": item.get("server_port"),
        } for item in outbounds[:30]]
        return {
            "id": identifier, "url": url, "url_display": self._masked_subscription_url(url),
            "label": clean_label, "label_input": label_input,
            "include": include.strip(), "exclude": exclude.strip(),
            "group": group_tag, "group_input": group_input, "outbounds": outbounds, "nodes": previews,
            "count": len(outbounds), "skipped": len(errors) + len(parsed) - len(selected),
            "added": added, "updated": updated, "removed": removed,
            "groups": self._subscription_groups(identifier, group_tag, outbounds, named_tags, categories),
            "node_aliases": {str(key): self._display_name(str(value), "node") for key, value in aliases.items() if str(value).strip()},
            "category_input": self._normalize_categories(categories),
            "override_input": normalized_overrides,
        }

    @staticmethod
    def _stored_label_input(info: dict) -> str:
        if "label_input" in info:
            return str(info.get("label_input", ""))
        label = str(info.get("label", ""))
        host = urllib.parse.urlparse(str(info.get("url", ""))).hostname or ""
        return "" if label == host else label

    @classmethod
    def _stored_group_input(cls, identifier: str, info: dict) -> str:
        if "group_input" in info:
            return str(info.get("group_input", ""))
        group = str(info.get("group", ""))
        automatic = {identifier + "-auto"}
        label = str(info.get("label", ""))
        if label:
            automatic.add(cls._group_tag(label))
        return "" if group in automatic else group

    @staticmethod
    def _public_subscription(identifier: str, info: dict) -> dict:
        url = str(info.get("url", ""))
        parsed = urllib.parse.urlparse(url)
        masked = GatewayService._masked_subscription_url(url) if parsed.scheme else ""
        return {
            "id": identifier, "label": info.get("label") or identifier,
            "custom_label": bool(GatewayService._stored_label_input(info)),
            "url": masked, "has_secret": bool(parsed.query or parsed.username or parsed.password or parsed.fragment),
            "include": info.get("include", ""), "exclude": info.get("exclude", ""),
            "group": info.get("group"),
            "custom_group": bool(GatewayService._stored_group_input(identifier, info)),
            "groups": info.get("groups", []),
            "categories": info.get("categories", []), "overrides": info.get("overrides", {}),
            "count": int(info.get("count", 0)), "skipped": int(info.get("skipped", 0)),
            "updated_at": info.get("updated_at"), "last_error": info.get("last_error"),
        }

    def list_subscriptions(self) -> list[dict]:
        return [
            self._public_subscription(identifier, info)
            for identifier, info in sorted(self._subscription_meta().items(), key=lambda item: str(item[1].get("label", item[0])).lower())
        ]

    def preview_subscription(
        self, url: str, label: str = "", include: str = "", exclude: str = "",
        group: str = "", identifier: str | None = None, categories: list[dict] | None = None,
        overrides: dict | None = None,
    ) -> dict:
        prepared = self._prepare_subscription(
            url, label, include, exclude, group, identifier, categories, overrides,
        )
        result = {
            key: value for key, value in prepared.items()
            if key not in {"url", "outbounds", "label_input", "group_input", "category_input", "override_input", "node_aliases"}
        }
        result["custom_label"] = bool(prepared["label_input"])
        result["custom_group"] = bool(prepared["group_input"])
        result["categories"] = prepared["category_input"]
        result["overrides"] = prepared["override_input"]
        return result

    def save_subscription(
        self, url: str, label: str = "", include: str = "", exclude: str = "",
        group: str = "", identifier: str | None = None, categories: list[dict] | None = None,
        overrides: dict | None = None, fallback_label: str = "",
    ) -> dict:
        with self._metadata_lock:
            meta = self._subscription_meta()
            if identifier and identifier not in meta:
                raise ServiceError(f"节点订阅 {identifier} 不存在", 404)
            previous = meta.get(identifier or self._subscription_id(url), {})
            prepared = self._prepare_subscription(
                url, label, include, exclude, group, identifier, categories, overrides, fallback_label,
            )
            identifier = prepared["id"]
            old_nodes = set(previous.get("nodes", []))
            old_groups = {item.get("tag") for item in previous.get("groups", []) if item.get("tag")}
            if previous.get("group"):
                old_groups.add(previous["group"])
            new_nodes = {item["tag"] for item in prepared["outbounds"]}
            group_specs = [item for item in prepared["groups"] if item["members"]]
            new_group = prepared["group"]
            new_groups = {item["tag"] for item in group_specs}
            old_owned = old_nodes | old_groups
            new_owned = new_nodes | new_groups
            current_config = self.control.load()
            current_by_tag = {item.get("tag"): item for item in current_config.get("outbounds", [])}
            new_by_digest = {
                self._outbound_digest(item): item["tag"] for item in prepared["outbounds"]
            }
            new_by_identity = {}
            for item in prepared["outbounds"]:
                identity = self._outbound_identity(item)
                new_by_identity.setdefault(identity, []).append(item["tag"])
            replacements = {}
            legacy_prefix = identifier + "-"
            for old_tag in old_nodes:
                old_outbound = current_by_tag.get(old_tag)
                if not old_outbound:
                    continue
                replacement = new_by_digest.get(self._outbound_digest(old_outbound))
                if not replacement:
                    identity_matches = new_by_identity.get(self._outbound_identity(old_outbound), [])
                    if len(identity_matches) == 1:
                        replacement = identity_matches[0]
                if not replacement and old_tag.startswith(legacy_prefix):
                    legacy_name = old_tag[len(legacy_prefix):]
                    matches = [tag for tag in new_nodes if tag == legacy_name or tag.startswith(legacy_name)]
                    if len(matches) == 1:
                        replacement = matches[0]
                if replacement:
                    replacements[old_tag] = replacement
            if previous.get("group") and previous.get("group") != new_group:
                replacements[previous["group"]] = new_group
            new_groups_by_label = {
                item["label"]: item["tag"] for item in prepared["groups"] if not item["master"]
            }
            for old_spec in previous.get("groups", []):
                old_tag = old_spec.get("tag")
                replacement = new_groups_by_label.get(old_spec.get("label"))
                if old_tag and replacement and old_tag != replacement:
                    replacements[old_tag] = replacement

            existing_groups = {
                item.get("tag"): json.loads(json.dumps(item))
                for item in current_config.get("outbounds", [])
                if item.get("tag") in old_groups and item.get("type") in GROUP_TYPES
            }
            for existing in existing_groups.values():
                if existing.get("default") in replacements:
                    existing["default"] = replacements[existing["default"]]
            for old_tag, replacement in replacements.items():
                if replacement not in existing_groups and old_tag in existing_groups:
                    existing_groups[replacement] = existing_groups[old_tag]
            old_master = existing_groups.get(previous.get("group"))
            if new_group not in existing_groups and old_master:
                existing_groups[new_group] = old_master

            def modify(config):
                occupied = {
                    item.get("tag") for item in config.get("outbounds", [])
                    if item.get("tag") not in old_owned
                }
                conflicts = sorted(new_owned & occupied)
                if conflicts:
                    raise ValueError("订阅标签与现有出口冲突: " + ", ".join(conflicts))
                config["outbounds"] = [
                    item for item in config.get("outbounds", []) if item.get("tag") not in old_owned
                ]
                config["outbounds"].extend(prepared["outbounds"])
                config["outbounds"].extend(
                    self._group_outbound(spec["tag"], spec["members"], existing_groups.get(spec["tag"]))
                    for spec in group_specs
                )
                removed = old_owned - new_owned
                route = config.setdefault("route", {})
                if route.get("final") in removed:
                    route["final"] = replacements.get(route["final"], new_group)
                for rule in route.setdefault("rules", []):
                    if rule.get("outbound") in removed:
                        rule["outbound"] = replacements.get(rule["outbound"], new_group)
                empty_groups = set()
                for outbound in config["outbounds"]:
                    if outbound.get("detour") in removed:
                        outbound["detour"] = replacements.get(outbound["detour"], new_group)
                    if outbound.get("type") in GROUP_TYPES and outbound.get("tag") != new_group:
                        members = [replacements.get(member, member) for member in outbound.get("outbounds", [])]
                        outbound["outbounds"] = list(dict.fromkeys(
                            member for member in members if member not in removed or member in replacements.values()
                        ))
                        if outbound.get("type") == "selector" and outbound.get("default") in removed:
                            selected = replacements.get(outbound["default"])
                            outbound["default"] = selected or (outbound["outbounds"][0] if outbound["outbounds"] else "")
                        if not outbound["outbounds"]:
                            empty_groups.add(outbound.get("tag"))
                if empty_groups:
                    broken = removed | empty_groups
                    config["outbounds"] = [
                        item for item in config["outbounds"] if item.get("tag") not in empty_groups
                    ]
                    for outbound in config["outbounds"]:
                        if outbound.get("detour") in broken:
                            outbound["detour"] = new_group
                        if outbound.get("type") in GROUP_TYPES and outbound.get("tag") != new_group:
                            outbound["outbounds"] = [
                                member for member in outbound.get("outbounds", []) if member not in broken
                            ]
                            if outbound.get("type") == "selector" and outbound.get("default") in broken:
                                outbound["default"] = outbound["outbounds"][0] if outbound["outbounds"] else ""
                    for rule in route["rules"]:
                        if rule.get("outbound") in empty_groups:
                            rule["outbound"] = new_group
                    if route.get("final") in empty_groups:
                        route["final"] = new_group

            self._check_result(self.control.apply(modify))
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            meta = self._subscription_meta()
            meta[identifier] = {
                "url": prepared["url"], "label": prepared["label"],
                "label_input": prepared["label_input"],
                "include": prepared["include"], "exclude": prepared["exclude"],
                "group": new_group, "group_input": prepared["group_input"],
                "groups": [{"tag": item["tag"], "label": item["label"], "count": item["count"]} for item in group_specs],
                "node_aliases": prepared["node_aliases"],
                "categories": prepared["category_input"], "overrides": prepared["override_input"],
                "nodes": sorted(new_nodes), "count": prepared["count"], "skipped": prepared["skipped"],
                "created_at": previous.get("created_at") or now, "updated_at": now, "last_error": None,
            }
            self._save_subscription_meta(meta)
        return self._public_subscription(identifier, meta[identifier])

    def preview_subscription_update(self, identifier: str, **changes) -> dict:
        info = self._subscription_meta().get(identifier)
        if not info:
            raise ServiceError(f"节点订阅 {identifier} 不存在", 404)
        prepared = self._prepare_subscription(
            str(changes.get("url") or info.get("url", "")),
            str(changes["label"]) if "label" in changes else self._stored_label_input(info),
            str(changes["include"]) if "include" in changes else str(info.get("include", "")),
            str(changes["exclude"]) if "exclude" in changes else str(info.get("exclude", "")),
            str(changes["group"]) if "group" in changes else self._stored_group_input(identifier, info),
            identifier,
            changes["categories"] if "categories" in changes else info.get("categories", []),
            changes["overrides"] if "overrides" in changes else info.get("overrides", {}),
            str(info.get("label", "")),
        )
        result = {
            key: value for key, value in prepared.items()
            if key not in {"url", "outbounds", "label_input", "group_input", "category_input", "override_input", "node_aliases"}
        }
        result["custom_label"] = bool(prepared["label_input"])
        result["custom_group"] = bool(prepared["group_input"])
        result["categories"] = prepared["category_input"]
        result["overrides"] = prepared["override_input"]
        return result

    def update_subscription(self, identifier: str, **changes) -> dict:
        info = self._subscription_meta().get(identifier)
        if not info:
            raise ServiceError(f"节点订阅 {identifier} 不存在", 404)
        return self.save_subscription(
            str(changes.get("url") or info.get("url", "")),
            str(changes["label"]) if "label" in changes else self._stored_label_input(info),
            str(changes["include"]) if "include" in changes else str(info.get("include", "")),
            str(changes["exclude"]) if "exclude" in changes else str(info.get("exclude", "")),
            str(changes["group"]) if "group" in changes else self._stored_group_input(identifier, info),
            identifier,
            changes["categories"] if "categories" in changes else info.get("categories", []),
            changes["overrides"] if "overrides" in changes else info.get("overrides", {}),
            str(info.get("label", "")),
        )

    def refresh_subscription(self, identifier: str) -> dict:
        return self.update_subscription(identifier)

    def remove_subscription(self, identifier: str) -> dict:
        with self._metadata_lock:
            meta = self._subscription_meta()
            if identifier not in meta:
                raise ServiceError(f"节点订阅 {identifier} 不存在", 404)
            info = meta[identifier]
            owned = set(info.get("nodes", []))
            owned.update(item.get("tag") for item in info.get("groups", []) if item.get("tag"))
            if info.get("group"):
                owned.add(info["group"])

            def modify(config):
                remaining = [item for item in config.get("outbounds", []) if item.get("tag") not in owned]
                empty_groups = set()
                for outbound in remaining:
                    if outbound.get("type") in GROUP_TYPES:
                        outbound["outbounds"] = [member for member in outbound.get("outbounds", []) if member not in owned]
                        if outbound.get("type") == "selector" and outbound.get("default") in owned:
                            outbound["default"] = outbound["outbounds"][0] if outbound["outbounds"] else ""
                        if not outbound["outbounds"]:
                            empty_groups.add(outbound.get("tag"))
                remaining = [item for item in remaining if item.get("tag") not in empty_groups]
                broken = owned | empty_groups
                for outbound in remaining:
                    if outbound.get("type") in GROUP_TYPES:
                        outbound["outbounds"] = [member for member in outbound.get("outbounds", []) if member not in broken]
                        if outbound.get("type") == "selector" and outbound.get("default") in broken:
                            outbound["default"] = outbound["outbounds"][0] if outbound["outbounds"] else ""
                live = exit_tags({"outbounds": remaining})
                if not live:
                    raise ValueError("删除订阅后没有可用出口")
                route = config.setdefault("route", {})
                fallback = route.get("final") if route.get("final") in live else next(
                    (tag for tag in ("jp", "direct") if tag in live), live[0]
                )
                route["final"] = fallback
                for rule in route.setdefault("rules", []):
                    if rule.get("outbound") in broken:
                        rule["outbound"] = fallback
                for outbound in remaining:
                    if outbound.get("detour") in broken:
                        outbound["detour"] = fallback
                config["outbounds"] = remaining

            self._check_result(self.control.apply(modify))
            meta.pop(identifier)
            self._save_subscription_meta(meta)
        return {"deleted": identifier}

    def refresh_subscriptions(self) -> list[dict]:
        results = []
        for identifier in list(self._subscription_meta()):
            try:
                value = self.refresh_subscription(identifier)
                results.append({"id": identifier, "ok": True, "count": value["count"]})
            except Exception as error:  # 定时任务逐个隔离，保留该订阅旧配置
                message = str(error)[:120]
                with self._metadata_lock:
                    meta = self._subscription_meta()
                    if identifier in meta:
                        meta[identifier]["last_error"] = message
                        self._save_subscription_meta(meta)
                results.append({"id": identifier, "ok": False, "error": message})
        return results

    def exit_impact(self, tag: str) -> dict:
        config = self.control.load()
        if tag not in deletable_tags(config):
            raise ServiceError(f"出口 {tag} 不存在或不可删除", 404)
        return outbound_impact(config, tag)

    def rename_exit(self, old_tag: str, new_name: str) -> dict:
        config = self.control.load()
        if old_tag not in deletable_tags(config):
            raise ServiceError(f"出口 {old_tag} 不存在或不可改名", 404)
        new_tag = self._display_name(new_name, old_tag)
        if new_tag == old_tag:
            raise ServiceError("新旧名称相同")
        if new_tag in exit_tags(config):
            raise ServiceError(f"名称 {new_tag} 已被占用", 409)
        target = next(item for item in config.get("outbounds", []) if item.get("tag") == old_tag)
        identity = self._outbound_identity(target)
        subscription_id = None
        meta = self._subscription_meta()
        for identifier, info in meta.items():
            if old_tag in info.get("nodes", []):
                subscription_id = identifier
                break

        def modify(value):
            for outbound in value.get("outbounds", []):
                if outbound.get("tag") == old_tag:
                    outbound["tag"] = new_tag
                if outbound.get("type") in GROUP_TYPES:
                    outbound["outbounds"] = [new_tag if member == old_tag else member for member in outbound.get("outbounds", [])]
                    if outbound.get("type") == "selector" and outbound.get("default") == old_tag:
                        outbound["default"] = new_tag
            route = value.setdefault("route", {})
            if route.get("final") == old_tag:
                route["final"] = new_tag
            for rule in route.setdefault("rules", []):
                if rule.get("outbound") == old_tag:
                    rule["outbound"] = new_tag
            for outbound in value.get("outbounds", []):
                if outbound.get("detour") == old_tag:
                    outbound["detour"] = new_tag

        self._check_result(self.control.apply(modify))
        if subscription_id:
            info = meta[subscription_id]
            info["nodes"] = [new_tag if tag == old_tag else tag for tag in info.get("nodes", [])]
            for group in info.get("groups", []):
                group["tag"] = new_tag if group.get("tag") == old_tag else group.get("tag")
                group["members"] = [new_tag if tag == old_tag else tag for tag in group.get("members", [])]
            aliases = info.setdefault("node_aliases", {})
            aliases[identity] = new_tag
            self._save_subscription_meta(meta)
        return {"old": old_tag, "tag": new_tag, "name_source": "订阅自定义" if subscription_id else "手动"}

    def remove_exit(self, tag: str) -> dict:
        if tag not in deletable_tags(self.control.load()):
            raise ServiceError(f"出口 {tag} 不存在或不可删除", 404)
        fallback = {"tag": None}
        def modify(config):
            fallback["tag"] = delete_outbound(config, tag)
        self._check_result(self.control.apply(modify))
        return {"deleted": tag, "fallback": fallback["tag"]}

    def set_final(self, tag: str) -> dict:
        if tag not in exit_tags(self.control.load()):
            raise ServiceError(f"出口 {tag} 不存在", 404)
        self._check_result(self.control.apply(lambda config: config["route"].__setitem__("final", tag)))
        return {"default_exit": tag}

    def save_group(self, name: str, members: list[str]) -> dict:
        raw_name = name.strip()
        if not raw_name:
            raise ServiceError("策略组名称不能为空")
        name = self._group_tag(raw_name)
        if not isinstance(members, list):
            raise ServiceError("策略组成员必须是数组")
        members = list(dict.fromkeys(str(member).strip() for member in members if str(member).strip()))
        config = self.control.load()
        available = concrete_tags(config)
        if name in available:
            raise ServiceError(f"组名 {name} 与现有出口冲突", 409)
        unknown = [member for member in members if member not in available]
        if unknown:
            raise ServiceError("未知出口: " + ", ".join(unknown))
        if len(members) < 2:
            raise ServiceError("策略组至少需要两个具体出口")

        def modify(value):
            for index, outbound in enumerate(value["outbounds"]):
                if outbound.get("tag") != name:
                    continue
                if outbound.get("type") not in GROUP_TYPES:
                    raise ValueError(f"名称 {name} 已被占用")
                value["outbounds"][index] = self._group_outbound(name, members, outbound)
                return
            value["outbounds"].append(self._group_outbound(name, members))

        self._check_result(self.control.apply(modify))
        current = next(item for item in self.list_exits() if item["tag"] == name)
        return {"tag": name, "members": members, "mode": current["mode"], "selected": current["selected"]}

    def set_group_selection(self, tag: str, selected: str | None) -> dict:
        config = self.control.load()
        group = next((item for item in config.get("outbounds", []) if item.get("tag") == tag), None)
        if not group or group.get("type") not in GROUP_TYPES:
            raise ServiceError(f"节点组 {tag} 不存在", 404)
        members = list(group.get("outbounds", []))
        selected = str(selected or "").strip()
        if selected and selected not in members:
            raise ServiceError(f"节点 {selected} 不属于组 {tag}")

        def modify(value):
            for index, outbound in enumerate(value.get("outbounds", [])):
                if outbound.get("tag") != tag:
                    continue
                existing = {"type": "selector", "default": selected} if selected else None
                value["outbounds"][index] = self._group_outbound(tag, members, existing)
                return
            raise ValueError(f"节点组 {tag} 不存在")

        self._check_result(self.control.apply(modify))
        return {"tag": tag, "mode": "manual" if selected else "auto", "selected": selected or None}

    def remove_group(self, tag: str) -> dict:
        config = self.control.load()
        group = next((item for item in config.get("outbounds", []) if item.get("tag") == tag), None)
        if not group or group.get("type") not in GROUP_TYPES:
            raise ServiceError(f"策略组 {tag} 不存在", 404)
        return self.remove_exit(tag)

    def _read_direct(self) -> list[str]:
        try:
            lines = Path(self.direct_path).read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        return sorted({
            line.strip().removeprefix("domain:") for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        })

    def _write_direct(self, domains: list[str]) -> None:
        path = Path(self.direct_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = "# pdg-admin 自定义直连\n" + "".join(
            f"domain:{domain}\n" for domain in sorted(set(domains))
        )
        with self.control.locked():
            old = path.read_bytes() if path.exists() else None
            fd, temp_name = tempfile.mkstemp(prefix=".pdg-direct-", dir=str(path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_name, 0o600)
                os.replace(temp_name, path)
                restarted = self._run(["systemctl", "restart", "mosdns"])
                if restarted.returncode == 0:
                    return
                if old is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(old)
                    os.chmod(path, 0o600)
                self._run(["systemctl", "restart", "mosdns"])
                raise ServiceError("mosdns 重启失败,直连规则已回滚", 409)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)

    @staticmethod
    def _domain(value: str) -> str:
        domain = value.strip().lstrip(".").lower()
        if len(domain) > 253 or ".." in domain or not re.fullmatch(r"[a-z0-9.-]+", domain):
            raise ServiceError("域名格式不正确")
        labels = domain.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
            raise ServiceError("域名格式不正确")
        return domain

    def _ruleset_meta(self) -> dict:
        try:
            return json.loads(Path(self.ruleset_meta_path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}

    def _save_ruleset_meta(self, value: dict) -> None:
        path = Path(self.ruleset_meta_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".pdg-rulesets-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    @staticmethod
    def _ruleset_url(url: str) -> str:
        url = url.strip()
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ServiceError("规则集 URL 只支持 http/https")
        if url.lower().split("?", 1)[0].endswith(".mrs"):
            raise ServiceError(".mrs 是 Mihomo 格式，请使用 .list/.txt 或 sing-box .srs")
        return url

    @staticmethod
    def _fetch(url: str) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": "privdns-gateway-admin"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(16 * 1024 * 1024 + 1)
        if not data:
            raise ServiceError("规则集响应为空")
        if len(data) > 16 * 1024 * 1024:
            raise ServiceError("规则集超过 16MB 限制")
        return data

    @staticmethod
    def _source_rules(data: bytes) -> tuple[dict, int, bool]:
        domains, suffixes, keywords, cidrs = [], [], [], []
        for raw in data.decode("utf-8", "ignore").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("//"):
                continue
            # 兼容 Surge list 和 Clash classical provider 的 payload 列表。
            line = re.sub(r"^-\s*", "", line)
            parts = [part.strip() for part in line.split(",")]
            kind = parts[0].upper()
            if len(parts) < 2:
                continue
            if kind == "DOMAIN":
                domains.append(parts[1])
            elif kind == "DOMAIN-SUFFIX":
                suffixes.append(parts[1])
            elif kind == "DOMAIN-KEYWORD":
                keywords.append(parts[1])
            elif kind in ("IP-CIDR", "IP-CIDR6"):
                cidrs.append(parts[1])
        rule = {}
        if domains:
            rule["domain"] = domains
        if suffixes:
            rule["domain_suffix"] = suffixes
        if keywords:
            rule["domain_keyword"] = keywords
        if cidrs:
            rule["ip_cidr"] = cidrs
        count = len(domains) + len(suffixes) + len(keywords) + len(cidrs)
        if not count:
            raise ServiceError("没有解析出受支持的规则")
        return {"version": 1, "rules": [rule]}, count, not (domains or suffixes or keywords)

    def _download_ruleset(self, url: str, tag: str) -> tuple[str, str, int | None, bool]:
        data = self._fetch(url)
        directory = Path(self.ruleset_dir)
        directory.mkdir(parents=True, exist_ok=True)
        binary = url.lower().split("?", 1)[0].endswith(".srs")
        path = directory / f"{tag}.{('srs' if binary else 'json')}"
        fd, temp_name = tempfile.mkstemp(prefix=f".{tag}-", dir=str(directory))
        try:
            if binary:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                count, ip_only, fmt = None, False, "binary"
            else:
                source, count, ip_only = self._source_rules(data)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(source, handle, ensure_ascii=False)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                fmt = "source"
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, path)
            return str(path), fmt, count, ip_only
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def list_rulesets(self) -> list[dict]:
        config = self.control.load()
        targets = {
            rule.get("rule_set"): rule.get("outbound")
            for rule in config.get("route", {}).get("rules", []) if rule.get("rule_set")
        }
        output = []
        for tag, info in self._ruleset_meta().items():
            path = info.get("path") or str(Path(self.ruleset_dir) / f"{tag}.json")
            output.append({
                "tag": tag, "label": info.get("label") or tag, "url": info.get("url", ""),
                "target": targets.get(tag) or info.get("outbound"), "format": info.get("format", "source"),
                "count": info.get("count"), "available": Path(path).is_file(),
                "updated_at": info.get("updated_at"), "last_error": info.get("last_error"),
            })
        return output

    @staticmethod
    def _split_route_rules(config: dict) -> tuple[list[dict], list[dict], list[dict]]:
        system, managed, remaining = [], [], []
        for rule in config.setdefault("route", {}).setdefault("rules", []):
            if rule.get("action") or rule.get("inbound"):
                system.append(rule)
                continue
            if rule.get("outbound") and isinstance(rule.get("rule_set"), str) \
                    and set(rule) <= {"rule_set", "outbound"}:
                managed.append({
                    "kind": "ruleset", "value": rule["rule_set"],
                    "rule": {"rule_set": rule["rule_set"], "outbound": rule["outbound"]},
                })
                continue
            matchers = [key for key in ("domain_suffix", "domain", "ip_cidr") if rule.get(key)]
            if rule.get("outbound") and len(matchers) == 1 \
                    and set(rule) <= {matchers[0], "outbound"} and isinstance(rule[matchers[0]], list):
                key = matchers[0]
                kind = "cidr" if key == "ip_cidr" else "domain"
                for value in rule[key]:
                    managed.append({
                        "kind": kind, "value": str(value),
                        "rule": {key: [str(value)], "outbound": rule["outbound"]},
                    })
                continue
            remaining.append(rule)
        return system, managed, remaining

    @staticmethod
    def _apply_route_parts(config: dict, system: list[dict], managed: list[dict], remaining: list[dict]) -> None:
        config.setdefault("route", {})["rules"] = system + [item["rule"] for item in managed] + remaining

    @classmethod
    def prioritize_route_rules(cls, config: dict) -> bool:
        original = json.dumps(config.setdefault("route", {}).setdefault("rules", []), sort_keys=True)
        system, managed, remaining = cls._split_route_rules(config)
        manual = [item for item in managed if item["kind"] != "ruleset"]
        rulesets = [item for item in managed if item["kind"] == "ruleset"]
        cls._apply_route_parts(config, system, manual + rulesets, remaining)
        return json.dumps(config["route"]["rules"], sort_keys=True) != original

    def migrate_rule_priority(self) -> dict:
        if Path(self.rule_order_marker_path).exists():
            return {"changed": False}
        changed = {"value": False}

        def modify(config):
            changed["value"] = self.prioritize_route_rules(config)

        config = self.control.load()
        preview = json.loads(json.dumps(config))
        if not self.prioritize_route_rules(preview):
            return {"changed": False}
        self._check_result(self.control.apply(modify))
        return {"changed": changed["value"]}

    def save_ruleset(self, url: str, target: str, label: str = "") -> dict:
        url = self._ruleset_url(url)
        if target not in exit_tags(self.control.load()):
            raise ServiceError(f"出口 {target} 不存在", 404)
        tag = "rs_" + hashlib.sha1(url.encode()).hexdigest()[:8]
        with self._metadata_lock:
            previous = self._ruleset_meta().get(tag)
            old_path = previous.get("path") if previous else None
            old_data = Path(old_path).read_bytes() if old_path and Path(old_path).is_file() else None
            path, fmt, count, ip_only = self._download_ruleset(url, tag)

            def modify(config):
                route = config.setdefault("route", {})
                route.setdefault("rule_set", [])
                route["rule_set"] = [item for item in route["rule_set"] if item.get("tag") != tag]
                route["rule_set"].append({"tag": tag, "type": "local", "format": fmt, "path": path})
                route.setdefault("rules", [])
                replacement = {"rule_set": tag, "outbound": target}
                for index, rule in enumerate(route["rules"]):
                    if rule.get("rule_set") == tag:
                        route["rules"][index] = replacement
                        break
                else:
                    route["rules"].append(replacement)
                if not Path(self.rule_order_marker_path).exists():
                    self.prioritize_route_rules(config)

            result = self.control.apply(modify)
            if not result[0]:
                if old_data is not None and old_path:
                    Path(old_path).write_bytes(old_data)
                elif not previous:
                    Path(path).unlink(missing_ok=True)
                self._check_result(result)
            meta = self._ruleset_meta()
            meta[tag] = {
                "url": url, "outbound": target, "format": fmt, "path": path, "count": count,
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "last_error": None,
            }
            clean_label = label.strip()[:40]
            if clean_label:
                meta[tag]["label"] = clean_label
            elif previous and previous.get("label"):
                meta[tag]["label"] = previous["label"]
            self._save_ruleset_meta(meta)
        return {
            "tag": tag, "label": meta[tag].get("label") or tag, "target": target,
            "format": fmt, "count": count, "ip_only": ip_only,
        }

    def update_ruleset(self, tag: str, target: str | None = None, label: str | None = None) -> dict:
        with self._metadata_lock:
            meta = self._ruleset_meta()
            if tag not in meta:
                raise ServiceError(f"规则集 {tag} 不存在", 404)
            if target is not None:
                if target not in exit_tags(self.control.load()):
                    raise ServiceError(f"出口 {target} 不存在", 404)
                def modify(config):
                    for rule in config.get("route", {}).get("rules", []):
                        if rule.get("rule_set") == tag:
                            rule["outbound"] = target
                            return
                    raise ValueError("规则集路由不存在")
                self._check_result(self.control.apply(modify))
                meta[tag]["outbound"] = target
            if label is not None:
                clean = label.strip()[:40]
                if clean:
                    meta[tag]["label"] = clean
                else:
                    meta[tag].pop("label", None)
            self._save_ruleset_meta(meta)
        return next(item for item in self.list_rulesets() if item["tag"] == tag)

    def refresh_ruleset(self, tag: str) -> dict:
        info = self._ruleset_meta().get(tag)
        if not info:
            raise ServiceError(f"规则集 {tag} 不存在", 404)
        try:
            return self.save_ruleset(info["url"], info.get("outbound") or "", info.get("label") or "")
        except Exception as error:
            with self._metadata_lock:
                meta = self._ruleset_meta()
                if tag in meta:
                    meta[tag]["last_error"] = str(error)[:120]
                    self._save_ruleset_meta(meta)
            raise

    def refresh_rulesets(self) -> list[dict]:
        results = []
        for tag in list(self._ruleset_meta()):
            try:
                value = self.refresh_ruleset(tag)
                results.append({"tag": tag, "ok": True, "count": value.get("count")})
            except Exception as error:
                results.append({"tag": tag, "ok": False, "error": str(error)[:120]})
        return results

    def remove_ruleset(self, tag: str) -> dict:
        with self._metadata_lock:
            meta = self._ruleset_meta()
            if tag not in meta:
                raise ServiceError(f"规则集 {tag} 不存在", 404)
            info = meta[tag]
            def modify(config):
                route = config.setdefault("route", {})
                route["rule_set"] = [item for item in route.get("rule_set", []) if item.get("tag") != tag]
                route["rules"] = [rule for rule in route.get("rules", []) if rule.get("rule_set") != tag]
            self._check_result(self.control.apply(modify))
            meta.pop(tag)
            self._save_ruleset_meta(meta)
            for path in (info.get("path"), str(Path(self.ruleset_dir) / f"{tag}.json"), str(Path(self.ruleset_dir) / f"{tag}.srs")):
                if path:
                    Path(path).unlink(missing_ok=True)
        return {"deleted": tag}

    def list_rules(self) -> list[dict]:
        config = self.control.load()
        meta = self._ruleset_meta()
        system, managed, remaining = self._split_route_rules(config)
        rules = []
        for index, item in enumerate(managed, len(system)):
            target = item["rule"]["outbound"]
            info = meta.get(item["value"], {}) if item["kind"] == "ruleset" else {}
            rules.append({
                "kind": item["kind"], "value": item["value"],
                "label": info.get("label") or item["value"], "target": target,
                "count": info.get("count") if item["kind"] == "ruleset" else None, "order": index,
            })
        direct_offset = len(system) + len(managed) + len(remaining)
        rules.extend(
            {"kind": "direct", "value": domain, "label": domain, "target": "direct", "order": direct_offset + index}
            for index, domain in enumerate(self._read_direct())
        )
        return rules

    @staticmethod
    def _upsert_route_entries(
        managed: list[dict], kind: str, values: list[str], target: str, field: str, custom_order: bool,
    ) -> list[dict]:
        wanted = set(values)
        replaced = set()
        output = []
        for item in managed:
            if item["kind"] == kind and item["value"] in wanted:
                if item["value"] not in replaced:
                    value = item["value"]
                    output.append({"kind": kind, "value": value, "rule": {field: [value], "outbound": target}})
                    replaced.add(value)
                continue
            output.append(item)
        additions = [
            {"kind": kind, "value": value, "rule": {field: [value], "outbound": target}}
            for value in values if value not in replaced
        ]
        if custom_order:
            output.extend(additions)
        else:
            insert_at = next((index for index, item in enumerate(output) if item["kind"] == "ruleset"), len(output))
            output[insert_at:insert_at] = additions
        return output

    @staticmethod
    def _remove_route_entries(managed: list[dict], kind: str, values: set[str]) -> list[dict]:
        return [item for item in managed if item["kind"] != kind or item["value"] not in values]

    def _domains(self, domains: list[str]) -> list[str]:
        if not isinstance(domains, list):
            raise ServiceError("域名列表格式不正确")
        output = list(dict.fromkeys(self._domain(str(domain)) for domain in domains if str(domain).strip()))
        if not output or len(output) > 200:
            raise ServiceError("每次需要提交 1-200 个域名")
        return output

    @staticmethod
    def _cidr(value: str) -> str:
        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as error:
            raise ServiceError(f"CIDR 格式不正确: {value}") from error

    def _cidrs(self, cidrs: list[str]) -> list[str]:
        if not isinstance(cidrs, list):
            raise ServiceError("CIDR 列表格式不正确")
        output = list(dict.fromkeys(self._cidr(str(cidr)) for cidr in cidrs if str(cidr).strip()))
        if not output or len(output) > 200:
            raise ServiceError("每次需要提交 1-200 个 CIDR")
        return output

    def set_rules(self, domains: list[str], target: str) -> dict:
        domains = self._domains(domains)
        config = self.control.load()
        if target != "direct" and target not in exit_tags(config):
            raise ServiceError(f"出口 {target} 不存在", 404)
        custom_order = Path(self.rule_order_marker_path).exists()

        def modify(value):
            system, managed, remaining = self._split_route_rules(value)
            if target == "direct":
                managed = self._remove_route_entries(managed, "domain", set(domains))
            else:
                managed = self._upsert_route_entries(managed, "domain", domains, target, "domain_suffix", custom_order)
            self._apply_route_parts(value, system, managed, remaining)

        self._check_result(self.control.apply(modify))
        direct = self._read_direct()
        next_direct = [value for value in direct if value not in domains]
        if target == "direct":
            next_direct.extend(domain for domain in domains if domain not in next_direct)
        if sorted(next_direct) != sorted(direct):
            self._write_direct(next_direct)
        return {"items": [{"domain": domain, "target": target} for domain in domains], "count": len(domains), "target": target}

    def set_rule(self, domain: str, target: str) -> dict:
        result = self.set_rules([domain], target)
        return result["items"][0]

    def set_cidrs(self, cidrs: list[str], target: str) -> dict:
        cidrs = self._cidrs(cidrs)
        if target not in exit_tags(self.control.load()):
            raise ServiceError(f"出口 {target} 不存在", 404)
        custom_order = Path(self.rule_order_marker_path).exists()

        def modify(value):
            system, managed, remaining = self._split_route_rules(value)
            managed = self._upsert_route_entries(managed, "cidr", cidrs, target, "ip_cidr", custom_order)
            self._apply_route_parts(value, system, managed, remaining)

        self._check_result(self.control.apply(modify))
        return {"items": [{"cidr": cidr, "target": target} for cidr in cidrs], "count": len(cidrs), "target": target}

    def remove_rule(self, domain: str) -> dict:
        domain = self._domain(domain)
        config = self.control.load()
        _, managed, _ = self._split_route_rules(config)
        in_config = any(item["kind"] == "domain" and item["value"] == domain for item in managed)
        direct = self._read_direct()
        if not in_config and domain not in direct:
            raise ServiceError(f"规则 {domain} 不存在", 404)
        if in_config:
            def modify(value):
                system, entries, remaining = self._split_route_rules(value)
                self._apply_route_parts(value, system, self._remove_route_entries(entries, "domain", {domain}), remaining)
            self._check_result(self.control.apply(modify))
        if domain in direct:
            self._write_direct([value for value in direct if value != domain])
        return {"deleted": domain}

    def remove_cidr(self, cidr: str) -> dict:
        cidr = self._cidr(cidr)
        _, managed, _ = self._split_route_rules(self.control.load())
        if not any(item["kind"] == "cidr" and item["value"] == cidr for item in managed):
            raise ServiceError(f"CIDR 规则 {cidr} 不存在", 404)

        def modify(value):
            system, entries, remaining = self._split_route_rules(value)
            self._apply_route_parts(value, system, self._remove_route_entries(entries, "cidr", {cidr}), remaining)

        self._check_result(self.control.apply(modify))
        return {"deleted": cidr}

    def reorder_rules(self, order: list[dict]) -> dict:
        if not isinstance(order, list):
            raise ServiceError("规则顺序必须是数组")
        config = self.control.load()
        _, managed, _ = self._split_route_rules(config)
        current = [(item["kind"], item["value"]) for item in managed]
        requested = []
        for item in order:
            if not isinstance(item, dict) or item.get("kind") not in {"domain", "cidr", "ruleset"}:
                raise ServiceError("规则顺序格式错误")
            requested.append((str(item["kind"]), str(item.get("value", ""))))
        if len(set(current)) != len(current):
            raise ServiceError("现有规则包含重复项，请先重新保存重复规则")
        if len(requested) != len(current) or len(set(requested)) != len(requested) or set(requested) != set(current):
            raise ServiceError("规则顺序必须包含全部可排序规则且不能重复", 409)
        marker = Path(self.rule_order_marker_path)

        def modify(value):
            current_system, current_managed, current_remaining = self._split_route_rules(value)
            by_key = {(item["kind"], item["value"]): item for item in current_managed}
            if len(by_key) != len(requested) or set(by_key) != set(requested):
                raise ValueError("规则已发生变化，请刷新后重试")
            self._apply_route_parts(value, current_system, [by_key[key] for key in requested], current_remaining)

        self._check_result(self.control.apply(modify))
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("custom\n", encoding="utf-8")
        os.chmod(marker, 0o600)
        return {"order": [{"kind": kind, "value": value} for kind, value in requested]}

    @staticmethod
    def _domain_match(domain: str, rule: dict) -> bool:
        if domain in rule.get("domain", []):
            return True
        if any(domain == suffix or domain.endswith("." + suffix) for suffix in rule.get("domain_suffix", [])):
            return True
        return any(keyword in domain for keyword in rule.get("domain_keyword", []))

    @staticmethod
    def _ip_match(address: ipaddress.IPv4Address | ipaddress.IPv6Address, rule: dict) -> str | None:
        for cidr in rule.get("ip_cidr", []):
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return str(cidr)
            except ValueError:
                continue
        return None

    def test_route(self, domain: str) -> dict:
        query = domain.strip()
        try:
            address = ipaddress.ip_address(query)
            domain = str(address)
        except ValueError:
            address = None
            domain = self._domain(query)
        if address is None and any(domain == item or domain.endswith("." + item) for item in self._read_direct()):
            return {"domain": domain, "target": "direct", "kind": "direct", "match": "自定义直连"}
        config = self.control.load()
        definitions = {
            item.get("tag"): item for item in config.get("route", {}).get("rule_set", [])
        }
        meta = self._ruleset_meta()
        unresolved = []
        for rule in config.get("route", {}).get("rules", []):
            target = rule.get("outbound")
            if not target:
                continue
            matched_cidr = self._ip_match(address, rule) if address is not None else None
            if matched_cidr:
                return {"domain": domain, "target": target, "kind": "cidr", "match": matched_cidr}
            elif self._domain_match(domain, rule):
                values = rule.get("domain", []) + rule.get("domain_suffix", []) + rule.get("domain_keyword", [])
                return {"domain": domain, "target": target, "kind": "domain", "match": values[0] if values else domain}
            names = rule.get("rule_set")
            if not names:
                continue
            for name in names if isinstance(names, list) else [names]:
                definition = definitions.get(name, {})
                if definition.get("format") != "source":
                    if definition.get("format") == "binary":
                        unresolved.append(meta.get(name, {}).get("label") or name)
                    continue
                try:
                    source = json.loads(Path(definition.get("path", "")).read_text(encoding="utf-8"))
                except (FileNotFoundError, json.JSONDecodeError, OSError):
                    continue
                if address is not None:
                    matched = any(self._ip_match(address, item) for item in source.get("rules", []))
                else:
                    matched = any(self._domain_match(domain, item) for item in source.get("rules", []))
                if matched:
                    label = meta.get(name, {}).get("label") or name
                    return {"domain": domain, "target": target, "kind": "ruleset", "match": label}
        if unresolved:
            return {
                "domain": domain, "target": "无法判定", "kind": "binary-ruleset",
                "match": "二进制规则集: " + ", ".join(dict.fromkeys(unresolved)),
            }
        return {
            "domain": domain, "target": config.get("route", {}).get("final"),
            "kind": "final", "match": "默认出口",
        }

    def _project_status(self, check_remote: bool = False) -> dict:
        repo = "/opt/privdns-gateway"
        if check_remote:
            fetched = self._run(["git", "-C", repo, "fetch", "-q", "--prune", "--prune-tags", "origin", "main", "+refs/tags/*:refs/tags/*"])
            if fetched.returncode != 0:
                raise ServiceError("检查项目更新失败: " + ((fetched.stderr or fetched.stdout).strip()[-160:]), 502)
        current_result = self._run(["git", "-C", repo, "describe", "--tags", "--exclude", "*migrate*", "--always"])
        tags_result = self._run(["git", "-C", repo, "tag", "-l", "v*"])
        if current_result.returncode != 0:
            return {"current": "unknown", "latest": None, "update_available": False}
        current = current_result.stdout.strip() or "unknown"
        latest = None
        if tags_result.returncode == 0:
            stages = {"alpha": 0, "beta": 1, "rc": 2, None: 3}
            parsed = []
            for tag in tags_result.stdout.splitlines():
                match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?", tag)
                if match:
                    major, minor, patch, stage, number = match.groups()
                    parsed.append(((int(major), int(minor), int(patch), stages[stage], int(number or 0)), tag))
            if parsed:
                latest = max(parsed)[1]
        update_available = False
        if latest:
            head = self._run(["git", "-C", repo, "rev-parse", "HEAD"])
            target = self._run(["git", "-C", repo, "rev-parse", latest + "^{commit}"])
            ancestor = self._run(["git", "-C", repo, "merge-base", "--is-ancestor", "HEAD", latest])
            update_available = head.returncode == 0 and target.returncode == 0 \
                and head.stdout.strip() != target.stdout.strip() and ancestor.returncode == 0
        return {"current": current, "latest": latest, "update_available": update_available}

    @staticmethod
    def _file_updated_at(paths: list[Path]) -> str | None:
        mtimes = [path.stat().st_mtime for path in paths if path.is_file()]
        if not mtimes:
            return None
        return datetime.fromtimestamp(max(mtimes), timezone.utc).isoformat(timespec="seconds")

    def resource_status(self) -> dict:
        geosite_paths = [
            Path("/etc/mosdns/rules/geosite_cn.txt"),
            Path("/etc/mosdns/rules/geosite_geolocation-!cn.txt"),
            Path("/etc/mosdns/rules/geosite_apple.txt"),
        ]
        return {
            "subscriptions": self.list_subscriptions(),
            "rulesets": self.list_rulesets(),
            "geosite": {
                "available": all(path.is_file() for path in geosite_paths),
                "updated_at": self._file_updated_at(geosite_paths),
                "files": sum(path.is_file() for path in geosite_paths),
            },
            "project": self._project_status(),
        }

    def refresh_geosite(self) -> dict:
        result = self._run(["/bin/bash", "/opt/pdg-bot/update-rules.sh"])
        if result.returncode != 0:
            raise ServiceError("Geosite 更新失败: " + ((result.stderr or result.stdout).strip()[-200:]), 502)
        return {"ok": True, "updated_at": self._file_updated_at([
            Path("/etc/mosdns/rules/geosite_cn.txt"),
            Path("/etc/mosdns/rules/geosite_geolocation-!cn.txt"),
            Path("/etc/mosdns/rules/geosite_apple.txt"),
        ])}

    def check_project_update(self) -> dict:
        return self._project_status(check_remote=True)

    def start_project_update(self) -> dict:
        unit = "pdg-web-update-" + str(int(time.time()))
        result = self._run([
            "systemd-run", "--collect", "--unit", unit, "/usr/local/bin/pdg", "update",
        ])
        if result.returncode != 0:
            raise ServiceError("项目更新任务启动失败: " + ((result.stderr or result.stdout).strip()[-160:]), 502)
        return {"accepted": True, "unit": unit}

    def _clash_request(self, path: str, method: str = "GET") -> dict:
        request = urllib.request.Request(self.clash_url + path, method=method)
        with urllib.request.urlopen(request, timeout=12) as response:
            data = response.read()
        return json.loads(data) if data else {}

    def list_connections(self) -> dict:
        data = self._clash_request("/connections")
        connections = []
        for item in (data.get("connections") or [])[:300]:
            metadata = item.get("metadata") or {}
            connections.append({
                "id": item.get("id"), "host": metadata.get("host") or metadata.get("destinationIP") or "?",
                "sniff_host": metadata.get("sniffHost"),
                "destination": metadata.get("destinationIP"), "destination_port": metadata.get("destinationPort"),
                "source": metadata.get("sourceIP"), "source_port": metadata.get("sourcePort"),
                "network": metadata.get("network"), "type": metadata.get("type"),
                "inbound": metadata.get("inboundName") or metadata.get("inboundIP"),
                "rule": item.get("rule"), "rule_payload": item.get("rulePayload"),
                "chains": item.get("chains") or [],
                "upload": item.get("upload", 0), "download": item.get("download", 0),
                "start": item.get("start"),
            })
        return {
            "connections": connections, "upload_total": data.get("uploadTotal", 0),
            "download_total": data.get("downloadTotal", 0),
        }

    def close_connection(self, connection_id: str | None = None) -> dict:
        path = "/connections" if not connection_id else "/connections/" + urllib.parse.quote(connection_id, safe="")
        self._clash_request(path, "DELETE")
        return {"closed": connection_id or "all"}

    def logs(self, limit: int = 100) -> dict:
        limit = max(20, min(int(limit), 300))
        result = self._run([
            "journalctl", "-u", "sing-box", "-u", "mosdns", "-u", "pdg-admin",
            "-n", str(limit), "--no-pager", "-o", "short-iso",
        ])
        if result.returncode != 0:
            raise ServiceError("读取服务日志失败", 500)
        return {"lines": result.stdout.splitlines()[-limit:]}

    def test_exits(self, tags: list[str] | None = None, target: str = "google") -> list[dict]:
        if target not in TEST_TARGETS:
            raise ServiceError("未知测速目标")
        available = concrete_tags(self.control.load())
        if tags is None:
            selected = available
        elif not isinstance(tags, list):
            raise ServiceError("测速节点必须是数组")
        else:
            selected = list(dict.fromkeys(str(tag) for tag in tags))
            unknown = [tag for tag in selected if tag not in available]
            if unknown:
                raise ServiceError("未知测速节点: " + ", ".join(unknown), 404)
        results = []
        for tag in selected:
            query = urllib.parse.urlencode({"timeout": 8000, "url": TEST_TARGETS[target]})
            url = f"{self.clash_url}/proxies/{urllib.parse.quote(tag, safe='')}/delay?{query}"
            started = time.monotonic()
            try:
                with urllib.request.urlopen(url, timeout=11) as response:
                    delay = int(json.load(response).get("delay") or 0)
                if delay <= 0:
                    raise ValueError("测速未返回有效延迟")
                results.append({"tag": tag, "ok": True, "delay": delay, "target": target, "error": None})
            except urllib.error.HTTPError as error:
                results.append({
                    "tag": tag, "ok": False, "delay": None, "target": target,
                    "error": f"核心返回 HTTP {error.code}", "elapsed": int((time.monotonic() - started) * 1000),
                })
            except urllib.error.URLError as error:
                reason = "连接超时" if isinstance(error.reason, TimeoutError) else "目标不可达"
                results.append({
                    "tag": tag, "ok": False, "delay": None, "target": target,
                    "error": reason, "elapsed": int((time.monotonic() - started) * 1000),
                })
            except Exception as error:
                results.append({
                    "tag": tag, "ok": False, "delay": None, "target": target,
                    "error": str(error)[:80] or "测速失败", "elapsed": int((time.monotonic() - started) * 1000),
                })
        return results
