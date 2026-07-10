#!/usr/bin/env python3
"""PrivDNS Gateway 管理业务服务，供 Bot 与 Web API 复用。"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

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
    ) -> None:
        self.control = control or SingBoxControl()
        self.direct_path = direct_path
        self.ruleset_meta_path = ruleset_meta_path
        self.clash_url = clash_url.rstrip("/")
        self.ruleset_dir = ruleset_dir
        self.subscription_meta_path = subscription_meta_path
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

    def list_exits(self) -> list[dict]:
        config = self.control.load()
        final = config.get("route", {}).get("final")
        output = []
        for item in config.get("outbounds", []):
            tag = item.get("tag")
            if tag not in exit_tags(config):
                continue
            impact = outbound_impact(config, tag)
            output.append({
                "tag": tag,
                "type": item.get("type"),
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

    def preview_link(self, link: str) -> dict:
        return self._outbound_preview(parse_link(link))

    def add_outbound(self, outbound: dict) -> dict:
        if outbound.get("type") not in PROXY_TYPES or not outbound.get("tag"):
            raise ServiceError("出口类型或名称无效")
        preview = self._outbound_preview(outbound)

        def modify(config):
            config["outbounds"] = [
                item for item in config.get("outbounds", []) if item.get("tag") != outbound["tag"]
            ]
            config["outbounds"].append(outbound)

        self._check_result(self.control.apply(modify))
        return preview

    def add_exit(self, link: str) -> dict:
        return self.add_outbound(parse_link(link))

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

    def _fetch_subscription(self, url: str) -> bytes:
        self._require_public_subscription_host(url)
        request = urllib.request.Request(url, headers={"User-Agent": "privdns-gateway-subscription"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                final_url = self._subscription_url(response.geturl())
                self._require_public_subscription_host(final_url)
                data = response.read(8 * 1024 * 1024 + 1)
        except ServiceError:
            raise
        except Exception as error:
            raise ServiceError("节点订阅下载失败") from error
        if not data:
            raise ServiceError("节点订阅响应为空")
        if len(data) > 8 * 1024 * 1024:
            raise ServiceError("节点订阅超过 8MB 限制")
        return data

    @staticmethod
    def _subscription_tag(identifier: str, outbound: dict, used: dict[str, str]) -> str:
        original = normalize_tag(str(outbound.get("tag", "node")))
        digest_source = {key: value for key, value in outbound.items() if key != "tag"}
        digest = hashlib.sha1(json.dumps(digest_source, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        base = normalize_tag(f"{identifier}-{original}")[:40]
        if base not in used:
            used[base] = digest
            return base
        if used[base] == digest:
            return base
        tag = base[:33] + "-" + digest[:6]
        suffix = 1
        while tag in used and used[tag] != digest:
            tail = f"-{suffix}"
            tag = (base[:40 - len(tail)] + tail)
            suffix += 1
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
            category_hash = hashlib.sha1(category["name"].encode()).hexdigest()[:8]
            tag = normalize_tag(f"{identifier}-cat-{category_hash}")[:40]
            if tag in occupied:
                raise ServiceError(f"节点分类组名称冲突: {category['name']}")
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
    ) -> dict:
        url = self._subscription_url(url)
        identifier = identifier or self._subscription_id(url)
        include_re = self._subscription_regex(include, "包含")
        exclude_re = self._subscription_regex(exclude, "排除")
        normalized_overrides = self._normalize_subscription_overrides(overrides)
        try:
            parsed, errors = parse_subscription(self._fetch_subscription(url))
        except ValueError as error:
            raise ServiceError(str(error)) from error
        if len(parsed) > 500:
            raise ServiceError("单个订阅最多允许 500 个节点")

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

        used, outbounds, named_tags = {}, [], []
        for outbound, display_name in selected:
            value = json.loads(json.dumps(outbound))
            value["tag"] = display_name
            for property_name, enabled in normalized_overrides["properties"].items():
                if property_name == "tcp_fast_open" and enabled and value.get("type") == "anytls":
                    continue
                value[property_name] = enabled
            tag = self._subscription_tag(identifier, value, used)
            if any(item.get("tag") == tag for item in outbounds):
                continue
            value["tag"] = tag
            outbounds.append(value)
            named_tags.append((display_name, tag))
        if not outbounds:
            raise ServiceError("订阅没有可应用的唯一节点")

        clean_label = label.strip()[:40] or urllib.parse.urlparse(url).hostname or identifier
        group_tag = self._group_tag(group, identifier + "-auto")
        if group_tag in {item["tag"] for item in outbounds}:
            raise ServiceError("订阅分类组名称与节点冲突")

        meta = self._subscription_meta()
        previous = meta.get(identifier, {})
        old_nodes = set(previous.get("nodes", []))
        current = {item.get("tag"): item for item in self.control.load().get("outbounds", [])}
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
            "label": clean_label, "include": include.strip(), "exclude": exclude.strip(),
            "group": group_tag, "outbounds": outbounds, "nodes": previews,
            "count": len(outbounds), "skipped": len(errors) + len(parsed) - len(selected),
            "added": added, "updated": updated, "removed": removed,
            "groups": self._subscription_groups(identifier, group_tag, outbounds, named_tags, categories),
            "category_input": self._normalize_categories(categories),
            "override_input": normalized_overrides,
        }

    @staticmethod
    def _public_subscription(identifier: str, info: dict) -> dict:
        url = str(info.get("url", ""))
        parsed = urllib.parse.urlparse(url)
        masked = GatewayService._masked_subscription_url(url) if parsed.scheme else ""
        return {
            "id": identifier, "label": info.get("label") or identifier,
            "url": masked, "has_secret": bool(parsed.query or parsed.username or parsed.password or parsed.fragment),
            "include": info.get("include", ""), "exclude": info.get("exclude", ""),
            "group": info.get("group"), "groups": info.get("groups", []),
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
            if key not in {"url", "outbounds", "category_input", "override_input"}
        }
        result["categories"] = prepared["category_input"]
        result["overrides"] = prepared["override_input"]
        return result

    def save_subscription(
        self, url: str, label: str = "", include: str = "", exclude: str = "",
        group: str = "", identifier: str | None = None, categories: list[dict] | None = None,
        overrides: dict | None = None,
    ) -> dict:
        with self._metadata_lock:
            meta = self._subscription_meta()
            if identifier and identifier not in meta:
                raise ServiceError(f"节点订阅 {identifier} 不存在", 404)
            previous = meta.get(identifier or self._subscription_id(url), {})
            prepared = self._prepare_subscription(
                url, label, include, exclude, group, identifier, categories, overrides,
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
            existing_groups = {
                item.get("tag"): item for item in self.control.load().get("outbounds", [])
                if item.get("tag") in old_groups and item.get("type") in GROUP_TYPES
            }

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
                    route["final"] = new_group
                for rule in route.setdefault("rules", []):
                    if rule.get("outbound") in removed:
                        rule["outbound"] = new_group
                empty_groups = set()
                for outbound in config["outbounds"]:
                    if outbound.get("detour") in removed:
                        outbound["detour"] = new_group
                    if outbound.get("type") in GROUP_TYPES and outbound.get("tag") != new_group:
                        outbound["outbounds"] = [
                            member for member in outbound.get("outbounds", []) if member not in removed
                        ]
                        if outbound.get("type") == "selector" and outbound.get("default") in removed:
                            outbound["default"] = outbound["outbounds"][0] if outbound["outbounds"] else ""
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
                "include": prepared["include"], "exclude": prepared["exclude"],
                "group": new_group,
                "groups": [{"tag": item["tag"], "label": item["label"], "count": item["count"]} for item in group_specs],
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
            str(changes["label"]) if "label" in changes else str(info.get("label", "")),
            str(changes["include"]) if "include" in changes else str(info.get("include", "")),
            str(changes["exclude"]) if "exclude" in changes else str(info.get("exclude", "")),
            str(changes["group"]) if "group" in changes else str(info.get("group", "")),
            identifier,
            changes["categories"] if "categories" in changes else info.get("categories", []),
            changes["overrides"] if "overrides" in changes else info.get("overrides", {}),
        )
        result = {
            key: value for key, value in prepared.items()
            if key not in {"url", "outbounds", "category_input", "override_input"}
        }
        result["categories"] = prepared["category_input"]
        result["overrides"] = prepared["override_input"]
        return result

    def update_subscription(self, identifier: str, **changes) -> dict:
        info = self._subscription_meta().get(identifier)
        if not info:
            raise ServiceError(f"节点订阅 {identifier} 不存在", 404)
        return self.save_subscription(
            str(changes.get("url") or info.get("url", "")),
            str(changes["label"]) if "label" in changes else str(info.get("label", "")),
            str(changes["include"]) if "include" in changes else str(info.get("include", "")),
            str(changes["exclude"]) if "exclude" in changes else str(info.get("exclude", "")),
            str(changes["group"]) if "group" in changes else str(info.get("group", "")),
            identifier,
            changes["categories"] if "categories" in changes else info.get("categories", []),
            changes["overrides"] if "overrides" in changes else info.get("overrides", {}),
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
            raise ServiceError("故障组名称不能为空")
        name = self._group_tag(raw_name)
        if not isinstance(members, list):
            raise ServiceError("故障组成员必须是数组")
        members = list(dict.fromkeys(str(member).strip() for member in members if str(member).strip()))
        config = self.control.load()
        available = concrete_tags(config)
        if name in available:
            raise ServiceError(f"组名 {name} 与现有出口冲突", 409)
        unknown = [member for member in members if member not in available]
        if unknown:
            raise ServiceError("未知出口: " + ", ".join(unknown))
        if len(members) < 2:
            raise ServiceError("故障组至少需要两个具体出口")

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
            raise ServiceError(f"故障组 {tag} 不存在", 404)
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
                route["rules"] = [rule for rule in route["rules"] if rule.get("rule_set") != tag]
                index = 0
                while index < len(route["rules"]) and (route["rules"][index].get("action") or route["rules"][index].get("inbound")):
                    index += 1
                route["rules"].insert(index, {"rule_set": tag, "outbound": target})

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
        rules = []
        for item in config.get("route", {}).get("rules", []):
            target = item.get("outbound")
            if not target:
                continue
            if item.get("rule_set"):
                name = item["rule_set"]
                info = meta.get(name, {})
                rules.append({
                    "kind": "ruleset", "value": name,
                    "label": info.get("label") or name, "target": target,
                    "count": info.get("count"),
                })
                continue
            for domain in item.get("domain_suffix", []) + item.get("domain", []):
                rules.append({"kind": "domain", "value": domain, "label": domain, "target": target})
        rules.extend(
            {"kind": "direct", "value": domain, "label": domain, "target": "direct"}
            for domain in self._read_direct()
        )
        return rules

    @staticmethod
    def _without_domain_rules(config: dict, domain: str) -> None:
        for rule in config.get("route", {}).get("rules", []):
            for key in ("domain_suffix", "domain"):
                if rule.get(key):
                    rule[key] = [value for value in rule[key] if value != domain]
        config["route"]["rules"] = [
            rule for rule in config["route"]["rules"]
            if rule.get("action") or "outbound" not in rule or rule.get("rule_set")
            or rule.get("domain_suffix") or rule.get("domain")
            or rule.get("domain_keyword") or rule.get("ip_cidr") or rule.get("inbound")
        ]

    def set_rule(self, domain: str, target: str) -> dict:
        domain = self._domain(domain)
        config = self.control.load()
        if target != "direct" and target not in exit_tags(config):
            raise ServiceError(f"出口 {target} 不存在", 404)

        def modify(value):
            self._without_domain_rules(value, domain)
            if target == "direct":
                return
            for rule in value["route"]["rules"]:
                if rule.get("outbound") == target and "rule_set" not in rule and rule.get("domain_suffix") is not None:
                    rule["domain_suffix"].append(domain)
                    return
            rules = value["route"]["rules"]
            index = 0
            while index < len(rules) and (rules[index].get("action") or rules[index].get("inbound")):
                index += 1
            rules.insert(index, {"domain_suffix": [domain], "outbound": target})

        self._check_result(self.control.apply(modify))
        direct = self._read_direct()
        if target == "direct" and domain not in direct:
            self._write_direct(direct + [domain])
        elif target != "direct" and domain in direct:
            self._write_direct([value for value in direct if value != domain])
        return {"domain": domain, "target": target}

    def remove_rule(self, domain: str) -> dict:
        domain = self._domain(domain)
        config = self.control.load()
        in_config = any(
            domain in rule.get(key, [])
            for rule in config.get("route", {}).get("rules", [])
            for key in ("domain_suffix", "domain")
        )
        direct = self._read_direct()
        if not in_config and domain not in direct:
            raise ServiceError(f"规则 {domain} 不存在", 404)
        if in_config:
            self._check_result(self.control.apply(lambda value: self._without_domain_rules(value, domain)))
        if domain in direct:
            self._write_direct([value for value in direct if value != domain])
        return {"deleted": domain}

    @staticmethod
    def _domain_match(domain: str, rule: dict) -> bool:
        if domain in rule.get("domain", []):
            return True
        if any(domain == suffix or domain.endswith("." + suffix) for suffix in rule.get("domain_suffix", [])):
            return True
        return any(keyword in domain for keyword in rule.get("domain_keyword", []))

    def test_route(self, domain: str) -> dict:
        domain = self._domain(domain)
        if any(domain == item or domain.endswith("." + item) for item in self._read_direct()):
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
            if self._domain_match(domain, rule):
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
                if any(self._domain_match(domain, item) for item in source.get("rules", [])):
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
            fetched = self._run(["git", "-C", repo, "fetch", "-q", "--tags", "origin", "main"])
            if fetched.returncode != 0:
                raise ServiceError("检查项目更新失败: " + ((fetched.stderr or fetched.stdout).strip()[-160:]), 502)
        current_result = self._run(["git", "-C", repo, "describe", "--tags", "--always"])
        tags_result = self._run(["git", "-C", repo, "tag", "-l", "v*", "--sort=-v:refname"])
        if current_result.returncode != 0:
            return {"current": "unknown", "latest": None, "update_available": False}
        current = current_result.stdout.strip() or "unknown"
        latest = next(iter(tags_result.stdout.splitlines()), None) if tags_result.returncode == 0 else None
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
                "source": metadata.get("sourceIP"), "network": metadata.get("network"),
                "type": metadata.get("type"), "chains": item.get("chains") or [],
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
