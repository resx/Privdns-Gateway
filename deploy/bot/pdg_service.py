#!/usr/bin/env python3
"""PrivDNS Gateway 管理业务服务，供 Bot 与 Web API 复用。"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import urllib.parse
import urllib.request
from pathlib import Path

from pdg_control import (
    SingBoxControl,
    PROXY_TYPES,
    concrete_tags,
    deletable_tags,
    delete_outbound,
    exit_tags,
    outbound_impact,
    proxy_outbounds,
)
from pdg_links import normalize_tag, parse_link


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
    ) -> None:
        self.control = control or SingBoxControl()
        self.direct_path = direct_path
        self.ruleset_meta_path = ruleset_meta_path
        self.clash_url = clash_url.rstrip("/")
        self.ruleset_dir = ruleset_dir
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
        groups = sum(1 for item in config.get("outbounds", []) if item.get("type") == "urltest")
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
                "members": item.get("outbounds", []) if item.get("type") == "urltest" else [],
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
        name = normalize_tag(raw_name)
        if not re.search(r"[A-Za-z0-9]", name):
            raise ServiceError("故障组名称必须包含字母或数字")
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
            for outbound in value["outbounds"]:
                if outbound.get("tag") == name:
                    if outbound.get("type") != "urltest":
                        raise ValueError(f"名称 {name} 已被占用")
                    outbound["outbounds"] = members
                    outbound.setdefault("url", "http://www.gstatic.com/generate_204")
                    outbound.setdefault("interval", "3m")
                    outbound.setdefault("tolerance", 50)
                    return
            value["outbounds"].append({
                "type": "urltest", "tag": name, "outbounds": members,
                "url": "http://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50,
            })

        self._check_result(self.control.apply(modify))
        return {"tag": name, "members": members}

    def remove_group(self, tag: str) -> dict:
        config = self.control.load()
        group = next((item for item in config.get("outbounds", []) if item.get("tag") == tag), None)
        if not group or group.get("type") != "urltest":
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
        return self.save_ruleset(info["url"], info.get("outbound") or "", info.get("label") or "")

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

    def test_exits(self) -> list[dict]:
        results = []
        for tag in concrete_tags(self.control.load()):
            query = urllib.parse.urlencode({"timeout": 5000, "url": "http://www.gstatic.com/generate_204"})
            url = f"{self.clash_url}/proxies/{urllib.parse.quote(tag, safe='')}/delay?{query}"
            try:
                with urllib.request.urlopen(url, timeout=8) as response:
                    delay = json.load(response).get("delay")
                results.append({"tag": tag, "ok": True, "delay": delay})
            except Exception:
                results.append({"tag": tag, "ok": False, "delay": None})
        return results
