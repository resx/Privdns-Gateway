#!/usr/bin/env python3
"""PrivDNS Gateway 配置控制层。

所有 sing-box 配置写入统一经过：跨进程锁、候选配置校验、原子替换、
服务稳定性检查和失败回滚。Telegram Bot 与后续 Web API 共用本模块。
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from typing import Callable

try:
    import fcntl
except ImportError:  # pragma: no cover - 生产环境为 Linux
    fcntl = None


Runner = Callable[[list[str]], subprocess.CompletedProcess]
Modifier = Callable[[dict], None]

PROXY_TYPES = (
    "shadowsocks", "vmess", "trojan", "vless", "hysteria", "hysteria2",
    "tuic", "anytls", "shadowtls", "ssh", "socks", "http",
)
SYSTEM_OUTBOUND_TAGS = {"gms-mtalk"}
GROUP_TYPES = ("urltest", "selector")


def proxy_outbounds(config: dict) -> list[dict]:
    return [item for item in config.get("outbounds", []) if item.get("type") in PROXY_TYPES]


def exit_tags(config: dict) -> list[str]:
    return [
        item["tag"] for item in config.get("outbounds", [])
        if item.get("type") in PROXY_TYPES + ("direct",) + GROUP_TYPES
        and item.get("tag") not in SYSTEM_OUTBOUND_TAGS
    ]


def concrete_tags(config: dict) -> list[str]:
    return [
        item["tag"] for item in config.get("outbounds", [])
        if item.get("type") in PROXY_TYPES + ("direct",)
        and item.get("tag") not in SYSTEM_OUTBOUND_TAGS
    ]


def deletable_tags(config: dict) -> list[str]:
    return [
        item["tag"] for item in config.get("outbounds", [])
        if item.get("type") in PROXY_TYPES + GROUP_TYPES
    ]


def outbound_impact(config: dict, tag: str) -> dict:
    """返回删除出口前需要展示的引用影响。"""
    groups = [
        item["tag"] for item in config.get("outbounds", [])
        if item.get("type") in GROUP_TYPES and tag in item.get("outbounds", [])
    ]
    rules = []
    telegram = False
    for rule in config.get("route", {}).get("rules", []):
        if rule.get("outbound") != tag:
            continue
        if rule.get("inbound") == ["tg-proxy"]:
            telegram = True
            continue
        if rule.get("rule_set"):
            rules.append("规则集 " + str(rule["rule_set"]))
            continue
        domains = rule.get("domain_suffix", []) + rule.get("domain", [])
        rules.append(", ".join(domains[:3]) if domains else "系统路由")
    return {
        "groups": groups,
        "rules": rules,
        "final": config.get("route", {}).get("final") == tag,
        "telegram": telegram,
    }


def delete_outbound(config: dict, tag: str) -> str:
    """删除出口并修复全部失效引用，返回新的兜底出口。"""
    if tag not in deletable_tags(config):
        raise ValueError(f"出口 {tag} 不存在或不可删除")

    config["outbounds"] = [item for item in config["outbounds"] if item.get("tag") != tag]
    removed_groups = set()
    for item in config["outbounds"]:
        if item.get("type") in GROUP_TYPES:
            item["outbounds"] = [member for member in item.get("outbounds", []) if member != tag]
            if item.get("type") == "selector" and item.get("default") == tag:
                item["default"] = item["outbounds"][0] if item["outbounds"] else ""
            if not item["outbounds"]:
                removed_groups.add(item["tag"])
    if removed_groups:
        config["outbounds"] = [
            item for item in config["outbounds"] if item.get("tag") not in removed_groups
        ]

    live = exit_tags(config)
    if not live:
        raise ValueError("删除后没有可用出口")
    route = config.setdefault("route", {})
    current_final = route.get("final")
    fallback = current_final if current_final in live else next(
        (candidate for candidate in ("jp", "direct") if candidate in live), live[0]
    )
    route["final"] = fallback
    broken = {tag} | removed_groups
    for rule in route.setdefault("rules", []):
        if rule.get("outbound") in broken:
            rule["outbound"] = fallback
    return fallback


def run_command(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=180)


class SingBoxControl:
    """sing-box 配置的唯一事务写入口。"""

    def __init__(
        self,
        config_path: str = "/etc/sing-box/config.json",
        lock_path: str = "/run/privdns-gateway.lock",
        runner: Runner = run_command,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config_path = config_path
        self.lock_path = lock_path
        self.runner = runner
        self.sleeper = sleeper
        self._thread_lock = threading.RLock()

    def load(self) -> dict:
        with open(self.config_path, encoding="utf-8") as handle:
            return json.load(handle)

    @contextmanager
    def locked(self):
        # 与 pdg CLI 使用同一个锁，避免 Bot、Web 和更新流程并发覆盖配置。
        with self._thread_lock:
            lock_dir = os.path.dirname(self.lock_path)
            if lock_dir:
                os.makedirs(lock_dir, exist_ok=True)
            with open(self.lock_path, "a+", encoding="utf-8") as handle:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if fcntl is not None:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _write_candidate(self, config: dict, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)

    def _service_active(self, need: int = 3, delay: float = 0.6, max_polls: int = 15) -> bool:
        streak = 0
        for _ in range(max_polls):
            result = self.runner(["systemctl", "is-active", "sing-box"])
            if result.stdout.strip() == "active":
                streak += 1
                if streak >= need:
                    return True
            else:
                streak = 0
            self.sleeper(delay)
        return False

    @staticmethod
    def _tail(result: subprocess.CompletedProcess, limit: int) -> str:
        return ((result.stdout or "") + (result.stderr or ""))[-limit:]

    def apply(self, modify: Modifier) -> tuple[bool, str]:
        """修改并应用配置；失败时恢复上一份可用配置。"""
        with self.locked():
            current = self.load()
            candidate = copy.deepcopy(current)
            try:
                modify(candidate)
            except ValueError as error:
                return False, str(error)

            config_dir = os.path.dirname(self.config_path) or "."
            fd, temp_path = tempfile.mkstemp(prefix=".pdg-config-", dir=config_dir)
            os.close(fd)
            backup_path = self.config_path + ".botbak"
            try:
                self._write_candidate(candidate, temp_path)
                checked = self.runner(["sing-box", "check", "-c", temp_path])
                if checked.returncode != 0:
                    return False, "配置校验失败,未应用:\n" + self._tail(checked, 400)

                shutil.copy2(self.config_path, backup_path)
                os.chmod(backup_path, 0o600)
                os.replace(temp_path, self.config_path)

                self.runner(["systemctl", "reset-failed", "sing-box"])
                restarted = self.runner(["systemctl", "restart", "sing-box"])
                if restarted.returncode == 0 and self._service_active():
                    return True, ""

                shutil.copy2(backup_path, self.config_path)
                os.chmod(self.config_path, 0o600)
                self.runner(["systemctl", "reset-failed", "sing-box"])
                rollback = self.runner(["systemctl", "restart", "sing-box"])
                detail = self._tail(restarted, 300)
                if rollback.returncode != 0:
                    return False, "重启 sing-box 失败,配置已还原但服务恢复失败:\n" + detail
                return False, "重启 sing-box 失败,已还原上一份配置:\n" + detail
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
