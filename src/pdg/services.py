"""编排: 编译落盘、配置校验、reload、rollback、doctor、status。

在没有 dnsdist/sing-box/systemd/root 的开发机上, 各操作优雅降级 (报告 skip)。
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import Paths
from .generators import dnsdist as gen_dnsdist
from .generators import nftables as gen_nft
from .generators import singbox as gen_singbox
from .model import Config
from .rules import ruleset
from .rules.compiler import CompiledTable, compile_rules


@dataclass
class Check:
    label: str
    ok: bool | None      # True/False, None = skip/unknown
    detail: str = ""

    def render(self) -> str:
        mark = {True: "✓", False: "✗", None: "·"}[self.ok]
        line = f"  {mark} {self.label}"
        return f"{line} — {self.detail}" if self.detail else line


# ── 编译 ────────────────────────────────────────────────────
def build_table(config: Config, paths: Paths, *,
                force_download: bool = False,
                allow_download: bool = True) -> CompiledTable:
    if not paths.rules_conf.exists():
        raise FileNotFoundError(f"找不到规则文件: {paths.rules_conf}")
    text = paths.rules_conf.read_text(encoding="utf-8")
    return compile_rules(config, text, paths.cache_dir,
                         force_download=force_download, allow_download=allow_download)


def render_all(table: CompiledTable, config: Config) -> dict[str, str]:
    return {
        "dnsdist": gen_dnsdist.generate(table, config),
        "singbox": gen_singbox.generate(table, config),
        "nftables": gen_nft.generate(config),
    }


def _write_with_backup(path: Path, text: str, backup_dir: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, backup_dir / (path.name + ".prev"))
    path.write_text(text, encoding="utf-8")


def write_outputs(paths: Paths, texts: dict[str, str]) -> dict[str, Path]:
    targets = {
        "dnsdist": paths.dnsdist_out,
        "singbox": paths.singbox_out,
        "nftables": paths.nftables_out,
    }
    for key, path in targets.items():
        _write_with_backup(path, texts[key], paths.backup_dir)
    return targets


def rollback(paths: Paths) -> list[Check]:
    out: list[Check] = []
    for path in (paths.dnsdist_out, paths.singbox_out, paths.nftables_out):
        prev = paths.backup_dir / (path.name + ".prev")
        if prev.exists():
            shutil.copy2(prev, path)
            out.append(Check(f"恢复 {path.name}", True, str(path)))
        else:
            out.append(Check(f"恢复 {path.name}", None, "无备份"))
    return out


# ── 校验 / reload ───────────────────────────────────────────
def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)


def validate(paths: Paths) -> list[Check]:
    out: list[Check] = []
    # sing-box check 针对生成的完整配置
    if shutil.which("sing-box"):
        code, msg = _run(["sing-box", "check", "-c", str(paths.singbox_out)])
        out.append(Check("sing-box check", code == 0, msg[:200] if msg else "ok"))
    else:
        out.append(Check("sing-box check", None, "未安装 (开发机跳过)"))

    main_dnsdist = Path("/etc/dnsdist/dnsdist.conf")
    if shutil.which("dnsdist") and main_dnsdist.exists():
        code, msg = _run(["dnsdist", "--check-config", "-C", str(main_dnsdist)])
        out.append(Check("dnsdist --check-config", code == 0, msg[:200] if msg else "ok"))
    else:
        out.append(Check("dnsdist --check-config", None, "未安装或无主配置 (跳过)"))
    return out


def reload_services(paths: Paths) -> list[Check]:
    out: list[Check] = []
    systemctl = shutil.which("systemctl")
    if systemctl:
        for svc in ("dnsdist", "sing-box"):
            code, msg = _run([systemctl, "reload-or-restart", svc])
            out.append(Check(f"reload {svc}", code == 0, msg[:160]))
    else:
        out.append(Check("systemctl", None, "不可用 (开发机跳过)"))
    if shutil.which("nft"):
        code, msg = _run(["nft", "-f", str(paths.nftables_out)])
        out.append(Check("nft -f", code == 0, msg[:160]))
    else:
        out.append(Check("nft", None, "未安装 (跳过)"))
    return out


# ── doctor / status ─────────────────────────────────────────
def _tcp_ok(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _svc_active(name: str) -> bool | None:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return None
    code, _ = _run([systemctl, "is-active", "--quiet", name])
    return code == 0


def doctor(config: Config, paths: Paths) -> list[Check]:
    out: list[Check] = []

    # 1-4 服务与端口
    out.append(Check("dnsdist 运行", _svc_active("dnsdist")))
    out.append(Check(f"DoT {config.dot_port}", _tcp_ok("127.0.0.1", config.dot_port),
                     "Android Private DNS"))
    out.append(Check(f"DoH {config.doh_port}", _tcp_ok("127.0.0.1", config.doh_port),
                     "iOS DoH"))
    out.append(Check("sing-box 运行", _svc_active("sing-box")))
    out.append(Check(f"透明入口 tproxy :{config.tproxy_port}",
                     _tcp_ok("127.0.0.1", config.tproxy_port)))

    # 6-7 SS2022 出口可连
    for tag, ob in config.outbounds.items():
        if ob.type == "shadowsocks":
            srv = ob.params.get("server", "")
            port = int(ob.params.get("server_port", 0))
            ok = _tcp_ok(srv, port) if srv and port and "CHANGE" not in srv.upper() \
                and "_OR_" not in srv.upper() else None
            out.append(Check(f"出口 {tag} ({srv}:{port})", ok))

    # 8 规则编译
    try:
        table = build_table(config, paths, allow_download=False)
        out.append(Check("规则编译", True, f"{len(table.rules)} 条规则"))
    except Exception as exc:  # noqa: BLE001
        table = None
        out.append(Check("规则编译", False, str(exc)))

    # 9 远程 RULE-SET 缓存
    cache = paths.cache_dir
    n_cache = len(list(cache.glob("*.list"))) if cache.exists() else 0
    out.append(Check("远程 RULE-SET 缓存", None if n_cache == 0 else True,
                     f"{n_cache} 个缓存文件"))

    # 10-13 抽样验证分流
    if table is not None:
        for domain in ("chatgpt.com", "youtube.com", "binance.com", "netflix.com"):
            cr = table.match(domain)
            out.append(Check(f"分流 {domain}", True,
                             f"{cr.policy} → {cr.outbound} ({cr.dns_mode})"))
    return out


def status(config: Config, paths: Paths) -> list[str]:
    lines = [
        "PrivDNS Gateway — status",
        f"  JP 内网入口 IP : {config.jp_internal_ip}  (HTTP {config.http_port} / HTTPS {config.https_port})",
        f"  透明入口端口   : tproxy :{config.tproxy_port}",
        f"  DoT / DoH      : {config.dot_port} / {config.doh_port}   主机名 {config.dns_hostname or '(未设)'}",
        f"  上游解析       : {', '.join(config.upstream)}",
        "  出口:",
    ]
    for tag, ob in config.outbounds.items():
        extra = ""
        if ob.type == "shadowsocks":
            extra = f"  {ob.params.get('server', '?')}:{ob.params.get('server_port', '?')}"
        lines.append(f"    - {tag:<12} type={ob.type:<12} dns={ob.dns_mode}{extra}")
    lines.append("  策略映射:")
    for pol, tag in config.policies.items():
        lines.append(f"    - {pol:<12} → {tag}")
    lines.append("  产物:")
    for label, p in (("dnsdist", paths.dnsdist_out),
                     ("sing-box", paths.singbox_out),
                     ("nftables", paths.nftables_out)):
        mark = "✓" if p.exists() else "·"
        lines.append(f"    {mark} {label:<9} {p}")
    return lines
