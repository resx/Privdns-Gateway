"""生成 sing-box 完整配置 (/etc/sing-box/config.json)。

透明入口 (tproxy) + sniff: 手机连 JP:80/443 (非代理协议), nftables TPROXY 交给
sing-box, sniff 出 TLS SNI / HTTP Host 后按域名规则分流到 HK/TW/JP/direct。

目标: sing-box 1.8 ~ 1.10 (inbound 级 sniff)。1.11+ 需迁移到 route action sniff,
见 docs/deployment.md。V1 仅 TCP。
"""

from __future__ import annotations

import json

from ..model import Config
from ..rules.compiler import CompiledTable


def _build_outbound(tag: str, config: Config) -> dict:
    ob = config.outbounds[tag]
    if ob.type == "shadowsocks":
        p = ob.params
        return {
            "type": "shadowsocks",
            "tag": tag,
            "server": p.get("server", "CHANGE_ME"),
            "server_port": int(p.get("server_port", 0)),
            "method": p.get("method", "2022-blake3-aes-256-gcm"),
            "password": p.get("password", "CHANGE_ME"),
            "network": "tcp",
        }
    if ob.type == "block":
        return {"type": "block", "tag": tag}
    # direct (含内置 jp)
    return {"type": "direct", "tag": tag}


def generate(table: CompiledTable, config: Config) -> str:
    by_outbound = table.matchers_by_outbound()

    # 需要发出的出口: 规则中用到的 + final + 必备内置
    used = set(by_outbound) | {table.final_outbound, "direct", "block"}
    # 保证 jp 若被引用也包含 (上面 used 已含)
    outbounds = [_build_outbound(tag, config) for tag in sorted(used)]

    # route 规则: 每个出口一条, 聚合其匹配器 (跳过空键)
    rules = []
    for tag, m in by_outbound.items():
        if tag in ("direct",) and not any(m.values()):
            continue
        rule: dict = {}
        for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
            if m[key]:
                rule[key] = m[key]
        if rule:
            rule["outbound"] = tag
            rules.append(rule)

    conf = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "tproxy",
                "tag": "pdg-transparent",
                "listen": "::",
                "listen_port": config.tproxy_port,
                "network": "tcp",
                "sniff": True,
                "sniff_override_destination": True,
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": table.final_outbound,
            "auto_detect_interface": True,
        },
    }
    return json.dumps(conf, indent=2, ensure_ascii=False) + "\n"
