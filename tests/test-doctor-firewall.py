#!/usr/bin/env python3
"""Static + dynamic regression for doctor firewall port coverage."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
checks_src = (ROOT / "deploy/bot/checks.py").read_text(encoding="utf-8")

assert '{"53", "80", "81", "443", "853", "8111", "5228", "5229", "5230", "8445", "9443"}' in checks_src, (
    "doctor firewall leak detection must include admin 9443, TG 8445 and GMS 5228-5230"
)
assert "53/80/81/443/853/8111/5228-5230/8445/9443" in checks_src, (
    "doctor firewall OK text should mention admin, TG and GMS ports"
)

# 动态: 端口区间写法(如 5228-5230)对全网开放也要被识别为泄露; 限内网来源则不报。
spec = importlib.util.spec_from_file_location("pdg_checks", ROOT / "deploy/bot/checks.py")
checks = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(checks)

checks._run = lambda cmd: (0, "chain input {\n tcp dport { 22 } accept\n"
                              " tcp dport { 5228-5230 } accept\n}", "")
st, _, msg = checks.check_nft()
assert st == "fail" and "5228" in msg and "5230" in msg, (st, msg)

checks._run = lambda cmd: (0, "chain input {\n tcp dport { 22 } accept\n"
                              " ip saddr 172.22.0.0/16 tcp dport { 53, 80-81, 443, 853, 5228-5230, 8445 } accept\n}", "")
st, _, msg = checks.check_nft()
assert st == "ok", (st, msg)

# 宽区间对全网开放: 不枚举也要把落在区间内的敏感端口全报出来
checks._run = lambda cmd: (0, "chain input {\n tcp dport { 1-65535 } accept\n}", "")
st, _, msg = checks.check_nft()
assert st == "fail", (st, msg)
for p in ("53", "443", "8111", "5228", "5230", "8445", "9443"):
    assert p in msg, (p, msg)

# 宽区间但限定内网来源: 不算泄露
checks._run = lambda cmd: (0, "chain input {\n ip saddr 172.22.0.0/16 tcp dport { 1-65535 } accept\n}", "")
st, _, msg = checks.check_nft()
assert st == "ok", (st, msg)

# ── check_gms: sing-box 三入站 + 防火墙内网放行 → ok; 任一缺失 → warn(不 fail) ──
import json, tempfile

NFT_OK = ("chain input {\n ip saddr 172.22.0.0/16 tcp dport { 53, 80-81, 443, 853, 5228-5230, 8445 } accept\n}")
NFT_NO_GMS = ("chain input {\n ip saddr 172.22.0.0/16 tcp dport { 53, 80-81, 443, 853, 8445 } accept\n}")

def gms_case(ports, nft_out, legacy_sniff=False):
    gms_inbounds = []
    for p in ports:
        inbound = {"type": "direct", "tag": f"in-gms-{p}", "listen_port": p}
        if legacy_sniff and p in (5228, 5229, 5230):
            inbound["sniff"] = True
        gms_inbounds.append(inbound)
    config = {
        "inbounds": gms_inbounds,
        "outbounds": [{"type": "direct", "tag": "gms-mtalk"}],
        "route": {"rules": [{
            "inbound": ["in-gms-5228", "in-gms-5229", "in-gms-5230"],
            "action": "route", "outbound": "gms-mtalk", "override_address": "mtalk.google.com",
        }]},
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        path = f.name
    checks.SB = path
    checks._run = lambda cmd: (0, nft_out, "")
    return checks.check_gms()

st, _, msg = gms_case([443, 80, 5228, 5229, 5230], NFT_OK)
assert st == "ok" and "5228-5230" in msg, (st, msg)

st, _, msg = gms_case([443, 80, 5228, 5229, 5230], NFT_OK, legacy_sniff=True)
assert st == "warn" and "旧版" in msg, (st, msg)

st, _, msg = gms_case([443, 80, 5229, 5230], NFT_OK)          # sing-box 缺 5228
assert st == "warn" and "pdg" in msg, (st, msg)

st, _, msg = gms_case([443, 80, 5228, 5229, 5230], NFT_NO_GMS)  # 防火墙缺 5228-5230
assert st == "warn", (st, msg)

st, _, msg = gms_case([443, 80], NFT_NO_GMS)                    # 双缺也只 warn, 不 fail
assert st == "warn", (st, msg)

# iOS 下载应用层来源必须与 mosdns 内网策略精确一致，缺失或放宽都 fail。
with tempfile.TemporaryDirectory() as work:
    root = Path(work)
    checks.MOSDNS_CONF = str(root / "mosdns.yaml")
    checks.IOS_PROFILE_ENV = str(root / "ios-profile.env")
    Path(checks.MOSDNS_CONF).write_text(
        'args: { ips: ["172.22.0.0/16"] }\n', encoding="utf-8"
    )
    Path(checks.IOS_PROFILE_ENV).write_text(
        "PDG_IOS_ALLOWED_CIDRS=172.22.0.0/16\n", encoding="ascii"
    )
    st, _, msg = checks.check_ios_profile_access()
    assert st == "ok", (st, msg)

    Path(checks.IOS_PROFILE_ENV).write_text(
        "PDG_IOS_ALLOWED_CIDRS=0.0.0.0/0\n", encoding="ascii"
    )
    st, _, msg = checks.check_ios_profile_access()
    assert st == "fail" and "不一致" in msg, (st, msg)

    Path(checks.IOS_PROFILE_ENV).unlink()
    st, _, msg = checks.check_ios_profile_access()
    assert st == "fail" and "缺少" in msg, (st, msg)

print("doctor-firewall regression OK")
