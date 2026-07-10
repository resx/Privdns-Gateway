#!/usr/bin/env python3
"""管理业务服务的出口与分流 CRUD 回归。"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))

from pdg_control import SingBoxControl  # noqa: E402
from pdg_service import GatewayService, ServiceError  # noqa: E402


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        if command[:3] == ["systemctl", "is-active", "sing-box"]:
            return subprocess.CompletedProcess(command, 0, "active\n", "")
        if command[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(command, 0, "active\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    config_path = root / "config.json"
    direct_path = root / "custom_direct.txt"
    meta_path = root / "rulesets.json"
    config = {
        "outbounds": [
            {"type": "direct", "tag": "jp"},
            {"type": "direct", "tag": "gms-mtalk"},
            {"type": "shadowsocks", "tag": "hk", "server": "hk.example.com", "server_port": 443,
             "method": "aes-128-gcm", "password": "secret"},
            {"type": "urltest", "tag": "auto", "outbounds": ["hk", "jp"]},
        ],
        "route": {
            "rules": [
                {"inbound": ["in-gms-5228"], "action": "route", "outbound": "gms-mtalk",
                 "override_address": "mtalk.google.com"},
                {"action": "reject", "ip_cidr": ["203.0.113.1/32"]},
                {"rule_set": "rs_media", "outbound": "hk"},
                {"domain_suffix": ["old.example"], "outbound": "hk"},
            ],
            "final": "hk",
        },
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    direct_path.write_text("domain:direct.example\n", encoding="utf-8")
    meta_path.write_text(json.dumps({"rs_media": {"label": "流媒体", "count": 12}}), encoding="utf-8")

    runner = Runner()
    control = SingBoxControl(str(config_path), str(root / "pdg.lock"), runner=runner, sleeper=lambda _: None)
    service = GatewayService(control, str(direct_path), str(meta_path), ruleset_dir=str(root / "rs"))

    overview = service.overview()
    assert overview["default_exit"] == "hk" and overview["proxy_count"] == 1
    assert all(value == "active" for value in overview["services"].values())

    exits = service.list_exits()
    assert "gms-mtalk" not in [item["tag"] for item in exits]
    hk = next(item for item in exits if item["tag"] == "hk")
    assert hk["server"] == "hk***.com" and "secret" not in json.dumps(exits)
    assert hk["default"] and hk["references"] >= 3

    preview = service.preview_link("socks5://u:p@node.example.com:1080#new")
    assert preview == {
        "tag": "new", "type": "socks", "server": "nod***.com",
        "server_port": 1080, "tls": False, "replacing": False,
    }
    service.add_exit("socks5://u:p@node.example.com:1080#new")
    assert any(item["tag"] == "new" for item in service.list_exits())
    service.set_final("new")
    assert service.overview()["default_exit"] == "new"

    group = service.save_group("fallback", ["hk", "new"])
    assert group == {"tag": "fallback", "members": ["hk", "new"]}
    try:
        service.save_group("bad", ["hk"])
        raise AssertionError("single-member group should fail")
    except ServiceError as error:
        assert "两个" in str(error)
    assert any(item["tag"] == "fallback" and item["members"] == ["hk", "new"] for item in service.list_exits())

    # 新域名规则应排在 GMS/reject 系统规则之后，且同域名更新时不重复。
    service.set_rule("video.example", "new")
    current = json.loads(config_path.read_text(encoding="utf-8"))
    assert current["route"]["rules"][0].get("inbound")
    assert current["route"]["rules"][1].get("action") == "reject"
    assert current["route"]["rules"][2] == {"domain_suffix": ["video.example"], "outbound": "new"}
    service.set_rule("video.example", "jp")
    rules = service.list_rules()
    hits = [item for item in rules if item["value"] == "video.example"]
    assert len(hits) == 1 and hits[0]["target"] == "jp"

    service.set_rule("local.example", "direct")
    assert "local.example" in direct_path.read_text(encoding="utf-8")
    assert any(item["kind"] == "ruleset" and item["label"] == "流媒体" for item in service.list_rules())
    service.remove_rule("local.example")
    assert "local.example" not in direct_path.read_text(encoding="utf-8")

    service._fetch = lambda url: b"DOMAIN-SUFFIX,stream.example\nDOMAIN,exact.example\n"
    try:
        service.save_ruleset("file:///etc/passwd", "new", "bad")
        raise AssertionError("non-http ruleset should fail")
    except ServiceError as error:
        assert "http/https" in str(error)
    ruleset = service.save_ruleset("https://rules.example/media.list", "new", "媒体")
    assert ruleset["count"] == 2 and ruleset["label"] == "媒体"
    listed = service.list_rulesets()
    saved = next(item for item in listed if item["tag"] == ruleset["tag"])
    assert saved["available"]
    assert service.test_route("www.stream.example")["match"] == "媒体"
    updated = service.update_ruleset(ruleset["tag"], "jp", "视频")
    assert updated["target"] == "jp" and updated["label"] == "视频"
    refreshed = service.refresh_ruleset(ruleset["tag"])
    assert refreshed["count"] == 2

    service._clash_request = lambda path, method="GET": ({
        "connections": [{"id": "c1", "metadata": {"host": "example.com", "network": "tcp"},
                         "chains": ["new"], "upload": 10, "download": 20}],
        "uploadTotal": 10, "downloadTotal": 20,
    } if method == "GET" else {})
    runtime = service.list_connections()
    assert runtime["connections"][0]["host"] == "example.com"
    assert service.close_connection("c1") == {"closed": "c1"}

    assert service.remove_ruleset(ruleset["tag"])["deleted"] == ruleset["tag"]
    assert all(item["tag"] != ruleset["tag"] for item in service.list_rulesets())
    service.remove_group("fallback")

    impact = service.exit_impact("hk")
    assert impact["groups"] == ["auto"] and impact["rules"]
    removed = service.remove_exit("hk")
    assert removed["deleted"] == "hk"
    current = json.loads(config_path.read_text(encoding="utf-8"))
    assert all(item.get("tag") != "hk" for item in current["outbounds"])
    assert current["route"]["rules"][0]["outbound"] == "gms-mtalk"

    try:
        service.set_final("missing")
        raise AssertionError("missing exit should fail")
    except ServiceError as error:
        assert error.status == 404

print("pdg-service regression OK")
