#!/usr/bin/env python3
"""管理业务服务的出口与分流 CRUD 回归。"""
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))

from pdg_control import SingBoxControl  # noqa: E402
from pdg_links import normalize_tag  # noqa: E402
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
    subscription_path = root / "subscriptions.json"
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
    service = GatewayService(
        control, str(direct_path), str(meta_path), ruleset_dir=str(root / "rs"),
        subscription_meta_path=str(subscription_path),
    )

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

    group = service.save_group("🇯🇵 自动优选_日本", ["hk", "new"])
    assert group == {"tag": "🇯🇵-自动优选_日本", "members": ["hk", "new"], "mode": "auto", "selected": None}
    assert service.set_group_selection("🇯🇵-自动优选_日本", "new") == {
        "tag": "🇯🇵-自动优选_日本", "mode": "manual", "selected": "new",
    }
    current = json.loads(config_path.read_text(encoding="utf-8"))
    fixed_group = next(item for item in current["outbounds"] if item.get("tag") == "🇯🇵-自动优选_日本")
    assert fixed_group["type"] == "selector" and fixed_group["default"] == "new"
    service.save_group("🇯🇵 自动优选_日本", ["hk", "new"])
    assert service.set_group_selection("🇯🇵-自动优选_日本", None)["mode"] == "auto"
    try:
        service.save_group("bad", ["hk"])
        raise AssertionError("single-member group should fail")
    except ServiceError as error:
        assert "两个" in str(error)
    assert any(item["tag"] == "🇯🇵-自动优选_日本" and item["members"] == ["hk", "new"] for item in service.list_exits())

    subscription_text = "\n".join([
        "socks5://user:pass@sub-hk.example.com:1080#🇭🇰 HK-01",
        "socks5://user:pass@sub-tw.example.com:1080#🇹🇼 TW-01",
        "unsupported://ignored",
    ])
    subscription_data = base64.urlsafe_b64encode(subscription_text.encode()).rstrip(b"=")
    encoded_title = base64.urlsafe_b64encode("🇭🇰 港台专线".encode()).decode().rstrip("=")
    assert service._subscription_title({"profile-title": f"base64:{encoded_title}"}) == "🇭🇰 港台专线"
    service._fetch_subscription = lambda url: (subscription_data, "🇭🇰 港台专线")
    try:
        service.preview_subscription("http://127.0.0.1/nodes")
        raise AssertionError("private subscription URL should fail")
    except ServiceError as error:
        assert "私有" in str(error)
    unchanged = config_path.read_bytes()
    try:
        service.preview_subscription("https://subscribe.example/nodes", include="NO-MATCH")
        raise AssertionError("empty filtered subscription should fail")
    except ServiceError as error:
        assert "没有可用节点" in str(error)
    assert config_path.read_bytes() == unchanged
    subscription_url = "https://subscribe.example/nodes?token=top-secret&client=sing-box&udp=1"
    categories = [{"name": "香港", "pattern": "HK|香港"}, {"name": "台湾", "pattern": "TW|台湾"}]
    auto_named = service.preview_subscription(subscription_url)
    assert auto_named["label"] == "🇭🇰 港台专线" and not auto_named["custom_label"]
    assert auto_named["group"] == "🇭🇰-港台专线" and not auto_named["custom_group"]
    overrides = {
        "types": ["socks"], "rename": [{"pattern": "^(HK|TW)-", "replacement": "Region-$1-"}],
        "sort": "name", "properties": {"tcp_fast_open": True, "udp_fragment": True},
    }
    sub_preview = service.preview_subscription(
        subscription_url, "机场 A", categories=categories, overrides=overrides,
    )
    assert sub_preview["count"] == 2 and sub_preview["skipped"] == 1
    assert sub_preview["custom_label"]
    assert sub_preview["group"] == "机场-A" and not sub_preview["custom_group"]
    assert [group["count"] for group in sub_preview["groups"]] == [2, 1, 1]
    assert any("🇭🇰" in node["tag"] for node in sub_preview["nodes"])
    assert any("🇹🇼" in node["tag"] for node in sub_preview["nodes"])
    assert "top-secret" not in json.dumps(sub_preview, ensure_ascii=False)
    assert sub_preview["overrides"] == overrides
    saved_sub = service.save_subscription(
        subscription_url, "机场 A", categories=categories, overrides=overrides,
    )
    assert saved_sub["count"] == 2 and saved_sub["has_secret"]
    assert "top-secret" not in json.dumps(service.list_subscriptions(), ensure_ascii=False)
    sub_meta = json.loads(subscription_path.read_text(encoding="utf-8"))[saved_sub["id"]]
    assert sub_meta["url"] == subscription_url
    assert sub_meta["label_input"] == "机场 A"
    assert sub_meta["group"] == "机场-A" and sub_meta["group_input"] == ""
    assert sub_meta["overrides"] == overrides
    old_nodes = sub_meta["nodes"]
    assert all(not tag.startswith(saved_sub["id"] + "-") for tag in old_nodes)
    assert service._subscription_tag(
        {"type": "socks", "tag": "节点", "server": "node.example", "server_port": 1080}, {},
    ) == "节点"
    conflict_tag = service._subscription_tag(
        {"type": "socks", "tag": "节点", "server": "other.example", "server_port": 1080}, {"节点": None},
    )
    assert conflict_tag.startswith("节点-") and not conflict_tag.startswith("sub_")
    current = json.loads(config_path.read_text(encoding="utf-8"))
    assert len(sub_meta["groups"]) == 3
    assert all(any(item.get("tag") == group["tag"] for item in current["outbounds"]) for group in sub_meta["groups"])
    owned_nodes = [item for item in current["outbounds"] if item.get("tag") in old_nodes]
    assert all(item.get("tcp_fast_open") is True and item.get("udp_fragment") is True for item in owned_nodes)
    listed_exits = service.list_exits()
    listed_owned = [item for item in listed_exits if item["tag"] in old_nodes]
    assert all(item["source"] == "subscription" and item["subscription_id"] == saved_sub["id"]
               and item["subscription_label"] == "机场 A" for item in listed_owned)
    assert next(item for item in listed_exits if item["tag"] == "hk")["source"] == "manual"
    anytls = {"type": "anytls", "tag": "AnyTLS", "server": "node.example", "server_port": 443}
    service._fetch_subscription = lambda url: (base64.urlsafe_b64encode(
        b"anytls://password@node.example:443#AnyTLS"
    ).rstrip(b"="), "")
    anytls_preview = service.preview_subscription(
        "https://subscribe.example/anytls", overrides={"properties": {"tcp_fast_open": True}},
    )
    assert anytls_preview["count"] == 1
    prepared_anytls = service._prepare_subscription(
        "https://subscribe.example/anytls", overrides={"properties": {"tcp_fast_open": True}},
    )["outbounds"][0]
    assert prepared_anytls["type"] == anytls["type"] and "tcp_fast_open" not in prepared_anytls
    current["route"]["rules"].append({"domain_suffix": ["owned.example"], "outbound": old_nodes[-1]})
    config_path.write_text(json.dumps(current), encoding="utf-8")
    service.set_group_selection(sub_meta["group"], old_nodes[0])
    meta_before_migration = json.loads(subscription_path.read_text(encoding="utf-8"))
    meta_before_migration[saved_sub["id"]].pop("group_input", None)
    legacy_group = saved_sub["id"] + "-auto"
    legacy_nodes = {
        tag: normalize_tag(f"{saved_sub['id']}-{tag}")[:40] for tag in old_nodes
    }
    meta_before_migration[saved_sub["id"]]["group"] = legacy_group
    meta_before_migration[saved_sub["id"]]["nodes"] = sorted(legacy_nodes.values())
    for group_info in meta_before_migration[saved_sub["id"]]["groups"]:
        if group_info["label"] == "全部节点":
            group_info["tag"] = legacy_group
    subscription_path.write_text(json.dumps(meta_before_migration), encoding="utf-8")
    current = json.loads(config_path.read_text(encoding="utf-8"))
    current["route"]["final"] = legacy_nodes[old_nodes[0]]
    current["route"]["rules"].append({"domain_suffix": ["mapped.example"], "outbound": legacy_nodes[old_nodes[0]]})
    current["outbounds"].append({
        "type": "urltest", "tag": "external-sub-group",
        "outbounds": [legacy_nodes[old_nodes[0]], "hk"],
    })
    legacy_category = saved_sub["id"] + "-cat-legacy"
    readable_category = next(group["tag"] for group in sub_meta["groups"] if group["label"] == "香港")
    for group_info in meta_before_migration[saved_sub["id"]]["groups"]:
        if group_info["label"] == "香港":
            group_info["tag"] = legacy_category
    subscription_path.write_text(json.dumps(meta_before_migration), encoding="utf-8")
    for outbound in current["outbounds"]:
        tag = outbound.get("tag")
        if tag == sub_meta["group"]:
            outbound["tag"] = legacy_group
        elif tag == readable_category:
            outbound.clear()
            outbound.update({
                "type": "selector", "tag": legacy_category,
                "outbounds": [legacy_nodes[old_nodes[0]]], "default": legacy_nodes[old_nodes[0]],
            })
        elif tag in legacy_nodes:
            outbound["tag"] = legacy_nodes[tag]
        if outbound.get("type") in ("urltest", "selector"):
            outbound["outbounds"] = [legacy_nodes.get(member, member) for member in outbound.get("outbounds", [])]
            if outbound.get("default") in legacy_nodes:
                outbound["default"] = legacy_nodes[outbound["default"]]
    for rule in current["route"]["rules"]:
        if rule.get("outbound") in legacy_nodes:
            rule["outbound"] = legacy_nodes[rule["outbound"]]
    config_path.write_text(json.dumps(current), encoding="utf-8")

    service._fetch_subscription = lambda url: (base64.urlsafe_b64encode(
        "socks5://user:newpass@sub-hk.example.com:1080#🇭🇰 HK-01".encode()
    ).rstrip(b"="), "🇭🇰 港台专线")
    refreshed_sub = service.refresh_subscription(saved_sub["id"])
    assert refreshed_sub["count"] == 1
    current = json.loads(config_path.read_text(encoding="utf-8"))
    selected_group = next(item for item in current["outbounds"] if item.get("tag") == "机场-A")
    assert selected_group["type"] == "selector" and selected_group["default"] == old_nodes[0]
    current_tags = {item.get("tag") for item in current["outbounds"]}
    assert legacy_group not in current_tags
    assert not (set(legacy_nodes.values()) & current_tags)
    assert current["route"]["final"] == old_nodes[0]
    assert any(rule.get("domain_suffix") == ["mapped.example"] and rule.get("outbound") == old_nodes[0]
               for rule in current["route"]["rules"])
    external_group = next(item for item in current["outbounds"] if item.get("tag") == "external-sub-group")
    assert external_group["outbounds"] == [old_nodes[0], "hk"]
    migrated_category = next(item for item in current["outbounds"] if item.get("tag") == readable_category)
    assert migrated_category["type"] == "selector" and migrated_category["default"] == old_nodes[0]
    assert legacy_category not in current_tags
    assert all(rule.get("outbound") != old_nodes[-1] for rule in current["route"]["rules"])
    assert any(rule.get("outbound") == sub_meta["group"] for rule in current["route"]["rules"])
    service.set_final(sub_meta["group"])
    assert service.remove_subscription(saved_sub["id"])["deleted"] == saved_sub["id"]
    current = json.loads(config_path.read_text(encoding="utf-8"))
    assert current["route"]["final"] != sub_meta["group"]
    removed_tags = set(old_nodes + [group["tag"] for group in sub_meta["groups"]])
    assert all(item.get("tag") not in removed_tags for item in current["outbounds"])

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
    assert all(isinstance(item["order"], int) for item in rules)

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
        "connections": [{
            "id": "c1", "metadata": {
                "host": "example.com", "sniffHost": "sniff.example.com",
                "sourceIP": "100.64.0.2", "sourcePort": "51000",
                "destinationIP": "203.0.113.10", "destinationPort": "443",
                "network": "tcp", "type": "HTTP", "inboundName": "mixed-in",
            },
            "rule": "RuleSet", "rulePayload": "rs_example",
            "chains": ["new"], "upload": 10, "download": 20,
        }],
        "uploadTotal": 10, "downloadTotal": 20,
    } if method == "GET" else {})
    runtime = service.list_connections()
    connection = runtime["connections"][0]
    assert connection["host"] == "example.com" and connection["sniff_host"] == "sniff.example.com"
    assert connection["source_port"] == "51000" and connection["destination_port"] == "443"
    assert connection["inbound"] == "mixed-in" and connection["rule_payload"] == "rs_example"
    assert service.close_connection("c1") == {"closed": "c1"}

    assert service.remove_ruleset(ruleset["tag"])["deleted"] == ruleset["tag"]
    assert all(item["tag"] != ruleset["tag"] for item in service.list_rulesets())
    service.remove_group("🇯🇵-自动优选_日本")
    service.remove_group("external-sub-group")

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
