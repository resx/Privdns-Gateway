#!/usr/bin/env python3
"""pdg_control 配置事务与出口引用迁移回归。"""
import copy
import json
import subprocess
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))

from pdg_control import (  # noqa: E402
    SingBoxControl,
    delete_outbound,
    exit_tags,
    outbound_impact,
)


class FakeRunner:
    def __init__(self, check_rc=0, first_restart_rc=0):
        self.check_rc = check_rc
        self.first_restart_rc = first_restart_rc
        self.restart_count = 0
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        if command[:2] == ["sing-box", "check"]:
            return subprocess.CompletedProcess(command, self.check_rc, "", "bad candidate")
        if command[:3] == ["systemctl", "restart", "sing-box"]:
            self.restart_count += 1
            rc = self.first_restart_rc if self.restart_count == 1 else 0
            return subprocess.CompletedProcess(command, rc, "", "restart failed" if rc else "")
        if command[:3] == ["systemctl", "is-active", "sing-box"]:
            return subprocess.CompletedProcess(command, 0, "active\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")


def write_config(path, value="jp"):
    path.write_text(json.dumps({"route": {"final": value}, "outbounds": []}), encoding="utf-8")


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    config = root / "config.json"
    lock = root / "pdg.lock"

    # 候选配置校验失败时，现用配置不能被替换或触发重启。
    write_config(config)
    runner = FakeRunner(check_rc=1)
    control = SingBoxControl(str(config), str(lock), runner=runner, sleeper=lambda _: None)
    ok, msg = control.apply(lambda value: value["route"].__setitem__("final", "hk"))
    assert not ok and "未应用" in msg
    assert json.loads(config.read_text(encoding="utf-8"))["route"]["final"] == "jp"
    assert runner.restart_count == 0

    # 校验通过后原子应用，并留下权限收紧的回滚副本。
    write_config(config)
    runner = FakeRunner()
    control = SingBoxControl(str(config), str(lock), runner=runner, sleeper=lambda _: None)
    ok, msg = control.apply(lambda value: value["route"].__setitem__("final", "hk"))
    assert ok, msg
    assert json.loads(config.read_text(encoding="utf-8"))["route"]["final"] == "hk"
    assert Path(str(config) + ".botbak").exists()
    assert runner.restart_count == 1

    # 新配置启动失败时恢复原文件，并再次启动上一版。
    write_config(config)
    runner = FakeRunner(first_restart_rc=1)
    control = SingBoxControl(str(config), str(lock), runner=runner, sleeper=lambda _: None)
    ok, msg = control.apply(lambda value: value["route"].__setitem__("final", "hk"))
    assert not ok and "已还原" in msg
    assert json.loads(config.read_text(encoding="utf-8"))["route"]["final"] == "jp"
    assert runner.restart_count == 2


cfg = {
    "outbounds": [
        {"type": "direct", "tag": "jp"},
        {"type": "direct", "tag": "gms-mtalk"},
        {"type": "shadowsocks", "tag": "hk"},
        {"type": "shadowsocks", "tag": "tw"},
        {"type": "urltest", "tag": "auto", "outbounds": ["hk", "tw"]},
    ],
    "route": {
        "final": "hk",
        "rules": [
            {"inbound": ["in-gms-5228"], "outbound": "gms-mtalk"},
            {"inbound": ["tg-proxy"], "outbound": "hk"},
            {"domain_suffix": ["example.com"], "outbound": "hk"},
        ],
    },
}
impact = outbound_impact(cfg, "hk")
assert impact == {
    "groups": ["auto"],
    "rules": ["example.com"],
    "final": True,
    "telegram": True,
}
assert "gms-mtalk" not in exit_tags(cfg), "系统出站不能出现在用户出口选择里"

changed = copy.deepcopy(cfg)
fallback = delete_outbound(changed, "hk")
assert fallback == "jp"
assert changed["route"]["final"] == "jp"
auto = next(item for item in changed["outbounds"] if item.get("tag") == "auto")
assert auto["outbounds"] == ["tw"]
assert changed["route"]["rules"][0]["outbound"] == "gms-mtalk"
assert changed["route"]["rules"][1]["outbound"] == "jp"
assert changed["route"]["rules"][2]["outbound"] == "jp"

print("pdg-control regression OK")
