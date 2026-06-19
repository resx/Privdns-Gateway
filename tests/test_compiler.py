"""编译器与生成器核心不变量测试 (标准库 unittest, 无需 pytest)。

运行: PYTHONPATH=src python3 -m unittest discover -s tests
"""

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# 让 resolve_paths 用仓库内 config/, 产物写到临时 var。
os.environ["PDG_ETC"] = str(ROOT / "config")

from pdg.config import load_config, resolve_paths  # noqa: E402
from pdg.generators import dnsdist as gen_dnsdist  # noqa: E402
from pdg.generators import singbox as gen_singbox  # noqa: E402
from pdg.services import build_table  # noqa: E402


class CompilerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = resolve_paths()
        cls.config = load_config(cls.paths)
        cls.table = build_table(cls.config, cls.paths, allow_download=False)

    def test_proxy_domain_to_remote(self):
        cr = self.table.match("api.openai.com")   # 子域命中后缀
        self.assertEqual(cr.policy, "AI")
        self.assertEqual(cr.outbound, "tw-ss2022")
        self.assertEqual(cr.dns_mode, "spoof")

    def test_media_to_hk(self):
        self.assertEqual(self.table.match("youtube.com").outbound, "hk-ss2022")
        self.assertEqual(self.table.match("x.com").outbound, "hk-ss2022")

    def test_direct_domain_real_ip(self):
        cr = self.table.match("bilibili.com")
        self.assertEqual(cr.outbound, "direct")
        self.assertEqual(cr.dns_mode, "direct")

    def test_final_falls_to_jp(self):
        cr = self.table.match("nowhere.example")
        self.assertEqual(cr.rule.type, "FINAL")
        self.assertEqual(cr.outbound, "jp")
        self.assertEqual(cr.dns_mode, "spoof")

    def test_dnsdist_spoofs_proxy_not_direct(self):
        lua = gen_dnsdist.generate(self.table, self.config)
        self.assertIn('pdgProxy:add("openai.com")', lua)
        self.assertIn("SpoofAction({SPOOF_IP}", lua)
        # 直连域名不应进入 spoof 集
        self.assertNotIn('pdgProxy:add("bilibili.com")', lua)

    def test_singbox_routes_and_final(self):
        conf = json.loads(gen_singbox.generate(self.table, self.config))
        self.assertEqual(conf["route"]["final"], "jp")
        tags = {ob["tag"] for ob in conf["outbounds"]}
        self.assertTrue({"hk-ss2022", "tw-ss2022", "direct", "jp"} <= tags)
        # 透明入口必须开 sniff, 否则拿不到域名
        inbound = conf["inbounds"][0]
        self.assertTrue(inbound["sniff"])
        self.assertTrue(inbound["sniff_override_destination"])


if __name__ == "__main__":
    unittest.main()
