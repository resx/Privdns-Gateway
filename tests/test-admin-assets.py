#!/usr/bin/env python3
"""Zashboard 静态资源自检回归。"""
import importlib.util
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pdg_checks", ROOT / "deploy/bot/checks.py")
checks = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(checks)

with tempfile.TemporaryDirectory() as directory:
    checks.ZASHBOARD_ROOT = directory
    level, label, detail = checks.check_zashboard_assets()
    assert level == "warn" and label == "Zashboard 资源", (level, label, detail)
    assert "404" in detail and "sudo pdg update" in detail, detail

    Path(directory, "index.html").write_text("<h1>Zashboard</h1>", encoding="utf-8")
    level, label, detail = checks.check_zashboard_assets()
    assert level == "ok" and label == "Zashboard 资源", (level, label, detail)

print("admin-assets regression OK")
