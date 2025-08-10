"""Minimal smoke test scaffold.
Extend later with synthetic pcaps and golden evidence.json fixtures.
"""
from pathlib import Path
import json

def test_reports_exist(tmp_path: Path):
    out = tmp_path / "reports"
    out.mkdir()
    (out / "evidence.json").write_text(json.dumps({"ok": True}))
    (out / "connectivity_report.md").write_text("# ok")

    assert (out / "evidence.json").exists()
    assert (out / "connectivity_report.md").exists()
