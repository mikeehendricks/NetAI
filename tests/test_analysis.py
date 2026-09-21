#!/usr/bin/env python3
"""Unit tests for the NetAI analysis engine (no server needed): python3 -m unittest tests.test_analysis"""
import pathlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analysis import engine  # noqa: E402
from app.analysis.common import detect_vendor  # noqa: E402
from app.analysis.summary import to_markdown  # noqa: E402

DEMO = Path(__file__).resolve().parents[1] / "demo_configs"


def load_items():
    return [{"name": f.name, "text": f.read_text()} for f in sorted(DEMO.glob("*.txt"))]


class TestVendorDetection(unittest.TestCase):
    def test_all_five_detected(self):
        for it in load_items():
            with self.subTest(it["name"]):
                self.assertNotEqual(detect_vendor(it["text"]), "unknown")

    def test_specific_vendors(self):
        expect = {"aruba-branch-sw.txt": "aruba", "cisco-access-switch.txt": "cisco",
                  "cisco-core-router.txt": "cisco", "fg-branch-fw.txt": "fortinet",
                  "pa-edge-fw.txt": "paloalto"}
        for it in load_items():
            self.assertEqual(detect_vendor(it["text"]), expect[it["name"]])

    def test_garbage_is_unknown(self):
        self.assertEqual(detect_vendor("hello world\nnothing here\n"), "unknown")


class TestEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = engine.analyze_files(load_items())

    def test_finds_critical_issues(self):
        rules = {f["rule_id"] for f in self.res["findings"]}
        for expected in ("CIS-001", "CIS-003", "PAN-001", "PAN-004",
                         "FGT-001", "FGT-007", "ARU-003", "ARU-004"):
            self.assertIn(expected, rules)

    def test_score_and_grade(self):
        self.assertGreater(self.res["score"], 60)
        self.assertIn(self.res["grade"], ("E", "F"))

    def test_topology_nodes(self):
        kinds = {n["kind"] for n in self.res["topology"]["nodes"]}
        self.assertIn("firewall", kinds)
        self.assertIn("router", kinds)
        self.assertIn("subnet", kinds)
        self.assertIn("cloud", kinds)          # default routes present
        self.assertIn("vlan", kinds)

    def test_topology_links_reference_existing_nodes(self):
        ids = {n["id"] for n in self.res["topology"]["nodes"]}
        for l in self.res["topology"]["links"]:
            self.assertIn(l["source"], ids)
            self.assertIn(l["target"], ids)

    def test_summary_structure(self):
        s = self.res["summary"]
        self.assertIn("headline", s)
        self.assertGreater(s["total_findings"], 10)
        self.assertEqual(len(s["devices"]), 5)
        md = to_markdown(s)
        self.assertIn("Executive Summary", md)
        self.assertIn("Remediation roadmap", md)

    def test_improved_configs_generated(self):
        for pf in self.res["per_file"]:
            mod = engine.VENDOR_MODULES[pf["vendor"]]
            improved = mod.improve(pf["device"], pf["findings"])
            self.assertGreater(len(improved), len(pf["device"]["raw"]) * 0.5)
            if any(f["auto_fixable"] for f in pf["findings"]):
                self.assertIn("NetAI", improved)

    def test_cisco_telnet_replaced(self):
        import re as _re

        for pf in self.res["per_file"]:
            if pf["vendor"] == "cisco" and pf["device"].get("hostname") == "CORE-RTR-01":
                mod = engine.VENDOR_MODULES["cisco"]
                improved = mod.improve(pf["device"], pf["findings"])
                self.assertIsNone(_re.search(r"^\s*transport input telnet", improved, _re.M))
                self.assertIsNone(_re.search(r"^\s*transport input all", improved, _re.M))
                self.assertIn("transport input ssh", improved)


if __name__ == "__main__":
    unittest.main(verbosity=2)
