"""
Unit tests for the What-If Supply Chain Simulator.
Validates non-mutating copy, risk improvements, worsening, neutral replacements,
unknown component handling, multi-node replacement, and engine immutability.
"""

import copy
import json
import unittest
from pathlib import Path
import sys

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "src"))

from bom_parser import parse_bom
from cve_matcher import load_cve_database
from rules_engine import load_rules
from alternatives_engine import load_alternatives, find_alternatives_for
from simulator import run_simulation, evaluate_components

CVE_DB_PATH = BASE_DIR / "data" / "cve_database.json"
RULES_PATH = BASE_DIR / "data" / "rules.json"
ALTERNATIVES_PATH = BASE_DIR / "data" / "alternatives.json"
SAMPLE_CSV_PATH = BASE_DIR / "data" / "sample_bom.csv"
RAW_BOM_PATH = BASE_DIR / "data" / "raw_bom_large.csv"


class TestSimulator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cve_db = load_cve_database(CVE_DB_PATH)
        cls.rules = load_rules(RULES_PATH)
        cls.alternatives = load_alternatives(ALTERNATIVES_PATH)
        cls.components, _ = parse_bom(SAMPLE_CSV_PATH)

    def test_alternatives_catalog_loaded(self):
        self.assertGreater(len(self.alternatives), 0)
        alts = find_alternatives_for("BMC Firmware", "AMI", self.alternatives)
        self.assertGreaterEqual(len(alts), 2)
        self.assertEqual(alts[0]["version"], "13.1")

    def test_simulation_improves_risk(self):
        """Replacing vulnerable AMI BMC v12.4 with patched v13.1 should reduce risk."""
        target = {"component_name": "BMC Firmware", "vendor": "AMI", "version": "12.4"}
        substitute = {
            "component_name": "BMC Firmware",
            "vendor": "AMI",
            "version": "13.1",
            "origin_country": "US",
            "part_number": "AMI-BMC-131",
        }

        # Snapshot original copy to test immutability
        orig_before = copy.deepcopy(self.components)

        res = run_simulation(
            original_components=self.components,
            target_component=target,
            substitute_component=substitute,
            cve_entries=self.cve_db,
            rules=self.rules,
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["overall"]["outcome"], "improved")
        self.assertLess(res["overall"]["after_score"], res["overall"]["before_score"])
        self.assertLess(res["overall"]["delta_score"], 0)
        self.assertGreater(res["overall"]["percent_reduction"], 0)

        # Target had 2 CVEs; substitute has 0 CVEs
        self.assertEqual(res["target"]["cve_count"], 2)
        self.assertEqual(res["substitute"]["cve_count"], 0)
        self.assertEqual(res["dimension_changes"]["cve_delta"], -2)
        self.assertIn("Remediated 2 known CVE(s)", res["explanation"])

        # Check immutability of original components
        self.assertEqual(self.components, orig_before)

    def test_simulation_resolves_policy_violation(self):
        """Replacing Hikvision camera with Axis camera resolves restricted-vendor flag."""
        target = {"component_name": "Network Camera Module", "vendor": "Hikvision", "version": "DS-2CD2143"}
        substitute = {
            "component_name": "Network Camera Module",
            "vendor": "Axis Communications",
            "version": "10.12",
            "origin_country": "SE",
            "part_number": "AXIS-M3065V",
        }

        res = run_simulation(
            original_components=self.components,
            target_component=target,
            substitute_component=substitute,
            cve_entries=self.cve_db,
            rules=self.rules,
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(len(res["target"]["policy_flags"]), 1)
        self.assertEqual(len(res["substitute"]["policy_flags"]), 0)
        self.assertEqual(res["dimension_changes"]["policy_flag_delta"], -1)
        self.assertIn("compliance violation", res["explanation"])

    def test_simulation_worsens_risk(self):
        """Replacing a moderate component with an ultra-vulnerable, restricted component increases risk."""
        # Replace UEFI Firmware (56.7) with Aspeed BMC Firmware <=2.9 (CVSS 9.8 Pantsdown + EOL + Single Source)
        target = {"component_name": "UEFI Firmware", "vendor": "AMI", "version": "5.19"}
        substitute = {
            "component_name": "BMC Firmware",
            "vendor": "Aspeed",
            "version": "2.8",
            "origin_country": "RU",  # Restricted country (25 pts) + CVE-2019-6260 (58.8 pts) + EOL (7.5 pts) = 91.3
            "part_number": "ASPEED-28-RU",
        }

        res = run_simulation(
            original_components=self.components,
            target_component=target,
            substitute_component=substitute,
            cve_entries=self.cve_db,
            rules=self.rules,
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["overall"]["outcome"], "worsened")
        self.assertGreater(res["overall"]["after_score"], res["overall"]["before_score"])
        self.assertGreater(res["overall"]["delta_score"], 0)
        self.assertIn("Overall BOM risk increased", res["explanation"])

    def test_simulation_no_effect(self):
        """Replacing with identical specs yields delta = 0."""
        target = {"component_name": "BMC Firmware", "vendor": "AMI", "version": "12.4"}
        substitute = {
            "component_name": "BMC Firmware",
            "vendor": "AMI",
            "version": "12.4",
            "origin_country": "US",
            "part_number": "AMI-BMC-124",
        }

        res = run_simulation(
            original_components=self.components,
            target_component=target,
            substitute_component=substitute,
            cve_entries=self.cve_db,
            rules=self.rules,
        )

        self.assertEqual(res["overall"]["outcome"], "unchanged")
        self.assertEqual(res["overall"]["delta_score"], 0.0)
        self.assertEqual(res["overall"]["before_score"], res["overall"]["after_score"])

    def test_unknown_component_handling(self):
        """An unrecognized replacement must be flagged as unscored and NOT assumed safe."""
        target = {"component_name": "BMC Firmware", "vendor": "AMI", "version": "12.4"}
        substitute = {
            "component_name": "Mysterious Custom BMC",
            "vendor": "UnknownVendorTech",
            "version": "9.9.9",
            "origin_country": "ZZ",
            "part_number": "UNKNOWN-001",
        }

        res = run_simulation(
            original_components=self.components,
            target_component=target,
            substitute_component=substitute,
            cve_entries=self.cve_db,
            rules=self.rules,
        )

        self.assertIsNone(res["substitute"]["risk_score"])
        self.assertFalse(res["substitute"]["is_scored"])
        self.assertIn("unscored (requires manual verification, not assumed safe)", res["explanation"])

    def test_no_target_raises_error(self):
        """Specifying a nonexistent target component raises ValueError."""
        target = {"component_name": "NonExistentPart", "vendor": "GhostCorp", "version": "0.0"}
        substitute = {"component_name": "Replacement", "vendor": "RealCorp", "version": "1.0"}

        with self.assertRaises(ValueError):
            run_simulation(
                original_components=self.components,
                target_component=target,
                substitute_component=substitute,
                cve_entries=self.cve_db,
                rules=self.rules,
            )

    def test_multi_node_fleet_replacement(self):
        """In large BOM with multi-node components, fleet-wide replacement updates all nodes."""
        raw_components, _ = parse_bom(RAW_BOM_PATH)
        target = {"component_name": "BMC Firmware", "vendor": "AMI", "version": "12.4"}
        substitute = {
            "component_name": "BMC Firmware",
            "vendor": "AMI",
            "version": "13.1",
            "origin_country": "US",
            "part_number": "AMI-BMC-131",
        }

        res = run_simulation(
            original_components=raw_components,
            target_component=target,
            substitute_component=substitute,
            cve_entries=self.cve_db,
            rules=self.rules,
            scope="all_instances",
        )

        self.assertGreater(res["replaced_count"], 1)
        self.assertIn(f"Applied across {res['replaced_count']} affected units", res["explanation"])


if __name__ == "__main__":
    unittest.main()
