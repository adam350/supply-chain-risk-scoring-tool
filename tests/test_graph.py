"""
Unit tests for build_graph_data in visualization.py
"""

import unittest
from pathlib import Path
import sys

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR / "src"))

from visualization import build_graph_data


class TestRiskGraphData(unittest.TestCase):
    def test_empty_or_invalid_report(self):
        self.assertEqual(build_graph_data(None)["nodes"], [])
        self.assertEqual(build_graph_data({})["nodes"], [])
        self.assertEqual(build_graph_data("not a dict")["edges"], [])

    def test_component_vendor_and_cve_extraction(self):
        report_data = {
            "findings_ranked": [
                {
                    "component_name": "BMC Firmware",
                    "vendor": "AMI",
                    "version": "12.4",
                    "origin_country": "US",
                    "risk_score": 69.6,
                    "score_breakdown": {"cve_term": 54.6, "vendor_origin_term": 0.0, "lifecycle_term": 15},
                    "matched_cves": [
                        {
                            "id": "CVE-2023-34329",
                            "cvss": 9.1,
                            "severity": "CRITICAL",
                            "description": "Auth bypass",
                        }
                    ],
                    "policy_flags": [],
                    "lifecycle_flags": ["EOL"],
                    "suggested_mitigation": "Upgrade firmware",
                    "affected_units": ["NODE-01"],
                    "unit_count": 1,
                },
                {
                    "component_name": "UEFI Firmware",
                    "vendor": "AMI",
                    "version": "5.19",
                    "origin_country": "US",
                    "risk_score": 55.0,
                    "score_breakdown": {"cve_term": 45.0, "vendor_origin_term": 0.0, "lifecycle_term": 10},
                    "matched_cves": [],
                    "policy_flags": [],
                    "lifecycle_flags": [],
                    "suggested_mitigation": "",
                    "affected_units": ["NODE-01"],
                    "unit_count": 1,
                }
            ],
            "unscored_components": [
                {
                    "component_name": "Generic Sensor",
                    "vendor": "Rev3 Labs",
                    "version": "1.0",
                    "origin_country": "ZZ",
                    "reason": "No verification data",
                    "action_required": "Manual review",
                    "affected_units": ["NODE-01"],
                    "unit_count": 1,
                }
            ]
        }

        graph = build_graph_data(report_data)
        nodes = graph["nodes"]
        edges = graph["edges"]
        summary = graph["summary"]

        # Check nodes
        node_types = {n["type"] for n in nodes}
        self.assertIn("component", node_types)
        self.assertIn("vendor", node_types)
        self.assertIn("vulnerability", node_types)

        # Components: 2 scored + 1 unscored = 3
        comp_nodes = [n for n in nodes if n["type"] == "component"]
        self.assertEqual(len(comp_nodes), 3)

        # Check risk level assignment
        bmc_node = next(n for n in comp_nodes if n["name"] == "BMC Firmware")
        self.assertEqual(bmc_node["risk_level"], "critical")
        self.assertEqual(bmc_node["risk_score"], 69.6)

        uefi_node = next(n for n in comp_nodes if n["name"] == "UEFI Firmware")
        self.assertEqual(uefi_node["risk_level"], "high")

        sensor_node = next(n for n in comp_nodes if n["name"] == "Generic Sensor")
        self.assertEqual(sensor_node["risk_level"], "unscored")

        # Vendors: "AMI" (shared between BMC & UEFI) and "Rev3 Labs" = 2 vendor nodes
        vendor_nodes = [n for n in nodes if n["type"] == "vendor"]
        self.assertEqual(len(vendor_nodes), 2)
        ami_vendor = next(v for v in vendor_nodes if v["name"] == "AMI")
        self.assertEqual(ami_vendor["component_count"], 2)

        # Vulnerabilities: 1 CVE node
        cve_nodes = [n for n in nodes if n["type"] == "vulnerability"]
        self.assertEqual(len(cve_nodes), 1)
        self.assertEqual(cve_nodes[0]["cve_id"], "CVE-2023-34329")

        # Edges:
        # BMC -> AMI (supplied_by)
        # BMC -> CVE-2023-34329 (vulnerable_to)
        # UEFI -> AMI (supplied_by)
        # Generic Sensor -> Rev3 Labs (supplied_by)
        # Total edges = 4
        self.assertEqual(len(edges), 4)
        edge_types = {e["type"] for e in edges}
        self.assertEqual(edge_types, {"supplied_by", "vulnerable_to"})

        # Summary
        self.assertEqual(summary["total_nodes"], len(nodes))
        self.assertEqual(summary["total_edges"], len(edges))
        self.assertEqual(summary["components_count"], 3)
        self.assertEqual(summary["vendors_count"], 2)
        self.assertEqual(summary["cves_count"], 1)
        self.assertEqual(summary["risk_counts"]["critical"], 1)
        self.assertEqual(summary["risk_counts"]["high"], 1)
        self.assertEqual(summary["risk_counts"]["unscored"], 1)


if __name__ == "__main__":
    unittest.main()
