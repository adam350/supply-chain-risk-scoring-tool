"""
Unit tests for bom_parser.py (CSV and CycloneDX BOM ingestion).
"""

import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from bom_parser import parse_bom, parse_cyclonedx, parse_csv


class TestBOMParser(unittest.TestCase):

    def test_parse_sample_cyclonedx(self):
        sample_path = Path(__file__).parent.parent / "data" / "sample_bom_cyclonedx.json"
        components, errors = parse_cyclonedx(sample_path)

        # 5 valid demo parts
        self.assertEqual(len(components), 5)
        # 1 nested invalid fragment (MegaRAC SP-X missing vendor and version)
        self.assertEqual(len(errors), 1)
        self.assertIn("missing required field(s)", errors[0]["issue"])
        self.assertIn("vendor", errors[0]["issue"])
        self.assertIn("version", errors[0]["issue"])

        names = [c["component_name"] for c in components]
        vendors = [c["vendor"] for c in components]
        versions = [c["version"] for c in components]
        origins = [c["origin_country"] for c in components]

        self.assertEqual(names, [
            "BMC Firmware",
            "NIC Firmware",
            "TPM Module",
            "Network Camera Module",
            "Custom Sensor Board",
        ])
        self.assertEqual(vendors, [
            "AMI",
            "Broadcom",
            "Nuvoton",
            "Hikvision",
            "Rev3 Labs",
        ])
        self.assertEqual(versions, [
            "12.4",
            "21.60",
            "1.3.2",
            "DS-2CD2143",
            "2.1",
        ])
        self.assertEqual(origins, [
            "US",
            "US",
            "TW",
            "CN",
            "ZZ",
        ])

    def test_vendor_precedence_and_types(self):
        # Test supplier, manufacturer, publisher in priority order
        test_bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "Comp Supplier Dict",
                    "version": "1.0",
                    "supplier": {"name": "SupCorp"},
                    "manufacturer": {"name": "ManCorp"},
                    "publisher": "PubCorp",
                },
                {
                    "name": "Comp Supplier String",
                    "version": "1.0",
                    "supplier": "SupStrCorp",
                },
                {
                    "name": "Comp Manufacturer Dict",
                    "version": "1.0",
                    "manufacturer": {"name": "ManCorp"},
                    "publisher": "PubCorp",
                },
                {
                    "name": "Comp Manufacturers List",
                    "version": "1.0",
                    "manufacturers": [{"name": "ListManCorp"}],
                },
                {
                    "name": "Comp Publisher Str",
                    "version": "1.0",
                    "publisher": "PubCorp",
                },
                {
                    "name": "Comp Publisher Dict",
                    "version": "1.0",
                    "publisher": {"name": "PubDictCorp"},
                },
            ],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(test_bom, f)
            temp_path = f.name

        try:
            comps, errs = parse_cyclonedx(temp_path)
            self.assertEqual(len(errs), 0)
            self.assertEqual(comps[0]["vendor"], "SupCorp")
            self.assertEqual(comps[1]["vendor"], "SupStrCorp")
            self.assertEqual(comps[2]["vendor"], "ManCorp")
            self.assertEqual(comps[3]["vendor"], "ListManCorp")
            self.assertEqual(comps[4]["vendor"], "PubCorp")
            self.assertEqual(comps[5]["vendor"], "PubDictCorp")
        finally:
            Path(temp_path).unlink()

    def test_origin_resolution(self):
        # Test demo properties override address, address used when properties absent
        test_bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "Prop Origin",
                    "vendor": "TestVendor",
                    "supplier": {
                        "name": "TestVendor",
                        "address": {"country": "Taiwan"},
                    },
                    "version": "1.0",
                    "properties": [{"name": "origin_country", "value": "Japan"}],
                },
                {
                    "name": "Supplier Address Origin",
                    "version": "1.0",
                    "supplier": {
                        "name": "TestVendor",
                        "address": {"country": "Germany"},
                    },
                },
                {
                    "name": "Manufacturer Address Origin",
                    "version": "1.0",
                    "manufacturer": {
                        "name": "TestVendor",
                        "address": {"country": "United States"},
                    },
                },
                {
                    "name": "Unknown Origin",
                    "version": "1.0",
                    "publisher": "TestVendor",
                },
            ],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(test_bom, f)
            temp_path = f.name

        try:
            comps, errs = parse_cyclonedx(temp_path)
            self.assertEqual(len(errs), 0)
            self.assertEqual(comps[0]["origin_country"], "JP")
            self.assertEqual(comps[1]["origin_country"], "DE")
            self.assertEqual(comps[2]["origin_country"], "US")
            self.assertEqual(comps[3]["origin_country"], "UNKNOWN")
        finally:
            Path(temp_path).unlink()

    def test_missing_required_fields_logged_and_continued(self):
        test_bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "Valid First",
                    "supplier": {"name": "Vendor A"},
                    "version": "1.0",
                },
                {
                    "type": "library",
                    "name": "Missing Vendor",
                    "version": "1.0",
                },
                {
                    "type": "library",
                    "supplier": {"name": "Vendor C"},
                    "version": "1.0",
                },
                {
                    "type": "library",
                    "name": "Missing Version",
                    "supplier": {"name": "Vendor D"},
                },
                {
                    "type": "library",
                    "name": "Valid Last",
                    "publisher": "Vendor E",
                    "version": "2.0",
                },
            ],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(test_bom, f)
            temp_path = f.name

        try:
            comps, errs = parse_cyclonedx(temp_path)
            self.assertEqual(len(comps), 2)
            self.assertEqual(comps[0]["component_name"], "Valid First")
            self.assertEqual(comps[1]["component_name"], "Valid Last")

            self.assertEqual(len(errs), 3)
            self.assertIn("['vendor']", errs[0]["issue"])
            self.assertIn("['component_name']", errs[1]["issue"])
            self.assertIn("['version']", errs[2]["issue"])
        finally:
            Path(temp_path).unlink()

    def test_reject_non_cyclonedx_json(self):
        # A random JSON file that is not CycloneDX must raise ValueError
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"project": "not a cyclonedx file", "data": [1, 2, 3]}, f)
            temp_path = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                parse_cyclonedx(temp_path)
            self.assertIn("is not a CycloneDX BOM (expected top-level bomFormat 'CycloneDX')", str(ctx.exception))
        finally:
            Path(temp_path).unlink()


if __name__ == "__main__":
    unittest.main()
