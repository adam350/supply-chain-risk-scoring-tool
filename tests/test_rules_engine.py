"""
Unit tests for rules_engine.py

Covers:
  - check_origin_and_vendor: restricted country, restricted vendor,
    unknown origin, clean component produces no flags.
  - check_lifecycle: EOL in past, approaching EOL (within 6 months),
    EOL in future beyond 6 months, single-source dependency,
    no lifecycle data.
  - apply_rules: integration check that both sub-checks are combined.
  - Edge cases: case-insensitive vendor matching, multiple flags at once.
"""

import sys
import unittest
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rules_engine import check_origin_and_vendor, check_lifecycle, apply_rules


# ---------------------------------------------------------------------------
# Minimal rule fixtures (mimic the real rules.json structure)
# ---------------------------------------------------------------------------

RULES = {
    "restricted_countries": ["CN", "RU"],
    "restricted_vendors": [
        {"vendor": "Hikvision", "reason": "Subject to NDAA Section 889 restrictions."},
        {"vendor": "Dahua", "reason": "Subject to NDAA Section 889 restrictions."},
    ],
    "eol_dates": {
        "AMI:BMC Firmware": "2023-01-01",          # well in the past
        "Broadcom:NIC Firmware": "2099-12-31",      # far future
        "Nuvoton:TPM Module": "",                   # empty string — no EOL data
    },
    "single_source_components": ["Custom Sensor Board"],
}


def _component(name="Widget", vendor="ACME", country="US"):
    return {
        "component_name": name,
        "vendor": vendor,
        "version": "1.0",
        "origin_country": country,
        "part_number": "",
    }


# ---------------------------------------------------------------------------
# check_origin_and_vendor
# ---------------------------------------------------------------------------

class TestCheckOriginAndVendor(unittest.TestCase):

    def test_clean_component_no_flags(self):
        flags = check_origin_and_vendor(_component(vendor="ACME", country="US"), RULES)
        self.assertEqual(flags, [])

    def test_restricted_country_flagged(self):
        flags = check_origin_and_vendor(_component(country="CN"), RULES)
        self.assertTrue(any("CN" in f for f in flags))

    def test_another_restricted_country_flagged(self):
        flags = check_origin_and_vendor(_component(country="RU"), RULES)
        self.assertTrue(any("RU" in f for f in flags))

    def test_non_restricted_country_not_flagged(self):
        flags = check_origin_and_vendor(_component(country="DE"), RULES)
        self.assertFalse(any("DE" in f for f in flags))

    def test_restricted_vendor_flagged(self):
        flags = check_origin_and_vendor(_component(vendor="Hikvision", country="US"), RULES)
        self.assertTrue(any("Hikvision" in f for f in flags))

    def test_restricted_vendor_case_insensitive(self):
        flags = check_origin_and_vendor(_component(vendor="HIKVISION", country="US"), RULES)
        self.assertTrue(any("HIKVISION" in f for f in flags))

    def test_restricted_vendor_lowercase(self):
        flags = check_origin_and_vendor(_component(vendor="dahua", country="US"), RULES)
        self.assertTrue(len(flags) >= 1)

    def test_both_country_and_vendor_restricted(self):
        flags = check_origin_and_vendor(_component(vendor="Hikvision", country="CN"), RULES)
        self.assertGreaterEqual(len(flags), 2)

    def test_unknown_origin_flagged(self):
        flags = check_origin_and_vendor(_component(country="UNKNOWN"), RULES)
        self.assertTrue(any("UNKNOWN" in f or "not provided" in f for f in flags))

    def test_unknown_origin_and_restricted_vendor(self):
        flags = check_origin_and_vendor(_component(vendor="Hikvision", country="UNKNOWN"), RULES)
        self.assertGreaterEqual(len(flags), 2)


# ---------------------------------------------------------------------------
# check_lifecycle
# ---------------------------------------------------------------------------

class TestCheckLifecycle(unittest.TestCase):

    def test_eol_in_past_flagged(self):
        comp = _component(name="BMC Firmware", vendor="AMI")
        flags = check_lifecycle(comp, RULES)
        self.assertTrue(any("end-of-life" in f.lower() for f in flags))

    def test_eol_far_future_not_flagged(self):
        comp = _component(name="NIC Firmware", vendor="Broadcom")
        flags = check_lifecycle(comp, RULES)
        # Far-future EOL should not trigger the flag
        self.assertFalse(any("end-of-life" in f.lower() for f in flags))
        self.assertFalse(any("approaching" in f.lower() for f in flags))

    def test_eol_approaching_within_6_months(self):
        # Use a dynamic date 3 months in the future so the test never expires
        soon = (date.today() + timedelta(days=90)).strftime("%Y-%m-%d")
        rules = dict(RULES, eol_dates={"TestVendor:TestComp": soon})
        comp = _component(name="TestComp", vendor="TestVendor")
        flags = check_lifecycle(comp, rules)
        self.assertTrue(any("approaching" in f.lower() for f in flags))

    def test_eol_just_over_6_months_not_flagged(self):
        future = (date.today() + timedelta(days=210)).strftime("%Y-%m-%d")
        rules = dict(RULES, eol_dates={"TestVendor:TestComp": future})
        comp = _component(name="TestComp", vendor="TestVendor")
        flags = check_lifecycle(comp, rules)
        self.assertEqual(flags, [])

    def test_no_eol_data_no_flag(self):
        comp = _component(name="TPM Module", vendor="Nuvoton")
        flags = check_lifecycle(comp, RULES)
        eol_flags = [f for f in flags if "end-of-life" in f.lower() or "approaching" in f.lower()]
        self.assertEqual(eol_flags, [])

    def test_single_source_flagged(self):
        comp = _component(name="Custom Sensor Board", vendor="Rev3 Labs")
        flags = check_lifecycle(comp, RULES)
        self.assertTrue(any("single-source" in f.lower() for f in flags))

    def test_non_single_source_not_flagged(self):
        comp = _component(name="Widget", vendor="ACME")
        flags = check_lifecycle(comp, RULES)
        self.assertFalse(any("single-source" in f.lower() for f in flags))

    def test_both_eol_and_single_source(self):
        soon = (date.today() + timedelta(days=30)).strftime("%Y-%m-%d")
        rules = dict(RULES, eol_dates={"Rev3 Labs:Custom Sensor Board": soon})
        comp = _component(name="Custom Sensor Board", vendor="Rev3 Labs")
        flags = check_lifecycle(comp, rules)
        self.assertGreaterEqual(len(flags), 2)

    def test_today_param_respected(self):
        """Passing an explicit 'today' must override date.today()."""
        rules = dict(RULES, eol_dates={"ACME:Widget": "2025-06-01"})
        comp = _component(name="Widget", vendor="ACME")
        # When today is after EOL, flag must fire
        flags_after = check_lifecycle(comp, rules, today=date(2025, 7, 1))
        self.assertTrue(any("end-of-life" in f.lower() for f in flags_after))
        # When today is well before EOL (> 6 months), no flag
        flags_before = check_lifecycle(comp, rules, today=date(2024, 11, 1))
        self.assertEqual(flags_before, [])


# ---------------------------------------------------------------------------
# apply_rules (integration)
# ---------------------------------------------------------------------------

class TestApplyRules(unittest.TestCase):

    def test_apply_rules_returns_both_dimensions(self):
        comp = _component(vendor="Hikvision", country="CN")
        result = apply_rules(comp, RULES)
        self.assertIn("origin_vendor_flags", result)
        self.assertIn("lifecycle_flags", result)
        self.assertIsInstance(result["origin_vendor_flags"], list)
        self.assertIsInstance(result["lifecycle_flags"], list)

    def test_clean_component_no_flags(self):
        comp = _component(vendor="ACME", country="US")
        result = apply_rules(comp, RULES)
        self.assertEqual(result["origin_vendor_flags"], [])
        self.assertEqual(result["lifecycle_flags"], [])

    def test_vendor_flag_via_apply_rules(self):
        comp = _component(vendor="Hikvision", country="US")
        result = apply_rules(comp, RULES)
        self.assertTrue(len(result["origin_vendor_flags"]) >= 1)

    def test_lifecycle_flag_via_apply_rules(self):
        comp = _component(name="Custom Sensor Board", vendor="Rev3 Labs", country="US")
        result = apply_rules(comp, RULES)
        self.assertTrue(len(result["lifecycle_flags"]) >= 1)


# ---------------------------------------------------------------------------
# cve_matcher version range (bonus — exercises the new robust comparator)
# ---------------------------------------------------------------------------

class TestVersionRange(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from cve_matcher import _version_in_range as _vir_fn
        cls.vir = staticmethod(_vir_fn)

    def test_exact_match(self):
        self.assertTrue(self.vir("1.2.3", ["1.2.3"]))
        self.assertFalse(self.vir("1.2.4", ["1.2.3"]))

    def test_less_than_or_equal(self):
        self.assertTrue(self.vir("1.2.0", ["<=1.3.0"]))
        self.assertTrue(self.vir("1.3.0", ["<=1.3.0"]))
        self.assertFalse(self.vir("1.4.0", ["<=1.3.0"]))

    def test_less_than(self):
        self.assertTrue(self.vir("1.2.9", ["<1.3.0"]))
        self.assertFalse(self.vir("1.3.0", ["<1.3.0"]))

    def test_greater_than_or_equal(self):
        self.assertTrue(self.vir("2.0.0", [">=1.5.0"]))
        self.assertTrue(self.vir("1.5.0", [">=1.5.0"]))
        self.assertFalse(self.vir("1.4.9", [">=1.5.0"]))

    def test_greater_than(self):
        self.assertTrue(self.vir("1.5.1", [">1.5.0"]))
        self.assertFalse(self.vir("1.5.0", [">1.5.0"]))

    def test_not_equal(self):
        self.assertTrue(self.vir("1.2.4", ["!=1.2.3"]))
        self.assertFalse(self.vir("1.2.3", ["!=1.2.3"]))

    def test_compound_range(self):
        self.assertTrue(self.vir("1.5.0", [">=1.0.0,<2.0.0"]))
        self.assertFalse(self.vir("2.0.0", [">=1.0.0,<2.0.0"]))
        self.assertFalse(self.vir("0.9.9", [">=1.0.0,<2.0.0"]))

    def test_build_metadata_stripped(self):
        self.assertTrue(self.vir("1.2.3+build.20240101", ["1.2.3"]))

    def test_prerelease_less_than_release(self):
        # 1.3.0-rc1 should be treated as less than 1.3.0
        self.assertTrue(self.vir("1.3.0-rc1", ["<1.3.0"]))
        self.assertFalse(self.vir("1.3.0-rc1", [">=1.3.0"]))

    def test_multiple_patterns_any_match(self):
        # "12.4" or "12.5" — version 12.5 should match
        self.assertTrue(self.vir("12.5", ["12.4", "12.5"]))

    def test_no_match_returns_false(self):
        self.assertFalse(self.vir("99.0.0", ["<1.0", "1.0", "2.0"]))


if __name__ == "__main__":
    unittest.main()
