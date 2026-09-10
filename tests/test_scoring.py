"""
Unit tests for scoring.py

Covers:
  - score_component: CVE term, vendor/origin term, lifecycle term,
    fuzzy confidence scaling, score cap at 100.
  - score_bom: aggregate formula (0.6*max + 0.4*mean), unknown count,
    all-unscored edge case, single-component BOM.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scoring import (
    score_component,
    score_bom,
    CVE_WEIGHT_MAX,
    VENDOR_ORIGIN_WEIGHT,
    LIFECYCLE_WEIGHT_MAX,
    LIFECYCLE_PER_FLAG,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _component(name="Widget", vendor="ACME", version="1.0", country="US"):
    return {
        "component_name": name,
        "vendor": vendor,
        "version": version,
        "origin_country": country,
        "part_number": "",
    }


def _exact_match(cvss_scores):
    return {
        "status": "matched",
        "confidence": 1.0,
        "cves": [{"id": f"CVE-2024-{i}", "cvss_score": s} for i, s in enumerate(cvss_scores)],
    }


def _fuzzy_match(cvss_scores, confidence):
    result = _exact_match(cvss_scores)
    result["status"] = "fuzzy_matched"
    result["confidence"] = confidence
    return result


def _unmatched():
    return {"status": "unmatched", "confidence": 0.0, "cves": []}


def _no_flags():
    return {"origin_vendor_flags": [], "lifecycle_flags": []}


def _vendor_flags(*reasons):
    return {"origin_vendor_flags": list(reasons), "lifecycle_flags": []}


def _lifecycle_flags(*reasons):
    return {"origin_vendor_flags": [], "lifecycle_flags": list(reasons)}


# ---------------------------------------------------------------------------
# score_component
# ---------------------------------------------------------------------------

class TestScoreComponent(unittest.TestCase):

    def test_no_cve_no_flags_scores_zero(self):
        result = score_component(_component(), _unmatched(), _no_flags())
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["breakdown"]["cve_term"], 0.0)
        self.assertEqual(result["breakdown"]["vendor_origin_term"], 0.0)
        self.assertEqual(result["breakdown"]["lifecycle_term"], 0.0)

    def test_critical_cvss_10_exact_match(self):
        result = score_component(_component(), _exact_match([10.0]), _no_flags())
        self.assertEqual(result["breakdown"]["cve_term"], CVE_WEIGHT_MAX)
        self.assertEqual(result["score"], float(CVE_WEIGHT_MAX))

    def test_cvss_uses_max_not_sum(self):
        result_two = score_component(_component(), _exact_match([4.0, 8.0]), _no_flags())
        result_one = score_component(_component(), _exact_match([8.0]), _no_flags())
        self.assertEqual(result_two["breakdown"]["cve_term"], result_one["breakdown"]["cve_term"])

    def test_fuzzy_match_scales_by_confidence(self):
        exact = score_component(_component(), _exact_match([10.0]), _no_flags())
        fuzzy = score_component(_component(), _fuzzy_match([10.0], 0.9), _no_flags())
        self.assertAlmostEqual(
            fuzzy["breakdown"]["cve_term"],
            exact["breakdown"]["cve_term"] * 0.9,
            places=5,
        )

    def test_unmatched_produces_zero_cve_term(self):
        result = score_component(_component(), _unmatched(), _no_flags())
        self.assertEqual(result["breakdown"]["cve_term"], 0.0)
        self.assertEqual(result["match_status"], "unmatched")

    def test_vendor_flag_adds_full_weight(self):
        result = score_component(_component(), _unmatched(), _vendor_flags("Restricted vendor"))
        self.assertEqual(result["breakdown"]["vendor_origin_term"], VENDOR_ORIGIN_WEIGHT)

    def test_multiple_vendor_flags_do_not_stack(self):
        result = score_component(_component(), _unmatched(), _vendor_flags("Reason A", "Reason B"))
        self.assertEqual(result["breakdown"]["vendor_origin_term"], VENDOR_ORIGIN_WEIGHT)

    def test_no_vendor_flag_zero_term(self):
        result = score_component(_component(), _unmatched(), _no_flags())
        self.assertEqual(result["breakdown"]["vendor_origin_term"], 0.0)

    def test_one_lifecycle_flag(self):
        result = score_component(_component(), _unmatched(), _lifecycle_flags("EOL 2024-01-01"))
        self.assertEqual(result["breakdown"]["lifecycle_term"], LIFECYCLE_PER_FLAG)

    def test_two_lifecycle_flags_hit_cap(self):
        result = score_component(_component(), _unmatched(), _lifecycle_flags("EOL", "Single-source"))
        self.assertEqual(result["breakdown"]["lifecycle_term"], LIFECYCLE_WEIGHT_MAX)

    def test_three_lifecycle_flags_still_capped(self):
        result = score_component(_component(), _unmatched(), _lifecycle_flags("A", "B", "C"))
        self.assertEqual(result["breakdown"]["lifecycle_term"], LIFECYCLE_WEIGHT_MAX)

    def test_score_capped_at_100(self):
        result = score_component(
            _component(),
            _exact_match([10.0]),
            {"origin_vendor_flags": ["Restricted"], "lifecycle_flags": ["EOL", "Single-source"]},
        )
        self.assertLessEqual(result["score"], 100.0)

    def test_score_is_rounded_to_one_decimal(self):
        result = score_component(_component(), _exact_match([7.3]), _no_flags())
        self.assertEqual(result["score"], round(result["score"], 1))

    def test_return_fields_present(self):
        result = score_component(_component(), _exact_match([5.0]), _no_flags())
        for key in ("score", "breakdown", "cve_confidence", "match_status"):
            self.assertIn(key, result)
        for key in ("cve_term", "vendor_origin_term", "lifecycle_term"):
            self.assertIn(key, result["breakdown"])

    def test_match_status_propagated(self):
        exact = score_component(_component(), _exact_match([5.0]), _no_flags())
        fuzzy = score_component(_component(), _fuzzy_match([5.0], 0.85), _no_flags())
        unmatched = score_component(_component(), _unmatched(), _no_flags())
        self.assertEqual(exact["match_status"], "matched")
        self.assertEqual(fuzzy["match_status"], "fuzzy_matched")
        self.assertEqual(unmatched["match_status"], "unmatched")


# ---------------------------------------------------------------------------
# score_bom
# ---------------------------------------------------------------------------

class TestScoreBom(unittest.TestCase):

    def _scored(self, score):
        return {"score_data": {"score": score}}

    def _unscored(self):
        return {"score_data": None}

    def test_aggregate_formula(self):
        components = [self._scored(80.0), self._scored(40.0)]
        result = score_bom(components)
        expected = round(0.6 * 80.0 + 0.4 * 60.0, 1)
        self.assertEqual(result["aggregate_score"], expected)

    def test_single_component(self):
        result = score_bom([self._scored(55.0)])
        self.assertEqual(result["aggregate_score"], 55.0)

    def test_unknown_components_excluded(self):
        components = [self._scored(70.0), self._unscored(), self._unscored()]
        result = score_bom(components)
        self.assertEqual(result["scored_count"], 1)
        self.assertEqual(result["unknown_count"], 2)
        self.assertEqual(result["aggregate_score"], 70.0)

    def test_all_unscored_returns_none(self):
        result = score_bom([self._unscored(), self._unscored()])
        self.assertIsNone(result["aggregate_score"])
        self.assertEqual(result["unknown_count"], 2)
        self.assertIn("note", result)

    def test_aggregate_score_rounded(self):
        result = score_bom([self._scored(77.7), self._scored(33.3)])
        self.assertEqual(result["aggregate_score"], round(result["aggregate_score"], 1))

    def test_max_and_mean_reported(self):
        result = score_bom([self._scored(90.0), self._scored(30.0)])
        self.assertEqual(result["max_component_score"], 90.0)
        self.assertAlmostEqual(result["mean_component_score"], 60.0, places=1)

    def test_scored_and_unknown_counts(self):
        components = [self._scored(50.0), self._scored(60.0), self._unscored()]
        result = score_bom(components)
        self.assertEqual(result["scored_count"], 2)
        self.assertEqual(result["unknown_count"], 1)


if __name__ == "__main__":
    unittest.main()
