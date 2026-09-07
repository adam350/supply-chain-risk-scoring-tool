"""
rules_engine.py
Applies the non-CVE risk dimensions required by the brief:
  - country-of-origin / restricted-vendor rules
  - component-level factors: EOL status, single-source dependency

Kept separate from cve_matcher.py so each risk dimension is independently
testable and independently explainable in the report (the brief asks for
"at least three risk dimensions" - this module alone covers two of them).
"""

import json
from datetime import date, datetime


def load_rules(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check_origin_and_vendor(component, rules):
    reasons = []
    country = component["origin_country"]
    vendor = component["vendor"]

    if country in rules["restricted_countries"]:
        reasons.append(f"Component origin country '{country}' is on the restricted-country list.")

    for entry in rules["restricted_vendors"]:
        if vendor.lower() == entry["vendor"].lower():
            reasons.append(f"Vendor '{vendor}' is on the restricted-vendor list: {entry['reason']}")

    if country == "UNKNOWN":
        reasons.append("Origin country not provided - cannot verify against restricted-country list.")

    return reasons


def check_lifecycle(component, rules, today=None):
    """EOL status + single-source dependency check."""
    today = today or date.today()
    reasons = []
    key = f"{component['vendor']}:{component['component_name']}"

    eol_str = rules["eol_dates"].get(key)
    if eol_str:
        eol_date = datetime.strptime(eol_str, "%Y-%m-%d").date()
        if eol_date <= today:
            reasons.append(f"Component reached end-of-life on {eol_str} - no further security patches expected.")
        elif (eol_date.year - today.year) * 12 + (eol_date.month - today.month) <= 6:
            reasons.append(f"Component approaching end-of-life ({eol_str}) within 6 months.")

    if component["component_name"] in rules["single_source_components"]:
        reasons.append(f"'{component['component_name']}' is flagged as a single-source dependency - no qualified alternate vendor on record.")

    return reasons


def apply_rules(component, rules):
    """Returns {"origin_vendor_flags": [...], "lifecycle_flags": [...]}"""
    return {
        "origin_vendor_flags": check_origin_and_vendor(component, rules),
        "lifecycle_flags": check_lifecycle(component, rules),
    }
