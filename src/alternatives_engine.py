"""
alternatives_engine.py
Loads, filters, and manages alternative component recommendations for the What-If Supply Chain Simulator.
"""

import json
from pathlib import Path


def load_alternatives(path):
    """Loads the alternatives catalog from a JSON file."""
    path = Path(path)
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
        return data.get("alternatives", [])


def find_alternatives_for(component_name, vendor, alternatives_catalog):
    """
    Finds predefined alternatives for a given component_name and vendor.
    Case-insensitive matching.
    Returns a list of option dicts.
    """
    c_name_lower = (component_name or "").strip().lower()
    vendor_lower = (vendor or "").strip().lower()

    for item in alternatives_catalog:
        target_name = (item.get("target_component_name") or "").strip().lower()
        target_vendor = (item.get("target_vendor") or "").strip().lower()

        if target_name == c_name_lower and (not target_vendor or target_vendor == vendor_lower):
            return item.get("options", [])

    return []
