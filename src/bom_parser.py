"""
bom_parser.py
Normalizes input BOMs (CSV or CycloneDX JSON) into one internal schema so every
downstream module (matcher, rules, scoring) only ever deals with one shape of data.

Internal schema per component:
    {
        "component_name": str,
        "vendor": str,
        "version": str,
        "origin_country": str,   # ISO-2 code, or "UNKNOWN" if missing
        "part_number": str,      # optional, "" if not present
        "raw_row": dict          # original row, kept for traceability in the report
    }
"""

import csv
import json
from pathlib import Path


REQUIRED_FIELDS = ["component_name", "vendor", "version"]


def _normalize_row(component_name, vendor, version, origin_country, part_number, raw_row, unit_id=None):
    return {
        "component_name": (component_name or "").strip(),
        "vendor": (vendor or "").strip(),
        "version": (version or "").strip(),
        "origin_country": (origin_country or "UNKNOWN").strip().upper() or "UNKNOWN",
        "part_number": (part_number or "").strip(),
        "unit_id": (unit_id or "UNSPECIFIED").strip() or "UNSPECIFIED",
        "raw_row": raw_row,
    }


def parse_csv(path):
    """Parses a flat CSV BOM. Expected columns (case-insensitive):
    component_name, vendor, version, origin_country, part_number.
    Missing optional columns are tolerated; missing required columns raise per-row
    validation errors that are returned alongside successfully parsed rows rather
    than aborting the whole ingest (a malformed row shouldn't take down the batch).
    """
    components = []
    errors = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        # allow header variants like "Component Name" / "component_name"
        fieldmap = {h: h.strip().lower().replace(" ", "_") for h in (reader.fieldnames or [])}
        for i, row in enumerate(reader, start=2):  # header is row 1
            norm_row = {fieldmap[k]: v for k, v in row.items() if k in fieldmap}
            missing = [f for f in REQUIRED_FIELDS if not norm_row.get(f)]
            if missing:
                errors.append({"row": i, "issue": f"missing required field(s): {missing}", "raw": row})
                continue
            components.append(_normalize_row(
                norm_row.get("component_name"),
                norm_row.get("vendor"),
                norm_row.get("version"),
                norm_row.get("origin_country"),
                norm_row.get("part_number"),
                row,
                unit_id=norm_row.get("unit_id"),
            ))
    return components, errors


def parse_cyclonedx(path):
    """Parses a (subset of) CycloneDX JSON BOM. Only the fields the scoring
    pipeline needs are extracted; unrecognized fields are ignored rather than
    rejected, since real-world CycloneDX documents carry far more metadata
    than this tool consumes.
    """
    components = []
    errors = []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    for i, comp in enumerate(data.get("components", [])):
        name = comp.get("name")
        vendor = (comp.get("supplier") or {}).get("name")
        version = comp.get("version")
        origin = None
        for prop in comp.get("properties", []):
            if prop.get("name") == "origin_country":
                origin = prop.get("value")
        if not all([name, vendor, version]):
            errors.append({"row": i, "issue": "missing required field(s) in component entry", "raw": comp})
            continue
        components.append(_normalize_row(name, vendor, version, origin, comp.get("part_number"), comp))
    return components, errors


def parse_bom(path):
    """Auto-detects format from file extension and dispatches to the right parser."""
    path = Path(path)
    if path.suffix.lower() == ".csv":
        return parse_csv(path)
    elif path.suffix.lower() == ".json":
        return parse_cyclonedx(path)
    else:
        raise ValueError(f"Unsupported BOM file type: {path.suffix}. Expected .csv or .json (CycloneDX).")
