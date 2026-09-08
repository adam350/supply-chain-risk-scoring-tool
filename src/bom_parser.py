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

from normalize import normalize_country


REQUIRED_FIELDS = ["component_name", "vendor", "version"]
KNOWN_CDX_SPEC_VERSIONS = {"1.4", "1.5", "1.6"}
ORIGIN_PROPERTY_NAMES = (
    "origin_country",
    "cdx:hardware:origin",
    "countryoforigin",
    "country_of_origin",
)
PART_NUMBER_PROPERTY_NAMES = ("part_number", "partnumber")
UNIT_ID_PROPERTY_NAMES = ("unit_id", "unitid")


def _normalize_row(component_name, vendor, version, origin_country, part_number, raw_row, unit_id=None):
    origin, _note = normalize_country(origin_country)
    return {
        "component_name": (component_name or "").strip(),
        "vendor": (vendor or "").strip(),
        "version": (version or "").strip(),
        "origin_country": origin or "UNKNOWN",
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


def _properties_by_name(comp):
    mapped = {}
    for prop in comp.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        name = (prop.get("name") or "").strip()
        if name:
            mapped[name.lower()] = prop.get("value")
    return mapped


def _org_name(entity):
    if isinstance(entity, dict):
        return (entity.get("name") or "").strip() or None
    return None


def _org_country(entity):
    if not isinstance(entity, dict):
        return None
    address = entity.get("address")
    if isinstance(address, dict):
        country = (address.get("country") or "").strip()
        return country or None
    return None


def _vendor_from_comp(comp):
    publisher = comp.get("publisher")
    publisher_name = publisher.strip() if isinstance(publisher, str) else None
    return (
        _org_name(comp.get("supplier"))
        or _org_name(comp.get("manufacturer"))
        or publisher_name
        or None
    )


def _origin_from_comp(comp):
    props = _properties_by_name(comp)
    for key in ORIGIN_PROPERTY_NAMES:
        value = props.get(key)
        if value:
            return value
    return _org_country(comp.get("manufacturer")) or _org_country(comp.get("supplier"))


def _first_property(comp, names):
    props = _properties_by_name(comp)
    for key in names:
        value = props.get(key)
        if value:
            return value
    return ""


def _walk_components(items, collected):
    for comp in items or []:
        if not isinstance(comp, dict):
            continue
        collected.append(comp)
        nested = comp.get("components")
        if nested:
            _walk_components(nested, collected)


def _append_component(components, errors, comp, index):
    name = (comp.get("name") or "").strip()
    vendor = _vendor_from_comp(comp)
    version = (comp.get("version") or "").strip()
    if not all([name, vendor, version]):
        errors.append({
            "row": index,
            "issue": "missing required field(s) in component entry",
            "raw": comp,
        })
        return
    components.append(_normalize_row(
        name,
        vendor,
        version,
        _origin_from_comp(comp),
        _first_property(comp, PART_NUMBER_PROPERTY_NAMES),
        comp,
        unit_id=_first_property(comp, UNIT_ID_PROPERTY_NAMES) or None,
    ))


def parse_cyclonedx(path):
    """Parses a (subset of) CycloneDX JSON BOM. Only the fields the scoring
    pipeline needs are extracted; unrecognized fields are ignored rather than
    rejected, since real-world CycloneDX documents carry far more metadata
    than this tool consumes.

    Vendor: supplier.name, then manufacturer.name, then publisher.
    Origin: origin_country (and a few aliases) in properties, then
    manufacturer/supplier address.country.
    Nested components are flattened into one list.
    """
    components = []
    errors = []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise ValueError(
            f"{path} is not a CycloneDX BOM (expected top-level bomFormat 'CycloneDX')."
        )

    spec = str(data.get("specVersion") or "").strip()
    if spec and spec not in KNOWN_CDX_SPEC_VERSIONS:
        errors.append({
            "row": "document",
            "issue": (
                f"warning: unrecognized CycloneDX specVersion '{spec}' "
                f"(known: {sorted(KNOWN_CDX_SPEC_VERSIONS)}); continuing"
            ),
            "raw": {"specVersion": spec},
        })

    metadata_component = (data.get("metadata") or {}).get("component")
    if isinstance(metadata_component, dict):
        name = (metadata_component.get("name") or "").strip()
        vendor = _vendor_from_comp(metadata_component)
        version = (metadata_component.get("version") or "").strip()
        if name and vendor and version:
            _append_component(components, errors, metadata_component, "metadata.component")

    flat = []
    _walk_components(data.get("components") or [], flat)
    for i, comp in enumerate(flat):
        _append_component(components, errors, comp, i)

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
