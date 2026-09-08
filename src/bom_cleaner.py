"""
bom_cleaner.py
Runs BEFORE bom_parser/scoring. Takes a raw, potentially messy human-edited
CSV BOM and produces (1) a cleaned CSV ready for the scoring pipeline, and
(2) a cleaning report listing exactly what was removed/changed and why.

This is a deliberately separate stage from "unknown component handling" in
the scoring pipeline. Those are two different problems:
  - A row that's junk (blank, a placeholder like "TBD", an accidental
    duplicate) is not a real component at all - it should never reach the
    scoring pipeline, and it should never appear as "needs manual review"
    in the risk report, because there's nothing to review.
  - A row that IS a real component but has no matching CVE/policy/lifecycle
    data is genuinely unknown, and SHOULD appear as "needs manual review" -
    that's a correct, honest outcome, not a data quality problem.
Conflating these two would either hide real junk-data problems inside the
risk report, or bury genuine "we don't know" findings inside a cleaning log
where a security reviewer wouldn't think to look for them.
"""

import csv
from pathlib import Path

from normalize import normalize_country as _normalize_country


# Placeholder/test values that mean "this isn't real data" regardless of casing
JUNK_VALUES = {
    "", "tbd", "n/a", "na", "none", "null", "xxx", "xxxx", "test", "test data",
    "todo", "-", "--", "?", "unknown", "unspecified", "placeholder", "sample",
    "component_name", "vendor",  # guards against an accidentally re-pasted header row
}

REQUIRED_FIELDS = ["component_name", "vendor", "version"]


def _is_junk(value):
    return (value or "").strip().lower() in JUNK_VALUES


def clean_bom_csv(raw_path):
    """Returns (cleaned_rows, cleaning_log) where cleaned_rows is a list of
    dicts ready to be written back out as a clean CSV, and cleaning_log is a
    list of {"row": n, "action": "removed"|"corrected", "reason": str,
    "raw": dict} entries - one per row that was changed or dropped.
    """
    cleaned_rows = []
    cleaning_log = []
    seen_keys = set()  # for true-duplicate detection: same unit + same component

    with open(raw_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldmap = {h: h.strip().lower().replace(" ", "_") for h in (reader.fieldnames or [])}

        for i, raw_row in enumerate(reader, start=2):
            row = {fieldmap[k]: (v or "").strip() for k, v in raw_row.items() if k in fieldmap}

            # 1. Fully blank row
            if not any(row.values()):
                cleaning_log.append({"row": i, "action": "removed", "reason": "completely blank row", "raw": raw_row})
                continue

            # 2. Placeholder/junk values in the fields that matter most
            name = row.get("component_name", "")
            vendor = row.get("vendor", "")
            version = row.get("version", "")
            if _is_junk(name) or _is_junk(vendor):
                cleaning_log.append({
                    "row": i, "action": "removed",
                    "reason": f"placeholder/test value in required field (component_name='{name}', vendor='{vendor}')",
                    "raw": raw_row,
                })
                continue

            # 3. Missing required fields (real data, just incomplete)
            missing = [f for f in REQUIRED_FIELDS if not row.get(f) or _is_junk(row.get(f))]
            if missing:
                cleaning_log.append({
                    "row": i, "action": "removed",
                    "reason": f"missing/placeholder required field(s): {missing}",
                    "raw": raw_row,
                })
                continue

            # 4. Normalize country field
            unit_id = row.get("unit_id", "").strip() or "UNSPECIFIED"
            country_raw = row.get("origin_country", "")
            country_norm, country_note = _normalize_country(country_raw)
            if country_note:
                cleaning_log.append({"row": i, "action": "corrected", "reason": country_note, "raw": raw_row})

            # 5. Normalize whitespace/casing for display consistency (matching
            #    is case-insensitive downstream regardless, this is just hygiene)
            clean_row = {
                "unit_id": unit_id,
                "component_name": " ".join(name.split()),
                "vendor": " ".join(vendor.split()),
                "version": version,
                "origin_country": country_norm,
                "part_number": row.get("part_number", "").strip(),
            }

            # 6. True-duplicate detection: same unit_id + same component signature
            #    typed twice by mistake. NOTE: the same component appearing under
            #    DIFFERENT unit_ids is legitimate (e.g. 4 identical server nodes)
            #    and is deliberately NOT flagged here.
            dedup_key = (
                clean_row["unit_id"].lower(),
                clean_row["component_name"].lower(),
                clean_row["vendor"].lower(),
                clean_row["version"].lower(),
            )
            if dedup_key in seen_keys:
                cleaning_log.append({
                    "row": i, "action": "removed",
                    "reason": f"exact duplicate of an earlier row within the same unit ({unit_id})",
                    "raw": raw_row,
                })
                continue
            seen_keys.add(dedup_key)

            cleaned_rows.append(clean_row)

    return cleaned_rows, cleaning_log


def write_cleaned_csv(cleaned_rows, out_path):
    fieldnames = ["unit_id", "component_name", "vendor", "version", "origin_country", "part_number"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(cleaned_rows)


def render_cleaning_report_html(raw_path, cleaned_rows, cleaning_log, out_path):
    removed = [e for e in cleaning_log if e["action"] == "removed"]
    corrected = [e for e in cleaning_log if e["action"] == "corrected"]

    removed_cards = "".join(
        f"""<div class="log-card log-removed">
              <div class="log-head"><span class="row-num">Row {e['row']}</span><span class="pill pill-removed">Removed</span></div>
              <div class="log-reason">{e['reason']}</div>
              <div class="log-raw">{dict(e['raw'])}</div>
            </div>"""
        for e in removed
    )
    corrected_cards = "".join(
        f"""<div class="log-card log-corrected">
              <div class="log-head"><span class="row-num">Row {e['row']}</span><span class="pill pill-corrected">Corrected</span></div>
              <div class="log-reason">{e['reason']}</div>
            </div>"""
        for e in corrected
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BOM Cleaning Report</title>
<style>
  :root {{
    --bg: #0b1220; --panel: #131d30; --panel-2: #16233a; --border: #223252;
    --text: #e6edf3; --text-dim: #93a5c2; --accent: #6ee7c9;
    --red: #ff6b6b; --red-bg: #2a1418; --amber: #f0b74d; --amber-bg: #2a2114;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 32px 40px 64px; line-height: 1.5;
  }}
  .wrap {{ max-width: 860px; margin: 0 auto; }}
  h1 {{ font-size: 22px; font-weight: 700; margin: 0 0 24px; }}
  h2 {{ font-size: 15px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;
       letter-spacing: 0.06em; margin: 32px 0 14px; }}

  .summary {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
              padding: 20px 24px; display: flex; gap: 28px; flex-wrap: wrap; }}
  .stat {{ }}
  .stat .num {{ font-size: 26px; font-weight: 800; line-height: 1; }}
  .stat .label {{ font-size: 12px; color: var(--text-dim); margin-top: 4px; }}
  .stat.stat-removed .num {{ color: var(--red); }}
  .stat.stat-corrected .num {{ color: var(--amber); }}
  .stat.stat-clean .num {{ color: var(--accent); }}

  .log-card {{ background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--border);
               border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; font-size: 13px; }}
  .log-removed {{ border-left-color: var(--red); }}
  .log-corrected {{ border-left-color: var(--amber); }}
  .log-head {{ display: flex; justify-content: space-between; align-items: center; }}
  .row-num {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--text-dim); font-size: 12px; }}
  .pill {{ font-size: 10.5px; font-weight: 700; padding: 2px 9px; border-radius: 999px; text-transform: uppercase; letter-spacing: 0.03em; }}
  .pill-removed {{ background: var(--red-bg); color: var(--red); }}
  .pill-corrected {{ background: var(--amber-bg); color: var(--amber); }}
  .log-reason {{ margin-top: 6px; }}
  .log-raw {{ margin-top: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px;
              color: var(--text-dim); background: var(--panel-2); border-radius: 6px; padding: 6px 8px;
              word-break: break-all; }}
  .empty {{ color: var(--text-dim); font-size: 13px; }}
</style></head>
<body>
<div class="wrap">
  <h1>BOM Cleaning Report</h1>

  <div class="summary">
    <div class="stat stat-removed"><div class="num">{len(removed)}</div><div class="label">Rows removed</div></div>
    <div class="stat stat-corrected"><div class="num">{len(corrected)}</div><div class="label">Rows corrected</div></div>
    <div class="stat stat-clean"><div class="num">{len(cleaned_rows)}</div><div class="label">Clean rows → scoring</div></div>
  </div>

  <h2>Removed rows — never reach the risk report</h2>
  {removed_cards if removed_cards else '<p class="empty">None removed.</p>'}

  <h2>Corrected rows — kept, value normalized</h2>
  {corrected_cards if corrected_cards else '<p class="empty">None corrected.</p>'}
</div>
</body></html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
