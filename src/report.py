"""
report.py
Turns the scored component list into (1) a JSON findings report for
programmatic use, and (2) a minimal single-file HTML report so the team can
literally open a file in a browser and see the output during the demo -
no frontend framework required at this stage.
"""

import json
from datetime import datetime


def build_findings_report(bom_source, scored_components, aggregate, parse_errors):
    known = [c for c in scored_components if c["score_data"] is not None]
    unknown = [c for c in scored_components if c["score_data"] is None]

    # Group by (component_name, vendor, version): the same part on multiple
    # physical units (e.g. 4 identical server nodes) is one finding with a
    # list of affected units, not 4 near-identical report rows. This is a
    # deliberate choice for readability at fleet scale - see DOCUMENTATION_NOTES.md.
    def group_key(c):
        comp = c["component"]
        return (comp["component_name"].lower(), comp["vendor"].lower(), comp["version"].lower())

    grouped_known = {}
    for c in known:
        key = group_key(c)
        grouped_known.setdefault(key, []).append(c)

    known_sorted = sorted(grouped_known.values(), key=lambda group: group[0]["score_data"]["score"], reverse=True)

    findings = []
    for group in known_sorted:
        c = group[0]  # representative entry; score/breakdown identical within a group by construction
        comp = c["component"]
        sd = c["score_data"]
        mitigation = _suggest_mitigation(comp, c["rule_flags"], c["match_result"])
        affected_units = sorted({g["component"]["unit_id"] for g in group})
        findings.append({
            "component_name": comp["component_name"],
            "vendor": comp["vendor"],
            "version": comp["version"],
            "origin_country": comp["origin_country"],
            "affected_units": affected_units,
            "unit_count": len(affected_units),
            "risk_score": sd["score"],
            "score_breakdown": sd["breakdown"],
            "match_status": sd["match_status"],
            "match_confidence": sd["cve_confidence"],
            "matched_cves": [
                {"id": e["cve_id"], "cvss": e["cvss_score"], "severity": e["severity"], "description": e["description"],
                 "provenance": e.get("provenance", "unknown"), "source_url": e.get("source_url")}
                for e in c["match_result"]["cves"]
            ],
            "policy_flags": c["rule_flags"]["origin_vendor_flags"],
            "lifecycle_flags": c["rule_flags"]["lifecycle_flags"],
            "suggested_mitigation": mitigation,
        })

    grouped_unknown = {}
    for c in unknown:
        key = group_key(c)
        grouped_unknown.setdefault(key, []).append(c)

    unscored = []
    for group in grouped_unknown.values():
        c = group[0]
        comp = c["component"]
        affected_units = sorted({g["component"]["unit_id"] for g in group})
        unscored.append({
            "component_name": comp["component_name"],
            "vendor": comp["vendor"],
            "version": comp["version"],
            "origin_country": comp["origin_country"],
            "affected_units": affected_units,
            "unit_count": len(affected_units),
            "reason": "No CVE match (exact or fuzzy) found in local dataset - cannot be verified as safe or unsafe.",
            "action_required": "Manual review required before procurement approval.",
        })

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "bom_source": str(bom_source),
        "ingestion_errors": parse_errors,
        "aggregate": aggregate,
        "findings_ranked": findings,
        "unscored_components": unscored,
    }
    return report


def _suggest_mitigation(component, rule_flags, match_result):
    if match_result["cves"]:
        return (f"Patch/upgrade {component['component_name']} ({component['vendor']}) past the affected "
                f"version range, or isolate on a management-only network segment until patched.")
    if rule_flags["origin_vendor_flags"]:
        return f"Source an equivalent {component['component_name']} from a non-restricted vendor/origin before procurement approval."
    if rule_flags["lifecycle_flags"]:
        return f"Qualify an alternate vendor for {component['component_name']} and plan replacement ahead of EOL."
    return "No action required based on current data."


def verdict_for_score(score, has_policy_flag=False):
    """Policy/compliance flags (restricted vendor or country) are a hard stop
    regardless of numeric score - a low CVE-based score should never present
    a sanctioned or entity-listed vendor as 'safe to buy'. This is deliberately
    NOT folded into the numeric score, since procurement needs the compliance
    reason surfaced explicitly, not buried inside an aggregate number.
    """
    if has_policy_flag:
        return "DO NOT BUY"
    if score is None:
        return "NEEDS REVIEW"
    if score >= 70:
        return "DO NOT BUY"
    if score >= 40:
        return "NEEDS REVIEW"
    return "SAFE TO BUY"


def render_html(report, out_path):
    agg = report["aggregate"]
    agg_score = agg.get("aggregate_score")
    any_policy_flag = any(f["policy_flags"] for f in report["findings_ranked"])
    agg_verdict = verdict_for_score(agg_score, has_policy_flag=any_policy_flag)
    agg_verdict_class = agg_verdict.replace(" ", "-").lower()

    rows = ""
    for f in report["findings_ranked"]:
        verdict = verdict_for_score(f["risk_score"], has_policy_flag=bool(f["policy_flags"]))
        verdict_class = verdict.replace(" ", "-").lower()
        cve_list = "".join(
            f"<li><span class='cve-id'>{c['id']}</span> "
            f"<span class='badge badge-{'real' if c['provenance']=='real' else 'sim'}'>"
            f"{'REAL' if c['provenance']=='real' else 'SIMULATED'}</span> "
            f"<span class='sev sev-{c['severity'].lower()}'>{c['severity']} · CVSS {c['cvss']}</span>"
            f"<div class='cve-desc'>{c['description']}"
            f"{' — <a href=\"' + c['source_url'] + '\" target=\"_blank\">source</a>' if c['source_url'] else ''}</div></li>"
            for c in f["matched_cves"]
        )
        policy = "".join(f"<li>{p}</li>" for p in f["policy_flags"])
        life = "".join(f"<li>{p}</li>" for p in f["lifecycle_flags"])
        units_display = ", ".join(f["affected_units"]) if f["affected_units"] != ["UNSPECIFIED"] else "—"
        rows += f"""
        <div class="finding-card verdict-border-{verdict_class}">
          <div class="finding-head">
            <div>
              <div class="comp-name">{f['component_name']}</div>
              <div class="comp-meta">{f['vendor']} · v{f['version']} · {f['origin_country']}</div>
            </div>
            <div class="finding-head-right">
              <span class="pill pill-{verdict_class}">{verdict}</span>
              <span class="risk-score">{f['risk_score']}<span class="risk-score-max">/100</span></span>
            </div>
          </div>
          <div class="finding-units">Affects: <b>{units_display}</b>{f" ({f['unit_count']} units)" if f['unit_count']>1 else ""}</div>
          <div class="finding-body">
            <div class="breakdown">
              <span>Match: <b>{f['match_status']}</b> (confidence {f['match_confidence']})</span>
              <span class="breakdown-terms">CVE {f['score_breakdown']['cve_term']} + Vendor/Origin {f['score_breakdown']['vendor_origin_term']} + Lifecycle {f['score_breakdown']['lifecycle_term']}</span>
            </div>
            {"<div class='section-label'>Known vulnerabilities</div><ul class='cve-ul'>" + cve_list + "</ul>" if cve_list else ""}
            {"<div class='section-label'>Policy flags</div><ul>" + policy + "</ul>" if policy else ""}
            {"<div class='section-label'>Lifecycle flags</div><ul>" + life + "</ul>" if life else ""}
            <div class="mitigation"><span class="section-label">Suggested mitigation</span>{f['suggested_mitigation']}</div>
          </div>
        </div>"""

    unscored_rows = ""
    for u in report["unscored_components"]:
        units_display = ", ".join(u["affected_units"]) if u["affected_units"] != ["UNSPECIFIED"] else "—"
        unscored_rows += f"""
        <div class="finding-card verdict-border-needs-review">
          <div class="finding-head">
            <div>
              <div class="comp-name">{u['component_name']}</div>
              <div class="comp-meta">{u['vendor']} · v{u['version']} · {u['origin_country']}</div>
            </div>
            <span class="pill pill-needs-review">NEEDS REVIEW</span>
          </div>
          <div class="finding-units">Affects: <b>{units_display}</b></div>
          <div class="finding-body"><p>{u['reason']} {u['action_required']}</p></div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Supply Chain Risk Report</title>
<style>
  :root {{
    --bg: #0b1220; --panel: #131d30; --panel-2: #16233a; --border: #223252;
    --text: #e6edf3; --text-dim: #93a5c2; --accent: #6ee7c9;
    --red: #ff6b6b; --red-bg: #2a1418; --amber: #f0b74d; --amber-bg: #2a2114; --green: #6ee7c9; --green-bg: #12261d;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 32px 40px 64px;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; }}
  h1 {{ font-size: 22px; font-weight: 700; margin: 0 0 4px; letter-spacing: -0.01em; }}
  h2 {{ font-size: 15px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;
       letter-spacing: 0.06em; margin: 36px 0 14px; }}
  .subtitle {{ color: var(--text-dim); font-size: 13px; margin-bottom: 24px; }}

  .summary {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 20px 24px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;
  }}
  .summary-meta {{ font-size: 13px; color: var(--text-dim); }}
  .summary-meta div {{ margin-bottom: 3px; }}
  .summary-score {{ text-align: right; }}
  .summary-score .num {{ font-size: 40px; font-weight: 800; line-height: 1; }}
  .summary-score .num-max {{ font-size: 16px; color: var(--text-dim); font-weight: 500; }}
  .summary-counts {{ display:flex; gap: 20px; font-size: 13px; color: var(--text-dim); }}
  .summary-counts b {{ color: var(--text); }}

  .pill {{
    display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px;
    font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase; white-space: nowrap;
  }}
  .pill-do-not-buy {{ background: var(--red-bg); color: var(--red); border: 1px solid #542229; }}
  .pill-needs-review {{ background: var(--amber-bg); color: var(--amber); border: 1px solid #5a4520; }}
  .pill-safe-to-buy {{ background: var(--green-bg); color: var(--green); border: 1px solid #1f4536; }}

  .finding-card {{
    background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--border);
    border-radius: 10px; padding: 16px 20px; margin-bottom: 12px;
  }}
  .verdict-border-do-not-buy {{ border-left-color: var(--red); }}
  .verdict-border-needs-review {{ border-left-color: var(--amber); }}
  .verdict-border-safe-to-buy {{ border-left-color: var(--green); }}

  .finding-head {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }}
  .finding-head-right {{ display: flex; align-items: center; gap: 12px; flex-shrink: 0; }}
  .comp-name {{ font-size: 16px; font-weight: 700; }}
  .comp-meta {{ font-size: 12.5px; color: var(--text-dim); margin-top: 2px; }}
  .risk-score {{ font-size: 20px; font-weight: 800; min-width: 56px; text-align: right; }}
  .risk-score-max {{ font-size: 12px; font-weight: 500; color: var(--text-dim); }}
  .finding-units {{ font-size: 12.5px; color: var(--text-dim); margin: 10px 0 2px; }}

  .finding-body {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); font-size: 13.5px; }}
  .breakdown {{ display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; color: var(--text-dim); font-size: 12.5px; margin-bottom: 8px; }}
  .section-label {{ display: block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;
                     color: var(--text-dim); margin: 10px 0 4px; }}
  ul {{ margin: 0 0 4px; padding-left: 20px; }}
  li {{ margin-bottom: 6px; }}
  .cve-ul {{ list-style: none; padding-left: 0; }}
  .cve-ul li {{ background: var(--panel-2); border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; }}
  .cve-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; font-weight: 700; }}
  .cve-desc {{ margin-top: 4px; color: var(--text-dim); font-size: 12.5px; }}
  .cve-desc a {{ color: var(--accent); }}
  .badge {{ font-size: 10px; font-weight: 800; padding: 1px 6px; border-radius: 4px; letter-spacing: 0.03em; }}
  .badge-real {{ background: #12261d; color: var(--green); }}
  .badge-sim {{ background: #2a2114; color: var(--amber); }}
  .sev {{ font-size: 11.5px; color: var(--text-dim); }}
  .sev-critical {{ color: var(--red); }}
  .sev-high {{ color: var(--amber); }}
  .mitigation {{ margin-top: 10px; }}
  .mitigation .section-label {{ margin-top: 0; }}
</style></head>
<body>
<div class="wrap">
  <h1>Supply Chain Risk Report</h1>
  <div class="subtitle">Source: {report['bom_source']} · Generated {report['generated_at']}</div>

  <div class="summary">
    <div class="summary-meta">
      <div class="summary-counts">
        <span>Scored: <b>{agg.get('scored_count')}</b></span>
        <span>Unscored: <b>{agg.get('unknown_count')}</b></span>
        <span>Ingestion errors: <b>{len(report['ingestion_errors'])}</b></span>
      </div>
    </div>
    <div class="summary-score">
      <span class="pill pill-{agg_verdict_class}">{agg_verdict}</span>
      <div class="num">{agg_score}<span class="num-max"> / 100</span></div>
    </div>
  </div>

  <h2>Findings — ranked by risk</h2>
  {rows if rows else '<p style="color:var(--text-dim)">No components could be scored.</p>'}

  <h2>Unscored / unknown components — require manual review</h2>
  {unscored_rows if unscored_rows else '<p style="color:var(--text-dim)">None — every component matched or was ruled on.</p>'}
</div>
</body></html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
