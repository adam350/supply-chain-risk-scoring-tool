"""
report.py
Turns the scored component list into (1) a JSON findings report for
programmatic use, and (2) a single-file HTML report so the team can
open a file in a browser and see the output during the demo.
When report["presentation"] is present, HTML follows that 5-page layout.
"""

from datetime import datetime
from html import escape as html_escape


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
    report["presentation"] = build_presentation(report)
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


def risk_level_for_score(score):
    """Presentation bands from report.json (distinct from buy/no-buy verdicts)."""
    if score is None:
        return "UNKNOWN"
    if score >= 60:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


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


def build_presentation(report):
    findings = report["findings_ranked"]
    unscored = report["unscored_components"]
    agg = report["aggregate"]
    score = agg.get("aggregate_score")
    level = risk_level_for_score(score)

    nodes = sorted({
        u for group in (findings + unscored)
        for u in group.get("affected_units", [])
        if u != "UNSPECIFIED"
    })

    ranked = []
    for i, f in enumerate(findings, start=1):
        cves = f.get("matched_cves") or []
        ranked.append({
            "priority": i,
            "component": f["component_name"],
            "vendor": f["vendor"],
            "version": f["version"],
            "risk_score": f["risk_score"],
            "risk_level": risk_level_for_score(f["risk_score"]),
            "affected_nodes": f["unit_count"],
            "matched_cves": [c["id"] for c in cves],
            "highest_cvss": max((c["cvss"] for c in cves), default=0),
            "policy_flags": len(f.get("policy_flags") or []),
            "lifecycle_flags": len(f.get("lifecycle_flags") or []),
            "recommended_action": f["suggested_mitigation"],
        })

    heatmap = []
    for f in findings:
        heatmap.append({
            "component": f["component_name"],
            "vendor": f["vendor"],
            "risk_score": f["risk_score"],
            "risk_level": risk_level_for_score(f["risk_score"]),
            "affected_nodes": {n: n in f["affected_units"] for n in nodes},
        })

    def _is_single_source(flags):
        return any("single-source" in (flag or "").lower() for flag in flags)

    lifecycle_risk = [
        {"component": f["component_name"], "vendor": f["vendor"],
         "risk_score": f["risk_score"], "flags": f["lifecycle_flags"]}
        for f in findings if f.get("lifecycle_flags")
    ]
    policy_risk = [
        {"component": f["component_name"], "vendor": f["vendor"],
         "risk_score": f["risk_score"], "flags": f["policy_flags"]}
        for f in findings if f.get("policy_flags")
    ]
    single_source = [
        {"component": f["component_name"], "vendor": f["vendor"], "flags": [
            flag for flag in f["lifecycle_flags"] if "single-source" in flag.lower()
        ]}
        for f in findings if _is_single_source(f.get("lifecycle_flags") or [])
    ]

    high_or_critical = sum(1 for f in findings if f["risk_score"] >= 50)
    headline = "High risk" if level in ("CRITICAL", "HIGH") else (
        "Elevated risk" if level == "MEDIUM" else "Low risk"
    )

    return {
        "title": "Supply Chain Security Assessment",
        "subtitle": "Infrastructure deployment risk assessment",
        "executive_summary": {
            "risk_score": score,
            "risk_level": level,
            "total_components": (agg.get("scored_count") or 0) + (agg.get("unknown_count") or 0),
            "assessed_components": agg.get("scored_count"),
            "unverified_components": agg.get("unknown_count"),
            "identified_high_or_critical_findings": high_or_critical,
            "maximum_component_risk": agg.get("max_component_score"),
            "mean_component_risk": agg.get("mean_component_score"),
            "affected_nodes": len(nodes),
            "policy_findings": len(policy_risk),
            "lifecycle_findings": len(lifecycle_risk),
            "single_source_dependencies": len(single_source),
            "headline": headline,
            "unknown_is_not_safe": bool(unscored),
            "unknown_message": (
                "No CVE match was found for these components, so they cannot be "
                "verified as safe or unsafe. Manual review is required before procurement approval."
            ),
        },
        "risk_bands": {
            "critical": ">= 60",
            "high": "50-59.9",
            "medium": "25-49.9",
            "low": "< 25",
        },
        "risk_landscape": {
            "ranked_findings": ranked,
            "node_heatmap": heatmap,
            "nodes": nodes,
        },
        "remediation_priority": [
            {
                "priority": item["priority"],
                "component": item["component"],
                "vendor": item["vendor"],
                "risk_score": item["risk_score"],
                "risk_level": item["risk_level"],
                "action": item["recommended_action"],
            }
            for item in ranked[:5]
        ],
        "supply_chain_intelligence": {
            "lifecycle_risk": lifecycle_risk,
            "policy_risk": policy_risk,
            "single_source_dependencies": single_source,
            "unknown_components": [
                {
                    "component": u["component_name"],
                    "vendor": u["vendor"],
                    "version": u["version"],
                    "affected_nodes": u["unit_count"],
                    "reason": u["reason"],
                    "action_required": u["action_required"],
                }
                for u in unscored
            ],
        },
        "report_pages": [
            {"page": 1, "title": "Executive Summary",
             "purpose": "10-second overview of overall supply-chain risk and key metrics.",
             "sections": ["risk_score", "headline_metrics", "risk_overview"]},
            {"page": 2, "title": "Risk Landscape",
             "purpose": "Ranked component risk and node-level exposure.",
             "sections": ["risk_chart", "node_heatmap"]},
            {"page": 3, "title": "Critical Findings",
             "purpose": "Explain the highest-priority risks using exposure, evidence and action.",
             "sections": ["top_3_findings"]},
            {"page": 4, "title": "Supply Chain Intelligence",
             "purpose": "Highlight lifecycle, vendor-policy, concentration and unknown risks.",
             "sections": ["lifecycle_risk", "policy_risk", "single_source", "unknown_risk"]},
            {"page": 5, "title": "Remediation & Methodology",
             "purpose": "Show prioritized actions and how the assessment works.",
             "sections": ["remediation_order", "methodology", "prototype_note"]},
        ],
        "methodology": [
            "BOM ingestion",
            "Component normalization",
            "Component matching",
            "CVE intelligence",
            "Lifecycle intelligence",
            "Vendor / policy checks",
            "Risk scoring",
            "Prioritized remediation",
        ],
        "prototype_note": (
            "Some vulnerability records in this assessment are simulated for prototype "
            "coverage and should not be interpreted as real CVE advisories."
        ),
        "generated_for": "5-page competition-ready PDF layout",
    }


def _e(value):
    if value is None:
        return ""
    return html_escape(str(value), quote=True)


def _level_class(level):
    return (level or "unknown").lower().replace(" ", "-")


def _lookup_finding(report, component, vendor, version=None):
    for f in report.get("findings_ranked") or []:
        if f["component_name"] != component or f["vendor"] != vendor:
            continue
        if version is None or f["version"] == version:
            return f
    return None


def render_html(report, out_path):
    if report.get("presentation"):
        html = _render_presentation_html(report)
    else:
        html = _render_legacy_html(report)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def _render_presentation_html(report):
    p = report["presentation"]
    es = p.get("executive_summary") or {}
    bands = p.get("risk_bands") or {}
    landscape = p.get("risk_landscape") or {}
    intel = p.get("supply_chain_intelligence") or {}
    pages = p.get("report_pages") or []
    ranked = landscape.get("ranked_findings") or []
    heatmap = landscape.get("node_heatmap") or []
    nodes = landscape.get("nodes") or []
    remediations = p.get("remediation_priority") or []
    methodology = p.get("methodology") or []

    level = es.get("risk_level") or risk_level_for_score(es.get("risk_score"))
    level_cls = _level_class(level)

    nav = "".join(
        f'<a href="#page-{pg["page"]}">{pg["page"]}. {_e(pg["title"])}</a>'
        for pg in pages
    ) or (
        '<a href="#page-1">1. Executive Summary</a>'
        '<a href="#page-2">2. Risk Landscape</a>'
        '<a href="#page-3">3. Critical Findings</a>'
        '<a href="#page-4">4. Supply Chain Intelligence</a>'
        '<a href="#page-5">5. Remediation &amp; Methodology</a>'
    )

    metrics = [
        ("Total components", es.get("total_components")),
        ("Assessed", es.get("assessed_components")),
        ("Unverified", es.get("unverified_components")),
        ("High / critical", es.get("identified_high_or_critical_findings")),
        ("Max component risk", es.get("maximum_component_risk")),
        ("Mean component risk", es.get("mean_component_risk")),
        ("Affected nodes", es.get("affected_nodes")),
        ("Policy findings", es.get("policy_findings")),
        ("Lifecycle findings", es.get("lifecycle_findings")),
        ("Single-source deps", es.get("single_source_dependencies")),
    ]
    metric_html = "".join(
        f'<div class="metric"><div class="metric-label">{_e(label)}</div>'
        f'<div class="metric-value">{_e(value)}</div></div>'
        for label, value in metrics if value is not None
    )

    band_html = "".join(
        f'<span class="band band-{name}">{name.upper()} {_e(rng)}</span>'
        for name, rng in bands.items()
    )

    chart_rows = ""
    for item in ranked:
        width = min(100, max(2, float(item.get("risk_score") or 0)))
        chart_rows += (
            f'<div class="bar-row">'
            f'<div class="bar-label">{_e(item.get("priority"))}. {_e(item.get("component"))}'
            f'<span>{_e(item.get("vendor"))} · v{_e(item.get("version"))}</span></div>'
            f'<div class="bar-track"><div class="bar-fill lvl-{_level_class(item.get("risk_level"))}" '
            f'style="width:{width}%"></div></div>'
            f'<div class="bar-score">{_e(item.get("risk_score"))}</div>'
            f'<span class="pill pill-{_level_class(item.get("risk_level"))}">{_e(item.get("risk_level"))}</span>'
            f'</div>'
        )

    head_cells = "".join(f"<th>{_e(n)}</th>" for n in nodes)
    heat_rows = ""
    for row in heatmap:
        cells = ""
        affected = row.get("affected_nodes") or {}
        for n in nodes:
            on = "on" if affected.get(n) else "off"
            cells += f'<td><span class="heat-cell {on} lvl-{_level_class(row.get("risk_level"))}"></span></td>'
        heat_rows += (
            f'<tr><td class="heat-name">{_e(row.get("component"))}'
            f'<div class="comp-meta">{_e(row.get("vendor"))} · {_e(row.get("risk_score"))}</div></td>'
            f'{cells}</tr>'
        )

    top3 = ranked[:3]
    finding_cards = ""
    for item in top3:
        detail = _lookup_finding(report, item.get("component"), item.get("vendor"), item.get("version"))
        cves = (detail or {}).get("matched_cves") or []
        cve_ids = item.get("matched_cves") or [c["id"] for c in cves]
        cve_html = ""
        if cves:
            cve_html = "<ul class='cve-ul'>" + "".join(
                f"<li><span class='cve-id'>{_e(c['id'])}</span> "
                f"<span class='badge badge-{'real' if c.get('provenance')=='real' else 'sim'}'>"
                f"{'REAL' if c.get('provenance')=='real' else 'SIMULATED'}</span> "
                f"<span class='sev sev-{(c.get('severity') or '').lower()}'>"
                f"{_e(c.get('severity'))} · CVSS {_e(c.get('cvss'))}</span>"
                f"<div class='cve-desc'>{_e(c.get('description'))}"
                f"{(' — <a href=\"' + _e(c.get('source_url')) + '\" target=\"_blank\">source</a>') if c.get('source_url') else ''}"
                f"</div></li>"
                for c in cves
            ) + "</ul>"
        elif cve_ids:
            cve_html = "<div class='comp-meta'>" + ", ".join(_e(i) for i in cve_ids) + "</div>"

        policy = "".join(f"<li>{_e(flag)}</li>" for flag in (detail or {}).get("policy_flags") or [])
        life = "".join(f"<li>{_e(flag)}</li>" for flag in (detail or {}).get("lifecycle_flags") or [])
        finding_cards += f"""
        <div class="finding-card verdict-border-{_level_class(item.get('risk_level'))}">
          <div class="finding-head">
            <div>
              <div class="comp-name">#{_e(item.get('priority'))} {_e(item.get('component'))}</div>
              <div class="comp-meta">{_e(item.get('vendor'))} · v{_e(item.get('version'))} · {item.get('affected_nodes')} nodes</div>
            </div>
            <div class="finding-head-right">
              <button type="button" class="what-if-btn" onclick="triggerSimulation('{_e(item.get('component'))}', '{_e(item.get('vendor'))}', '{_e(item.get('version'))}')">⚡ What-If</button>
              <span class="pill pill-{_level_class(item.get('risk_level'))}">{_e(item.get('risk_level'))}</span>
              <span class="risk-score">{_e(item.get('risk_score'))}<span class="risk-score-max">/100</span></span>
            </div>
          </div>
          <div class="finding-body">
            {"<div class='section-label'>Known vulnerabilities</div>" + cve_html if cve_html else ""}
            {"<div class='section-label'>Policy flags</div><ul>" + policy + "</ul>" if policy else ""}
            {"<div class='section-label'>Lifecycle flags</div><ul>" + life + "</ul>" if life else ""}
            <div class="mitigation"><span class="section-label">Recommended action</span>{_e(item.get('recommended_action'))}</div>
          </div>
        </div>"""

    remaining = ranked[3:]
    remaining_html = ""
    for item in remaining:
        remaining_html += (
            f'<div class="mini-finding">'
            f'<span class="pill pill-{_level_class(item.get("risk_level"))}">{_e(item.get("risk_level"))}</span>'
            f'<b>{_e(item.get("component"))}</b> · {_e(item.get("vendor"))} · {_e(item.get("risk_score"))}'
            f'<div class="comp-meta">{_e(item.get("recommended_action"))}</div></div>'
        )

    def intel_cards(items, kind):
        if not items:
            return '<p class="empty">None identified.</p>'
        out = ""
        for item in items:
            flags = "".join(f"<li>{_e(flag)}</li>" for flag in item.get("flags") or [])
            extra = f" · {_e(item.get('risk_score'))}" if item.get("risk_score") is not None else ""
            out += (
                f'<div class="intel-card {kind}">'
                f'<div class="comp-name">{_e(item.get("component"))}</div>'
                f'<div class="comp-meta">{_e(item.get("vendor"))}{extra}</div>'
                f'{"<ul>" + flags + "</ul>" if flags else ""}</div>'
            )
        return out

    unknown_html = ""
    for u in intel.get("unknown_components") or []:
        unknown_html += (
            f'<div class="intel-card unknown">'
            f'<div class="comp-name">{_e(u.get("component"))}</div>'
            f'<div class="comp-meta">{_e(u.get("vendor"))} · v{_e(u.get("version"))} · {u.get("affected_nodes")} nodes</div>'
            f'<p>{_e(u.get("reason"))} {_e(u.get("action_required"))}</p></div>'
        )
    if not unknown_html:
        unknown_html = '<p class="empty">None — every component matched or was ruled on.</p>'

    rem_html = ""
    for item in remediations:
        rem_html += (
            f'<div class="rem-row">'
            f'<div class="rem-num">{_e(item.get("priority"))}</div>'
            f'<div><div class="comp-name">{_e(item.get("component"))}'
            f' <span class="pill pill-{_level_class(item.get("risk_level"))}">{_e(item.get("risk_level"))}</span></div>'
            f'<div class="comp-meta">{_e(item.get("vendor"))} · {_e(item.get("risk_score"))}</div>'
            f'<p>{_e(item.get("action"))}</p></div></div>'
        )

    method_html = "".join(
        f'<li><span class="step">{i}</span>{_e(step)}</li>'
        for i, step in enumerate(methodology, start=1)
    )

    unknown_banner = ""
    if es.get("unknown_is_not_safe"):
        unknown_banner = (
            f'<div class="callout">{_e(es.get("unknown_message") or "Unverified components are not assumed safe.")}</div>'
        )

    page_meta = {pg["page"]: pg for pg in pages}

    def page_head(num, fallback_title, fallback_purpose):
        meta = page_meta.get(num) or {}
        title = meta.get("title") or fallback_title
        purpose = meta.get("purpose") or fallback_purpose
        return (
            f'<h2>{_e(title)}</h2>'
            f'<p class="purpose">{_e(purpose)}</p>'
        )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{_e(p.get('title') or 'Supply Chain Risk Report')}</title>
<style>
  :root {{
    --bg: #0b1220; --panel: #131d30; --panel-2: #16233a; --border: #223252;
    --text: #e6edf3; --text-dim: #93a5c2; --accent: #6ee7c9;
    --red: #ff6b6b; --red-bg: #2a1418; --amber: #f0b74d; --amber-bg: #2a2114;
    --green: #6ee7c9; --green-bg: #12261d; --blue: #7dd3fc;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 28px 32px 72px; line-height: 1.5;
  }}
  .wrap {{ max-width: 1040px; margin: 0 auto; }}
  h1 {{ font-size: 26px; font-weight: 750; margin: 0 0 4px; letter-spacing: -0.02em; }}
  h2 {{ font-size: 20px; font-weight: 750; margin: 0 0 6px; letter-spacing: -0.01em; }}
  h3 {{ font-size: 13px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;
        letter-spacing: 0.06em; margin: 22px 0 10px; }}
  .subtitle {{ color: var(--text-dim); font-size: 14px; margin-bottom: 18px; }}
  .nav {{
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 28px;
  }}
  .nav a {{
    color: var(--accent); text-decoration: none; font-size: 12px; font-weight: 600;
    border: 1px solid var(--border); background: var(--panel); padding: 6px 10px; border-radius: 999px;
  }}
  .page {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
    padding: 28px 32px; margin-bottom: 22px; overflow: auto; isolation: isolate;
  }}
  .purpose {{ color: var(--text-dim); font-size: 13.5px; margin: 0 0 18px; }}
  .hero {{ display: flex; justify-content: space-between; gap: 24px; flex-wrap: wrap; align-items: flex-end; }}
  .hero-score .num {{ font-size: 56px; font-weight: 800; line-height: 1; }}
  .hero-score .num-max {{ font-size: 16px; color: var(--text-dim); font-weight: 500; }}
  .headline {{ font-size: 22px; font-weight: 700; margin-top: 8px; }}
  .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-top: 22px; }}
  .metric {{ background: var(--panel-2); border-radius: 10px; padding: 12px 14px; }}
  .metric-label {{ font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.04em; }}
  .metric-value {{ font-size: 22px; font-weight: 750; margin-top: 4px; }}
  .bands {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }}
  .band {{ font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border); }}
  .band-critical {{ color: var(--red); }} .band-high {{ color: var(--amber); }}
  .band-medium {{ color: var(--blue); }} .band-low {{ color: var(--green); }}
  .callout {{
    margin-top: 18px; padding: 12px 14px; border-radius: 10px;
    background: var(--amber-bg); border: 1px solid #5a4520; color: var(--amber); font-size: 13.5px;
  }}
  .pill {{
    display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px;
    font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase; white-space: nowrap;
  }}
  .pill-critical, .pill-do-not-buy {{ background: var(--red-bg); color: var(--red); border: 1px solid #542229; }}
  .pill-high, .pill-needs-review {{ background: var(--amber-bg); color: var(--amber); border: 1px solid #5a4520; }}
  .pill-medium {{ background: #102033; color: var(--blue); border: 1px solid #1e3a5f; }}
  .pill-low, .pill-safe-to-buy {{ background: var(--green-bg); color: var(--green); border: 1px solid #1f4536; }}
  .bar-row {{ display: grid; grid-template-columns: minmax(140px, 220px) minmax(0, 1fr) 48px auto; gap: 10px; align-items: center; margin-bottom: 10px; }}
  .bar-label {{ font-size: 13px; font-weight: 650; min-width: 0; }}
  .bar-label span {{ display: block; color: var(--text-dim); font-size: 11.5px; font-weight: 500; }}
  .bar-track {{ height: 10px; background: var(--panel-2); border-radius: 999px; overflow: hidden; min-width: 0; }}
  .bar-fill {{ height: 100%; border-radius: 999px; }}
  .bar-fill.lvl-critical {{ background: var(--red); }}
  .bar-fill.lvl-high {{ background: var(--amber); }}
  .bar-fill.lvl-medium {{ background: var(--blue); }}
  .bar-fill.lvl-low {{ background: var(--green); }}
  .bar-score {{ font-weight: 750; text-align: right; }}
  .heatmap-wrap {{ display: block; width: 100%; overflow-x: auto; margin: 4px 0 8px; }}
  table.heatmap {{ display: table; width: 100%; height: auto; border-collapse: collapse; font-size: 13px; }}
  table.heatmap th, table.heatmap td {{ padding: 8px 6px; text-align: center; vertical-align: middle; }}
  table.heatmap th {{ color: var(--text-dim); font-size: 11px; letter-spacing: 0.04em; }}
  .heat-name {{ text-align: left !important; font-weight: 650; white-space: nowrap; }}
  .heat-cell {{ display: inline-block; width: 18px; height: 18px; border-radius: 4px; background: #1a2438; border: 1px solid var(--border); }}
  .heat-cell.on.lvl-critical {{ background: var(--red); border-color: var(--red); }}
  .heat-cell.on.lvl-high {{ background: var(--amber); border-color: var(--amber); }}
  .heat-cell.on.lvl-medium {{ background: var(--blue); border-color: var(--blue); }}
  .heat-cell.on.lvl-low {{ background: var(--green); border-color: var(--green); }}
  .finding-card {{
    background: var(--panel-2); border: 1px solid var(--border); border-left: 4px solid var(--border);
    border-radius: 10px; padding: 16px 20px; margin-bottom: 12px;
  }}
  .verdict-border-critical, .verdict-border-do-not-buy {{ border-left-color: var(--red); }}
  .verdict-border-high, .verdict-border-needs-review {{ border-left-color: var(--amber); }}
  .verdict-border-medium {{ border-left-color: var(--blue); }}
  .verdict-border-low, .verdict-border-safe-to-buy {{ border-left-color: var(--green); }}
  .finding-head {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }}
  .finding-head-right {{ display: flex; align-items: center; gap: 12px; flex-shrink: 0; }}
  .comp-name {{ font-size: 16px; font-weight: 700; }}
  .comp-meta {{ font-size: 12.5px; color: var(--text-dim); margin-top: 2px; }}
  .risk-score {{ font-size: 20px; font-weight: 800; min-width: 56px; text-align: right; }}
  .risk-score-max {{ font-size: 12px; font-weight: 500; color: var(--text-dim); }}
  .finding-body {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); font-size: 13.5px; }}
  .section-label {{ display: block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;
                     color: var(--text-dim); margin: 10px 0 4px; }}
  ul {{ margin: 0 0 4px; padding-left: 20px; }}
  li {{ margin-bottom: 6px; }}
  .cve-ul {{ list-style: none; padding-left: 0; }}
  .cve-ul li {{ background: var(--bg); border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; }}
  .cve-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; font-weight: 700; }}
  .cve-desc {{ margin-top: 4px; color: var(--text-dim); font-size: 12.5px; }}
  .cve-desc a {{ color: var(--accent); }}
  .badge {{ font-size: 10px; font-weight: 800; padding: 1px 6px; border-radius: 4px; letter-spacing: 0.03em; }}
  .badge-real {{ background: #12261d; color: var(--green); }}
  .badge-sim {{ background: #2a2114; color: var(--amber); }}
  .sev-critical {{ color: var(--red); }}
  .sev-high {{ color: var(--amber); }}
  .mitigation {{ margin-top: 10px; }}
  .mitigation .section-label {{ margin-top: 0; }}
  .mini-finding {{ background: var(--panel-2); border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; font-size: 13.5px; }}
  .intel-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; }}
  .intel-card {{ background: var(--panel-2); border-radius: 10px; padding: 12px 14px; }}
  .intel-card.unknown {{ border-left: 3px solid var(--amber); }}
  .intel-card.policy {{ border-left: 3px solid var(--red); }}
  .empty {{ color: var(--text-dim); }}
  .rem-row {{ display: flex; gap: 14px; margin-bottom: 14px; }}
  .rem-num {{
    width: 32px; height: 32px; border-radius: 50%; background: var(--panel-2); color: var(--accent);
    display: flex; align-items: center; justify-content: center; font-weight: 800; flex-shrink: 0;
  }}
  .method {{ list-style: none; padding: 0; }}
  .method li {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .step {{
    width: 24px; height: 24px; border-radius: 50%; background: var(--panel-2); color: var(--text-dim);
    display: inline-flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700;
  }}
  .note {{ margin-top: 18px; color: var(--text-dim); font-size: 13px; font-style: italic; }}
  .what-if-btn {{
    background: linear-gradient(135deg, #0284c7, #2563eb);
    color: #fff;
    border: 1px solid #38bdf8;
    font-size: 11px;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
    letter-spacing: 0.02em;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    box-shadow: 0 2px 6px rgba(2, 132, 199, 0.25);
  }}
  .what-if-btn:hover {{
    background: linear-gradient(135deg, #38bdf8, #3b82f6);
    transform: translateY(-1px);
    box-shadow: 0 4px 10px rgba(56, 189, 248, 0.35);
  }}
  @media (max-width: 720px) {{
    .bar-row {{ grid-template-columns: 1fr; }}
    body {{ padding: 16px; }}
    .page {{ padding: 18px; }}
  }}
</style></head>
<body>
<div class="wrap">
  <h1>{_e(p.get('title') or 'Supply Chain Risk Report')}</h1>
  <div class="subtitle">{_e(p.get('subtitle') or '')}</div>
  <nav class="nav">{nav}</nav>

  <section class="page" id="page-1">
    {page_head(1, 'Executive Summary', '10-second overview of overall supply-chain risk and key metrics.')}
    <div class="hero">
      <div>
        <div class="headline">{_e(es.get('headline') or level)}</div>
        <p class="purpose" style="margin:8px 0 0">Overall assessment for this bill of materials.</p>
      </div>
      <div class="hero-score">
        <span class="pill pill-{level_cls}">{_e(level)}</span>
        <div class="num">{_e(es.get('risk_score'))}<span class="num-max"> / 100</span></div>
      </div>
    </div>
    <div class="metrics">{metric_html}</div>
    <div class="bands">{band_html}</div>
    {unknown_banner}
  </section>

  <section class="page" id="page-2">
    {page_head(2, 'Risk Landscape', 'Ranked component risk and node-level exposure.')}
    <h3>Ranked findings</h3>
    {chart_rows or '<p class="empty">No ranked findings.</p>'}
    <h3>Node heatmap</h3>
    {"<div class='heatmap-wrap'><table class='heatmap'><thead><tr><th></th>" + head_cells + "</tr></thead><tbody>" + heat_rows + "</tbody></table></div>" if heat_rows else '<p class="empty">No node exposure data.</p>'}
  </section>

  <section class="page" id="page-3">
    {page_head(3, 'Critical Findings', 'Explain the highest-priority risks using exposure, evidence and action.')}
    {finding_cards or '<p class="empty">No critical findings.</p>'}
    {"<h3>Other ranked findings</h3>" + remaining_html if remaining_html else ""}
  </section>

  <section class="page" id="page-4">
    {page_head(4, 'Supply Chain Intelligence', 'Highlight lifecycle, vendor-policy, concentration and unknown risks.')}
    <h3>Lifecycle risk</h3>
    <div class="intel-grid">{intel_cards(intel.get('lifecycle_risk') or [], 'lifecycle')}</div>
    <h3>Policy risk</h3>
    <div class="intel-grid">{intel_cards(intel.get('policy_risk') or [], 'policy')}</div>
    <h3>Single-source dependencies</h3>
    <div class="intel-grid">{intel_cards(intel.get('single_source_dependencies') or [], 'single')}</div>
    <h3>Unknown / unverified components</h3>
    <div class="intel-grid">{unknown_html}</div>
  </section>

  <section class="page" id="page-5">
    {page_head(5, 'Remediation & Methodology', 'Show prioritized actions and how the assessment works.')}
    <h3>Remediation order</h3>
    {rem_html or '<p class="empty">No remediation items.</p>'}
    <h3>Methodology</h3>
    <ol class="method">{method_html}</ol>
    <p class="note">{_e(p.get('prototype_note'))}</p>
  </section>
</div>
<script>
function triggerSimulation(componentName, vendor, version) {{
  if (window.parent && window.parent !== window) {{
    window.parent.postMessage({{
      type: 'OPEN_WHAT_IF_SIMULATOR',
      component: componentName,
      vendor: vendor,
      version: version
    }}, '*');
  }} else {{
    alert('What-If Supply Chain Simulator: To simulate replacing ' + componentName + ' (' + vendor + ' v' + version + '), open this report inside the Server BOM Ingestion Portal at http://localhost:8080');
  }}
}}
</script>
</body></html>"""


def _render_legacy_html(report):
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
            f"<li><span class='cve-id'>{_e(c['id'])}</span> "
            f"<span class='badge badge-{'real' if c['provenance']=='real' else 'sim'}'>"
            f"{'REAL' if c['provenance']=='real' else 'SIMULATED'}</span> "
            f"<span class='sev sev-{_e(c['severity']).lower()}'>{_e(c['severity'])} · CVSS {_e(c['cvss'])}</span>"
            f"<div class='cve-desc'>{_e(c['description'])}"
            f"{' — <a href=\"' + _e(c['source_url']) + '\" target=\"_blank\">source</a>' if c['source_url'] else ''}</div></li>"
            for c in f["matched_cves"]
        )
        policy = "".join(f"<li>{_e(p)}</li>" for p in f["policy_flags"])
        life = "".join(f"<li>{_e(p)}</li>" for p in f["lifecycle_flags"])
        units_display = ", ".join(f["affected_units"]) if f["affected_units"] != ["UNSPECIFIED"] else "—"
        rows += f"""
        <div class="finding-card verdict-border-{verdict_class}">
          <div class="finding-head">
            <div>
              <div class="comp-name">{_e(f['component_name'])}</div>
              <div class="comp-meta">{_e(f['vendor'])} · v{_e(f['version'])} · {_e(f['origin_country'])}</div>
            </div>
            <div class="finding-head-right">
              <span class="pill pill-{verdict_class}">{verdict}</span>
              <span class="risk-score">{_e(f['risk_score'])}<span class="risk-score-max">/100</span></span>
            </div>
          </div>
          <div class="finding-units">Affects: <b>{_e(units_display)}</b>{f" ({f['unit_count']} units)" if f['unit_count']>1 else ""}</div>
          <div class="finding-body">
            <div class="breakdown">
              <span>Match: <b>{_e(f['match_status'])}</b> (confidence {_e(f['match_confidence'])})</span>
              <span class="breakdown-terms">CVE {_e(f['score_breakdown']['cve_term'])} + Vendor/Origin {_e(f['score_breakdown']['vendor_origin_term'])} + Lifecycle {_e(f['score_breakdown']['lifecycle_term'])}</span>
            </div>
            {"<div class='section-label'>Known vulnerabilities</div><ul class='cve-ul'>" + cve_list + "</ul>" if cve_list else ""}
            {"<div class='section-label'>Policy flags</div><ul>" + policy + "</ul>" if policy else ""}
            {"<div class='section-label'>Lifecycle flags</div><ul>" + life + "</ul>" if life else ""}
            <div class="mitigation"><span class="section-label">Suggested mitigation</span>{_e(f['suggested_mitigation'])}</div>
          </div>
        </div>"""

    unscored_rows = ""
    for u in report["unscored_components"]:
        units_display = ", ".join(u["affected_units"]) if u["affected_units"] != ["UNSPECIFIED"] else "—"
        unscored_rows += f"""
        <div class="finding-card verdict-border-needs-review">
          <div class="finding-head">
            <div>
              <div class="comp-name">{_e(u['component_name'])}</div>
              <div class="comp-meta">{_e(u['vendor'])} · v{_e(u['version'])} · {_e(u['origin_country'])}</div>
            </div>
            <span class="pill pill-needs-review">NEEDS REVIEW</span>
          </div>
          <div class="finding-units">Affects: <b>{_e(units_display)}</b></div>
          <div class="finding-body"><p>{_e(u['reason'])} {_e(u['action_required'])}</p></div>
        </div>"""

    return f"""<!DOCTYPE html>
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
  h1 {{ font-size: 22px; font-weight: 700; margin: 0 0 24px; letter-spacing: -0.01em; }}
  h2 {{ font-size: 15px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;
       letter-spacing: 0.06em; margin: 36px 0 14px; }}
  .summary {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 20px 24px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;
  }}
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
  .cve-ul {{ list-style: none; padding-left: 0; }}
  .cve-ul li {{ background: var(--panel-2); border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; }}
  .cve-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; font-weight: 700; }}
  .cve-desc {{ margin-top: 4px; color: var(--text-dim); font-size: 12.5px; }}
  .cve-desc a {{ color: var(--accent); }}
  .badge {{ font-size: 10px; font-weight: 800; padding: 1px 6px; border-radius: 4px; }}
  .badge-real {{ background: #12261d; color: var(--green); }}
  .badge-sim {{ background: #2a2114; color: var(--amber); }}
  .sev-critical {{ color: var(--red); }}
  .sev-high {{ color: var(--amber); }}
  .mitigation {{ margin-top: 10px; }}
</style></head>
<body>
<div class="wrap">
  <h1>Supply Chain Risk Report</h1>
  <div class="summary">
    <div class="summary-meta">
      <div class="summary-counts">
        <span>Scored: <b>{_e(agg.get('scored_count'))}</b></span>
        <span>Unscored: <b>{_e(agg.get('unknown_count'))}</b></span>
        <span>Ingestion errors: <b>{len(report['ingestion_errors'])}</b></span>
      </div>
    </div>
    <div class="summary-score">
      <span class="pill pill-{agg_verdict_class}">{agg_verdict}</span>
      <div class="num">{_e(agg_score)}<span class="num-max"> / 100</span></div>
    </div>
  </div>
  <h2>Findings — ranked by risk</h2>
  {rows if rows else '<p style="color:var(--text-dim)">No components could be scored.</p>'}
  <h2>Unscored / unknown components — require manual review</h2>
  {unscored_rows if unscored_rows else '<p style="color:var(--text-dim)">None — every component matched or was ruled on.</p>'}
</div>
</body></html>"""
