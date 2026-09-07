#!/usr/bin/env python3
"""
main.py - Supply Chain Risk Scoring Tool (prototype, software-only version)

Usage:
    python main.py --bom data/sample_bom.csv --out output/demo_run

Running with no arguments (e.g. clicking the Run button in VS Code) scores
the small clean demo BOM by default - see --bom/--out defaults below.

This is intentionally a CLI + static HTML output, not a web app: the brief
asks for functionality and an explainable report, and a frontend is being
handled separately by another team member. This gives that teammate a
working JSON report to build a real UI against, plus an HTML view so anyone
can see the pipeline's output immediately without running a server.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from bom_parser import parse_bom
from cve_matcher import load_cve_database, match_component
from rules_engine import load_rules, apply_rules
from scoring import score_component, score_bom
from report import build_findings_report, render_html


def run(bom_path, out_dir, cve_db_path, rules_path):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    components, parse_errors = parse_bom(bom_path)
    cve_entries = load_cve_database(cve_db_path)
    rules = load_rules(rules_path)

    scored_components = []
    for comp in components:
        match_result = match_component(comp, cve_entries)
        rule_flags = apply_rules(comp, rules)

        if match_result["status"] == "unmatched" and not rule_flags["origin_vendor_flags"] and not rule_flags["lifecycle_flags"]:
            # Truly nothing to go on for this component: no CVE match, no
            # policy hit, no lifecycle data. Reported as unscored rather
            # than assumed safe, per the brief's explicit requirement.
            score_data = None
        else:
            score_data = score_component(comp, match_result, rule_flags)

        scored_components.append({
            "component": comp,
            "match_result": match_result,
            "rule_flags": rule_flags,
            "score_data": score_data,
        })

    aggregate = score_bom(scored_components)
    report = build_findings_report(bom_path, scored_components, aggregate, parse_errors)

    json_path = out_dir / "report.json"
    html_path = out_dir / "report.html"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    render_html(report, html_path)

    print(f"Parsed {len(components)} components ({len(parse_errors)} ingestion errors).")
    print(f"Aggregate BOM risk score: {aggregate.get('aggregate_score')}  "
          f"(scored: {aggregate.get('scored_count')}, unscored: {aggregate.get('unknown_count')})")
    print(f"JSON report -> {json_path}")
    print(f"HTML report -> {html_path}")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Supply Chain Risk Scoring Tool")
    parser.add_argument("--bom", default="output/cleaned_bom.csv",
                         help="Path to BOM file (.csv or CycloneDX .json). Defaults to the cleaned output of clean_bom.py — run that first.")
    parser.add_argument("--out", default="output", help="Output directory for reports")
    parser.add_argument("--cve-db", default="data/cve_database.json")
    parser.add_argument("--rules", default="data/rules.json")
    args = parser.parse_args()

    run(args.bom, args.out, args.cve_db, args.rules)
