"""
simulator.py
Core simulation engine for the What-If Supply Chain Simulator.

Performs non-mutating hypothetical component substitutions, recalculates risk using
the existing scoring pipeline (cve_matcher, rules_engine, scoring), and generates
comparative metrics and explainable risk deltas.
"""

import copy
from cve_matcher import match_component
from rules_engine import apply_rules
from scoring import score_component, score_bom


def evaluate_components(components, cve_entries, rules):
    """
    Evaluates and scores a list of normalized component records using the existing
    scoring pipeline. Exactly mirrors main.py logic without writing any report files.
    """
    scored_components = []
    for comp in components:
        match_result = match_component(comp, cve_entries)
        rule_flags = apply_rules(comp, rules)

        if (
            match_result["status"] == "unmatched"
            and not rule_flags["origin_vendor_flags"]
            and not rule_flags["lifecycle_flags"]
        ):
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
    return scored_components, aggregate


def _find_component_summary(scored_components, comp_name, vendor, version=None):
    """Finds first matching component and extracts summary statistics."""
    name_l = (comp_name or "").strip().lower()
    vendor_l = (vendor or "").strip().lower()
    version_l = (version or "").strip().lower() if version else None

    for item in scored_components:
        c = item["component"]
        if c["component_name"].strip().lower() == name_l and c["vendor"].strip().lower() == vendor_l:
            if version_l is None or c["version"].strip().lower() == version_l:
                sd = item["score_data"]
                mr = item["match_result"]
                rf = item["rule_flags"]
                cves = mr.get("cves") or []
                highest_cvss = max((cve.get("cvss_score", 0.0) for cve in cves), default=0.0)

                return {
                    "component_name": c["component_name"],
                    "vendor": c["vendor"],
                    "version": c["version"],
                    "origin_country": c.get("origin_country", "UNKNOWN"),
                    "part_number": c.get("part_number", ""),
                    "unit_id": c.get("unit_id", "UNSPECIFIED"),
                    "risk_score": sd["score"] if sd else None,
                    "score_breakdown": sd["breakdown"] if sd else None,
                    "match_status": mr.get("status", "unmatched"),
                    "match_confidence": mr.get("confidence", 0.0),
                    "cve_count": len(cves),
                    "matched_cves": [cve.get("cve_id") for cve in cves],
                    "highest_cvss": highest_cvss,
                    "policy_flags": rf.get("origin_vendor_flags", []),
                    "lifecycle_flags": rf.get("lifecycle_flags", []),
                    "is_scored": sd is not None,
                }
    return None


def generate_diff_explanation(target_summary, sub_summary, orig_agg, sim_agg, replaced_count):
    """
    Generates a concise, plain-English explanation of why the BOM score changed.
    """
    orig_score = orig_agg.get("aggregate_score")
    sim_score = sim_agg.get("aggregate_score")

    orig_target_score = target_summary.get("risk_score")
    sub_score = sub_summary.get("risk_score")

    sentences = []

    # 1. Component-level change
    name = target_summary.get("component_name")
    from_desc = f"{target_summary.get('vendor')} v{target_summary.get('version')}"
    to_desc = f"{sub_summary.get('vendor')} v{sub_summary.get('version')}"

    comp_score_str = f"from {orig_target_score} to {sub_score}" if orig_target_score is not None and sub_score is not None else ""
    sentences.append(f"Replacing {name} ({from_desc}) with {to_desc} adjusted component risk {comp_score_str}.".strip())

    # 2. Key factors (CVE, Policy, Lifecycle)
    cve_diff = sub_summary.get("cve_count", 0) - target_summary.get("cve_count", 0)
    if cve_diff < 0:
        sentences.append(f"Remediated {abs(cve_diff)} known CVE(s) (highest CVSS {target_summary.get('highest_cvss')} eliminated).")
    elif cve_diff > 0:
        sentences.append(f"Introduced {cve_diff} additional CVE vulnerability finding(s).")

    pol_diff = len(sub_summary.get("policy_flags", [])) - len(target_summary.get("policy_flags", []))
    if pol_diff < 0:
        sentences.append("Resolved restricted vendor / country-of-origin compliance violation.")
    elif pol_diff > 0:
        sentences.append("Triggered new restricted vendor or country-of-origin policy flag.")

    life_diff = len(sub_summary.get("lifecycle_flags", [])) - len(target_summary.get("lifecycle_flags", []))
    if life_diff < 0:
        sentences.append("Eliminated EOL / single-source dependency flags.")
    elif life_diff > 0:
        sentences.append("Added lifecycle warning (EOL / single-source dependency).")

    if not sub_summary.get("is_scored"):
        sentences.append("Notice: Proposed alternative has no known CVE/rule data and is marked unscored (requires manual verification, not assumed safe).")

    # 3. Overall impact
    if orig_score is not None and sim_score is not None:
        delta = round(sim_score - orig_score, 1)
        if delta < 0:
            pct = round((abs(delta) / orig_score) * 100, 1) if orig_score > 0 else 0.0
            sentences.append(f"Overall BOM risk decreased by {abs(delta)} points ({pct}% reduction, from {orig_score} to {sim_score}).")
        elif delta > 0:
            pct = round((delta / orig_score) * 100, 1) if orig_score > 0 else 0.0
            sentences.append(f"Overall BOM risk increased by {delta} points (+{pct}%, from {orig_score} to {sim_score}).")
        else:
            sentences.append(f"Overall BOM risk remained unchanged at {orig_score}.")

    if replaced_count > 1:
        sentences.append(f"(Applied across {replaced_count} affected units in BOM).")

    return " ".join(sentences)


def run_simulation(
    original_components,
    target_component,
    substitute_component,
    cve_entries,
    rules,
    scope="all_instances",
    specific_unit_id=None
):
    """
    Executes a hypothetical What-If simulation on a non-mutating copy of the BOM.

    Parameters:
        original_components: list of dicts from parse_bom (NEVER mutated).
        target_component: dict with {"component_name", "vendor", "version"}.
        substitute_component: dict with {"component_name", "vendor", "version", "origin_country", "part_number"}.
        cve_entries: loaded CVE database entries list.
        rules: loaded rules dict.
        scope: "all_instances" or "single_unit".
        specific_unit_id: if scope is "single_unit", specifies the target node unit_id.

    Returns:
        dict with comparison metrics, before/after component eval, and explanation.
    """
    # 1. Non-mutating deep copy of components
    simulated_components = copy.deepcopy(original_components)

    t_name = target_component.get("component_name", "").strip().lower()
    t_vendor = target_component.get("vendor", "").strip().lower()
    t_version = target_component.get("version", "").strip().lower()

    replaced_count = 0
    for comp in simulated_components:
        c_name = comp.get("component_name", "").strip().lower()
        c_vendor = comp.get("vendor", "").strip().lower()
        c_version = comp.get("version", "").strip().lower()
        c_unit = comp.get("unit_id", "UNSPECIFIED")

        if c_name == t_name and c_vendor == t_vendor and (not t_version or c_version == t_version):
            if scope == "single_unit" and specific_unit_id and c_unit != specific_unit_id:
                continue

            comp["component_name"] = substitute_component["component_name"].strip()
            comp["vendor"] = substitute_component["vendor"].strip()
            comp["version"] = substitute_component["version"].strip()
            comp["origin_country"] = substitute_component.get("origin_country", "UNKNOWN").strip()
            comp["part_number"] = substitute_component.get("part_number", "").strip()
            comp["_is_simulated"] = True
            replaced_count += 1

    if replaced_count == 0:
        raise ValueError(
            f"Target component '{target_component.get('component_name')}' "
            f"({target_component.get('vendor')} {target_component.get('version')}) "
            f"not found in BOM."
        )

    # 2. Evaluate both BOM states using the EXACT same scoring engine
    orig_scored, orig_agg = evaluate_components(original_components, cve_entries, rules)
    sim_scored, sim_agg = evaluate_components(simulated_components, cve_entries, rules)

    # 3. Component level summaries
    target_summary = _find_component_summary(orig_scored, t_name, t_vendor, t_version) or {
        "component_name": target_component.get("component_name"),
        "vendor": target_component.get("vendor"),
        "version": target_component.get("version"),
        "risk_score": None,
    }

    sub_summary = _find_component_summary(
        sim_scored,
        substitute_component["component_name"],
        substitute_component["vendor"],
        substitute_component["version"]
    ) or {
        "component_name": substitute_component.get("component_name"),
        "vendor": substitute_component.get("vendor"),
        "version": substitute_component.get("version"),
        "risk_score": None,
    }

    # 4. Deltas
    orig_score = orig_agg.get("aggregate_score")
    sim_score = sim_agg.get("aggregate_score")
    score_delta = round(sim_score - orig_score, 1) if orig_score is not None and sim_score is not None else None

    pct_reduction = 0.0
    if orig_score is not None and sim_score is not None and orig_score > 0:
        pct_reduction = round(((orig_score - sim_score) / orig_score) * 100, 1)

    outcome = "unchanged"
    if score_delta is not None:
        if score_delta < 0:
            outcome = "improved"
        elif score_delta > 0:
            outcome = "worsened"

    explanation = generate_diff_explanation(target_summary, sub_summary, orig_agg, sim_agg, replaced_count)

    return {
        "status": "success",
        "replaced_count": replaced_count,
        "scope": scope,
        "target": target_summary,
        "substitute": sub_summary,
        "overall": {
            "before_score": orig_score,
            "after_score": sim_score,
            "delta_score": score_delta,
            "percent_reduction": pct_reduction,
            "outcome": outcome,
            "orig_scored_count": orig_agg.get("scored_count", 0),
            "sim_scored_count": sim_agg.get("scored_count", 0),
            "orig_unknown_count": orig_agg.get("unknown_count", 0),
            "sim_unknown_count": sim_agg.get("unknown_count", 0),
            "orig_max_score": orig_agg.get("max_component_score"),
            "sim_max_score": sim_agg.get("max_component_score"),
        },
        "dimension_changes": {
            "cve_delta": sub_summary.get("cve_count", 0) - target_summary.get("cve_count", 0),
            "highest_cvss_delta": round(sub_summary.get("highest_cvss", 0.0) - target_summary.get("highest_cvss", 0.0), 1),
            "policy_flag_delta": len(sub_summary.get("policy_flags", [])) - len(target_summary.get("policy_flags", [])),
            "lifecycle_flag_delta": len(sub_summary.get("lifecycle_flags", [])) - len(target_summary.get("lifecycle_flags", [])),
        },
        "explanation": explanation,
    }
