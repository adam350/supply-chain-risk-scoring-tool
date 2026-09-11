"""
visualization.py - Modular Chart Engine for Supply Chain Risk Reporting

Generates publication-ready static charts (PNG and SVG) using Matplotlib (Agg backend).
Optimized for A4/Letter PDF embedding and web report integration:
- Target resolution: ~1200x700 px (default 150-200 DPI)
- Clean, modern, accessible color palette
- Modular registry pattern: new chart types can be added and registered easily
- Supports caching per analysis/run_id
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")  # Non-interactive, thread-safe server rendering
import matplotlib.pyplot as plt

# Consistent styling & palette
PALETTE = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#38bdf8",
    "low": "#10b981",
    "unknown": "#94a3b8",
    "bg": "#ffffff",
    "panel": "#f8fafc",
    "text": "#0f172a",
    "text_muted": "#64748b",
    "grid": "#e2e8f0",
    "accent": "#2563eb",
    "bars": ["#3b82f6", "#0ea5e9", "#06b6d4", "#14b8a6", "#10b981", "#84cc16", "#eab308", "#f97316"]
}

CHART_REGISTRY = {}


def register_chart(name):
    """Decorator to register a chart generator function into the modular registry."""
    def decorator(fn):
        CHART_REGISTRY[name] = fn
        return fn
    return decorator


def _setup_figure(figsize=(8, 4.6), dpi=150):
    """Creates a pre-styled figure and axis."""
    fig, ax = plt.subplots(figsize=figsize, dpi=dpi)
    fig.patch.set_facecolor(PALETTE["bg"])
    ax.set_facecolor(PALETTE["bg"])
    ax.tick_params(colors=PALETTE["text_muted"], labelsize=9)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    for spine in ["bottom", "left"]:
        ax.spines[spine].set_color(PALETTE["grid"])
        ax.spines[spine].set_linewidth(0.8)
    return fig, ax


@register_chart("risk_distribution")
def generate_risk_distribution_chart(report_data, output_path, export_svg=True):
    """
    Generates a donut/pie chart showing risk level distribution across components.
    """
    findings = report_data.get("findings_ranked", [])
    unscored = report_data.get("unscored_components", [])

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unverified": len(unscored)}
    for f in findings:
        score = f.get("risk_score", 0)
        if score >= 60:
            counts["Critical"] += 1
        elif score >= 50:
            counts["High"] += 1
        elif score >= 25:
            counts["Medium"] += 1
        else:
            counts["Low"] += 1

    # Filter non-zero
    filtered = {k: v for k, v in counts.items() if v > 0}
    if not filtered:
        filtered = {"No Data": 1}

    labels = list(filtered.keys())
    values = list(filtered.values())
    color_map = {
        "Critical": PALETTE["critical"],
        "High": PALETTE["high"],
        "Medium": PALETTE["medium"],
        "Low": PALETTE["low"],
        "Unverified": PALETTE["unknown"],
        "No Data": PALETTE["grid"]
    }
    colors = [color_map.get(k, PALETTE["accent"]) for k in labels]

    fig, ax = plt.subplots(figsize=(7.5, 4.4), dpi=150)
    fig.patch.set_facecolor(PALETTE["bg"])

    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        autopct=lambda p: f'{p:.1f}%\n({int(round(p * sum(values) / 100.0))})',
        startangle=140,
        colors=colors,
        pctdistance=0.72,
        wedgeprops=dict(width=0.45, edgecolor=PALETTE["bg"], linewidth=2)
    )

    for text in texts:
        text.set_color(PALETTE["text"])
        text.set_fontsize(9)
        text.set_fontweight("bold")
    for autotext in autotexts:
        autotext.set_color("#ffffff")
        autotext.set_fontsize(8.5)
        autotext.set_fontweight("bold")

    ax.set_title("Component Risk Level Distribution", fontsize=12, fontweight="bold", color=PALETTE["text"], pad=14)
    plt.tight_layout()

    _save_fig(fig, output_path, export_svg=export_svg)
    plt.close(fig)
    return str(output_path)


@register_chart("risk_by_category")
def generate_risk_by_category_chart(report_data, output_path, export_svg=True):
    """
    Generates a horizontal bar chart of average risk score breakdown
    (CVE Vulnerability, Vendor/Origin Policy, Lifecycle/EOL).
    """
    findings = report_data.get("findings_ranked", [])
    if not findings:
        return _generate_empty_chart("Risk By Category (No Data)", output_path, export_svg)

    cve_sum = 0.0
    vendor_sum = 0.0
    lifecycle_sum = 0.0
    n = len(findings)

    for f in findings:
        bd = f.get("score_breakdown", {})
        cve_sum += bd.get("cve_term", 0.0)
        vendor_sum += bd.get("vendor_origin_term", 0.0)
        lifecycle_sum += bd.get("lifecycle_term", 0.0)

    categories = ["Lifecycle / EOL Risk", "Vendor / Origin Policy", "Known CVE Risk"]
    max_weights = [15.0, 25.0, 60.0]
    averages = [lifecycle_sum / n, vendor_sum / n, cve_sum / n]
    colors = [PALETTE["high"], PALETTE["critical"], PALETTE["accent"]]

    fig, ax = _setup_figure(figsize=(8, 4.2))
    bars = ax.barh(categories, averages, color=colors, height=0.55, edgecolor="none", zorder=3)
    ax.grid(axis="x", linestyle="--", alpha=0.5, color=PALETTE["grid"], zorder=0)

    # Annotate bar values
    for bar, avg, max_w in zip(bars, averages, max_weights):
        width = bar.get_width()
        ax.text(
            width + 0.5,
            bar.get_y() + bar.get_height() / 2,
            f"{avg:.1f} pts (max {int(max_w)})",
            va="center",
            ha="left",
            fontsize=8.5,
            fontweight="bold",
            color=PALETTE["text"]
        )

    ax.set_xlim(0, max(max(averages) * 1.35, 20))
    ax.set_title("Average Risk Score Contribution by Dimension", fontsize=12, fontweight="bold", color=PALETTE["text"], pad=14)
    ax.set_xlabel("Mean Score Points", fontsize=9, color=PALETTE["text_muted"])
    plt.tight_layout()

    _save_fig(fig, output_path, export_svg=export_svg)
    plt.close(fig)
    return str(output_path)


@register_chart("vendor_risk")
def generate_vendor_risk_chart(report_data, output_path, export_svg=True):
    """
    Generates a horizontal bar chart comparing max and mean risk by top vendors.
    """
    findings = report_data.get("findings_ranked", [])
    if not findings:
        return _generate_empty_chart("Vendor Risk Breakdown (No Data)", output_path, export_svg)

    vendor_scores = {}
    for f in findings:
        vendor = f.get("vendor", "Unknown").strip() or "Unknown"
        score = f.get("risk_score", 0.0)
        vendor_scores.setdefault(vendor, []).append(score)

    # Sort vendors by max risk then mean risk
    aggregated = []
    for vendor, scores in vendor_scores.items():
        aggregated.append({
            "vendor": vendor,
            "max": max(scores),
            "mean": sum(scores) / len(scores),
            "count": len(scores)
        })
    aggregated.sort(key=lambda x: (x["max"], x["mean"]), reverse=True)
    top_vendors = aggregated[:8]
    top_vendors.reverse()  # For bottom-up vertical display

    vendors = [f"{item['vendor']} ({item['count']})" for item in top_vendors]
    max_vals = [item["max"] for item in top_vendors]
    mean_vals = [item["mean"] for item in top_vendors]

    fig, ax = _setup_figure(figsize=(8, 4.6))
    y_indices = range(len(vendors))
    height = 0.35

    ax.barh([y + height/2 for y in y_indices], max_vals, height=height, label="Max Risk Score", color=PALETTE["critical"], alpha=0.9, zorder=3)
    ax.barh([y - height/2 for y in y_indices], mean_vals, height=height, label="Mean Risk Score", color=PALETTE["accent"], alpha=0.85, zorder=3)

    ax.set_yticks(list(y_indices))
    ax.set_yticklabels(vendors, fontsize=9, color=PALETTE["text"])
    ax.grid(axis="x", linestyle="--", alpha=0.5, color=PALETTE["grid"], zorder=0)
    ax.set_xlim(0, 105)
    ax.set_xlabel("Risk Score (0 - 100)", fontsize=9, color=PALETTE["text_muted"])
    ax.set_title("Vendor Risk Profile (Top Vendors by Exposure)", fontsize=12, fontweight="bold", color=PALETTE["text"], pad=14)
    ax.legend(frameon=False, fontsize=8.5, loc="lower right")

    plt.tight_layout()
    _save_fig(fig, output_path, export_svg=export_svg)
    plt.close(fig)
    return str(output_path)


@register_chart("component_risk")
def generate_component_risk_chart(report_data, output_path, export_svg=True):
    """
    Generates a ranked horizontal bar chart of the highest risk components.
    """
    findings = report_data.get("findings_ranked", [])
    if not findings:
        return _generate_empty_chart("Top Vulnerable Components (No Data)", output_path, export_svg)

    top_findings = findings[:10]
    top_findings.reverse()

    labels = [f"{f.get('component_name', 'Unknown')}\n({f.get('vendor', '')})" for f in top_findings]
    scores = [f.get("risk_score", 0.0) for f in top_findings]

    def get_color(s):
        if s >= 60:
            return PALETTE["critical"]
        if s >= 50:
            return PALETTE["high"]
        if s >= 25:
            return PALETTE["medium"]
        return PALETTE["low"]

    colors = [get_color(s) for s in scores]

    fig, ax = _setup_figure(figsize=(8.2, 5.0))
    bars = ax.barh(labels, scores, color=colors, height=0.6, zorder=3)
    ax.grid(axis="x", linestyle="--", alpha=0.5, color=PALETTE["grid"], zorder=0)

    for bar, score in zip(bars, scores):
        ax.text(
            bar.get_width() + 1.2,
            bar.get_y() + bar.get_height() / 2,
            f"{score:.1f}",
            va="center",
            fontsize=8.5,
            fontweight="bold",
            color=PALETTE["text"]
        )

    ax.set_xlim(0, 110)
    ax.set_xlabel("Risk Score (0 - 100)", fontsize=9, color=PALETTE["text_muted"])
    ax.set_title("Highest Risk Components (Top 10 Ranked)", fontsize=12, fontweight="bold", color=PALETTE["text"], pad=14)
    plt.tight_layout()

    _save_fig(fig, output_path, export_svg=export_svg)
    plt.close(fig)
    return str(output_path)


def _generate_empty_chart(title, output_path, export_svg=True):
    fig, ax = _setup_figure(figsize=(6, 3))
    ax.text(0.5, 0.5, "No Data Available", ha="center", va="center", color=PALETTE["text_muted"], fontsize=11)
    ax.set_title(title, fontsize=11, fontweight="bold", color=PALETTE["text"])
    ax.set_xticks([])
    ax.set_yticks([])
    _save_fig(fig, output_path, export_svg=export_svg)
    plt.close(fig)
    return str(output_path)


def _save_fig(fig, output_path, export_svg=True):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save PNG (~1200x700 approx at 150 DPI for 8x4.6 in)
    fig.savefig(output_path.with_suffix(".png"), dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())

    # Save SVG if requested
    if export_svg:
        fig.savefig(output_path.with_suffix(".svg"), bbox_inches="tight", facecolor=fig.get_facecolor())


def generate_all_charts(report_data, output_dir, run_id=None, force_regenerate=False, export_svg=True):
    """
    Coordinates modular chart generation for a report run.
    Follows storage standard: reports/charts/{run_id}/
    Implements per-run caching: skips generation if charts already exist unless force_regenerate is True.

    Returns dict mapping chart_name -> {'png': path, 'svg': path, 'cached': bool}
    """
    output_dir = Path(output_dir)
    charts_dir = output_dir if not run_id else (output_dir / "charts" / str(run_id))
    charts_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    for name, generator_fn in CHART_REGISTRY.items():
        png_file = charts_dir / f"{name}.png"
        svg_file = charts_dir / f"{name}.svg"

        # Caching check: if not forcing and already generated, reuse!
        if not force_regenerate and png_file.exists():
            results[name] = {
                "png": str(png_file),
                "svg": str(svg_file) if svg_file.exists() else None,
                "cached": True
            }
            continue

        try:
            generator_fn(report_data, png_file, export_svg=export_svg)
            results[name] = {
                "png": str(png_file),
                "svg": str(svg_file) if export_svg and svg_file.exists() else None,
                "cached": False
            }
        except Exception as e:
            results[name] = {"error": str(e)}

    return results


def build_graph_data(report_data):
    """
    Constructs a lightweight node-link graph data structure from evaluated BOM report data.
    Nodes:
      - 'component': BOM items styled by risk level (critical, high, medium, low, unscored)
      - 'vendor': Suppliers linked to components ('supplied_by')
      - 'vulnerability': CVEs linked to affected components ('vulnerable_to')
    Edges:
      Explicit relationships only (component -> vendor, component -> vulnerability).
    """
    if not isinstance(report_data, dict):
        return {"nodes": [], "edges": [], "summary": {"total_nodes": 0, "total_edges": 0}}

    findings = report_data.get("findings_ranked", []) or []
    unscored = report_data.get("unscored_components", []) or []

    nodes = []
    edges = []
    seen_vendors = {}
    seen_cves = {}
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unscored": 0}

    def get_risk_level(score):
        if score is None:
            return "unscored"
        if score >= 60:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    # 1. Process Scored Findings
    for idx, f in enumerate(findings):
        comp_id = f"comp_{idx}"
        score = f.get("risk_score")
        level = get_risk_level(score)
        risk_counts[level] = risk_counts.get(level, 0) + 1

        comp_name = f.get("component_name") or "Unknown Component"
        vendor_name = (f.get("vendor") or "").strip()
        version = f.get("version") or ""

        nodes.append({
            "id": comp_id,
            "type": "component",
            "label": comp_name,
            "name": comp_name,
            "vendor": vendor_name,
            "version": version,
            "origin_country": f.get("origin_country", ""),
            "risk_score": score,
            "risk_level": level,
            "score_breakdown": f.get("score_breakdown", {}),
            "matched_cves": f.get("matched_cves", []),
            "policy_flags": f.get("policy_flags", []),
            "lifecycle_flags": f.get("lifecycle_flags", []),
            "suggested_mitigation": f.get("suggested_mitigation", ""),
            "unit_count": f.get("unit_count", 0),
            "affected_units": f.get("affected_units", []),
            "is_scored": True
        })

        # Explicit Vendor Relationship
        if vendor_name and vendor_name.lower() != "unknown":
            v_id = f"vendor:{vendor_name.lower()}"
            if v_id not in seen_vendors:
                v_node = {
                    "id": v_id,
                    "type": "vendor",
                    "label": vendor_name,
                    "name": vendor_name,
                    "component_count": 1
                }
                seen_vendors[v_id] = v_node
                nodes.append(v_node)
            else:
                seen_vendors[v_id]["component_count"] += 1

            edges.append({
                "source": comp_id,
                "target": v_id,
                "type": "supplied_by",
                "label": "Supplied By"
            })

        # Explicit Vulnerability (CVE) Relationships
        for cve in f.get("matched_cves", []):
            cve_id = (cve.get("id") or "").strip()
            if not cve_id:
                continue
            cve_node_id = f"cve:{cve_id}"
            if cve_node_id not in seen_cves:
                cve_node = {
                    "id": cve_node_id,
                    "type": "vulnerability",
                    "label": cve_id,
                    "cve_id": cve_id,
                    "cvss": cve.get("cvss"),
                    "severity": (cve.get("severity") or "UNKNOWN").upper(),
                    "description": cve.get("description", ""),
                    "source_url": cve.get("source_url")
                }
                seen_cves[cve_node_id] = cve_node
                nodes.append(cve_node)

            edges.append({
                "source": comp_id,
                "target": cve_node_id,
                "type": "vulnerable_to",
                "label": "Affected By"
            })

    # 2. Process Unscored / Unverified Components
    for u_idx, u in enumerate(unscored):
        comp_id = f"comp_u_{u_idx}"
        risk_counts["unscored"] += 1

        comp_name = u.get("component_name") or "Unknown Component"
        vendor_name = (u.get("vendor") or "").strip()
        version = u.get("version") or ""

        nodes.append({
            "id": comp_id,
            "type": "component",
            "label": comp_name,
            "name": comp_name,
            "vendor": vendor_name,
            "version": version,
            "origin_country": u.get("origin_country", ""),
            "risk_score": None,
            "risk_level": "unscored",
            "reason": u.get("reason", "No verification data found."),
            "action_required": u.get("action_required", "Manual review required."),
            "unit_count": u.get("unit_count", 0),
            "affected_units": u.get("affected_units", []),
            "is_scored": False
        })

        if vendor_name and vendor_name.lower() != "unknown":
            v_id = f"vendor:{vendor_name.lower()}"
            if v_id not in seen_vendors:
                v_node = {
                    "id": v_id,
                    "type": "vendor",
                    "label": vendor_name,
                    "name": vendor_name,
                    "component_count": 1
                }
                seen_vendors[v_id] = v_node
                nodes.append(v_node)
            else:
                seen_vendors[v_id]["component_count"] += 1

            edges.append({
                "source": comp_id,
                "target": v_id,
                "type": "supplied_by",
                "label": "Supplied By"
            })

    summary = {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "components_count": len(findings) + len(unscored),
        "vendors_count": len(seen_vendors),
        "cves_count": len(seen_cves),
        "risk_counts": risk_counts
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": summary
    }

