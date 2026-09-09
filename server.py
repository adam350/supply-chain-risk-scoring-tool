#!/usr/bin/env python3
"""
server.py - Local Web Interface for Manual Server BOM Ingestion & Risk Scoring

Runs a local web server (Python standard library only) allowing users to:
  1. Drag and drop or browse to upload a BOM file (CycloneDX JSON or CSV).
  2. Optionally auto-clean messy CSV BOMs prior to scoring.
  3. One-click load built-in sample BOMs (CycloneDX JSON, sample CSV, messy raw CSV).
  4. View instant summary KPIs (Aggregate score, buy/hold verdict, component counts).
  5. Explore the interactive findings report directly in an embedded viewer.

Usage:
    python server.py [--port 8080] [--no-browser]
"""

import argparse
import email
import email.policy
import json
import mimetypes
import os
import re
import sys
import threading
import time
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from uuid import uuid4

BASE_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(BASE_DIR / "src"))

import main as scoring_pipeline
import clean_bom as cleaner_module
from bom_parser import parse_bom
from cve_matcher import load_cve_database
from rules_engine import load_rules
from alternatives_engine import load_alternatives, find_alternatives_for
from simulator import run_simulation

UPLOADS_DIR = BASE_DIR / "output" / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

CVE_DB_PATH = BASE_DIR / "data" / "cve_database.json"
RULES_PATH = BASE_DIR / "data" / "rules.json"
ALTERNATIVES_PATH = BASE_DIR / "data" / "alternatives.json"

SAMPLES = {
    "cyclonedx": BASE_DIR / "data" / "sample_bom_cyclonedx.json",
    "csv": BASE_DIR / "data" / "sample_bom.csv",
    "raw_csv": BASE_DIR / "data" / "raw_bom_large.csv",
}


def process_bom_file(file_path, original_filename, clean_csv=True):
    """
    Executes the ingestion and scoring pipeline for an uploaded BOM.
    Returns (summary_dict, report_data, run_dir).
    """
    run_id = f"{int(time.time())}_{uuid4().hex[:8]}"
    run_dir = UPLOADS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    target_bom_path = run_dir / original_filename
    if file_path != target_bom_path:
        with open(file_path, "rb") as src, open(target_bom_path, "wb") as dst:
            dst.write(src.read())

    suffix = target_bom_path.suffix.lower()
    cleaned_csv_path = None

    if suffix == ".csv" and clean_csv:
        # Run messy-data cleaning first
        cleaned_csv_path = cleaner_module.run(target_bom_path, run_dir)
        scoring_bom_path = cleaned_csv_path
    elif suffix in (".csv", ".json"):
        scoring_bom_path = target_bom_path
    else:
        raise ValueError(f"Unsupported file type: {suffix}. Expected .json (CycloneDX) or .csv")

    report = scoring_pipeline.run(
        bom_path=scoring_bom_path,
        out_dir=run_dir,
        cve_db_path=CVE_DB_PATH,
        rules_path=RULES_PATH,
    )

    # Save parsed components list in run_dir for non-mutating What-If simulations
    try:
        comps, _ = parse_bom(scoring_bom_path)
        with open(run_dir / "components.json", "w", encoding="utf-8") as f:
            json.dump(comps, f, indent=2)
    except Exception:
        pass

    presentation = report.get("presentation", {})
    summary = {
        "run_id": run_id,
        "filename": original_filename,
        "format": "CycloneDX JSON" if suffix == ".json" else "CSV",
        "cleaned_first": bool(cleaned_csv_path),
        "aggregate_score": report.get("aggregate", {}).get("aggregate_score"),
        "verdict": presentation.get("verdict", {}).get("label", "REVIEW"),
        "verdict_color": presentation.get("verdict", {}).get("color", "#f59e0b"),
        "scored_count": report.get("aggregate", {}).get("scored_count", 0),
        "unscored_count": report.get("aggregate", {}).get("unknown_count", 0),
        "total_components": len(report.get("findings_ranked", [])) + len(report.get("unscored_components", [])),
        "ingestion_errors": len(report.get("ingestion_errors", [])),
        "report_html_url": f"/reports/{run_id}/report.html",
        "report_json_url": f"/reports/{run_id}/report.json",
        "cleaning_report_url": f"/reports/{run_id}/cleaning_report.html" if cleaned_csv_path else None,
    }

    return summary, report, run_dir


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Supply Chain Risk Scoring — Server BOM Ingestion</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f293d;
      --card-hover: #26334d;
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.15);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #10b981;
      --mono: 'JetBrains Mono', monospace;
      --sans: 'Inter', system-ui, -apple-system, sans-serif;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      min-height: 100vh;
      line-height: 1.5;
      padding-bottom: 60px;
    }

    header {
      background: rgba(17, 24, 39, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--card-border);
      padding: 18px 32px;
      position: sticky;
      top: 0;
      z-index: 50;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-icon {
      background: linear-gradient(135deg, #38bdf8, #6366f1);
      width: 36px;
      height: 36px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      color: #fff;
      font-size: 18px;
      box-shadow: 0 0 15px rgba(56, 189, 248, 0.35);
    }

    .brand-title {
      font-size: 17px;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: #fff;
    }

    .brand-subtitle {
      font-size: 12px;
      color: var(--text-muted);
      font-family: var(--mono);
    }

    .header-badge {
      background: rgba(56, 189, 248, 0.1);
      border: 1px solid rgba(56, 189, 248, 0.25);
      color: var(--accent);
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 11px;
      font-family: var(--mono);
      font-weight: 600;
    }

    main {
      max-width: 1200px;
      margin: 32px auto;
      padding: 0 24px;
      display: flex;
      flex-direction: column;
      gap: 28px;
    }

    .hero {
      text-align: center;
      padding: 24px 0 12px 0;
    }

    .hero h1 {
      font-size: 32px;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #ffffff 40%, #94a3b8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 8px;
    }

    .hero p {
      color: var(--text-muted);
      font-size: 15px;
      max-width: 680px;
      margin: 0 auto;
    }

    .upload-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
    }

    .dropzone {
      border: 2px dashed var(--card-border);
      border-radius: 12px;
      padding: 48px 24px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s ease;
      background: rgba(15, 23, 42, 0.6);
      position: relative;
    }

    .dropzone:hover, .dropzone.dragover {
      border-color: var(--accent);
      background: var(--accent-glow);
    }

    .dropzone-icon {
      font-size: 40px;
      margin-bottom: 12px;
      display: inline-block;
      filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.4));
    }

    .dropzone-title {
      font-size: 17px;
      font-weight: 600;
      color: #fff;
      margin-bottom: 6px;
    }

    .dropzone-desc {
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 16px;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: linear-gradient(135deg, #0284c7, #2563eb);
      color: #fff;
      font-weight: 600;
      font-size: 14px;
      padding: 10px 20px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      transition: all 0.2s;
      box-shadow: 0 2px 10px rgba(37, 99, 235, 0.3);
    }

    .btn:hover {
      background: linear-gradient(135deg, #38bdf8, #3b82f6);
      transform: translateY(-1px);
      box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4);
    }

    .btn-secondary {
      background: #1e293b;
      color: #cbd5e1;
      border: 1px solid #334155;
      box-shadow: none;
    }

    .btn-secondary:hover {
      background: #334155;
      color: #fff;
      transform: translateY(-1px);
    }

    .btn-group {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }

    .controls-row {
      margin-top: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      padding-top: 16px;
      border-top: 1px solid var(--card-border);
    }

    .checkbox-label {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: #cbd5e1;
      cursor: pointer;
      user-select: none;
    }

    .checkbox-label input[type="checkbox"] {
      accent-color: var(--accent);
      width: 16px;
      height: 16px;
      cursor: pointer;
    }

    .sample-triggers {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .sample-label {
      font-size: 12px;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .pill-btn {
      background: #1e293b;
      border: 1px solid #334155;
      color: #94a3b8;
      font-size: 12px;
      padding: 5px 12px;
      border-radius: 9999px;
      cursor: pointer;
      transition: all 0.15s ease;
      font-family: var(--mono);
    }

    .pill-btn:hover {
      background: #334155;
      color: #fff;
      border-color: var(--accent);
    }

    /* Selected File Bar */
    .selected-bar {
      display: none;
      margin-top: 16px;
      background: #0f172a;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 12px 18px;
      justify-content: space-between;
      align-items: center;
    }

    .selected-bar.active {
      display: flex;
    }

    .file-meta {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .file-name {
      font-weight: 600;
      color: #fff;
      font-size: 14px;
      font-family: var(--mono);
    }

    .file-badge {
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 4px;
      font-family: var(--mono);
      font-weight: 600;
    }

    .badge-json { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
    .badge-csv { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }

    /* Alert Banner */
    .alert {
      display: none;
      padding: 14px 18px;
      border-radius: 8px;
      font-size: 13px;
      margin-top: 16px;
    }

    .alert-error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #fca5a5;
    }

    .alert-info {
      background: rgba(56, 189, 248, 0.1);
      border: 1px solid rgba(56, 189, 248, 0.3);
      color: #7dd3fc;
    }

    /* Results Section */
    .results-container {
      display: none;
      flex-direction: column;
      gap: 20px;
    }

    .results-container.active {
      display: flex;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
    }

    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      position: relative;
      overflow: hidden;
    }

    .metric-title {
      font-size: 12px;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .metric-value {
      font-size: 28px;
      font-weight: 800;
      font-family: var(--mono);
      color: #fff;
    }

    .metric-sub {
      font-size: 12px;
      color: var(--text-muted);
    }

    .report-viewer-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
      display: flex;
      flex-direction: column;
    }

    .viewer-header {
      padding: 16px 24px;
      background: rgba(15, 23, 42, 0.8);
      border-bottom: 1px solid var(--card-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }

    .viewer-title {
      font-weight: 700;
      font-size: 15px;
      color: #fff;
    }

    .report-frame {
      width: 100%;
      height: 750px;
      border: none;
      background: #0f172a;
    }

    .loader-overlay {
      position: fixed;
      inset: 0;
      background: rgba(9, 13, 22, 0.85);
      backdrop-filter: blur(6px);
      display: none;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      gap: 16px;
      z-index: 100;
    }

    .loader-overlay.active {
      display: flex;
    }

    .spinner {
      width: 48px;
      height: 48px;
      border: 4px solid rgba(56, 189, 248, 0.2);
      border-top-color: var(--accent);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .loader-text {
      font-size: 16px;
      font-weight: 600;
      color: #fff;
    }

    /* What-If Simulator Modal Styles */
    .sim-modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(9, 13, 22, 0.85);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 200;
      padding: 20px;
    }

    .sim-modal-overlay.active {
      display: flex;
    }

    .sim-modal {
      background: #111827;
      border: 1px solid #1f293d;
      border-radius: 16px;
      width: 100%;
      max-width: 860px;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
      display: flex;
      flex-direction: column;
      animation: modalFadeIn 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    }

    @keyframes modalFadeIn {
      from { opacity: 0; transform: scale(0.96) translateY(10px); }
      to { opacity: 1; transform: scale(1) translateY(0); }
    }

    .sim-header {
      padding: 20px 24px;
      background: rgba(15, 23, 42, 0.85);
      border-bottom: 1px solid #1f293d;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .sim-title {
      font-size: 18px;
      font-weight: 800;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .sim-close-btn {
      background: #1e293b;
      border: 1px solid #334155;
      color: #94a3b8;
      width: 32px;
      height: 32px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.15s;
    }

    .sim-close-btn:hover {
      background: #334155;
      color: #fff;
    }

    .sim-body {
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .sim-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }

    @media (max-width: 640px) {
      .sim-grid { grid-template-columns: 1fr; }
    }

    .sim-card {
      background: #0f172a;
      border: 1px solid #1f293d;
      border-radius: 12px;
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .sim-card.target-card {
      border-left: 4px solid var(--danger);
    }

    .sim-card.sub-card {
      border-left: 4px solid var(--accent);
    }

    .sim-card-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }

    .sim-comp-name {
      font-size: 16px;
      font-weight: 700;
      color: #fff;
    }

    .sim-comp-meta {
      font-size: 12.5px;
      color: var(--text-muted);
    }

    .sim-field-label {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 6px;
      display: block;
    }

    .sim-select, .sim-input {
      width: 100%;
      background: #1e293b;
      border: 1px solid #334155;
      color: #fff;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-family: var(--sans);
      outline: none;
      transition: border-color 0.2s;
    }

    .sim-select:focus, .sim-input:focus {
      border-color: var(--accent);
    }

    .sim-custom-toggle {
      font-size: 12px;
      color: var(--accent);
      cursor: pointer;
      text-decoration: underline;
      display: inline-block;
      margin-top: 4px;
    }

    .sim-custom-inputs {
      display: none;
      flex-direction: column;
      gap: 10px;
      margin-top: 8px;
    }

    .sim-custom-inputs.active {
      display: flex;
    }

    /* Simulation Results Banner */
    .sim-results-box {
      display: none;
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid #1f293d;
      border-radius: 12px;
      padding: 20px;
      flex-direction: column;
      gap: 16px;
    }

    .sim-results-box.active {
      display: flex;
    }

    .sim-kpi-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }

    .sim-kpi {
      background: #111827;
      border: 1px solid #1f293d;
      border-radius: 10px;
      padding: 14px;
    }

    .sim-kpi-label {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .sim-kpi-val {
      font-size: 24px;
      font-weight: 800;
      font-family: var(--mono);
      margin-top: 4px;
    }

    .sim-kpi-sub {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    .sim-explanation {
      background: #1e293b;
      border-left: 3px solid var(--accent);
      padding: 12px 16px;
      border-radius: 6px;
      font-size: 13.5px;
      color: #e2e8f0;
      line-height: 1.6;
    }

    .btn-sim-run {
      width: 100%;
      padding: 12px;
      font-size: 15px;
      justify-content: center;
      background: linear-gradient(135deg, #0284c7, #2563eb);
      font-weight: 700;
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="brand-icon">⚡</div>
      <div>
        <div class="brand-title">Supply Chain Risk Scoring Tool</div>
        <div class="brand-subtitle">Server BOM Ingestion Portal</div>
      </div>
    </div>
    <div class="header-badge">CycloneDX 1.4-1.6 & CSV Ingestion</div>
  </header>

  <main>
    <section class="hero">
      <h1>Ingest & Score Server Bill of Materials</h1>
      <p>Upload a CycloneDX JSON document or flat CSV BOM to match components against CVE advisories, evaluate national/vendor restrictions, and generate an explainable risk report.</p>
    </section>

    <!-- Upload Card -->
    <section class="upload-card">
      <div id="dropzone" class="dropzone">
        <div class="dropzone-icon">📥</div>
        <div class="dropzone-title">Drop your server BOM here, or browse</div>
        <div class="dropzone-desc">Supports CycloneDX JSON (.json) or CSV (.csv)</div>
        <input type="file" id="fileInput" accept=".json,.csv" style="display: none;" />
        <button type="button" class="btn" onclick="document.getElementById('fileInput').click()">Select BOM File</button>
      </div>

      <!-- File Confirmation & Action Bar -->
      <div id="selectedBar" class="selected-bar">
        <div class="file-meta">
          <span id="fileBadge" class="file-badge">FORMAT</span>
          <span id="fileName" class="file-name">filename.json</span>
        </div>
        <div class="btn-group">
          <button type="button" class="btn btn-secondary" onclick="clearSelected()">Change File</button>
          <button type="button" id="scoreBtn" class="btn" onclick="submitUpload()">⚡ Score BOM</button>
        </div>
      </div>

      <div id="alertBox" class="alert"></div>

      <!-- Footer Controls & Quick Samples -->
      <div class="controls-row">
        <label class="checkbox-label">
          <input type="checkbox" id="cleanCsvCheckbox" checked />
          <span>Auto-clean raw CSV BOMs (deduplicate, sanitize placeholders, normalize ISO-2)</span>
        </label>

        <div class="sample-triggers">
          <span class="sample-label">Try built-in sample:</span>
          <button type="button" class="pill-btn" onclick="loadSample('cyclonedx')">CycloneDX JSON</button>
          <button type="button" class="pill-btn" onclick="loadSample('csv')">Clean CSV (14 parts)</button>
          <button type="button" class="pill-btn" onclick="loadSample('raw_csv')">Messy Raw CSV (60 parts)</button>
        </div>
      </div>
    </section>

    <!-- Live Results Section -->
    <section id="resultsSection" class="results-container">
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-title">Aggregate BOM Score</div>
          <div id="metricScore" class="metric-value">--</div>
          <div id="metricScoreSub" class="metric-sub">0 to 100 Scale</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Procurement Verdict</div>
          <div id="metricVerdict" class="metric-value">--</div>
          <div id="metricVerdictSub" class="metric-sub">Decision gate</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Components Evaluated</div>
          <div id="metricCount" class="metric-value">--</div>
          <div id="metricCountSub" class="metric-sub">Scored vs unscored</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Ingestion Quality</div>
          <div id="metricErrors" class="metric-value">--</div>
          <div id="metricErrorsSub" class="metric-sub">Dropped / invalid rows</div>
        </div>
      </div>

      <div class="report-viewer-card">
        <div class="viewer-header">
          <div class="viewer-title" id="viewerTitle">Risk Findings & Action Report</div>
          <div class="btn-group">
            <button type="button" id="launchSimulatorBtn" class="btn" style="background: linear-gradient(135deg, #0284c7, #2563eb); font-size: 13px; padding: 6px 14px;" onclick="openSimulatorModal()">⚡ What-If Simulator</button>
            <a id="cleanReportLink" href="#" target="_blank" class="btn btn-secondary" style="display: none; font-size: 13px; padding: 6px 14px;">View Cleaning Report</a>
            <a id="downloadJsonBtn" href="#" target="_blank" class="btn btn-secondary" style="font-size: 13px; padding: 6px 14px;">Download JSON</a>
            <a id="openTabBtn" href="#" target="_blank" class="btn" style="font-size: 13px; padding: 6px 14px;">Open Full Report ↗</a>
          </div>
        </div>
        <iframe id="reportFrame" class="report-frame" src="about:blank"></iframe>
      </div>
    </section>
  </main>

  <!-- What-If Supply Chain Simulator Modal -->
  <div id="simModalOverlay" class="sim-modal-overlay">
    <div class="sim-modal">
      <div class="sim-header">
        <div class="sim-title">⚡ What-If Supply Chain Simulator</div>
        <button type="button" class="sim-close-btn" onclick="closeSimulatorModal()">✕</button>
      </div>
      <div class="sim-body">
        <div class="sim-grid">
          <!-- Current Target Component -->
          <div class="sim-card target-card">
            <div class="sim-card-title">Current Component in BOM</div>
            <div>
              <label class="sim-field-label">Select Component to Replace</label>
              <select id="simTargetSelect" class="sim-select" onchange="onSimTargetChange()">
                <option value="">-- Choose a component --</option>
              </select>
            </div>
            <div id="simTargetDetails" style="display: none; flex-direction: column; gap: 6px;">
              <div class="sim-comp-name" id="simTargetName">--</div>
              <div class="sim-comp-meta" id="simTargetMeta">--</div>
              <div style="margin-top: 4px; display: flex; align-items: center; gap: 8px;">
                <span class="pill" id="simTargetPill">--</span>
                <span style="font-weight: 700; font-family: var(--mono); font-size: 14px;" id="simTargetScore">Risk: --</span>
              </div>
              <div id="simTargetFlags" style="font-size: 12px; color: var(--text-muted); margin-top: 4px;"></div>
            </div>
          </div>

          <!-- Proposed Substitute Component -->
          <div class="sim-card sub-card">
            <div class="sim-card-title">Simulated Replacement</div>
            <div>
              <label class="sim-field-label">Select Pre-Configured Alternative</label>
              <select id="simAltSelect" class="sim-select" onchange="onSimAltSelectChange()">
                <option value="">-- Select alternative --</option>
              </select>
              <span class="sim-custom-toggle" onclick="toggleCustomAltInputs()">or define custom replacement ✎</span>
            </div>

            <!-- Custom replacement input fields -->
            <div id="simCustomInputs" class="sim-custom-inputs">
              <div>
                <label class="sim-field-label">Component Name</label>
                <input type="text" id="simCustomName" class="sim-input" placeholder="e.g. BMC Firmware" />
              </div>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                <div>
                  <label class="sim-field-label">Vendor</label>
                  <input type="text" id="simCustomVendor" class="sim-input" placeholder="e.g. Aspeed" />
                </div>
                <div>
                  <label class="sim-field-label">Version</label>
                  <input type="text" id="simCustomVersion" class="sim-input" placeholder="e.g. 2.14" />
                </div>
              </div>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                <div>
                  <label class="sim-field-label">Origin Country (ISO-2)</label>
                  <input type="text" id="simCustomOrigin" class="sim-input" placeholder="e.g. US or TW" />
                </div>
                <div>
                  <label class="sim-field-label">Part Number (Optional)</label>
                  <input type="text" id="simCustomPart" class="sim-input" placeholder="e.g. AST2600-OBMC" />
                </div>
              </div>
            </div>

            <div id="simAltNotes" style="display: none; font-size: 12px; color: #7dd3fc; background: rgba(56, 189, 248, 0.1); padding: 8px 12px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.25);"></div>
          </div>
        </div>

        <button type="button" id="runSimulationBtn" class="btn btn-sim-run" onclick="executeSimulation()">⚡ Run What-If Simulation</button>

        <!-- Simulation Comparison Results -->
        <div id="simResultsBox" class="sim-results-box">
          <div style="font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent);">Simulation Impact Analysis</div>
          
          <div class="sim-kpi-row">
            <div class="sim-kpi">
              <div class="sim-kpi-label">Overall BOM Risk</div>
              <div class="sim-kpi-val" id="simKpiBOMScore">-- ➔ --</div>
              <div class="sim-kpi-sub" id="simKpiBOMDelta">--</div>
            </div>
            <div class="sim-kpi">
              <div class="sim-kpi-label">Component Risk</div>
              <div class="sim-kpi-val" id="simKpiCompScore">-- ➔ --</div>
              <div class="sim-kpi-sub" id="simKpiCompDelta">--</div>
            </div>
            <div class="sim-kpi">
              <div class="sim-kpi-label">Vulnerabilities (CVEs)</div>
              <div class="sim-kpi-val" id="simKpiCves">--</div>
              <div class="sim-kpi-sub" id="simKpiCveDetail">--</div>
            </div>
            <div class="sim-kpi">
              <div class="sim-kpi-label">Policy & Lifecycle</div>
              <div class="sim-kpi-val" id="simKpiPolicy">--</div>
              <div class="sim-kpi-sub" id="simKpiPolicyDetail">--</div>
            </div>
          </div>

          <div class="sim-explanation" id="simExplanationText">--</div>
        </div>
      </div>
    </div>
  </div>

  <div id="loader" class="loader-overlay">
    <div class="spinner"></div>
    <div id="loaderText" class="loader-text">Analyzing BOM components...</div>
  </div>

  <script>
    let selectedFile = null;

    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const selectedBar = document.getElementById('selectedBar');
    const fileNameEl = document.getElementById('fileName');
    const fileBadgeEl = document.getElementById('fileBadge');
    const alertBox = document.getElementById('alertBox');
    const cleanCheckbox = document.getElementById('cleanCsvCheckbox');
    const loader = document.getElementById('loader');
    const loaderText = document.getElementById('loaderText');
    const resultsSection = document.getElementById('resultsSection');

    // Drag & Drop
    ['dragenter', 'dragover'].forEach(name => {
      dropzone.addEventListener(name, (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    });
    ['dragleave', 'drop'].forEach(name => {
      dropzone.addEventListener(name, (e) => { e.preventDefault(); dropzone.classList.remove('dragover'); });
    });
    dropzone.addEventListener('drop', (e) => {
      const files = e.dataTransfer.files;
      if (files.length > 0) handleFileSelect(files[0]);
    });
    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) handleFileSelect(e.target.files[0]);
    });

    function handleFileSelect(file) {
      selectedFile = file;
      hideAlert();
      const ext = file.name.split('.').pop().toLowerCase();
      fileNameEl.textContent = file.name;
      fileBadgeEl.textContent = ext === 'json' ? 'CycloneDX JSON' : 'CSV BOM';
      fileBadgeEl.className = 'file-badge ' + (ext === 'json' ? 'badge-json' : 'badge-csv');
      selectedBar.classList.add('active');
    }

    function clearSelected() {
      selectedFile = null;
      fileInput.value = '';
      selectedBar.classList.remove('active');
      hideAlert();
    }

    function showAlert(msg, isError = true) {
      alertBox.textContent = msg;
      alertBox.className = 'alert ' + (isError ? 'alert-error' : 'alert-info');
      alertBox.style.display = 'block';
    }

    function hideAlert() {
      alertBox.style.display = 'none';
    }

    function showLoader(text) {
      loaderText.textContent = text;
      loader.classList.add('active');
    }

    function hideLoader() {
      loader.classList.remove('active');
    }

    async function submitUpload() {
      if (!selectedFile) {
        showAlert('Please select a BOM file first.');
        return;
      }
      hideAlert();
      showLoader('Uploading and parsing ' + selectedFile.name + '...');

      try {
        const clean = cleanCheckbox.checked ? 'true' : 'false';
        const resp = await fetch('/api/upload', {
          method: 'POST',
          body: selectedFile,
          headers: {
            'X-Filename': encodeURIComponent(selectedFile.name),
            'X-Clean-Csv': clean,
          }
        });

        const data = await resp.json();
        if (!resp.ok) {
          throw new Error(data.error || 'Server error occurred during ingestion.');
        }

        renderResults(data);
      } catch (err) {
        showAlert(err.message, true);
      } finally {
        hideLoader();
      }
    }

    async function loadSample(type) {
      hideAlert();
      showLoader('Loading and scoring ' + type + ' sample BOM...');
      try {
        const clean = cleanCheckbox.checked ? 'true' : 'false';
        const resp = await fetch('/api/samples/' + type + '?clean=' + clean);
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to load sample.');
        renderResults(data);
      } catch (err) {
        showAlert(err.message, true);
      } finally {
        hideLoader();
      }
    }

    function renderResults(data) {
      document.getElementById('metricScore').textContent = data.aggregate_score !== null ? data.aggregate_score : 'N/A';
      const verdictEl = document.getElementById('metricVerdict');
      verdictEl.textContent = data.verdict;
      verdictEl.style.color = data.verdict_color;

      document.getElementById('metricCount').textContent = data.total_components;
      document.getElementById('metricCountSub').textContent = `${data.scored_count} scored, ${data.unscored_count} unscored`;

      document.getElementById('metricErrors').textContent = data.ingestion_errors;
      document.getElementById('metricErrorsSub').textContent = data.ingestion_errors === 0 ? 'All rows clean' : 'Invalid rows logged & skipped';

      document.getElementById('viewerTitle').textContent = `Risk Findings Report — ${data.filename} (${data.format})`;
      document.getElementById('openTabBtn').href = data.report_html_url;
      document.getElementById('downloadJsonBtn').href = data.report_json_url;

      const cleanLink = document.getElementById('cleanReportLink');
      if (data.cleaning_report_url) {
        cleanLink.href = data.cleaning_report_url;
        cleanLink.style.display = 'inline-flex';
      } else {
        cleanLink.style.display = 'none';
      }

      const frame = document.getElementById('reportFrame');
      frame.src = data.report_html_url;

      resultsSection.classList.add('active');
      resultsSection.scrollIntoView({ behavior: 'smooth' });

      // Populate Simulator Target dropdown
      currentRunId = data.run_id;
      fetchRunFindings(data.report_json_url);
    }

    /* What-If Simulator Client Logic */
    let currentRunId = null;
    let currentFindings = [];
    let currentSelectedTarget = null;
    let currentAlternatives = [];
    let isCustomAlt = false;

    async function fetchRunFindings(reportJsonUrl) {
      try {
        const resp = await fetch(reportJsonUrl);
        if (resp.ok) {
          const report = await resp.json();
          currentFindings = report.findings_ranked || [];
          populateTargetDropdown(currentFindings);
        }
      } catch (e) {
        console.warn('Could not load findings for simulator:', e);
      }
    }

    function populateTargetDropdown(findings) {
      const select = document.getElementById('simTargetSelect');
      select.innerHTML = '<option value="">-- Choose a component --</option>';
      findings.forEach((f, idx) => {
        const opt = document.createElement('option');
        opt.value = idx;
        opt.textContent = `${f.component_name} (${f.vendor} v${f.version}) — Score: ${f.risk_score}`;
        select.appendChild(opt);
      });
    }

    function openSimulatorModal(targetCompName, targetVendor, targetVersion) {
      const overlay = document.getElementById('simModalOverlay');
      overlay.classList.add('active');

      if (targetCompName) {
        // Pre-select matching component
        const idx = currentFindings.findIndex(f => 
          f.component_name.toLowerCase() === targetCompName.toLowerCase() &&
          (!targetVendor || f.vendor.toLowerCase() === targetVendor.toLowerCase())
        );
        if (idx !== -1) {
          const select = document.getElementById('simTargetSelect');
          select.value = idx;
          onSimTargetChange();
        }
      } else if (!currentSelectedTarget && currentFindings.length > 0) {
        document.getElementById('simTargetSelect').value = "0";
        onSimTargetChange();
      }
    }

    function closeSimulatorModal() {
      document.getElementById('simModalOverlay').classList.remove('active');
    }

    async function onSimTargetChange() {
      const select = document.getElementById('simTargetSelect');
      const idx = select.value;
      const detailsBox = document.getElementById('simTargetDetails');

      if (idx === "") {
        detailsBox.style.display = 'none';
        currentSelectedTarget = null;
        return;
      }

      const f = currentFindings[idx];
      currentSelectedTarget = f;

      detailsBox.style.display = 'flex';
      document.getElementById('simTargetName').textContent = `${f.component_name} (${f.vendor})`;
      document.getElementById('simTargetMeta').textContent = `Version: ${f.version} · Origin: ${f.origin_country} · Affects ${f.unit_count} unit(s)`;
      document.getElementById('simTargetScore').textContent = `Risk: ${f.risk_score} / 100`;

      const pill = document.getElementById('simTargetPill');
      const score = f.risk_score;
      if (score >= 60) {
        pill.className = 'pill pill-critical';
        pill.textContent = 'CRITICAL';
      } else if (score >= 50) {
        pill.className = 'pill pill-high';
        pill.textContent = 'HIGH';
      } else if (score >= 25) {
        pill.className = 'pill pill-medium';
        pill.textContent = 'MEDIUM';
      } else {
        pill.className = 'pill pill-low';
        pill.textContent = 'LOW';
      }

      let flagInfo = [];
      if (f.matched_cves && f.matched_cves.length > 0) {
        flagInfo.push(`${f.matched_cves.length} CVE(s) detected`);
      }
      if (f.policy_flags && f.policy_flags.length > 0) {
        flagInfo.push(`Policy violation (${f.policy_flags.length})`);
      }
      if (f.lifecycle_flags && f.lifecycle_flags.length > 0) {
        flagInfo.push(`Lifecycle flag (${f.lifecycle_flags.length})`);
      }
      document.getElementById('simTargetFlags').textContent = flagInfo.join(' • ') || 'No flags';

      // Fetch alternatives for this component
      await fetchAlternativesFor(f.component_name, f.vendor);
    }

    async function fetchAlternativesFor(compName, vendor) {
      const altSelect = document.getElementById('simAltSelect');
      altSelect.innerHTML = '<option value="">Loading alternatives...</option>';
      document.getElementById('simAltNotes').style.display = 'none';

      try {
        const resp = await fetch(`/api/alternatives?component=${encodeURIComponent(compName)}&vendor=${encodeURIComponent(vendor)}`);
        const data = await resp.json();
        currentAlternatives = data.options || [];

        altSelect.innerHTML = '';
        if (currentAlternatives.length > 0) {
          currentAlternatives.forEach((alt, i) => {
            const opt = document.createElement('option');
            opt.value = i;
            opt.textContent = `${alt.label}`;
            altSelect.appendChild(opt);
          });
          altSelect.value = "0";
          onSimAltSelectChange();
        } else {
          altSelect.innerHTML = '<option value="">No pre-configured alternatives in catalog</option>';
          // Auto-expand custom inputs if no catalog entry
          toggleCustomAltInputs(true);
          document.getElementById('simCustomName').value = compName;
        }
      } catch (err) {
        altSelect.innerHTML = '<option value="">Failed to load catalog</option>';
      }
    }

    function onSimAltSelectChange() {
      const idx = document.getElementById('simAltSelect').value;
      const notesBox = document.getElementById('simAltNotes');

      if (idx !== "" && currentAlternatives[idx]) {
        const alt = currentAlternatives[idx];
        notesBox.textContent = `ℹ️ ${alt.notes}`;
        notesBox.style.display = 'block';

        // Pre-fill custom fields in case user toggles
        document.getElementById('simCustomName').value = alt.component_name;
        document.getElementById('simCustomVendor').value = alt.vendor;
        document.getElementById('simCustomVersion').value = alt.version;
        document.getElementById('simCustomOrigin').value = alt.origin_country || 'US';
        document.getElementById('simCustomPart').value = alt.part_number || '';
      } else {
        notesBox.style.display = 'none';
      }
    }

    function toggleCustomAltInputs(forceOpen = null) {
      const inputs = document.getElementById('simCustomInputs');
      if (forceOpen !== null) {
        isCustomAlt = forceOpen;
      } else {
        isCustomAlt = !isCustomAlt;
      }

      if (isCustomAlt) {
        inputs.classList.add('active');
      } else {
        inputs.classList.remove('active');
      }
    }

    async function executeSimulation() {
      if (!currentSelectedTarget) {
        alert('Please choose a component to replace first.');
        return;
      }

      let substitute = null;
      const altIdx = document.getElementById('simAltSelect').value;

      if (!isCustomAlt && altIdx !== "" && currentAlternatives[altIdx]) {
        const alt = currentAlternatives[altIdx];
        substitute = {
          component_name: alt.component_name,
          vendor: alt.vendor,
          version: alt.version,
          origin_country: alt.origin_country || 'US',
          part_number: alt.part_number || '',
        };
      } else {
        // Read custom input fields
        const cName = document.getElementById('simCustomName').value.trim();
        const cVendor = document.getElementById('simCustomVendor').value.trim();
        const cVersion = document.getElementById('simCustomVersion').value.trim();
        const cOrigin = document.getElementById('simCustomOrigin').value.trim() || 'US';
        const cPart = document.getElementById('simCustomPart').value.trim();

        if (!cName || !cVendor || !cVersion) {
          alert('Please provide component name, vendor, and version for custom replacement.');
          return;
        }

        substitute = {
          component_name: cName,
          vendor: cVendor,
          version: cVersion,
          origin_country: cOrigin,
          part_number: cPart,
        };
      }

      const runBtn = document.getElementById('runSimulationBtn');
      runBtn.textContent = 'Simulating...';
      runBtn.disabled = true;

      try {
        const payload = {
          run_id: currentRunId,
          target: {
            component_name: currentSelectedTarget.component_name,
            vendor: currentSelectedTarget.vendor,
            version: currentSelectedTarget.version,
          },
          substitute: substitute,
          scope: 'all_instances',
        };

        const resp = await fetch('/api/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const data = await resp.json();
        if (!resp.ok) {
          throw new Error(data.error || 'Simulation failed');
        }

        renderSimulationResults(data);
      } catch (err) {
        alert('Simulation error: ' + err.message);
      } finally {
        runBtn.textContent = '⚡ Run What-If Simulation';
        runBtn.disabled = false;
      }
    }

    function renderSimulationResults(data) {
      const box = document.getElementById('simResultsBox');
      box.classList.add('active');

      const overall = data.overall;
      const target = data.target;
      const sub = data.substitute;
      const dim = data.dimension_changes;

      // Overall BOM score
      const bScore = overall.before_score !== null ? overall.before_score : '--';
      const aScore = overall.after_score !== null ? overall.after_score : '--';
      document.getElementById('simKpiBOMScore').textContent = `${bScore} ➔ ${aScore}`;

      const delta = overall.delta_score;
      const deltaEl = document.getElementById('simKpiBOMDelta');
      if (delta < 0) {
        deltaEl.textContent = `▼ ${Math.abs(delta)} pts (${overall.percent_reduction}% reduction)`;
        deltaEl.style.color = 'var(--success)';
      } else if (delta > 0) {
        deltaEl.textContent = `▲ +${delta} pts (increased risk)`;
        deltaEl.style.color = 'var(--danger)';
      } else {
        deltaEl.textContent = `No change in BOM aggregate score`;
        deltaEl.style.color = 'var(--text-muted)';
      }

      // Component Score
      const tScore = target.risk_score !== null ? target.risk_score : 'N/A';
      const sScore = sub.risk_score !== null ? sub.risk_score : 'Unscored';
      document.getElementById('simKpiCompScore').textContent = `${tScore} ➔ ${sScore}`;
      
      const compDeltaEl = document.getElementById('simKpiCompDelta');
      if (target.risk_score !== null && sub.risk_score !== null) {
        const cDelta = Math.round((sub.risk_score - target.risk_score) * 10) / 10;
        compDeltaEl.textContent = cDelta <= 0 ? `${cDelta} pts` : `+${cDelta} pts`;
        compDeltaEl.style.color = cDelta < 0 ? 'var(--success)' : (cDelta > 0 ? 'var(--danger)' : 'var(--text-muted)');
      } else {
        compDeltaEl.textContent = 'Manual review required';
        compDeltaEl.style.color = 'var(--warning)';
      }

      // CVEs
      const cveDelta = dim.cve_delta;
      const cveVal = document.getElementById('simKpiCves');
      cveVal.textContent = cveDelta < 0 ? `${cveDelta} CVEs` : (cveDelta > 0 ? `+${cveDelta} CVEs` : `0 CVE change`);
      cveVal.style.color = cveDelta < 0 ? 'var(--success)' : (cveDelta > 0 ? 'var(--danger)' : 'var(--text-muted)');
      document.getElementById('simKpiCveDetail').textContent = `Max CVSS: ${target.highest_cvss} ➔ ${sub.highest_cvss}`;

      // Policy & Lifecycle
      const polDelta = dim.policy_flag_delta;
      const lifeDelta = dim.lifecycle_flag_delta;
      const polVal = document.getElementById('simKpiPolicy');
      if (polDelta < 0) {
        polVal.textContent = 'Policy Cleared';
        polVal.style.color = 'var(--success)';
      } else if (polDelta > 0) {
        polVal.textContent = 'Policy Hit!';
        polVal.style.color = 'var(--danger)';
      } else {
        polVal.textContent = lifeDelta < 0 ? 'Lifecycle Cleared' : (lifeDelta > 0 ? 'Lifecycle Added' : 'No Policy Changes');
        polVal.style.color = lifeDelta < 0 ? 'var(--success)' : 'var(--text-muted)';
      }
      document.getElementById('simKpiPolicyDetail').textContent = `Policy flags: ${polDelta >= 0 ? '+' : ''}${polDelta}, Lifecycle: ${lifeDelta >= 0 ? '+' : ''}${lifeDelta}`;

      // Explanation
      document.getElementById('simExplanationText').textContent = data.explanation;
      box.scrollIntoView({ behavior: 'smooth' });
    }

    // Listen for postMessage from report iframe
    window.addEventListener('message', (event) => {
      if (event.data && event.data.type === 'OPEN_WHAT_IF_SIMULATOR') {
        openSimulatorModal(event.data.component, event.data.vendor, event.data.version);
      }
    });
  </script>
</body>
</html>
"""


class BOMServerHandler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            content = HTML_PAGE.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if path.startswith("/api/samples/"):
            sample_key = path.replace("/api/samples/", "").strip().lower()
            if sample_key not in SAMPLES:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown sample '{sample_key}'. Available: {list(SAMPLES.keys())}"})
                return

            sample_file = SAMPLES[sample_key]
            params = urllib.parse.parse_qs(parsed.query)
            clean_csv = params.get("clean", ["true"])[0].lower() in ("1", "true", "yes")

            try:
                summary, _report, _dir = process_bom_file(
                    sample_file,
                    sample_file.name,
                    clean_csv=clean_csv,
                )
                self.send_json(HTTPStatus.OK, summary)
            except Exception as e:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(e)})
            return

        if path == "/api/alternatives":
            params = urllib.parse.parse_qs(parsed.query)
            c_name = params.get("component", [""])[0]
            c_vendor = params.get("vendor", [""])[0]

            alts_catalog = load_alternatives(ALTERNATIVES_PATH)
            options = find_alternatives_for(c_name, c_vendor, alts_catalog)
            self.send_json(HTTPStatus.OK, {
                "component_name": c_name,
                "vendor": c_vendor,
                "options": options,
                "has_vetted_alternatives": len(options) > 0,
            })
            return

        if path.startswith("/reports/"):
            # Serve files under UPLOADS_DIR
            relative = path.replace("/reports/", "", 1)
            target = (UPLOADS_DIR / relative).resolve()
            if not str(target).startswith(str(UPLOADS_DIR)) or not target.is_file():
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()
                return

            mime_type, _ = mimetypes.guess_type(str(target))
            mime_type = mime_type or "application/octet-stream"
            with open(target, "rb") as f:
                content = f.read()

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", f"{mime_type}; charset=utf-8" if "text" in mime_type or "json" in mime_type else mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/simulate":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Empty simulation request payload."})
                return

            try:
                body = json.loads(self.rfile.read(content_length).decode("utf-8"))
            except Exception as e:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON payload: {e}"})
                return

            run_id = body.get("run_id")
            target = body.get("target")
            substitute = body.get("substitute")
            scope = body.get("scope", "all_instances")

            if not target or not substitute:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing 'target' or 'substitute' in simulation payload."})
                return

            # Determine components source: run_id directory or default sample BOM
            components = None
            if run_id:
                run_dir = UPLOADS_DIR / run_id
                comp_file = run_dir / "components.json"
                if comp_file.exists():
                    try:
                        with open(comp_file, encoding="utf-8") as f:
                            components = json.load(f)
                    except Exception:
                        components = None
                if components is None:
                    # Fallback to finding any CSV or JSON BOM in run_dir
                    for f_cand in run_dir.iterdir():
                        if f_cand.suffix.lower() in (".csv", ".json") and f_cand.name != "report.json":
                            try:
                                components, _ = parse_bom(f_cand)
                                break
                            except Exception:
                                pass

            if components is None:
                # Fallback to sample_bom.csv
                components, _ = parse_bom(SAMPLES["csv"])

            try:
                cve_entries = load_cve_database(CVE_DB_PATH)
                rules = load_rules(RULES_PATH)
                result = run_simulation(
                    original_components=components,
                    target_component=target,
                    substitute_component=substitute,
                    cve_entries=cve_entries,
                    rules=rules,
                    scope=scope,
                )
                self.send_json(HTTPStatus.OK, result)
            except Exception as e:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(e)})
            return
        if parsed.path == "/api/upload":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Empty upload request body."})
                return

            content_type = self.headers.get("Content-Type", "")
            raw_body = self.rfile.read(content_length)

            filename = None
            file_bytes = None

            # 1. Check for custom X-Filename header (direct binary upload from JS fetch)
            x_filename = self.headers.get("X-Filename")
            if x_filename:
                filename = urllib.parse.unquote(x_filename)
                file_bytes = raw_body
                clean_csv = self.headers.get("X-Clean-Csv", "true").lower() in ("1", "true", "yes")
            elif "multipart/form-data" in content_type:
                # 2. Handle multipart form uploads
                msg = email.message_from_bytes(
                    f"Content-Type: {content_type}\r\n\r\n".encode("utf-8") + raw_body,
                    policy=email.policy.default,
                )
                clean_csv = True
                for part in msg.iter_parts():
                    cd = part.get("Content-Disposition", "")
                    if 'name="clean"' in cd:
                        clean_csv = part.get_payload(decode=True).decode().strip().lower() in ("1", "true", "yes")
                    if 'name="file"' in cd or 'name="bom"' in cd or part.get_filename():
                        filename = part.get_filename() or "uploaded_bom.json"
                        file_bytes = part.get_payload(decode=True)

            if not filename or file_bytes is None:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "No BOM file attached or filename missing."})
                return

            clean_filename = re.sub(r"[^\w\.-]", "_", Path(filename).name)
            temp_path = UPLOADS_DIR / f"temp_{uuid4().hex[:8]}_{clean_filename}"
            try:
                with open(temp_path, "wb") as f:
                    f.write(file_bytes)

                summary, _report, _dir = process_bom_file(
                    temp_path,
                    clean_filename,
                    clean_csv=clean_csv,
                )
                self.send_json(HTTPStatus.OK, summary)
            except Exception as e:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(e)})
            finally:
                if temp_path.exists():
                    temp_path.unlink()
            return

        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()


def run_server(port=8080, open_browser=True):
    # Try requested port or increment if busy
    server_address = ("", port)
    for p in range(port, port + 10):
        try:
            httpd = HTTPServer(("", p), BOMServerHandler)
            port = p
            break
        except OSError:
            continue
    else:
        raise RuntimeError(f"Could not bind server to ports in range {port}-{port+10}")

    url = f"http://localhost:{port}"
    print(f"\n" + "=" * 60)
    print(f"🚀 Supply Chain Risk Scoring Web Server running at:")
    print(f"   {url}")
    print(f"=" * 60)
    print(f"Upload BOMs (CycloneDX JSON or CSV) directly in your browser.")
    print(f"Press Ctrl+C to stop the server.\n")

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run BOM Ingestion & Risk Scoring Web Interface")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the browser")
    args = parser.parse_args()

    run_server(port=args.port, open_browser=not args.no_browser)
