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

UPLOADS_DIR = BASE_DIR / "output" / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

CVE_DB_PATH = BASE_DIR / "data" / "cve_database.json"
RULES_PATH = BASE_DIR / "data" / "rules.json"

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
            <a id="cleanReportLink" href="#" target="_blank" class="btn btn-secondary" style="display: none; font-size: 13px; padding: 6px 14px;">View Cleaning Report</a>
            <a id="downloadJsonBtn" href="#" target="_blank" class="btn btn-secondary" style="font-size: 13px; padding: 6px 14px;">Download JSON</a>
            <a id="openTabBtn" href="#" target="_blank" class="btn" style="font-size: 13px; padding: 6px 14px;">Open Full Report ↗</a>
          </div>
        </div>
        <iframe id="reportFrame" class="report-frame" src="about:blank"></iframe>
      </div>
    </section>
  </main>

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
    }
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
