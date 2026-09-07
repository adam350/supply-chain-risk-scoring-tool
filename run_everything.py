#!/usr/bin/env python3
"""
run_everything.py

Click Run (the ▷ button) on THIS file in VS Code to run the whole demo in
one go - no terminal, no arguments needed. It runs, in order:
  1. Cleans the messy 4-node BOM (data/raw_bom_large.csv)
  2. Scores the cleaned BOM

Everything lands in one folder: output/
  - output/cleaning_report.html  <- what was filtered out and why
  - output/report.html           <- the risk findings report
  - output/cleaned_bom.csv       <- the cleaned data (intermediate)
  - output/report.json           <- structured output for the frontend teammate

Only two HTML files to look at, one folder - kept deliberately simple since
the PDF submission has a size/screenshot limit.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

import clean_bom
import main as scoring_main

BASE = Path(__file__).parent
OUT = BASE / "output"


def section(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


if __name__ == "__main__":
    section("STEP 1/2 — Cleaning the messy 4-node BOM")
    cleaned_path = clean_bom.run(BASE / "data" / "raw_bom_large.csv", OUT)

    section("STEP 2/2 — Scoring the cleaned BOM")
    scoring_main.run(cleaned_path, OUT, BASE / "data" / "cve_database.json", BASE / "data" / "rules.json")

    section("DONE — open these two in your browser")
    print(f"  {OUT / 'cleaning_report.html'}")
    print(f"  {OUT / 'report.html'}")

