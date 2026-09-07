#!/usr/bin/env python3
"""
clean_bom.py - BOM cleaning stage (run this BEFORE main.py on a raw/messy BOM)

Usage:
    python clean_bom.py --bom data/raw_bom_large.csv --out output/clean_run

Running with no arguments (e.g. clicking the Run button in VS Code) cleans
the large messy demo BOM by default - see --bom/--out defaults below.

Produces:
    output/clean_run/cleaned_bom.csv       <- feed this into main.py
    output/clean_run/cleaning_report.html  <- what was removed/corrected and why

Why this is a separate step from main.py rather than baked in silently:
you should be able to SEE what got filtered out and why before it
disappears, rather than trusting a black box to have made the right call
on every row. Open cleaning_report.html, skim the "removed" table, and
confirm nothing that should have been kept got thrown out.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from bom_cleaner import clean_bom_csv, write_cleaned_csv, render_cleaning_report_html


def run(bom_path, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cleaned_rows, cleaning_log = clean_bom_csv(bom_path)

    cleaned_csv_path = out_dir / "cleaned_bom.csv"
    report_html_path = out_dir / "cleaning_report.html"
    write_cleaned_csv(cleaned_rows, cleaned_csv_path)
    render_cleaning_report_html(bom_path, cleaned_rows, cleaning_log, report_html_path)

    removed = sum(1 for e in cleaning_log if e["action"] == "removed")
    corrected = sum(1 for e in cleaning_log if e["action"] == "corrected")
    print(f"Read raw BOM: {bom_path}")
    print(f"Removed {removed} junk/duplicate/blank rows.")
    print(f"Corrected {corrected} rows (e.g. country name normalization).")
    print(f"Clean rows ready for scoring: {len(cleaned_rows)}")
    print(f"Cleaned BOM      -> {cleaned_csv_path}")
    print(f"Cleaning report  -> {report_html_path}")
    print(f"\nNext step: python main.py --bom {cleaned_csv_path} --out output/<run_name>")
    return cleaned_csv_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clean a raw BOM before scoring")
    parser.add_argument("--bom", default="data/raw_bom_large.csv", help="Path to raw/messy BOM CSV")
    parser.add_argument("--out", default="output", help="Output directory")
    args = parser.parse_args()
    run(args.bom, args.out)
