# Supply Chain Risk Scoring Tool (Software-Only Prototype)

Scores an AI server bill-of-materials (BOM) for supply-chain risk across three
dimensions: known CVEs, restricted vendor/country-of-origin, and component
lifecycle (EOL / single-source). Outputs exactly two reports: a cleaning
report and a risk findings report — kept deliberately minimal since the PDF
submission has a size limit.

## Running this in VS Code (no terminal needed)

1. **Open the `scrisk` folder itself in VS Code** — File → Open Folder → select
   this `scrisk` folder (not its parent). This matters: it makes VS Code treat
   `scrisk` as the project root, which is what makes the file paths below work.
2. If VS Code asks to install the **Python extension**, install it (one-time).
3. Open `run_everything.py` and click the **▷ Run** button (top-right corner,
   or right-click the file → "Run Python File"). That's it — it cleans the
   demo BOM, scores it, and prints the paths to both reports at the end.
4. To open a report: find it in the VS Code file explorer under `output/`,
   right-click → **Reveal in File Explorer / Finder**, then double-click it to
   open in your browser. (VS Code can preview HTML too, but it's more reliable
   to open reports in an actual browser.)

**Want to run just one step?** Open the **Run and Debug** panel (▷ icon with
a bug, left sidebar), use the dropdown at the top to pick "1. Clean the BOM
only" or "2. Score the BOM only", and click the green ▷ play arrow. No typing
required.

## Running from a terminal instead

Requires Python 3.8+, no external packages (standard library only).

```bash
python clean_bom.py     # Step 1 — cleans data/raw_bom_large.csv -> output/
python main.py           # Step 2 — scores output/cleaned_bom.csv -> output/
```

Both scripts work with **no arguments** — they default to the demo BOM and
the shared `output/` folder. Then open, in your browser:

- `output/cleaning_report.html` — what was filtered out of the raw BOM and why
- `output/report.html` — the risk findings report

## Project layout

```
scrisk/
├── .vscode/
│   └── launch.json        <- VS Code run presets (Run and Debug panel)
├── run_everything.py       <- click Run on this for the full demo, one click
├── main.py                 <- scores a BOM (step 2)
├── clean_bom.py             <- cleans a raw BOM first (step 1)
├── data/                   <- sample data (see below)
├── src/                    <- pipeline code, not run directly
└── output/                 <- BOTH reports land here, nothing else
    ├── cleaning_report.html
    ├── cleaned_bom.csv      (intermediate data, not a report)
    ├── report.html
    └── report.json          (for the frontend teammate)
```

## What's in `data/`

- `raw_bom_large.csv` — the default input. A **realistically messy** 4-node
  server rack BOM (60 real component rows + deliberately injected junk: a
  blank row, a placeholder "TBD" row, an accidental exact duplicate, an
  accidentally re-pasted header row, mixed-case vendor names, full country
  names instead of ISO codes).
- `sample_bom.csv` / `sample_bom_cyclonedx.json` — smaller, already-clean
  alternative BOMs. Not run by default; pass `--bom data/sample_bom_cyclonedx.json`
  to `main.py` if you want to demonstrate the other supported format (skip
  `clean_bom.py` for these — they're already clean).

## What it does

1. **Cleans the raw BOM** — strips blank/junk/placeholder/duplicate rows out
   *before* they ever reach scoring, and normalizes country names to ISO
   codes. Produces a separate cleaning report so nothing is silently dropped
   without a visible reason.
2. Parses the cleaned BOM (CSV or CycloneDX JSON) into a normalized
   component list.
3. Matches each component against a local CVE dataset (exact + fuzzy) —
   including **real, verified CVEs** for actual BMC firmware vulnerabilities
   (clearly labeled `real` vs `simulated` per entry — see `REFERENCES.md`).
4. Checks each component against restricted-vendor/country rules and
   lifecycle data (EOL, single-source).
5. Produces a per-component risk score with a full breakdown, plus one
   aggregate score for the whole BOM. Identical components across multiple
   physical units (e.g. 4 server nodes) are grouped into one finding showing
   which units are affected, instead of repeating the same row 4 times.
6. Surfaces components with no matching data as "unscored / needs manual
   review" rather than assuming they're safe.

See `DOCUMENTATION_NOTES.md` for the full design rationale, written for the
teammates producing the write-up/PDF submission — it maps directly to the
judging rubric. See `REFERENCES.md` for every citation and dataset
disclosure — nothing there is a placeholder.

## Editing the rules or CVE data

`data/rules.json` and `data/cve_database.json` are plain JSON — no code
changes needed to add a restricted vendor, update an EOL date, or add a CVE
entry.

## For the frontend teammate

`output/report.json` has the full structured output — findings, scores,
breakdowns, affected units, unscored components — everything needed to build
a real UI against, without touching the scoring logic.
