# Supply Chain Risk Scoring Tool — Documentation Notes for Write-Up

This file is written for the teammates producing the PDF submission. It's organized
around the jury's scoring rubric so each section can be lifted almost directly into
the corresponding part of the write-up. Where something is a design decision, the
justification is included — that's the part that answers "why did you build it this
way" if asked live.

**Read `REFERENCES.md` alongside this file.** Every factual claim below that needs a
citation is sourced there with a real, verified URL — nothing in that file is a
placeholder or invented reference. It also contains the mandatory disclosure that our
CVE dataset and parts of our rules dataset are self-built sample data, not live data
pulled from NVD/BIS/OFAC — that disclosure needs to make it into the submission,
stated plainly, not buried in a footnote.

---

## 1. Fit to the brief and the business problem (20%)

**The problem, restated in business terms:** AI infrastructure is assembled from
globally-sourced hardware and firmware. Risk (a known vulnerability, a sanctioned
vendor, an end-of-life component with no patches) enters at the procurement stage —
before any network exists to attack. Today this check is manual or doesn't happen:
procurement teams buy against a spec sheet, not a risk profile.

**Who buys/deploys this:** procurement and security teams at any organization
standing up AI server infrastructure — the people who approve a purchase order,
not the people who later monitor the running network.

**What it replaces:** an ad-hoc or nonexistent process — someone manually
cross-referencing a vendor list against CVE databases, if it happens at all. This
tool turns that into a repeatable, auditable step in the procurement workflow: upload
the bill of materials, get a ranked risk report with a clear buy/hold/reject signal
per component.

**Screenshot to capture:** the report summary block (aggregate score + verdict) —
this is the single image that answers "what does this tool do" in one glance.

---

## 2. Relevance of the proposed solution (15%)

**Why this approach, not the one from three years ago:** BOM-based supply chain
risk scoring extends a real, live standardization trend — CycloneDX (OWASP,
now also published as the Ecma International standard ECMA-424) and SPDX
(Linux Foundation, ISO/IEC 5962:2021) became standard formats for software
supply chain security largely off the back of the 2021 U.S. Executive Order
14028 push for software transparency. Hardware/firmware BOM risk is
comparatively underserved by comparison. Rather than inventing a new format,
this tool ingests the two formats real procurement/security tooling already
produces (CycloneDX JSON, plain CSV) — so it plugs into an existing workflow
instead of requiring a new one.

**Accuracy note for the write-up:** don't overstate this as "SBOMs are
currently mandated by federal law" — EO 14028 itself is still in effect, but
the specific OMB memos that mandated SBOMs government-wide were rescinded in
2026 in favor of a discretionary, risk-based approach (OMB M-26-05). The
accurate framing is "this built the standardization and tooling landscape we
build on," not "this is a live legal mandate." Full citations and the exact
nuance are in `REFERENCES.md` §3.

**Why now:** CVE databases (NVD) and export-control/entity-list data are both
structured, machine-readable, and continuously updated via public APIs — the
NVD API 2.0 (services.nvd.nist.gov) and the BIS Entity List (downloadable as
CSV) both exist as live, queryable sources today. Automating this check at
the component/firmware level didn't reliably have this data infrastructure
behind it a few years ago; most existing SCA (software composition analysis)
tooling focused on software dependencies, not physical/firmware BOMs.

---

## 3. Does the prototype work (25%)

This is graded on: does it run end-to-end from the README, does the demo scenario
complete, does it survive a second run and unexpected input.

**What was verified, concretely:**
- Ran end-to-end on both supported input formats (CSV and CycloneDX JSON) via a
  single command (`python main.py --bom <file> --out <dir>`), no manual setup step
  beyond having Python 3 installed.
- Ran twice in a row on the same input — deterministic, same output both times
  (no hidden state, no crash on re-run).
- Fed it a deliberately broken CSV (a row with a missing component name, a row
  with a missing vendor, a row with a missing version) — it skipped only the bad
  rows, logged them as ingestion errors in the report, and successfully scored
  the valid row. It did not crash and did not silently drop the error.

**Demo scenario (matches the brief's required demo):** `data/sample_bom.csv` is a
realistic AI server BOM. Running it produces:
- **4 vulnerable firmware components correctly flagged** with real-shaped CVE
  detail (BMC Firmware, UEFI Firmware, NIC Firmware, RAID Controller Firmware —
  more than the brief's minimum of two, to show the matching isn't hand-tuned to
  a single example).
- **1 restricted-vendor component correctly flagged** (a component sourced from
  Hikvision, which is on the restricted-vendor list) — and importantly, flagged
  as "DO NOT BUY" regardless of its numeric CVE score, because a compliance/policy
  hit is treated as a hard stop, not just a score input (see §4 for why).
- **1 genuinely unknown component** (`Custom Sensor Board`, an invented vendor
  with no CVE or policy data) correctly surfaced in a separate "needs manual
  review" section — not silently scored as safe.
- **8 components with no matching data** (CPU, GPU, memory, etc.) also correctly
  land in the "unscored" section rather than being assigned a false score of 0.

**Screenshots to capture:**
1. Terminal output of the run command (shows it runs end-to-end from the README).
2. The HTML report's summary block.
3. The findings table showing the ranked vulnerable components with their CVE
   detail expanded.
4. The "unscored/unknown" table at the bottom of the report.

---

## 4. Technical depth and correctness (25%)

This is the section most likely to get probed with follow-up questions, so the
reasoning behind each choice is documented, not just the choice itself.

### 4.1 Three risk dimensions (brief requires at least three)
1. **Known vulnerabilities** — matched against a local CVE dataset (structured to
   mirror NVD's schema: CVE ID, CVSS base score, severity, affected version
   ranges). *Design note:* in a production version this dataset is a locally
   synced copy of the NVD feed, refreshed on a schedule — not queried live per
   request — so the tool works offline and isn't rate-limited during a scoring
   run. The prototype uses a small hand-built dataset with the same shape so this
   swap is a data-source change, not an architecture change.
2. **Country-of-origin / restricted-vendor rules** — checked against an editable
   JSON rules file (restricted countries, restricted/entity-listed vendors). Kept
   out of the code deliberately so a security/procurement team can update the
   list without a code change or redeploy.
3. **Component-level lifecycle factors** — end-of-life status and single-source
   dependency flags, also in the editable rules file.

### 4.2 Matching strategy (this is the part most likely to get a "how does this
actually work" question)
- **Exact match:** component name + vendor match a CVE entry exactly, and the
  component's version falls inside the entry's affected-version range.
- **Fuzzy match:** if no exact match, a similarity ratio (Python's `difflib`,
  threshold 0.82) is computed between the component's name+vendor and each CVE
  entry's name+vendor. This catches near-matches from inconsistent naming
  (e.g. "NIC Firmware" vs "Network Interface Firmware") without being so loose
  that unrelated components start matching each other.
- **Confidence scaling:** a fuzzy match's contribution to the risk score is
  multiplied by its similarity ratio — an uncertain match can never produce as
  high a score as a confirmed exact match. This is a deliberate, statable
  design decision if asked "why isn't a fuzzy match scored the same as an exact
  one."
- **Known limitation, stated honestly rather than hidden:** the threshold is a
  judgment call. In testing, `TPM Module / Nuvoton / 1.3.2` did **not** match
  `TPM Firmware / Nuvoton` in the CVE dataset (ratio 0.737, below the 0.82
  threshold) purely due to "Module" vs "Firmware" naming — a real limitation of
  name-based fuzzy matching, and a good example of why unmatched components are
  surfaced for manual review rather than assumed safe.

### 4.3 Scoring formula (fully explainable, not a black box)
Per component: `score = CVE_term + vendor_origin_term + lifecycle_term` (capped
at 100).
- **CVE term (max 60 pts):** `(highest matched CVSS score / 10) × 60 ×
  match_confidence`. CVE severity is weighted heaviest because it's the most
  concrete, independently-verifiable signal (a published CVSS score), versus a
  policy or lifecycle judgment call.
- **Vendor/origin term (25 pts, fixed if any flag hits):** treated as
  near-binary because a restricted-vendor/country hit is a compliance failure,
  not a graded severity — but capped so it alone can't outweigh a critical CVE.
- **Lifecycle term (max 15 pts, 7.5 per flag):** the softest signal — EOL status
  and single-source dependency indicate elevated *future* risk, not a current
  exploit path, so they're weighted lowest.

**Aggregate BOM score** is `0.6 × (highest single component score) + 0.4 ×
(mean of scored components)` — weighted toward the worst offender rather than a
flat average, because one critical component (e.g. a compromised BMC) can
compromise an entire server regardless of how clean the rest of the BOM is.
Unscored/unknown components are excluded from this number entirely (see §4.4) —
counted separately, never treated as a 0 ("safe").

### 4.4 Handling the "unknown" case (the brief calls this out explicitly)
A component is only marked **unscored** if it has *no* CVE match (exact or
fuzzy) *and no* policy/lifecycle flag — i.e. there is genuinely nothing in the
tool's data to make a call on. It is reported in a distinct section with an
explicit "manual review required" action, and excluded from the numeric
aggregate. This was a deliberate design decision: an unmatched component
defaulting to a score of 0 would be indistinguishable from a component that was
actually checked and found clean — which is the exact failure mode the brief
warns against.

### 4.5 Policy hard-stop overriding numeric score
One correction made during testing, worth including as evidence of validation:
a restricted-vendor component (Hikvision, scored 25/100 on the numeric scale)
initially rendered as "SAFE TO BUY" because 25 falls under the numeric safety
threshold. This was caught and fixed — a policy/compliance flag now forces a
"DO NOT BUY" verdict regardless of numeric score, because a sanctioned or
entity-listed vendor is not a "moderate risk," it's a compliance failure that a
procurement team cannot approve around. This is a good talking point for "did
you test this yourselves" — it shows the scoring wasn't just written once and
trusted, it was checked against a scenario where the numeric shortcut would have
given the wrong real-world answer.

### 4.6 Resilience
Malformed CSV rows (missing required fields) are individually skipped and
logged as ingestion errors rather than aborting the whole batch — a
"single bad row shouldn't sink a 200-component BOM" design choice, verified by
testing against a file with missing component names, missing vendors, and
missing versions in the same run.

**Screenshot to capture:** the score breakdown detail for one flagged component
(shows the CVE term / vendor term / lifecycle term split), and the terminal
output from the malformed-input test if you want to show resilience explicitly.

---

### 4.7 Data cleaning stage (added after initial testing, on request)
A real BOM is never as clean as a demo file — blank rows, placeholder values
("TBD", "N/A"), accidental duplicate entries, and inconsistent formatting
(full country names instead of ISO codes, mixed casing) are normal in
human-edited spreadsheets. `clean_bom.py` runs as an explicit stage *before*
`main.py` and:
- Removes fully blank rows, placeholder/junk values, and true accidental
  duplicates (same component, same physical unit, listed twice by mistake).
- Normalizes common full country names to ISO-2 codes.
- Produces a separate `cleaning_report.html` listing exactly what was removed
  and why — so nothing disappears silently.

**This is deliberately a different problem from "unknown component
handling" (§4.4).** A junk row (blank, "TBD", a duplicate) isn't a real
component at all — it should never reach the risk report, not even as
"unscored." A row that IS a real component but has no matching CVE/policy/
lifecycle data is genuinely unknown and *should* show up as "needs manual
review" — conflating the two would either hide real data-quality problems
inside the risk report, or bury genuine "we don't know" findings where a
security reviewer wouldn't think to look.

Tested against `data/raw_bom_large.csv` — a 4-node server rack BOM (65 raw
rows) with a blank row, a "TBD" placeholder row, an accidental exact
duplicate, an accidentally re-pasted header row, and mixed-case/full-name
country values injected on purpose. The cleaner correctly caught and removed
all 5 junk rows and correctly normalized all 14 non-ISO country values,
leaving 60 clean rows for scoring — verified by inspecting the cleaning log
directly, not just trusting the row count.

### 4.8 Multi-unit grouping (fleet-scale readability)
The large BOM models 4 identical server nodes. Rather than reporting the
same vulnerable BMC firmware as 4 separate near-identical rows, the report
groups identical findings (same component/vendor/version) across units and
shows which units are affected (e.g. "BMC Firmware — affects NODE-01,
NODE-02, NODE-03, NODE-04"). This also correctly demonstrated real
discrimination during testing: one node (NODE-04) had a patched UEFI
firmware version (6.0) that the other three didn't (5.19) — the tool
correctly scored NODE-04's UEFI at 7.5 (clean) versus 56.7 for the other
three (still vulnerable), rather than treating the whole fleet as uniformly
risky. That's a genuinely meaningful result to show live: it proves the
matching is version-specific, not just component-name-specific.

### 4.9 Real vs. simulated CVE data — upgraded after initial build
The original prototype used entirely fabricated CVE entries. Since accuracy
matters for the submission, three entries were replaced with **real,
verified CVEs** for actual server BMC firmware vulnerabilities:
- **CVE-2019-6260 ("Pantsdown")** — a real, widely-documented vulnerability
  in Aspeed AST2400/AST2500 BMC chips, affecting numerous OEMs including
  Supermicro, Gigabyte, IBM, and HPE.
- **CVE-2023-34329 and CVE-2023-34330** — real vulnerabilities in AMI
  MegaRAC BMC firmware (the "BMC&C" vulnerability set), disclosed by
  Eclypsium, with real CVSS scores (9.1 and 8.2).

Every entry in `cve_database.json` now carries a `provenance` field
(`"real"` or `"simulated"`) and, for real entries, a `source_url` you can
open and verify yourself. The remaining entries (NIC/RAID/UEFI/TPM/
Bootloader/PCIe categories) are still simulated — a real public CVE with a
convenient exact match wasn't found for those specific component/vendor
pairings during the research for this prototype, and they're labeled as
such rather than presented as real. Full details and links in
`REFERENCES.md` §1-2.

### 4.10 What-If Supply Chain Simulator (interactive mitigation modeling)
Added to enable procurement and security analysts to simulate replacing a risky
component with a vetted alternative and immediately observe how that hypothetical
replacement changes component-level and overall BOM risk:
- **Non-mutating hypothetical clone**: The uploaded or parsed BOM data is deep-copied
  in memory (`copy.deepcopy`), ensuring baseline reports and audit records are never
  mutated by hypothetical scenarios.
- **Engine reuse, zero logic duplication**: The simulation calls the exact same
  `match_component`, `apply_rules`, `score_component`, and `score_bom` functions
  used in the primary ingestion pipeline.
- **Explainable delta calculations**: The simulator outputs both component-level
  and BOM-level deltas, percentage reductions, changes in CVE exposure, policy
  flag resolutions (e.g. replacing a restricted vendor with a TAA/NDAA compliant
  alternative), and generates a plain-English explanation of why the score shifted.
- **Unknowns remain unverified**: If a user tests an unrecognized replacement,
  the component is tracked as unscored and excluded from the numeric score rather
  than falsely assuming 0 risk.
- **Fleet-wide multi-node application**: In a multi-node rack BOM, replacing a
  component applies across all affected nodes to simulate fleet procurement swaps.

## 5. Innovation (15%)

Brief note: innovation is not complexity — a simpler solution that does the job
better is not a mark against. These are the non-obvious choices in this
prototype, kept deliberately simple, with real backing rather than assertion
(full citations in `REFERENCES.md` §7):

- **Explainable scoring, not a single black-box number.** Every score shows its
  three contributing terms. This is a genuine design choice justified by the
  brief's own "technical depth and correctness" criterion — not attributed to
  an external standard, because no such standard was found for this exact
  combination (see `REFERENCES.md` §6). Many teams tackling this brief will
  likely output a single risk number without a breakdown; this is a real
  point of differentiation, honestly labeled as our own design choice rather
  than borrowed authority.
- **Policy flag as a hard stop, not a score input** — a restricted-vendor hit
  forces "DO NOT BUY" regardless of numeric CVE score. This isn't an arbitrary
  choice: it mirrors how U.S. federal procurement actually treats a
  Section 889-covered vendor under FAR 52.204-25 — a flat prohibition, not a
  severity-weighted judgment call. Citing real procurement law here, not just
  "it seemed right," is what makes this defensible under questioning.
- **Component-specific mitigation suggestions**, not a generic "review this."
  Different flag types (CVE, policy, lifecycle) get different, relevant
  advice rather than one templated warning.
- **Confidence-aware fuzzy matching** rather than exact-match-only (which
  would miss real-world naming inconsistencies) or unbounded fuzzy matching
  (which would produce false positives) — built on Python's standard
  `difflib.SequenceMatcher`, with the confidence scaling as our own addition
  on top of it.

**Two legitimate, citable extensions to name as "future work" — not built, and
labeled honestly as unbuilt rather than implied to already exist:**
- **EPSS (Exploit Prediction Scoring System)**, published by FIRST.org
  alongside CVSS, estimates the probability a specific CVE is *actually*
  exploited in the wild within 30 days — a real, queryable complement to
  CVSS's severity-only view. A production version could combine "high
  severity" (CVSS) with "likely to be exploited" (EPSS) to prioritize far
  better than severity alone.
- **CISA's Known Exploited Vulnerabilities (KEV) catalog** — a real, actively
  maintained U.S. government list of CVEs with confirmed real-world
  exploitation. A production version could flag any matched CVE that also
  appears on KEV as automatic maximum priority.

Both are real, citable, currently-maintained systems (URLs in
`REFERENCES.md` §7) — naming them as future work is a stronger answer to "how
would this actually get better" than inventing a mechanism, and is honest
about what was and wasn't built for this submission.

---

## 6. Known limitations (state these proactively — it reads as rigor, not weakness)

- CVE dataset and rules file are hand-built sample data for the prototype, not
  a live NVD sync — documented in-code (`_source_note` fields in both JSON
  files) as the swap point for a production version.
- Version-range matching only supports simple `<=X` / exact patterns, not full
  semver ranges — noted in `cve_matcher.py` as a deliberate scope cut.
- Fuzzy-match threshold (0.82) is a manually chosen value, not tuned against a
  labeled dataset — the TPM Module/TPM Firmware miss (§4.3) is direct evidence
  of this limitation and is worth mentioning if asked about matching accuracy.
- No persistence between runs (no scan history) — each run is independent, which
  is why the "drift over time" idea in §5 is future work, not implemented.

---

## 7. How to run it (for the screenshots section)

```bash
cd scrisk
python main.py --bom data/sample_bom.csv --out output/csv_run
python main.py --bom data/sample_bom_cyclonedx.json --out output/cyclonedx_run
```

Outputs land in `output/<run_name>/report.json` (for the teammate building the
real frontend to consume) and `report.html` (open directly in a browser — this
is what to screenshot for the PDF).

## 8. File map (for whoever writes the architecture section)

```
scrisk/
├── main.py                  # CLI entry point, runs the full pipeline
├── data/
│   ├── cve_database.json    # sample CVE dataset (NVD-shaped)
│   ├── rules.json           # restricted countries/vendors, EOL, single-source
│   ├── sample_bom.csv        # demo BOM (CSV format)
│   └── sample_bom_cyclonedx.json  # demo BOM (CycloneDX format)
├── src/
│   ├── bom_parser.py        # ingestion: CSV + CycloneDX -> normalized schema
│   ├── cve_matcher.py       # exact + fuzzy CVE matching
│   ├── rules_engine.py      # vendor/origin + lifecycle rule checks
│   ├── scoring.py           # per-component + aggregate BOM scoring
│   └── report.py            # findings report (JSON) + HTML render
└── output/                  # generated reports (per run)
```
