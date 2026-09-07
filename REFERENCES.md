# References & Disclosures

Every citation below was verified by live web search on the date this file was
written (Sept 2026). Where a source's information conflicts with another
source, or is time-sensitive, that is stated explicitly — don't present it as
settled fact in the write-up without checking the primary source yourself
first, since regulatory/sanctions details change and this file has a fixed
"as of" date.

---

## 1. Dataset disclosure (read this first)

**`data/cve_database.json` and `data/rules.json` are datasets we built
ourselves for this prototype.** Some entries are now real, verified public
CVEs (see below); the rest, and all of `rules.json`'s illustrative fields,
remain self-built/synthetic. This must be stated plainly in the submission.

**CVE dataset — now mixed, disclosed per-entry via a `provenance` field:**
- **Real, verified entries** (`"provenance": "real"`, with a `source_url`
  you can open yourself):
  - `CVE-2019-6260` ("Pantsdown") — a genuine, widely-documented vulnerability
    in Aspeed AST2400/AST2500 BMC hardware/firmware.
    https://www.flamingspork.com/blog/2019/01/23/cve-2019-6260-gaining-control-of-bmc-from-the-host-processor/
  - `CVE-2023-34329` and `CVE-2023-34330` — genuine vulnerabilities in AMI
    MegaRAC BMC firmware (the "BMC&C" set), disclosed by Eclypsium, with
    real CVSS scores (9.1 and 8.2 respectively).
    https://eclypsium.com/research/bmcc-lights-out-forever/
- **Simulated entries** (`"provenance": "simulated"`, IDs suffixed `-SIM`):
  fabricated for component categories (NIC/RAID/UEFI/TPM/Bootloader/PCIe
  switch) where a convenient, exactly-matching real public CVE wasn't found
  during research for this prototype. Each simulated entry's description
  states plainly that it's fabricated, and notes the real vulnerability
  class it's modeled on where one exists (e.g. the UEFI entry notes it's
  modeled on the real, published "LogoFAIL"/"PixieFail" vulnerability
  classes without copying either).

**`rules.json` — still mixed provenance, as before:** Hikvision and Dahua
are real companies under real current U.S. restrictions (§4 below). The
country list, EOL dates, and single-source flags are our own illustrative
entries, not extracted from any live registry.

If asked "where does your data come from" in the demo: three CVE entries are
real and citable; the rest are hand-built sample data shaped like the real
schema, clearly labeled as such in the data file itself.

---

## 2. CVSS scoring (the CVE risk dimension)

- **Common Vulnerability Scoring System v3.1 Specification** — FIRST.org
  (the standards body that publishes CVSS). Defines the Base/Temporal/
  Environmental metric groups and the 0–10 severity scale our `cvss_score`
  field is modeled on.
  https://www.first.org/cvss/v3.1/specification-document
- **National Vulnerability Database (NVD)** — U.S. NIST. The real-world
  source our sample dataset's schema (CVE ID, CVSS score, affected
  versions, description) is modeled on, and the source a production version
  would sync from.
  https://nvd.nist.gov/vuln (browse) · https://nvd.nist.gov/developers/vulnerabilities
  (API documentation, including the `services.nvd.nist.gov/rest/json/cves/2.0`
  endpoint and its rate limits — this is why the design note in the code
  says "sync on a schedule, don't call live per request").

## 3. BOM formats (ingestion)

- **CycloneDX** — OWASP / Ecma International (published as **ECMA-424**).
  The format our `parse_cyclonedx()` function reads.
  https://cyclonedx.org/specification/overview/
- **SPDX** — Linux Foundation, recognized as international standard
  **ISO/IEC 5962:2021**. Mentioned in the write-up as the other standard
  format procurement/security tooling commonly produces (not implemented in
  this prototype — CSV and CycloneDX are the two formats we built parsers
  for).
  https://spdx.dev/about/overview/
- **Executive Order 14028 ("Improving the Nation's Cybersecurity")** — the
  U.S. policy action most responsible for CycloneDX/SPDX becoming standard
  procurement artifacts, cited for the "why this approach now" argument.
  **Important nuance, stated accurately rather than simplified:** EO 14028
  itself (May 2021) remains in effect, but the specific OMB implementation
  memos that mandated SBOMs government-wide (M-22-18, M-23-16) were
  **rescinded in 2026 by OMB Memorandum M-26-05**, which shifted federal
  agencies to a discretionary, risk-based approach rather than a blanket
  requirement. Cite this as "the policy trend that established SBOMs as a
  procurement artifact," not as "SBOMs are currently mandated by federal
  law" — that overstates the current state as of 2026.
  https://www.federalregister.gov/d/2021-10460 (EO 14028 original text)
  https://www.dwt.com/blogs/privacy--security-law-blog/2026/02/omb-changes-course-on-software-security
  (reporting on M-26-05's rescission of the earlier mandate)
- **CISA Hardware Bill of Materials (HBOM) Framework** (2023) — a real,
  published U.S. government framework specifically for *hardware* BOMs
  (rather than software SBOMs), developed by CISA's ICT Supply Chain Risk
  Management Task Force. It defines a component data-field taxonomy for
  exactly the kind of hardware/firmware component list this tool ingests.
  Worth citing directly as evidence this isn't a made-up problem shape —
  the U.S. government has already formally defined what fields a hardware
  BOM should carry, and our BOM schema (component name, vendor, version,
  origin, part number) is a practical subset of that taxonomy.
  https://www.cisa.gov/resources-tools/resources/hardware-bill-materials-hbom-framework-supply-chain-risk-management

## 4. Restricted-vendor / country-of-origin rules

- **NDAA Section 889** (National Defense Authorization Act for Fiscal Year
  2019, Public Law 115-232) — the actual U.S. statute naming Hikvision and
  Dahua (alongside Huawei, ZTE, Hytera) as covered telecommunications/video
  surveillance equipment producers, prohibiting federal agencies and
  federal contractors from procuring or using their equipment.
- **FCC Covered List** — maintained under the Secure and Trusted
  Communications Networks Act; Hikvision and Dahua are on it.
  https://www.fcc.gov/supplychain/coveredlist (referenced by multiple
  sources; this is the FCC's own list page)
- **FAR 52.204-25** — the Federal Acquisition Regulation clause that
  operationalizes the Section 889 prohibition in federal contracts. This is
  the real-world legal basis for the design decision in §4.5 of
  `DOCUMENTATION_NOTES.md` — a restricted-vendor hit being a **hard
  compliance stop**, not a score input, mirrors how this actually works in
  federal procurement: it's a prohibition, not a risk weighting.
- **Note on scope:** these restrictions legally bind federal agencies,
  federal contractors, and recipients of federal grants/loans — they are
  not a blanket ban on private commercial purchase. State this distinction
  accurately if asked; several sources describe private-sector adoption as
  a risk-management choice rather than a legal requirement.
  (Synthesized from multiple 2026 legal/compliance sources describing
  current NDAA 889 / FCC Covered List status — verify directly at
  fcc.gov/supplychain/coveredlist before the submission, since covered
  lists are amended periodically.)
- **BIS Entity List** — U.S. Department of Commerce, Bureau of Industry and
  Security. Cited as the general legal mechanism our `restricted_vendors`
  concept is modeled on (export-controlled/national-security-flagged
  entities), separate from and broader than the NDAA 889 / FCC list above.
  https://www.bis.gov/licensing/guidance-on-end-user-and-end-use-controls-and-us-person-controls
- **OFAC sanctions programs** — U.S. Department of the Treasury. Cited as
  the general legal mechanism our `restricted_countries` concept is
  modeled on.
  **Conflicting current information, disclosed rather than resolved:**
  multiple 2026 sources disagree on whether Syria remains under a
  comprehensive OFAC embargo or had it lifted in 2025 — some describe Cuba/
  Iran/North Korea/Syria as the current four comprehensively-sanctioned
  countries, others describe only Cuba/Iran/North Korea as comprehensively
  sanctioned as of 2026, with Syria's comprehensive sanctions removed.
  **Do not state Syria's status as settled fact in the submission.** Check
  the authoritative source directly before finalizing:
  https://ofac.treasury.gov/sanctions-programs-and-country-information

## 5. Matching algorithm

- **Python `difflib.SequenceMatcher`** — the standard library module used
  for fuzzy name/vendor matching (Ratcliff/Obershelp pattern-matching
  algorithm). Official documentation for the `.ratio()` method and
  `autojunk` behavior our matcher relies on.
  https://docs.python.org/3/library/difflib.html

## 6. Scoring formula and weights — explicitly NOT an external standard

The weighting (CVE term max 60 pts, vendor/origin term 25 pts, lifecycle
term max 15 pts, aggregate = 0.6×max + 0.4×mean) is **our own design
decision**, reasoned from the compliance/severity logic described in
`DOCUMENTATION_NOTES.md` §4.3 — it is not derived from a published scoring
standard, and the write-up should not cite it as if it were. If asked "is
this formula from a standard," the honest answer is no — CVSS and EPSS
(below) score individual vulnerabilities, not a multi-factor BOM component
risk score; no widely-adopted public standard for combining CVE + policy +
lifecycle signals into one BOM risk number was found during research for
this prototype. State it as an original, documented, defensible design
choice rather than implying external validation it doesn't have.

## 7. Innovation — real backing for the design choices in §5 of
   `DOCUMENTATION_NOTES.md`

- **Policy flag as a hard stop, not a score input:** directly justified by
  FAR 52.204-25 (§4 above) — federal procurement law treats a Section
  889-covered vendor as a flat prohibition, not something weighed against a
  severity score. This is real-world precedent for the design choice, not
  just an assumption.
- **Explainable, decomposed scoring instead of a single black-box number:**
  not citing an external standard here — this is a design philosophy choice
  justified by the brief's own grading criterion ("technical depth and
  correctness"), stated as such rather than attributed to a source.
- **Future-work extension worth naming (not built, honestly labeled as
  future work):** the **Exploit Prediction Scoring System (EPSS)**, also
  published by FIRST.org, estimates the probability a specific CVE will
  actually be exploited in the wild within 30 days — a real, live,
  queryable complement to CVSS (which measures severity, not likelihood).
  A production version of this tool could pull EPSS scores alongside CVSS
  to prioritize "high severity AND likely to be exploited" over "high
  severity but never exploited in practice." This is a legitimate,
  citable extension idea, not a fabricated one.
  https://www.first.org/epss/
- **CISA Known Exploited Vulnerabilities (KEV) catalog** — a real,
  actively-maintained U.S. government list of CVEs with confirmed
  real-world exploitation. Another legitimate future-work citation: a
  production version could flag any matched CVE that also appears on KEV
  as maximum priority, since it's not theoretical risk at that point.
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

## 8. BOM cleaning stage — our own design, not an external standard

`clean_bom.py` / `bom_cleaner.py` (the pre-scoring data-cleaning stage) is
our own design — the specific junk-value list, country-name mapping, and
duplicate-detection logic were written for this prototype, not derived from
a published data-cleaning standard. If asked, say so plainly rather than
attributing it to a source it doesn't have.

## 9. How to verify any of this yourself

If a jury member or teammate wants to check a claim directly rather than
trust this file:
- CVE / CVSS data: https://nvd.nist.gov (search any real CVE ID directly)
- CycloneDX spec: https://cyclonedx.org/specification/overview/
- SPDX spec: https://spdx.dev/
- FCC Covered List (current): https://www.fcc.gov/supplychain/coveredlist
- BIS Entity List (current, downloadable as CSV):
  https://www.bis.gov/licensing/guidance-on-end-user-and-end-use-controls-and-us-person-controls
- OFAC sanctions programs (current, authoritative):
  https://ofac.treasury.gov/sanctions-programs-and-country-information
- EPSS: https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
