"""
Shared value cleanup used by CSV cleaning and CycloneDX ingest so origin
codes do not drift between the two input paths.
"""

import re

# Common full country names -> ISO-2, so a human typing "United States" instead
# of "US" doesn't get treated as a data error. Not exhaustive - anything not in
# here that also isn't a 2-letter code is flagged for manual correction rather
# than guessed at.
COUNTRY_NAME_TO_ISO2 = {
    "united states": "US", "usa": "US", "u.s.a.": "US", "u.s.": "US",
    "taiwan": "TW", "china": "CN", "south korea": "KR", "korea": "KR",
    "singapore": "SG", "japan": "JP", "germany": "DE", "india": "IN",
    "vietnam": "VN", "mexico": "MX", "malaysia": "MY", "philippines": "PH",
    "thailand": "TH", "united kingdom": "GB", "uk": "GB",
}


def normalize_country(value):
    """Returns (iso_or_original, note). Empty input becomes UNKNOWN with no note."""
    v = (value or "").strip()
    if not v:
        return "UNKNOWN", None
    if re.fullmatch(r"[A-Za-z]{2}", v):
        return v.upper(), None
    mapped = COUNTRY_NAME_TO_ISO2.get(v.lower())
    if mapped:
        return mapped, f"origin_country '{v}' normalized to ISO-2 '{mapped}'"
    return v, (
        f"origin_country '{v}' is not a recognized ISO-2 code or known country "
        "name - left as-is, flag for manual correction"
    )
