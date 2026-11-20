"""CVE extraction + NVD enrichment.

Pulls CVE IDs out of scanner output (nuclei templates, service banners, exploit-db
matches) and enriches the top ones with CVSS score + summary from the NVD API. Results
are fed to the AI analysis and used to tag findings.
"""
from __future__ import annotations

import re
from functools import lru_cache

import httpx

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def extract(text: str) -> list[str]:
    return sorted({c.upper() for c in _CVE_RE.findall(text or "")})


@lru_cache(maxsize=512)
def nvd_lookup(cve: str) -> dict:
    out = {"cve": cve, "cvss": None, "severity": None, "summary": "", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
    try:
        r = httpx.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                      params={"cveId": cve}, timeout=10,
                      headers={"User-Agent": "Iron360-VAPT/1.0"})
        if r.status_code != 200:
            return out
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return out
        v = vulns[0]["cve"]
        metrics = v.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                data = m.get("cvssData", {})
                out["cvss"] = data.get("baseScore")
                out["severity"] = (data.get("baseSeverity") or m.get("baseSeverity") or "").upper() or None
                break
        out["summary"] = next((d["value"] for d in v.get("descriptions", []) if d.get("lang") == "en"), "")[:320]
    except Exception:  # noqa: BLE001
        pass
    return out


def enrich(text: str, limit: int = 6) -> list[dict]:
    """Extract CVEs from text and enrich the first `limit` with NVD data."""
    cves = extract(text)
    return [nvd_lookup(c) for c in cves[:limit]]
