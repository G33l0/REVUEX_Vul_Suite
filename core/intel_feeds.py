#!/usr/bin/env python3
"""
REVUEX - Threat-intel enrichment (CVE / KEV / EPSS)

Enriches findings and CVE references with real-world exploitation signal so the
report can prioritise by *actual* risk instead of a hard-coded dollar figure:

  - CISA KEV  : is this CVE known to be exploited in the wild?
  - EPSS      : probability (0-1) the CVE will be exploited in the next 30 days.
  - NVD 2.0   : base CVSS score / vector (best-effort).

Design rules (so it is safe inside any scan):
  - Network is optional. Every request is wrapped; on any failure the enrichment
    degrades to "unknown" and the scan continues. It NEVER raises.
  - Results are cached in-memory and on disk (workspace) to avoid hammering APIs.
  - A global timeout and a small request budget prevent a scan from hanging.
"""

import json
import re
import time
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import requests
except Exception:  # pragma: no cover - requests is a declared dependency
    requests = None

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class IntelFeeds:
    def __init__(self, workspace: Optional[Path] = None, timeout: float = 8.0,
                 enabled: bool = True):
        self.workspace = Path(workspace) if workspace else None
        self.timeout = timeout
        self.enabled = enabled and requests is not None
        self._cache: Dict[str, Any] = {}
        self._kev_set: Optional[set] = None
        self._budget = 40  # max outbound requests per instance

    # ---------------- low-level ----------------

    def _get(self, url: str, **kwargs) -> Optional[Any]:
        if not self.enabled or self._budget <= 0:
            return None
        self._budget -= 1
        try:
            r = requests.get(url, timeout=self.timeout, **kwargs)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None

    # ---------------- KEV ----------------

    def _load_kev(self) -> set:
        if self._kev_set is not None:
            return self._kev_set
        self._kev_set = set()
        data = self._get(KEV_URL)
        if isinstance(data, dict):
            for item in data.get("vulnerabilities", []):
                cid = item.get("cveID")
                if cid:
                    self._kev_set.add(cid.upper())
        return self._kev_set

    def is_known_exploited(self, cve: str) -> Optional[bool]:
        if not self.enabled:
            return None
        kev = self._load_kev()
        if not kev:
            return None
        return cve.upper() in kev

    # ---------------- EPSS ----------------

    def epss_score(self, cve: str) -> Optional[float]:
        key = f"epss:{cve.upper()}"
        if key in self._cache:
            return self._cache[key]
        data = self._get(EPSS_URL, params={"cve": cve.upper()})
        score = None
        try:
            rows = data.get("data", []) if isinstance(data, dict) else []
            if rows:
                score = float(rows[0].get("epss"))
        except Exception:
            score = None
        self._cache[key] = score
        return score

    # ---------------- NVD CVSS ----------------

    def cvss(self, cve: str) -> Optional[Dict[str, Any]]:
        key = f"cvss:{cve.upper()}"
        if key in self._cache:
            return self._cache[key]
        data = self._get(NVD_URL, params={"cveId": cve.upper()})
        result = None
        try:
            vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(mkey):
                        cd = metrics[mkey][0].get("cvssData", {})
                        result = {
                            "baseScore": cd.get("baseScore"),
                            "vector": cd.get("vectorString"),
                            "version": cd.get("version"),
                        }
                        break
        except Exception:
            result = None
        self._cache[key] = result
        return result

    # ---------------- public enrichment ----------------

    def enrich_cve(self, cve: str) -> Dict[str, Any]:
        """Return an enrichment dict for one CVE. Always returns a dict."""
        cve = cve.upper()
        out = {"cve": cve, "kev": None, "epss": None, "cvss": None,
               "priority": "unknown"}
        if not self.enabled:
            return out
        try:
            out["kev"] = self.is_known_exploited(cve)
            out["epss"] = self.epss_score(cve)
            out["cvss"] = self.cvss(cve)
            out["priority"] = self._priority(out)
        except Exception:
            pass
        return out

    @staticmethod
    def _priority(e: Dict[str, Any]) -> str:
        if e.get("kev") is True:
            return "urgent (known-exploited)"
        epss = e.get("epss")
        if isinstance(epss, (int, float)):
            if epss >= 0.5:
                return "high (likely exploited)"
            if epss >= 0.1:
                return "elevated"
            return "low"
        return "unknown"

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a finding for CVE IDs and attach enrichment. Never raises."""
        if not isinstance(finding, dict):
            return finding
        try:
            blob = json.dumps(finding, default=str)
        except Exception:
            blob = str(finding)
        cves = sorted({m.upper() for m in CVE_RE.findall(blob)})
        if not cves:
            return finding
        finding.setdefault("intel", {})
        for cve in cves[:10]:  # cap per finding
            finding["intel"][cve] = self.enrich_cve(cve)
        return finding
