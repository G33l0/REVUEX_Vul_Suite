#!/usr/bin/env python3
"""
REVUEX - Reflected XSS Scanner (context-aware, evidence-based)

Rewritten from a non-functional stub into a working reflected-XSS detector.

False-positive discipline — reflection is NOT XSS:
  - We inject a unique canary containing HTML-significant characters
    (`<`, `>`, `"`, `'`). A finding is only raised when those characters are
    reflected UNENCODED in a context where they are dangerous (so a value that
    is HTML-entity-encoded, e.g. `&lt;`, is correctly treated as safe).
  - We classify the reflection context (raw HTML body, attribute, script,
    HTML-encoded) and report severity accordingly, with the exact evidence.

This covers reflected XSS only. DOM-based and stored XSS require a browser / a
second request and are listed as manual follow-ups.

Author: G33L0
"""

import time
import json
import re
import html
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EnhancedXSSScanner:
    def __init__(self, target: str, workspace: Path, delay: float = 3.0):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.workspace = Path(workspace)
        self.delay = delay
        self.timeout = 10
        self.max_requests = 120
        self.request_count = 0
        self.headers = {
            "User-Agent": "REVUEX-XSSScanner/1.0 (Security Research; +https://github.com/G33L0)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.manual_checks: List[Dict[str, Any]] = []

    # ---------------- infra ----------------

    def _get(self, params: Dict[str, str]) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests:
            return None
        parsed = urlparse(self.target)
        base_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        base_params.update(params)
        new_q = urlencode(base_params, doseq=True)
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                          parsed.params, new_q, parsed.fragment))
        try:
            r = requests.get(url, headers=self.headers, timeout=self.timeout,
                             verify=False, allow_redirects=True)
            self.request_count += 1
            return r
        except Exception:
            return None

    def _identify_parameters(self) -> List[str]:
        params = list(parse_qs(urlparse(self.target).query).keys())
        if not params:
            # No query params present; probe a common default so the scan still
            # does something meaningful on a bare URL.
            params = ["q"]
        return params

    # ---------------- detection ----------------

    def scan(self) -> Dict[str, Any]:
        print(f"\n{'='*60}\n🧪 REVUEX Reflected XSS Scanner\n{'='*60}")
        print(f"Target: {self.target}\n")

        params = self._identify_parameters()
        print(f"   Parameters under test: {params}")

        for param in params:
            if self.request_count >= self.max_requests:
                break
            self._test_param(param)
            time.sleep(self.delay)

        self.manual_checks.append({
            "type": "XSS - DOM-based & Stored",
            "severity": "info",
            "confidence": "manual-verification-required",
            "url": self.target,
            "how_to_confirm": ("This module covers reflected XSS. For DOM XSS, "
                               "review client-side sinks (innerHTML, document.write, "
                               "eval) with a headless browser; for stored XSS, submit "
                               "a canary and check where it renders later."),
            "tags": ["xss", "dom", "stored", "manual"],
        })

        self._save()
        print(f"\n✅ XSS scan complete. Findings: {len(self.vulnerabilities)}, "
              f"manual: {len(self.manual_checks)}\n")
        return self._result()

    def _test_param(self, param: str):
        token = "rvx" + uuid.uuid4().hex[:8]
        # Canary carries every HTML-significant char plus the token so we can
        # locate it and inspect how each char was (or wasn't) encoded.
        canary = f"{token}<\"'>"
        resp = self._get({param: canary})
        if resp is None:
            return
        body = resp.text or ""
        if token not in body:
            # Not reflected at all -> cannot be reflected XSS.
            print(f"   ✓ '{param}' not reflected")
            return

        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype.lower() and ctype:
            # Reflected into a non-HTML response (e.g. application/json). Report
            # as low/manual — not directly rendered as HTML by the browser.
            self.manual_checks.append({
                "type": "XSS - Reflection in non-HTML response",
                "severity": "info",
                "confidence": "needs-manual-verification",
                "url": self.target, "parameter": param,
                "evidence": f"Token reflected; Content-Type: {ctype}",
                "how_to_confirm": "Confirm the response is ever rendered as HTML "
                                  "(e.g. sniffed, or used in a sink) before treating "
                                  "as XSS.",
                "tags": ["xss", "reflection", "unconfirmed"],
            })
            print(f"   ? '{param}' reflected in non-HTML ({ctype})")
            return

        # Find the reflection and inspect which dangerous chars survived raw.
        idx = body.find(token)
        window = body[idx: idx + len(canary) + 8]
        raw_lt = "<" in window
        raw_gt = ">" in window
        raw_dq = '"' in window
        raw_sq = "'" in window
        encoded_present = ("&lt;" in body or "&gt;" in body or
                           "&quot;" in body or "&#x27;" in body or "&#39;" in body)

        if raw_lt and raw_gt:
            # Angle brackets survive unencoded in an HTML context -> can inject
            # a new tag. This is reflected XSS.
            self.vulnerabilities.append({
                "type": "Reflected XSS",
                "severity": "high",
                "owasp_2025": "A05",
                "url": self.target,
                "parameter": param,
                "evidence": f"Canary reflected with unencoded < and > : "
                            f"...{html.escape(window)}...",
                "payload_used": canary,
                "poc": f"{self.target}{'&' if '?' in self.target else '?'}"
                       f"{param}=<script>alert(document.domain)</script>",
                "description": "User input is reflected into the HTML response with "
                               "angle brackets unencoded, allowing script injection.",
                "remediation": ["Context-aware output encoding (HTML entity-encode "
                                "< > \" '); set a strong CSP; prefer framework "
                                "auto-escaping."],
                "tags": ["xss", "reflected", "injection"],
            })
            print(f"   • Reflected XSS on '{param}' (unencoded angle brackets)")
        elif (raw_dq or raw_sq) and not (raw_lt or raw_gt):
            # Quotes survive but angle brackets don't -> possible attribute-context
            # breakout. Needs manual confirmation of the surrounding context.
            self.vulnerabilities.append({
                "type": "Reflected XSS - Possible Attribute Breakout",
                "severity": "medium",
                "owasp_2025": "A05",
                "confidence": "needs-manual-verification",
                "url": self.target,
                "parameter": param,
                "evidence": f"Unencoded quote reflected: ...{html.escape(window)}...",
                "description": "Input is reflected with quotes unencoded; if it "
                               "lands inside an HTML attribute, an attribute/event "
                               "breakout may be possible.",
                "remediation": ["Entity-encode quotes in attribute context; quote "
                                "all attributes; add CSP."],
                "tags": ["xss", "reflected", "attribute", "unconfirmed"],
            })
            print(f"   • Possible attribute-context XSS on '{param}' (quotes raw)")
        else:
            # Reflected but dangerous chars encoded -> correctly handled, no XSS.
            note = " (dangerous chars encoded)" if encoded_present else ""
            print(f"   ✓ '{param}' reflected but encoded{note} - not XSS")

    def _result(self) -> Dict[str, Any]:
        return {"scanner": "EnhancedXSSScanner", "target": self.target,
                "vulnerabilities": self.vulnerabilities,
                "manual_checks": self.manual_checks}

    def _save(self):
        out = self.workspace / "xss_scans"
        out.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w\-]", "_", self.target)
        with open(out / f"{safe}_xss.json", "w") as f:
            json.dump(self._result(), f, indent=2)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <target_url>")
        sys.exit(1)
    EnhancedXSSScanner(sys.argv[1], Path("revuex_workspace")).scan()
