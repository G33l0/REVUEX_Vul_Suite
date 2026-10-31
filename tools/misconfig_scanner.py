#!/usr/bin/env python3
"""
REVUEX - Security Misconfiguration Scanner  (OWASP A02:2025)

Security Misconfiguration rose to #2 in the OWASP Top 10:2025. This scanner
checks for the high-signal, evidence-based misconfigurations:

  - Missing / weak HTTP security headers
  - Verbose server & framework version banners
  - Exposed sensitive files & endpoints (.git, .env, actuator, phpinfo, etc.)
  - Directory listing enabled
  - Debug mode / stack traces in error pages

False-positive discipline (consistent with the rest of the suite):
  - Exposed-path checks confirm with a CONTENT signature, and compare against a
    known-404/soft-404 baseline, so a catch-all page returning 200 for every
    path does not produce findings.
  - Missing-header checks only apply to document responses actually served.

Author: G33L0
"""

import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MisconfigScanner:
    def __init__(self, target: str, workspace: Path, delay: float = 2.0):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.workspace = Path(workspace)
        self.delay = delay
        self.timeout = 10
        self.max_requests = 60
        self.request_count = 0
        self.headers = {
            "User-Agent": "REVUEX-MisconfigScanner/1.0 (Security Research; +https://github.com/G33L0)",
            "Accept": "*/*",
        }
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.manual_checks: List[Dict[str, Any]] = []

        # path -> content signature(s) proving the file is really exposed.
        self.sensitive_paths = {
            "/.git/HEAD": ["ref: refs/"],
            "/.git/config": ["[core]", "repositoryformatversion"],
            "/.env": ["=", "APP_", "DB_", "SECRET", "KEY"],
            "/.aws/credentials": ["aws_access_key_id", "aws_secret_access_key"],
            "/server-status": ["Apache Server Status", "Scoreboard"],
            "/actuator/env": ["propertySources", "systemProperties"],
            "/actuator/health": ["\"status\""],
            "/phpinfo.php": ["phpinfo()", "PHP Version"],
            "/info.php": ["phpinfo()", "PHP Version"],
            "/.DS_Store": ["Bud1", "\x00\x00\x00"],
            "/config.json": ["{", "}"],
            "/wp-config.php.bak": ["DB_PASSWORD", "DB_NAME"],
            "/swagger.json": ["\"swagger\"", "\"openapi\""],
            "/.svn/entries": ["dir", "svn"],
            "/docker-compose.yml": ["services:", "image:"],
        }

        self.security_headers = {
            "Content-Security-Policy": "medium",
            "Strict-Transport-Security": "medium",
            "X-Content-Type-Options": "low",
            "X-Frame-Options": "low",
            "Referrer-Policy": "low",
            "Permissions-Policy": "low",
        }

    # ---------------- infra ----------------

    def _get(self, url: str) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests:
            return None
        try:
            r = requests.get(url, headers=self.headers, timeout=self.timeout,
                             verify=False, allow_redirects=True)
            self.request_count += 1
            return r
        except Exception:
            return None

    # ---------------- scan ----------------

    def scan(self) -> Dict[str, Any]:
        print(f"\n{'='*60}\n⚙️  REVUEX Security Misconfiguration Scanner (A02:2025)\n{'='*60}")
        print(f"Target: {self.target}\n")

        root = self._get(self.target)
        if root is None:
            print("   ⚠️  Target did not respond; skipping.")
            self._save()
            return {"scanner": "MisconfigScanner", "target": self.target,
                    "vulnerabilities": self.vulnerabilities,
                    "manual_checks": self.manual_checks}

        self._check_security_headers(root)
        time.sleep(self.delay)
        self._check_version_banner(root)
        self._check_directory_listing()
        time.sleep(self.delay)
        self._check_exposed_paths()
        self._check_debug_errors()

        self._save()
        print(f"\n✅ Misconfig scan complete. Findings: {len(self.vulnerabilities)}, "
              f"manual: {len(self.manual_checks)}\n")
        return {"scanner": "MisconfigScanner", "target": self.target,
                "vulnerabilities": self.vulnerabilities,
                "manual_checks": self.manual_checks}

    def _check_security_headers(self, resp: requests.Response):
        missing = []
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        for header, sev in self.security_headers.items():
            if header.lower() not in hdrs:
                # HSTS only meaningful over HTTPS.
                if header == "Strict-Transport-Security" and \
                        urlparse(self.target).scheme != "https":
                    continue
                missing.append({"header": header, "severity": sev})
        if missing:
            worst = "medium" if any(m["severity"] == "medium" for m in missing) else "low"
            self.vulnerabilities.append({
                "type": "Security Misconfiguration - Missing Security Headers",
                "severity": worst,
                "owasp_2025": "A02",
                "url": self.target,
                "missing_headers": missing,
                "description": "Response is missing recommended security headers.",
                "evidence": ", ".join(m["header"] for m in missing),
                "remediation": ["Set CSP, HSTS, X-Content-Type-Options, "
                                "X-Frame-Options, Referrer-Policy, Permissions-Policy."],
                "tags": ["misconfig", "headers"],
            })
            print(f"   • Missing headers: {', '.join(m['header'] for m in missing)}")

    def _check_version_banner(self, resp: requests.Response):
        leaks = []
        for h in ("Server", "X-Powered-By", "X-AspNet-Version",
                  "X-AspNetMvc-Version", "X-Generator"):
            val = resp.headers.get(h)
            # Only flag when a VERSION NUMBER is disclosed, not a bare product
            # name (e.g. "nginx" alone is not a finding; "nginx/1.18.0" is).
            if val and re.search(r"\d+\.\d+", val):
                leaks.append({"header": h, "value": val})
        if leaks:
            self.vulnerabilities.append({
                "type": "Security Misconfiguration - Version Disclosure",
                "severity": "low",
                "owasp_2025": "A02",
                "url": self.target,
                "evidence": "; ".join(f"{l['header']}: {l['value']}" for l in leaks),
                "description": "Server/framework version numbers disclosed in headers.",
                "remediation": ["Suppress version banners in server/framework config."],
                "tags": ["misconfig", "version_disclosure"],
            })
            print(f"   • Version banner(s): {[l['value'] for l in leaks]}")

    def _check_directory_listing(self):
        # Probe a likely-listable directory.
        for path in ("/images/", "/uploads/", "/static/", "/assets/", "/files/"):
            r = self._get(urljoin(self.target, path))
            if r is not None and r.status_code == 200 and \
                    re.search(r"<title>\s*Index of /|Directory listing for", r.text, re.I):
                self.vulnerabilities.append({
                    "type": "Security Misconfiguration - Directory Listing",
                    "severity": "medium",
                    "owasp_2025": "A02",
                    "url": urljoin(self.target, path),
                    "evidence": "Autoindex / 'Index of' page served.",
                    "description": "Directory listing is enabled.",
                    "remediation": ["Disable autoindex/directory browsing."],
                    "tags": ["misconfig", "directory_listing"],
                })
                print(f"   • Directory listing at {path}")
                return
            time.sleep(self.delay)

    def _baseline_404(self) -> str:
        """Fetch a path that should not exist, to characterise soft-404s."""
        r = self._get(urljoin(self.target, "/revuex_nope_%s" % int(time.time())))
        return r.text if r is not None else ""

    def _check_exposed_paths(self):
        baseline = self._baseline_404()
        for path, signatures in self.sensitive_paths.items():
            if self.request_count >= self.max_requests:
                break
            r = self._get(urljoin(self.target, path))
            if r is None or r.status_code != 200:
                time.sleep(self.delay)
                continue
            body = r.text or ""
            # Require a content signature present here AND absent from the
            # soft-404 baseline, so a catch-all 200 page is not flagged.
            hit = next((s for s in signatures if s in body and s not in baseline), None)
            if hit:
                self.vulnerabilities.append({
                    "type": "Security Misconfiguration - Exposed Sensitive File",
                    "severity": "high",
                    "owasp_2025": "A02",
                    "url": urljoin(self.target, path),
                    "evidence": f"Signature '{hit[:40]}' served at {path}",
                    "description": f"Sensitive path {path} is publicly accessible.",
                    "remediation": [f"Block or remove {path}; keep VCS/config/debug "
                                    "artifacts out of the web root."],
                    "tags": ["misconfig", "exposed_file"],
                })
                print(f"   • Exposed: {path}")
            time.sleep(self.delay)

    def _check_debug_errors(self):
        # Trigger a likely error and look for stack-trace / debug signatures.
        r = self._get(urljoin(self.target, "/'\"><revuex"))
        if r is None:
            return
        body = r.text or ""
        signatures = [
            "Traceback (most recent call last)", "Werkzeug Debugger",
            "Whitespace: Whoops", "Whoops\\", "symfony/debug",
            "django.core.exceptions", "DEBUG = True",
            "Exception in thread", "java.lang.", "at org.springframework",
            ".cfm line", "ASP.NET is configured to show verbose error messages",
        ]
        hit = next((s for s in signatures if s in body), None)
        if hit:
            self.vulnerabilities.append({
                "type": "Security Misconfiguration - Debug/Stack Trace Exposure",
                "severity": "medium",
                "owasp_2025": "A02",
                "url": self.target,
                "evidence": f"Error page signature: {hit}",
                "description": "Application leaks stack traces / debug output.",
                "remediation": ["Disable debug mode in production; return generic "
                                "error pages; log details server-side only."],
                "tags": ["misconfig", "debug", "verbose_error"],
            })
            print(f"   • Debug/stack-trace leak: {hit}")

    def _save(self):
        out = self.workspace / "misconfig_scans"
        out.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w\-]", "_", urlparse(self.target).netloc or self.target)
        with open(out / f"{safe}_misconfig.json", "w") as f:
            json.dump({"scanner": "MisconfigScanner", "target": self.target,
                       "vulnerabilities": self.vulnerabilities,
                       "manual_checks": self.manual_checks}, f, indent=2)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python misconfig_scanner.py <target_url>")
        sys.exit(1)
    MisconfigScanner(sys.argv[1], Path("revuex_workspace")).scan()
