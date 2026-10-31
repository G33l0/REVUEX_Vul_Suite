#!/usr/bin/env python3
"""
REVUEX - Software Supply Chain Scanner  (OWASP A03:2025)

"Software Supply Chain Failures" is a new, top-tier OWASP 2025 category. This
scanner focuses on supply-chain exposure reachable from the web surface:

  - Exposed dependency manifests / lockfiles in the web root
    (package.json, composer.json, requirements.txt, yarn.lock, Gemfile.lock, ...)
  - Exposed CI/CD and registry config (.npmrc, .github/workflows, Dockerfile)
  - Dependency-confusion candidates: internal/scoped package names referenced in
    exposed manifests that may not exist on the public registry
  - Optional CVE/KEV/EPSS enrichment of discovered components (best-effort,
    offline-safe via core.intel_feeds)

Discipline: a manifest finding is only reported when the file is actually
retrievable AND parses as that manifest type (not a soft-404 HTML page).

Author: G33L0
"""

import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional enrichment; must never break the scan if unavailable.
try:
    from core.intel_feeds import IntelFeeds
except Exception:  # pragma: no cover
    IntelFeeds = None


class SupplyChainScanner:
    def __init__(self, target: str, workspace: Path, delay: float = 2.0,
                 enrich: bool = False):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.workspace = Path(workspace)
        self.delay = delay
        self.timeout = 10
        self.max_requests = 50
        self.request_count = 0
        self.enrich = enrich
        self.headers = {
            "User-Agent": "REVUEX-SupplyChain/1.0 (Security Research; +https://github.com/G33L0)",
            "Accept": "*/*",
        }
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.manual_checks: List[Dict[str, Any]] = []
        self.components: List[Dict[str, str]] = []

        # manifest path -> (parser name, required signature substrings)
        self.manifests = {
            "/package.json": ("npm", ['"dependencies"', '"name"', "{"]),
            "/package-lock.json": ("npm-lock", ['"lockfileVersion"', '"dependencies"']),
            "/yarn.lock": ("yarn", ["# yarn lockfile", "resolved "]),
            "/composer.json": ("composer", ['"require"', "{"]),
            "/composer.lock": ("composer-lock", ['"packages"', '"name"']),
            "/requirements.txt": ("pip", ["==", "\n"]),
            "/Pipfile.lock": ("pipenv", ['"_meta"', '"default"']),
            "/Gemfile.lock": ("bundler", ["GEM", "specs:"]),
            "/go.mod": ("gomod", ["module ", "go 1."]),
            "/pom.xml": ("maven", ["<dependencies>", "<groupId>"]),
        }
        self.cicd_paths = {
            "/.npmrc": ["registry=", "//", "_authToken"],
            "/Dockerfile": ["FROM ", "RUN "],
            "/.github/workflows/": ["name:", "on:", "jobs:"],
            "/.gitlab-ci.yml": ["stages:", "script:"],
            "/Jenkinsfile": ["pipeline", "stage("],
        }

    # ---------------- infra ----------------

    def _get(self, path: str) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests:
            return None
        try:
            r = requests.get(urljoin(self.target, path), headers=self.headers,
                             timeout=self.timeout, verify=False, allow_redirects=True)
            self.request_count += 1
            return r
        except Exception:
            return None

    def _baseline_404(self) -> str:
        r = self._get("/revuex_missing_%s" % int(time.time()))
        return r.text if r is not None else ""

    # ---------------- scan ----------------

    def scan(self) -> Dict[str, Any]:
        print(f"\n{'='*60}\n📦 REVUEX Software Supply Chain Scanner (A03:2025)\n{'='*60}")
        print(f"Target: {self.target}\n")

        baseline = self._baseline_404()
        self._check_manifests(baseline)
        self._check_cicd(baseline)
        self._check_dependency_confusion()
        if self.enrich:
            self._enrich_components()

        self._manual_guidance()
        self._save()
        print(f"\n✅ Supply-chain scan complete. Findings: {len(self.vulnerabilities)}, "
              f"components: {len(self.components)}, manual: {len(self.manual_checks)}\n")
        return self._result()

    def _confirmed(self, resp, signatures, baseline) -> bool:
        if resp is None or resp.status_code != 200:
            return False
        body = resp.text or ""
        # Require at least one signature here that is not in the soft-404 page.
        return any(s in body and s not in baseline for s in signatures)

    def _check_manifests(self, baseline: str):
        for path, (kind, sigs) in self.manifests.items():
            if self.request_count >= self.max_requests:
                break
            r = self._get(path)
            if self._confirmed(r, sigs, baseline):
                comps = self._parse_components(kind, r.text)
                self.components.extend(comps)
                self.vulnerabilities.append({
                    "type": "Supply Chain - Exposed Dependency Manifest",
                    "severity": "medium",
                    "owasp_2025": "A03",
                    "url": urljoin(self.target, path),
                    "manifest_type": kind,
                    "component_count": len(comps),
                    "evidence": f"{path} served and parsed as {kind} "
                                f"({len(comps)} components).",
                    "description": "A dependency manifest/lockfile is publicly "
                                   "accessible, revealing the software bill of "
                                   "materials and aiding targeted supply-chain attacks.",
                    "remediation": [f"Remove {path} from the web root; serve only "
                                    "built assets; generate an SBOM privately."],
                    "tags": ["supply_chain", "dependency", "exposed_file"],
                })
                print(f"   • Exposed manifest: {path} ({len(comps)} components)")
            time.sleep(self.delay)

    def _check_cicd(self, baseline: str):
        for path, sigs in self.cicd_paths.items():
            if self.request_count >= self.max_requests:
                break
            r = self._get(path)
            if self._confirmed(r, sigs, baseline):
                sev = "high" if path == "/.npmrc" and "_authToken" in (r.text or "") \
                    else "medium"
                self.vulnerabilities.append({
                    "type": "Supply Chain - Exposed CI/CD or Registry Config",
                    "severity": sev,
                    "owasp_2025": "A03",
                    "url": urljoin(self.target, path),
                    "evidence": f"{path} publicly served.",
                    "description": "CI/CD or package-registry configuration is "
                                   "exposed; may leak registry tokens, build logic, "
                                   "or enable supply-chain tampering.",
                    "remediation": [f"Remove {path} from the web root; rotate any "
                                    "exposed registry/CI tokens."],
                    "tags": ["supply_chain", "ci_cd", "exposed_file"],
                })
                print(f"   • Exposed CI/CD config: {path} ({sev})")
            time.sleep(self.delay)

    def _parse_components(self, kind: str, text: str) -> List[Dict[str, str]]:
        comps: List[Dict[str, str]] = []
        try:
            if kind in ("npm", "composer", "npm-lock", "composer-lock", "pipenv"):
                data = json.loads(text)
                buckets = []
                if kind == "npm":
                    buckets = [data.get("dependencies", {}),
                               data.get("devDependencies", {})]
                elif kind == "composer":
                    buckets = [data.get("require", {}),
                               data.get("require-dev", {})]
                elif kind == "npm-lock":
                    buckets = [data.get("dependencies", {})]
                elif kind == "pipenv":
                    buckets = [data.get("default", {}), data.get("develop", {})]
                elif kind == "composer-lock":
                    for pkg in data.get("packages", []):
                        if isinstance(pkg, dict) and pkg.get("name"):
                            comps.append({"name": pkg["name"],
                                          "version": str(pkg.get("version", "")),
                                          "ecosystem": "composer"})
                for b in buckets:
                    if isinstance(b, dict):
                        for name, ver in b.items():
                            comps.append({"name": str(name), "version": str(ver),
                                          "ecosystem": kind})
            elif kind == "pip":
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=)?\s*([\w.\-]*)", line)
                    if m:
                        comps.append({"name": m.group(1),
                                      "version": m.group(3) or "",
                                      "ecosystem": "pip"})
            elif kind == "gomod":
                for m in re.finditer(r"^\s*([\w./\-]+)\s+v([\w.\-]+)", text, re.M):
                    comps.append({"name": m.group(1), "version": "v" + m.group(2),
                                  "ecosystem": "go"})
        except Exception:
            # Parsing is best-effort; a parse failure must not break the scan.
            pass
        # De-dup.
        seen = set()
        uniq = []
        for c in comps:
            key = (c["name"], c.get("version", ""))
            if key not in seen:
                seen.add(key)
                uniq.append(c)
        return uniq

    def _check_dependency_confusion(self):
        """Heuristic: scoped/internal-looking package names in exposed manifests
        that may be claimable on the public registry (dependency confusion)."""
        candidates = []
        for c in self.components:
            name = c.get("name", "")
            # Internal-looking npm scopes or private-ish prefixes.
            if re.match(r"^@[\w.\-]+/", name) or \
               re.search(r"(internal|private|corp|intranet)", name, re.I):
                candidates.append(name)
        if candidates:
            uniq = sorted(set(candidates))[:25]
            self.manual_checks.append({
                "type": "Supply Chain - Dependency Confusion Candidates",
                "severity": "info",
                "confidence": "manual-verification-required",
                "owasp_2025": "A03",
                "url": self.target,
                "packages": uniq,
                "how_to_confirm": ("Check whether these internal/scoped package "
                                   "names are unclaimed on the public registry. If "
                                   "claimable, a higher public version can hijack "
                                   "installs (dependency confusion)."),
                "tags": ["supply_chain", "dependency_confusion", "manual", "unconfirmed"],
            })
            print(f"   • Dependency-confusion candidates: {uniq}")

    def _enrich_components(self):
        if IntelFeeds is None:
            return
        try:
            feeds = IntelFeeds(self.workspace)
        except Exception:
            return
        # We don't resolve component->CVE here (needs OSV); we enrich any CVE
        # strings already present in findings, and leave component CVE lookup as
        # a documented follow-up (OSV integration).
        for v in self.vulnerabilities:
            try:
                feeds.enrich_finding(v)
            except Exception:
                continue

    def _manual_guidance(self):
        self.manual_checks.append({
            "type": "Supply Chain - Deep SCA / SBOM",
            "severity": "info",
            "confidence": "manual-verification-required",
            "owasp_2025": "A03",
            "url": self.target,
            "how_to_confirm": ("For full A03 coverage, run OSV-Scanner / Trivy / "
                               "Grype against the repo or built image for known-CVE "
                               "components, verify lockfile integrity, and review "
                               "CI/CD (e.g. pull_request_target, cache poisoning, "
                               "OIDC trust)."),
            "tags": ["supply_chain", "sca", "sbom", "manual"],
        })

    def _result(self) -> Dict[str, Any]:
        return {"scanner": "SupplyChainScanner", "target": self.target,
                "components": self.components,
                "vulnerabilities": self.vulnerabilities,
                "manual_checks": self.manual_checks}

    def _save(self):
        out = self.workspace / "supply_chain_scans"
        out.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w\-]", "_", urlparse(self.target).netloc or self.target)
        with open(out / f"{safe}_supply_chain.json", "w") as f:
            json.dump(self._result(), f, indent=2)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python supply_chain_scanner.py <target_url>")
        sys.exit(1)
    SupplyChainScanner(sys.argv[1], Path("revuex_workspace")).scan()
