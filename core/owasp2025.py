#!/usr/bin/env python3
"""
REVUEX - OWASP Top 10:2025 mapping layer

The suite's scanners were written against the OWASP Top 10 (2021) mental model.
The 2025 list (published Nov 2025) reorganised several categories, most notably:

  - A01 Broken Access Control  (now explicitly includes BOLA/BFLA AND SSRF,
        which is no longer a standalone category)
  - A02 Security Misconfiguration  (risen to #2)
  - A03 Software Supply Chain Failures  (new; expands "Vulnerable & Outdated
        Components")
  - A04 Cryptographic Failures
  - A05 Injection
  - A06 Insecure Design
  - A07 Authentication Failures
  - A08 Software or Data Integrity Failures
  - A09 Security Logging & Monitoring Failures
  - A10 Mishandling of Exceptional Conditions  (new; uncaught exceptions, race
        conditions, missing error handling)

This module is pure/stdlib-only so it can never raise at import time. It exposes
`annotate_finding()` which tags a finding dict with its OWASP 2025 category based
on the finding's `type`/`tags`, without overwriting an explicit mapping a scanner
already set. It is intentionally conservative: unknown findings get "unmapped".
"""

from typing import Dict, Any, List

CATEGORIES = {
    "A01": "A01:2025 Broken Access Control",
    "A02": "A02:2025 Security Misconfiguration",
    "A03": "A03:2025 Software Supply Chain Failures",
    "A04": "A04:2025 Cryptographic Failures",
    "A05": "A05:2025 Injection",
    "A06": "A06:2025 Insecure Design",
    "A07": "A07:2025 Authentication Failures",
    "A08": "A08:2025 Software or Data Integrity Failures",
    "A09": "A09:2025 Security Logging & Monitoring Failures",
    "A10": "A10:2025 Mishandling of Exceptional Conditions",
    "LLM": "OWASP LLM Top 10 (2026)",
    "API": "OWASP API Security Top 10 (2023)",
}

# Ordered (keyword, category-code). First match wins, so put specific before
# generic. Matched case-insensitively against the finding type + tags text.
_RULES = [
    # Access control / SSRF (SSRF folded into A01 in 2025) / IDOR / BOLA / BFLA
    ("ssrf", "A01"),
    ("idor", "A01"),
    ("bola", "A01"),
    ("bfla", "A01"),
    ("access control", "A01"),
    ("broken access", "A01"),
    ("authorization", "A01"),
    ("privilege", "A01"),
    # Supply chain (BEFORE misconfig so "exposed dependency manifest" maps to
    # A03 rather than the generic "exposed" -> A02 rule).
    ("supply chain", "A03"),
    ("dependency confusion", "A03"),
    ("dependency", "A03"),
    ("typosquat", "A03"),
    ("outdated component", "A03"),
    ("vulnerable component", "A03"),
    ("ci/cd", "A03"),
    ("malicious package", "A03"),
    # Misconfiguration
    ("misconfig", "A02"),
    ("security header", "A02"),
    ("directory listing", "A02"),
    ("default cred", "A02"),
    ("debug", "A02"),
    ("exposed", "A02"),
    ("cors", "A02"),
    ("verbose error", "A02"),
    # Crypto
    ("jwt", "A04"),
    ("crypto", "A04"),
    ("weak secret", "A04"),
    ("tls", "A04"),
    ("ssl", "A04"),
    ("entropy", "A04"),
    # Injection
    ("sqli", "A05"),
    ("sql injection", "A05"),
    ("nosql", "A05"),
    ("xss", "A05"),
    ("ssti", "A05"),
    ("injection", "A05"),
    ("xxe", "A05"),
    ("command inj", "A05"),
    ("template injection", "A05"),
    # Insecure design / business logic
    ("business logic", "A06"),
    ("price manipulation", "A06"),
    ("insecure design", "A06"),
    ("workflow", "A06"),
    # AuthN
    ("session", "A07"),
    ("authentication", "A07"),
    ("csrf", "A07"),
    ("credential", "A07"),
    ("login", "A07"),
    # Integrity
    ("deserial", "A08"),
    ("integrity", "A08"),
    ("file upload", "A08"),
    ("insecure deserialization", "A08"),
    # Logging
    ("logging", "A09"),
    ("monitoring", "A09"),
    # Exceptional conditions
    ("race condition", "A10"),
    ("race", "A10"),
    ("exceptional condition", "A10"),
    ("uncaught", "A10"),
    ("denial of service", "A10"),
    # LLM / AI / MCP
    ("prompt injection", "LLM"),
    ("llm", "LLM"),
    ("mcp", "LLM"),
    ("ai agent", "LLM"),
    ("agent", "LLM"),
    ("excessive agency", "LLM"),
    ("system prompt", "LLM"),
    # API
    ("graphql", "API"),
    ("mass assignment", "API"),
    ("api", "API"),
]


def classify(text: str) -> str:
    """Return an OWASP 2025 category code for a blob of text, or 'unmapped'."""
    t = (text or "").lower()
    for keyword, code in _RULES:
        if keyword in t:
            return code
    return "unmapped"


def annotate_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Add `owasp_2025` (and human-readable `owasp_2025_name`) to a finding,
    unless the scanner already set `owasp_2025`. Never raises; returns the same
    dict for chaining."""
    if not isinstance(finding, dict):
        return finding
    if finding.get("owasp_2025"):
        code = finding["owasp_2025"]
    else:
        blob = " ".join([
            str(finding.get("type", "")),
            " ".join(str(t) for t in finding.get("tags", []) if t is not None),
        ])
        code = classify(blob)
        finding["owasp_2025"] = code
    finding["owasp_2025_name"] = CATEGORIES.get(code, "Unmapped / needs triage")
    return finding


def annotate_all(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Annotate a list of findings in place and return it. Tolerates non-dicts."""
    if not isinstance(findings, list):
        return findings
    for f in findings:
        try:
            annotate_finding(f)
        except Exception:
            # Mapping must never break a scan.
            continue
    return findings
