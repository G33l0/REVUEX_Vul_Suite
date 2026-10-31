#!/usr/bin/env python3
"""
REVUEX - Out-of-Band (OOB) interaction helper

Blind SSRF / XXE / SSTI / RCE can only be *confirmed* when the target reaches
back to an attacker-controlled collector. This module provides a lightweight,
dependency-free way to:

  1. mint a unique correlation token + an OOB callback URL/hostname, and
  2. check whether that token was observed by a collector.

It supports two backends, chosen by how it is configured (no hard requirement
on any external service, so it never breaks a scan):

  - "manual"      : default. Generates payload URLs embedding a unique token and
                    tells the operator to watch their own collector (interactsh,
                    Burp Collaborator, a DNS logger, requestbin...). `poll()`
                    always returns False; confirmation is manual.
  - "http-poll"   : if a `poll_url` is provided, `poll()` GETs it and treats a
                    response body containing the token as a confirmed hit. This
                    matches self-hosted collectors that expose a lookup endpoint.

Nothing here opens a listening socket or phones home on its own.
"""

import os
import time
import uuid
from typing import Optional, Dict, Any

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


class OOBClient:
    def __init__(self, collector_domain: Optional[str] = None,
                 poll_url: Optional[str] = None, timeout: float = 6.0):
        # Collector domain may be supplied via env for CI use.
        self.collector_domain = (collector_domain
                                 or os.environ.get("REVUEX_OOB_DOMAIN"))
        self.poll_url = poll_url or os.environ.get("REVUEX_OOB_POLL_URL")
        self.timeout = timeout
        self.session_id = uuid.uuid4().hex[:8]
        self._tokens: Dict[str, Dict[str, Any]] = {}

    @property
    def mode(self) -> str:
        if self.poll_url and requests is not None:
            return "http-poll"
        return "manual"

    @property
    def enabled(self) -> bool:
        """True when a collector domain is configured so payloads can be built."""
        return bool(self.collector_domain)

    def new_token(self, label: str = "") -> Dict[str, Any]:
        """Mint a correlation token and the callback endpoints to embed."""
        token = f"{self.session_id}{uuid.uuid4().hex[:10]}"
        rec: Dict[str, Any] = {"token": token, "label": label,
                               "created": time.time(), "confirmed": False}
        if self.collector_domain:
            host = f"{token}.{self.collector_domain}".strip(".")
            rec["http_url"] = f"http://{host}/{token}"
            rec["dns_host"] = host
        else:
            # No collector configured: provide a clearly-marked placeholder so
            # the operator knows to substitute their own.
            rec["http_url"] = f"http://REPLACE-WITH-YOUR-COLLECTOR/{token}"
            rec["dns_host"] = None
        self._tokens[token] = rec
        return rec

    def poll(self, token: str) -> bool:
        """Return True if the token has been observed. Only functional in
        http-poll mode; manual mode always returns False (confirm by hand)."""
        rec = self._tokens.get(token)
        if not rec:
            return False
        if rec.get("confirmed"):
            return True
        if self.mode != "http-poll":
            return False
        try:
            r = requests.get(self.poll_url, params={"token": token},
                             timeout=self.timeout)
            if r.status_code == 200 and token in (r.text or ""):
                rec["confirmed"] = True
                return True
        except Exception:
            return False
        return False

    def guidance(self) -> str:
        if self.enabled:
            return (f"OOB mode={self.mode}, collector={self.collector_domain}. "
                    f"Embed the minted http_url/dns_host in payloads; "
                    + ("poll() will auto-confirm."
                       if self.mode == "http-poll"
                       else "confirm hits on your collector manually."))
        return ("OOB not configured. Set REVUEX_OOB_DOMAIN (and optionally "
                "REVUEX_OOB_POLL_URL) to enable blind-vuln confirmation; "
                "otherwise blind findings remain manual-verification only.")
