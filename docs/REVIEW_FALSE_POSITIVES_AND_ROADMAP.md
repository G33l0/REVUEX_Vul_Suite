# REVUEX Suite — False-Positive Review & Modernization Roadmap

**Reviewer:** Claude Code · **Date:** 2026-10-30
**Scope:** detection logic of the 19 scanners + core, focusing on false positives.

---

## 1. Summary of what was wrong

The suite had a **systemic false-positive problem**. Two distinct classes:

### Class A — Fabricated findings (most serious)
Several "tests" appended hard-coded `critical`/`high` vulnerabilities **without
making or validating any HTTP request**. They fired against *any* target —
even a host that never responded — and some even embedded fake
`request`/`response`/`evidence` text describing attacks that never happened.
Running the suite against a benign site produced a page full of fake criticals.

| Scanner | Fabricated tests (before) |
|---|---|
| `ssrf_scanner` | **all 4** (basic, cloud-metadata, internal-net, bypasses) always reported |
| `business_logic_abuser` | **all 8** (payment, coupon, checkout, quantity, state, multi-step, refund, subscription) — never sent a request, fake "Payment successful" evidence |
| `session_analyzer` | fixation, concurrent-sessions, timeout always reported |
| `csrf_tester` | "Token Not Validated" (critical) always reported |
| `xxe_scanner` | blind, SVG, parameter-entity, SOAP always reported |

### Class B — Trivial-signal / naive-match false positives
Findings fired on signals that are true for almost every site:

| Scanner | False-positive trigger (before) |
|---|---|
| `sqli_scanner` | UNION/NoSQL flagged on `status == 200`; WAF flagged on `status != 403`; error/fingerprint matched the bare word `mysql`/`postgresql`/`sqlite` anywhere in the page; time-based used one sample (+4 s) → network jitter FPs; boolean summed unequal groups |
| `ssti_engine` | `"49" in body` (from `{{7*7}}`) — matches any page with "49"; also fired when the literal `{{7*7}}` was merely reflected, not evaluated |
| `jwt_analyzer` | "accepted" = `status < 400` (any public 200 page); every RS256 token flagged as algorithm-confusion `high`; `role`/`admin` substring flagged as a "sensitive data leak" |
| `js_secrets_miner` | generic `token=`/`api_key=`/`password=` regexes with no entropy check → matched minified identifiers, i18n strings, placeholders |
| `graphql_introspector` | field *named* `password`/`key`/`card` reported as `high` data exposure (matched `keyboard`, `cardinality`, etc.) |
| `file_upload_tester` | HTTP 200 on upload reported as confirmed **critical RCE** (acceptance ≠ stored ≠ executable) |
| `cors_scanner` | *(already correct — validates real ACAO/ACAC headers; left as-is)* |

---

## 2. What was fixed (this branch)

Guiding principle: **a finding is only reported when there is concrete,
differential evidence.** Where a flaw genuinely cannot be auto-confirmed
(OOB blind XXE, session fixation needing login, business-logic flows), the item
is emitted to a separate `manual_checks` list with `severity: info` and
`confidence: manual-verification-required` — useful guidance that never inflates
the confirmed-finding count.

Key mechanics introduced:
- **Baselines + differentials** (SSRF, SQLi, JWT, NoSQL): compare payload
  responses against a benign baseline so "the page always returns this" can't
  masquerade as a finding.
- **Content-specific signatures** (SQLi error strings, XXE file contents)
  instead of bare keywords.
- **Re-test confirmation** for timing (SQLi time-based requires two delayed
  responses over a *median* baseline).
- **High-entropy markers** (SSTI uses `1733*1733=3003289` and verifies the raw
  expression was *evaluated*, not reflected).
- **Entropy gating + placeholder filters** for generic secret patterns
  (provider-specific patterns like `AKIA…`, `ghp_…`, `sk_live_…` kept as-is).
- **Scoping** (session cookie flags only on session/auth cookies; GraphQL
  keyword match is word-boundary aware).
- **Honest severity** (file-upload acceptance → `impact_confirmed: false` with
  a verification step, not auto-"critical RCE").

**Verification:** against a benign mock server the six worst offenders now report
**0** confirmed vulnerabilities (was dozens); against mock vulnerable servers
SSRF and SQLi still detect true positives. (Test harness in session scratchpad.)

### Still-open code issues noted (not false-positive scope, but real bugs)
- `tools/xss_scanner.py` and `tools/race_tester.py` are **incomplete stubs** —
  `scan()`/`test()` reference methods that don't exist; they will `AttributeError`
  at runtime. XSS also needs reflection-*context* + execution awareness (a
  reflected payload that is HTML-encoded is not XSS).
- `core/safety_checks.py` and `core/init.py` contain **smart-quote characters**
  (`“ ”`) and do not parse. `core/init.py` should be `core/__init__.py`.
- `base_scanner.safe_request` hard-codes `verify=False` globally; make TLS
  verification opt-out per-scan, not the default.

---

## 3. Modernization roadmap (the tool was built ~10 months ago)

Detection coverage should be refreshed for 2025–2026 bug-bounty/pentest reality.

### 3.1 New / high-value vulnerability classes to add
- **OWASP API Security Top 10 (2023)** — the suite is web-page oriented; APIs
  are where the money is. Add BOLA/BFLA (object- and function-level authZ — your
  `IDOR_tester` is a start; extend to REST/GraphQL method & field authz),
  mass assignment, and unrestricted resource consumption.
- **AI/LLM app vulns (OWASP LLM Top 10)** — prompt injection, insecure output
  handling, system-prompt/secret leakage, tool/function-call abuse. Fast-growing
  bounty category.
- **Server-Side Request Forgery escalations** — gopher/dict smuggling, DNS
  rebinding, IMDSv2 `PUT`-token flows (your SSRF now checks metadata content;
  add rebinding + IMDSv2).
- **HTTP Request Smuggling / desync** (CL.TE, TE.CL, CL.0, H2.TE) and
  **Web Cache Deception / Poisoning** — major 2023–2025 classes, entirely absent.
- **Single-packet race conditions** (Kettle's HTTP/2 technique) — your
  `race_tester` is a stub; implement last-byte-sync / single-packet attack.
- **Prototype pollution** (client + server) and **DOM clobbering**.
- **GraphQL** — batching/alias-based brute force, query-depth/complexity DoS,
  field-level authz, injection via resolvers (extend `graphql_introspector`).
- **OAuth/OIDC/SAML misconfig** — redirect_uri bypass, PKCE downgrade, `state`
  CSRF, SAML signature wrapping.
- **Dependency confusion / typosquatting** and **CI/CD + supply-chain**
  (GitHub Actions `pull_request_target`, poisoned caches, leaked OIDC) — extend
  `dependency_checker` beyond known-CVE lookups.
- **Recent framework RCEs** — keep a living payload set for Spring (Spring4Shell),
  JNDI/Log4Shell-style lookups, Next.js middleware auth bypass, deserialization
  gadgets (Java/.NET/PHP/Python pickle), template engines.
- **Client-side path traversal**, **CSPT→XSS/CSRF chains**, **postMessage** abuse.

### 3.2 Engineering improvements (quality > quantity of scanners)
- **Correlate with a real CVE/vuln feed** at runtime: NVD 2.0 API, OSV.dev,
  GitHub Security Advisories (GHSA), CISA KEV (known-exploited), and EPSS scores
  so findings are prioritized by *real-world exploitation probability*, not a
  hard-coded "$120K–$360K" claim.
- **Confidence model**: every finding should carry `confidence` +
  `evidence` + `reproduction` (this branch starts that); feed it into
  `report_generator` so reports separate *confirmed* from *needs-verification*.
- **Active confirmation hooks**: out-of-band interaction server (self-hosted
  interactsh/Collaborator-style) so blind SSRF/XXE/SSTI can be *confirmed*, not
  just listed as manual.
- **Finish/standardize the base class**: all scanners should inherit
  `BaseScanner` (rate limit, scope allow-list, request budget, logging). Today
  several reimplement `requests.get` and ignore `is_safe_url`/scope.
- **Scope & safety controls**: explicit in-scope host allow-list, `robots`/rate
  awareness, and a dry-run mode; don't default `verify=False`.
- **Dedup & fingerprinting**: hash (type, param, evidence) to collapse repeats;
  per-finding CWE + CVSS vector (not a single hard-coded score).
- **Tests**: add a `tests/` suite with mock vulnerable/benign servers (the
  benign-target "zero findings" assertion used in this review makes a great
  regression gate against future fabricated findings).

---

## 4. Repos worth integrating (more / deeper vulnerabilities)

REVUEX is web/app-surface focused. The biggest coverage gains come from
(a) best-in-class scanning engines and (b) crossing into **binary / mobile /
firmware / smart-contract** reverse engineering — where **REA** fits.

### 4.1 REA — "Reverse Engineer Anything" (the one you asked about)
<https://github.com/morluto/rea>
- **What it is:** an MCP server + CLI (`rea-agents`) that reverse-engineers
  native binaries (Ghidra/IDA/Hopper/Rizin), ELF/PE structure & mitigations,
  APKs (JADX), Flutter, .NET, Electron/JS, firmware (Binwalk/Unblob), WASM,
  **EVM bytecode**, crash reports, PCAP/HAR, and runtime behaviour.
- **Why integrate:** it covers the layer REVUEX doesn't. Natural fits:
  - Supercharge `apk_analyzer` → call REA's APK/JADX + Flutter + IL2CPP analysis
    for deep static review (hardcoded secrets, exported components, native libs).
  - New **binary/firmware** scanner module: ELF mitigation gaps (no NX/PIE/
    RELRO/canary), PE cert issues, embedded deps/secrets.
  - New **smart-contract** surface via EVM bytecode analysis.
  - Confirm `js_secrets_miner` hits by decompiling Electron/JS bundles.
- **How:** REA is already an **MCP server** (`npx rea-agents setup`), so an
  agent-driven REVUEX can call it directly; or shell out to
  `rea analyze-* --json` and fold results into `report_generator`.
  *Note:* native decompilation needs a licensed engine (Ghidra is free).

### 4.2 Web / recon engines to orchestrate (don't reinvent)
- **Nuclei** (`projectdiscovery/nuclei`) — 9k+ community templates, updated
  continuously; the single highest-ROI integration for fresh CVE/misconfig
  coverage. Run it and ingest its JSON.
- **ProjectDiscovery suite** — `subfinder`/`dnsx` (replace `subdomain_hunter`),
  `httpx` (fingerprinting), `katana` (crawl), `naabu` (ports),
  **`interactsh`** (OOB confirmation — closes the blind-vuln gap above).
- **Nikto / testssl.sh** — server & TLS hygiene.

### 4.3 Dependency, secret & supply-chain feeds
- **OSV-Scanner** (`google/osv-scanner`) + **Trivy** / **Grype** — SCA across
  lockfiles, containers, SBOMs → feed `dependency_checker`.
- **TruffleHog** / **Gitleaks** — verified-secret detection (they *validate*
  keys against the provider), far lower FP than regex-only; pair with the
  entropy gate now in `js_secrets_miner`.
- **CISA KEV + EPSS + OSV.dev + NVD 2.0** data feeds — prioritization.

### 4.4 Exploitation / confirmation references
- **PayloadsAllTheThings** and **SecLists** — keep the `payloads/` directory in
  sync with these instead of hand-maintained lists.
- **sqlmap** — use as a confirmation engine behind `sqli_scanner`'s candidates
  rather than trying to match its depth.

---

## 5. Suggested priority order
1. **(done)** Stop fabricating findings — this branch.
2. Finish/replace the stub scanners (XSS, race) and fix the broken `core/` files.
3. Add an **OOB interaction server** + **Nuclei** ingestion — biggest coverage/
   confidence jump for least code.
4. Wire **REA** (MCP) for binary/mobile/firmware/EVM depth.
5. Add CVE/KEV/EPSS prioritization + a confidence-aware report format.
6. Add the regression test harness (benign target ⇒ 0 findings).
