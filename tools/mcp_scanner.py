#!/usr/bin/env python3
"""
REVUEX - MCP / AI-Agent Security Scanner  (2026)

The Model Context Protocol (MCP) became the dominant new attack surface in 2026:
NVD-tracked CVEs mentioning MCP/AI-agents jumped from a handful in 2025 to
hundreds in 2026, with command injection and missing authentication the most
common patterns, plus malicious-server registration and tool-description prompt
injection. Guidance: NSA "MCP Security Design Considerations" (May 2026) and the
OWASP LLM Top 10 (2026).

This scanner probes an HTTP(S) endpoint that may speak MCP (JSON-RPC 2.0) for:

  - An MCP server exposed WITHOUT authentication (tools/list succeeds anon)
  - Tool definitions whose descriptions carry prompt-injection / instruction text
  - Dangerous tool surface (shell/exec/file/http tools reachable)
  - Server metadata / capability disclosure

Discipline: it first confirms the endpoint actually behaves like an MCP/JSON-RPC
server (correct response shape). Everything else is reported only on that basis;
anything it cannot confirm is emitted as a manual_check, never a fake finding.

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


class MCPScanner:
    def __init__(self, target: str, workspace: Path, delay: float = 2.0):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.workspace = Path(workspace)
        self.delay = delay
        self.timeout = 12
        self.max_requests = 40
        self.request_count = 0
        self.headers = {
            "User-Agent": "REVUEX-MCPScanner/1.0 (Security Research; +https://github.com/G33L0)",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.manual_checks: List[Dict[str, Any]] = []

        self.candidate_paths = [
            "", "/mcp", "/mcp/", "/sse", "/messages", "/message",
            "/rpc", "/jsonrpc", "/api/mcp", "/v1/mcp", "/mcp/sse",
        ]
        # Tool names that indicate a high-impact surface if reachable.
        self.dangerous_tool_re = re.compile(
            r"(shell|exec|command|run_|subprocess|spawn|eval|"
            r"read_file|write_file|delete|fs_|filesystem|"
            r"http_request|fetch|request|sql|query|database)",
            re.I)

    # ---------------- infra ----------------

    def _rpc(self, url: str, method: str, params: Optional[dict] = None,
             rpc_id: int = 1) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests:
            return None
        payload = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
        if params is not None:
            payload["params"] = params
        try:
            r = requests.post(url, headers=self.headers, json=payload,
                              timeout=self.timeout, verify=False)
            self.request_count += 1
            return r
        except Exception:
            return None

    @staticmethod
    def _parse_json(resp: requests.Response) -> Optional[dict]:
        if resp is None:
            return None
        text = resp.text or ""
        # MCP over SSE wraps JSON in "data: {...}" lines.
        if "data:" in text and "{" in text:
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    frag = line[5:].strip()
                    try:
                        return json.loads(frag)
                    except Exception:
                        continue
        try:
            return resp.json()
        except Exception:
            try:
                return json.loads(text)
            except Exception:
                return None

    def _looks_like_mcp(self, data: dict) -> bool:
        """A JSON-RPC 2.0 response shape (result/error + jsonrpc/id)."""
        if not isinstance(data, dict):
            return False
        if data.get("jsonrpc") == "2.0" and ("result" in data or "error" in data):
            return True
        # Some servers answer initialize with capabilities/serverInfo.
        res = data.get("result")
        if isinstance(res, dict) and (res.get("capabilities") or res.get("serverInfo")
                                      or res.get("protocolVersion")):
            return True
        return False

    # ---------------- scan ----------------

    def scan(self) -> Dict[str, Any]:
        print(f"\n{'='*60}\n🤖 REVUEX MCP / AI-Agent Security Scanner (2026)\n{'='*60}")
        print(f"Target: {self.target}\n")

        endpoint, init_data = self._discover_endpoint()
        if not endpoint:
            print("   ✓ No MCP/JSON-RPC server detected at common paths.")
            self.manual_checks.append({
                "type": "MCP - Endpoint Discovery",
                "severity": "info",
                "confidence": "manual-verification-required",
                "url": self.target,
                "how_to_confirm": ("No MCP server auto-detected. If the service "
                                   "exposes MCP over a non-standard path/transport "
                                   "(stdio, websocket), test it directly with an "
                                   "MCP client."),
                "tags": ["mcp", "ai_agent", "manual", "unconfirmed"],
            })
            self._save()
            return self._result()

        print(f"   ✓ MCP/JSON-RPC server detected at: {endpoint}")
        self._check_unauth_access(endpoint, init_data)
        time.sleep(self.delay)
        self._analyze_tools(endpoint)

        self._save()
        print(f"\n✅ MCP scan complete. Findings: {len(self.vulnerabilities)}, "
              f"manual: {len(self.manual_checks)}\n")
        return self._result()

    def _discover_endpoint(self):
        for path in self.candidate_paths:
            url = urljoin(self.target, path) if path else self.target
            resp = self._rpc(url, "initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "revuex", "version": "1.0"},
            })
            data = self._parse_json(resp)
            if data and self._looks_like_mcp(data):
                return url, data
            time.sleep(self.delay)
        return None, None

    def _check_unauth_access(self, endpoint: str, init_data: dict):
        """We reached the server with no credentials. If tools/list also works
        anonymously, the server is unauthenticated."""
        resp = self._rpc(endpoint, "tools/list", {})
        data = self._parse_json(resp)
        tools = []
        if isinstance(data, dict) and isinstance(data.get("result"), dict):
            tools = data["result"].get("tools", []) or []

        if tools or (isinstance(data, dict) and "result" in data):
            server_info = ""
            if isinstance(init_data.get("result"), dict):
                si = init_data["result"].get("serverInfo", {})
                server_info = f"{si.get('name','?')} {si.get('version','')}".strip()
            self.vulnerabilities.append({
                "type": "MCP - Unauthenticated Server Access",
                "severity": "high",
                "owasp_2025": "A01",
                "url": endpoint,
                "server_info": server_info,
                "evidence": f"initialize + tools/list succeeded with no auth; "
                            f"{len(tools)} tool(s) enumerated.",
                "description": "MCP server accepts JSON-RPC calls (initialize, "
                               "tools/list) without authentication, exposing its "
                               "tool surface to anonymous clients.",
                "remediation": ["Require authentication/authorization on the MCP "
                                "transport; scope tools per client; follow NSA MCP "
                                "guidance (May 2026)."],
                "tags": ["mcp", "ai_agent", "unauth", "access_control"],
            })
            print(f"   • Unauthenticated MCP access ({len(tools)} tools)")

    def _analyze_tools(self, endpoint: str):
        resp = self._rpc(endpoint, "tools/list", {})
        data = self._parse_json(resp)
        if not (isinstance(data, dict) and isinstance(data.get("result"), dict)):
            return
        tools = data["result"].get("tools", []) or []

        dangerous = []
        injected = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", ""))
            desc = str(tool.get("description", ""))
            if self.dangerous_tool_re.search(name) or self.dangerous_tool_re.search(desc):
                dangerous.append(name or "(unnamed)")
            # Tool-description prompt injection: imperative instructions aimed at
            # the *agent* embedded in a tool description.
            if re.search(r"(ignore (all |the )?(previous|above) instruction|"
                         r"system prompt|you must|always (call|use|run)|"
                         r"do not tell|exfiltrat|print your|reveal)", desc, re.I):
                injected.append(name or "(unnamed)")

        if dangerous:
            self.vulnerabilities.append({
                "type": "MCP - Dangerous Tool Surface Exposed",
                "severity": "high",
                "owasp_2025": "LLM",
                "url": endpoint,
                "tools": dangerous[:20],
                "evidence": f"Tools implying code/file/network/db access: "
                            f"{', '.join(dangerous[:10])}",
                "description": "MCP server exposes high-impact tools (command/file/"
                               "network/database). If callable by untrusted input, "
                               "this enables RCE/SSRF/data access via the agent.",
                "remediation": ["Gate dangerous tools behind explicit authz and "
                                "human-in-the-loop; validate/sandbox tool inputs."],
                "tags": ["mcp", "ai_agent", "excessive_agency", "command_injection"],
            })
            print(f"   • Dangerous tools: {dangerous[:10]}")

        if injected:
            self.vulnerabilities.append({
                "type": "MCP - Prompt Injection in Tool Descriptions",
                "severity": "high",
                "owasp_2025": "LLM",
                "url": endpoint,
                "tools": injected[:20],
                "evidence": f"Instruction-like text in description of: "
                            f"{', '.join(injected[:10])}",
                "description": "Tool descriptions contain imperative text targeting "
                               "the agent (indirect prompt injection). A malicious "
                               "or compromised server can hijack agent behaviour.",
                "remediation": ["Treat tool metadata as untrusted; strip/record "
                                "instructions; pin trusted servers."],
                "tags": ["mcp", "ai_agent", "prompt_injection"],
            })
            print(f"   • Prompt-injection in tool descriptions: {injected[:10]}")

    def _result(self) -> Dict[str, Any]:
        return {"scanner": "MCPScanner", "target": self.target,
                "vulnerabilities": self.vulnerabilities,
                "manual_checks": self.manual_checks}

    def _save(self):
        out = self.workspace / "mcp_scans"
        out.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w\-]", "_", urlparse(self.target).netloc or self.target)
        with open(out / f"{safe}_mcp.json", "w") as f:
            json.dump(self._result(), f, indent=2)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python mcp_scanner.py <target_url>")
        sys.exit(1)
    MCPScanner(sys.argv[1], Path("revuex_workspace")).scan()
