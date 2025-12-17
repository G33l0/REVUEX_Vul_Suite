#!/usr/bin/env python3
"""
REVUEX Vul Suite v2.0 - Root Launcher
Integrated with SSTI Engine and SSL Fixes
"""

import sys
import time
import argparse
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ================= CORE IMPORTS =================
from core.logger import RevuexLogger
from core.intelligence_hub import IntelligenceHub
from core.report_generator import ReportGenerator

# ================= SCANNER IMPORTS =================
# Ensure ssti_engine is inside the tools/ directory
from tools import (
    subdomain_hunter, tech_fingerprinter, js_secrets_miner,
    graphql_introspector, jwt_analyzer, apk_analyzer,
    race_tester, price_scanner, ssrf_scanner, sqli_scanner,
    IDOR_tester, xss_scanner, business_logic_abuser,
    file_upload_tester, xxe_scanner, session_analyzer,
    cors_scanner, csrf_tester, dependency_checker,
    ssti_engine  # <--- New Tool
)

# ================= REAL-TIME UI =================
class RealTimeStatusDisplay:
    def __init__(self):
        self.scanners_completed = 0
        self.total_scanners = 0
        self.findings_count = 0
        self.start_time = None

    def print_banner(self):
        banner = f"""{Fore.CYAN}
   ██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
   ██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
   ██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
   ██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
   ╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
                      VUL SUITE v2.0
"""
        print(banner)

    def print_config(self, target, mode, delay, scanners_count):
        print(f"{Fore.YELLOW}SCAN CONFIGURATION{Fore.CYAN}\nTarget: {target} | Mode: {mode} | Scanners: {scanners_count}\n")

    def start_scanner(self, scanner_name):
        self.scanners_completed += 1
        print(f"{Fore.BLUE}[{self.scanners_completed}/{self.total_scanners}] {scanner_name} starting...")

    def complete_scanner(self, name, findings, duration):
        self.findings_count += findings
        status = f"{Fore.RED}{findings} findings" if findings else f"{Fore.GREEN}clean"
        print(f"{Fore.CYAN}{name}{Style.RESET_ALL} completed - {status} ({duration:.1f}s)")

# ================= SUITE CORE =================
class RevuexSuite:
    def __init__(self, target, mode='sequential', delay=2.0):
        self.target = target
        self.mode = mode
        self.delay = delay
        self.workspace = self._create_workspace()
        self.logger = RevuexLogger(self.workspace)
        self.status = RealTimeStatusDisplay()

        self.scanners = {
            'reconnaissance': [
                ('SubdomainHunter', subdomain_hunter.SubdomainHunter),
                ('TechFingerprinter', tech_fingerprinter.TechFingerprinter),
            ],
            'scanning': [
                ('SSTIEngine', ssti_engine.SSTIEngine), # <--- Integrated
                ('SSRFScanner', ssrf_scanner.SSRFScanner),
                ('EnhancedSQLiScanner', sqli_scanner.EnhancedSQLiScanner),
                ('XXEScanner', xxe_scanner.XXEScanner),
            ],
            'exploitation': [
                ('FileUploadTester', file_upload_tester.FileUploadTester),
            ],
        }

    def _create_workspace(self):
        # Clean target name for folder creation
        clean_target = self.target.replace("://", "_").replace("/", "_")
        path = Path(f"scans/{clean_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def run_full_scan(self):
        self.status.print_banner()
        total = sum(len(v) for v in self.scanners.values())
        self.status.total_scanners = total
        self.status.print_config(self.target, self.mode, self.delay, total)

        for phase in self.scanners:
            print(f"\n{Fore.MAGENTA}--- PHASE: {phase.upper()} ---")
            self._run_phase(phase)

        print(f"\n{Fore.GREEN}SCAN COMPLETE. Findings saved to {self.workspace}")

    def _run_phase(self, phase):
        for name, cls in self.scanners[phase]:
            start = time.time()
            try:
                self.status.start_scanner(name)
                # Ensure tools inherit from BaseScanner correctly
                scanner = cls(self.target, self.workspace, self.delay)
                results = scanner.scan()

                # Handle different return types (List or Dict)
                findings = 0
                if isinstance(results, list):
                    findings = len(results)
                elif isinstance(results, dict):
                    findings = len(results.get('vulnerabilities', []))

                self.status.complete_scanner(name, findings, time.time() - start)
            except Exception as e:
                print(f"{Fore.RED}[!] Error in {name}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="REVUEX Vul Suite v2.0")
    parser.add_argument('command', choices=['full'], help='Scan mode')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-d', '--delay', type=float, default=2.0)
    args = parser.parse_args()

    suite = RevuexSuite(args.target, delay=args.delay)
    suite.run_full_scan()

if __name__ == "__main__":
    main()
