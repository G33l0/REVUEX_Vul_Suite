#!/usr/bin/env python3
"""
REVUEX Vul Suite v2.0 - Root Launcher
Integrated with SSTI Engine, JWT Analyzer, CSRF, Dependency Checker, and Auto-Reporting
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
from tools import (
    subdomain_hunter, tech_fingerprinter, js_secrets_miner,
    graphql_introspector, jwt_analyzer, apk_analyzer,
    race_tester, price_scanner, ssrf_scanner, sqli_scanner,
    IDOR_tester, xss_scanner, business_logic_abuser,
    file_upload_tester, xxe_scanner, session_analyzer,
    cors_scanner, csrf_tester, dependency_checker,
    ssti_engine
)

# ================= REAL-TIME UI =================
class RealTimeStatusDisplay:
    def __init__(self):
        self.scanners_completed = 0
        self.total_scanners = 0
        self.findings_count = 0
        self.findings_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

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

    def update_stats(self, results):
        """Helper to categorize findings for the report generator"""
        if isinstance(results, list):
            for item in results:
                sev = item.get('severity', 'low').lower()
                if sev in self.findings_stats:
                    self.findings_stats[sev] += 1
        elif isinstance(results, dict):
            for item in results.get('vulnerabilities', []):
                sev = item.get('severity', 'low').lower()
                if sev in self.findings_stats:
                    self.findings_stats[sev] += 1

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
        
        # Data aggregation for reporting
        self.all_vulnerabilities = []
        self.recon_data = {'subdomains': [], 'technologies': {}}

        self.scanners = {
            'reconnaissance': [
                ('SubdomainHunter', subdomain_hunter.SubdomainHunter),
                ('TechFingerprinter', tech_fingerprinter.TechFingerprinter),
                ('DependencyChecker', dependency_checker.DependencyChecker),
            ],
            'authentication_jwt': [
                ('JWTAnalyzer', jwt_analyzer.JWTAnalyzer),
                ('SessionAnalyzer', session_analyzer.SessionAnalyzer),
                ('CORSScanner', cors_scanner.CORSScanner),
                ('CSRFTester', csrf_tester.CSRFTester),
            ],
            'injection_scanning': [
                ('SSTIEngine', ssti_engine.SSTIEngine),
                ('SSRFScanner', ssrf_scanner.SSRFScanner),
                ('EnhancedSQLiScanner', sqli_scanner.EnhancedSQLiScanner),
                ('XXEScanner', xxe_scanner.XXEScanner),
                ('XSSScanner', xss_scanner.XSSScanner),
            ],
            'business_logic': [
                ('IDORTester', IDOR_tester.IDORTester),
                ('PriceScanner', price_scanner.PriceScanner),
                ('RaceTester', race_tester.RaceTester),
                ('BusinessLogicAbuser', business_logic_abuser.BusinessLogicAbuser),
            ],
            'exploitation': [
                ('FileUploadTester', file_upload_tester.FileUploadTester),
            ],
        }

    def _create_workspace(self):
        clean_target = self.target.replace("://", "_").replace("/", "_").replace(".", "_")
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

        # FINAL STEP: Report Generation
        self._generate_final_report()

    def _run_phase(self, phase):
        for name, cls in self.scanners[phase]:
            start = time.time()
            try:
                self.status.start_scanner(name)
                
                # Special cases for tool initialization
                if name == "JWTAnalyzer":
                    token = input(f"{Fore.YELLOW}   [?] Enter JWT token for analysis (or press Enter to skip): ")
                    if not token:
                        print(f"{Fore.YELLOW}   [!] Skipping JWT analysis")
                        continue
                    scanner = cls(self.target, [token], self.workspace, self.delay)
                else:
                    scanner = cls(self.target, self.workspace, self.delay)

                # Execute based on existing method names
                if hasattr(scanner, 'scan'): results = scanner.scan()
                elif hasattr(scanner, 'discover'): results = scanner.discover()
                elif hasattr(scanner, 'analyze'): results = scanner.analyze()
                else: continue

                # Collect findings for reporting
                self.status.update_stats(results)
                if isinstance(results, list):
                    self.all_vulnerabilities.extend(results)
                elif isinstance(results, dict):
                    self.all_vulnerabilities.extend(results.get('vulnerabilities', []))
                    # Extract recon data if applicable
                    if name == 'SubdomainHunter':
                        self.recon_data['subdomains'] = results.get('subdomains', [])

                findings = len(results) if isinstance(results, list) else len(results.get('vulnerabilities', []))
                self.status.complete_scanner(name, findings, time.time() - start)
                
                time.sleep(self.delay)
            except Exception as e:
                print(f"{Fore.RED}[!] Error in {name}: {str(e)}")

    def _generate_final_report(self):
        """Integration block for the ReportGenerator"""
        print(f"\n{Fore.YELLOW}📊 Aggregating data and generating professional report...")
        
        report_data = {
            'target': self.target,
            'vulnerabilities': self.all_vulnerabilities,
            'statistics': {
                'findings': self.status.findings_stats
            },
            'reconnaissance': self.recon_data,
            'confirmed_bugs': [v for v in self.all_vulnerabilities if v.get('confirmed')]
        }

        try:
            generator = ReportGenerator(self.workspace)
            report_path = generator.generate_html_report(report_data)
            print(f"{Fore.GREEN}✅ SCAN COMPLETE. Professional report generated at: {report_path}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to generate report: {str(e)}")

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
