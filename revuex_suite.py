#!/usr/bin/env python3
"""
REVUEX Vul Suite v2.0 - Real-Time Status Display Version
Enhanced with live monitoring and status updates

Author: G33L0
Telegram: @x0x0h33l0
GitHub: github.com/G33L0/revuex-vul-suite
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
    SubdomainHunter,
    TechFingerprinter,
    JSSecretsMiner,
    GraphQLIntrospector,
    JWTAnalyzer,
    APKAnalyzer,
    RaceConditionTester,
    PriceManipulationScanner,
    SSRFScanner,
    EnhancedSQLiScanner,
    IDORTester,
    EnhancedXSSScanner,
    BusinessLogicAbuser,
    FileUploadTester,
    XXEScanner,
    SessionAnalyzer,
    CORSScanner,
    CSRFTester,
    DependencyChecker
)

# ================= REAL-TIME UI =================

class RealTimeStatusDisplay:
    """Real-time status display with live updates"""

    def __init__(self):
        self.current_phase = ""
        self.current_scanner = ""
        self.scanners_completed = 0
        self.total_scanners = 0
        self.findings_count = 0
        self.start_time = None

    def clear_line(self):
        sys.stdout.write('\r' + ' ' * 120 + '\r')
        sys.stdout.flush()

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗           ║
║   ██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝           ║
║   ██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝            ║
║   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗            ║
║   ██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗           ║
║   ╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝           ║
║                                                               ║
║              VUL SUITE v2.0                                   ║
║        Advanced Bug Bounty Automation Framework               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

{Fore.YELLOW}Author: {Fore.WHITE}G33L0 {Fore.YELLOW}| Telegram: {Fore.WHITE}@x0x0h33l0
{Fore.YELLOW}GitHub: {Fore.WHITE}github.com/G33L0/revuex-vul-suite
{Fore.GREEN}NEW: {Fore.WHITE}19 Advanced Security Scanners Integrated!
{Style.RESET_ALL}
"""
        print(banner)

    def print_config(self, target, mode, delay, scanners_count):
        print(f"""
{Fore.CYAN}═══════════════════════════════════════════════════════════════
{Fore.YELLOW}SCAN CONFIGURATION
{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}

{Fore.GREEN}Target:{Style.RESET_ALL}    {target}
{Fore.GREEN}Mode:{Style.RESET_ALL}      {mode}
{Fore.GREEN}Delay:{Style.RESET_ALL}     {delay}s
{Fore.GREEN}Scanners:{Style.RESET_ALL}  {scanners_count}

{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}
""")

    def start_scan(self, total_scanners):
        self.start_time = time.time()
        self.total_scanners = total_scanners
        self.scanners_completed = 0
        self.findings_count = 0

        print(f"{Fore.GREEN}Framework initialized successfully{Style.RESET_ALL}\n")

    def update_phase(self, phase_name):
        elapsed = self._elapsed()
        print(f"\n{Fore.CYAN}Phase:{Style.RESET_ALL} {phase_name} | Elapsed: {elapsed}")

    def start_scanner(self, scanner_name):
        self.scanners_completed += 1
        print(f"{Fore.BLUE}[{self.scanners_completed}/{self.total_scanners}] {scanner_name} starting...{Style.RESET_ALL}")

    def update_scanner_status(self, msg):
        self.clear_line()
        print(f"  {Fore.YELLOW}{msg}{Style.RESET_ALL}", end='', flush=True)

    def complete_scanner(self, name, findings, duration):
        self.clear_line()
        self.findings_count += findings
        status = f"{Fore.RED}{findings} findings" if findings else f"{Fore.GREEN}clean"
        print(f"{Fore.CYAN}{name}{Style.RESET_ALL} completed - {status} ({duration:.1f}s)")

    def show_error(self, name, error):
        print(f"{Fore.RED}{name} error: {error}{Style.RESET_ALL}")

    def complete_scan(self):
        print(f"\n{Fore.GREEN}SCAN COMPLETE{Style.RESET_ALL}")
        print(f"Scanners run: {self.scanners_completed}")
        print(f"Findings: {self.findings_count}")
        print(f"Total time: {self._elapsed()}")

    def _elapsed(self):
        if not self.start_time:
            return "0s"
        sec = time.time() - self.start_time
        return f"{int(sec)}s"

# ================= SUITE CORE =================

class RevuexSuite:
    """Main REVUEX Suite orchestrator"""

    def __init__(self, target, mode='sequential', delay=2.0):
        self.target = target
        self.mode = mode
        self.delay = delay
        self.workspace = self._create_workspace()

        self.logger = RevuexLogger(self.workspace)
        self.intelligence = IntelligenceHub(self.workspace)
        self.report_gen = ReportGenerator(self.workspace)

        self.status = RealTimeStatusDisplay()

        self.scanners = {
            'reconnaissance': [
                ('SubdomainHunter', SubdomainHunter),
                ('TechFingerprinter', TechFingerprinter),
                ('JSSecretsMiner', JSSecretsMiner),
            ],
            'scanning': [
                ('SSRFScanner', SSRFScanner),
                ('EnhancedSQLiScanner', EnhancedSQLiScanner),
                ('EnhancedXSSScanner', EnhancedXSSScanner),
                ('IDORTester', IDORTester),
                ('XXEScanner', XXEScanner),
                ('CORSScanner', CORSScanner),
                ('CSRFTester', CSRFTester),
                ('SessionAnalyzer', SessionAnalyzer),
                ('DependencyChecker', DependencyChecker),
            ],
            'exploitation': [
                ('GraphQLIntrospector', GraphQLIntrospector),
                ('JWTAnalyzer', JWTAnalyzer),
                ('APKAnalyzer', APKAnalyzer),
                ('BusinessLogicAbuser', BusinessLogicAbuser),
                ('FileUploadTester', FileUploadTester),
                ('RaceConditionTester', RaceConditionTester),
                ('PriceManipulationScanner', PriceManipulationScanner),
            ],
        }

    def _create_workspace(self):
        path = Path(f"scans/{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def run_full_scan(self):
        self.status.print_banner()
        total = sum(len(v) for v in self.scanners.values())
        self.status.print_config(self.target, self.mode, self.delay, total)
        self.status.start_scan(total)

        for phase in self.scanners:
            self.status.update_phase(phase.title())
            self._run_phase(phase)

        self.status.complete_scan()

    def _run_phase(self, phase):
        for name, cls in self.scanners[phase]:
            start = time.time()
            try:
                self.status.start_scanner(name)
                scanner = cls(self.target, self.workspace, self.delay)
                results = scanner.scan()
                findings = len(results.get('vulnerabilities', [])) if isinstance(results, dict) else 0
                self.status.complete_scanner(name, findings, time.time() - start)
            except Exception as e:
                self.status.show_error(name, str(e))

# ================= CLI =================

def main():
    parser = argparse.ArgumentParser(
        description="REVUEX Vul Suite v2.0 - Advanced Bug Bounty Automation"
    )

    parser.add_argument('command', choices=['full'], help='Scan mode')
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-d', '--delay', type=float, default=2.0)
    parser.add_argument('--version', action='version', version='REVUEX v2.0')

    args = parser.parse_args()

    suite = RevuexSuite(args.target, delay=args.delay)
    suite.run_full_scan()

# ================= ENTRY =================

if __name__ == "__main__":
    main()