#!/usr/bin/env python3
"""
REVUEX Vulnerability Suite - Master Orchestrator
Advanced Bug Bounty Automation Framework

Author: G33L0
Telegram: @x0x0h33l0
GitHub: github.com/G33L0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
The author is not responsible for any misuse or damage caused by this tool.
Always ensure you have explicit permission before testing any systems.
Use responsibly and ethically.
"""

import argparse
import json
import time
import sys
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio

# Import all REVUEX tools
from tools.subdomain_hunter import SubdomainHunter
from tools.tech_fingerprinter import TechFingerprinter
from tools.js_secrets_miner import JSSecretsMiner
from tools.graphql_introspector import GraphQLIntrospector
from tools.jwt_analyzer import JWTAnalyzer
from tools.apk_analyzer import APKAnalyzer
from tools.race_tester import RaceConditionTester
from tools.price_scanner import PriceManipulationScanner
from core.intelligence_hub import IntelligenceHub
from core.report_generator import ReportGenerator
from core.logger import RevuexLogger

__author__ = "G33L0"
__version__ = "1.0"
__telegram__ = "@x0x0h33l0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    """Display REVUEX banner in hacker style"""
    banner = f"""{Colors.BOLD}{Colors.CYAN}
    ██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
    ██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
    ██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
    ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
    ██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
                                                        
    ██╗   ██╗██╗   ██╗██╗         ███████╗██╗   ██╗██╗████████╗███████╗
    ██║   ██║██║   ██║██║         ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
    ██║   ██║██║   ██║██║         ███████╗██║   ██║██║   ██║   █████╗  
    ╚██╗ ██╔╝██║   ██║██║         ╚════██║██║   ██║██║   ██║   ██╔══╝  
     ╚████╔╝ ╚██████╔╝███████╗    ███████║╚██████╔╝██║   ██║   ███████╗
      ╚═══╝   ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
{Colors.END}
{Colors.BOLD}{Colors.GREEN}        Advanced Bug Bounty Automation Framework v{__version__}{Colors.END}
{Colors.BOLD}{Colors.YELLOW}        Author: {__author__} | Telegram: {__telegram__}{Colors.END}
{Colors.BOLD}{Colors.MAGENTA}        github.com/G33L0/revuex-vul-suite{Colors.END}
{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
    """
    print(banner)

class RevuexSuite:
    """Main orchestrator for REVUEX Vulnerability Suite"""
    
    def __init__(self, target, execution_mode='sequential', delay=2):
        """
        Initialize REVUEX Suite
        
        Args:
            target: Target domain
            execution_mode: 'sequential' or 'parallel'
            delay: Delay between requests (seconds)
        """
        self.target = target
        self.execution_mode = execution_mode
        self.delay = delay
        self.start_time = datetime.now()
        
        # Setup workspace
        self.workspace = Path(f"./revuex_workspace/{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.intel = IntelligenceHub(self.workspace)
        self.logger = RevuexLogger(self.workspace)
        self.report_gen = ReportGenerator(self.workspace)
        
        # Statistics
        self.stats = {
            'phase': 'Initializing',
            'progress': 0,
            'total_steps': 0,
            'completed_steps': 0,
            'findings': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        self.logger.log_info(f"REVUEX Suite initialized for {target}")
        self.logger.log_info(f"Execution mode: {execution_mode}")
        self.logger.log_info(f"Workspace: {self.workspace}")
    
    def update_progress(self, phase, step=None, total=None):
        """Update progress tracking"""
        self.stats['phase'] = phase
        if step and total:
            self.stats['completed_steps'] = step
            self.stats['total_steps'] = total
            self.stats['progress'] = int((step / total) * 100)
        
        # Display progress
        progress_bar = '█' * (self.stats['progress'] // 5) + '░' * (20 - self.stats['progress'] // 5)
        print(f"\r{Colors.CYAN}[{progress_bar}] {self.stats['progress']}% - {phase}{Colors.END}", end='', flush=True)
    
    def phase_1_reconnaissance(self):
        """PHASE 1: Reconnaissance - Sequential Execution"""
        print(f"\n\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}║         PHASE 1: RECONNAISSANCE                            ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.END}\n")
        
        self.update_progress("Phase 1: Reconnaissance", 0, 3)
        
        try:
            # Step 1: Subdomain Discovery
            print(f"\n{Colors.YELLOW}[1/3] SubdomainHunter Pro - Discovering subdomains...{Colors.END}")
            self.logger.log_info("Starting subdomain discovery")
            
            subdomain_hunter = SubdomainHunter(self.target, self.workspace, self.delay)
            subdomains = subdomain_hunter.discover()
            
            self.intel.add_subdomains(subdomains)
            self.logger.log_success(f"Found {len(subdomains)} subdomains")
            print(f"{Colors.GREEN}    ✓ Found {len(subdomains)} subdomains{Colors.END}")
            
            time.sleep(self.delay)
            self.update_progress("Subdomain Discovery Complete", 1, 3)
            
            # Step 2: Technology Fingerprinting
            print(f"\n{Colors.YELLOW}[2/3] TechStack Fingerprinter - Identifying technologies...{Colors.END}")
            self.logger.log_info("Starting technology fingerprinting")
            
            tech_count = 0
            for idx, subdomain in enumerate(subdomains):
                print(f"{Colors.CYAN}    [{idx+1}/{len(subdomains)}] Fingerprinting {subdomain}...{Colors.END}")
                
                fingerprinter = TechFingerprinter(subdomain, self.workspace, self.delay)
                tech_stack = fingerprinter.identify()
                
                self.intel.add_technology(subdomain, tech_stack)
                tech_count += len(tech_stack.get('technologies', []))
                
                if tech_stack.get('technologies'):
                    print(f"{Colors.GREEN}        ✓ {', '.join(tech_stack['technologies'][:3])}{Colors.END}")
                
                time.sleep(self.delay)
            
            self.logger.log_success(f"Identified {tech_count} technologies")
            print(f"{Colors.GREEN}    ✓ Technology fingerprinting complete{Colors.END}")
            
            self.update_progress("Technology Fingerprinting Complete", 2, 3)
            
            # Step 3: JavaScript Secrets Mining
            print(f"\n{Colors.YELLOW}[3/3] JavaScript Secrets Miner - Extracting endpoints & secrets...{Colors.END}")
            self.logger.log_info("Starting JavaScript analysis")
            
            total_endpoints = 0
            total_secrets = 0
            
            for idx, subdomain in enumerate(subdomains):
                print(f"{Colors.CYAN}    [{idx+1}/{len(subdomains)}] Mining {subdomain}...{Colors.END}")
                
                js_miner = JSSecretsMiner(subdomain, self.workspace, self.delay)
                findings = js_miner.mine()
                
                self.intel.add_endpoints(subdomain, findings.get('endpoints', []))
                self.intel.add_secrets(subdomain, findings.get('secrets', {}))
                
                total_endpoints += len(findings.get('endpoints', []))
                total_secrets += len(findings.get('secrets', {}).get('api_keys', [])) + \
                                len(findings.get('secrets', {}).get('tokens', []))
                
                if findings.get('endpoints'):
                    print(f"{Colors.GREEN}        ✓ {len(findings['endpoints'])} endpoints, {total_secrets} secrets{Colors.END}")
                
                time.sleep(self.delay)
            
            self.logger.log_success(f"Extracted {total_endpoints} endpoints, {total_secrets} secrets")
            print(f"{Colors.GREEN}    ✓ JavaScript mining complete{Colors.END}")
            
            self.update_progress("Reconnaissance Complete", 3, 3)
            
            # Save reconnaissance database
            self.intel.save_recon_database()
            print(f"\n{Colors.GREEN}✓ PHASE 1 COMPLETE - Recon database saved{Colors.END}")
            
        except Exception as e:
            self.logger.log_error(f"Phase 1 error: {str(e)}")
            print(f"{Colors.RED}✗ Phase 1 error: {str(e)}{Colors.END}")
            raise
    
    def phase_2_vulnerability_detection(self):
        """PHASE 2: Vulnerability Detection - Intelligent Sequential Execution"""
        print(f"\n\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}║         PHASE 2: VULNERABILITY DETECTION                   ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.END}\n")
        
        recon_data = self.intel.get_recon_database()
        subdomains = recon_data.get('subdomains', [])
        
        total_steps = 0
        completed_steps = 0
        
        # Calculate total steps based on what's detected
        for subdomain in subdomains:
            tech = recon_data['technologies'].get(subdomain, {})
            secrets = recon_data['secrets'].get(subdomain, {})
            
            if 'GraphQL' in tech.get('technologies', []):
                total_steps += 1
            if secrets.get('jwt_tokens') or secrets.get('tokens'):
                total_steps += 1
            if 'Android' in tech.get('technologies', []) or secrets.get('apk_urls'):
                total_steps += 1
        
        if total_steps == 0:
            print(f"{Colors.YELLOW}⚠ No specific vulnerability targets detected{Colors.END}")
            return
        
        self.update_progress("Phase 2: Vulnerability Detection", 0, total_steps)
        
        try:
            vulnerabilities = []
            
            for subdomain in subdomains:
                tech = recon_data['technologies'].get(subdomain, {})
                secrets = recon_data['secrets'].get(subdomain, {})
                
                print(f"\n{Colors.CYAN}━━━ Scanning {subdomain} ━━━{Colors.END}")
                
                # GraphQL Introspection
                if 'GraphQL' in tech.get('technologies', []):
                    print(f"{Colors.YELLOW}[GraphQL] Running introspection...{Colors.END}")
                    self.logger.log_info(f"GraphQL detected on {subdomain}")
                    
                    introspector = GraphQLIntrospector(subdomain, self.workspace, self.delay)
                    vulns = introspector.scan()
                    
                    vulnerabilities.extend(vulns)
                    self.intel.add_vulnerabilities(vulns)
                    
                    print(f"{Colors.GREEN}    ✓ Found {len(vulns)} GraphQL issues{Colors.END}")
                    completed_steps += 1
                    self.update_progress("GraphQL Scanning", completed_steps, total_steps)
                    time.sleep(self.delay * 2)
                
                # JWT Analysis
                if secrets.get('jwt_tokens') or secrets.get('tokens'):
                    print(f"{Colors.YELLOW}[JWT] Analyzing tokens...{Colors.END}")
                    self.logger.log_info(f"JWT tokens found on {subdomain}")
                    
                    tokens = secrets.get('jwt_tokens', []) + secrets.get('tokens', [])
                    analyzer = JWTAnalyzer(subdomain, tokens, self.workspace, self.delay)
                    vulns = analyzer.analyze()
                    
                    vulnerabilities.extend(vulns)
                    self.intel.add_vulnerabilities(vulns)
                    
                    print(f"{Colors.GREEN}    ✓ Found {len(vulns)} JWT issues{Colors.END}")
                    completed_steps += 1
                    self.update_progress("JWT Analysis", completed_steps, total_steps)
                    time.sleep(self.delay * 2)
                
                # APK Analysis
                if 'Android' in tech.get('technologies', []) or secrets.get('apk_urls'):
                    print(f"{Colors.YELLOW}[APK] Analyzing mobile app...{Colors.END}")
                    self.logger.log_info(f"Mobile app detected for {subdomain}")
                    
                    apk_urls = secrets.get('apk_urls', [])
                    analyzer = APKAnalyzer(subdomain, apk_urls, self.workspace, self.delay)
                    vulns = analyzer.scan()
                    
                    vulnerabilities.extend(vulns)
                    self.intel.add_vulnerabilities(vulns)
                    
                    print(f"{Colors.GREEN}    ✓ Found {len(vulns)} mobile issues{Colors.END}")
                    completed_steps += 1
                    self.update_progress("APK Analysis", completed_steps, total_steps)
                    time.sleep(self.delay * 2)
            
            # Update statistics
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                if severity in self.stats['findings']:
                    self.stats['findings'][severity] += 1
            
            self.intel.save_vulnerabilities_database()
            print(f"\n{Colors.GREEN}✓ PHASE 2 COMPLETE - Found {len(vulnerabilities)} vulnerabilities{Colors.END}")
            print(f"{Colors.CYAN}  Critical: {self.stats['findings']['critical']}, High: {self.stats['findings']['high']}, "
                  f"Medium: {self.stats['findings']['medium']}, Low: {self.stats['findings']['low']}{Colors.END}")
            
        except Exception as e:
            self.logger.log_error(f"Phase 2 error: {str(e)}")
            print(f"{Colors.RED}✗ Phase 2 error: {str(e)}{Colors.END}")
            raise
    
    def phase_3_exploitation(self):
        """PHASE 3: Exploitation & Validation - Careful Sequential Execution"""
        print(f"\n\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}║         PHASE 3: EXPLOITATION & VALIDATION                 ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.END}\n")
        
        vulnerabilities = self.intel.get_vulnerabilities()
        
        if not vulnerabilities:
            print(f"{Colors.YELLOW}⚠ No vulnerabilities to exploit{Colors.END}")
            return
        
        # Find testable endpoints
        race_targets = [v for v in vulnerabilities if 'business_logic' in v.get('tags', [])]
        price_targets = [v for v in vulnerabilities if 'ecommerce' in v.get('tags', []) or 'payment' in v.get('tags', [])]
        
        total_steps = len(race_targets) + len(price_targets)
        
        if total_steps == 0:
            print(f"{Colors.YELLOW}⚠ No exploitation targets found{Colors.END}")
            return
        
        self.update_progress("Phase 3: Exploitation", 0, total_steps)
        confirmed_bugs = []
        
        try:
            completed = 0
            
            # Race Condition Testing
            if race_targets:
                print(f"\n{Colors.YELLOW}[Race Conditions] Testing {len(race_targets)} targets...{Colors.END}")
                
                for idx, vuln in enumerate(race_targets):
                    endpoint = vuln.get('endpoint', vuln.get('url'))
                    print(f"{Colors.CYAN}    [{idx+1}/{len(race_targets)}] Testing {endpoint}...{Colors.END}")
                    
                    tester = RaceConditionTester(endpoint, self.workspace, self.delay)
                    result = tester.test()
                    
                    if result.get('exploitable'):
                        confirmed_bugs.append(result)
                        self.intel.add_confirmed_bug(result)
                        print(f"{Colors.RED}        ✓ CONFIRMED: Race condition exploitable!{Colors.END}")
                    else:
                        print(f"{Colors.GREEN}        ✓ Not exploitable{Colors.END}")
                    
                    completed += 1
                    self.update_progress("Race Condition Testing", completed, total_steps)
                    time.sleep(self.delay * 3)  # Extra delay for safety
            
            # Price Manipulation Testing
            if price_targets:
                print(f"\n{Colors.YELLOW}[Price Manipulation] Testing {len(price_targets)} targets...{Colors.END}")
                
                for idx, vuln in enumerate(price_targets):
                    endpoint = vuln.get('endpoint', vuln.get('url'))
                    print(f"{Colors.CYAN}    [{idx+1}/{len(price_targets)}] Testing {endpoint}...{Colors.END}")
                    
                    scanner = PriceManipulationScanner(endpoint, self.workspace, self.delay)
                    result = scanner.test()
                    
                    if result.get('exploitable'):
                        confirmed_bugs.append(result)
                        self.intel.add_confirmed_bug(result)
                        print(f"{Colors.RED}        ✓ CONFIRMED: Price manipulation possible!{Colors.END}")
                    else:
                        print(f"{Colors.GREEN}        ✓ Not exploitable{Colors.END}")
                    
                    completed += 1
                    self.update_progress("Price Manipulation Testing", completed, total_steps)
                    time.sleep(self.delay * 3)  # Extra delay for safety
            
            self.intel.save_confirmed_bugs()
            print(f"\n{Colors.GREEN}✓ PHASE 3 COMPLETE - Confirmed {len(confirmed_bugs)} critical bugs{Colors.END}")
            
        except Exception as e:
            self.logger.log_error(f"Phase 3 error: {str(e)}")
            print(f"{Colors.RED}✗ Phase 3 error: {str(e)}{Colors.END}")
            raise
    
    def generate_final_report(self):
        """Generate comprehensive HTML report"""
        print(f"\n\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}║         GENERATING FINAL REPORT                            ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.END}\n")
        
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        # Compile all data
        report_data = {
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': str(duration),
            'execution_mode': self.execution_mode,
            'reconnaissance': self.intel.get_recon_database(),
            'vulnerabilities': self.intel.get_vulnerabilities(),
            'confirmed_bugs': self.intel.get_confirmed_bugs(),
            'statistics': self.stats
        }
        
        # Generate HTML report
        html_file = self.report_gen.generate_html_report(report_data)
        
        # Generate JSON report
        json_file = self.workspace / "REVUEX_FINAL_REPORT.json"
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"{Colors.GREEN}✓ HTML Report: {html_file}{Colors.END}")
        print(f"{Colors.GREEN}✓ JSON Report: {json_file}{Colors.END}")
        print(f"{Colors.CYAN}✓ Workspace: {self.workspace}{Colors.END}")
        
        return html_file, json_file
    
    def full_hunt(self):
        """Execute complete hunting workflow"""
        print_banner()
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}Target: {self.target}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}Mode: {self.execution_mode.upper()}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}Delay: {self.delay}s between requests{Colors.END}")
        print(f"{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}\n")
        
        try:
            # Execute all phases
            self.phase_1_reconnaissance()
            self.phase_2_vulnerability_detection()
            self.phase_3_exploitation()
            
            # Generate reports
            html_report, json_report = self.generate_final_report()
            
            # Final summary
            print(f"\n\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}║         REVUEX SCAN COMPLETE                               ║{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.END}\n")
            
            vulns = self.intel.get_vulnerabilities()
            bugs = self.intel.get_confirmed_bugs()
            
            print(f"{Colors.CYAN}Target: {self.target}{Colors.END}")
            print(f"{Colors.CYAN}Duration: {datetime.now() - self.start_time}{Colors.END}")
            print(f"{Colors.CYAN}Vulnerabilities Found: {len(vulns)}{Colors.END}")
            print(f"{Colors.RED}Confirmed Exploits: {len(bugs)}{Colors.END}")
            print(f"\n{Colors.YELLOW}Severity Breakdown:{Colors.END}")
            print(f"  {Colors.RED}Critical: {self.stats['findings']['critical']}{Colors.END}")
            print(f"  {Colors.MAGENTA}High: {self.stats['findings']['high']}{Colors.END}")
            print(f"  {Colors.YELLOW}Medium: {self.stats['findings']['medium']}{Colors.END}")
            print(f"  {Colors.GREEN}Low: {self.stats['findings']['low']}{Colors.END}")
            print(f"\n{Colors.GREEN}Reports generated successfully!{Colors.END}")
            print(f"{Colors.CYAN}View your report: {html_report}{Colors.END}\n")
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
            self.logger.log_warning("Scan interrupted by user")
        except Exception as e:
            print(f"\n\n{Colors.RED}[!] Fatal error: {str(e)}{Colors.END}")
            self.logger.log_error(f"Fatal error: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(
        description='REVUEX Vulnerability Suite - Advanced Bug Bounty Automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Full automated scan (sequential, safe)
  python3 revuex_suite.py full -t example.com
  
  # Full scan with custom delay
  python3 revuex_suite.py full -t example.com -d 5
  
  # Reconnaissance only
  python3 revuex_suite.py recon -t example.com
  
  # Vulnerability scan from existing recon
  python3 revuex_suite.py vuln-scan -w ./revuex_workspace/example.com_20250101_120000
  
  # Exploitation phase only
  python3 revuex_suite.py exploit -w ./revuex_workspace/example.com_20250101_120000

Author: {__author__} | Telegram: {__telegram__}
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Full hunt command
    full_parser = subparsers.add_parser('full', help='Run complete vulnerability hunt')
    full_parser.add_argument('-t', '--target', required=True, help='Target domain')
    full_parser.add_argument('-d', '--delay', type=int, default=2, help='Delay between requests (default: 2s)')
    full_parser.add_argument('-m', '--mode', choices=['sequential', 'parallel'], default='sequential',
                            help='Execution mode (default: sequential - RECOMMENDED)')
    
    # Recon command
    recon_parser = subparsers.add_parser('recon', help='Run reconnaissance phase only')
    recon_parser.add_argument('-t', '--target', required=True, help='Target domain')
    recon_parser.add_argument('-d', '--delay', type=int, default=2, help='Delay between requests')
    
    # Vuln-scan command
    vuln_parser = subparsers.add_parser('vuln-scan', help='Run vulnerability detection phase')
    vuln_parser.add_argument('-w', '--workspace', required=True, help='Workspace directory')
    vuln_parser.add_argument('-d', '--delay', type=int, default=2, help='Delay between requests')
    
    # Exploit command
    exploit_parser = subparsers.add_parser('exploit', help='Run exploitation phase')
    exploit_parser.add_argument('-w', '--workspace', required=True, help='Workspace directory')
    exploit_parser.add_argument('-d', '--delay', type=int, default=3, help='Delay between requests')
    
    # Version command
    parser.add_argument('-v', '--version', action='version', version=f'REVUEX Suite v{__version__}')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'full':
            suite = RevuexSuite(args.target, args.mode, args.delay)
            suite.full_hunt()
        
        elif args.command == 'recon':
            suite = RevuexSuite(args.target, 'sequential', args.delay)
            suite.phase_1_reconnaissance()
            print(f"\n{Colors.GREEN}✓ Reconnaissance complete!{Colors.END}")
        
        elif args.command == 'vuln-scan':
            # Load existing workspace
            workspace_path = Path(args.workspace)
            if not workspace_path.exists():
                print(f"{Colors.RED}✗ Workspace not found: {args.workspace}{Colors.END}")
                return
            
            target = workspace_path.name.split('_')[0]
            suite = RevuexSuite(target, 'sequential', args.delay)
            suite.workspace = workspace_path
            suite.intel = IntelligenceHub(workspace_path)
            suite.logger = RevuexLogger(workspace_path)
            
            suite.phase_2_vulnerability_detection()
            print(f"\n{Colors.GREEN}✓ Vulnerability scan complete!{Colors.END}")
        
        elif args.command == 'exploit':
            workspace_path = Path(args.workspace)
            if not workspace_path.exists():
                print(f"{Colors.RED}✗ Workspace not found: {args.workspace}{Colors.END}")
                return
            
            target = workspace_path.name.split('_')[0]
            suite = RevuexSuite(target, 'sequential', args.delay)
            suite.workspace = workspace_path
            suite.intel = IntelligenceHub(workspace_path)
            suite.logger = RevuexLogger(workspace_path)
            
            suite.phase_3_exploitation()
            suite.generate_final_report()
            print(f"\n{Colors.GREEN}✓ Exploitation complete!{Colors.END}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {str(e)}{Colors.END}")
        sys.exit(1)

if __name__ == '__main__':
    main()
