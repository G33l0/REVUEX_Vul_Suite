#!/usr/bin/env python3
"""
REVUEX Report Generator v2.1 - World-Class Professional Security Reports
Author: G33L0
Enhanced & Optimized by: Assistant
Added: Generic add_section() method for custom sections
"""

import json
import hashlib
import html
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate professional HTML reports with comprehensive security analysis"""

    def __init__(self, workspace: Union[str, Path]):
        """Initialize report generator"""
        self.workspace = Path(workspace)
        
        # Ensure workspace exists
        try:
            self.workspace.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create workspace: {e}")
            raise

        # Severity scoring matrix with CVSS 3.1
        self.severity_matrix = {
            'critical': {
                'score': 9.0,
                'cvss_range': '9.0-10.0',
                'color': '#dc3545',
                'icon': '🔴',
                'priority': 'IMMEDIATE',
                'sla': '24 hours'
            },
            'high': {
                'score': 7.0,
                'cvss_range': '7.0-8.9',
                'color': '#fd7e14',
                'icon': '🟠',
                'priority': 'URGENT',
                'sla': '7 days'
            },
            'medium': {
                'score': 4.0,
                'cvss_range': '4.0-6.9',
                'color': '#ffc107',
                'icon': '🟡',
                'priority': 'MODERATE',
                'sla': '30 days'
            },
            'low': {
                'score': 0.1,
                'cvss_range': '0.1-3.9',
                'color': '#28a745',
                'icon': '🟢',
                'priority': 'LOW',
                'sla': '90 days'
            }
        }

        # Scanner-specific information
        self.scanner_info = {
            'SSRFScanner': {'name': 'SSRF Scanner', 'category': 'Server-Side', 'owasp': 'A10:2021'},
            'EnhancedSQLiScanner': {'name': 'Enhanced SQLi Scanner', 'category': 'Injection', 'owasp': 'A03:2021'},
            'IDORTester': {'name': 'IDOR Tester', 'category': 'Access Control', 'owasp': 'A01:2021'},
            'EnhancedXSSScanner': {'name': 'Enhanced XSS Scanner', 'category': 'Injection', 'owasp': 'A03:2021'},
            'BusinessLogicAbuser': {'name': 'Business Logic Abuser', 'category': 'Design', 'owasp': 'A04:2021'},
            'FileUploadTester': {'name': 'File Upload Tester', 'category': 'Upload', 'owasp': 'A04:2021'},
            'XXEScanner': {'name': 'XXE Scanner', 'category': 'Injection', 'owasp': 'A03:2021'},
            'SessionAnalyzer': {'name': 'Session Analyzer', 'category': 'Authentication', 'owasp': 'A07:2021'},
            'CORSScanner': {'name': 'CORS Scanner', 'category': 'Configuration', 'owasp': 'A05:2021'},
            'CSRFTester': {'name': 'CSRF Tester', 'category': 'Access Control', 'owasp': 'A01:2021'},
            'DependencyChecker': {'name': 'Dependency Checker', 'category': 'Components', 'owasp': 'A06:2021'},
            'SubdomainHunter': {'name': 'Subdomain Hunter', 'category': 'Reconnaissance', 'owasp': 'N/A'},
            'TechFingerprinter': {'name': 'Tech Fingerprinter', 'category': 'Reconnaissance', 'owasp': 'N/A'},
            'JSSecretsMiner': {'name': 'JS Secrets Miner', 'category': 'Reconnaissance', 'owasp': 'A02:2021'},
            'GraphQLIntrospector': {'name': 'GraphQL Introspector', 'category': 'API', 'owasp': 'A01:2021'},
            'JWTAnalyzer': {'name': 'JWT Analyzer', 'category': 'Authentication', 'owasp': 'A07:2021'},
            'APKAnalyzer': {'name': 'APK Analyzer', 'category': 'Mobile', 'owasp': 'A08:2021'},
            'RaceConditionTester': {'name': 'Race Condition Tester', 'category': 'Logic', 'owasp': 'A04:2021'},
            'PriceManipulationScanner': {'name': 'Price Manipulation Scanner', 'category': 'Payment', 'owasp': 'A04:2021'}
        }

    #######################
    # --- PUBLIC METHODS ---
    #######################

    def generate_html_report(self, data: Dict[str, Any], custom_sections: List[str] = None) -> Path:
        """
        Generate a professional HTML report.
        `data` is the main vulnerability data dictionary.
        `custom_sections` is a list of HTML strings to append at the end of the report.
        """
        logger.info(f"Generating report for target: {data.get('target', 'Unknown')}")
        
        exec_summary = self._generate_executive_summary_data(data)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REVUEX v2.1 Security Assessment - {data.get('target', 'Target')}</title>
    <style>{self._get_enhanced_css()}</style>
</head>
<body>
    <div class="container">
        {self._generate_header(data)}
        <div class="version-badge"><strong>🔒 REVUEX Suite v2.1</strong> | 19 Security Scanners | OWASP Top 10 2021 Coverage</div>
        
        {self._generate_executive_summary(data, exec_summary)}
        {self._generate_quick_stats(data)}
        {self._generate_severity_breakdown(data)}
        {self._generate_confirmed_bugs_section(data.get('confirmed_bugs', []))}
        {self._generate_vulnerabilities_section(data.get('vulnerabilities', []))}
        {self._generate_reconnaissance_section(data.get('reconnaissance', {}))}
        {self._generate_remediation_roadmap(data)}

        <!-- Insert custom sections here -->
        {''.join(custom_sections) if custom_sections else ''}

        {self._generate_footer()}
    </div>
</body>
</html>
"""
        # Save report
        output_file = self.workspace / "REVUEX_PROFESSIONAL_REPORT.html"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"Report successfully saved to {output_file}")

            # Save executive summary as JSON for integrations
            exec_json = self.workspace / "executive_summary.json"
            with open(exec_json, 'w', encoding='utf-8') as f:
                json.dump(exec_summary, f, indent=2)

            return output_file
        except IOError as e:
            logger.error(f"Failed to write report files: {e}")
            raise

    def add_section(self, html_content: str, section_name: str = "Additional Section") -> str:
        """
        Return an HTML block for a custom section.
        Can be added to the `custom_sections` list in generate_html_report().
        """
        return f"""
        <div class="section">
            <h2 class="section-title">📌 {html.escape(section_name)}</h2>
            {html_content}
        </div>
        """

    #######################
    # --- PRIVATE METHODS ---
    #######################

    # Executive summary
    def _generate_executive_summary_data(self, data: Dict) -> Dict:
        vulnerabilities = data.get('vulnerabilities', [])
        confirmed_bugs = data.get('confirmed_bugs', [])
        stats = data.get('statistics', {}).get('findings', {})
        
        # Calculate risk score
        risk_score = min(100, (
            stats.get('critical', 0) * 25 +
            stats.get('high', 0) * 15 +
            stats.get('medium', 0) * 8 +
            stats.get('low', 0) * 2
        ))
        
        if risk_score >= 80:
            risk_level, risk_color = 'CRITICAL', '#dc3545'
        elif risk_score >= 60:
            risk_level, risk_color = 'HIGH', '#fd7e14'
        elif risk_score >= 30:
            risk_level, risk_color = 'MEDIUM', '#ffc107'
        else:
            risk_level, risk_color = 'LOW', '#28a745'
        
        affected_endpoints = set()
        for vuln in vulnerabilities + confirmed_bugs:
            endpoint = vuln.get('url') or vuln.get('endpoint', '')
            if endpoint:
                affected_endpoints.add(endpoint)

        recon = data.get('reconnaissance', {})
        attack_surface = {
            'total_subdomains': len(recon.get('subdomains', [])),
            'total_endpoints': sum(len(eps) for eps in recon.get('endpoints', {}).values()),
            'affected_endpoints': len(affected_endpoints),
            'vulnerable_technologies': self._identify_vulnerable_technologies(data)
        }

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'total_vulnerabilities': len(vulnerabilities),
            'confirmed_exploits': len(confirmed_bugs),
            'severity_distribution': stats,
            'affected_endpoints': len(affected_endpoints),
            'business_impact': self._calculate_business_impact(vulnerabilities, confirmed_bugs),
            'attack_surface': attack_surface,
            'remediation_timeline': self._calculate_remediation_timeline(stats),
            'compliance_impact': self._assess_compliance_impact(vulnerabilities, confirmed_bugs)
        }

    # --- Other private methods remain unchanged ---
    # For brevity, you can keep all the private methods from v2.0 (like
    # _generate_header, _generate_quick_stats, _generate_confirmed_bugs_section, etc.)
    # They remain fully functional. Only change is the ability to inject custom sections.

    def _identify_vulnerable_technologies(self, data: Dict) -> List:
        vuln_tech = set()
        technologies = data.get('reconnaissance', {}).get('technologies', {})
        for _, tech_data in technologies.items():
            tech_list = tech_data.get('technologies', [])
            vuln_tech.update(tech_list)
        return list(vuln_tech)

    # Include all other private methods (_generate_header, _generate_quick_stats, etc.)
    # as in your original v2.0 script

    def _get_enhanced_css(self) -> str:
        """CSS for report, unchanged from v2.0"""
        return """
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #1a202c; color: white; padding: 40px; text-align: center; }
        .section { padding: 30px; border-bottom: 1px solid #e2e8f0; }
        .section-title { color: #2d3748; margin-bottom: 20px; border-bottom: 2px solid #4a5568; padding-bottom: 10px; }
        .severity-badge { padding: 4px 10px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8em; }
        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: black; }
        .severity-badge.low { background: #28a745; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 20px; }
        .summary-card { padding: 20px; background: #f8f9fa; border-radius: 8px; text-align: center; }
        .summary-card .number { font-size: 2em; font-weight: bold; }
        .code-block { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: monospace; }
        .footer { background: #1a202c; color: white; padding: 20px; text-align: center; font-size: 0.9em; }
        """