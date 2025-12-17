#!/usr/bin/env python3
"""
REVUEX Report Generator v2.0 - World-Class Professional Security Reports
Author: G33L0
Fixed & Optimized by: Assistant
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
        """Initialize report generator v2.0"""
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

    def generate_html_report(self, data: Dict[str, Any]) -> Path:
        """Generate comprehensive HTML report with professional sections"""
        logger.info(f"Generating report for target: {data.get('target', 'Unknown')}")
        
        # Calculate executive metrics
        exec_summary = self._generate_executive_summary_data(data)
        
        # Construct HTML Structure
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REVUEX v2.0 Security Assessment - {data.get('target', 'Target')}</title>
    <style>
        {self._get_enhanced_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header(data)}

        <div class="version-badge">
            <strong>🔒 REVUEX Suite v2.0</strong> | 19 Security Scanners | OWASP Top 10 2021 Coverage
        </div>
        
        {self._generate_executive_summary(data, exec_summary)}
        
        {self._generate_quick_stats(data)}
        
        {self._generate_severity_breakdown(data)}
        
        {self._generate_confirmed_bugs_section(data.get('confirmed_bugs', []))}
        
        {self._generate_vulnerabilities_section(data.get('vulnerabilities', []))}
        
        {self._generate_reconnaissance_section(data.get('reconnaissance', {}))}
        
        {self._generate_remediation_roadmap(data)}
        
        {self._generate_footer()}
    </div>
</body>
</html>"""

        # Save report
        try:
            output_file = self.workspace / "REVUEX_PROFESSIONAL_REPORT.html"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Report successfully saved to {output_file}")
            
            # Also save executive summary as JSON for integration purposes
            exec_json = self.workspace / "executive_summary.json"
            with open(exec_json, 'w') as f:
                json.dump(exec_summary, f, indent=2)
                
            return output_file
        except IOError as e:
            logger.error(f"Failed to write report files: {e}")
            raise

    def _generate_executive_summary_data(self, data: Dict) -> Dict:
        """Calculate executive summary metrics"""
        vulnerabilities = data.get('vulnerabilities', [])
        confirmed_bugs = data.get('confirmed_bugs', [])
        stats = data.get('statistics', {}).get('findings', {})
        
        # Calculate risk score (0-100)
        risk_score = min(100, (
            stats.get('critical', 0) * 25 +
            stats.get('high', 0) * 15 +
            stats.get('medium', 0) * 8 +
            stats.get('low', 0) * 2
        ))
        
        # Determine risk level
        if risk_score >= 80:
            risk_level, risk_color = 'CRITICAL', '#dc3545'
        elif risk_score >= 60:
            risk_level, risk_color = 'HIGH', '#fd7e14'
        elif risk_score >= 30:
            risk_level, risk_color = 'MEDIUM', '#ffc107'
        else:
            risk_level, risk_color = 'LOW', '#28a745'
        
        # Calculate affected endpoints
        affected_endpoints = set()
        for vuln in vulnerabilities + confirmed_bugs:
            endpoint = vuln.get('url') or vuln.get('endpoint', '')
            if endpoint:
                affected_endpoints.add(endpoint)
        
        # Attack surface metrics
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

    def _calculate_business_impact(self, vulnerabilities: List, confirmed_bugs: List) -> Dict:
        """Calculate business impact assessment"""
        impacts = {
            'data_breach_risk': False,
            'financial_loss_risk': False,
            'reputation_damage_risk': False,
            'service_disruption_risk': False,
            'compliance_violation_risk': False
        }
        
        high_risk = ['SQL Injection', 'Authentication Bypass', 'RCE', 'IDOR', 'Sensitive Data', 'SSRF', 'XXE']
        financial_risk = ['Price Manipulation', 'Payment', 'Discount', 'Business Logic']
        
        for vuln in vulnerabilities + confirmed_bugs:
            vuln_type = vuln.get('type', '')
            severity = vuln.get('severity', 'low').lower()
            
            if any(risk in vuln_type for risk in high_risk):
                impacts['data_breach_risk'] = True
                impacts['compliance_violation_risk'] = True
            
            if any(risk in vuln_type for risk in financial_risk):
                impacts['financial_loss_risk'] = True
            
            if severity in ['critical', 'high']:
                impacts['reputation_damage_risk'] = True
            
            if 'DoS' in vuln_type or 'Race Condition' in vuln_type:
                impacts['service_disruption_risk'] = True
        
        return impacts

    def _calculate_remediation_timeline(self, severity_stats: Dict) -> Dict:
        """Calculate estimated remediation timeline"""
        # Time estimates in days
        critical_time = severity_stats.get('critical', 0) * 1
        high_time = severity_stats.get('high', 0) * 3
        medium_time = severity_stats.get('medium', 0) * 7
        low_time = severity_stats.get('low', 0) * 14
        
        total_days = critical_time + high_time + medium_time + low_time
        
        return {
            'immediate_action': severity_stats.get('critical', 0),
            'short_term': severity_stats.get('high', 0),
            'medium_term': severity_stats.get('medium', 0),
            'long_term': severity_stats.get('low', 0),
            'estimated_total_days': total_days
        }

    def _assess_compliance_impact(self, vulnerabilities: List, confirmed_bugs: List) -> Dict:
        """Assess compliance and regulatory impact"""
        compliance_issues = {
            'PCI_DSS': False, 'GDPR': False, 'HIPAA': False, 'SOC2': False, 'ISO27001': False
        }
        
        for vuln in vulnerabilities + confirmed_bugs:
            vuln_type = vuln.get('type', '')
            tags = vuln.get('tags', [])
            
            if 'payment' in tags or 'Price Manipulation' in vuln_type or 'SQL Injection' in vuln_type:
                compliance_issues['PCI_DSS'] = True
            
            if 'IDOR' in vuln_type or 'Data Exposure' in vuln_type or 'SSRF' in vuln_type:
                compliance_issues['GDPR'] = True
                compliance_issues['HIPAA'] = True
            
            if vuln.get('severity', '').lower() in ['critical', 'high']:
                compliance_issues['SOC2'] = True
                compliance_issues['ISO27001'] = True
        
        return compliance_issues

    def _identify_vulnerable_technologies(self, data: Dict) -> List:
        """Identify vulnerable technologies"""
        vuln_tech = set()
        technologies = data.get('reconnaissance', {}).get('technologies', {})
        for _, tech_data in technologies.items():
            tech_list = tech_data.get('technologies', [])
            vuln_tech.update(tech_list)
        return list(vuln_tech)

    def _generate_header(self, data: Dict) -> str:
        return f"""
        <div class="header">
            <h1>🔒 REVUEX</h1>
            <div class="subtitle">Professional Security Assessment Report v2.0</div>
            <div class="target-badge">{html.escape(data.get('target', ''))}</div>
            <div class="author">
                <strong>Date:</strong> {datetime.now().strftime('%B %d, %Y')}
            </div>
        </div>
        """

    def _generate_executive_summary(self, data: Dict, exec_summary: Dict) -> str:
        """Generate executive summary section"""
        impact_icons = {
            'data_breach_risk': '🔓 Data Breach Risk',
            'financial_loss_risk': '💰 Financial Loss Risk',
            'reputation_damage_risk': '📉 Reputation Damage Risk',
            'service_disruption_risk': '⚠️ Service Disruption Risk',
            'compliance_violation_risk': '⚖️ Compliance Violation Risk'
        }
        
        active_impacts = [impact_icons[k] for k, v in exec_summary['business_impact'].items() if v]
        compliance_at_risk = [k.replace('_', ' ') for k, v in exec_summary['compliance_impact'].items() if v]
        
        return f"""
        <div class="section executive-summary">
            <h2 class="section-title">📋 EXECUTIVE SUMMARY</h2>
            
            <div class="exec-box">
                <h3>🎯 Assessment Overview</h3>
                <p class="exec-text">
                    This security assessment of <strong>{html.escape(data.get('target', ''))}</strong> 
                    employed automated vulnerability discovery techniques across 
                    {exec_summary['attack_surface']['total_subdomains']} subdomains and 
                    {exec_summary['attack_surface']['total_endpoints']} endpoints.
                </p>
            </div>
            
            <div class="risk-score-container">
                <div class="risk-score" style="border-color: {exec_summary['risk_color']};">
                    <div class="risk-number" style="color: {exec_summary['risk_color']};">
                        {exec_summary['risk_score']}/100
                    </div>
                    <div class="risk-label" style="background: {exec_summary['risk_color']};">
                        OVERALL RISK: {exec_summary['risk_level']}
                    </div>
                </div>
            </div>
            
            <div class="exec-box critical-findings">
                <h3>🚨 Critical Findings</h3>
                <div class="finding-grid">
                    <div class="finding-item">
                        <div class="finding-number critical">{exec_summary['confirmed_exploits']}</div>
                        <div class="finding-label">Confirmed Exploitable Bugs</div>
                    </div>
                    <div class="finding-item">
                        <div class="finding-number high">{exec_summary['total_vulnerabilities']}</div>
                        <div class="finding-label">Total Vulnerabilities</div>
                    </div>
                    <div class="finding-item">
                        <div class="finding-number medium">{exec_summary['affected_endpoints']}</div>
                        <div class="finding-label">Affected Endpoints</div>
                    </div>
                </div>
            </div>
            
            <div class="exec-box">
                <h3>💼 Business Impact Assessment</h3>
                <div class="impact-grid">
                    {''.join(f'<div class="impact-item">⚠️ {i}</div>' for i in active_impacts) if active_impacts else '<p class="no-impact">✅ No immediate business-critical impacts detected.</p>'}
                </div>
            </div>
            
            <div class="exec-box">
                <h3>⚖️ Compliance & Regulatory Impact</h3>
                <div class="compliance-grid">
                    {''.join(f'<div class="compliance-item">⚠️ {s}</div>' for s in compliance_at_risk) if compliance_at_risk else '<p class="no-impact">✅ No direct compliance violations detected.</p>'}
                </div>
            </div>
        </div>
        """

    def _generate_quick_stats(self, data: Dict) -> str:
        recon = data.get('reconnaissance', {})
        total_endpoints = sum(len(eps) for eps in recon.get('endpoints', {}).values())
        return f"""
        <div class="summary">
            <div class="summary-card">
                <div class="number critical">{len(data.get('confirmed_bugs', []))}</div>
                <div class="label">Confirmed Exploits</div>
            </div>
            <div class="summary-card">
                <div class="number high">{len(data.get('vulnerabilities', []))}</div>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="summary-card">
                <div class="number info">{len(recon.get('subdomains', []))}</div>
                <div class="label">Subdomains Scanned</div>
            </div>
            <div class="summary-card">
                <div class="number medium">{total_endpoints}</div>
                <div class="label">Endpoints Discovered</div>
            </div>
        </div>
        """

    def _generate_severity_breakdown(self, data: Dict) -> str:
        stats = data.get('statistics', {}).get('findings', {})
        return f"""
        <div class="section" style="background: #f8f9fa;">
            <h2 class="section-title">📊 SEVERITY BREAKDOWN</h2>
            <div class="severity-details">
                {self._generate_severity_detail('critical', stats.get('critical', 0))}
                {self._generate_severity_detail('high', stats.get('high', 0))}
                {self._generate_severity_detail('medium', stats.get('medium', 0))}
                {self._generate_severity_detail('low', stats.get('low', 0))}
            </div>
        </div>
        """

    def _generate_severity_detail(self, severity: str, count: int) -> str:
        info = self.severity_matrix[severity]
        return f"""
        <div class="severity-card {severity}">
            <div class="severity-header">
                <span class="severity-icon">{info['icon']}</span>
                <span class="severity-name">{severity.upper()}</span>
                <span class="severity-count">{count}</span>
            </div>
            <div class="severity-info">
                <div><strong>CVSS Range:</strong> {info['cvss_range']}</div>
                <div><strong>Priority:</strong> {info['priority']}</div>
                <div><strong>SLA:</strong> {info['sla']}</div>
            </div>
        </div>
        """

    def _generate_confirmed_bugs_section(self, bugs: List) -> str:
        if not bugs:
            return """<div class="section"><h2 class="section-title">🎯 CONFIRMED EXPLOITABLE BUGS</h2>
            <div class="no-findings"><div class="success-icon">✅</div><p>No confirmed exploitable bugs were discovered.</p></div></div>"""
        
        html_out = """<div class="section"><h2 class="section-title">🎯 CONFIRMED EXPLOITABLE BUGS</h2>"""
        
        for idx, bug in enumerate(bugs, 1):
            severity = bug.get('severity', 'high').lower()
            html_out += f"""
            <div class="vulnerability-card {severity}">
                {self._generate_vuln_header(idx, bug, 'CONFIRMED EXPLOIT')}
                <div class="vuln-section">
                    <h4 class="vuln-section-title">📋 Vulnerability Details</h4>
                    {self._generate_basic_info(bug)}
                </div>
                <div class="vuln-section">
                    <h4 class="vuln-section-title">🔬 TECHNICAL EVIDENCE</h4>
                    {self._generate_technical_evidence(bug)}
                </div>
                {self._generate_poc_section(bug)}
                {self._generate_impact_assessment(bug, severity)}
                <div class="vuln-section">
                    <h4 class="vuln-section-title">🛠️ REMEDIATION GUIDANCE</h4>
                    {self._generate_detailed_remediation(bug, severity)}
                </div>
                <div class="vuln-metadata">
                    <span><strong>Confirmed:</strong> {bug.get('confirmed_at', 'N/A')}</span>
                    <span><strong>Reference ID:</strong> REV-{self._generate_vuln_id(bug)}</span>
                </div>
            </div>
            """
        html_out += "</div>"
        return html_out

    def _generate_vulnerabilities_section(self, vulnerabilities: List) -> str:
        if not vulnerabilities:
            return """<div class="section" style="background: #f8f9fa;"><h2 class="section-title">🔍 DETECTED VULNERABILITIES</h2>
            <div class="no-findings"><div class="success-icon">✅</div><p>No additional vulnerabilities detected.</p></div></div>"""
        
        html_out = """<div class="section" style="background: #f8f9fa;"><h2 class="section-title">🔍 DETECTED VULNERABILITIES</h2>"""
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'medium').lower()
            html_out += f"""
            <div class="vulnerability-card {severity}">
                {self._generate_vuln_header(idx, vuln, 'POTENTIAL VULNERABILITY')}
                <div class="vuln-section">
                    <h4 class="vuln-section-title">📋 Vulnerability Details</h4>
                    {self._generate_basic_info(vuln)}
                </div>
                <div class="vuln-section">
                    <h4 class="vuln-section-title">🔍 Evidence</h4>
                    {self._generate_evidence_section(vuln)}
                </div>
                {self._generate_impact_assessment(vuln, severity)}
                <div class="vuln-section">
                    <h4 class="vuln-section-title">🛠️ REMEDIATION GUIDANCE</h4>
                    {self._generate_detailed_remediation(vuln, severity)}
                </div>
            </div>
            """
        html_out += "</div>"
        return html_out

    def _generate_vuln_header(self, index: int, vuln: Dict, badge_text: str) -> str:
        severity = vuln.get('severity', 'medium').lower()
        severity_info = self.severity_matrix.get(severity, self.severity_matrix['medium'])
        
        return f"""
        <div class="vuln-header">
            <div class="vuln-title">
                <span class="vuln-index">[{index}]</span>
                {html.escape(vuln.get('type', 'Unknown Vulnerability'))}
            </div>
            <div class="vuln-badges">
                <span class="exploit-badge">{badge_text}</span>
                <span class="severity-badge {severity}">
                    {severity_info['icon']} {severity.upper()}
                </span>
            </div>
        </div>
        """

    def _generate_basic_info(self, vuln: Dict) -> str:
        endpoint = vuln.get('url') or vuln.get('endpoint', 'N/A')
        return f"""
        <div class="info-grid">
            <div class="info-item">
                <strong>Target Endpoint:</strong>
                <code>{html.escape(endpoint)}</code>
            </div>
            <div class="info-item">
                <strong>Vulnerability Type:</strong>
                <span class="vuln-type-badge">{html.escape(vuln.get('type', 'Unknown'))}</span>
            </div>
            <div class="info-item">
                <strong>Description:</strong>
                {html.escape(vuln.get('description', 'No description available'))}
            </div>
        </div>
        """

    def _generate_technical_evidence(self, bug: Dict) -> str:
        evidence = html.escape(bug.get('evidence', 'No evidence available'))
        return f"""
        <div class="evidence-container">
            <div class="evidence-item"><strong>Finding:</strong><p>{evidence}</p></div>
            {self._generate_http_evidence(bug)}
            {self._generate_reproduction_steps(bug)}
        </div>
        """

    def _generate_http_evidence(self, vuln: Dict) -> str:
        request = vuln.get('request', '')
        response = vuln.get('response', '')
        
        if not request and not response:
            return ""
        
        html_out = '<div class="http-evidence">'
        if request:
            html_out += f'<div class="http-block"><div class="http-label">📤 HTTP Request</div><div class="code-block">{html.escape(str(request))}</div></div>'
        if response:
            html_out += f'<div class="http-block"><div class="http-label">📥 HTTP Response</div><div class="code-block">{html.escape(str(response))}</div></div>'
        html_out += '</div>'
        return html_out

    def _generate_reproduction_steps(self, vuln: Dict) -> str:
        attack_path = vuln.get('attack_path', [])
        if not attack_path:
            return ""
        
        steps = ''.join(f'<li>{html.escape(step)}</li>' for step in attack_path)
        return f"""
        <div class="reproduction-steps">
            <div class="http-label">🔄 Reproduction Steps</div>
            <ol class="steps-list">{steps}</ol>
        </div>
        """

    def _generate_evidence_section(self, vuln: Dict) -> str:
        evidence = html.escape(vuln.get('evidence', 'No evidence available'))
        return f"""
        <div class="evidence-container">
            <p>{evidence}</p>
            {self._generate_http_evidence(vuln)}
        </div>
        """

    def _generate_poc_section(self, bug: Dict) -> str:
        poc = bug.get('poc', '')
        if not poc:
            return ""
        return f"""
        <div class="vuln-section">
            <h4 class="vuln-section-title">💣 Proof of Concept</h4>
            <div class="code-block">{html.escape(str(poc))}</div>
        </div>
        """

    def _generate_impact_assessment(self, vuln: Dict, severity: str) -> str:
        severity_info = self.severity_matrix.get(severity, self.severity_matrix['medium'])
        impacts = self._determine_impacts(vuln)
        
        return f"""
        <div class="vuln-section impact-section">
            <h4 class="vuln-section-title">💥 Impact Assessment</h4>
            <div class="impact-details">
                <div class="impact-score">
                    <div class="impact-cvss">
                        <strong>CVSS Score Range:</strong> {severity_info['cvss_range']}
                    </div>
                    <div class="impact-priority" style="background: {severity_info['color']};">
                        {severity_info['priority']} PRIORITY
                    </div>
                </div>
                <div class="impact-categories">
                    <strong>Potential Impact:</strong>
                    <ul>{impacts}</ul>
                </div>
                <div class="impact-timeline">
                    <strong>Remediation SLA:</strong> {severity_info['sla']}
                </div>
            </div>
        </div>
        """

    def _determine_impacts(self, vuln: Dict) -> str:
        vuln_type = vuln.get('type', '').lower()
        impacts = []
        
        # Mapping simple logic for impacts based on type
        if 'sql' in vuln_type:
            impacts = ['Database compromise', 'Data theft', 'Data manipulation']
        elif 'xss' in vuln_type:
            impacts = ['Session hijacking', 'Credential theft', 'Malware distribution']
        elif 'ssrf' in vuln_type:
            impacts = ['Internal network scanning', 'Cloud metadata access', 'Service discovery']
        elif 'idor' in vuln_type:
            impacts = ['Unauthorized data access', 'Privacy violations', 'Account takeover']
        elif 'rce' in vuln_type or 'execution' in vuln_type:
            impacts = ['Full system compromise', 'Data destruction', 'Malware installation']
        else:
            impacts = ['Security posture degradation', 'Information disclosure']
        
        return ''.join(f'<li>{i}</li>' for i in impacts)

    def _generate_detailed_remediation(self, vuln: Dict, severity: str) -> str:
        vuln_type = vuln.get('type', '').lower()
        remediation_steps = self._get_remediation_steps(vuln_type)
        custom_remediation = vuln.get('remediation', [])
        severity_info = self.severity_matrix.get(severity, self.severity_matrix['medium'])
        
        custom_html = ""
        if custom_remediation:
            custom_items = ''.join(f'<li>{r}</li>' for r in custom_remediation)
            custom_html = f"""
            <div class="remediation-specific">
                <strong>📝 Specific Recommendations:</strong>
                <ul>{custom_items}</ul>
            </div>
            """
            
        return f"""
        <div class="remediation-container">
            <div class="remediation-priority" style="border-left-color: {severity_info['color']};">
                <strong>⏰ Priority Level:</strong> {severity_info['priority']} 
                <span class="remediation-sla">(Fix within {severity_info['sla']})</span>
            </div>
            <div class="remediation-steps">
                <strong>🔧 Immediate Actions:</strong>
                <ol>{remediation_steps}</ol>
            </div>
            {custom_html}
        </div>
        """

    def _get_remediation_steps(self, vuln_type: str) -> str:
        # Simplified mapping (could be expanded)
        if 'sql' in vuln_type:
            return "<li>Use parameterized queries</li><li>Input validation</li><li>Least privilege</li>"
        if 'xss' in vuln_type:
            return "<li>Context-aware encoding</li><li>CSP Headers</li><li>Input sanitization</li>"
        if 'idor' in vuln_type:
            return "<li>Access control checks</li><li>Use random IDs</li><li>Session validation</li>"
        
        return """
            <li>Review and patch the affected component</li>
            <li>Implement input validation</li>
            <li>Enable security logging</li>
        """

    def _generate_reconnaissance_section(self, recon_data: Dict) -> str:
        html_out = """
        <div class="section">
            <h2 class="section-title">🔎 RECONNAISSANCE RESULTS</h2>
            <h3 style="margin: 30px 0 20px 0; color: #1e3c72;">🌐 Discovered Subdomains</h3>
            <div class="subdomain-list">
        """
        
        for subdomain in recon_data.get('subdomains', []):
            tech = recon_data.get('technologies', {}).get(subdomain, {})
            technologies = tech.get('technologies', [])
            
            badges = ''.join(f'<span class="tech-badge">{t}</span>' for t in technologies[:5]) or '<span class="tech-badge">Unknown Stack</span>'
            
            html_out += f"""
            <div class="subdomain-item">
                <div class="domain">🌐 {html.escape(subdomain)}</div>
                <div class="tech">{badges}</div>
            </div>
            """
            
        html_out += "</div></div>"
        return html_out

    def _generate_remediation_roadmap(self, data: Dict) -> str:
        vulnerabilities = data.get('vulnerabilities', [])
        confirmed_bugs = data.get('confirmed_bugs', [])
        all_issues = vulnerabilities + confirmed_bugs
        
        # Categorize
        critical = [v for v in all_issues if v.get('severity', '').lower() == 'critical']
        high = [v for v in all_issues if v.get('severity', '').lower() == 'high']
        medium = [v for v in all_issues if v.get('severity', '').lower() == 'medium']
        low = [v for v in all_issues if v.get('severity', '').lower() == 'low']
        
        return f"""
        <div class="section remediation-roadmap">
            <h2 class="section-title">🗓️ REMEDIATION ROADMAP</h2>
            <div class="roadmap-timeline">
                {self._generate_roadmap_phase('Phase 1: Critical Fixes (24-48 hours)', critical, 'critical')}
                {self._generate_roadmap_phase('Phase 2: High Priority (1-2 weeks)', high, 'high')}
                {self._generate_roadmap_phase('Phase 3: Medium Priority (1 month)', medium, 'medium')}
                {self._generate_roadmap_phase('Phase 4: Low Priority (3 months)', low, 'low')}
            </div>
        </div>
        """

    def _generate_roadmap_phase(self, phase_name: str, items: List, severity: str) -> str:
        if not items:
            return f"""<div class="roadmap-phase {severity}"><div class="phase-header"><h3>{phase_name}</h3><span class="phase-count">0 items</span></div><p class="phase-empty">✅ No issues</p></div>"""
        
        list_items = ""
        for item in items:
            t = html.escape(item.get('type', 'Unknown'))
            u = html.escape(item.get('url') or item.get('endpoint', 'N/A'))
            list_items += f'<li><strong>{t}</strong> - {u}</li>'
            
        return f"""
        <div class="roadmap-phase {severity}">
            <div class="phase-header">
                <h3>{phase_name}</h3>
                <span class="phase-count">{len(items)} items</span>
            </div>
            <ul class="phase-items">{list_items}</ul>
        </div>
        """

    def _generate_footer(self) -> str:
        return f"""
        <div class="footer">
            <p><strong>REVUEX Vulnerability Suite v2.0</strong></p>
            <p>Report generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        </div>
        """

    def _generate_vuln_id(self, vuln: Dict) -> str:
        data = f"{vuln.get('type', '')}{vuln.get('url', '')}"
        return hashlib.md5(data.encode()).hexdigest()[:8].upper()

    def _get_enhanced_css(self) -> str:
        """Get enhanced CSS for professional report - v2.0"""
        # CSS Minified/Collapsed for brevity in python script, 
        # but expanded here for readability
        return """
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #1a202c; color: white; padding: 40px; text-align: center; }
        .section { padding: 30px; border-bottom: 1px solid #e2e8f0; }
        .section-title { color: #2d3748; margin-bottom: 20px; border-bottom: 2px solid #4a5568; padding-bottom: 10px; }
        
        /* Badges */
        .severity-badge { padding: 4px 10px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8em; }
        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: black; }
        .severity-badge.low { background: #28a745; }
        
        /* Layouts */
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 20px; }
        .summary-card { padding: 20px; background: #f8f9fa; border-radius: 8px; text-align: center; }
        .summary-card .number { font-size: 2em; font-weight: bold; }
        
        .severity-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .severity-card { padding: 15px; border-radius: 8px; color: white; }
        .severity-card.critical { background: #dc3545; }
        .severity-card.high { background: #fd7e14; }
        .severity-card.medium { background: #ffc107; color: black; }
        .severity-card.low { background: #28a745; }
        
        .code-block { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: monospace; }
        .vulnerability-card { margin-bottom: 30px; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
        .vuln-header { background: #f7fafc; padding: 15px; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; }
        .vuln-section { padding: 15px; }
        
        /* Roadmap */
        .remediation-roadmap { background: #f8f9fa; }
        .roadmap-phase { background: white; margin-bottom: 15px; padding: 15px; border-radius: 8px; border-left: 5px solid #cbd5e0; }
        .roadmap-phase.critical { border-left-color: #dc3545; }
        .roadmap-phase.high { border-left-color: #fd7e14; }
        
        .footer { background: #1a202c; color: white; padding: 20px; text-align: center; font-size: 0.9em; }
        """
