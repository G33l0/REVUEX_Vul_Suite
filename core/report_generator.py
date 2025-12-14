#!/usr/bin/env python3
“””
REVUEX Report Generator - World-Class Professional Security Reports
Author: G33L0
Telegram: @x0x0h33l0

Enhanced with:

- Executive Summary
- Technical Evidence
- Severity Assessment
- Clear Remediation Guidance
  “””

from pathlib import Path
from datetime import datetime
import json
import hashlib

class ReportGenerator:
“”“Generate professional HTML reports with comprehensive security analysis”””

```
def __init__(self, workspace):
    """Initialize report generator"""
    self.workspace = Path(workspace)
    
    # Severity scoring matrix
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

def generate_html_report(self, data):
    """Generate comprehensive HTML report with professional sections"""
    
    # Calculate executive metrics
    exec_summary = self._generate_executive_summary_data(data)
    
    html_content = f"""<!DOCTYPE html>
```

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REVUEX Security Assessment - {data['target']}</title>
    <style>
        {self._get_enhanced_css()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        {self._generate_header(data)}

```
    <!-- Executive Summary -->
    {self._generate_executive_summary(data, exec_summary)}
    
    <!-- Quick Stats Dashboard -->
    {self._generate_quick_stats(data)}
    
    <!-- Severity Breakdown -->
    {self._generate_severity_breakdown(data)}
    
    <!-- Confirmed Exploitable Bugs (with full technical evidence) -->
    {self._generate_confirmed_bugs_section(data['confirmed_bugs'])}
    
    <!-- All Vulnerabilities (with remediation guidance) -->
    {self._generate_vulnerabilities_section(data['vulnerabilities'])}
    
    <!-- Reconnaissance Results -->
    {self._generate_reconnaissance_section(data['reconnaissance'])}
    
    <!-- Remediation Roadmap -->
    {self._generate_remediation_roadmap(data)}
    
    <!-- Footer -->
    {self._generate_footer()}
</div>
```

</body>
</html>"""

```
    # Save report
    output_file = self.workspace / "REVUEX_PROFESSIONAL_REPORT.html"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # Also save executive summary as JSON
    exec_json = self.workspace / "executive_summary.json"
    with open(exec_json, 'w') as f:
        json.dump(exec_summary, f, indent=2)
    
    return output_file

def _generate_executive_summary_data(self, data):
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
        risk_level = 'CRITICAL'
        risk_color = '#dc3545'
    elif risk_score >= 60:
        risk_level = 'HIGH'
        risk_color = '#fd7e14'
    elif risk_score >= 30:
        risk_level = 'MEDIUM'
        risk_color = '#ffc107'
    else:
        risk_level = 'LOW'
        risk_color = '#28a745'
    
    # Calculate affected endpoints
    affected_endpoints = set()
    for vuln in vulnerabilities + confirmed_bugs:
        endpoint = vuln.get('url') or vuln.get('endpoint', '')
        if endpoint:
            affected_endpoints.add(endpoint)
    
    # Business impact assessment
    business_impact = self._calculate_business_impact(vulnerabilities, confirmed_bugs)
    
    # Attack surface metrics
    attack_surface = {
        'total_subdomains': len(data.get('reconnaissance', {}).get('subdomains', [])),
        'total_endpoints': sum(len(eps) for eps in data.get('reconnaissance', {}).get('endpoints', {}).values()),
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
        'business_impact': business_impact,
        'attack_surface': attack_surface,
        'remediation_timeline': self._calculate_remediation_timeline(stats),
        'compliance_impact': self._assess_compliance_impact(vulnerabilities, confirmed_bugs)
    }

def _calculate_business_impact(self, vulnerabilities, confirmed_bugs):
    """Calculate business impact assessment"""
    impacts = {
        'data_breach_risk': False,
        'financial_loss_risk': False,
        'reputation_damage_risk': False,
        'service_disruption_risk': False,
        'compliance_violation_risk': False
    }
    
    high_risk_types = ['SQL Injection', 'Authentication Bypass', 'RCE', 'IDOR', 'Sensitive Data Exposure']
    financial_risk_types = ['Price Manipulation', 'Payment Bypass', 'Discount Abuse']
    
    for vuln in vulnerabilities + confirmed_bugs:
        vuln_type = vuln.get('type', '')
        severity = vuln.get('severity', 'low').lower()
        
        if any(risk in vuln_type for risk in high_risk_types):
            impacts['data_breach_risk'] = True
            impacts['compliance_violation_risk'] = True
        
        if any(risk in vuln_type for risk in financial_risk_types):
            impacts['financial_loss_risk'] = True
        
        if severity in ['critical', 'high']:
            impacts['reputation_damage_risk'] = True
        
        if 'DoS' in vuln_type or 'Race Condition' in vuln_type:
            impacts['service_disruption_risk'] = True
    
    return impacts

def _calculate_remediation_timeline(self, severity_stats):
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

def _assess_compliance_impact(self, vulnerabilities, confirmed_bugs):
    """Assess compliance and regulatory impact"""
    compliance_issues = {
        'PCI_DSS': False,
        'GDPR': False,
        'HIPAA': False,
        'SOC2': False,
        'ISO27001': False
    }
    
    for vuln in vulnerabilities + confirmed_bugs:
        vuln_type = vuln.get('type', '')
        tags = vuln.get('tags', [])
        
        if 'payment' in tags or 'Price Manipulation' in vuln_type:
            compliance_issues['PCI_DSS'] = True
        
        if 'IDOR' in vuln_type or 'Data Exposure' in vuln_type:
            compliance_issues['GDPR'] = True
            compliance_issues['HIPAA'] = True
        
        if vuln.get('severity', '').lower() in ['critical', 'high']:
            compliance_issues['SOC2'] = True
            compliance_issues['ISO27001'] = True
    
    return compliance_issues

def _identify_vulnerable_technologies(self, data):
    """Identify vulnerable technologies"""
    vuln_tech = set()
    
    technologies = data.get('reconnaissance', {}).get('technologies', {})
    for subdomain, tech_data in technologies.items():
        tech_list = tech_data.get('technologies', [])
        vuln_tech.update(tech_list)
    
    return list(vuln_tech)

def _generate_header(self, data):
    """Generate report header"""
    return f"""
    <div class="header">
        <h1>🔒 REVUEX</h1>
        <div class="subtitle">Professional Security Assessment Report</div>
        <div class="target-badge">{data['target']}</div>
        <div class="author">
            <strong>Security Researcher:</strong> G33L0 | 
            <strong>Contact:</strong> @x0x0h33l0 | 
            <strong>Date:</strong> {datetime.now().strftime('%B %d, %Y')}
        </div>
    </div>
    """

def _generate_executive_summary(self, data, exec_summary):
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
                This security assessment of <strong>{data['target']}</strong> was conducted from 
                <strong>{data['start_time']}</strong> to <strong>{data['end_time']}</strong> 
                (Duration: {data['duration']}). The assessment employed automated vulnerability 
                discovery techniques across {exec_summary['attack_surface']['total_subdomains']} 
                subdomains and {exec_summary['attack_surface']['total_endpoints']} endpoints.
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
                <div class="finding-item">
                    <div class="finding-number critical">{exec_summary['severity_distribution'].get('critical', 0)}</div>
                    <div class="finding-label">Critical Severity</div>
                </div>
            </div>
        </div>
        
        <div class="exec-box">
            <h3>💼 Business Impact Assessment</h3>
            <div class="impact-grid">
                {self._generate_impact_items(active_impacts)}
            </div>
            {self._generate_no_impacts_message(active_impacts)}
        </div>
        
        <div class="exec-box">
            <h3>⚖️ Compliance & Regulatory Impact</h3>
            {self._generate_compliance_section(compliance_at_risk)}
        </div>
        
        <div class="exec-box">
            <h3>🛠️ Recommended Actions</h3>
            <div class="action-timeline">
                <div class="action-item immediate">
                    <div class="action-header">
                        <span class="action-badge critical">IMMEDIATE (24-48 hours)</span>
                    </div>
                    <div class="action-content">
                        Address {exec_summary['remediation_timeline']['immediate_action']} critical vulnerabilities.
                        Focus on confirmed exploits with direct business impact.
                    </div>
                </div>
                <div class="action-item urgent">
                    <div class="action-header">
                        <span class="action-badge high">SHORT-TERM (1-2 weeks)</span>
                    </div>
                    <div class="action-content">
                        Remediate {exec_summary['remediation_timeline']['short_term']} high-severity issues.
                        Implement security controls and monitoring.
                    </div>
                </div>
                <div class="action-item moderate">
                    <div class="action-header">
                        <span class="action-badge medium">MEDIUM-TERM (1 month)</span>
                    </div>
                    <div class="action-content">
                        Fix {exec_summary['remediation_timeline']['medium_term']} medium-severity vulnerabilities.
                        Enhance security architecture.
                    </div>
                </div>
                <div class="action-item low-priority">
                    <div class="action-header">
                        <span class="action-badge low">LONG-TERM (3 months)</span>
                    </div>
                    <div class="action-content">
                        Address {exec_summary['remediation_timeline']['long_term']} low-severity findings.
                        Implement security best practices.
                    </div>
                </div>
            </div>
            <div class="timeline-summary">
                <strong>Estimated Total Remediation Time:</strong> {exec_summary['remediation_timeline']['estimated_total_days']} days
                with dedicated security team resources.
            </div>
        </div>
        
        <div class="exec-box key-recommendations">
            <h3>🎯 Key Recommendations</h3>
            <ol class="recommendations-list">
                <li><strong>Immediate Patch Deployment:</strong> Apply security patches for all critical vulnerabilities within 24 hours.</li>
                <li><strong>Security Review:</strong> Conduct code review for affected components, especially authentication and authorization mechanisms.</li>
                <li><strong>Monitoring Enhancement:</strong> Implement real-time security monitoring and alerting for exploit attempts.</li>
                <li><strong>Penetration Testing:</strong> Schedule follow-up manual penetration testing to validate automated findings.</li>
                <li><strong>Security Training:</strong> Provide secure coding training to development team focusing on identified vulnerability patterns.</li>
            </ol>
        </div>
    </div>
    """

def _generate_impact_items(self, impacts):
    """Generate impact items HTML"""
    if not impacts:
        return ""
    
    html = ""
    for impact in impacts:
        html += f'<div class="impact-item">⚠️ {impact}</div>'
    return html

def _generate_no_impacts_message(self, impacts):
    """Generate message when no impacts detected"""
    if impacts:
        return ""
    return '<p class="no-impact">✅ No immediate business-critical impacts detected in automated scan.</p>'

def _generate_compliance_section(self, compliance_at_risk):
    """Generate compliance section"""
    if not compliance_at_risk:
        return '<p class="no-impact">✅ No direct compliance violations detected in automated scan.</p>'
    
    html = '<div class="compliance-grid">'
    for standard in compliance_at_risk:
        html += f'<div class="compliance-item">⚠️ {standard}</div>'
    html += '</div>'
    html += '<p class="compliance-note"><em>Note: Manual review recommended to confirm compliance impact.</em></p>'
    return html

def _generate_quick_stats(self, data):
    """Generate quick stats dashboard"""
    return f"""
    <div class="summary">
        <div class="summary-card">
            <div class="number critical">{len(data['confirmed_bugs'])}</div>
            <div class="label">Confirmed Exploits</div>
        </div>
        <div class="summary-card">
            <div class="number high">{len(data['vulnerabilities'])}</div>
            <div class="label">Total Vulnerabilities</div>
        </div>
        <div class="summary-card">
            <div class="number info">{len(data['reconnaissance']['subdomains'])}</div>
            <div class="label">Subdomains Scanned</div>
        </div>
        <div class="summary-card">
            <div class="number medium">{sum(len(eps) for eps in data['reconnaissance']['endpoints'].values())}</div>
            <div class="label">Endpoints Discovered</div>
        </div>
    </div>
    """

def _generate_severity_breakdown(self, data):
    """Generate severity breakdown section"""
    stats = data['statistics']['findings']
    
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

def _generate_severity_detail(self, severity, count):
    """Generate individual severity detail card"""
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

def _generate_confirmed_bugs_section(self, bugs):
    """Generate confirmed bugs section with full technical evidence"""
    if not bugs:
        return """
    <div class="section">
        <h2 class="section-title">🎯 CONFIRMED EXPLOITABLE BUGS</h2>
        <div class="no-findings">
            <div class="success-icon">✅</div>
            <p>No confirmed exploitable bugs were discovered during this assessment.</p>
        </div>
    </div>
        """
    
    html = """
    <div class="section">
        <h2 class="section-title">🎯 CONFIRMED EXPLOITABLE BUGS</h2>
        <p class="section-description">
            The following vulnerabilities have been confirmed as exploitable through automated testing.
            Each finding includes complete technical evidence and proof-of-concept.
        </p>
    """
    
    for idx, bug in enumerate(bugs, 1):
        severity = bug.get('severity', 'high').lower()
        html += f"""
        <div class="vulnerability-card {severity}">
            {self._generate_vuln_header(idx, bug, 'CONFIRMED EXPLOIT')}
            
            <!-- Basic Information -->
            <div class="vuln-section">
                <h4 class="vuln-section-title">📋 Vulnerability Details</h4>
                {self._generate_basic_info(bug)}
            </div>
            
            <!-- Technical Evidence -->
            <div class="vuln-section">
                <h4 class="vuln-section-title">🔬 TECHNICAL EVIDENCE</h4>
                {self._generate_technical_evidence(bug)}
            </div>
            
            <!-- Proof of Concept -->
            {self._generate_poc_section(bug)}
            
            <!-- Impact Assessment -->
            {self._generate_impact_assessment(bug, severity)}
            
            <!-- Remediation Guidance -->
            <div class="vuln-section">
                <h4 class="vuln-section-title">🛠️ REMEDIATION GUIDANCE</h4>
                {self._generate_detailed_remediation(bug, severity)}
            </div>
            
            <!-- Metadata -->
            <div class="vuln-metadata">
                <span><strong>Confirmed:</strong> {bug.get('confirmed_at', 'N/A')}</span>
                <span><strong>CVE:</strong> {bug.get('cve', 'Pending')}</span>
                <span><strong>Reference ID:</strong> REV-{self._generate_vuln_id(bug)}</span>
            </div>
        </div>
        """
    
    html += "</div>"
    return html

def _generate_vulnerabilities_section(self, vulnerabilities):
    """Generate vulnerabilities section with remediation guidance"""
    if not vulnerabilities:
        return """
    <div class="section" style="background: #f8f9fa;">
        <h2 class="section-title">🔍 DETECTED VULNERABILITIES</h2>
        <div class="no-findings">
            <div class="success-icon">✅</div>
            <p>No additional vulnerabilities detected beyond confirmed exploits.</p>
        </div>
    </div>
        """
    
    html = """
    <div class="section" style="background: #f8f9fa;">
        <h2 class="section-title">🔍 DETECTED VULNERABILITIES</h2>
        <p class="section-description">
            Additional security issues discovered during reconnaissance and scanning phases.
            While not yet confirmed as exploitable, these warrant immediate investigation.
        </p>
    """
    
    for idx, vuln in enumerate(vulnerabilities, 1):
        severity = vuln.get('severity', 'medium').lower()
        html += f"""
        <div class="vulnerability-card {severity}">
            {self._generate_vuln_header(idx, vuln, 'POTENTIAL VULNERABILITY')}
            
            <!-- Basic Information -->
            <div class="vuln-section">
                <h4 class="vuln-section-title">📋 Vulnerability Details</h4>
                {self._generate_basic_info(vuln)}
            </div>
            
            <!-- Evidence -->
            <div class="vuln-section">
                <h4 class="vuln-section-title">🔍 Evidence</h4>
                {self._generate_evidence_section(vuln)}
            </div>
            
            <!-- Impact Assessment -->
            {self._generate_impact_assessment(vuln, severity)}
            
            <!-- Remediation -->
            <div class="vuln-section">
                <h4 class="vuln-section-title">🛠️ REMEDIATION GUIDANCE</h4>
                {self._generate_detailed_remediation(vuln, severity)}
            </div>
            
            <!-- Metadata -->
            <div class="vuln-metadata">
                <span><strong>Discovered:</strong> {vuln.get('discovered_at', 'N/A')}</span>
                <span><strong>Reference ID:</strong> REV-{self._generate_vuln_id(vuln)}</span>
            </div>
        </div>
        """
    
    html += "</div>"
    return html

def _generate_vuln_header(self, index, vuln, badge_text):
    """Generate vulnerability header"""
    severity = vuln.get('severity', 'medium').lower()
    severity_info = self.severity_matrix[severity]
    
    return f"""
    <div class="vuln-header">
        <div class="vuln-title">
            <span class="vuln-index">[{index}]</span>
            {vuln.get('type', 'Unknown Vulnerability')}
        </div>
        <div class="vuln-badges">
            <span class="exploit-badge">{badge_text}</span>
            <span class="severity-badge {severity}">
                {severity_info['icon']} {severity.upper()}
            </span>
        </div>
    </div>
    """

def _generate_basic_info(self, vuln):
    """Generate basic vulnerability information"""
    return f"""
    <div class="info-grid">
        <div class="info-item">
            <strong>Target Endpoint:</strong>
            <code>{vuln.get('url', vuln.get('endpoint', 'N/A'))}</code>
        </div>
        <div class="info-item">
            <strong>Vulnerability Type:</strong>
            <span class="vuln-type-badge">{vuln.get('type', 'Unknown')}</span>
        </div>
        <div class="info-item">
            <strong>Description:</strong>
            {vuln.get('description', 'No description available')}
        </div>
    </div>
    """

def _generate_technical_evidence(self, bug):
    """Generate comprehensive technical evidence section"""
    evidence = bug.get('evidence', 'No evidence available')
    
    # Generate HTTP request/response if available
    http_evidence = self._generate_http_evidence(bug)
    
    return f"""
    <div class="evidence-container">
        <div class="evidence-item">
            <strong>Finding:</strong>
            <p>{evidence}</p>
        </div>
        
        {http_evidence}
        
        {self._generate_reproduction_steps(bug)}
    </div>
    """

def _generate_http_evidence(self, vuln):
    """Generate HTTP request/response evidence"""
    request = vuln.get('request', '')
    response = vuln.get('response', '')
    
    if not request and not response:
        return ""
    
    html = '<div class="http-evidence">'
    
    if request:
        html += f"""
        <div class="http-block">
            <div class="http-label">📤 HTTP Request</div>
            <div class="code-block">{self._escape_html(request)}</div>
        </div>
        """
    
    if response:
        html += f"""
        <div class="http-block">
            <div class="http-label">📥 HTTP Response</div>
            <div class="code-block">{self._escape_html(response)}</div>
        </div>
        """
    
    html += '</div>'
    return html

def _generate_reproduction_steps(self, vuln):
    """Generate step-by-step reproduction guide"""
    attack_path = vuln.get('attack_path', [])
    
    if not attack_path:
        return ""
    
    html = """
    <div class="reproduction-steps">
        <div class="http-label">🔄 Reproduction Steps</div>
        <ol class="steps-list">
    """
    
    for step in attack_path:
        html += f'<li>{step}</li>'
    
    html += """
        </ol>
    </div>
    """
    return html

def _generate_evidence_section(self, vuln):
    """Generate evidence section for potential vulnerabilities"""
    evidence = vuln.get('evidence', 'No evidence available')
    
    return f"""
    <div class="evidence-container">
        <p>{evidence}</p>
        {self._generate_http_evidence(vuln)}
    </div>
    """

def _generate_poc_section(self, bug):
    """Generate proof of concept section"""
    poc = bug.get('poc', '')
    
    if not poc:
        return ""
    
    return f"""
    <div class="vuln-section">
        <h4 class="vuln-section-title">💣 Proof of Concept</h4>
        <div class="code-block">{self._escape_html(poc)}</div>
    </div>
    """

def _generate_impact_assessment(self, vuln, severity):
    """Generate detailed impact assessment"""
    severity_info = self.severity_matrix[severity]
    
    # Determine potential impacts based on vulnerability type
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
                <ul>
                    {impacts}
                </ul>
            </div>
            <div class="impact-timeline">
                <strong>Remediation SLA:</strong> {severity_info['sla']}
            </div>
        </div>
    </div>
    """

def _determine_impacts(self, vuln):
    """Determine potential impacts based on vulnerability type"""
    vuln_type = vuln.get('type', '').lower()
    impacts = []
    
    if 'sql injection' in vuln_type or 'sqli' in vuln_type:
        impacts = [
            'Complete database compromise',
            'Unauthorized access to sensitive data',
            'Data manipulation or deletion',
            'Potential server takeover'
        ]
    elif 'xss' in vuln_type or 'cross-site scripting' in vuln_type:
        impacts = [
            'Session hijacking',
            'Credential theft',
            'Phishing attacks',
            'Malware distribution'
        ]
    elif 'idor' in vuln_type or 'broken access' in vuln_type:
        impacts = [
            'Unauthorized data access',
            'Privacy violations',
            'Account takeover potential',
            'Compliance violations (GDPR/CCPA)'
        ]
    elif 'race condition' in vuln_type:
        impacts = [
            'Business logic bypass',
            'Financial loss',
            'Inventory manipulation',
            'System integrity compromise'
        ]
    elif 'price manipulation' in vuln_type or 'payment' in vuln_type:
        impacts = [
            'Direct financial loss',
            'Revenue leakage',
            'Fraud exploitation',
            'Payment system compromise'
        ]
    elif 'graphql' in vuln_type:
        impacts = [
            'Data schema exposure',
            'Mass data extraction',
            'DoS through complex queries',
            'Authorization bypass'
        ]
    elif 'jwt' in vuln_type or 'token' in vuln_type:
        impacts = [
            'Authentication bypass',
            'Session manipulation',
            'Privilege escalation',
            'Identity theft'
        ]
    else:
        impacts = [
            'Security posture degradation',
            'Potential exploitation vector',
            'Information disclosure',
            'Attack surface expansion'
        ]
    
    return ''.join(f'<li>{impact}</li>' for impact in impacts)

def _generate_detailed_remediation(self, vuln, severity):
    """Generate comprehensive remediation guidance"""
    vuln_type = vuln.get('type', '').lower()
    
    # Get vulnerability-specific remediation
    remediation_steps = self._get_remediation_steps(vuln_type)
    
    # Get custom remediation from vulnerability data
    custom_remediation = vuln.get('remediation', [])
    
    severity_info = self.severity_matrix[severity]
    
    html = f"""
    <div class="remediation-container">
        <div class="remediation-priority" style="border-left-color: {severity_info['color']};">
            <strong>⏰ Priority Level:</strong> {severity_info['priority']} 
            <span class="remediation-sla">(Fix within {severity_info['sla']})</span>
        </div>
        
        <div class="remediation-steps">
            <strong>🔧 Immediate Actions:</strong>
            <ol>
                {remediation_steps}
            </ol>
        </div>
    """
    
    if custom_remediation:
        html += """
        <div class="remediation-specific">
            <strong>📝 Specific Recommendations:</strong>
            <ul>
        """
        for rec in custom_remediation:
            html += f'<li>{rec}</li>'
        html += """
            </ul>
        </div>
        """
    
    # Add validation steps
    html += """
        <div class="remediation-validation">
            <strong>✅ Validation Steps:</strong>
            <ol>
                <li>Apply the recommended fixes in a development environment</li>
                <li>Perform regression testing to ensure functionality</li>
                <li>Conduct security testing to verify the fix</li>
                <li>Deploy to production during low-traffic period</li>
                <li>Monitor logs for any anomalies post-deployment</li>
                <li>Schedule re-scan to confirm vulnerability resolution</li>
            </ol>
        </div>
    </div>
    """
    
    return html

def _get_remediation_steps(self, vuln_type):
    """Get specific remediation steps based on vulnerability type"""
    remediation_map = {
        'sql injection': """
            <li>Implement parameterized queries (prepared statements) for all database operations</li>
            <li>Use ORM frameworks with built-in SQL injection protection</li>
            <li>Validate and sanitize all user inputs with whitelist approach</li>
            <li>Apply principle of least privilege to database accounts</li>
            <li>Enable WAF rules to detect and block SQL injection attempts</li>
            <li>Regular security audits of database queries</li>
        """,
        'xss': """
            <li>Implement context-aware output encoding for all user-generated content</li>
            <li>Use Content Security Policy (CSP) headers to restrict script execution</li>
            <li>Sanitize HTML input using trusted libraries (DOMPurify, OWASP Java Encoder)</li>
            <li>Enable HTTPOnly and Secure flags on all cookies</li>
            <li>Implement strict input validation with whitelist approach</li>
            <li>Regular XSS scanning and penetration testing</li>
        """,
        'idor': """
            <li>Implement indirect object references (mapping IDs internally)</li>
            <li>Add authorization checks before every data access operation</li>
            <li>Use UUID or cryptographic random IDs instead of sequential integers</li>
            <li>Implement access control matrix for resource permissions</li>
            <li>Log all access attempts with user context for auditing</li>
            <li>Regular access control testing and review</li>
        """,
        'race condition': """
            <li>Implement database-level locking (pessimistic or optimistic)</li>
            <li>Use atomic operations for critical business logic</li>
            <li>Implement idempotency keys for sensitive transactions</li>
            <li>Add rate limiting on critical endpoints</li>
            <li>Use distributed locks (Redis/Memcached) for multi-server setups</li>
            <li>Implement request deduplication mechanisms</li>
        """,
        'price manipulation': """
            <li>Implement server-side price validation before checkout</li>
            <li>Never trust client-side pricing data</li>
            <li>Use cryptographic signatures for price data integrity</li>
            <li>Implement real-time fraud detection algorithms</li>
            <li>Add transaction logging and monitoring</li>
            <li>Regular financial reconciliation and audits</li>
        """,
        'graphql': """
            <li>Disable GraphQL introspection in production environments</li>
            <li>Implement query depth limiting and complexity analysis</li>
            <li>Add field-level authorization checks</li>
            <li>Implement query cost analysis and rate limiting</li>
            <li>Use persisted queries to prevent arbitrary query execution</li>
            <li>Regular schema review and access control audits</li>
        """,
        'jwt': """
            <li>Use strong signing algorithms (RS256 instead of HS256 for public systems)</li>
            <li>Implement proper key management and rotation</li>
            <li>Set appropriate token expiration times (short-lived tokens)</li>
            <li>Validate all JWT claims (iss, aud, exp, nbf)</li>
            <li>Implement token revocation mechanism</li>
            <li>Never store sensitive data in JWT payload</li>
        """
    }
    
    # Find matching remediation
    for key, value in remediation_map.items():
        if key in vuln_type:
            return value
    
    # Default remediation
    return """
        <li>Review and patch the affected component according to security best practices</li>
        <li>Implement input validation and output encoding</li>
        <li>Apply principle of least privilege</li>
        <li>Enable security logging and monitoring</li>
        <li>Conduct security code review of affected areas</li>
        <li>Schedule follow-up penetration testing</li>
    """

def _generate_reconnaissance_section(self, recon_data):
    """Generate reconnaissance section"""
    html = """
    <div class="section">
        <h2 class="section-title">🔎 RECONNAISSANCE RESULTS</h2>
        <p class="section-description">
            Discovery phase results showing the attack surface mapped during the assessment.
        </p>
        
        <h3 style="margin: 30px 0 20px 0; color: #1e3c72;">🌐 Discovered Subdomains</h3>
        <div class="subdomain-list">
    """
    
    for subdomain in recon_data.get('subdomains', []):
        tech = recon_data.get('technologies', {}).get(subdomain, {})
        technologies = tech.get('technologies', [])
        
        html += f"""
        <div class="subdomain-item">
            <div class="domain">🌐 {subdomain}</div>
            <div class="tech">
        """
        
        if technologies:
            for t in technologies[:5]:
                html += f'<span class="tech-badge">{t}</span>'
        else:
            html += '<span class="tech-badge">Unknown Stack</span>'
        
        html += """
            </div>
        </div>
        """
    
    html += """
        </div>
    </div>
    """
    return html

def _generate_remediation_roadmap(self, data):
    """Generate comprehensive remediation roadmap"""
    vulnerabilities = data.get('vulnerabilities', [])
    confirmed_bugs = data.get('confirmed_bugs', [])
    
    # Organize by severity and timeline
    critical_items = [v for v in vulnerabilities + confirmed_bugs if v.get('severity', '').lower() == 'critical']
    high_items = [v for v in vulnerabilities + confirmed_bugs if v.get('severity', '').lower() == 'high']
    medium_items = [v for v in vulnerabilities + confirmed_bugs if v.get('severity', '').lower() == 'medium']
    low_items = [v for v in vulnerabilities + confirmed_bugs if v.get('severity', '').lower() == 'low']
    
    return f"""
    <div class="section remediation-roadmap">
        <h2 class="section-title">🗓️ REMEDIATION ROADMAP</h2>
        <p class="section-description">
            Prioritized action plan for addressing identified security issues.
        </p>
        
        <div class="roadmap-timeline">
            {self._generate_roadmap_phase('Phase 1: Critical Fixes (24-48 hours)', critical_items, 'critical')}
            {self._generate_roadmap_phase('Phase 2: High Priority (1-2 weeks)', high_items, 'high')}
            {self._generate_roadmap_phase('Phase 3: Medium Priority (1 month)', medium_items, 'medium')}
            {self._generate_roadmap_phase('Phase 4: Low Priority (3 months)', low_items, 'low')}
        </div>
        
        <div class="roadmap-summary">
            <h3>📊 Remediation Summary</h3>
            <ul>
                <li><strong>Total Items:</strong> {len(critical_items + high_items + medium_items + low_items)}</li>
                <li><strong>Immediate Action Required:</strong> {len(critical_items)} critical issues</li>
                <li><strong>Short-term Focus:</strong> {len(high_items)} high-severity issues</li>
                <li><strong>Estimated Timeline:</strong> {self._calculate_total_timeline(critical_items, high_items, medium_items, low_items)}</li>
            </ul>
        </div>
    </div>
    """

def _generate_roadmap_phase(self, phase_name, items, severity):
    """Generate individual roadmap phase"""
    if not items:
        return f"""
        <div class="roadmap-phase {severity}">
            <div class="phase-header">
                <h3>{phase_name}</h3>
                <span class="phase-count">0 items</span>
            </div>
            <p class="phase-empty">✅ No issues in this category</p>
        </div>
        """
    
    html = f"""
    <div class="roadmap-phase {severity}">
        <div class="phase-header">
            <h3>{phase_name}</h3>
            <span class="phase-count">{len(items)} items</span>
        </div>
        <ul class="phase-items">
    """
    
    for item in items:
        vuln_type = item.get('type', 'Unknown')
        endpoint = item.get('url', item.get('endpoint', 'N/A'))
        html += f'<li><strong>{vuln_type}</strong> - {endpoint}</li>'
    
    html += """
        </ul>
    </div>
    """
    return html

def _calculate_total_timeline(self, critical, high, medium, low):
    """Calculate total remediation timeline"""
    days = len(critical) * 1 + len(high) * 3 + len(medium) * 7 + len(low) * 14
    
    if days < 7:
        return f"{days} days"
    elif days < 30:
        weeks = days // 7
        return f"{weeks} weeks"
    else:
        months = days // 30
        return f"{months} months"

def _generate_footer(self):
    """Generate report footer"""
    return f"""
    <div class="footer">
        <p><strong>REVUEX Vulnerability Suite</strong> - Professional Security Assessment Platform</p>
        <p>Report generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        <p>Security Researcher: G33L0 | Contact: <a href="https://t.me/x0x0h33l0">@x0x0h33l0</a></p>
        <p style="margin-top: 20px; font-size: 0.9em; opacity: 0.8;">
            ⚠️ <strong>CONFIDENTIAL:</strong> This report contains sensitive security information.
            Distribution should be limited to authorized personnel only.
        </p>
        <p style="font-size: 0.85em; opacity: 0.7; margin-top: 10px;">
            <strong>Disclaimer:</strong> This assessment was performed using automated tools.
            Manual verification and penetration testing are recommended to confirm findings.
        </p>
    </div>
    """

def _generate_vuln_id(self, vuln):
    """Generate unique vulnerability reference ID"""
    data = f"{vuln.get('type', '')}{vuln.get('url', '')}{vuln.get('discovered_at', '')}"
    return hashlib.md5(data.encode()).hexdigest()[:8].upper()

def _escape_html(self, text):
    """Escape HTML special characters"""
    if not text:
        return ""
    return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))

def _get_enhanced_css(self):
    """Get enhanced CSS for professional report"""
    return """
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        color: #333;
        line-height: 1.6;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        background: white;
        border-radius: 20px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        overflow: hidden;
    }
    
    .header {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        color: white;
        padding: 50px 40px;
        text-align: center;
    }
    
    .header h1 {
        font-size: 3.5em;
        margin-bottom: 10px;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        font-family: 'Courier New', monospace;
        letter-spacing: 3px;
    }
    
    .header .subtitle {
        font-size: 1.3em;
        opacity: 0.9;
        margin-bottom: 15px;
    }
    
    .header .target-badge {
        display: inline-block;
        background: rgba(255,255,255,0.2);
        padding: 10px 30px;
        border-radius: 25px;
        font-size: 1.1em;
        margin: 15px 0;
        border: 2px solid rgba(255,255,255,0.3);
    }
    
    .header .author {
        margin-top: 20px;
        padding-top: 20px;
        border-top: 1px solid rgba(255,255,255,0.3);
        font-size: 0.95em;
    }
    
    /* Executive Summary Styles */
    .executive-summary {
        background: #f8f9fa;
    }
    
    .exec-box {
        background: white;
        padding: 25px;
        margin: 20px 0;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .exec-box h3 {
        color: #1e3c72;
        margin-bottom: 15px;
        font-size: 1.4em;
        border-bottom: 2px solid #667eea;
        padding-bottom: 10px;
    }
    
    .exec-text {
        font-size: 1.05em;
        line-height: 1.8;
        color: #555;
    }
    
    .risk-score-container {
        text-align: center;
        margin: 30px 0;
    }
    
    .risk-score {
        display: inline-block;
        background: white;
        padding: 30px 50px;
        border-radius: 15px;
        border: 4px solid;
        box-shadow: 0 5px 20px rgba(0,0,0,0.15);
    }
    
    .risk-number {
        font-size: 4em;
        font-weight: bold;
        margin-bottom: 10px;
    }
    
    .risk-label {
        color: white;
        padding: 10px 25px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 1.1em;
    }
    
    .critical-findings {
        background: linear-gradient(135deg, #fff5f5 0%, #ffe5e5 100%);
        border-left: 5px solid #dc3545;
    }
    
    .finding-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }
    
    .finding-item {
        text-align: center;
        padding: 20px;
        background: white;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .finding-number {
        font-size: 2.5em;
        font-weight: bold;
        margin-bottom: 10px;
    }
    
    .finding-label {
        color: #666;
        font-size: 0.9em;
        text-transform: uppercase;
    }
    
    .impact-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 15px;
        margin-top: 15px;
    }
    
    .impact-item {
        background: #fff3cd;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #ffc107;
        font-size: 0.95em;
    }
    
    .no-impact {
        color: #28a745;
        font-size: 1.1em;
        padding: 15px;
        background: #d4edda;
        border-radius: 8px;
        margin-top: 10px;
    }
    
    .compliance-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin-top: 15px;
    }
    
    .compliance-item {
        background: #fff3cd;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #fd7e14;
        text-align: center;
        font-weight: bold;
    }
    
    .compliance-note {
        margin-top: 15px;
        font-size: 0.9em;
        color: #666;
        font-style: italic;
    }
    
    .action-timeline {
        margin-top: 20px;
    }
    
    .action-item {
        margin: 15px 0;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid;
    }
    
    .action-item.immediate {
        background: #fff5f5;
        border-left-color: #dc3545;
    }
    
    .action-item.urgent {
        background: #fff8f0;
        border-left-color: #fd7e14;
    }
    
    .action-item.moderate {
        background: #fffbf0;
        border-left-color: #ffc107;
    }
    
    .action-item.low-priority {
        background: #f0fff4;
        border-left-color: #28a745;
    }
    
    .action-header {
        margin-bottom: 10px;
    }
    
    .action-badge {
        display: inline-block;
        padding: 8px 20px;
        border-radius: 20px;
        color: white;
        font-weight: bold;
        font-size: 0.85em;
    }
    
    .action-badge.critical { background: #dc3545; }
    .action-badge.high { background: #fd7e14; }
    .action-badge.medium { background: #ffc107; color: #333; }
    .action-badge.low { background: #28a745; }
    
    .action-content {
        margin-top: 10px;
        line-height: 1.6;
    }
    
    .timeline-summary {
        margin-top: 20px;
        padding: 15px;
        background: #e9ecef;
        border-radius: 8px;
        text-align: center;
    }
    
    .key-recommendations {
        background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
        border-left: 5px solid #28a745;
    }
    
    .recommendations-list {
        margin-top: 15px;
        margin-left: 25px;
    }
    
    .recommendations-list li {
        margin: 12px 0;
        line-height: 1.6;
    }
    
    /* Summary Cards */
    .summary {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        padding: 40px;
        background: #f8f9fa;
    }
    
    .summary-card {
        background: white;
        padding: 25px;
        border-radius: 15px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        text-align: center;
        transition: transform 0.3s;
    }
    
    .summary-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(0,0,0,0.15);
    }
    
    .summary-card .number {
        font-size: 3em;
        font-weight: bold;
        margin-bottom: 10px;
    }
    
    .summary-card .label {
        color: #666;
        font-size: 0.9em;
        text-transform: uppercase;
    }
    
    /* Severity Colors */
    .critical { color: #dc3545; }
    .high { color: #fd7e14; }
    .medium { color: #ffc107; }
    .low { color: #28a745; }
    .info { color: #17a2b8; }
    
    /* Severity Breakdown */
    .severity-details {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
    }
    
    .severity-card {
        background: white;
        padding: 25px;
        border-radius: 12px;
        border-left: 5px solid;
        box-shadow: 0 3px 10px rgba(0,0,0,0.1);
    }
    
    .severity-card.critical {
        border-left-color: #dc3545;
        background: linear-gradient(135deg, #fff 0%, #fff5f5 100%);
    }
    
    .severity-card.high {
        border-left-color: #fd7e14;
        background: linear-gradient(135deg, #fff 0%, #fff8f0 100%);
    }
    
    .severity-card.medium {
        border-left-color: #ffc107;
        background: linear-gradient(135deg, #fff 0%, #fffbf0 100%);
    }
    
    .severity-card.low {
        border-left-color: #28a745;
        background: linear-gradient(135deg, #fff 0%, #f0fff4 100%);
    }
    
    .severity-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
        padding-bottom: 15px;
        border-bottom: 2px solid #f0f0f0;
    }
    
    .severity-icon {
        font-size: 2em;
    }
    
    .severity-name {
        font-size: 1.3em;
        font-weight: bold;
    }
    
    .severity-count {
        font-size: 2em;
        font-weight: bold;
    }
    
    .severity-info {
        margin-top: 15px;
    }
    
    .severity-info div {
        margin: 8px 0;
        font-size: 0.9em;
    }
    
    /* Section Styles */
    .section {
        padding: 40px;
    }
    
    .section-title {
        font-size: 2em;
        margin-bottom: 15px;
        color: #1e3c72;
        border-bottom: 3px solid #667eea;
        padding-bottom: 10px;
    }
    
    .section-description {
        font-size: 1.05em;
        color: #666;
        margin-bottom: 25px;
        line-height: 1.6;
    }
    
    .no-findings {
        text-align: center;
        padding: 60px 20px;
        background: #f8f9fa;
        border-radius: 15px;
    }
    
    .success-icon {
        font-size: 5em;
        margin-bottom: 20px;
    }
    
    /* Vulnerability Card Styles */
    .vulnerability-card {
        background: white;
        border-left: 5px solid #667eea;
        padding: 30px;
        margin-bottom: 25px;
        border-radius: 12px;
        box-shadow: 0 3px 15px rgba(0,0,0,0.1);
    }
    
    .vulnerability-card.critical {
        border-left-color: #dc3545;
        background: linear-gradient(135deg, #fff 0%, #fff5f5 100%);
    }
    
    .vulnerability-card.high {
        border-left-color: #fd7e14;
        background: linear-gradient(135deg, #fff 0%, #fff8f0 100%);
    }
    
    .vulnerability-card.medium {
        border-left-color: #ffc107;
        background: linear-gradient(135deg, #fff 0%, #fffbf0 100%);
    }
    
    .vulnerability-card.low {
        border-left-color: #28a745;
        background: linear-gradient(135deg, #fff 0%, #f0fff4 100%);
    }
    
    .vuln-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 25px;
        padding-bottom: 20px;
        border-bottom: 2px solid #f0f0f0;
    }
    
    .vuln-title {
        font-size: 1.4em;
        font-weight: bold;
        color: #1e3c72;
        flex: 1;
    }
    
    .vuln-index {
        color: #667eea;
        margin-right: 10px;
    }
    
    .vuln-badges {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
    }
    
    .exploit-badge {
        background: #dc3545;
        color: white;
        padding: 6px 15px;
        border-radius: 15px;
        font-size: 0.75em;
        font-weight: bold;
        text-transform: uppercase;
    }
    
    .severity-badge {
        padding: 8px 20px;
        border-radius: 20px;
        color: white;
        font-weight: bold;
        font-size: 0.85em;
        text-transform: uppercase;
    }
    
    .severity-badge.critical { background: #dc3545; }
    .severity-badge.high { background: #fd7e14; }
    .severity-badge.medium { background: #ffc107; color: #333; }
    .severity-badge.low { background: #28a745; }
    
    .vuln-section {
        margin: 25px 0;
        padding: 20px;
        background: rgba(255,255,255,0.5);
        border-radius: 8px;
    }
    
    .vuln-section-title {
        color: #1e3c72;
        font-size: 1.2em;
        margin-bottom: 15px;
        padding-bottom: 10px;
        border-bottom: 2px solid #e9ecef;
    }
    
    .info-grid {
        display: grid;
        gap: 15px;
    }
    
    .info-item {
        padding: 12px;
        background: white;
        border-radius: 6px;
    }
    
    .info-item strong {
        color: #1e3c72;
        display: block;
        margin-bottom: 8px;
    }
    
    .info-item code {
        background: #f8f9fa;
        padding: 4px 8px;
        border-radius: 4px;
        font-family: 'Courier New', monospace;
        color: #dc3545;
    }
    
    .vuln-type-badge {
        display: inline-block;
        background: #667eea;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.9em;
    }
    
    /* Evidence Styles */
    .evidence-container {
        background: #f8f9fa;
        padding: 20px;
        border-radius: 8px;
    }
    
    .evidence-item {
        margin: 15px 0;
    }
    
    .evidence-item strong {
        color: #1e3c72;
        display: block;
        margin-bottom: 8px;
    }
    
    .http-evidence {
        margin: 20px 0;
    }
    
    .http-block {
        margin: 15px 0;
    }
    
    .http-label {
        background: #667eea;
        color: white;
        padding: 8px 15px;
        border-radius: 6px 6px 0 0;
        font-weight: bold;
        font-size: 0.9em;
    }
    
    .code-block {
        background: #2d2d2d;
        color: #f8f8f2;
        padding: 20px;
        border-radius: 0 0 8px 8px;
        overflow-x: auto;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
        line-height: 1.6;
        white-space: pre-wrap;
    }
    
    .reproduction-steps {
        margin: 20px 0;
    }
    
    .steps-list {
        margin-left: 25px;
        margin-top: 10px;
    }
    
    .steps-list li {
        margin: 10px 0;
        padding: 12px;
        background: white;
        border-radius: 6px;
        line-height: 1.6;
    }
    
    /* Impact Section */
    .impact-section {
        background: linear-gradient(135deg, #fff8f0 0%, #ffe5cc 100%);
        border-left: 4px solid #fd7e14;
    }
    
    .impact-details {
        margin-top: 15px;
    }
    
    .impact-score {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding: 15px;
        background: white;
        border-radius: 8px;
    }
    
    .impact-cvss {
        font-size: 1.1em;
    }
    
    .impact-priority {
        padding: 10px 25px;
        border-radius: 20px;
        color: white;
        font-weight: bold;
    }
    
    .impact-categories {
        margin: 15px 0;
        padding: 15px;
        background: white;
        border-radius: 8px;
    }
    
    .impact-categories ul {
        margin-left: 25px;
        margin-top: 10px;
    }
    
    .impact-categories li {
        margin: 8px 0;
        line-height: 1.5;
    }
    
    .impact-timeline {
        padding: 12px;
        background: white;
        border-radius: 8px;
        text-align: center;
        font-size: 1.05em;
    }
    
    /* Remediation Styles */
    .remediation-container {
        background: #d4edda;
        padding: 25px;
        border-radius: 8px;
        border-left: 4px solid #28a745;
    }
    
    .remediation-priority {
        background: white;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 20px;
        border-left: 4px solid;
    }
    
    .remediation-sla {
        color: #666;
        font-weight: normal;
    }
    
    .remediation-steps {
        margin: 15px 0;
    }
    
    .remediation-steps ol {
        margin-left: 25px;
        margin-top: 10px;
    }
    
    .remediation-steps li {
        margin: 10px 0;
        line-height: 1.6;
    }
    
    .remediation-specific {
        margin: 15px 0;
        padding: 15px;
        background: white;
        border-radius: 8px;
    }
    
    .remediation-specific ul {
        margin-left: 25px;
        margin-top: 10px;
    }
    
    .remediation-specific li {
        margin: 8px 0;
        line-height: 1.5;
    }
    
    .remediation-validation {
        margin-top: 15px;
        padding: 15px;
        background: white;
        border-radius: 8px;
    }
    
    .remediation-validation ol {
        margin-left: 25px;
        margin-top: 10px;
    }
    
    .remediation-validation li {
        margin: 8px 0;
        line-height: 1.5;
    }
    
    /* Metadata */
    .vuln-metadata {
        display: flex;
        gap: 30px;
        margin-top: 25px;
        padding-top: 20px;
        border-top: 2px solid #f0f0f0;
        font-size: 0.9em;
        color: #666;
        flex-wrap: wrap;
    }
    
    .vuln-metadata strong {
        color: #1e3c72;
    }
    
    /* Subdomain List */
    .subdomain-list {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 15px;
    }
    
    .subdomain-item {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        border-left: 3px solid #667eea;
        transition: transform 0.2s;
    }
    
    .subdomain-item:hover {
        transform: translateX(5px);
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .subdomain-item .domain {
        font-weight: bold;
        color: #1e3c72;
        margin-bottom: 8px;
    }
    
    .subdomain-item .tech {
        font-size: 0.85em;
        color: #666;
    }
    
    .tech-badge {
        display: inline-block;
        background: #e9ecef;
        padding: 4px 12px;
        border-radius: 12px;
        margin: 3px;
        font-size: 0.85em;
    }
    
    /* Remediation Roadmap */
    .remediation-roadmap {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
    }
    
    .roadmap-timeline {
        margin-top: 30px;
    }
    
    .roadmap-phase {
        margin: 20px 0;
        padding: 25px;
        background: white;
        border-radius: 12px;
        border-left: 5px solid;
    }
    
    .roadmap-phase.critical { border-left-color: #dc3545; }
    .roadmap-phase.high { border-left-color: #fd7e14; }
    .roadmap-phase.medium { border-left-color: #ffc107; }
    .roadmap-phase.low { border-left-color: #28a745; }
    
    .phase-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
        padding-bottom: 15px;
        border-bottom: 2px solid #f0f0f0;
    }
    
    .phase-header h3 {
        color: #1e3c72;
        font-size: 1.3em;
    }
    
    .phase-count {
        background: #667eea;
        color: white;
        padding: 6px 15px;
        border-radius: 15px;
        font-weight: bold;
    }
    
    .phase-empty {
        color: #28a745;
        text-align: center;
        padding: 20px;
        font-size: 1.1em;
    }
    
    .phase-items {
        margin-left: 25px;
    }
    
    .phase-items li {
        margin: 10px 0;
        line-height: 1.6;
    }
    
    .roadmap-summary {
        margin-top: 30px;
        padding: 25px;
        background: white;
        border-radius: 12px;
        border-left: 5px solid #667eea;
    }
    
    .roadmap-summary h3 {
        color: #1e3c72;
        margin-bottom: 15px;
    }
    
    .roadmap-summary ul {
        margin-left: 25px;
    }
    
    .roadmap-summary li {
        margin: 10px 0;
        line-height: 1.6;
    }
    
    /* Footer */
    .footer {
        background: #1e3c72;
        color: white;
        padding: 40px;
        text-align: center;
    }
    
    .footer p {
        margin: 10px 0;
    }
    
    .footer a {
        color: #667eea;
        text-decoration: none;
    }
    
    .footer a:hover {
        text-decoration: underline;
    }
    
    /* Print Styles */
    @media print {
        body {
            background: white;
        }
        .container {
            box-shadow: none;
        }
        .vulnerability-card {
            page-break-inside: avoid;
        }
    }
    
    /* Responsive Design */
    @media (max-width: 768px) {
        .header h1 {
            font-size: 2em;
        }
        
        .summary {
            grid-template-columns: 1fr;
        }
        
        .severity-details {
            grid-template-columns: 1fr;
        }
        
        .finding-grid {
            grid-template-columns: 1fr;
        }
        
        .subdomain-list {
            grid-template-columns: 1fr;
        }
    }
    """
```