#!/usr/bin/env python3
"""
REVUEX Report Generator - World-Class HTML Reports
Author: G33L0
Telegram: @x0x0h33l0
"""

from pathlib import Path
from datetime import datetime

class ReportGenerator:
    """Generate professional HTML reports"""
    
    def __init__(self, workspace):
        """Initialize report generator"""
        self.workspace = Path(workspace)
    
    def generate_html_report(self, data):
        """Generate comprehensive HTML report"""
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REVUEX Vulnerability Report - {data['target']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            font-family: 'Courier New', monospace;
            letter-spacing: 3px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .header .author {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.3);
            font-size: 0.9em;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }}
        
        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .summary-card .label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        
        .section {{
            padding: 40px;
        }}
        
        .section-title {{
            font-size: 2em;
            margin-bottom: 25px;
            color: #1e3c72;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .vulnerability-card {{
            background: white;
            border-left: 5px solid #667eea;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }}
        
        .vulnerability-card.critical {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        
        .vulnerability-card.high {{
            border-left-color: #fd7e14;
            background: #fff8f0;
        }}
        
        .vulnerability-card.medium {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        
        .vulnerability-card.low {{
            border-left-color: #28a745;
            background: #f0fff4;
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .vuln-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #1e3c72;
        }}
        
        .severity-badge {{
            padding: 8px 20px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{ background: #dc3545; }}
        .severity-badge.high {{ background: #fd7e14; }}
        .severity-badge.medium {{ background: #ffc107; color: #333; }}
        .severity-badge.low {{ background: #28a745; }}
        
        .vuln-detail {{
            margin: 15px 0;
        }}
        
        .vuln-detail strong {{
            color: #1e3c72;
            display: inline-block;
            min-width: 120px;
        }}
        
        .code-block {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin: 15px 0;
            font-size: 0.9em;
        }}
        
        .attack-path {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }}
        
        .attack-path ol {{
            margin-left: 20px;
        }}
        
        .attack-path li {{
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 5px;
        }}
        
        .remediation {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }}
        
        .remediation h4 {{
            color: #155724;
            margin-bottom: 10px;
        }}
        
        .remediation ul {{
            margin-left: 20px;
        }}
        
        .remediation li {{
            margin: 8px 0;
            color: #155724;
        }}
        
        .target-info {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
        }}
        
        .target-info h3 {{
            margin-bottom: 15px;
            font-size: 1.5em;
        }}
        
        .target-info .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .info-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
        }}
        
        .info-item strong {{
            display: block;
            margin-bottom: 5px;
            opacity: 0.8;
        }}
        
        .subdomain-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
        }}
        
        .subdomain-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #667eea;
        }}
        
        .subdomain-item .domain {{
            font-weight: bold;
            color: #1e3c72;
            margin-bottom: 8px;
        }}
        
        .subdomain-item .tech {{
            font-size: 0.85em;
            color: #666;
        }}
        
        .tech-badge {{
            display: inline-block;
            background: #e9ecef;
            padding: 4px 12px;
            border-radius: 12px;
            margin: 3px;
            font-size: 0.8em;
        }}
        
        .footer {{
            background: #1e3c72;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}
        
        .footer a:hover {{
            text-decoration: underline;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔒 REVUEX</h1>
            <div class="subtitle">Vulnerability Assessment Report</div>
            <div class="author">
                <strong>Author:</strong> G33L0 | 
                <strong>Telegram:</strong> @x0x0h33l0 | 
                <strong>GitHub:</strong> github.com/G33L0
            </div>
        </div>
        
        <!-- Summary Dashboard -->
        <div class="summary">
            <div class="summary-card">
                <div class="number critical">{len(data['confirmed_bugs'])}</div>
                <div class="label">Confirmed Bugs</div>
            </div>
            <div class="summary-card">
                <div class="number high">{len(data['vulnerabilities'])}</div>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="summary-card">
                <div class="number info">{len(data['reconnaissance']['subdomains'])}</div>
                <div class="label">Subdomains Found</div>
            </div>
            <div class="summary-card">
                <div class="number medium">{sum(len(eps) for eps in data['reconnaissance']['endpoints'].values())}</div>
                <div class="label">Endpoints Discovered</div>
            </div>
        </div>
        
        <!-- Target Information -->
        <div class="section">
            <div class="target-info">
                <h3>🎯 Target Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <strong>Target Domain</strong>
                        {data['target']}
                    </div>
                    <div class="info-item">
                        <strong>Scan Started</strong>
                        {data['start_time']}
                    </div>
                    <div class="info-item">
                        <strong>Scan Completed</strong>
                        {data['end_time']}
                    </div>
                    <div class="info-item">
                        <strong>Total Duration</strong>
                        {data['duration']}
                    </div>
                    <div class="info-item">
                        <strong>Execution Mode</strong>
                        {data['execution_mode'].upper()}
                    </div>
                    <div class="info-item">
                        <strong>REVUEX Version</strong>
                        1.0
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Severity Breakdown -->
        <div class="section" style="background: #f8f9fa;">
            <h2 class="section-title">📊 Severity Breakdown</h2>
            <div class="summary">
                <div class="summary-card">
                    <div class="number critical">{data['statistics']['findings']['critical']}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card">
                    <div class="number high">{data['statistics']['findings']['high']}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card">
                    <div class="number medium">{data['statistics']['findings']['medium']}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card">
                    <div class="number low">{data['statistics']['findings']['low']}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>
        
        <!-- Confirmed Exploitable Bugs -->
        {self._generate_confirmed_bugs_section(data['confirmed_bugs'])}
        
        <!-- All Vulnerabilities -->
        {self._generate_vulnerabilities_section(data['vulnerabilities'])}
        
        <!-- Reconnaissance Results -->
        {self._generate_reconnaissance_section(data['reconnaissance'])}
        
        <!-- Footer -->
        <div class="footer">
            <p><strong>REVUEX Vulnerability Suite</strong> - Advanced Bug Bounty Automation</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Author: G33L0 | Telegram: <a href="https://t.me/x0x0h33l0">@x0x0h33l0</a></p>
            <p style="margin-top: 15px; font-size: 0.9em; opacity: 0.8;">
                ⚠️ This report contains sensitive security information. Handle with care.
            </p>
        </div>
    </div>
</body>
</html>"""
        
        # Save report
        output_file = self.workspace / "REVUEX_REPORT.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
    
    def _generate_confirmed_bugs_section(self, bugs):
        """Generate confirmed bugs section"""
        if not bugs:
            return """
        <div class="section">
            <h2 class="section-title">🎯 Confirmed Exploitable Bugs</h2>
            <p style="color: #28a745; font-size: 1.2em;">✓ No confirmed exploitable bugs found</p>
        </div>
            """
        
        html = """
        <div class="section">
            <h2 class="section-title">🎯 Confirmed Exploitable Bugs</h2>
        """
        
        for idx, bug in enumerate(bugs, 1):
            severity = bug.get('severity', 'high').lower()
            html += f"""
            <div class="vulnerability-card {severity}">
                <div class="vuln-header">
                    <div class="vuln-title">[{idx}] {bug.get('type', 'Unknown')}</div>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </div>
                
                <div class="vuln-detail">
                    <strong>Target:</strong> {bug.get('endpoint', bug.get('url', 'N/A'))}
                </div>
                
                <div class="vuln-detail">
                    <strong>Description:</strong> {bug.get('description', 'No description available')}
                </div>
                
                <div class="vuln-detail">
                    <strong>Evidence:</strong> {bug.get('evidence', 'No evidence available')}
                </div>
                
                {self._generate_attack_path(bug.get('attack_path', []))}
                {self._generate_remediation(bug.get('remediation', []))}
                
                <div class="vuln-detail" style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <strong>Confirmed At:</strong> {bug.get('confirmed_at', 'N/A')}
                </div>
            </div>
            """
        
        html += "</div>"
        return html
    
    def _generate_vulnerabilities_section(self, vulnerabilities):
        """Generate vulnerabilities section"""
        if not vulnerabilities:
            return """
        <div class="section" style="background: #f8f9fa;">
            <h2 class="section-title">🔍 Detected Vulnerabilities</h2>
            <p style="color: #28a745; font-size: 1.2em;">✓ No vulnerabilities detected</p>
        </div>
            """
        
        html = """
        <div class="section" style="background: #f8f9fa;">
            <h2 class="section-title">🔍 Detected Vulnerabilities</h2>
        """
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'medium').lower()
            html += f"""
            <div class="vulnerability-card {severity}">
                <div class="vuln-header">
                    <div class="vuln-title">[{idx}] {vuln.get('type', 'Unknown Vulnerability')}</div>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </div>
                
                <div class="vuln-detail">
                    <strong>Target:</strong> {vuln.get('url', vuln.get('endpoint', 'N/A'))}
                </div>
                
                <div class="vuln-detail">
                    <strong>Description:</strong> {vuln.get('description', 'No description available')}
                </div>
                
                <div class="vuln-detail">
                    <strong>Evidence:</strong> {vuln.get('evidence', 'No evidence available')}
                </div>
                
                {self._generate_attack_path(vuln.get('attack_path', []))}
                {self._generate_remediation(vuln.get('remediation', []))}
                
                <div class="vuln-detail" style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <strong>Discovered At:</strong> {vuln.get('discovered_at', 'N/A')}
                </div>
            </div>
            """
        
        html += "</div>"
        return html
    
    def _generate_attack_path(self, attack_path):
        """Generate attack path HTML"""
        if not attack_path:
            return ""
        
        html = """
        <div class="attack-path">
            <h4>🎯 Attack Path:</h4>
            <ol>
        """
        
        for step in attack_path:
            html += f"<li>{step}</li>"
        
        html += """
            </ol>
        </div>
        """
        return html
    
    def _generate_remediation(self, remediation):
        """Generate remediation HTML"""
        if not remediation:
            return ""
        
        html = """
        <div class="remediation">
            <h4>🛠️ Remediation:</h4>
            <ul>
        """
        
        for fix in remediation:
            html += f"<li>{fix}</li>"
        
        html += """
            </ul>
        </div>
        """
        return html
    
    def _generate_reconnaissance_section(self, recon_data):
        """Generate reconnaissance section"""
        html = """
        <div class="section">
            <h2 class="section-title">🔎 Reconnaissance Results</h2>
            
            <h3 style="margin: 30px 0 20px 0; color: #1e3c72;">Discovered Subdomains</h3>
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
                for t in technologies[:5]:  # Show first 5 technologies
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
