#!/usr/bin/env python3
"""
REVUEX Intelligence Hub - Central Intelligence Database v2.0
Author: G33L0
Telegram: @x0x0h33l0
GitHub: github.com/G33L0/revuex-vul-suite

Enhanced Features:

- Support for 19 security scanners
- Advanced vulnerability tracking
- Scanner statistics and metrics
- Payload tracking
- CVSS score calculation
- Risk assessment
- Compliance mapping
- Attack path analysis
  “””

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any, Optional

class IntelligenceHub:
“”“Central intelligence database for REVUEX Suite v2.0”””

```
def __init__(self, workspace):
    """
    Initialize intelligence hub
    
    Args:
        workspace: Workspace directory path
    """
    self.workspace = Path(workspace)
    self.db = {
        'metadata': {
            'version': '2.0',
            'created_at': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
            'target': None,
            'scan_mode': 'sequential',
            'total_scanners': 19,
            'scanners_used': []
        },
        
        # Reconnaissance data
        'subdomains': [],
        'technologies': {},
        'endpoints': {},
        'secrets': {},
        
        # Vulnerability data
        'vulnerabilities': [],
        'confirmed_bugs': [],
        
        # Scanner-specific data
        'scanner_results': {
            'ssrf': [],
            'sqli': [],
            'idor': [],
            'xss': [],
            'business_logic': [],
            'file_upload': [],
            'xxe': [],
            'session': [],
            'cors': [],
            'csrf': [],
            'dependencies': [],
            'graphql': [],
            'jwt': [],
            'apk': [],
            'race_condition': [],
            'price_manipulation': []
        },
        
        # Statistics and metrics
        'statistics': {
            'scan_duration': None,
            'requests_made': 0,
            'vulnerabilities_by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'vulnerabilities_by_scanner': {},
            'scanner_timings': {},
            'top_vulnerable_targets': [],
            'owasp_coverage': {}
        },
        
        # Risk assessment
        'risk_assessment': {
            'overall_risk_score': 0,
            'risk_level': 'unknown',
            'critical_issues': [],
            'high_priority_targets': [],
            'attack_paths': []
        },
        
        # Compliance tracking
        'compliance': {
            'pci_dss': {'compliant': True, 'issues': []},
            'gdpr': {'compliant': True, 'issues': []},
            'hipaa': {'compliant': True, 'issues': []},
            'soc2': {'compliant': True, 'issues': []}
        },
        
        # Payload tracking
        'payloads_used': {
            'sqli': [],
            'xss': [],
            'xxe': [],
            'ssrf': [],
            'file_upload': []
        }
    }
    
    # Load existing data if available
    self._load_existing_data()

def _load_existing_data(self):
    """Load existing intelligence data"""
    recon_file = self.workspace / "recon_database.json"
    if recon_file.exists():
        try:
            with open(recon_file, 'r') as f:
                data = json.load(f)
                # Merge with existing structure, preserving new fields
                if 'subdomains' in data:
                    self.db['subdomains'] = data['subdomains']
                if 'technologies' in data:
                    self.db['technologies'] = data['technologies']
                if 'endpoints' in data:
                    self.db['endpoints'] = data['endpoints']
                if 'secrets' in data:
                    self.db['secrets'] = data['secrets']
        except Exception as e:
            print(f"Warning: Could not load existing data: {e}")

def _update_timestamp(self):
    """Update last modified timestamp"""
    self.db['metadata']['last_updated'] = datetime.now().isoformat()

# ========================================
# METADATA MANAGEMENT
# ========================================

def set_target(self, target):
    """Set scan target"""
    self.db['metadata']['target'] = target
    self._update_timestamp()

def set_scan_mode(self, mode):
    """Set scan execution mode"""
    self.db['metadata']['scan_mode'] = mode
    self._update_timestamp()

def add_scanner_used(self, scanner_name):
    """Track which scanners were used"""
    if scanner_name not in self.db['metadata']['scanners_used']:
        self.db['metadata']['scanners_used'].append(scanner_name)
    self._update_timestamp()

# ========================================
# RECONNAISSANCE DATA
# ========================================

def add_subdomains(self, subdomains: List[str]):
    """Add discovered subdomains"""
    for subdomain in subdomains:
        if subdomain not in self.db['subdomains']:
            self.db['subdomains'].append(subdomain)
    self._update_timestamp()

def add_technology(self, subdomain: str, tech_stack: Dict):
    """Add technology stack for subdomain"""
    self.db['technologies'][subdomain] = tech_stack
    self._update_timestamp()

def add_endpoints(self, subdomain: str, endpoints: List[str]):
    """Add discovered endpoints"""
    if subdomain not in self.db['endpoints']:
        self.db['endpoints'][subdomain] = []
    
    for endpoint in endpoints:
        if endpoint not in self.db['endpoints'][subdomain]:
            self.db['endpoints'][subdomain].append(endpoint)
    self._update_timestamp()

def add_secrets(self, subdomain: str, secrets: Dict):
    """Add discovered secrets"""
    self.db['secrets'][subdomain] = secrets
    self._update_timestamp()

# ========================================
# VULNERABILITY MANAGEMENT
# ========================================

def add_vulnerabilities(self, vulnerabilities: List[Dict]):
    """
    Add discovered vulnerabilities
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
    """
    for vuln in vulnerabilities:
        # Add metadata
        vuln['discovered_at'] = datetime.now().isoformat()
        vuln['id'] = f"REVUEX-{len(self.db['vulnerabilities']) + 1:04d}"
        
        # Add to main list
        self.db['vulnerabilities'].append(vuln)
        
        # Update severity statistics
        severity = vuln.get('severity', 'low').lower()
        if severity in self.db['statistics']['vulnerabilities_by_severity']:
            self.db['statistics']['vulnerabilities_by_severity'][severity] += 1
        
        # Update scanner statistics
        scanner = vuln.get('scanner', 'unknown')
        if scanner not in self.db['statistics']['vulnerabilities_by_scanner']:
            self.db['statistics']['vulnerabilities_by_scanner'][scanner] = 0
        self.db['statistics']['vulnerabilities_by_scanner'][scanner] += 1
        
        # Add to scanner-specific results
        vuln_type = vuln.get('type', '').lower()
        if 'ssrf' in vuln_type and 'ssrf' in self.db['scanner_results']:
            self.db['scanner_results']['ssrf'].append(vuln)
        elif 'sql' in vuln_type and 'sqli' in self.db['scanner_results']:
            self.db['scanner_results']['sqli'].append(vuln)
        elif 'idor' in vuln_type and 'idor' in self.db['scanner_results']:
            self.db['scanner_results']['idor'].append(vuln)
        elif 'xss' in vuln_type and 'xss' in self.db['scanner_results']:
            self.db['scanner_results']['xss'].append(vuln)
        elif 'business' in vuln_type and 'business_logic' in self.db['scanner_results']:
            self.db['scanner_results']['business_logic'].append(vuln)
        elif 'upload' in vuln_type and 'file_upload' in self.db['scanner_results']:
            self.db['scanner_results']['file_upload'].append(vuln)
        elif 'xxe' in vuln_type and 'xxe' in self.db['scanner_results']:
            self.db['scanner_results']['xxe'].append(vuln)
        elif 'session' in vuln_type and 'session' in self.db['scanner_results']:
            self.db['scanner_results']['session'].append(vuln)
        elif 'cors' in vuln_type and 'cors' in self.db['scanner_results']:
            self.db['scanner_results']['cors'].append(vuln)
        elif 'csrf' in vuln_type and 'csrf' in self.db['scanner_results']:
            self.db['scanner_results']['csrf'].append(vuln)
        elif 'graphql' in vuln_type and 'graphql' in self.db['scanner_results']:
            self.db['scanner_results']['graphql'].append(vuln)
        elif 'jwt' in vuln_type and 'jwt' in self.db['scanner_results']:
            self.db['scanner_results']['jwt'].append(vuln)
        
        # Update compliance tracking
        self._update_compliance(vuln)
        
    self._update_timestamp()
    self._calculate_risk_assessment()

def add_confirmed_bug(self, bug: Dict):
    """Add confirmed exploitable bug"""
    bug['confirmed_at'] = datetime.now().isoformat()
    bug['id'] = f"EXPLOIT-{len(self.db['confirmed_bugs']) + 1:04d}"
    self.db['confirmed_bugs'].append(bug)
    self._update_timestamp()

# ========================================
# SCANNER RESULTS
# ========================================

def add_scanner_result(self, scanner_type: str, result: Dict):
    """
    Add scanner-specific result
    
    Args:
        scanner_type: Type of scanner (e.g., 'ssrf', 'sqli')
        result: Scanner result dictionary
    """
    if scanner_type in self.db['scanner_results']:
        self.db['scanner_results'][scanner_type].append(result)
    self._update_timestamp()

def get_scanner_results(self, scanner_type: str) -> List[Dict]:
    """Get results from specific scanner"""
    return self.db['scanner_results'].get(scanner_type, [])

# ========================================
# PAYLOAD TRACKING
# ========================================

def add_payload_used(self, payload_type: str, payload: str, successful: bool = False):
    """
    Track payload usage
    
    Args:
        payload_type: Type of payload (sqli, xss, etc.)
        payload: The actual payload string
        successful: Whether payload was successful
    """
    if payload_type in self.db['payloads_used']:
        self.db['payloads_used'][payload_type].append({
            'payload': payload,
            'successful': successful,
            'used_at': datetime.now().isoformat()
        })
    self._update_timestamp()

# ========================================
# STATISTICS & METRICS
# ========================================

def set_scanner_timing(self, scanner_name: str, duration: float):
    """Set scanner execution time"""
    self.db['statistics']['scanner_timings'][scanner_name] = duration
    self._update_timestamp()

def increment_requests(self, count: int = 1):
    """Increment request counter"""
    self.db['statistics']['requests_made'] += count
    self._update_timestamp()

def set_scan_duration(self, duration: str):
    """Set total scan duration"""
    self.db['statistics']['scan_duration'] = duration
    self._update_timestamp()

def get_statistics(self) -> Dict:
    """Get comprehensive intelligence statistics"""
    stats = {
        'total_subdomains': len(self.db['subdomains']),
        'total_endpoints': sum(len(eps) for eps in self.db['endpoints'].values()),
        'total_technologies': len(self.db['technologies']),
        'total_secrets': sum(
            len(s.get('api_keys', [])) + len(s.get('tokens', [])) 
            for s in self.db['secrets'].values()
        ),
        'total_vulnerabilities': len(self.db['vulnerabilities']),
        'confirmed_bugs': len(self.db['confirmed_bugs']),
        'severity_breakdown': self.db['statistics']['vulnerabilities_by_severity'].copy(),
        'scanners_used': len(self.db['metadata']['scanners_used']),
        'scanner_breakdown': self.db['statistics']['vulnerabilities_by_scanner'].copy(),
        'requests_made': self.db['statistics']['requests_made'],
        'scan_duration': self.db['statistics']['scan_duration'],
        'overall_risk_score': self.db['risk_assessment']['overall_risk_score'],
        'risk_level': self.db['risk_assessment']['risk_level']
    }
    return stats

# ========================================
# RISK ASSESSMENT
# ========================================

def _calculate_risk_assessment(self):
    """Calculate overall risk assessment"""
    # Calculate risk score (0-100)
    severity_weights = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 1,
        'info': 0
    }
    
    total_score = 0
    for severity, count in self.db['statistics']['vulnerabilities_by_severity'].items():
        total_score += count * severity_weights.get(severity, 0)
    
    # Normalize to 0-100
    max_score = 100
    risk_score = min(total_score, max_score)
    
    # Determine risk level
    if risk_score >= 75:
        risk_level = 'critical'
    elif risk_score >= 50:
        risk_level = 'high'
    elif risk_score >= 25:
        risk_level = 'medium'
    elif risk_score > 0:
        risk_level = 'low'
    else:
        risk_level = 'none'
    
    self.db['risk_assessment']['overall_risk_score'] = risk_score
    self.db['risk_assessment']['risk_level'] = risk_level
    
    # Identify critical issues
    self.db['risk_assessment']['critical_issues'] = [
        vuln for vuln in self.db['vulnerabilities']
        if vuln.get('severity', '').lower() == 'critical'
    ]
    
    self._update_timestamp()

def get_risk_assessment(self) -> Dict:
    """Get risk assessment data"""
    return self.db['risk_assessment'].copy()

# ========================================
# COMPLIANCE TRACKING
# ========================================

def _update_compliance(self, vuln: Dict):
    """Update compliance status based on vulnerability"""
    vuln_type = vuln.get('type', '').lower()
    severity = vuln.get('severity', '').lower()
    
    # PCI-DSS: Payment vulnerabilities
    if any(keyword in vuln_type for keyword in ['payment', 'credit', 'sqli', 'xss']):
        if severity in ['critical', 'high']:
            self.db['compliance']['pci_dss']['compliant'] = False
            self.db['compliance']['pci_dss']['issues'].append(vuln['id'])
    
    # GDPR: Data protection vulnerabilities
    if any(keyword in vuln_type for keyword in ['idor', 'sqli', 'ssrf', 'xxe']):
        if severity in ['critical', 'high']:
            self.db['compliance']['gdpr']['compliant'] = False
            self.db['compliance']['gdpr']['issues'].append(vuln['id'])
    
    # HIPAA: Healthcare data vulnerabilities
    if any(keyword in vuln_type for keyword in ['sqli', 'idor', 'session']):
        if severity in ['critical', 'high']:
            self.db['compliance']['hipaa']['compliant'] = False
            self.db['compliance']['hipaa']['issues'].append(vuln['id'])
    
    # SOC2: Security vulnerabilities
    if severity == 'critical':
        self.db['compliance']['soc2']['compliant'] = False
        self.db['compliance']['soc2']['issues'].append(vuln['id'])

def get_compliance_status(self) -> Dict:
    """Get compliance status"""
    return self.db['compliance'].copy()

# ========================================
# TARGET PRIORITIZATION
# ========================================

def get_high_priority_targets(self) -> List[str]:
    """
    Get high-priority targets for deep scanning
    
    Returns:
        List of high-priority subdomain targets
    """
    priority_targets = []
    
    for subdomain in self.db['subdomains']:
        tech = self.db['technologies'].get(subdomain, {})
        secrets = self.db['secrets'].get(subdomain, {})
        
        # High priority if has interesting tech
        interesting_tech = ['GraphQL', 'Android', 'JWT', 'API', 'Admin', 'Payment']
        if any(t in tech.get('technologies', []) for t in interesting_tech):
            priority_targets.append(subdomain)
        
        # High priority if has secrets
        elif secrets.get('api_keys') or secrets.get('jwt_tokens') or secrets.get('passwords'):
            priority_targets.append(subdomain)
        
        # High priority if has many endpoints
        elif subdomain in self.db['endpoints'] and len(self.db['endpoints'][subdomain]) > 20:
            priority_targets.append(subdomain)
    
    return list(set(priority_targets))  # Remove duplicates

def get_top_vulnerable_targets(self, limit: int = 10) -> List[Dict]:
    """
    Get most vulnerable targets
    
    Args:
        limit: Maximum number of targets to return
        
    Returns:
        List of targets with vulnerability counts
    """
    target_vulns = defaultdict(lambda: {'count': 0, 'critical': 0, 'high': 0})
    
    for vuln in self.db['vulnerabilities']:
        target = vuln.get('target', vuln.get('url', 'unknown'))
        target_vulns[target]['count'] += 1
        
        severity = vuln.get('severity', '').lower()
        if severity == 'critical':
            target_vulns[target]['critical'] += 1
        elif severity == 'high':
            target_vulns[target]['high'] += 1
    
    # Sort by critical, then high, then total
    sorted_targets = sorted(
        target_vulns.items(),
        key=lambda x: (x[1]['critical'], x[1]['high'], x[1]['count']),
        reverse=True
    )
    
    return [
        {'target': target, **data}
        for target, data in sorted_targets[:limit]
    ]

# ========================================
# DATA RETRIEVAL
# ========================================

def get_recon_database(self) -> Dict:
    """Get reconnaissance data"""
    return {
        'subdomains': self.db['subdomains'],
        'technologies': self.db['technologies'],
        'endpoints': self.db['endpoints'],
        'secrets': self.db['secrets']
    }

def get_vulnerabilities(self) -> List[Dict]:
    """Get all vulnerabilities"""
    return self.db['vulnerabilities']

def get_confirmed_bugs(self) -> List[Dict]:
    """Get confirmed bugs"""
    return self.db['confirmed_bugs']

def get_vulnerabilities_by_severity(self, severity: str) -> List[Dict]:
    """Get vulnerabilities by severity level"""
    return [
        vuln for vuln in self.db['vulnerabilities']
        if vuln.get('severity', '').lower() == severity.lower()
    ]

def get_vulnerabilities_by_scanner(self, scanner: str) -> List[Dict]:
    """Get vulnerabilities found by specific scanner"""
    return [
        vuln for vuln in self.db['vulnerabilities']
        if vuln.get('scanner', '') == scanner
    ]

# ========================================
# FILE OPERATIONS
# ========================================

def save_recon_database(self) -> Path:
    """Save reconnaissance database"""
    output_file = self.workspace / "recon_database.json"
    with open(output_file, 'w') as f:
        json.dump(self.get_recon_database(), f, indent=2)
    return output_file

def save_vulnerabilities_database(self) -> Path:
    """Save vulnerabilities database"""
    output_file = self.workspace / "vulnerabilities.json"
    with open(output_file, 'w') as f:
        json.dump(self.db['vulnerabilities'], f, indent=2)
    return output_file

def save_confirmed_bugs(self) -> Path:
    """Save confirmed bugs"""
    output_file = self.workspace / "confirmed_bugs.json"
    with open(output_file, 'w') as f:
        json.dump(self.db['confirmed_bugs'], f, indent=2)
    return output_file

def save_full_database(self) -> Path:
    """Save complete intelligence database"""
    output_file = self.workspace / "intelligence_hub_full.json"
    with open(output_file, 'w') as f:
        json.dump(self.db, f, indent=2)
    return output_file

def save_statistics(self) -> Path:
    """Save statistics report"""
    output_file = self.workspace / "intelligence_statistics.json"
    stats = self.get_statistics()
    stats['top_vulnerable_targets'] = self.get_top_vulnerable_targets()
    stats['compliance_status'] = self.get_compliance_status()
    
    with open(output_file, 'w') as f:
        json.dump(stats, f, indent=2)
    return output_file
```