#!/usr/bin/env python3
"""
REVUEX Intelligence Hub - Central Intelligence Database
Author: G33L0
Telegram: @x0x0h33l0
"""

import json
from pathlib import Path
from datetime import datetime

class IntelligenceHub:
    """Central intelligence database for REVUEX Suite"""
    
    def __init__(self, workspace):
        """Initialize intelligence hub"""
        self.workspace = Path(workspace)
        self.db = {
            'subdomains': [],
            'technologies': {},
            'endpoints': {},
            'secrets': {},
            'vulnerabilities': [],
            'confirmed_bugs': [],
            'metadata': {
                'created_at': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
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
                    self.db.update(data)
            except:
                pass
    
    def _update_timestamp(self):
        """Update last modified timestamp"""
        self.db['metadata']['last_updated'] = datetime.now().isoformat()
    
    def add_subdomains(self, subdomains):
        """Add discovered subdomains"""
        for subdomain in subdomains:
            if subdomain not in self.db['subdomains']:
                self.db['subdomains'].append(subdomain)
        self._update_timestamp()
    
    def add_technology(self, subdomain, tech_stack):
        """Add technology stack for subdomain"""
        self.db['technologies'][subdomain] = tech_stack
        self._update_timestamp()
    
    def add_endpoints(self, subdomain, endpoints):
        """Add discovered endpoints"""
        if subdomain not in self.db['endpoints']:
            self.db['endpoints'][subdomain] = []
        
        for endpoint in endpoints:
            if endpoint not in self.db['endpoints'][subdomain]:
                self.db['endpoints'][subdomain].append(endpoint)
        self._update_timestamp()
    
    def add_secrets(self, subdomain, secrets):
        """Add discovered secrets"""
        self.db['secrets'][subdomain] = secrets
        self._update_timestamp()
    
    def add_vulnerabilities(self, vulnerabilities):
        """Add discovered vulnerabilities"""
        for vuln in vulnerabilities:
            vuln['discovered_at'] = datetime.now().isoformat()
            self.db['vulnerabilities'].append(vuln)
        self._update_timestamp()
    
    def add_confirmed_bug(self, bug):
        """Add confirmed exploitable bug"""
        bug['confirmed_at'] = datetime.now().isoformat()
        self.db['confirmed_bugs'].append(bug)
        self._update_timestamp()
    
    def get_recon_database(self):
        """Get reconnaissance data"""
        return {
            'subdomains': self.db['subdomains'],
            'technologies': self.db['technologies'],
            'endpoints': self.db['endpoints'],
            'secrets': self.db['secrets']
        }
    
    def get_vulnerabilities(self):
        """Get all vulnerabilities"""
        return self.db['vulnerabilities']
    
    def get_confirmed_bugs(self):
        """Get confirmed bugs"""
        return self.db['confirmed_bugs']
    
    def get_high_priority_targets(self):
        """Get high-priority targets for deep scanning"""
        priority_targets = []
        
        for subdomain in self.db['subdomains']:
            tech = self.db['technologies'].get(subdomain, {})
            secrets = self.db['secrets'].get(subdomain, {})
            
            # High priority if has interesting tech or secrets
            if any(t in tech.get('technologies', []) for t in ['GraphQL', 'Android', 'JWT']):
                priority_targets.append(subdomain)
            elif secrets.get('api_keys') or secrets.get('jwt_tokens'):
                priority_targets.append(subdomain)
        
        return priority_targets
    
    def save_recon_database(self):
        """Save reconnaissance database"""
        output_file = self.workspace / "recon_database.json"
        with open(output_file, 'w') as f:
            json.dump(self.get_recon_database(), f, indent=2)
        return output_file
    
    def save_vulnerabilities_database(self):
        """Save vulnerabilities database"""
        output_file = self.workspace / "vulnerabilities.json"
        with open(output_file, 'w') as f:
            json.dump(self.db['vulnerabilities'], f, indent=2)
        return output_file
    
    def save_confirmed_bugs(self):
        """Save confirmed bugs"""
        output_file = self.workspace / "confirmed_bugs.json"
        with open(output_file, 'w') as f:
            json.dump(self.db['confirmed_bugs'], f, indent=2)
        return output_file
    
    def get_statistics(self):
        """Get intelligence statistics"""
        return {
            'total_subdomains': len(self.db['subdomains']),
            'total_endpoints': sum(len(eps) for eps in self.db['endpoints'].values()),
            'total_vulnerabilities': len(self.db['vulnerabilities']),
            'confirmed_bugs': len(self.db['confirmed_bugs']),
            'severity_breakdown': self._get_severity_breakdown()
        }
    
    def _get_severity_breakdown(self):
        """Get vulnerability severity breakdown"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.db['vulnerabilities']:
            severity = vuln.get('severity', 'low').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown
