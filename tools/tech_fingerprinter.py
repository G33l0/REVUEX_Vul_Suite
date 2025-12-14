#!/usr/bin/env python3
"""
REVUEX - TechStack Fingerprinter
Advanced Technology Stack Detection & CVE Matching

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
"""

import requests
import re
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse
import hashlib

class TechFingerprinter:
    """Advanced technology stack fingerprinting"""
    
    def __init__(self, target, workspace, delay=2):
        """
        Initialize TechStack Fingerprinter
        
        Args:
            target: Target URL/domain
            workspace: Workspace directory
            delay: Delay between requests
        """
        self.target = target if target.startswith('http') else f"https://{target}"
        self.workspace = Path(workspace)
        self.delay = delay
        
        self.headers = {
            'User-Agent': 'REVUEX-TechFingerprinter/1.0 (Security Research; +https://github.com/G33L0)'
        }
        
        # Technology signatures database
        self.tech_signatures = {
            'frameworks': {
                'React': {
                    'headers': ['x-react-version'],
                    'html': ['react', '_react', 'reactDOM'],
                    'scripts': ['react.js', 'react.min.js', 'react-dom']
                },
                'Vue.js': {
                    'headers': [],
                    'html': ['vue', 'v-if', 'v-for', 'v-model'],
                    'scripts': ['vue.js', 'vue.min.js']
                },
                'Angular': {
                    'headers': [],
                    'html': ['ng-app', 'ng-controller', 'angular'],
                    'scripts': ['angular.js', 'angular.min.js']
                },
                'jQuery': {
                    'headers': [],
                    'html': ['jquery'],
                    'scripts': ['jquery.js', 'jquery.min.js']
                },
                'Next.js': {
                    'headers': ['x-nextjs-cache'],
                    'html': ['__NEXT_DATA__', '_next/static'],
                    'scripts': ['_next/']
                },
                'Django': {
                    'headers': [],
                    'html': ['csrfmiddlewaretoken', 'django'],
                    'cookies': ['csrftoken', 'sessionid']
                },
                'Laravel': {
                    'headers': [],
                    'html': ['laravel', 'csrf-token'],
                    'cookies': ['laravel_session', 'XSRF-TOKEN']
                },
                'Express': {
                    'headers': ['x-powered-by: express'],
                    'html': [],
                    'cookies': ['connect.sid']
                },
                'Flask': {
                    'headers': [],
                    'html': [],
                    'cookies': ['session']
                },
                'Ruby on Rails': {
                    'headers': [],
                    'html': ['csrf-param', 'csrf-token'],
                    'cookies': ['_session_id']
                }
            },
            'servers': {
                'Nginx': {
                    'headers': ['server: nginx'],
                    'patterns': ['nginx']
                },
                'Apache': {
                    'headers': ['server: apache'],
                    'patterns': ['apache']
                },
                'IIS': {
                    'headers': ['server: microsoft-iis'],
                    'patterns': ['iis']
                },
                'Cloudflare': {
                    'headers': ['server: cloudflare', 'cf-ray'],
                    'patterns': ['cloudflare']
                },
                'Varnish': {
                    'headers': ['x-varnish', 'via: varnish'],
                    'patterns': ['varnish']
                }
            },
            'cms': {
                'WordPress': {
                    'paths': ['/wp-content/', '/wp-includes/', '/wp-admin/'],
                    'html': ['wp-content', 'wordpress'],
                    'meta': ['generator: wordpress']
                },
                'Joomla': {
                    'paths': ['/administrator/', '/components/'],
                    'html': ['joomla'],
                    'meta': ['generator: joomla']
                },
                'Drupal': {
                    'paths': ['/sites/default/', '/core/'],
                    'html': ['drupal'],
                    'meta': ['generator: drupal']
                },
                'Shopify': {
                    'paths': ['/cdn.shopify.com/'],
                    'html': ['shopify', 'myshopify.com'],
                    'headers': ['x-shopid']
                },
                'Magento': {
                    'paths': ['/skin/frontend/', '/media/'],
                    'html': ['magento'],
                    'cookies': ['frontend']
                }
            },
            'languages': {
                'PHP': {
                    'headers': ['x-powered-by: php'],
                    'cookies': ['PHPSESSID'],
                    'extensions': ['.php']
                },
                'ASP.NET': {
                    'headers': ['x-aspnet-version', 'x-powered-by: asp.net'],
                    'cookies': ['ASP.NET_SessionId'],
                    'extensions': ['.aspx', '.asp']
                },
                'Python': {
                    'headers': [],
                    'frameworks': ['Django', 'Flask']
                },
                'Node.js': {
                    'headers': [],
                    'frameworks': ['Express']
                },
                'Java': {
                    'headers': [],
                    'cookies': ['JSESSIONID'],
                    'extensions': ['.jsp', '.do']
                },
                'Ruby': {
                    'headers': [],
                    'frameworks': ['Ruby on Rails']
                }
            },
            'databases': {
                'MongoDB': {
                    'errors': ['mongodb', 'mongoose'],
                    'ports': [27017]
                },
                'MySQL': {
                    'errors': ['mysql', 'sql syntax'],
                    'ports': [3306]
                },
                'PostgreSQL': {
                    'errors': ['postgresql', 'psql'],
                    'ports': [5432]
                },
                'Redis': {
                    'errors': ['redis'],
                    'ports': [6379]
                }
            },
            'special': {
                'GraphQL': {
                    'paths': ['/graphql', '/graphiql', '/api/graphql'],
                    'html': ['graphql', '__schema']
                },
                'REST API': {
                    'paths': ['/api/', '/v1/', '/v2/'],
                    'headers': ['content-type: application/json']
                },
                'WebSocket': {
                    'headers': ['upgrade: websocket'],
                    'html': ['websocket', 'ws://']
                },
                'Android': {
                    'paths': ['/app-release.apk', '/mobile/android/'],
                    'html': ['android-app://', 'play.google.com']
                },
                'iOS': {
                    'paths': ['/mobile/ios/'],
                    'html': ['ios-app://', 'apps.apple.com']
                },
                'JWT': {
                    'html': ['eyJ'],  # JWT token pattern
                    'cookies': ['jwt', 'token', 'auth-token']
                }
            }
        }
    
    def identify(self):
        """Identify technology stack"""
        tech_stack = {
            'url': self.target,
            'technologies': [],
            'versions': {},
            'headers': {},
            'cookies': {},
            'cves': []
        }
        
        try:
            # Make initial request
            response = requests.get(
                self.target,
                headers=self.headers,
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            
            html = response.text
            headers = dict(response.headers)
            cookies = dict(response.cookies)
            
            # Store headers and cookies
            tech_stack['headers'] = headers
            tech_stack['cookies'] = list(cookies.keys())
            
            # Identify frameworks
            frameworks = self._identify_frameworks(html, headers, cookies)
            tech_stack['technologies'].extend(frameworks)
            
            # Identify servers
            servers = self._identify_servers(headers)
            tech_stack['technologies'].extend(servers)
            
            # Identify CMS
            cms = self._identify_cms(html, headers, cookies)
            tech_stack['technologies'].extend(cms)
            
            # Identify languages
            languages = self._identify_languages(headers, cookies, tech_stack['technologies'])
            tech_stack['technologies'].extend(languages)
            
            # Identify special technologies
            special = self._identify_special(html, headers)
            tech_stack['technologies'].extend(special)
            
            # Extract versions
            tech_stack['versions'] = self._extract_versions(html, headers)
            
            # Match CVEs (simplified - in real implementation, query CVE database)
            tech_stack['cves'] = self._match_cves(tech_stack['technologies'], tech_stack['versions'])
            
            # Remove duplicates
            tech_stack['technologies'] = list(set(tech_stack['technologies']))
            
        except Exception as e:
            tech_stack['error'] = str(e)
        
        # Save results
        self._save_results(tech_stack)
        
        return tech_stack
    
    def _identify_frameworks(self, html, headers, cookies):
        """Identify JavaScript/Web frameworks"""
        found = []
        
        for framework, signatures in self.tech_signatures['frameworks'].items():
            # Check headers
            for header_sig in signatures.get('headers', []):
                for header, value in headers.items():
                    if header_sig.lower() in f"{header}: {value}".lower():
                        found.append(framework)
                        break
            
            # Check HTML content
            for html_sig in signatures.get('html', []):
                if html_sig.lower() in html.lower():
                    found.append(framework)
                    break
            
            # Check scripts
            for script_sig in signatures.get('scripts', []):
                if script_sig.lower() in html.lower():
                    found.append(framework)
                    break
            
            # Check cookies
            for cookie_sig in signatures.get('cookies', []):
                if cookie_sig in cookies:
                    found.append(framework)
                    break
        
        return found
    
    def _identify_servers(self, headers):
        """Identify web servers and proxies"""
        found = []
        
        for server, signatures in self.tech_signatures['servers'].items():
            for header_sig in signatures.get('headers', []):
                for header, value in headers.items():
                    if header_sig.lower() in f"{header}: {value}".lower():
                        found.append(server)
                        break
        
        return found
    
    def _identify_cms(self, html, headers, cookies):
        """Identify Content Management Systems"""
        found = []
        
        for cms, signatures in self.tech_signatures['cms'].items():
            # Check common paths
            for path in signatures.get('paths', []):
                if path in html:
                    found.append(cms)
                    break
            
            # Check HTML patterns
            for pattern in signatures.get('html', []):
                if pattern.lower() in html.lower():
                    found.append(cms)
                    break
            
            # Check meta tags
            for meta in signatures.get('meta', []):
                if meta.lower() in html.lower():
                    found.append(cms)
                    break
            
            # Check headers
            for header_sig in signatures.get('headers', []):
                for header, value in headers.items():
                    if header_sig.lower() in f"{header}: {value}".lower():
                        found.append(cms)
                        break
        
        return found
    
    def _identify_languages(self, headers, cookies, existing_tech):
        """Identify programming languages"""
        found = []
        
        for language, signatures in self.tech_signatures['languages'].items():
            # Check headers
            for header_sig in signatures.get('headers', []):
                for header, value in headers.items():
                    if header_sig.lower() in f"{header}: {value}".lower():
                        found.append(language)
                        break
            
            # Check cookies
            for cookie_sig in signatures.get('cookies', []):
                if cookie_sig in cookies:
                    found.append(language)
                    break
            
            # Infer from frameworks
            for framework in signatures.get('frameworks', []):
                if framework in existing_tech:
                    found.append(language)
                    break
        
        return found
    
    def _identify_special(self, html, headers):
        """Identify special technologies (GraphQL, APIs, Mobile, etc.)"""
        found = []
        
        for tech, signatures in self.tech_signatures['special'].items():
            # Check paths
            for path in signatures.get('paths', []):
                if path in html:
                    found.append(tech)
                    break
            
            # Check HTML
            for pattern in signatures.get('html', []):
                if pattern in html:
                    found.append(tech)
                    break
            
            # Check headers
            for header_sig in signatures.get('headers', []):
                for header, value in headers.items():
                    if header_sig.lower() in f"{header}: {value}".lower():
                        found.append(tech)
                        break
        
        return found
    
    def _extract_versions(self, html, headers):
        """Extract technology versions"""
        versions = {}
        
        # Common version patterns
        version_patterns = {
            'WordPress': r'wp-(?:content|includes)/.*?/(\d+\.\d+\.?\d*)',
            'jQuery': r'jquery[.-](\d+\.\d+\.?\d*)',
            'React': r'react[.-](\d+\.\d+\.?\d*)',
            'Vue': r'vue[.-](\d+\.\d+\.?\d*)',
            'Angular': r'angular[.-](\d+\.\d+\.?\d*)',
            'Bootstrap': r'bootstrap[.-](\d+\.\d+\.?\d*)',
        }
        
        for tech, pattern in version_patterns.items():
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                versions[tech] = match.group(1)
        
        # Check headers for versions
        for header, value in headers.items():
            # X-Powered-By: PHP/7.4.3
            if 'php' in value.lower():
                match = re.search(r'php/(\d+\.\d+\.?\d*)', value, re.IGNORECASE)
                if match:
                    versions['PHP'] = match.group(1)
            
            # X-AspNet-Version
            if 'aspnet' in header.lower():
                versions['ASP.NET'] = value
            
            # Server: nginx/1.18.0
            if header.lower() == 'server':
                match = re.search(r'(\w+)/(\d+\.\d+\.?\d*)', value)
                if match:
                    versions[match.group(1).capitalize()] = match.group(2)
        
        return versions
    
    def _match_cves(self, technologies, versions):
        """Match technologies with known CVEs (simplified)"""
        # In a real implementation, this would query CVE databases
        # For now, return placeholder data
        cves = []
        
        # Example CVE data (simplified)
        known_vulns = {
            'WordPress': {
                '5.0': ['CVE-2019-8942', 'CVE-2019-8943'],
                '5.1': ['CVE-2019-9787'],
            },
            'jQuery': {
                '1.12.0': ['CVE-2020-11022', 'CVE-2020-11023'],
                '2.2.0': ['CVE-2020-11022'],
            },
            'Nginx': {
                '1.16.0': ['CVE-2019-9511', 'CVE-2019-9513'],
            }
        }
        
        for tech, version in versions.items():
            if tech in known_vulns:
                version_vulns = known_vulns[tech].get(version, [])
                for cve in version_vulns:
                    cves.append({
                        'technology': tech,
                        'version': version,
                        'cve_id': cve,
                        'severity': 'High'  # Simplified
                    })
        
        return cves
    
    def _save_results(self, tech_stack):
        """Save fingerprinting results"""
        # Create tech directory
        tech_dir = self.workspace / "tech_fingerprints"
        tech_dir.mkdir(exist_ok=True)
        
        # Safe filename from URL
        safe_name = re.sub(r'[^\w\-]', '_', urlparse(self.target).netloc)
        output_file = tech_dir / f"{safe_name}_tech.json"
        
        with open(output_file, 'w') as f:
            json.dump(tech_stack, f, indent=2)
