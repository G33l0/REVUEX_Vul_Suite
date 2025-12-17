#!/usr/bin/env python3
"""
REVUEX - Base Scanner
Foundation class for all security scanners

Author: G33L0
Telegram: @x0x0h33l0
"""

import time
import logging
import json
import requests
import urllib3
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# Suppress insecure request warnings for cleaner production output
# This prevents the terminal from being flooded with SSL warnings when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BaseScanner(ABC):
    """
    Base class for all REVUEX security scanners
    
    Provides:
    - Rate limiting
    - Error handling (with SSL bypass)
    - Safety checks
    - Logging
    - Standard reporting interface
    """

    def __init__(self, target: str, workspace: Path, delay: float = 2.0):
        """
        Initialize base scanner
        
        Args:
            target: Target URL or identifier
            workspace: Workspace directory for outputs
            delay: Delay between requests (seconds)
        """
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        self.vulnerabilities = []
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Safety limits
        self.max_requests = 100
        self.request_count = 0
        self.timeout = 10
        
        # Standard headers
        self.headers = {
            'User-Agent': 'REVUEX/2.0 (Security Research; +https://github.com/G33L0)',
            'Accept': '*/*'
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup scanner-specific logging"""
        logger = logging.getLogger(self.__class__.__name__)
        logger.setLevel(logging.INFO)
        
        # Create logs directory
        log_dir = self.workspace / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler
        handler = logging.FileHandler(
            log_dir / f"{self.__class__.__name__}.log"
        )
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        logger.addHandler(handler)
        
        return logger

    def safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make a rate-limited, safe HTTP request with SSL verification disabled
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            **kwargs: Additional request arguments
            
        Returns:
            Response object or None on error
        """
        # Check request limit
        if self.request_count >= self.max_requests:
            self.logger.warning(f"Request limit reached: {self.max_requests}")
            return None
        
        # Apply rate limiting
        time.sleep(self.delay)
        
        try:
            # Merge headers
            headers = self.headers.copy()
            if 'headers' in kwargs:
                headers.update(kwargs['headers'])
                kwargs['headers'] = headers
            else:
                kwargs['headers'] = headers
            
            # Set default timeout
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout
            
            # PRODUCTION FIX: Make request with verify=False 
            # This allows testing targets with self-signed or expired certificates
            response = requests.request(method, url, verify=False, **kwargs)
            self.request_count += 1
            
            self.logger.info(f"{method} {url} - Status: {response.status_code}")
            
            return response
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout requesting {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error(f"Connection error to {url}")
            return None
        except Exception as e:
            self.logger.error(f"Request error: {str(e)}")
            return None

    def extract_host(self, url: str) -> str:
        """Extract hostname from URL"""
        parsed = urlparse(url)
        return parsed.netloc or url

    def is_safe_url(self, url: str) -> bool:
        """
        Validate URL is safe to test
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ['http', 'https']:
                self.logger.warning(f"Invalid scheme: {parsed.scheme}")
                return False
            
            dangerous_hosts = [
                'localhost', '127.0.0.1', '0.0.0.0',
                '::1', '169.254.169.254'
            ]
            
            if parsed.netloc.split(':')[0].lower() in dangerous_hosts:
                self.logger.warning(f"Dangerous host detected: {parsed.netloc}")
                return False
            
            return True
        except Exception:
            return False

    def add_vulnerability(self, vuln: Dict[str, Any]):
        """
        Add a vulnerability to the findings list
        """
        required_fields = ['type', 'severity', 'description']
        if not all(field in vuln for field in required_fields):
            self.logger.error("Vulnerability missing required fields")
            return
        
        if 'severity' in vuln:
            vuln['severity'] = vuln['severity'].lower()
        
        vuln['scanner'] = self.__class__.__name__
        vuln['timestamp'] = time.time()
        
        self.vulnerabilities.append(vuln)
        self.logger.info(f"Vulnerability found: {vuln['type']} ({vuln['severity']})")

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all discovered vulnerabilities"""
        return self.vulnerabilities

    def save_results(self, filename: Optional[str] = None):
        """
        Save scan results to file
        """
        if not filename:
            filename = f"{self.__class__.__name__}_results.json"
        
        output_dir = self.workspace / "scan_results"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / filename
        
        with open(output_file, 'w') as f:
            json.dump({
                'scanner': self.__class__.__name__,
                'target': self.target,
                'vulnerabilities': self.vulnerabilities,
                'statistics': {
                    'total_requests': self.request_count,
                    'vulnerabilities_found': len(self.vulnerabilities)
                }
            }, f, indent=2)
        
        self.logger.info(f"Results saved to {output_file}")

    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """Main scanning method - must be implemented by subclasses"""
        pass

    def __enter__(self):
        self.logger.info(f"Starting {self.__class__.__name__} scan")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.logger.error(f"Scan error: {exc_val}")
        
        self.logger.info(f"Scan complete: {len(self.vulnerabilities)} vulnerabilities found")
        self.save_results()
