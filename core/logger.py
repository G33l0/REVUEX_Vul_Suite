#!/usr/bin/env python3
"""
REVUEX Logger - Advanced Logging System
Author: G33L0
Telegram: @x0x0h33l0
"""

import logging
from pathlib import Path
from datetime import datetime

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class RevuexLogger:
    """Advanced logging system for REVUEX Suite"""
    
    def __init__(self, workspace):
        """Initialize logger"""
        self.workspace = Path(workspace)
        self.log_file = self.workspace / "revuex_scan.log"
        
        # Setup file logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
            ]
        )
        self.logger = logging.getLogger('REVUEX')
    
    def log_info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def log_success(self, message):
        """Log success message"""
        self.logger.info(f"[SUCCESS] {message}")
    
    def log_warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def log_error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def log_critical(self, message):
        """Log critical message"""
        self.logger.critical(message)
    
    def log_vulnerability(self, vuln_type, severity, target):
        """Log vulnerability discovery"""
        self.logger.info(f"[VULNERABILITY] {severity.upper()} - {vuln_type} on {target}")
    
    def log_exploit(self, exploit_type, target, success):
        """Log exploitation attempt"""
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"[EXPLOIT] {status} - {exploit_type} on {target}")
    
    def get_log_file(self):
        """Get log file path"""
        return self.log_file
