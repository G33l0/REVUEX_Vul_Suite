# REVUEX Vulnerability Suite

Advanced Bug Bounty Automation Framework

**Author:** G33L0  
**Telegram:** @x0x0h33l0  
**Version:** 1.0

## 🎯 Features

### 8 Integrated Security Tools:
1. **SubdomainHunter Pro** - Advanced subdomain discovery
2. **TechStack Fingerprinter** - Technology detection & CVE matching
3. **JavaScript Secrets Miner** - Extract API keys, tokens, endpoints
4. **GraphQL Introspector** - GraphQL security testing
5. **JWT Analyzer** - JWT vulnerability detection
6. **APK Analyzer** - Android app security analysis
7. **Race Condition Tester** - Race condition detection
8. **Price Manipulation Scanner** - E-commerce security testing

### Advanced Features:
- Sequential execution (safe, recommended)
- Intelligent vulnerability detection
- Shared intelligence database
- World-class HTML reports
- Progress tracking
- Error handling
- Comprehensive logging

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/revuex-vul-suite
cd revuex-vul-suite

# Install dependencies
pip3 install -r requirements.txt

Usage
Full Automated Scan

python3 revuex_suite.py full -t example.com

Phase-by-Phase

# Reconnaissance only
python3 revuex_suite.py recon -t example.com

# Vulnerability scan
python3 revuex_suite.py vuln-scan -w ./revuex_workspace/example.com_*

# Exploitation
python3 revuex_suite.py exploit -w ./revuex_workspace/example.com_*

Custom Delay

python3 revuex_suite.py full -t example.com -d 5

Output
	•	HTML Report: Professional vulnerability report
	•	JSON Report: Machine-readable findings
	•	Workspace: All raw data and logs
Disclaimer
For authorized security testing only.
This tool is for educational purposes and authorized penetration testing only.Unauthorized access to computer systems is illegal.Always obtain proper authorization before testing.
License
MIT License - See LICENSE file
Author
G33L0Telegram: @x0x0h33l0GitHub: github.com/G33L0
Contributing
Contributions welcome! Please read CONTRIBUTING.md

Made with ❤️ by G33L0
