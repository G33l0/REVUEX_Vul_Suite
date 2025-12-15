# 🔒 REVUEX Vulnerability Suite

<div align="center">

**Advanced Bug Bounty Automation Framework**

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/G33L0/revuex-vul-suite)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://www.python.org/)
[![Telegram](https://img.shields.io/badge/Telegram-@x0x0h33l0-blue.svg)](https://t.me/x0x0h33l0)

**Author:** [G33L0](https://github.com/G33L0) | **Telegram:** [@x0x0h33l0](https://t.me/x0x0h33l0)

-----

*Professional security assessment toolkit for authorized penetration testing and bug bounty hunting*

</div>

-----

## 📋 Table of Contents

- [Features](#-features)
- [What’s New](#-whats-new)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Report Capabilities](#-report-capabilities)
- [Tools Overview](#-tools-overview)
- [Output & Reports](#-output--reports)
- [Disclaimer](#%EF%B8%8F-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

-----

## ✨ Features

### 🛠️ **8 Integrated Security Tools**

|Tool                          |Description                                            |Severity Detection|
|------------------------------|-------------------------------------------------------|------------------|
|**SubdomainHunter Pro**       |Advanced subdomain discovery via CT logs, DNS, archives|Reconnaissance    |
|**TechStack Fingerprinter**   |Technology detection & CVE matching                    |Info Gathering    |
|**JavaScript Secrets Miner**  |Extract API keys, tokens, endpoints from JS files      |Medium-High       |
|**GraphQL Introspector**      |GraphQL security testing & schema extraction           |Medium-Critical   |
|**JWT Analyzer**              |JWT vulnerability detection & token analysis           |High-Critical     |
|**APK Analyzer**              |Android app security analysis                          |Medium-High       |
|**Race Condition Tester**     |Race condition detection in critical endpoints         |High-Critical     |
|**Price Manipulation Scanner**|E-commerce security testing                            |Critical          |

### 🎯 **Advanced Capabilities**

- ✅ **Sequential Execution** - Safe, recommended approach with request delays
- ✅ **Intelligent Detection** - Context-aware vulnerability identification
- ✅ **Shared Intelligence** - Centralized database across all phases
- ✅ **Professional Reports** - Bug bounty-ready HTML & JSON output
- ✅ **Progress Tracking** - Real-time scan status monitoring
- ✅ **Error Handling** - Robust retry logic and graceful failures
- ✅ **Comprehensive Logging** - Full audit trail of all operations

-----

## 🆕 What’s New

### **Professional Reporting System**

REVUEX now generates **enterprise-grade security assessment reports** with:

#### 📋 **Executive Summary**

- Risk scoring algorithm (0-100 scale)
- Business impact assessment
- Compliance analysis (PCI-DSS, GDPR, HIPAA, SOC2, ISO27001)
- Attack surface metrics
- Remediation timeline estimates

#### 🔬 **Complete Technical Evidence**

- **Steps to Reproduce** - Clear, numbered instructions for developers
- **HTTP Request/Response** - Full traffic capture with syntax highlighting
- **Proof of Concept** - Ready-to-run exploit code with copy-to-clipboard
- **Before/After Comparison** - Visual impact demonstration
- **Sensitive Data Highlighting** - Auto-detection of passwords, tokens, API keys
- **Screenshots Support** - Visual evidence integration

#### 📊 **Severity Assessment**

- CVSS score ranges (0.1-10.0)
- Priority levels (IMMEDIATE/URGENT/MODERATE/LOW)
- SLA recommendations (24 hours to 90 days)
- Impact categorization by vulnerability type

#### 🛠️ **Remediation Guidance**

- Vulnerability-specific fix instructions (SQL Injection, XSS, IDOR, etc.)
- Implementation validation checklists
- 4-phase remediation roadmap
- Timeline and resource estimates

> 📖 **[View Report Integration Guide](docs/REPORT_INTEGRATION.md)** for detailed documentation

-----

## 🚀 Installation

### **Prerequisites**

- Python 3.8 or higher
- pip3 package manager
- Linux/MacOS (recommended) or WSL on Windows

### **Setup**

```bash
# Clone the repository
git clone https://github.com/G33L0/revuex-vul-suite.git
cd revuex-vul-suite

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 revuex_suite.py --version
```

### **Dependencies**

```
requests>=2.31.0
beautifulsoup4>=4.12.0
python-jwt>=4.0.0
lxml>=4.9.0
```

-----

## 🎯 Quick Start

### **Full Automated Scan**

```bash
# Complete vulnerability assessment
python3 revuex_suite.py full -t example.com

# With custom delay (recommended for production)
python3 revuex_suite.py full -t example.com -d 3
```

### **Phase-by-Phase Execution**

```bash
# Phase 1: Reconnaissance only
python3 revuex_suite.py recon -t example.com

# Phase 2: Vulnerability scanning
python3 revuex_suite.py vuln-scan -w ./revuex_workspace/example.com_20250115_120000

# Phase 3: Exploitation & validation
python3 revuex_suite.py exploit -w ./revuex_workspace/example.com_20250115_120000
```

-----

## 💡 Usage Examples

### **Basic Scan**

```bash
python3 revuex_suite.py full -t bugcrowd.com
```

### **Conservative Scan (Higher Delay)**

```bash
python3 revuex_suite.py full -t hackerone.com -d 5
```

### **Reconnaissance for Multiple Targets**

```bash
for target in target1.com target2.com target3.com; do
    python3 revuex_suite.py recon -t $target
done
```

### **Resume from Previous Scan**

```bash
# List available workspaces
ls revuex_workspace/

# Continue with vulnerability scanning
python3 revuex_suite.py vuln-scan -w ./revuex_workspace/example.com_20250115_120000
```

-----

## 📊 Report Capabilities

### **Generated Reports**

Each scan produces comprehensive documentation:

|File                             |Format|Purpose                                      |
|---------------------------------|------|---------------------------------------------|
|`REVUEX_PROFESSIONAL_REPORT.html`|HTML  |Executive & technical report for stakeholders|
|`REVUEX_FINAL_REPORT.json`       |JSON  |Machine-readable findings for automation     |
|`executive_summary.json`         |JSON  |Risk metrics and compliance data             |
|`recon_database.json`            |JSON  |Attack surface and reconnaissance data       |
|`vulnerabilities.json`           |JSON  |Detailed vulnerability findings              |
|`confirmed_bugs.json`            |JSON  |Validated exploitable vulnerabilities        |

### **Report Preview**

<details>
<summary><b>📸 Click to see report example</b></summary>

```
╔══════════════════════════════════════════════════════════╗
║              EXECUTIVE SUMMARY                            ║
╚══════════════════════════════════════════════════════════╝

Target: example.com
Risk Score: 75/100 (HIGH)
Confirmed Exploits: 3
Total Vulnerabilities: 12

Business Impact:
  ⚠️ Data Breach Risk
  ⚠️ Financial Loss Risk
  ⚠️ Compliance Violation Risk (PCI-DSS, GDPR)

╔══════════════════════════════════════════════════════════╗
║              TECHNICAL EVIDENCE                           ║
╚══════════════════════════════════════════════════════════╝

📝 STEPS TO REPRODUCE
┌──────────────────────────────────────────────────────────┐
│ Step 1: Navigate to https://example.com/api/users        │
│ Step 2: Inject payload: ' OR '1'='1                      │
│ Step 3: Observe all user records returned                │
└──────────────────────────────────────────────────────────┘

🔬 PROOF OF VULNERABILITY

📤 HTTP Request                              [📋 Copy]
┌──────────────────────────────────────────────────────────┐
│ GET /api/users?id=1' OR '1'='1 HTTP/1.1                  │
│ Host: example.com                                         │
│ Cookie: session=abc123                                    │
└──────────────────────────────────────────────────────────┘

📥 HTTP Response                             [📋 Copy]
┌──────────────────────────────────────────────────────────┐
│ HTTP/1.1 200 OK                                           │
│ {"users": [                                               │
│   {"email": "admin@example.com", "password": "hash"} ⚠️   │
│ ]}                                                        │
└──────────────────────────────────────────────────────────┘
```

</details>

-----

## 🔧 Tools Overview

### **1️⃣ SubdomainHunter Pro**

Advanced subdomain discovery using multiple techniques:

- Certificate Transparency logs (crt.sh)
- DNS enumeration with common wordlists
- Web archive historical data
- Search engine dorking

### **2️⃣ TechStack Fingerprinter**

Technology detection and security assessment:

- Server identification (Apache, Nginx, IIS)
- Framework detection (React, Laravel, Django)
- CMS identification (WordPress, Drupal)
- Known CVE matching

### **3️⃣ JavaScript Secrets Miner**

Extract sensitive data from JavaScript files:

- API keys and tokens
- Hardcoded credentials
- Internal endpoints
- AWS/GCP credentials

### **4️⃣ GraphQL Introspector**

Comprehensive GraphQL security testing:

- Schema introspection detection
- Query depth analysis
- Field-level authorization testing
- Mutation discovery

### **5️⃣ JWT Analyzer**

JSON Web Token security assessment:

- Algorithm confusion attacks
- Signature verification bypass
- Token expiration validation
- Claims manipulation testing

### **6️⃣ APK Analyzer**

Android application security analysis:

- Decompilation and source analysis
- Hardcoded credentials detection
- API endpoint extraction
- Insecure data storage

### **7️⃣ Race Condition Tester**

Business logic vulnerability detection:

- Concurrent request testing
- Coupon/discount abuse detection
- Inventory manipulation
- Payment bypass scenarios

### **8️⃣ Price Manipulation Scanner**

E-commerce security testing:

- Client-side price validation
- Checkout bypass detection
- Discount stacking vulnerabilities
- Cart manipulation testing

-----

## 📁 Output & Reports

### **Workspace Structure**

```
revuex_workspace/
└── example.com_20250115_120000/
    ├── REVUEX_PROFESSIONAL_REPORT.html  ← Main report
    ├── REVUEX_FINAL_REPORT.json
    ├── executive_summary.json
    ├── recon_database.json
    ├── vulnerabilities.json
    ├── confirmed_bugs.json
    ├── subdomains.txt
    ├── subdomains.json
    └── logs/
        └── revuex.log
```

### **Accessing Reports**

```bash
# Open HTML report in browser
firefox ./revuex_workspace/example.com_*/REVUEX_PROFESSIONAL_REPORT.html

# View JSON findings
cat ./revuex_workspace/example.com_*/confirmed_bugs.json | jq
```

-----

## ⚠️ Disclaimer

```
┌─────────────────────────────────────────────────────────────────┐
│                        LEGAL NOTICE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  This tool is for AUTHORIZED security testing only.             │
│                                                                  │
│  ✓ Educational purposes                                         │
│  ✓ Authorized penetration testing                               │
│  ✓ Bug bounty programs with explicit scope                      │
│  ✓ Your own systems and applications                            │
│                                                                  │
│  ✗ Unauthorized access to computer systems is ILLEGAL           │
│  ✗ Always obtain proper written authorization                   │
│  ✗ Respect scope limitations and rules of engagement            │
│  ✗ Do not use for malicious purposes                            │
│                                                                  │
│  The author (G33L0) is NOT responsible for misuse or damage     │
│  caused by this tool. Use responsibly and ethically.            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**By using this tool, you agree to:**

- Only test systems you have explicit permission to test
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Respect bug bounty program rules and scope

-----

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
1. **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
1. **Commit your changes** (`git commit -m 'Add some AmazingFeature'`)
1. **Push to the branch** (`git push origin feature/AmazingFeature`)
1. **Open a Pull Request**

### **Areas for Contribution**

- 🆕 New vulnerability detection modules
- 🐛 Bug fixes and improvements
- 📚 Documentation enhancements
- 🎨 Report template improvements
- 🔧 Tool integrations

See <CONTRIBUTING.md> for detailed guidelines.

-----

## 📄 License

This project is licensed under the **MIT License** - see the <LICENSE> file for details.

```
MIT License

Copyright (c) 2025 G33L0

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

[Full license text in LICENSE file]
```

-----

## 📞 Contact

<div align="center">

**G33L0**

[![GitHub](https://img.shields.io/badge/GitHub-G33L0-black?style=for-the-badge&logo=github)](https://github.com/G33L0)
[![Telegram](https://img.shields.io/badge/Telegram-@x0x0h33l0-blue?style=for-the-badge&logo=telegram)](https://t.me/x0x0h33l0)

**Project Link:** <https://github.com/G33L0/revuex-vul-suite>

-----

### ⭐ Star this repository if you found it helpful!

Made with ❤️ by [G33L0](https://github.com/G33L0) for the security community

</div>

-----

## 🙏 Acknowledgments

- Bug bounty community for continuous feedback
- Open source security tools that inspired this project
- All contributors who help improve REVUEX

-----

<div align="center">

**Happy Hunting! 🎯**

*Remember: With great power comes great responsibility*

</div>