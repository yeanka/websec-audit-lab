# 🔐 WebSec Audit Lab — Web Application Security Research Project

> A hands-on security research project demonstrating end-to-end vulnerability discovery, exploitation, and remediation across a custom-built intentionally vulnerable web application.

![Security](https://img.shields.io/badge/Domain-Web%20Application%20Security-red)
![OWASP](https://img.shields.io/badge/Framework-OWASP%20Top%2010-orange)
![Python](https://img.shields.io/badge/Language-Python%203.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active%20Research-brightgreen)

---

## 📋 Project Overview

This project simulates a real-world penetration test against a deliberately vulnerable web application. It demonstrates:

- **Threat Modeling** using the STRIDE framework
- **Automated vulnerability scanning** with a custom Python tool
- **Manual exploitation** of OWASP Top 10 vulnerabilities
- **Structured reporting** following industry-standard pentest report format
- **Remediation guidance** with before/after code comparisons

This project was built to demonstrate applied knowledge in offensive and defensive web security — not just theoretical understanding.

---

## 🗂️ Repository Structure

```
websec-audit/
├── README.md                   ← You are here
├── vulnerable-app/             ← Target application (Flask + SQLite)
│   ├── app.py                  ← Main application with intentional vulns
│   ├── templates/              ← HTML templates
│   ├── requirements.txt
│   └── setup.sh
├── scanner/                    ← Custom vulnerability scanner
│   ├── websec_scanner.py       ← Main scanner engine
│   ├── modules/                ← Individual vulnerability modules
│   │   ├── sqli_detector.py
│   │   ├── xss_detector.py
│   │   ├── csrf_detector.py
│   │   └── header_analyzer.py
│   └── requirements.txt
├── reports/                    ← Findings & formal report
│   ├── PENTEST_REPORT.md       ← Full professional report
│   ├── findings_summary.json   ← Machine-readable findings
│   └── screenshots/            ← Evidence (add yours here)
├── docs/                       ← Supporting documentation
│   ├── THREAT_MODEL.md         ← STRIDE threat model
│   ├── METHODOLOGY.md          ← Testing methodology
│   └── REMEDIATION_GUIDE.md    ← Fix-it guide
└── scripts/
    ├── setup_lab.sh            ← One-command lab setup
    └── run_audit.sh            ← Run full audit pipeline
```

---

## 🎯 Vulnerabilities Covered

| # | Vulnerability | OWASP Category | Severity | Status |
|---|---------------|----------------|----------|--------|
| 1 | SQL Injection (Login Bypass) | A03:2021 | 🔴 Critical | Documented |
| 2 | Reflected XSS | A03:2021 | 🟠 High | Documented |
| 3 | Stored XSS | A03:2021 | 🟠 High | Documented |
| 4 | Broken Access Control | A01:2021 | 🔴 Critical | Documented |
| 5 | CSRF (No Token Validation) | A01:2021 | 🟠 High | Documented |
| 6 | Insecure Direct Object Ref. | A01:2021 | 🟠 High | Documented |
| 7 | Missing Security Headers | A05:2021 | 🟡 Medium | Documented |
| 8 | Sensitive Data Exposure | A02:2021 | 🟠 High | Documented |
| 9 | Hardcoded Credentials | A07:2021 | 🔴 Critical | Documented |
| 10 | Directory Traversal | A01:2021 | 🟠 High | Documented |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip
- Git

### 1. Clone and set up

```bash
git clone https://github.com/YOUR_USERNAME/websec-audit-lab.git
cd websec-audit-lab
chmod +x scripts/setup_lab.sh
./scripts/setup_lab.sh
```

### 2. Launch the vulnerable app

```bash
cd vulnerable-app
pip install -r requirements.txt
python app.py
# App runs on http://localhost:5000
```

### 3. Run the scanner

```bash
cd scanner
pip install -r requirements.txt
python websec_scanner.py --target http://localhost:5000 --output ../reports/findings_summary.json
```

### 4. View results

Open `reports/PENTEST_REPORT.md` for the full findings report.

---

## ⚠️ Ethical Use Disclaimer

> **This project is for educational purposes only.** The vulnerable application is intentionally designed to be insecure. **Never deploy it on a public server or a production environment.** Only run security tests against systems you own or have explicit written permission to test. Unauthorized testing is illegal.

---

## 🧠 Key Learning Outcomes

- Hands-on OWASP Top 10 exploitation and remediation
- Writing custom security tooling in Python
- Structured threat modeling with STRIDE
- Professional penetration testing report writing
- Defensive programming patterns

---

## 📚 References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CVSSv3 Scoring System](https://www.first.org/cvss/)
- [PTES Technical Guidelines](http://www.pentest-standard.org/)

---

## 👤 Author

**[Your Name]**  
Graduate Applicant | Cybersecurity Researcher  
📧 your.email@example.com  
🔗 [LinkedIn](https://linkedin.com) | [GitHub](https://github.com)

---

*This project is part of my cybersecurity portfolio demonstrating applied security research skills for graduate program admission.*
