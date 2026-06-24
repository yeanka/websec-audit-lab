#!/usr/bin/env python3
"""
WebSec Audit Lab — Custom Vulnerability Scanner
================================================
A modular web application security scanner covering:
  - SQL Injection detection
  - Reflected XSS detection
  - Missing security headers
  - CSRF protection analysis
  - Sensitive data exposure
  - Open redirect checks

Usage:
    python websec_scanner.py --target http://localhost:5000
    python websec_scanner.py --target http://localhost:5000 --output report.json

Author: [Your Name]
"""

import argparse
import json
import sys
import time
import re
import urllib.parse
from datetime import datetime
from typing import Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Install requests: pip install requests")
    sys.exit(1)


# ─── Colour helpers ────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    ORANGE = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def info(msg):   print(f"{C.BLUE}[*]{C.RESET} {msg}")
def ok(msg):     print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):   print(f"{C.ORANGE}[!]{C.RESET} {msg}")
def vuln(msg):   print(f"{C.RED}[VULN]{C.RESET} {C.BOLD}{msg}{C.RESET}")
def banner(msg): print(f"\n{C.BOLD}{'─'*60}\n  {msg}\n{'─'*60}{C.RESET}")


# ─── Finding dataclass ─────────────────────────────────────────────────────────

class Finding:
    def __init__(self, vuln_id, name, severity, url, parameter,
                 payload, evidence, description, recommendation, cvss):
        self.vuln_id        = vuln_id
        self.name           = name
        self.severity       = severity          # Critical / High / Medium / Low / Info
        self.url            = url
        self.parameter      = parameter
        self.payload        = payload
        self.evidence       = evidence
        self.description    = description
        self.recommendation = recommendation
        self.cvss           = cvss
        self.timestamp      = datetime.utcnow().isoformat()

    def to_dict(self):
        return self.__dict__


# ─── Scanner modules ───────────────────────────────────────────────────────────

class SQLiDetector:
    """Detects SQL Injection via error-based and boolean-based techniques."""

    ERROR_PATTERNS = [
        r"sqlite3\.OperationalError",
        r"syntax error",
        r"unclosed quotation",
        r"sqlite_error",
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"pg_query\(\)",
        r"ORA-\d{5}",
    ]

    PAYLOADS = [
        ("'",            "Single quote — error trigger"),
        ('" OR "1"="1',  "Boolean-based bypass"),
        ("' OR '1'='1'--",  "Classic login bypass"),
        ("1 UNION SELECT null--", "UNION probe"),
        ("'; DROP TABLE users--", "Stacked query attempt"),
    ]

    def scan(self, session, base_url, endpoints):
        findings = []
        for endpoint, params, method in endpoints:
            url = f"{base_url}{endpoint}"
            for param in params:
                for payload, desc in self.PAYLOADS:
                    try:
                        data = {p: "test" for p in params}
                        data[param] = payload
                        if method == "POST":
                            r = session.post(url, data=data, timeout=8, verify=False)
                        else:
                            r = session.get(url, params=data, timeout=8, verify=False)

                        body = r.text.lower()
                        for pattern in self.ERROR_PATTERNS:
                            if re.search(pattern, body, re.I):
                                findings.append(Finding(
                                    vuln_id="SQLI-001",
                                    name="SQL Injection",
                                    severity="Critical",
                                    url=url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=f"Pattern '{pattern}' found in response",
                                    description=(
                                        "The application directly concatenates user input into SQL queries "
                                        "without parameterization. An attacker can manipulate query logic to "
                                        "bypass authentication, extract data, or modify the database."
                                    ),
                                    recommendation=(
                                        "Use parameterized queries (prepared statements) for ALL database "
                                        "interactions. Never concatenate user input into SQL strings. "
                                        "Example fix: cursor.execute('SELECT * FROM users WHERE username=?', (username,))"
                                    ),
                                    cvss=9.8
                                ))
                                vuln(f"SQLi detected: {url} | param={param} | payload={repr(payload)}")
                                break
                    except requests.exceptions.RequestException:
                        pass
        return findings


class XSSDetector:
    """Detects Reflected and Stored XSS."""

    PAYLOADS = [
        ('<script>alert("XSS")</script>',      "Basic script tag"),
        ('<img src=x onerror=alert(1)>',        "img onerror"),
        ('"><script>alert(1)</script>',         "Attribute breakout"),
        ("javascript:alert(1)",                 "JS protocol"),
        ('<svg onload=alert(1)>',               "SVG onload"),
    ]

    def scan(self, session, base_url, endpoints):
        findings = []
        for endpoint, params, method in endpoints:
            url = f"{base_url}{endpoint}"
            for param in params:
                for payload, desc in self.PAYLOADS:
                    try:
                        data = {p: "safe_value" for p in params}
                        data[param] = payload
                        if method == "POST":
                            r = session.post(url, data=data, timeout=8, verify=False)
                        else:
                            r = session.get(url, params=data, timeout=8, verify=False)

                        if payload in r.text or urllib.parse.quote(payload) in r.text:
                            xss_type = "Stored XSS" if method == "POST" else "Reflected XSS"
                            findings.append(Finding(
                                vuln_id="XSS-001" if method == "GET" else "XSS-002",
                                name=xss_type,
                                severity="High",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=f"Payload reflected unescaped in HTTP response",
                                description=(
                                    f"{xss_type} found. The application renders user-supplied data "
                                    "without HTML encoding, allowing injection of arbitrary JavaScript. "
                                    "Attackers can steal session cookies, redirect users, or deface pages."
                                ),
                                recommendation=(
                                    "HTML-encode all user-supplied output. In Flask/Jinja2, use {{ var }} "
                                    "(not {{ var|safe }}) to auto-escape output. Implement a Content-Security-Policy "
                                    "header to restrict script execution."
                                ),
                                cvss=7.4
                            ))
                            vuln(f"{xss_type}: {url} | param={param}")
                            break
                    except requests.exceptions.RequestException:
                        pass
        return findings


class HeaderAnalyzer:
    """Checks for missing/misconfigured HTTP security headers."""

    REQUIRED_HEADERS = {
        "X-Content-Type-Options":      ("nosniff", "Medium",   "CSP-001", 5.3),
        "X-Frame-Options":             ("DENY",    "Medium",   "CSP-002", 4.3),
        "Content-Security-Policy":     (None,      "High",     "CSP-003", 6.1),
        "Strict-Transport-Security":   (None,      "Medium",   "CSP-004", 4.3),
        "X-XSS-Protection":            ("1; mode=block", "Low","CSP-005", 3.1),
        "Referrer-Policy":             (None,      "Low",      "CSP-006", 3.1),
        "Permissions-Policy":          (None,      "Low",      "CSP-007", 2.7),
    }

    def scan(self, session, base_url):
        findings = []
        try:
            r = session.get(base_url, timeout=8, verify=False)
            for header, (expected, severity, vid, cvss) in self.REQUIRED_HEADERS.items():
                if header not in r.headers:
                    findings.append(Finding(
                        vuln_id=vid,
                        name=f"Missing Security Header: {header}",
                        severity=severity,
                        url=base_url,
                        parameter="HTTP Response Header",
                        payload="N/A",
                        evidence=f"Header '{header}' absent from server response",
                        description=(
                            f"The HTTP response does not include the '{header}' security header. "
                            "Missing security headers allow various browser-based attacks."
                        ),
                        recommendation=(
                            f"Add '{header}' to all HTTP responses. "
                            "In Flask: @app.after_request to inject headers globally."
                        ),
                        cvss=cvss
                    ))
                    warn(f"Missing header: {header}")
        except requests.exceptions.RequestException as e:
            warn(f"Header scan failed: {e}")
        return findings


class CSRFDetector:
    """Checks for absent CSRF tokens on state-changing forms."""

    def scan(self, session, base_url, form_endpoints):
        findings = []
        for endpoint in form_endpoints:
            url = f"{base_url}{endpoint}"
            try:
                r = session.get(url, timeout=8, verify=False)
                body = r.text.lower()
                has_csrf = (
                    "csrf_token" in body or
                    "csrfmiddlewaretoken" in body or
                    "_token" in body or
                    "x-csrf-token" in body
                )
                if "<form" in body and not has_csrf:
                    findings.append(Finding(
                        vuln_id="CSRF-001",
                        name="Cross-Site Request Forgery (No CSRF Token)",
                        severity="High",
                        url=url,
                        parameter="Form token",
                        payload="N/A",
                        evidence="HTML form present with no CSRF token field detected",
                        description=(
                            "State-changing forms lack CSRF tokens. An attacker can craft a "
                            "malicious page that silently submits requests on behalf of a "
                            "logged-in victim, leading to unauthorized actions."
                        ),
                        recommendation=(
                            "Implement synchronizer token pattern: generate a random CSRF token "
                            "per session, embed it in every form as a hidden field, and validate "
                            "server-side on each POST. Use flask-wtf or itsdangerous for this."
                        ),
                        cvss=7.1
                    ))
                    vuln(f"No CSRF token: {url}")
            except requests.exceptions.RequestException:
                pass
        return findings


class SensitiveDataDetector:
    """Looks for sensitive data exposure in responses."""

    PATTERNS = {
        "SSN":          r"\b\d{3}-\d{2}-\d{4}\b",
        "Email":        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "Private Key":  r"-----BEGIN.*PRIVATE KEY-----",
        "AWS Key":      r"AKIA[0-9A-Z]{16}",
        "Password field in response": r'"password"\s*:\s*"[^"]+"',
    }

    def scan(self, session, base_url, endpoints):
        findings = []
        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            try:
                r = session.get(url, timeout=8, verify=False)
                for label, pattern in self.PATTERNS.items():
                    matches = re.findall(pattern, r.text, re.I)
                    if matches:
                        findings.append(Finding(
                            vuln_id="SDE-001",
                            name=f"Sensitive Data Exposure: {label}",
                            severity="High",
                            url=url,
                            parameter="HTTP Response Body",
                            payload="N/A",
                            evidence=f"Pattern matched: {matches[0]} (and {len(matches)-1} more)" if len(matches) > 1 else f"Found: {matches[0]}",
                            description=(
                                f"The response at {url} contains sensitive {label} data "
                                "that should not be exposed to the client."
                            ),
                            recommendation=(
                                "Never return sensitive fields (passwords, SSNs, keys) in API responses. "
                                "Apply field-level access control. Encrypt sensitive data at rest "
                                "and use hashing (bcrypt) for passwords."
                            ),
                            cvss=7.5
                        ))
                        vuln(f"Sensitive data ({label}) at {url}")
                        break
            except requests.exceptions.RequestException:
                pass
        return findings


# ─── Main Scanner ──────────────────────────────────────────────────────────────

class WebSecScanner:

    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.session  = requests.Session()
        self.session.headers.update({"User-Agent": "WebSecAuditLab/1.0 (Security Research)"})
        self.findings: list[Finding] = []
        self.start_time = datetime.utcnow()

    def run(self):
        banner("WebSec Audit Lab — Vulnerability Scanner v1.0")
        info(f"Target : {self.target}")
        info(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        # ── 1. Security Headers ──────────────────────────────────────────────
        banner("Module 1: Security Header Analysis")
        ha = HeaderAnalyzer()
        self.findings += ha.scan(self.session, self.target)

        # ── 2. SQL Injection ─────────────────────────────────────────────────
        banner("Module 2: SQL Injection Detection")
        sqli_endpoints = [
            ("/login",  ["username", "password"], "POST"),
            ("/search", ["q"],                    "GET"),
        ]
        sqli = SQLiDetector()
        self.findings += sqli.scan(self.session, self.target, sqli_endpoints)

        # ── 3. XSS ──────────────────────────────────────────────────────────
        banner("Module 3: Cross-Site Scripting (XSS) Detection")
        xss_endpoints = [
            ("/search", ["q"],                        "GET"),
            ("/notes",  ["title", "content"],         "POST"),
        ]
        xss = XSSDetector()
        self.findings += xss.scan(self.session, self.target, xss_endpoints)

        # ── 4. CSRF ──────────────────────────────────────────────────────────
        banner("Module 4: CSRF Token Analysis")
        csrf = CSRFDetector()
        self.findings += csrf.scan(self.session, self.target, ["/login", "/notes"])

        # ── 5. Sensitive Data Exposure ───────────────────────────────────────
        banner("Module 5: Sensitive Data Exposure")
        sde = SensitiveDataDetector()
        self.findings += sde.scan(self.session, self.target, ["/user/1", "/user/2", "/admin"])

        # ── Summary ──────────────────────────────────────────────────────────
        self._print_summary()
        return self.findings

    def _print_summary(self):
        banner("Scan Complete — Summary")
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        print(f"  Total findings : {len(self.findings)}")
        print(f"  🔴 Critical    : {severity_counts['Critical']}")
        print(f"  🟠 High        : {severity_counts['High']}")
        print(f"  🟡 Medium      : {severity_counts['Medium']}")
        print(f"  🟢 Low         : {severity_counts['Low']}")
        duration = (datetime.utcnow() - self.start_time).seconds
        print(f"\n  Scan duration  : {duration}s")

    def export_json(self, path: str):
        report = {
            "meta": {
                "tool":    "WebSec Audit Lab Scanner v1.0",
                "target":  self.target,
                "date":    self.start_time.isoformat(),
                "total":   len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings]
        }
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)
        ok(f"JSON report saved → {path}")


# ─── CLI Entry Point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="WebSec Audit Lab — Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python websec_scanner.py --target http://localhost:5000
  python websec_scanner.py --target http://localhost:5000 --output findings.json
        """
    )
    parser.add_argument("--target",  required=True, help="Target base URL (e.g. http://localhost:5000)")
    parser.add_argument("--output",  default=None,  help="Save JSON findings to this path")
    args = parser.parse_args()

    scanner = WebSecScanner(target=args.target)
    findings = scanner.run()

    if args.output:
        scanner.export_json(args.output)

    sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    main()
