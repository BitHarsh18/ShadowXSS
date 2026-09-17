# ShadowXSS - Python Based XSS Vulnerability Scanner

## Overview

ShadowXSS is a modular Python-based Cross-Site Scripting (XSS) vulnerability scanner designed to automate the discovery, analysis, verification, and reporting of reflected XSS vulnerabilities in web applications.

The project was built from scratch to understand how real-world web vulnerability scanners work by implementing:

- Web crawling
- Link discovery
- Form discovery
- URL parameter testing
- Context detection
- Context-aware payload selection
- Payload injection
- Reflection detection
- Reflection normalization
- XSS candidate analysis
- Browser-based JavaScript verification
- Severity escalation
- Confidence tracking
- Evidence collection
- JSON reporting
- HTML reporting
- Report integrity validation
- Regression testing
- Accuracy testing

ShadowXSS is designed primarily for educational purposes and authorized security testing environments.

---

## Why I Built This Project

The main goal of ShadowXSS was to understand how an automated web vulnerability scanner works internally instead of relying only on existing scanning tools.

The project helped me gain practical experience with:

- Web application security
- Cross-Site Scripting (XSS)
- HTTP requests and responses
- Web crawling
- HTML parsing
- Form and parameter analysis
- Payload injection
- Reflection analysis
- Browser automation
- Vulnerability verification
- Severity classification
- Security evidence collection
- Automated security reporting
- Python modular architecture
- Regression testing

The project also focuses on reducing false positives by separating:

```text
Potential XSS
      ↓
Reflection Analysis
      ↓
Context Analysis
      ↓
Browser Verification
      ↓
Confirmed XSS
