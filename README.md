# ShadowXSS - Python Based XSS Vulnerability Scanner

## Overview

ShadowXSS is a modular Python-based Cross-Site Scripting (XSS) vulnerability scanner designed to automate the discovery of reflected XSS vulnerabilities in web applications.

The project was built from scratch to understand how real-world web vulnerability scanners work by implementing crawling, form extraction, payload injection, URL parameter testing, context detection, browser-based verification, vulnerability detection, deduplication, and report generation.

ShadowXSS focuses on detecting reflected XSS vulnerabilities through a multi-stage pipeline that distinguishes between simple reflection, potentially executable reflection, and browser-confirmed XSS execution.

---

## Why I Built This Project

Modern web applications frequently suffer from input validation and output encoding issues that can lead to Cross-Site Scripting (XSS) vulnerabilities.

The goal of this project was to:

* Learn offensive web security concepts
* Understand how automated scanners work internally
* Gain practical experience with HTTP requests, web crawling, HTML parsing, and browser automation
* Build a cybersecurity-focused project relevant to SOC Analyst and Security Analyst roles
* Develop a modular and extensible security tool
* Understand that finding a payload in an HTTP response is not the same as confirming an XSS vulnerability

---

HTML Vulnerability Report

<img width="968" height="646" alt="image" src="https://github.com/user-attachments/assets/ee0e1fc3-0c77-4f1d-b04e-65e1a545cd51" />
<img width="958" height="721" alt="image" src="https://github.com/user-attachments/assets/04f73ff9-e7f7-444d-bf44-b352efa30f46" />
<img width="947" height="863" alt="image" src="https://github.com/user-attachments/assets/11ea6227-54da-4e59-9ed0-280569d3f5df" />
<img width="932" height="858" alt="image" src="https://github.com/user-attachments/assets/32e84228-f3ee-497d-8611-4aace95e514e" />
<img width="933" height="844" alt="image" src="https://github.com/user-attachments/assets/f63d1ff6-47bb-4ea2-b2dc-000cf6991f96" />


### CLI Command execution 
<img width="432" height="946" alt="image" src="https://github.com/user-attachments/assets/af320d5b-95f2-4045-9470-ed1548d41fb0" />


### JSON report Generation
<img width="555" height="840" alt="image" src="https://github.com/user-attachments/assets/75d9a86e-670d-43d8-b7c8-f6f10873d1c7" />

---

## Features

### Web Crawling

* Discovers internal links automatically
* Crawls target pages
* Identifies attack surfaces

### Form Discovery

* Detects HTML forms
* Extracts:

  * Form action
  * Form method
  * Input fields

### Payload Injection

Supports:

* GET requests
* POST requests

Automatically injects XSS payloads into discovered inputs.

### URL Parameter Testing

Tests query string parameters such as:

```url
/profile?name=test
```

Payloads are automatically inserted into parameters and tested independently per parameter.

### Multi-Payload Engine

Currently supports 20+ XSS payloads including:

* Script Injection
* Event Handler Injection
* SVG Payloads
* Image Error Payloads
* Iframe Payloads
* Autofocus Payloads
* Object/Embed Payloads

### Reflection Detection

Detects and distinguishes between:

* **Direct Reflection** — Payload appears in the response as-is
* **Encoded Reflection** — Payload appears in HTML-encoded form (e.g., `&lt;script&gt;`)

The scanner does not treat encoded reflection as executable XSS automatically.

### Context Detection ⭐

One of the most important stages in ShadowXSS.

After detecting a reflection, the scanner identifies **where exactly** the input was reflected:

* HTML Text context
* HTML Attribute context
* Event Handler context
* JavaScript context
* JavaScript URL context
* HTML Comment context

Context detection uses a controlled marker/probe injected into the parameter. The surrounding HTML structure is then analyzed to determine the enclosing tag, attribute, quote style, and context type.

> **Important:** A `<script>` tag introduced by the payload itself is not treated as an existing JavaScript context. The scanner distinguishes between application-provided JavaScript blocks and attacker-introduced script tags.

### Potential XSS Classification

After context analysis, the scanner determines whether the reflection is:

* In an execution-relevant context
* Containing executable-looking patterns (script elements, event handlers, javascript: URLs)

Only then is the finding classified as **Potential XSS** — not immediately as a confirmed vulnerability.

### Browser-Based Verification ⭐

ShadowXSS uses **Selenium with Chrome** to verify whether JavaScript actually executes in a real browser environment for each potential XSS finding.

* If JavaScript execution is observed → Finding is marked as **Confirmed XSS**
* If execution is not observed → Finding is marked as **Not Confirmed**

This stage separates genuine vulnerabilities from false positives that pass HTTP-level analysis.

### Deduplication

When multiple payloads detect the same injection point, ShadowXSS consolidates them into a single finding rather than generating duplicate reports. Successful payload information is preserved within the deduplicated finding.

### Enhanced Reporting

Each finding now contains:

* Vulnerable URL
* Parameter
* Payload Used
* Request Method
* Reflection Type (Direct / Encoded)
* Context
* Confidence
* Severity
* Potential XSS flag
* Browser Verification status
* Confirmed XSS flag
* Successful Payloads
* Verification Reason
* Alert Text (if observed)
* Evidence

Generates:

* JSON Reports
* Professional HTML Reports
* Terminal output recorded in `main.txt`

---

## Complete Scanning Workflow

```text
Target URL
      │
      ▼
Web Crawling
      │
      ▼
Link & Form Discovery
      │
      ▼
Identify Injection Points
(URL Parameters + Form Inputs)
      │
      ▼
Context Probe
      │
      ▼
Payload Selection & Injection
      │
      ▼
HTTP Response Analysis
      │
      ▼
Reflection Detection
(Direct / Encoded / None)
      │
      ▼
Context Detection
(HTML / Attribute / JS / Comment / Event Handler)
      │
      ▼
Potential XSS Classification
      │
      ▼
Browser Verification (Selenium)
      │
      ▼
Confirmed XSS / Not Confirmed
      │
      ▼
Evidence Collection
      │
      ▼
Deduplication
      │
      ▼
Report Generation (JSON + HTML)
```

---

## Project Architecture

```text
ShadowXSS
│
├── main.py
│
├── core
│   ├── crawler.py
│   ├── injector.py
│   ├── detector.py
│   ├── url_scanner.py
│   ├── payloads.py
│   ├── context_detector.py
│   ├── browser_scanner.py
│   ├── reporter.py
│   └── html_reporter.py
│
├── reports
│   ├── report.json
│   ├── report.html
│   └── main.txt
│
└── vulnerable_app.py
```

---

## Module Breakdown

### crawler.py

Responsible for:

* Form extraction
* Link discovery
* Form metadata extraction

Functions:

* get_forms()
* get_form_details()
* get_links()

---

### injector.py

Responsible for:

* Payload insertion
* GET requests
* POST requests

Uses a persistent HTTP session for all requests.

Functions:

* submit_form()

---

### detector.py

Responsible for:

* Reflected payload detection
* Distinguishing direct reflection from encoded reflection
* Identifying potentially executable patterns

Functions:

* is_vulnerable()
* _looks_executable()

---

### context_detector.py ⭐ New

Responsible for:

* Injecting a controlled marker/probe into parameters
* Analyzing where the probe appears in the response
* Identifying the surrounding HTML/JS context
* Storing context metadata: context type, enclosing tag, attribute name, quote style, probe found status
* Distinguishing application-provided JavaScript blocks from attacker-introduced script tags

---

### browser_scanner.py ⭐ New

Responsible for:

* Browser-based JavaScript execution verification
* Selenium + Chrome integration
* Loading potential XSS test cases in a real browser
* Observing JavaScript execution behavior
* Marking findings as Confirmed or Not Confirmed

---

### url_scanner.py

Responsible for:

* URL parameter testing
* Testing each parameter independently with each payload

Concepts used:

* urlparse()
* parse_qs()
* urlencode()
* urlunparse()

---

### payloads.py

Stores all XSS payloads used during testing.

Current payload count:

20+

---

### reporter.py

Responsible for:

* Storing findings
* Deduplication of findings per injection point
* JSON export

Output example:

```json
{
  "url": "...",
  "parameter": "...",
  "payload": "...",
  "method": "...",
  "reflection": "direct",
  "context": "html_text",
  "confidence": "high",
  "severity": "high",
  "potential_xss": true,
  "browser_verified": true,
  "confirmed_xss": true,
  "type": "Reflected XSS"
}
```

---

### html_reporter.py

Responsible for:

* Dark-themed HTML reports
* Human-readable vulnerability summaries
* Evidence display per finding

---

## Example Scan

```bash
python3 main.py
```

```text
ENTER TARGET URL:
http://127.0.0.1:5000
```

Scanner:

* Crawls website
* Extracts forms and links
* Identifies injection points
* Probes each injection point for context
* Injects 20+ payloads
* Detects direct and encoded reflection
* Analyzes reflection context
* Classifies potential XSS findings
* Verifies browser execution via Selenium
* Deduplicates findings
* Generates JSON and HTML reports

---

## Vulnerability Testing Lab

A custom vulnerable Flask application was built for testing, regression testing, and evaluating true positives, true negatives, false positives, and false negatives.

Included vulnerable pages:

### Search Page

Reflected XSS via query parameter.

```url
/search?q=test
```

### Login Page

Reflected XSS via POST parameter.

```url
/login
```

### Profile Page

Reflected XSS via URL parameter.

```url
/profile?name=test
```

### Contact Page

Built for future textarea testing.

---

## Technologies Used

* Python
* Requests
* BeautifulSoup
* Selenium
* Chrome WebDriver
* Flask
* HTML
* CSS
* JSON

---

## Skills Demonstrated

### Cybersecurity

* Web Application Security
* Cross-Site Scripting (XSS)
* Vulnerability Assessment
* Security Testing
* Context-Aware Analysis
* Evidence-Based Vulnerability Reporting

### Programming

* Python
* Modular Architecture
* Object-Oriented Programming
* HTTP Requests
* Browser Automation

### Security Tool Development

* Crawling Engines
* Payload Management
* Context Detection Logic
* Browser Verification
* Deduplication
* Reporting Systems

---

## Current Capabilities

### Implemented

* Web Crawling
* Form Discovery
* Link Discovery
* GET Form Testing
* POST Form Testing
* URL Parameter Testing
* 20+ Payload Testing
* Direct Reflection Detection
* Encoded Reflection Detection
* Context Detection (HTML / Attribute / JS / Event Handler / Comment)
* Potential XSS Classification
* Browser-Based Verification (Selenium + Chrome)
* Confirmed XSS vs Not Confirmed distinction
* Severity and Confidence Scoring
* Deduplication of Findings
* JSON Reporting
* HTML Reporting
* Terminal Output Logging (main.txt)
* Modular Design
* Regression Testing with Custom Vulnerable Flask App

---

## Current Limitations

* Primarily focused on **reflected XSS** — stored and DOM-based XSS require additional workflows
* Complex authentication flows may require session handling beyond current scope
* Heavy JavaScript single-page applications may limit crawling effectiveness
* WAFs or application-specific sanitization may affect detection results
* DOM-based XSS requires dedicated client-side JavaScript analysis

---

## Future Roadmap

### Phase 1

* Complete Session Support
* Textarea Detection
* Select Field Detection

### Phase 2

* Authentication Support
* Login Automation
* Cookie Persistence

### Phase 3

* External Payload Files

Examples:

```text
payloads/
├── basic.txt
├── advanced.txt
├── waf_bypass.txt
```

### Phase 4

* 50+ Payload Library

### Phase 5

* Stored XSS Detection

### Phase 6

* DOM XSS Detection

### Phase 7

* Multithreaded Scanning

### Phase 8

* Custom Header Support

### Phase 9

* Command Line Arguments

Example:

```bash
python3 shadowxss.py \
--url http://target.com \
--output report.html
```

### Phase 10

* Playwright Integration for advanced browser automation

---

## Disclaimer

This project was developed for educational purposes and authorized security testing environments only.

Do not use this tool against systems without explicit permission.

---

## Author

Harshit Kumar Srivastava

Cybersecurity Enthusiast | Security Analyst Aspirant | Python Developer
