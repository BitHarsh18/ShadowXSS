# ShadowXSS - Python Based XSS Vulnerability Scanner

## Overview

ShadowXSS is a modular Python-based Cross-Site Scripting (XSS) vulnerability scanner designed to automate the discovery of reflected XSS vulnerabilities in web applications.

The project was built from scratch to understand how real-world web vulnerability scanners work by implementing crawling, form extraction, payload injection, URL parameter testing, vulnerability detection, and report generation.

ShadowXSS focuses on detecting reflected XSS vulnerabilities through automated testing of web forms and URL parameters using multiple XSS payloads.

---

## Why I Built This Project

Modern web applications frequently suffer from input validation and output encoding issues that can lead to Cross-Site Scripting (XSS) vulnerabilities.

The goal of this project was to:

* Learn offensive web security concepts
* Understand how automated scanners work
* Gain practical experience with HTTP requests and web crawling
* Build a cybersecurity-focused project relevant to SOC Analyst and Security Analyst roles
* Develop a modular and extensible security tool

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

Payloads are automatically inserted into parameters and tested.

### Multi-Payload Engine

Currently supports 20+ XSS payloads including:

* Script Injection
* Event Handler Injection
* SVG Payloads
* Image Error Payloads
* Iframe Payloads
* Autofocus Payloads
* Object/Embed Payloads

### Reflected XSS Detection

Detects reflected payloads by analyzing server responses.

Current detection logic:

```python
payload in response.text
```

### Reporting

Generates:

* JSON Reports
* Professional HTML Reports

Each finding contains:

* Vulnerable URL
* Payload Used
* Request Method
* Vulnerability Type

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
│   ├── reporter.py
│   └── html_reporter.py
│
├── reports
│   ├── report.json
│   └── report.html
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

Functions:

* submit_form()

---

### detector.py

Responsible for:

* Reflected payload detection

Functions:

* is_vulnerable()

---

### url_scanner.py

Responsible for:

* URL parameter testing

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
* JSON export

Output:

```json
{
  "url": "...",
  "payload": "...",
  "method": "...",
  "type": "Reflected XSS"
}
```

---

### html_reporter.py

Responsible for:

* Dark-themed HTML reports
* Human-readable vulnerability summaries

---

## Detection Workflow

```text
Target URL
      │
      ▼
Web Crawling
      │
      ▼
Link Discovery
      │
      ▼
Form Discovery
      │
      ▼
Payload Injection
      │
      ▼
Response Analysis
      │
      ▼
XSS Detection
      │
      ▼
Report Generation
```

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
* Extracts forms
* Tests URL parameters
* Injects 20+ payloads
* Detects reflected XSS
* Generates reports

---

## Vulnerability Testing Lab

A custom vulnerable Flask application was built for testing.

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

### Programming

* Python
* Modular Architecture
* Object-Oriented Programming
* HTTP Requests

### Security Tool Development

* Crawling Engines
* Payload Management
* Detection Logic
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
* Reflected XSS Detection
* JSON Reporting
* HTML Reporting
* Modular Design

---

## Current Limitations

Current version detects:

* Reflected Payloads

Current version does not yet verify:

* Actual JavaScript Execution
* Browser Execution Context
* DOM-Based XSS

The scanner currently identifies reflected XSS candidates by checking whether payloads are reflected in responses.

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

* Playwright Integration
* Selenium Integration
* Real Browser-Based XSS Verification

---

## Resume Description

Developed a modular Python-based XSS vulnerability scanner featuring automated web crawling, form discovery, URL parameter testing, multi-payload injection, reflected XSS detection, and JSON/HTML vulnerability reporting.

---

## Disclaimer

This project was developed for educational purposes and authorized security testing environments only.

Do not use this tool against systems without explicit permission.

---

## Author

Harshit Kumar Srivastava

Cybersecurity Enthusiast | Security Analyst Aspirant | Python Developer
