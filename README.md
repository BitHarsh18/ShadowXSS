# ShadowXSS - Python Based XSS Vulnerability Scanner

## Overview

ShadowXSS is a modular Python-based Cross-Site Scripting (XSS) vulnerability scanner designed to automate the discovery, analysis, verification, classification, and reporting of reflected XSS vulnerabilities in web applications.

The project was built from scratch to understand how real-world web vulnerability scanners work by implementing crawling, form extraction, payload injection, URL parameter testing, reflection analysis, context detection, context-aware payload selection, browser-based verification, severity classification, confidence tracking, evidence collection, finding deduplication, and automated report generation.

ShadowXSS focuses primarily on detecting reflected XSS vulnerabilities through automated testing of web forms and URL parameters using multiple categorized XSS payloads.

The scanner follows a multi-stage approach:

```text
Target
  │
  ▼
Crawling
  │
  ▼
Injection Point Discovery
  │
  ▼
Context Detection
  │
  ▼
Context-Aware Payload Selection
  │
  ▼
Payload Injection
  │
  ▼
Reflection Analysis
  │
  ▼
Potential XSS
  │
  ▼
Browser Verification
  │
  ▼
Confirmed XSS
  │
  ▼
Severity + Confidence
  │
  ▼
Evidence Collection
  │
  ▼
JSON + HTML Reports
