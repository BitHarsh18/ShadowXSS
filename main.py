import os
import requests
import argparse
from core.crawler import WebCrawler
from core.injector import Injector
from core.detector import XSSDetector
from core.url_scanner import URLScanner
from core.payloads import Payloads
from core.reporter import Reporter
from core.html_reporter import HTMLReporter
from datetime import datetime


payloads = Payloads.PAYLOADS


session = requests.Session()

crawler = WebCrawler(
    session
)

injector = Injector(
    session
)

reporter = Reporter()


total_forms = 0
payloads_tested = 0


if os.path.exists("report.json"):
    os.remove("report.json")

if os.path.exists("report.html"):
    os.remove("report.html")


parser = argparse.ArgumentParser(
    description="ShadowXSS - Automated Reflected XSS Scanner"
)

parser.add_argument(
    "--url",
    required=True,
    help="Target URL to scan"
)

args = parser.parse_args()

target_url = args.url
scan_start_time = datetime.now()


links = crawler.get_links(
    target_url
)


all_urls = [target_url] + links


print(
    f"\n[+] Found {len(links)} links\n"
)


for link in links:

    print(
        f"[LINK] {link}"
    )


for current_url in all_urls:

    print(
        f"\n[SCANNING] {current_url}"
    )

    if "?" in current_url:

        for payload in payloads:

            payloads_tested += 1

            response = URLScanner.scan_url(
                current_url,
                payload
            )

            is_vulnerable = XSSDetector.is_vulnerable(
                response,
                payload
            )

            if is_vulnerable:

                if "admin" in current_url:
                    severity = "CRITICAL"

                elif "profile" in current_url:
                    severity = "HIGH"

                elif "contact" in current_url:
                    severity = "MEDIUM"

                else:
                    severity = "LOW"

                reporter.add_finding(
                    current_url,
                    payload,
                    "URL_PARAMETER",
                    "Reflected XSS",
                    severity
                )

                print(
                    f"[URL VULNERABLE] {current_url}"
                )

                print(
                    f"Payload : {payload}"
                )

                print(
                    f"Severity : {severity}"
                )

    forms = crawler.get_forms(
        current_url
    )

    total_forms += len(forms)

    print(
        f"[+] Found {len(forms)} forms"
    )

    for form in forms:

        form_details = crawler.get_form_details(
            form
        )

        for payload in payloads:

            payloads_tested += 1

            response = injector.submit_form(
                form_details,
                current_url,
                payload
            )

            is_vulnerable = XSSDetector.is_vulnerable(
                response,
                payload
            )

            if is_vulnerable:

                if "admin" in current_url:
                    severity = "CRITICAL"

                elif "profile" in current_url:
                    severity = "HIGH"

                elif "contact" in current_url:
                    severity = "MEDIUM"

                else:
                    severity = "LOW"

                reporter.add_finding(
                    current_url,
                    payload,
                    form_details["method"],
                    "Reflected XSS",
                    severity
                )

                print(
                    "[VULNERABLE]"
                )

                print(
                    f"Payload : {payload}"
                )

                print(
                    f"Severity : {severity}"
                )

                print(
                    f"Method : {form_details['method']}"
                )

                print(
                    f"Inputs : {form_details['inputs']}\n"
                )


scan_end_time = datetime.now()
reporter.save_json()


HTMLReporter.generate(
    findings=reporter.findings,
    target_url=target_url,
    links_found=len(links),
    forms_found=total_forms,
    payloads_tested=payloads_tested,
    scan_start_time=scan_start_time,
    scan_end_time=scan_end_time
)