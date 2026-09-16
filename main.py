import os
import sys
import requests
import argparse

from core.crawler import WebCrawler
from core.injector import Injector
from core.detector import XSSDetector
from core.url_scanner import URLScanner
from core.payloads import Payloads
from core.reporter import Reporter
from core.html_reporter import HTMLReporter
from core.browser import BrowserScanner
from core.context_detector import ContextDetector
from core.context_payload_selector import ContextPayloadSelector

from datetime import datetime


# =================================================================
# TERMINAL OUTPUT LOGGER
# =================================================================
#
# Everything printed by main.py will:
#
# 1. Still appear normally in PowerShell
# 2. Also be saved into main.txt
#
# =================================================================


class Tee:

    def __init__(
        self,
        *streams
    ):

        self.streams = streams


    def write(
        self,
        data
    ):

        for stream in self.streams:

            stream.write(
                data
            )

            stream.flush()


    def flush(self):

        for stream in self.streams:

            stream.flush()


# -----------------------------------------------------------------
# Create terminal log file
# -----------------------------------------------------------------

terminal_log = open(
    "main.txt",
    "w",
    encoding="utf-8"
)


# -----------------------------------------------------------------
# Preserve original stdout/stderr
# -----------------------------------------------------------------

original_stdout = sys.stdout
original_stderr = sys.stderr


# -----------------------------------------------------------------
# Send stdout and stderr to:
#
# PowerShell + main.txt
# -----------------------------------------------------------------

sys.stdout = Tee(
    original_stdout,
    terminal_log
)

sys.stderr = Tee(
    original_stderr,
    terminal_log
)


# =================================================================
# PAYLOAD LIBRARY
# =================================================================

payloads = Payloads.PAYLOADS


# =================================================================
# HTTP SESSION
# =================================================================

session = requests.Session()


crawler = WebCrawler(
    session
)


injector = Injector(
    session
)


reporter = Reporter()


# =================================================================
# PHASE 2.1 - CONTEXT PROBE HELPERS
# =================================================================

def merge_context_probe(analysis, context_result):

    if analysis is None:
        analysis = {}

    if not context_result:
        return analysis

    # -------------------------------------------------------------
    # Preserve the payload-level classification separately.
    #
    # XSSDetector analyzes the actual payload and may correctly
    # notice markup introduced by that payload, such as:
    #
    #     <script>alert(1)</script>
    #
    # That is NOT necessarily the application's original
    # injection context.
    #
    # ContextDetector uses a harmless marker and therefore its
    # result is authoritative for the original injection context.
    # -------------------------------------------------------------

    analysis["payload_context"] = analysis.get(
        "context",
        "unknown"
    )

    analysis["payload_tag"] = analysis.get(
        "tag"
    )

    analysis["payload_attribute"] = analysis.get(
        "attribute"
    )

    analysis["payload_quote"] = analysis.get(
        "quote"
    )

    # -------------------------------------------------------------
    # Authoritative Phase 2.1 context
    # -------------------------------------------------------------

    context = context_result.get(
        "context"
    )

    if context and context not in (
        "unknown",
        "not reflected"
    ):

        analysis["context"] = context

    # Context metadata comes from the harmless marker probe.
    analysis["tag"] = context_result.get(
        "tag"
    )

    analysis["attribute"] = context_result.get(
        "attribute"
    )

    analysis["quote"] = context_result.get(
        "quote"
    )

    analysis["context_probe"] = context_result.get(
        "found",
        False
    )

    analysis["context_probe_marker"] = context_result.get(
        "marker",
        ""
    )

    analysis["context_probe_reason"] = context_result.get(
        "reason",
        ""
    )

    # Keep a copy of the probe evidence for reporting/debugging.
    analysis["context_probe_evidence"] = context_result.get(
        "evidence",
        ""
    )

    return analysis


def probe_url_parameter_context(url, parameter):

    try:

        return ContextDetector.detect_url_parameter_context(
            url,
            parameter,
            session=session
        )

    except Exception as error:

        return {
            "parameter": parameter,
            "marker": "",
            "context": "unknown",
            "tag": None,
            "attribute": None,
            "quote": None,
            "found": False,
            "reason": "Context probe failed: " + str(error),
            "evidence": ""
        }


def probe_form_input_context(form_details, url, input_name):

    marker = ContextDetector.generate_marker()

    try:

        response = injector.submit_input(
            form_details,
            url,
            input_name,
            marker
        )

        result = ContextDetector.detect_response_context(
            response,
            marker
        )

        result["parameter"] = input_name
        result["marker"] = marker

        return result

    except Exception as error:

        return {
            "parameter": input_name,
            "marker": marker,
            "context": "unknown",
            "tag": None,
            "attribute": None,
            "quote": None,
            "found": False,
            "reason": "Context probe failed: " + str(error),
            "evidence": ""
        }



def get_context_payloads(
    context,
    payload_limit
):
    """
    Phase 2.2:
    Select payloads according to the authoritative context.

    --p is applied AFTER context selection.
    """

    selected = ContextPayloadSelector.get_payloads(
        context
    )

    return selected[:payload_limit]



# =================================================================
# PHASE 6 - RISK-BASED SEVERITY
# =================================================================
#
# Severity is determined from the actual detection evidence rather
# than simply assigning severity from the endpoint name.
#
# Initial severity is based on:
#   1. Detector confidence
#   2. Authoritative injection context
#   3. Endpoint sensitivity as a secondary signal
#
# Browser verification is intentionally handled separately. A
# confirmed browser execution should not be confused with the
# initial HTTP-reflection severity.
# =================================================================

def calculate_severity(
    current_url,
    analysis
):

    confidence = str(
        analysis.get(
            "confidence",
            "low"
        )
    ).lower()

    context = str(
        analysis.get(
            "context",
            "unknown"
        )
    ).lower()

    # -------------------------------------------------------------
    # Context risk
    # -------------------------------------------------------------
    #
    # Executable JavaScript contexts are inherently more dangerous
    # than ordinary HTML text reflection.
    #

    if context in (
        "javascript",
        "event handler attribute",
        "javascript url attribute"
    ):

        context_risk = 3

    elif context in (
        "html attribute",
        "html text"
    ):

        context_risk = 2

    else:

        context_risk = 1


    # -------------------------------------------------------------
    # Confidence risk
    # -------------------------------------------------------------

    confidence_risk = {

        "high": 3,
        "medium": 2,
        "low": 1

    }.get(
        confidence,
        1
    )


    # -------------------------------------------------------------
    # Endpoint sensitivity
    # -------------------------------------------------------------
    #
    # Endpoint name is only a secondary risk signal. It must not
    # override stronger evidence from the detector/context.
    #

    endpoint = str(
        current_url
    ).lower()

    if "/admin" in endpoint:

        endpoint_risk = 3

    elif "/profile" in endpoint:

        endpoint_risk = 2

    elif "/contact" in endpoint:

        endpoint_risk = 2

    else:

        endpoint_risk = 1


    # -------------------------------------------------------------
    # Combined score
    # -------------------------------------------------------------

    score = (
        confidence_risk
        +
        context_risk
        +
        endpoint_risk
    )


    # -------------------------------------------------------------
    # Severity bands
    # -------------------------------------------------------------

    if score >= 8:

        return "CRITICAL"

    if score >= 6:

        return "HIGH"

    if score >= 4:

        return "MEDIUM"

    return "LOW"


# =================================================================
# SCAN STATISTICS
# =================================================================

total_forms = 0

total_injection_points = 0

payloads_tested = 0


# =================================================================
# REMOVE PREVIOUS REPORTS
# =================================================================

if os.path.exists(
    "report.json"
):

    os.remove(
        "report.json"
    )


if os.path.exists(
    "report.html"
):

    os.remove(
        "report.html"
)


# =================================================================
# COMMAND LINE ARGUMENTS
# =================================================================

parser = argparse.ArgumentParser(
    description=(
        "ShadowXSS - "
        "Automated Reflected XSS Scanner"
    )
)


parser.add_argument(
    "--url",
    required=True,
    help="Target URL to scan"
)

parser.add_argument(
    "--p",
    type=int,
    default=5,
    help="Number of payloads to test (default: 5)"
)


args = parser.parse_args()


if args.p < 1:

    parser.error(
        "--p must be at least 1"
    )


payload_limit = min(
    args.p,
    len(Payloads.PAYLOADS)
)


# The complete library remains available for reporting/fallback.
# Actual payloads are selected per injection point after context detection.
payloads = Payloads.PAYLOADS


target_url = args.url


scan_start_time = datetime.now()


# =================================================================
# CRAWL TARGET
# =================================================================

links = crawler.get_links(
    target_url
)


all_urls = [
    target_url
] + links


print(
    f"\n[+] Found {len(links)} links\n"
)


for link in links:

    print(
        f"[LINK] {link}"
    )


# =================================================================
# SCAN ALL DISCOVERED URLS
# =================================================================

for current_url in all_urls:

    print(
        f"\n[SCANNING] {current_url}"
    )


    # =============================================================
    # URL PARAMETER SCANNING
    # =============================================================

    parameters = URLScanner.get_parameters(
        current_url
    )


    if parameters:

        print(
            f"[+] Found "
            f"{len(parameters)} URL parameters"
        )


        # ---------------------------------------------------------
        # Every URL parameter = one injection point
        # ---------------------------------------------------------

        for parameter in parameters:

            total_injection_points += 1


            print(
                f"[PARAMETER] {parameter}"
            )

            # -----------------------------------------------------
            # Phase 2.1 context probe
            # -----------------------------------------------------

            context_probe = probe_url_parameter_context(
                current_url,
                parameter
            )

            print(
                f"[CONTEXT] "
                f"{context_probe.get('context', 'unknown')}"
            )

            print(
                f"Context Probe : "
                f"{context_probe.get('found', False)}"
            )

            print(
                f"Context Reason : "
                f"{context_probe.get('reason', '')}"
            )


            selected_payloads = get_context_payloads(
                context_probe.get(
                    "context",
                    "unknown"
                ),
                payload_limit
            )

            print(
                f"Payloads Selected : "
                f"{len(selected_payloads)}"
            )

            payload_categories = ContextPayloadSelector.get_categories(
                context_probe.get(
                    "context",
                    "unknown"
                )
            )

            print(
                f"Payload Categories : "
                f"{payload_categories}"
            )



            # -----------------------------------------------------
            # Test every payload
            # -----------------------------------------------------

            for payload in selected_payloads:

                payloads_tested += 1


                # -------------------------------------------------
                # Inject into ONLY this parameter
                # -------------------------------------------------

                response, test_url = (
                    URLScanner.scan_parameter(
                        current_url,
                        parameter,
                        payload
                    )
                )


                # -------------------------------------------------
                # Analyze HTTP response
                # -------------------------------------------------

                analysis = XSSDetector.analyze(
                    response,
                    payload
                )

                analysis = merge_context_probe(
                    analysis,
                    context_probe
                )


                # -------------------------------------------------
                # Potential XSS
                # -------------------------------------------------

                if analysis[
                    "potential_xss"
                ]:

                    # ---------------------------------------------
                    # Phase 6 - Risk-based severity
                    # ---------------------------------------------

                    severity = calculate_severity(
                        current_url,
                        analysis
                    )


                    # ---------------------------------------------
                    # Store finding
                    # ---------------------------------------------

                    reporter.add_finding(
                        current_url,
                        payload,
                        "URL_PARAMETER",
                        "Reflected XSS",
                        severity,
                        analysis,
                        parameter=parameter
                    )


                    # ---------------------------------------------
                    # Terminal output
                    # ---------------------------------------------

                    print(
                        f"[POTENTIAL XSS] "
                        f"{current_url}"
                    )


                    print(
                        f"Parameter : "
                        f"{parameter}"
                    )


                    print(
                        f"Payload : "
                        f"{payload}"
                    )


                    print(
                        f"Severity : "
                        f"{severity}"
                    )


                    print(
                        f"Context : "
                        f"{analysis['context']}"
                    )

                    print(
                        f"Context Probe : "
                        f"{analysis.get('context_probe', False)}"
                    )


                    print(
                        f"Confidence : "
                        f"{analysis['confidence']}"
                    )


                    print(
                        f"Reason : "
                        f"{analysis['reason']}"
                    )


    # =============================================================
    # FORM SCANNING
    # =============================================================

    forms = crawler.get_forms(
        current_url
    )


    total_forms += len(
        forms
    )


    print(
        f"[+] Found "
        f"{len(forms)} forms"
    )


    # -------------------------------------------------------------
    # Process every form
    # -------------------------------------------------------------

    for form in forms:

        form_details = crawler.get_form_details(
            form
        )


        # ---------------------------------------------------------
        # Get form inputs
        # ---------------------------------------------------------

        form_inputs = form_details.get(
            "inputs",
            []
        )


        print(
            f"[+] Form inputs: "
            f"{len(form_inputs)}"
        )


        # ---------------------------------------------------------
        # Every input = separate injection point
        # ---------------------------------------------------------

        for input_tag in form_inputs:

            input_name = input_tag.get(
                "name"
            )


            # Ignore unnamed inputs

            if not input_name:

                continue


            total_injection_points += 1


            print(
                f"[INPUT] {input_name}"
            )

            # -----------------------------------------------------
            # Phase 2.1 context probe
            # -----------------------------------------------------

            context_probe = probe_form_input_context(
                form_details,
                current_url,
                input_name
            )

            print(
                f"[CONTEXT] "
                f"{context_probe.get('context', 'unknown')}"
            )

            print(
                f"Context Probe : "
                f"{context_probe.get('found', False)}"
            )

            print(
                f"Context Reason : "
                f"{context_probe.get('reason', '')}"
            )


            selected_payloads = get_context_payloads(
                context_probe.get(
                    "context",
                    "unknown"
                ),
                payload_limit
            )

            print(
                f"Payloads Selected : "
                f"{len(selected_payloads)}"
            )

            payload_categories = ContextPayloadSelector.get_categories(
                context_probe.get(
                    "context",
                    "unknown"
                )
            )

            print(
                f"Payload Categories : "
                f"{payload_categories}"
            )



            # -----------------------------------------------------
            # Test every payload
            # -----------------------------------------------------

            for payload in selected_payloads:

                payloads_tested += 1


                # -------------------------------------------------
                # Inject into ONLY this input
                # -------------------------------------------------

                response = injector.submit_input(
                    form_details,
                    current_url,
                    input_name,
                    payload
                )


                # -------------------------------------------------
                # Analyze HTTP response
                # -------------------------------------------------

                analysis = XSSDetector.analyze(
                    response,
                    payload
                )

                analysis = merge_context_probe(
                    analysis,
                    context_probe
                )


                # -------------------------------------------------
                # Potential XSS
                # -------------------------------------------------

                if analysis[
                    "potential_xss"
                ]:

                    # ---------------------------------------------
                    # Phase 6 - Risk-based severity
                    # ---------------------------------------------

                    severity = calculate_severity(
                        current_url,
                        analysis
                    )


                    # ---------------------------------------------
                    # Store finding
                    # ---------------------------------------------

                    reporter.add_finding(
                        current_url,
                        payload,
                        form_details["method"],
                        "Reflected XSS",
                        severity,
                        analysis,
                        parameter=input_name
                    )


                    # ---------------------------------------------
                    # Terminal output
                    # ---------------------------------------------

                    print(
                        "[POTENTIAL XSS]"
                    )


                    print(
                        f"Input : "
                        f"{input_name}"
                    )


                    print(
                        f"Payload : "
                        f"{payload}"
                    )


                    print(
                        f"Severity : "
                        f"{severity}"
                    )


                    print(
                        f"Method : "
                        f"{form_details['method']}"
                    )


                    print(
                        f"Context : "
                        f"{analysis['context']}"
                    )

                    print(
                        f"Context Probe : "
                        f"{analysis.get('context_probe', False)}"
                    )


                    print(
                        f"Confidence : "
                        f"{analysis['confidence']}"
                    )


                    print(
                        f"Reason : "
                        f"{analysis['reason']}\n"
                    )


# =================================================================
# BROWSER VERIFICATION
# =================================================================
#
# IMPORTANT:
#
# We do NOT run Selenium for every payload-level reflection.
#
# Example:
#
# 60 payloads
#       ↓
# 50 payloads reflected at /search?q
#       ↓
# Reporter deduplicates them
#       ↓
# ONE unique finding
#       ↓
# Browser verifies one representative payload
#
# This makes browser verification much faster.
# =================================================================


print(
    "\n========================================"
)


print(
    "        BROWSER VERIFICATION"
)


print(
    "========================================"
)


browser_scanner = None


try:

    unique_findings = reporter.findings


    print(
        f"[+] Potential unique findings: "
        f"{len(unique_findings)}"
    )


    if unique_findings:

        # ---------------------------------------------------------
        # Start Selenium only when there are findings
        # ---------------------------------------------------------

        browser_scanner = BrowserScanner()


        # ---------------------------------------------------------
        # Verify each unique injection point
        # ---------------------------------------------------------

        for index, finding in enumerate(
            unique_findings,
            start=1
        ):

            url = finding.get(
                "url"
            )


            parameter = finding.get(
                "parameter"
            )


            method = finding.get(
                "method"
            )


            successful_payloads = finding.get(
                "successful_payloads",
                []
            )


            if not successful_payloads:

                print(
                    f"[{index}] Skipping "
                    f"{parameter} - "
                    f"no successful payload available"
                )

                continue


            # -----------------------------------------------------
            # Use one representative payload
            # -----------------------------------------------------

            verification_payload = (
                successful_payloads[0]
            )


            print(
                f"\n[VERIFYING {index}/"
                f"{len(unique_findings)}]"
            )


            print(
                f"URL : {url}"
            )


            print(
                f"Parameter : {parameter}"
            )


            print(
                f"Payload : "
                f"{verification_payload}"
            )


            # =====================================================
            # URL PARAMETER
            # =====================================================

            if method == "URL_PARAMETER":

                verification = (
                    browser_scanner.test_url_parameter(
                        url,
                        parameter,
                        verification_payload
                    )
                )


                reporter.update_verification(
                    url,
                    parameter,
                    method,
                    verification_payload,
                    verification
                )


            # =====================================================
            # FORM INPUT
            # =====================================================

            else:

                # -------------------------------------------------
                # Find the original form again
                # -------------------------------------------------

                page_forms = crawler.get_forms(
                    url
                )


                matching_form = None


                for form in page_forms:

                    details = (
                        crawler.get_form_details(
                            form
                        )
                    )


                    form_inputs = details.get(
                        "inputs",
                        []
                    )


                    input_names = [

                        input_tag.get(
                            "name"
                        )

                        for input_tag
                        in form_inputs

                        if input_tag.get(
                            "name"
                        )

                    ]


                    if parameter in input_names:

                        # Match method as well

                        if (
                            details.get(
                                "method",
                                "get"
                            ).lower()
                            ==
                            str(method).lower()
                        ):

                            matching_form = details

                            break


                # -------------------------------------------------
                # Form could not be reconstructed
                # -------------------------------------------------

                if matching_form is None:

                    verification = {

                        "verified": False,

                        "alert": False,

                        "alert_text": None,

                        "reason": (
                            "Could not reconstruct "
                            "the original form for "
                            "browser verification"
                        )

                    }


                else:

                    verification = (
                        browser_scanner.test_form_input(
                            url,
                            matching_form,
                            parameter,
                            verification_payload
                        )
                    )


                reporter.update_verification(
                    url,
                    parameter,
                    method,
                    verification_payload,
                    verification
                )


            # -----------------------------------------------------
            # Print verification result
            # -----------------------------------------------------

            if verification.get(
                "verified",
                False
            ):

                print(
                    "[CONFIRMED XSS]"
                )


                print(
                    "JavaScript execution "
                    "was detected by the browser."
                )


                if verification.get(
                    "alert_text"
                ) is not None:

                    print(
                        f"Alert : "
                        f"{verification['alert_text']}"
                    )


            else:

                print(
                    "[NOT CONFIRMED]"
                )


                print(
                    f"Reason : "
                    f"{verification.get('reason', '')}"
                )


except Exception as error:

    print(
        "\n[!] Browser verification "
        f"encountered an error: {error}"
    )


finally:

    if browser_scanner is not None:

        browser_scanner.close()


# =================================================================
# SCAN FINISHED
# =================================================================

scan_end_time = datetime.now()


# =================================================================
# FINAL STATISTICS
# =================================================================

statistics = reporter.get_statistics(
    payloads_tested
)


# =================================================================
# SCAN SUMMARY
# =================================================================

print(
    "\n========================================"
)


print(
    "             SCAN SUMMARY"
)


print(
    "========================================"
)


print(
    f"Links Found        : "
    f"{len(links)}"
)


print(
    f"Forms Found        : "
    f"{total_forms}"
)


print(
    f"Injection Points   : "
    f"{total_injection_points}"
)


print(
    f"Payload Library    : "
    f"{len(Payloads.PAYLOADS)}"
)

print(
    f"Payload Limit (--p): "
    f"{payload_limit}"
)


print(
    f"Payload Tests      : "
    f"{payloads_tested}"
)


print(
    f"Payload Reflections: "
    f"{reporter.payload_reflections}"
)


print(
    f"Unique Findings    : "
    f"{len(reporter.findings)}"
)


print(
    f"Confirmed XSS      : "
    f"{statistics['confirmed']}"
)


print(
    f"Not Confirmed      : "
    f"{statistics['not_confirmed']}"
)


print(
    f"Not Tested         : "
    f"{statistics['not_tested']}"
)


print(
    "========================================\n"
)


# =================================================================
# SAVE JSON REPORT
# =================================================================

reporter.save_json()


# =================================================================
# GENERATE HTML REPORT
# =================================================================

HTMLReporter.generate(
    findings=reporter.findings,
    target_url=target_url,
    links_found=len(links),
    forms_found=total_forms,
    payload_library=len(payloads),
    injection_points=total_injection_points,
    payloads_tested=payloads_tested,
    scan_start_time=scan_start_time,
    scan_end_time=scan_end_time
)


# =================================================================
# CLOSE TERMINAL LOG
# =================================================================
#
# Restore normal stdout/stderr before closing the log file.
# =================================================================

terminal_log.flush()


sys.stdout = original_stdout

sys.stderr = original_stderr


terminal_log.close()