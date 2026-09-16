import json
import os
import html


# ============================================================
# ShadowXSS - Phase 7.1
# HTML Report Integrity Regression Test
# ============================================================


REPORT_JSON = "report.json"
REPORT_HTML = "report.html"


# ============================================================
# LOAD JSON REPORT
# ============================================================


def load_json_report():

    if not os.path.exists(REPORT_JSON):

        print(
            f"[ERROR] {REPORT_JSON} not found."
        )

        return None

    try:

        with open(
            REPORT_JSON,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        print(
            f"[ERROR] Failed to read JSON report: {error}"
        )

        return None


# ============================================================
# LOAD HTML REPORT
# ============================================================


def load_html_report():

    if not os.path.exists(REPORT_HTML):

        print(
            f"[ERROR] {REPORT_HTML} not found."
        )

        return None

    try:

        with open(
            REPORT_HTML,
            "r",
            encoding="utf-8"
        ) as file:

            return file.read()

    except Exception as error:

        print(
            f"[ERROR] Failed to read HTML report: {error}"
        )

        return None


# ============================================================
# TEST HTML REPORT EXISTS
# ============================================================


def test_html_report_exists():

    result = os.path.isfile(
        REPORT_HTML
    )

    print("\n" + "=" * 70)
    print("HTML REPORT EXISTENCE")
    print("=" * 70)

    print(
        f"report.html exists : "
        f"{'PASS' if result else 'FAIL'}"
    )

    return result


# ============================================================
# TEST HTML CONTAINS FINAL FINDING STATE
# ============================================================


def test_html_finding_state():

    report = load_json_report()

    html_report = load_html_report()


    if report is None or html_report is None:

        return False


    findings = report.get(
        "findings",
        []
    )


    if not findings:

        print(
            "[FAIL] No findings available in report.json."
        )

        return False


    finding = findings[0]


    # --------------------------------------------------------
    # Values taken directly from report.json
    # --------------------------------------------------------

    severity = str(
        finding.get(
            "severity",
            ""
        )
    )

    confidence = str(
        finding.get(
            "confidence",
            ""
        )
    )

    payload = str(
        finding.get(
            "payload",
            ""
        )
    )

    context = str(
        finding.get(
            "context",
            ""
        )
    )

    verification = str(
        finding.get(
            "verification",
            ""
        )
    )

    verification_reason = str(
        finding.get(
            "verification_reason",
            ""
        )
    )

    alert_text = finding.get(
        "alert_text"
    )


    # --------------------------------------------------------
    # HTML escaping
    # --------------------------------------------------------

    escaped_payload = html.escape(
        payload
    )

    escaped_reason = html.escape(
        verification_reason
    )

    escaped_alert = (
        html.escape(
            str(alert_text)
        )
        if alert_text is not None
        else ""
    )


    # --------------------------------------------------------
    # Required HTML values
    # --------------------------------------------------------

    checks = {

        "Reflected XSS":
            "Reflected XSS"
            in html_report,

        "severity":
            severity
            in html_report,

        "confidence":
            confidence
            in html_report,

        "context":
            context
            in html_report,

        "potential_xss":
            "potential_xss=True"
            in html_report,

        "browser_verified":
            "browser_verified=True"
            in html_report,

        "confirmed_xss":
            "confirmed_xss=True"
            in html_report,

        "verification":
            (
                f"verification={verification}"
                in html_report
            ),

        "successful_payload":
            (
                escaped_payload
                in html_report
                or
                payload
                in html_report
            ),

        "verification_reason":
            (
                escaped_reason
                in html_report
                or
                verification_reason
                in html_report
            ),

        "alert_text":
            (
                escaped_alert
                in html_report
                or
                str(alert_text)
                in html_report
            ),

    }


    print("\n" + "=" * 70)
    print("HTML FINDING STATE INTEGRITY")
    print("=" * 70)


    passed = 0
    failed = 0


    for field, result in checks.items():

        print(
            f"{field:<24}: "
            f"{'PASS' if result else 'FAIL'}"
        )

        if result:

            passed += 1

        else:

            failed += 1


    print(
        f"\nHTML checks passed : "
        f"{passed}/{len(checks)}"
    )

    print(
        f"HTML checks failed : "
        f"{failed}/{len(checks)}"
    )


    return failed == 0


# ============================================================
# TEST CONFIRMED STATUS CONSISTENCY
# ============================================================


def test_confirmation_consistency():

    report = load_json_report()

    html_report = load_html_report()


    if report is None or html_report is None:

        return False


    findings = report.get(
        "findings",
        []
    )


    if not findings:

        return False


    finding = findings[0]


    json_confirmed = (
        finding.get(
            "confirmed_xss"
        )
        is True
    )

    json_verified = (
        finding.get(
            "browser_verified"
        )
        is True
    )

    json_verification = (
        finding.get(
            "verification"
        )
        ==
        "CONFIRMED"
    )


    html_confirmed = (
        "data-confirmed-xss=\"True\""
        in html_report
    )

    html_verified = (
        "data-browser-verified=\"True\""
        in html_report
    )

    html_verification = (
        "data-verification=\"CONFIRMED\""
        in html_report
    )


    checks = {

        "JSON confirmed_xss":
            json_confirmed,

        "HTML confirmed_xss":
            html_confirmed,

        "JSON browser_verified":
            json_verified,

        "HTML browser_verified":
            html_verified,

        "JSON verification":
            json_verification,

        "HTML verification":
            html_verification,

    }


    print("\n" + "=" * 70)
    print("JSON ↔ HTML CONFIRMATION CONSISTENCY")
    print("=" * 70)


    passed = 0
    failed = 0


    for name, result in checks.items():

        print(
            f"{name:<28}: "
            f"{'PASS' if result else 'FAIL'}"
        )

        if result:

            passed += 1

        else:

            failed += 1


    print(
        f"\nConsistency checks passed : "
        f"{passed}/{len(checks)}"
    )

    print(
        f"Consistency checks failed : "
        f"{failed}/{len(checks)}"
    )


    return failed == 0


# ============================================================
# MAIN
# ============================================================


def main():

    print("=" * 70)
    print("ShadowXSS - Phase 7.1")
    print("HTML Report Integrity Regression Test")
    print("=" * 70)


    exists_pass = (
        test_html_report_exists()
    )


    state_pass = (
        test_html_finding_state()
    )


    consistency_pass = (
        test_confirmation_consistency()
    )


    total = 3


    passed = sum(
        [
            exists_pass,
            state_pass,
            consistency_pass
        ]
    )


    failed = (
        total
        -
        passed
    )


    print("\n" + "=" * 70)
    print("PHASE 7.1 HTML REPORT SUMMARY")
    print("=" * 70)


    print(
        f"Total tests : {total}"
    )

    print(
        f"Passed      : {passed}"
    )

    print(
        f"Failed      : {failed}"
    )


    if failed == 0:

        print(
            "\nPhase 7.1 HTML Report Integrity: PASS"
        )

        return 0


    print(
        "\nPhase 7.1 HTML Report Integrity: FAIL"
    )

    return 1


# ============================================================
# ENTRY POINT
# ============================================================


if __name__ == "__main__":

    raise SystemExit(
        main()
    )