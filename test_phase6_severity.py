from core.reporter import Reporter


# ============================================================
# ShadowXSS - Phase 6
# Severity + Confidence + Evidence Regression Test
# ============================================================


TEST_URL = "http://127.0.0.1:5000/test"
TEST_PARAMETER = "q"
TEST_METHOD = "URL_PARAMETER"
TEST_PAYLOAD = "<script>alert(1)</script>"


# ============================================================
# TEST FINDING FACTORY
# ============================================================


def create_reporter_with_finding(
    severity,
    confidence="medium"
):

    reporter = Reporter()

    reporter.add_finding(
        url=TEST_URL,
        payload=TEST_PAYLOAD,
        method=TEST_METHOD,
        xss_type="Reflected XSS",
        severity=severity,
        analysis={
            "reflected": True,
            "encoded": False,
            "reflection_type": "exact",
            "context": "HTML text",
            "potential_xss": True,
            "confidence": confidence,
            "reason": "Test finding",
            "evidence": "Test evidence"
        },
        parameter=TEST_PARAMETER
    )

    return reporter


# ============================================================
# GET FINDING
# ============================================================


def get_finding(
    reporter
):

    return reporter.findings[0]


# ============================================================
# APPLY BROWSER VERIFICATION
# ============================================================


def verify_finding(
    reporter,
    verified
):

    return reporter.update_verification(

        TEST_URL,

        TEST_PARAMETER,

        TEST_METHOD,

        TEST_PAYLOAD,

        {
            "verified": verified,

            "alert_text":
                "1"
                if verified
                else None,

            "reason":
                (
                    "Browser detected a JavaScript alert "
                    "after payload execution"
                    if verified
                    else
                    "Payload was executed in the browser "
                    "but no JavaScript alert was detected"
                )
        }
    )


# ============================================================
# CONFIRMED SEVERITY ESCALATION
# ============================================================


def test_confirmed_severity_escalation():

    test_cases = [

        ("LOW", "MEDIUM"),

        ("MEDIUM", "HIGH"),

        ("HIGH", "CRITICAL"),

        ("CRITICAL", "CRITICAL"),

    ]

    passed = 0
    failed = 0

    print("=" * 70)
    print("ShadowXSS - Phase 6")
    print("Severity + Confidence + Evidence Regression Test")
    print("=" * 70)

    print("\n" + "=" * 70)
    print("CONFIRMED SEVERITY ESCALATION")
    print("=" * 70)

    for initial, expected in test_cases:

        reporter = create_reporter_with_finding(
            initial,
            "medium"
        )

        updated = verify_finding(
            reporter,
            True
        )

        finding = get_finding(
            reporter
        )

        actual_severity = finding.get(
            "severity"
        )

        actual_confidence = finding.get(
            "confidence"
        )

        result = (

            updated

            and

            actual_severity == expected

            and

            actual_confidence == "medium"

            and

            finding.get(
                "browser_verified"
            ) is True

            and

            finding.get(
                "confirmed_xss"
            ) is True

        )

        print("\n" + "-" * 70)

        print(
            f"Initial severity    : {initial}"
        )

        print(
            f"Expected severity   : {expected}"
        )

        print(
            f"Actual severity     : {actual_severity}"
        )

        print(
            f"Confidence          : {actual_confidence}"
        )

        print(
            f"Browser verified    : "
            f"{finding.get('browser_verified')}"
        )

        print(
            f"Confirmed XSS       : "
            f"{finding.get('confirmed_xss')}"
        )

        print(
            f"Verification        : "
            f"{finding.get('verification')}"
        )

        print(
            f"Result              : "
            f"{'PASS' if result else 'FAIL'}"
        )

        if result:

            passed += 1

        else:

            failed += 1

    return passed, failed


# ============================================================
# UNCONFIRMED SEVERITY + CONFIDENCE PRESERVATION
# ============================================================


def test_unconfirmed_preservation():

    initial_severity = "MEDIUM"

    initial_confidence = "medium"

    reporter = create_reporter_with_finding(

        initial_severity,

        initial_confidence

    )

    updated = verify_finding(

        reporter,

        False

    )

    finding = get_finding(
        reporter
    )

    actual_severity = finding.get(
        "severity"
    )

    actual_confidence = finding.get(
        "confidence"
    )

    result = (

        updated

        and

        actual_severity == initial_severity

        and

        actual_confidence == initial_confidence

        and

        finding.get(
            "browser_verified"
        ) is False

        and

        finding.get(
            "confirmed_xss"
        ) is False

        and

        finding.get(
            "verification"
        )
        ==
        "NOT_CONFIRMED"

    )

    print("\n" + "=" * 70)
    print("UNCONFIRMED FINDING PRESERVATION")
    print("=" * 70)

    print(
        f"Initial severity    : "
        f"{initial_severity}"
    )

    print(
        f"Final severity      : "
        f"{actual_severity}"
    )

    print(
        f"Initial confidence  : "
        f"{initial_confidence}"
    )

    print(
        f"Final confidence    : "
        f"{actual_confidence}"
    )

    print(
        f"Browser verified    : "
        f"{finding.get('browser_verified')}"
    )

    print(
        f"Confirmed XSS       : "
        f"{finding.get('confirmed_xss')}"
    )

    print(
        f"Verification        : "
        f"{finding.get('verification')}"
    )

    print(
        f"Result              : "
        f"{'PASS' if result else 'FAIL'}"
    )

    return 1 if result else 0


# ============================================================
# CONFIRMED HIGH-CONFIDENCE PRESERVATION
# ============================================================


def test_high_confidence_preservation():

    initial_severity = "MEDIUM"

    initial_confidence = "high"

    reporter = create_reporter_with_finding(

        initial_severity,

        initial_confidence

    )

    updated = verify_finding(

        reporter,

        True

    )

    finding = get_finding(
        reporter
    )

    actual_severity = finding.get(
        "severity"
    )

    actual_confidence = finding.get(
        "confidence"
    )

    result = (

        updated

        and

        actual_severity == "HIGH"

        and

        actual_confidence == initial_confidence

        and

        finding.get(
            "browser_verified"
        ) is True

        and

        finding.get(
            "confirmed_xss"
        ) is True

    )

    print("\n" + "=" * 70)
    print("HIGH-CONFIDENCE PRESERVATION")
    print("=" * 70)

    print(
        f"Initial severity    : "
        f"{initial_severity}"
    )

    print(
        f"Final severity      : "
        f"{actual_severity}"
    )

    print(
        f"Initial confidence  : "
        f"{initial_confidence}"
    )

    print(
        f"Final confidence    : "
        f"{actual_confidence}"
    )

    print(
        f"Browser verified    : "
        f"{finding.get('browser_verified')}"
    )

    print(
        f"Confirmed XSS       : "
        f"{finding.get('confirmed_xss')}"
    )

    print(
        f"Result              : "
        f"{'PASS' if result else 'FAIL'}"
    )

    return 1 if result else 0


# ============================================================
# CONFIRMED EVIDENCE CHAIN
# ============================================================


def test_confirmed_evidence_chain():

    reporter = create_reporter_with_finding(

        "MEDIUM",

        "medium"

    )

    updated = verify_finding(

        reporter,

        True

    )

    finding = get_finding(
        reporter
    )

    checks = {

        "payload":
            bool(
                finding.get(
                    "payload"
                )
            ),

        "reflected":
            finding.get(
                "reflected"
            ) is True,

        "reflection_type":
            bool(
                finding.get(
                    "reflection_type"
                )
            ),

        "context":
            bool(
                finding.get(
                    "context"
                )
            ),

        "potential_xss":
            finding.get(
                "potential_xss"
            ) is True,

        "confidence":
            bool(
                finding.get(
                    "confidence"
                )
            ),

        "reason":
            bool(
                finding.get(
                    "reason"
                )
            ),

        "evidence":
            bool(
                finding.get(
                    "evidence"
                )
            ),

        "successful_payloads":
            (
                isinstance(
                    finding.get(
                        "successful_payloads"
                    ),
                    list
                )

                and

                len(
                    finding.get(
                        "successful_payloads"
                    )
                ) > 0
            ),

        "browser_verified":
            finding.get(
                "browser_verified"
            ) is True,

        "confirmed_xss":
            finding.get(
                "confirmed_xss"
            ) is True,

        "verification":
            finding.get(
                "verification"
            )
            ==
            "CONFIRMED",

        "verification_reason":
            bool(
                finding.get(
                    "verification_reason"
                )
            ),

        "alert_text":
            finding.get(
                "alert_text"
            ) is not None

    }


    passed = sum(

        1

        for result in checks.values()

        if result

    )


    failed = (
        len(checks)
        -
        passed
    )


    overall = (

        updated

        and

        failed == 0

    )


    print("\n" + "=" * 70)
    print("CONFIRMED EVIDENCE CHAIN")
    print("=" * 70)


    for field, result in checks.items():

        print(
            f"{field:<22}: "
            f"{'PASS' if result else 'FAIL'}"
        )


    print(
        f"\nEvidence fields passed : "
        f"{passed}/{len(checks)}"
    )

    print(
        f"Evidence fields failed : "
        f"{failed}/{len(checks)}"
    )

    print(
        f"Evidence chain result  : "
        f"{'PASS' if overall else 'FAIL'}"
    )


    return 1 if overall else 0


# ============================================================
# MAIN
# ============================================================


def main():

    passed, failed = (
        test_confirmed_severity_escalation()
    )


    unconfirmed_passed = (
        test_unconfirmed_preservation()
    )


    high_confidence_passed = (
        test_high_confidence_preservation()
    )


    evidence_passed = (
        test_confirmed_evidence_chain()
    )


    passed += unconfirmed_passed

    passed += high_confidence_passed

    passed += evidence_passed


    total = (
        passed
        +
        failed
    )


    print("\n" + "=" * 70)
    print(
        "PHASE 6 SEVERITY + CONFIDENCE + "
        "EVIDENCE SUMMARY"
    )
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
            "\nPhase 6 Severity + Confidence + "
            "Evidence: PASS"
        )

        return 0


    print(
        "\nPhase 6 Severity + Confidence + "
        "Evidence: FAIL"
    )

    return 1


# ============================================================
# ENTRY POINT
# ============================================================


if __name__ == "__main__":

    raise SystemExit(
        main()
    )