import json
import os


# ============================================================
# ShadowXSS - Phase 7
# Report Integrity Regression Test
# ============================================================


REPORT_FILE = "report.json"


REQUIRED_FIELDS = [

    "url",
    "parameter",
    "payload",
    "method",
    "type",
    "severity",
    "reflected",
    "encoded",
    "reflection_type",
    "context",
    "potential_xss",
    "confidence",
    "reason",
    "evidence",
    "browser_verified",
    "confirmed_xss",
    "verification",
    "verification_reason",
    "alert_text",
]


# ============================================================
# LOAD REPORT
# ============================================================


def load_report():

    if not os.path.exists(REPORT_FILE):

        print(
            f"[ERROR] {REPORT_FILE} not found."
        )

        return None

    try:

        with open(
            REPORT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        print(
            f"[ERROR] Failed to read report: {error}"
        )

        return None


# ============================================================
# REPORT STRUCTURE TEST
# ============================================================


def test_report_structure():

    report = load_report()

    if report is None:

        return False


    findings = report.get(
        "findings"
    )


    if not isinstance(
        findings,
        list
    ):

        print(
            "[FAIL] findings is not a list."
        )

        return False


    if len(findings) == 0:

        print(
            "[FAIL] No findings found in report."
        )

        return False


    finding = findings[0]


    passed = 0
    failed = 0


    print("\n" + "=" * 70)
    print("REPORT FIELD INTEGRITY")
    print("=" * 70)


    for field in REQUIRED_FIELDS:

        exists = field in finding

        has_value = (
            finding.get(field) is not None
        )


        result = (
            exists
            and
            has_value
        )


        print(
            f"{field:<24}: "
            f"{'PASS' if result else 'FAIL'}"
        )


        if result:

            passed += 1

        else:

            failed += 1


    print(
        f"\nFields passed : "
        f"{passed}/{len(REQUIRED_FIELDS)}"
    )

    print(
        f"Fields failed : "
        f"{failed}/{len(REQUIRED_FIELDS)}"
    )


    return failed == 0


# ============================================================
# CONFIRMED FINDING STATE
# ============================================================


def test_confirmed_finding_state():

    report = load_report()

    if report is None:

        return False


    findings = report.get(
        "findings",
        []
    )


    if not findings:

        return False


    finding = findings[0]


    checks = {

        "potential_xss":
            finding.get(
                "potential_xss"
            ) is True,

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

        "severity":
            finding.get(
                "severity"
            )
            in
            {
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            },

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
                )
                >
                0
            ),

        "verification_reason":
            bool(
                finding.get(
                    "verification_reason"
                )
            ),

        "alert_text":
            finding.get(
                "alert_text"
            )
            is not None,

    }


    print("\n" + "=" * 70)
    print("CONFIRMED FINDING STATE")
    print("=" * 70)


    passed = 0
    failed = 0


    for name, result in checks.items():

        print(
            f"{name:<24}: "
            f"{'PASS' if result else 'FAIL'}"
        )


        if result:

            passed += 1

        else:

            failed += 1


    print(
        f"\nState checks passed : "
        f"{passed}/{len(checks)}"
    )

    print(
        f"State checks failed : "
        f"{failed}/{len(checks)}"
    )


    return failed == 0


# ============================================================
# SUCCESSFUL PAYLOAD CONSISTENCY
# ============================================================


def test_successful_payload_consistency():

    report = load_report()

    if report is None:

        return False


    findings = report.get(
        "findings",
        []
    )


    if not findings:

        return False


    finding = findings[0]


    payload = finding.get(
        "payload"
    )


    successful_payloads = finding.get(
        "successful_payloads",
        []
    )


    result = (

        isinstance(
            successful_payloads,
            list
        )

        and

        payload in successful_payloads

    )


    print("\n" + "=" * 70)
    print("SUCCESSFUL PAYLOAD CONSISTENCY")
    print("=" * 70)


    print(
        f"Payload present        : "
        f"{'PASS' if payload else 'FAIL'}"
    )

    print(
        f"Successful payload list: "
        f"{'PASS' if isinstance(successful_payloads, list) else 'FAIL'}"
    )

    print(
        f"Payload membership     : "
        f"{'PASS' if payload in successful_payloads else 'FAIL'}"
    )

    print(
        f"Result                 : "
        f"{'PASS' if result else 'FAIL'}"
    )


    return result


# ============================================================
# MAIN
# ============================================================


def main():

    print("=" * 70)
    print("ShadowXSS - Phase 7")
    print("Report Integrity Regression Test")
    print("=" * 70)


    structure_pass = (
        test_report_structure()
    )


    state_pass = (
        test_confirmed_finding_state()
    )


    payload_pass = (
        test_successful_payload_consistency()
    )


    total = 3


    passed = sum(
        [
            structure_pass,
            state_pass,
            payload_pass
        ]
    )


    failed = (
        total
        -
        passed
    )


    print("\n" + "=" * 70)
    print("PHASE 7 REPORT INTEGRITY SUMMARY")
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
            "\nPhase 7 Report Integrity: PASS"
        )

        return 0


    print(
        "\nPhase 7 Report Integrity: FAIL"
    )

    return 1


# ============================================================
# ENTRY POINT
# ============================================================


if __name__ == "__main__":

    raise SystemExit(
        main()
    )