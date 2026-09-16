import json
import os
import subprocess
import sys
from urllib.parse import urlparse


# ================================================================
# PATHS
# ================================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

CASES_FILE = os.path.join(
    BASE_DIR,
    "tests",
    "accuracy_cases.json"
)

REPORT_FILE = os.path.join(
    BASE_DIR,
    "report.json"
)

ACCURACY_REPORT_FILE = os.path.join(
    BASE_DIR,
    "accuracy_report.json"
)


# ================================================================
# LOAD CASES
# ================================================================

def load_cases():

    if not os.path.exists(CASES_FILE):

        print(
            "[ERROR] accuracy_cases.json not found."
        )

        return []

    try:

        with open(
            CASES_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

    except Exception as error:

        print(
            f"[ERROR] Failed to load accuracy cases: {error}"
        )

        return []

    if not isinstance(data, list):

        print(
            "[ERROR] accuracy_cases.json must contain a list."
        )

        return []

    return data


# ================================================================
# LOAD REPORT
# ================================================================

def load_report():

    if not os.path.exists(REPORT_FILE):

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
            f"[ERROR] Failed to read report.json: {error}"
        )

        return None


# ================================================================
# GET FINDINGS
# ================================================================

def get_findings(report):

    if isinstance(report, list):

        return report

    if isinstance(report, dict):

        for key in (
            "findings",
            "results",
            "vulnerabilities",
            "issues"
        ):

            value = report.get(key)

            if isinstance(value, list):

                return value

    return []


# ================================================================
# GET URL PATH
# ================================================================

def get_path(url):

    try:

        parsed = urlparse(
            str(url)
        )

        path = parsed.path

        if not path:

            return "/"

        return path.rstrip("/") or "/"

    except Exception:

        return ""


# ================================================================
# MATCH FINDING TO TEST CASE
# ================================================================

def finding_matches(
    finding,
    case
):

    finding_path = get_path(
        finding.get(
            "url",
            ""
        )
    )

    case_path = get_path(
        case.get(
            "url",
            ""
        )
    )

    finding_parameter = str(
        finding.get(
            "parameter",
            ""
        )
    ).strip()

    case_parameter = str(
        case.get(
            "parameter",
            ""
        )
    ).strip()

    return (
        finding_path == case_path
        and
        finding_parameter == case_parameter
    )


# ================================================================
# RUN SHADOWXSS
# ================================================================

def run_scanner(case):

    print(
        "\n[+] Running ShadowXSS..."
    )

    try:

        result = subprocess.run(
            [
                sys.executable,
                os.path.join(
                    BASE_DIR,
                    "main.py"
                ),
                "--url",
                case["url"],
                "--p",
                "1"
            ],
            cwd=BASE_DIR,
            capture_output=True,
            text=True
        )

    except Exception as error:

        print(
            f"[ERROR] Scanner execution failed: {error}"
        )

        return False

    if result.returncode != 0:

        print(
            "[ERROR] ShadowXSS returned an error."
        )

        if result.stderr:

            print(result.stderr)

        return False

    return True


# ================================================================
# EVALUATE CASE
# ================================================================

def evaluate_case(case):

    print(
        "\n" + "=" * 70
    )

    print(
        f"Case : {case.get('id', 'UNKNOWN')}"
    )

    print(
        f"Name : {case.get('name', '')}"
    )

    print(
        f"URL  : {case.get('url', '')}"
    )

    print(
        f"Parameter : {case.get('parameter', '')}"
    )

    ground_truth = str(
        case.get(
            "ground_truth",
            ""
        )
    ).strip().upper()

    if ground_truth not in (
        "VULNERABLE",
        "SAFE"
    ):

        print(
            "[ERROR] Invalid ground_truth."
        )

        return None

    expected_vulnerable = (
        ground_truth == "VULNERABLE"
    )

    expected_confirmation = bool(
        case.get(
            "expected_confirmation",
            False
        )
    )

    print(
        f"Ground Truth       : {ground_truth}"
    )

    print(
        f"Expected Confirmed : {expected_confirmation}"
    )

    # ------------------------------------------------------------
    # Run scanner
    # ------------------------------------------------------------

    if not run_scanner(case):

        return None

    # ------------------------------------------------------------
    # Load report
    # ------------------------------------------------------------

    report = load_report()

    if report is None:

        print(
            "[ERROR] report.json was not generated."
        )

        return None

    findings = get_findings(
        report
    )

    matching_findings = [

        finding

        for finding in findings

        if finding_matches(
            finding,
            case
        )

    ]

    # ------------------------------------------------------------
    # Detection result
    #
    # IMPORTANT:
    #
    # TP/TN/FP/FN are based on potential_xss.
    #
    # Browser confirmation is measured separately.
    # ------------------------------------------------------------

    actual_potential = any(

        finding.get(
            "potential_xss"
        ) is True

        for finding in matching_findings

    )

    # ------------------------------------------------------------
    # Browser confirmation
    # ------------------------------------------------------------

    actual_confirmed = any(

        finding.get(
            "confirmed_xss"
        ) is True

        for finding in matching_findings

    )

    # ------------------------------------------------------------
    # DETECTION CLASSIFICATION
    # ------------------------------------------------------------

    if (
        actual_potential
        and
        expected_vulnerable
    ):

        classification = "TP"

    elif (
        not actual_potential
        and
        not expected_vulnerable
    ):

        classification = "TN"

    elif (
        actual_potential
        and
        not expected_vulnerable
    ):

        classification = "FP"

    else:

        classification = "FN"

    # ------------------------------------------------------------
    # BROWSER CONFIRMATION MATCH
    # ------------------------------------------------------------

    confirmation_match = (
        actual_confirmed
        ==
        expected_confirmation
    )

    # ------------------------------------------------------------
    # OUTPUT
    # ------------------------------------------------------------

    print(
        f"Matching findings : "
        f"{len(matching_findings)}"
    )

    print(
        f"Potential XSS     : "
        f"{actual_potential}"
    )

    print(
        f"Confirmed XSS     : "
        f"{actual_confirmed}"
    )

    print(
        f"Expected confirmed: "
        f"{expected_confirmation}"
    )

    print(
        f"Detection result  : "
        f"{classification}"
    )

    print(
        f"Confirmation match: "
        f"{'PASS' if confirmation_match else 'FAIL'}"
    )

    return {
        "id": case.get("id"),
        "name": case.get("name"),
        "category": case.get("category"),
        "url": case.get("url"),
        "parameter": case.get("parameter"),

        "ground_truth": ground_truth,

        "expected_vulnerable":
            expected_vulnerable,

        "actual_potential":
            actual_potential,

        "actual_confirmed":
            actual_confirmed,

        "expected_confirmation":
            expected_confirmation,

        "confirmation_match":
            confirmation_match,

        "matching_findings":
            len(matching_findings),

        "classification":
            classification
    }


# ================================================================
# METRICS
# ================================================================

def calculate_metrics(results):

    tp = sum(
        1
        for result in results
        if result["classification"] == "TP"
    )

    tn = sum(
        1
        for result in results
        if result["classification"] == "TN"
    )

    fp = sum(
        1
        for result in results
        if result["classification"] == "FP"
    )

    fn = sum(
        1
        for result in results
        if result["classification"] == "FN"
    )

    total = (
        tp +
        tn +
        fp +
        fn
    )

    if total > 0:

        accuracy = (
            (tp + tn)
            /
            total
        )

    else:

        accuracy = 0.0

    if (tp + fp) > 0:

        precision = (
            tp
            /
            (tp + fp)
        )

    else:

        precision = 0.0

    if (tp + fn) > 0:

        recall = (
            tp
            /
            (tp + fn)
        )

    else:

        recall = 0.0

    if (fp + tn) > 0:

        false_positive_rate = (
            fp
            /
            (fp + tn)
        )

    else:

        false_positive_rate = 0.0

    # ------------------------------------------------------------
    # Browser confirmation statistics
    # ------------------------------------------------------------

    confirmation_pass = sum(

        1

        for result in results

        if result["confirmation_match"]

    )

    confirmation_fail = (
        len(results)
        -
        confirmation_pass
    )

    confirmation_rate = (

        confirmation_pass / len(results)

        if results

        else 0.0

    )

    return {
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,

        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "false_positive_rate":
            false_positive_rate,

        "confirmation_pass":
            confirmation_pass,

        "confirmation_fail":
            confirmation_fail,

        "confirmation_rate":
            confirmation_rate
    }


# ================================================================
# MAIN
# ================================================================

def main():

    print(
        "=" * 70
    )

    print(
        "ShadowXSS - Phase 5"
    )

    print(
        "Accuracy Evaluation"
    )

    print(
        "=" * 70
    )

    cases = load_cases()

    if not cases:

        print(
            "\n[ERROR] No accuracy cases found."
        )

        print(
            "\nPhase 5: FAIL"
        )

        return

    print(
        f"\n[+] Accuracy cases : "
        f"{len(cases)}"
    )

    results = []

    for case in cases:

        result = evaluate_case(
            case
        )

        if result is not None:

            results.append(
                result
            )

    if not results:

        print(
            "\n[ERROR] No cases were evaluated."
        )

        print(
            "\nPhase 5: FAIL"
        )

        return

    metrics = calculate_metrics(
        results
    )

    # ------------------------------------------------------------
    # Save report
    # ------------------------------------------------------------

    output = {

        "phase":
            "5",

        "description":
            "ShadowXSS Accuracy Evaluation",

        "total_cases":
            len(results),

        "results":
            results,

        "metrics":
            metrics
    }

    with open(
        ACCURACY_REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    # ------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "DETECTION ACCURACY SUMMARY"
    )

    print(
        "=" * 70
    )

    print(
        f"Test Cases          : "
        f"{len(results)}"
    )

    print(
        f"True Positives      : "
        f"{metrics['true_positive']}"
    )

    print(
        f"True Negatives      : "
        f"{metrics['true_negative']}"
    )

    print(
        f"False Positives     : "
        f"{metrics['false_positive']}"
    )

    print(
        f"False Negatives     : "
        f"{metrics['false_negative']}"
    )

    print(
        f"Accuracy            : "
        f"{metrics['accuracy'] * 100:.2f}%"
    )

    print(
        f"Precision           : "
        f"{metrics['precision'] * 100:.2f}%"
    )

    print(
        f"Recall              : "
        f"{metrics['recall'] * 100:.2f}%"
    )

    print(
        f"False Positive Rate : "
        f"{metrics['false_positive_rate'] * 100:.2f}%"
    )

    # ------------------------------------------------------------
    # Browser confirmation summary
    # ------------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "BROWSER CONFIRMATION SUMMARY"
    )

    print(
        "=" * 70
    )

    print(
        f"Confirmation PASS : "
        f"{metrics['confirmation_pass']}"
    )

    print(
        f"Confirmation FAIL : "
        f"{metrics['confirmation_fail']}"
    )

    print(
        f"Confirmation Rate : "
        f"{metrics['confirmation_rate'] * 100:.2f}%"
    )

    print(
        "\n[+] Accuracy report saved to:"
    )

    print(
        ACCURACY_REPORT_FILE
    )

    # ------------------------------------------------------------
    # Detection failures
    # ------------------------------------------------------------

    detection_failures = [

        result

        for result in results

        if result["classification"]
        in (
            "FP",
            "FN"
        )

    ]

    print(
        "\n" + "=" * 70
    )

    print(
        "DETECTION CASES REQUIRING INVESTIGATION"
    )

    print(
        "=" * 70
    )

    if detection_failures:

        for result in detection_failures:

            print(
                f"{result['id']} "
                f"-> "
                f"{result['classification']}"
            )

            print(
                f"   Parameter : "
                f"{result['parameter']}"
            )

            print(
                f"   URL       : "
                f"{result['url']}"
            )

    else:

        print(
            "[+] No detection errors."
        )

    print(
        "=" * 70
    )


if __name__ == "__main__":

    main()