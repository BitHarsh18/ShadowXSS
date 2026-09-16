from core.context_detector import ContextDetector


BASE_URL = (
    "http://127.0.0.1:5000/context-test"
)


def test_parameter(parameter):

    url = (
        BASE_URL
        + "?"
        + parameter
        + "=test"
    )


    print("\n" + "=" * 70)

    print(
        f"Testing parameter : {parameter}"
    )

    print(
        f"URL               : {url}"
    )

    print("=" * 70)


    result = (
        ContextDetector.detect_url_parameter_context(
            url,
            parameter
        )
    )


    print(
        f"Parameter : "
        f"{result.get('parameter')}"
    )

    print(
        f"Marker    : "
        f"{result.get('marker')}"
    )

    print(
        f"Context   : "
        f"{result.get('context')}"
    )

    print(
        f"Tag       : "
        f"{result.get('tag')}"
    )

    print(
        f"Attribute : "
        f"{result.get('attribute')}"
    )

    print(
        f"Quote     : "
        f"{result.get('quote')}"
    )

    print(
        f"Found     : "
        f"{result.get('found')}"
    )

    print(
        f"Reason    : "
        f"{result.get('reason')}"
    )


    print("\nEvidence:")

    print(
        result.get(
            "evidence",
            ""
        )
    )


def main():

    print("=" * 70)

    print(
        "ShadowXSS - Phase 2.1 Step 3"
    )

    print(
        "Controlled Multi-Context Testing"
    )

    print("=" * 70)


    # ============================================================
    # 1. HTML TEXT
    # ============================================================

    test_parameter(
        "html_text"
    )


    # ============================================================
    # 2. HTML ATTRIBUTE
    # ============================================================

    test_parameter(
        "attribute"
    )


    # ============================================================
    # 3. EVENT HANDLER ATTRIBUTE
    # ============================================================

    test_parameter(
        "event"
    )


    # ============================================================
    # 4. JAVASCRIPT URL ATTRIBUTE
    # ============================================================

    test_parameter(
        "js_url"
    )


    # ============================================================
    # 5. JAVASCRIPT CONTEXT
    # ============================================================

    test_parameter(
        "javascript"
    )


    # ============================================================
    # 6. HTML COMMENT
    # ============================================================

    test_parameter(
        "comment"
    )


    print("\n" + "=" * 70)

    print(
        "Phase 2.1 Step 3 testing completed."
    )

    print("=" * 70)


if __name__ == "__main__":

    main()