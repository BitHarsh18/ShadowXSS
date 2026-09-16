from core.context_payload_selector import (
    ContextPayloadSelector
)


def test_context(
    context
):

    payloads = (
        ContextPayloadSelector.get_payloads(
            context
        )
    )


    categories = (
        ContextPayloadSelector.get_categories(
            context
        )
    )


    print("\n" + "=" * 60)

    print(
        f"Context : {context}"
    )

    print(
        f"Categories : {categories}"
    )

    print(
        f"Payload Count : {len(payloads)}"
    )

    print("=" * 60)


    for index, payload in enumerate(
        payloads,
        start=1
    ):

        print(
            f"{index:02d}. {payload}"
        )


def main():

    print("=" * 60)

    print(
        "ShadowXSS - Phase 2.2.1"
    )

    print(
        "Context-Aware Payload Selector Test"
    )

    print("=" * 60)


    test_context(
        "HTML text"
    )


    test_context(
        "HTML attribute"
    )


    test_context(
        "Event Handler Attribute"
    )


    test_context(
        "JavaScript URL Attribute"
    )


    test_context(
        "JavaScript"
    )


    test_context(
        "HTML comment"
    )


    test_context(
        "unknown"
    )


    print("\n" + "=" * 60)

    print(
        "Phase 2.2.1 testing completed."
    )

    print("=" * 60)


if __name__ == "__main__":

    main()