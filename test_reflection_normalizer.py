from core.reflection_normalizer import (
    ReflectionNormalizer
)


def test(
    name,
    response,
    payload
):

    result = ReflectionNormalizer.classify(
        response,
        payload
    )

    print("\n" + "=" * 60)
    print(
        f"Test : {name}"
    )
    print(
        f"Result : {result}"
    )


def main():

    payload = "<script>alert(1)</script>"


    test(
        "Exact reflection",
        f"Hello {payload}",
        payload
    )


    test(
        "HTML encoded reflection",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        payload
    )


    test(
        "URL encoded reflection",
        "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        payload
    )


    test(
        "No reflection",
        "Hello world",
        payload
    )

    test(
        "Partial reflection",
        "<script>alert(1)",
        payload
    )


    test(
        "Transformed reflection",
        "<SCRIPT>alert(1)</SCRIPT>",
        payload
    )


    print("\n" + "=" * 60)
    print(
        "Phase 2.3.1 testing completed."
    )
    print("=" * 60)


if __name__ == "__main__":

    main()