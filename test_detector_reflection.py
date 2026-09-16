from core.detector import XSSDetector


class FakeResponse:

    def __init__(self, text):
        self.text = text


def test(
    name,
    response_text,
    payload
):

    response = FakeResponse(
        response_text
    )

    result = XSSDetector.analyze(
        response,
        payload
    )

    print("\n" + "=" * 60)
    print(
        f"Test : {name}"
    )
    print(
        f"Reflection Type : {result['reflection_type']}"
    )
    print(
        f"Reflected       : {result['reflected']}"
    )
    print(
        f"Encoded         : {result['encoded']}"
    )
    print(
        f"Context         : {result['context']}"
    )
    print(
        f"Potential XSS   : {result['potential_xss']}"
    )


def main():

    payload = "<script>alert(1)</script>"


    test(
        "Exact reflection",
        f"<div>{payload}</div>",
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
        "<div>Hello World</div>",
        payload
    )


    print("\n" + "=" * 60)
    print(
        "Phase 2.3.2 detector integration test completed."
    )
    print("=" * 60)


if __name__ == "__main__":

    main()