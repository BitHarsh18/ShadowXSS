import html

from urllib.parse import unquote


class ReflectionNormalizer:

    # ============================================================
    # Exact reflection
    # ============================================================

    @staticmethod
    def exact_match(
        response_text,
        payload
    ):

        return payload in response_text


    # ============================================================
    # HTML entity decoding
    # ============================================================

    @staticmethod
    def html_decoded_match(
        response_text,
        payload
    ):

        decoded_response = html.unescape(
            response_text
        )

        return payload in decoded_response


    # ============================================================
    # URL decoding
    # ============================================================

    @staticmethod
    def url_decoded_match(
        response_text,
        payload
    ):

        decoded_response = unquote(
            response_text
        )

        return payload in decoded_response


    # ============================================================
    # HTML encoded payload
    # ============================================================

    @staticmethod
    def html_encoded_forms(
        payload
    ):

        return list(
            dict.fromkeys(
                [
                    html.escape(
                        payload
                    ),

                    payload.replace(
                        "<",
                        "&lt;"
                    ).replace(
                        ">",
                        "&gt;"
                    ),

                    payload.replace(
                        '"',
                        "&quot;"
                    ),

                    payload.replace(
                        "'",
                        "&#x27;"
                    )
                ]
            )
        )


    # ============================================================
    # URL encoded payload
    # ============================================================

    @staticmethod
    def url_encoded_forms(
        payload
    ):

        from urllib.parse import quote

        return [
            quote(
                payload
            ),
            quote(
                payload,
                safe=""
            )
        ]


    # ============================================================
    # Determine reflection type
    # ============================================================

    @classmethod
    def classify(
        cls,
        response_text,
        payload
    ):

        if not response_text or not payload:

            return {
                "reflected": False,
                "type": "not reflected",
                "encoded": False
            }


        # --------------------------------------------------------
        # 1. Exact reflection
        # --------------------------------------------------------

        if cls.exact_match(
            response_text,
            payload
        ):

            return {
                "reflected": True,
                "type": "exact",
                "encoded": False
            }


        # --------------------------------------------------------
        # 2. HTML entity encoded reflection
        # --------------------------------------------------------

        html_forms = (
            cls.html_encoded_forms(
                payload
            )
        )


        if any(
            encoded in response_text
            for encoded in html_forms
            if encoded != payload
        ):

            return {
                "reflected": True,
                "type": "HTML encoded",
                "encoded": True
            }


        # --------------------------------------------------------
        # 3. URL encoded reflection
        # --------------------------------------------------------

        url_forms = (
            cls.url_encoded_forms(
                payload
            )
        )


        if any(
            encoded in response_text
            for encoded in url_forms
            if encoded != payload
        ):

            return {
                "reflected": True,
                "type": "URL encoded",
                "encoded": True
            }


        # --------------------------------------------------------
        # 4. Decode response and check HTML entities
        # --------------------------------------------------------

        if cls.html_decoded_match(
            response_text,
            payload
        ):

            return {
                "reflected": True,
                "type": "HTML decoded",
                "encoded": True
            }


        # --------------------------------------------------------
        # 5. Decode response and check URL encoding
        # --------------------------------------------------------

        if cls.url_decoded_match(
            response_text,
            payload
        ):

            return {
                "reflected": True,
                "type": "URL decoded",
                "encoded": True
            }


        # --------------------------------------------------------
        # 6. No known reflection
        # --------------------------------------------------------

        return {
            "reflected": False,
            "type": "not reflected",
            "encoded": False
        }