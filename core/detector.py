import html
import re

from core.reflection_normalizer import ReflectionNormalizer


class XSSDetector:

    @staticmethod
    def _base_result():

        return {
            "reflected": False,
            "encoded": False,
            "reflection_type": "not reflected",
            "context": "unknown",

            # Phase 2.1 context metadata
            "tag": None,
            "attribute": None,
            "quote": None,
            "execution_relevant": False,

            "potential_xss": False,
            "confidence": "low",
            "reason": "",
            "evidence": "",

            # Filled by browser verification later
            "browser_verified": False,
            "verification_reason": "",
            "alert_text": None
        }


    # =============================================================
    # Evidence
    # =============================================================

    @staticmethod
    def _evidence(
        response_text,
        position,
        payload,
        window=250
    ):

        start = max(
            0,
            position - window
        )

        end = min(
            len(response_text),
            position + len(payload) + window
        )

        return response_text[
            start:end
        ]


    # =============================================================
    # Find the HTML tag containing a position
    # =============================================================

    @staticmethod
    def _find_enclosing_tag(
        response_text,
        position
    ):

        last_open = response_text.rfind(
            "<",
            0,
            position + 1
        )

        last_close = response_text.rfind(
            ">",
            0,
            position + 1
        )

        # The position is outside an HTML tag.
        if last_open <= last_close:
            return None


        tag_end = response_text.find(
            ">",
            position
        )

        if tag_end == -1:
            return None


        tag_start = last_open

        tag_text = response_text[
            tag_start:tag_end + 1
        ]


        # Closing tags and declarations are not
        # injection attribute contexts.
        if re.match(
            r"<\s*/",
            tag_text
        ):
            return None


        if re.match(
            r"<\s*!",
            tag_text
        ):
            return None


        tag_match = re.match(
            r"<\s*([A-Za-z][\w:-]*)",
            tag_text
        )

        if not tag_match:
            return None


        return {
            "tag": tag_match.group(1),
            "text": tag_text,
            "start": tag_start,
            "end": tag_end
        }


    # =============================================================
    # Quote-aware attribute detection
    # =============================================================

    @staticmethod
    def _find_attribute_at_position(
        tag_text,
        relative_position
    ):

        # ---------------------------------------------------------
        # Parse the tag character-by-character.
        #
        # This is deliberately quote-aware. A simple regex can
        # incorrectly treat payload characters such as:
        #
        # "><script>
        #
        # as belonging to the original attribute.
        # ---------------------------------------------------------

        tag_name_match = re.match(
            r"<\s*[A-Za-z][\w:-]*",
            tag_text
        )

        if not tag_name_match:
            return None


        index = tag_name_match.end()

        length = len(tag_text)


        while index < length:

            # Skip whitespace.
            while (
                index < length
                and tag_text[index].isspace()
            ):
                index += 1


            if index >= length:
                break


            if tag_text[index] in "/>":
                break


            # -----------------------------------------------------
            # Attribute name
            # -----------------------------------------------------

            name_start = index

            while (
                index < length
                and not tag_text[index].isspace()
                and tag_text[index] not in "=/>"
            ):
                index += 1


            attribute_name = tag_text[
                name_start:index
            ]


            if not attribute_name:
                index += 1
                continue


            # Skip whitespace before '='.
            while (
                index < length
                and tag_text[index].isspace()
            ):
                index += 1


            # Boolean attribute.
            if (
                index >= length
                or tag_text[index] != "="
            ):

                if (
                    name_start
                    <= relative_position
                    <= index
                ):

                    return {
                        "attribute": attribute_name,
                        "quote": None
                    }

                continue


            index += 1


            # Skip whitespace after '='.
            while (
                index < length
                and tag_text[index].isspace()
            ):
                index += 1


            if index >= length:
                break


            # -----------------------------------------------------
            # Quoted value
            # -----------------------------------------------------

            if tag_text[index] in "\"'":

                quote = tag_text[index]

                value_start = index + 1

                value_end = tag_text.find(
                    quote,
                    value_start
                )


                if value_end == -1:
                    value_end = length - 1


                if (
                    value_start
                    <= relative_position
                    <= value_end
                ):

                    return {
                        "attribute": attribute_name,
                        "quote": quote
                    }


                index = value_end + 1

                continue


            # -----------------------------------------------------
            # Unquoted value
            # -----------------------------------------------------

            value_start = index

            while (
                index < length
                and not tag_text[index].isspace()
                and tag_text[index] != ">"
            ):
                index += 1


            value_end = index


            if (
                value_start
                <= relative_position
                <= value_end
            ):

                return {
                    "attribute": attribute_name,
                    "quote": None
                }


        return None


    # =============================================================
    # Check whether payload looks executable
    # =============================================================

    @staticmethod
    def _looks_executable(
        payload
    ):

        if not payload:
            return False

        return bool(
            re.search(
                r"""
                (
                    <\s*/?\s*script\b
                    |
                    <\s*(?:svg|img|iframe|body|input|
                    details|video|audio|button|select|
                    textarea|marquee|object|embed)\b
                    |
                    \bon[a-zA-Z]+\s*=
                    |
                    \bjavascript\s*:
                    |
                    \b(?:alert|confirm|prompt)\s*\(
                    |
                    \b(?:eval|Function)\s*\(
                    |
                    \bdocument\.(?:write|writeln)\s*\(
                    |
                    [;]\s*(?:alert|confirm|prompt|eval)\s*\(
                )
                """,
                payload,
                re.IGNORECASE | re.VERBOSE
            )
        )

    # =============================================================
    # JavaScript context detection
    # =============================================================

    @staticmethod
    def _in_script_context(
        response_text,
        position
    ):

        """
        Determine whether the reflection position is inside an
        application-provided <script> block.

        Important Phase 2.1 rule:

        The <script> tag introduced by the payload itself must NOT
        be treated as the enclosing JavaScript context.

        Example:

            <div>INPUT</div>

        where INPUT becomes:

            <script>alert(1)</script>

        is HTML text / injected markup, NOT an existing JavaScript
        context.

        We therefore inspect only script tags that begin before the
        reflection position and determine whether the position is
        between an existing opening and closing script tag.
        """

        script_open = -1
        script_close = -1

        for match in re.finditer(
            r"<\s*/?\s*script\b[^>]*>",
            response_text,
            re.IGNORECASE
        ):

            # A tag beginning at or after the reflection position
            # belongs to the reflected payload or content after it.
            if match.start() >= position:
                break

            tag = match.group(0)

            if re.match(
                r"<\s*/",
                tag
            ):

                script_close = match.end()

            else:

                script_open = match.end()

        return script_open > script_close


    @staticmethod
    def _payload_markup_starts_before_position(
        response_text,
        position,
        payload
    ):

        """
        Detect whether the apparent enclosing tag is actually the
        opening markup of the reflected payload.

        This prevents payloads such as:

            <script>alert(1)</script>
            <img src=x onerror=alert(1)>
            <svg onload=alert(1)>

        from being incorrectly classified as an existing HTML tag
        context simply because their own '<' occurs immediately
        before the reflection.
        """

        payload_start = position

        if response_text.startswith(
            payload,
            payload_start
        ):

            return False

        return False


    @staticmethod
    def _find_existing_script_context(
        response_text,
        position
    ):

        """
        More conservative JavaScript-context classifier.

        A reflection is considered JavaScript only when the response
        contains an already-open <script> element before the reflected
        value and no corresponding closing </script> occurs before
        the value.

        The reflected payload's own <script> opening tag cannot qualify
        because it begins at the reflection position or after it.
        """

        script_open = None
        script_close = None

        for match in re.finditer(
            r"<\s*(/?)\s*script\b[^>]*>",
            response_text,
            re.IGNORECASE
        ):

            if match.start() >= position:
                break

            if match.group(1):

                script_close = match.end()

            else:

                script_open = match.end()

        if (
            script_open is not None
            and (
                script_close is None
                or script_open > script_close
            )
        ):

            return True

        return False


    # =============================================================
    # Main analysis
    # =============================================================

    @staticmethod
    def analyze(
        response,
        payload
    ):

        result = XSSDetector._base_result()


        # =========================================================
        # 1. Validation
        # =========================================================

        if response is None or not payload:

            result["reason"] = (
                "Invalid response or payload"
            )

            return result


        response_text = response.text


        # =========================================================
        # Phase 2.3 reflection normalization
        # =========================================================
        # Keep the existing detector logic intact while adding a
        # normalized classification of the reflection.
        # =========================================================

        reflection_info = ReflectionNormalizer.classify(
            response_text,
            payload
        )

        result["reflection_type"] = reflection_info[
            "type"
        ]

        if reflection_info["encoded"]:

            result["encoded"] = True


        # =========================================================
        # 2. Exact reflection
        # =========================================================

        position = response_text.find(
            payload
        )


        if position == -1:

            decoded_response = html.unescape(
                response_text
            )


            if payload in decoded_response:

                result.update({

                    "reflected": True,

                    "encoded": True,

                    "context": "HTML encoded",

                    "potential_xss": False,

                    "confidence": "low",

                    "reason": (
                        "Payload appears only after HTML "
                        "decoding. The server appears to "
                        "have encoded the reflection."
                    )

                })

                return result


            # ---------------------------------------------------------
            # Phase 2.3 URL-encoded reflection
            # ---------------------------------------------------------

            if reflection_info["type"] == "URL encoded":

                result.update({

                    "reflected": True,

                    "encoded": True,

                    "context": "URL encoded",

                    "potential_xss": False,

                    "confidence": "low",

                    "reason": (
                        "An URL-encoded representation of the "
                        "payload was detected in the response."
                    )

                })

                return result


            # ---------------------------------------------------------
            # No reflection
            # ---------------------------------------------------------

            result["reflected"] = False

            result["encoded"] = False

            result["reflection_type"] = "not reflected"

            result["context"] = "not reflected"

            result["potential_xss"] = False

            result["confidence"] = "low"

            result["reason"] = (
                "Payload was not found in the HTTP response."
            )

            return result


        result["reflected"] = True


        result["evidence"] = (
            XSSDetector._evidence(
                response_text,
                position,
                payload
            )
        )


        # =========================================================
        # 3. Encoded reflection check
        # =========================================================

        encoded_variants = [

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


        if any(
            variant in response_text
            for variant in encoded_variants
            if variant != payload
        ):

            result.update({

                "encoded": True,

                "context": "HTML encoded",

                "potential_xss": False,

                "confidence": "low",

                "reason": (
                    "An encoded representation of the "
                    "payload was detected in the response."
                )

            })

            return result


        # =========================================================
        # 4. HTML comment
        # =========================================================

        before = response_text[
            :position
        ]


        comment_start = before.rfind(
            "<!--"
        )

        comment_end = before.rfind(
            "-->"
        )


        if comment_start > comment_end:

            result.update({

                "context": "HTML comment",

                "execution_relevant": False,

                "potential_xss": False,

                "confidence": "low",

                "reason": (
                    "Payload is reflected inside an HTML "
                    "comment and is not an active execution "
                    "context."
                )

            })

            return result


        # =========================================================
        # 5. JavaScript <script> context
        # =========================================================

        if XSSDetector._find_existing_script_context(
            response_text,
            position
        ):

            result.update({

                "context": "JavaScript",

                "execution_relevant": True,

                "potential_xss": (
                    XSSDetector._looks_executable(
                        payload
                    )
                ),

                "confidence": "high",

                "reason": (
                    "Payload is reflected inside an active "
                    "JavaScript context. Browser execution "
                    "still requires verification."
                )

            })

            return result


        # =========================================================
        # 6. Determine whether reflection is inside an HTML tag
        # =========================================================

        tag_info = XSSDetector._find_enclosing_tag(
            response_text,
            position
        )


        if tag_info:

            tag_text = tag_info[
                "text"
            ]


            relative_position = (
                position -
                tag_info["start"]
            )


            attribute_info = (
                XSSDetector._find_attribute_at_position(
                    tag_text,
                    relative_position
                )
            )


            result["tag"] = tag_info[
                "tag"
            ]


            # -----------------------------------------------------
            # 6A. Reflection inside an attribute
            # -----------------------------------------------------

            if attribute_info:

                attribute_name = (
                    attribute_info[
                        "attribute"
                    ]
                )


                quote = (
                    attribute_info[
                        "quote"
                    ]
                )


                result["attribute"] = (
                    attribute_name
                )

                result["quote"] = quote


                # Event handler.
                if re.fullmatch(
                    r"on[a-zA-Z]+",
                    attribute_name
                ):

                    result.update({

                        "context": (
                            "Event Handler Attribute"
                        ),

                        "execution_relevant": True,

                        "potential_xss": True,

                        "confidence": "high",

                        "reason": (
                            "Payload is reflected inside "
                            f"the {attribute_name} event-handler "
                            "attribute. Browser execution is "
                            "not yet confirmed."
                        )

                    })

                    return result


                # JavaScript-capable URL attribute.
                if attribute_name.lower() in {
                    "href",
                    "src",
                    "action",
                    "formaction"
                }:

                    attribute_start = (
                        tag_text.lower().find(
                            attribute_name.lower()
                        )
                    )


                    attribute_fragment = tag_text[
                        attribute_start:
                    ]


                    if re.search(
                        r"\bjavascript\s*:",
                        attribute_fragment,
                        re.IGNORECASE
                    ):

                        result.update({

                            "context": (
                                "JavaScript URL Attribute"
                            ),

                            "execution_relevant": True,

                            "potential_xss": True,

                            "confidence": "high",

                            "reason": (
                                "Payload is reflected inside "
                                "a JavaScript URL-capable "
                                "attribute."
                            )

                        })

                        return result


                # Generic attribute.
                result.update({

                    "context": "HTML attribute",

                    "execution_relevant": False,

                    "potential_xss": (
                        XSSDetector._looks_executable(
                            payload
                        )
                    ),

                    "confidence": (
                        "medium"
                        if XSSDetector._looks_executable(
                            payload
                        )
                        else "low"
                    ),

                    "reason": (
                        "Payload is reflected inside the "
                        f"{attribute_name} attribute of "
                        f"<{tag_info['tag']}>. Exploitability "
                        "depends on the specific attribute "
                        "and browser context."
                    )

                })

                return result


            # -----------------------------------------------------
            # 6B. Inside an HTML tag but not an attribute value
            # -----------------------------------------------------

            result.update({

                "context": "HTML tag",

                "execution_relevant": True,

                "potential_xss": (
                    XSSDetector._looks_executable(
                        payload
                    )
                ),

                "confidence": "medium",

                "reason": (
                    "Payload is reflected inside an HTML "
                    f"<{tag_info['tag']}> tag but could not "
                    "be associated with a specific attribute."
                )

            })

            return result


        # =========================================================
        # 7. HTML text context
        # =========================================================

        # ---------------------------------------------------------
        # HTML-text false-positive protection
        #
        # A javascript: scheme is executable when it is placed in
        # a JavaScript-capable URL attribute such as href/src/action,
        # but it is NOT executable merely because the same string is
        # reflected as ordinary HTML text.
        #
        # Therefore, HTML-text detection intentionally excludes the
        # javascript: pattern. The dedicated JavaScript URL attribute
        # logic above remains responsible for that case.
        # ---------------------------------------------------------

        executable_payload = bool(
            re.search(
                r"""
                (
                    <\\s*/?\\s*script\\b
                    |
                    <\\s*(?:svg|img|iframe|body|input|
                    details|video|audio|button|select|
                    textarea|marquee|object|embed)\\b
                    |
                    \\bon[a-zA-Z]+\\s*=
                )
                """,
                payload,
                re.IGNORECASE |
                re.VERBOSE
            )
        )


        if executable_payload:

            result.update({

                "context": "HTML text",

                "execution_relevant": True,

                "potential_xss": True,

                "confidence": "medium",

                "reason": (
                    "Payload is reflected in HTML text and "
                    "contains executable-looking HTML or "
                    "event-handler syntax. Browser execution "
                    "is not confirmed."
                )

            })

            return result


        # =========================================================
        # 8. Ordinary text reflection
        # =========================================================

        result.update({

            "context": "HTML text",

            "execution_relevant": False,

            "potential_xss": False,

            "confidence": "low",

            "reason": (
                "Payload is reflected as ordinary HTML text "
                "without obvious executable markup."
            )

        })

        return result


    # =============================================================
    # Backward-compatible API
    # =============================================================

    @staticmethod
    def is_vulnerable(
        response,
        payload
    ):

        result = XSSDetector.analyze(
            response,
            payload
        )

        return result[
            "potential_xss"
        ]