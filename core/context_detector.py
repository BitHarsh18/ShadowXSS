import re
import uuid
import requests

from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse
)


class ContextDetector:

    # ============================================================
    # Configuration
    # ============================================================

    MARKER_PREFIX = "ShadowXSS_CTX_"


    # ============================================================
    # Generate unique marker
    # ============================================================

    @staticmethod
    def generate_marker():

        return (
            ContextDetector.MARKER_PREFIX
            + uuid.uuid4().hex[:12]
        )


    # ============================================================
    # Build URL with marker in ONE parameter
    # ============================================================

    @staticmethod
    def build_test_url(
        url,
        parameter,
        marker
    ):

        parsed = urlparse(url)

        parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True
        )

        updated_parameters = []

        parameter_found = False

        for key, value in parameters:

            if key == parameter:

                updated_parameters.append(
                    (
                        key,
                        marker
                    )
                )

                parameter_found = True

            else:

                updated_parameters.append(
                    (
                        key,
                        value
                    )
                )


        if not parameter_found:

            return None


        new_query = urlencode(
            updated_parameters
        )


        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            )
        )


    # ============================================================
    # Find marker in response
    # ============================================================

    @staticmethod
    def find_marker(
        response_text,
        marker
    ):

        position = response_text.find(
            marker
        )

        if position == -1:

            return {
                "found": False,
                "position": -1,
                "evidence": ""
            }


        start = max(
            0,
            position - 300
        )

        end = min(
            len(response_text),
            position + len(marker) + 300
        )


        evidence = response_text[
            start:end
        ]


        return {
            "found": True,
            "position": position,
            "evidence": evidence
        }


    # ============================================================
    # Detect HTML comment context
    # ============================================================

    @staticmethod
    def detect_comment_context(
        response_text,
        position
    ):

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

            return True


        return False


    # ============================================================
    # Detect JavaScript context
    # ============================================================

    @staticmethod
    def detect_javascript_context(
        response_text,
        position
    ):

        script_open = None
        script_close = None


        for match in re.finditer(
            r"<\s*(/?)\s*script\b[^>]*>",
            response_text,
            re.IGNORECASE
        ):

            # Ignore tags appearing at or after marker.
            if match.start() >= position:

                break


            if match.group(1):

                script_close = match.end()

            else:

                script_open = match.end()


        if script_open is not None:

            if (
                script_close is None
                or script_open > script_close
            ):

                return True


        return False


    # ============================================================
    # Find enclosing HTML tag
    # ============================================================

    @staticmethod
    def find_enclosing_tag(
        response_text,
        position
    ):

        last_open = response_text.rfind(
            "<",
            0,
            position
        )

        last_close = response_text.rfind(
            ">",
            0,
            position
        )


        if last_open <= last_close:

            return None


        tag_end = response_text.find(
            ">",
            position
        )


        if tag_end == -1:

            return None


        tag_content = response_text[
            last_open:
            tag_end + 1
        ]


        match = re.match(
            r"<\s*([a-zA-Z][a-zA-Z0-9:-]*)",
            tag_content
        )


        if not match:

            return None


        tag_name = match.group(1)


        return {
            "tag": tag_name,
            "content": tag_content,
            "start": last_open,
            "end": tag_end
        }


    # ============================================================
    # Detect attribute containing marker
    # ============================================================

    @staticmethod
    def detect_attribute_context(
        tag_content,
        marker
    ):

        # --------------------------------------------------------
        # Quoted attributes
        # --------------------------------------------------------

        quoted_pattern = re.compile(
            r"""
            ([a-zA-Z_:][a-zA-Z0-9_:.:-]*)
            \s*=\s*
            (?:
                "([^"]*)"
                |
                '([^']*)'
            )
            """,
            re.VERBOSE
        )


        for match in quoted_pattern.finditer(
            tag_content
        ):

            attribute_name = match.group(1)

            double_value = match.group(2)

            single_value = match.group(3)


            value = (
                double_value
                if double_value is not None
                else single_value
            )


            if value is not None and marker in value:

                quote = (
                    '"'
                    if double_value is not None
                    else "'"
                )


                return {
                    "attribute": attribute_name,
                    "quote": quote
                }


        # --------------------------------------------------------
        # Unquoted attributes
        # --------------------------------------------------------

        unquoted_pattern = re.compile(
            r"""
            ([a-zA-Z_:][a-zA-Z0-9_:.:-]*)
            \s*=\s*
            ([^\s>]+)
            """,
            re.VERBOSE
        )


        for match in unquoted_pattern.finditer(
            tag_content
        ):

            attribute_name = match.group(1)

            value = match.group(2)


            if marker in value:

                return {
                    "attribute": attribute_name,
                    "quote": None
                }


        return None


    # ============================================================
    # Classify discovered context
    # ============================================================

    @staticmethod
    def classify_context(
        response_text,
        marker,
        position
    ):

        # --------------------------------------------------------
        # HTML comment
        # --------------------------------------------------------

        if ContextDetector.detect_comment_context(
            response_text,
            position
        ):

            return {
                "context": "HTML comment",
                "tag": None,
                "attribute": None,
                "quote": None,
                "reason": (
                    "Marker is located inside "
                    "an HTML comment"
                )
            }


        # --------------------------------------------------------
        # JavaScript
        # --------------------------------------------------------

        if ContextDetector.detect_javascript_context(
            response_text,
            position
        ):

            return {
                "context": "JavaScript",
                "tag": "script",
                "attribute": None,
                "quote": None,
                "reason": (
                    "Marker is located inside an "
                    "existing HTML script block"
                )
            }


        # --------------------------------------------------------
        # HTML tag / attribute
        # --------------------------------------------------------

        tag_info = ContextDetector.find_enclosing_tag(
            response_text,
            position
        )


        if tag_info:

            attribute_info = (
                ContextDetector.detect_attribute_context(
                    tag_info["content"],
                    marker
                )
            )


            if attribute_info:

                attribute_name = (
                    attribute_info["attribute"]
                )


                # ----------------------------------------------
                # Event handler
                # ----------------------------------------------

                if re.match(
                    r"^on[a-zA-Z]+$",
                    attribute_name,
                    re.IGNORECASE
                ):

                    return {
                        "context": (
                            "Event Handler Attribute"
                        ),
                        "tag": tag_info["tag"],
                        "attribute": attribute_name,
                        "quote": attribute_info["quote"],
                        "reason": (
                            "Marker is located inside "
                            "an event-handler attribute"
                        )
                    }


                # ----------------------------------------------
                # JavaScript URL
                # ----------------------------------------------

                attribute_lower = (
                    attribute_name.lower()
                )


                tag_lower = (
                    tag_info["tag"].lower()
                )


                # The marker itself is not necessarily prefixed
                # with javascript:. We inspect the beginning of
                # the attribute value in the tag.

                javascript_url_pattern = re.search(
                    r"""
                    (?:href|src|action)
                    \s*=\s*
                    (?:
                        ["']
                    )?
                    \s*javascript:
                    """,
                    tag_info["content"],
                    re.IGNORECASE | re.VERBOSE
                )


                if (
                    attribute_lower
                    in (
                        "href",
                        "src",
                        "action"
                    )
                    and javascript_url_pattern
                ):

                    return {
                        "context": (
                            "JavaScript URL Attribute"
                        ),
                        "tag": tag_info["tag"],
                        "attribute": attribute_name,
                        "quote": attribute_info["quote"],
                        "reason": (
                            "Marker is located inside "
                            "a JavaScript URL attribute"
                        )
                    }


                # ----------------------------------------------
                # Generic HTML attribute
                # ----------------------------------------------

                return {
                    "context": "HTML attribute",
                    "tag": tag_info["tag"],
                    "attribute": attribute_name,
                    "quote": attribute_info["quote"],
                    "reason": (
                        "Marker is located inside "
                        "an HTML attribute"
                    )
                }


            # ----------------------------------------------------
            # Marker is inside a tag but not an attribute value
            # ----------------------------------------------------

            return {
                "context": "HTML tag",
                "tag": tag_info["tag"],
                "attribute": None,
                "quote": None,
                "reason": (
                    "Marker is located inside "
                    "an HTML tag"
                )
            }


        # --------------------------------------------------------
        # HTML text
        # --------------------------------------------------------

        return {
            "context": "HTML text",
            "tag": None,
            "attribute": None,
            "quote": None,
            "reason": (
                "Marker is located directly "
                "inside HTML text"
            )
        }


    # ============================================================
    # Main URL parameter context probe
    # ============================================================

    @staticmethod
    def detect_url_parameter_context(
        url,
        parameter,
        session=None
    ):

        marker = (
            ContextDetector.generate_marker()
        )


        # --------------------------------------------------------
        # Build test URL
        # --------------------------------------------------------

        test_url = (
            ContextDetector.build_test_url(
                url,
                parameter,
                marker
            )
        )


        if test_url is None:

            return {
                "parameter": parameter,
                "marker": marker,
                "context": "unknown",
                "tag": None,
                "attribute": None,
                "quote": None,
                "found": False,
                "reason": (
                    "Parameter was not found "
                    "in the URL"
                ),
                "evidence": ""
            }


        # --------------------------------------------------------
        # HTTP session
        # --------------------------------------------------------

        if session is None:

            session = requests.Session()


        try:

            response = session.get(
                test_url,
                timeout=10
            )


        except requests.RequestException as error:

            return {
                "parameter": parameter,
                "marker": marker,
                "context": "unknown",
                "tag": None,
                "attribute": None,
                "quote": None,
                "found": False,
                "reason": (
                    "HTTP request failed: "
                    + str(error)
                ),
                "evidence": ""
            }


        response_text = response.text


        # --------------------------------------------------------
        # Locate marker
        # --------------------------------------------------------

        marker_result = (
            ContextDetector.find_marker(
                response_text,
                marker
            )
        )


        if not marker_result["found"]:

            return {
                "parameter": parameter,
                "marker": marker,
                "context": "not reflected",
                "tag": None,
                "attribute": None,
                "quote": None,
                "found": False,
                "reason": (
                    "Context marker was not "
                    "reflected in the response"
                ),
                "evidence": ""
            }


        position = (
            marker_result["position"]
        )


        # --------------------------------------------------------
        # Classify context
        # --------------------------------------------------------

        classification = (
            ContextDetector.classify_context(
                response_text,
                marker,
                position
            )
        )


        # --------------------------------------------------------
        # Final result
        # --------------------------------------------------------

        return {

            "parameter": parameter,

            "marker": marker,

            "context": classification.get(
                "context",
                "unknown"
            ),

            "tag": classification.get(
                "tag"
            ),

            "attribute": classification.get(
                "attribute"
            ),

            "quote": classification.get(
                "quote"
            ),

            "found": True,

            "reason": classification.get(
                "reason",
                ""
            ),

            "evidence": marker_result.get(
                "evidence",
                ""
            ),

            "status_code": response.status_code,

            "test_url": test_url

        }


    # ============================================================
    # Generic response context probe
    # ============================================================

    @staticmethod
    def detect_response_context(
        response,
        marker
    ):

        if response is None:

            return {
                "context": "unknown",
                "found": False,
                "reason": (
                    "Response is None"
                )
            }


        response_text = response.text


        marker_result = (
            ContextDetector.find_marker(
                response_text,
                marker
            )
        )


        if not marker_result["found"]:

            return {
                "context": "not reflected",
                "found": False,
                "reason": (
                    "Marker was not found "
                    "in response"
                )
            }


        position = (
            marker_result["position"]
        )


        result = (
            ContextDetector.classify_context(
                response_text,
                marker,
                position
            )
        )


        result.update({

            "marker": marker,

            "found": True,

            "evidence": marker_result[
                "evidence"
            ]

        })


        return result