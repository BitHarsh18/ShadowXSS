from core.payloads import Payloads


class ContextPayloadSelector:

    # ============================================================
    # Context → Payload Category Mapping
    # ============================================================

    CONTEXT_MAP = {

        # --------------------------------------------------------
        # HTML text
        # --------------------------------------------------------
        "HTML text": [
            "HTML_PAYLOADS",
            "HTML_ELEMENT_PAYLOADS",
            "SVG_PAYLOADS",
        ],


        # --------------------------------------------------------
        # HTML attribute
        # --------------------------------------------------------
        "HTML attribute": [
            "ATTRIBUTE_PAYLOADS",
        ],


        # --------------------------------------------------------
        # Event handler attribute
        # --------------------------------------------------------
        "Event Handler Attribute": [
            "EVENT_PAYLOADS",
            "ATTRIBUTE_PAYLOADS",
        ],


        # --------------------------------------------------------
        # JavaScript URL
        # --------------------------------------------------------
        "JavaScript URL Attribute": [
            "JAVASCRIPT_PAYLOADS",
            "ATTRIBUTE_PAYLOADS",
        ],


        # --------------------------------------------------------
        # JavaScript
        # --------------------------------------------------------
        "JavaScript": [
            "JAVASCRIPT_PAYLOADS",
        ],


        # --------------------------------------------------------
        # HTML comment
        # --------------------------------------------------------
        "HTML comment": [
            "HTML_PAYLOADS",
            "HTML_ELEMENT_PAYLOADS",
        ],


        # --------------------------------------------------------
        # Unknown
        # --------------------------------------------------------
        #
        # Unknown contexts use the complete library.
        #
        "unknown": [
            "HTML_PAYLOADS",
            "HTML_ELEMENT_PAYLOADS",
            "EVENT_PAYLOADS",
            "ATTRIBUTE_PAYLOADS",
            "JAVASCRIPT_PAYLOADS",
            "SVG_PAYLOADS",
        ],

    }


    # ============================================================
    # Get payloads for context
    # ============================================================

    @classmethod
    def get_payloads(
        cls,
        context
    ):

        categories = cls.CONTEXT_MAP.get(
            context
        )


        # --------------------------------------------------------
        # Unknown/unmapped context
        # --------------------------------------------------------

        if categories is None:

            categories = cls.CONTEXT_MAP[
                "unknown"
            ]


        selected_payloads = []


        # --------------------------------------------------------
        # Collect payloads
        # --------------------------------------------------------

        for category in categories:

            payload_group = getattr(
                Payloads,
                category,
                []
            )


            selected_payloads.extend(
                payload_group
            )


        # --------------------------------------------------------
        # Remove duplicates
        # --------------------------------------------------------

        return list(
            dict.fromkeys(
                selected_payloads
            )
        )


    # ============================================================
    # Get payload count
    # ============================================================

    @classmethod
    def count(
        cls,
        context
    ):

        return len(
            cls.get_payloads(
                context
            )
        )


    # ============================================================
    # Get selected category names
    # ============================================================

    @classmethod
    def get_categories(
        cls,
        context
    ):

        categories = cls.CONTEXT_MAP.get(
            context
        )


        if categories is None:

            categories = cls.CONTEXT_MAP[
                "unknown"
            ]


        return list(
            categories
        )