import json


class Reporter:

    def __init__(self):

        # =========================================================
        # EVERY PAYLOAD-LEVEL FINDING
        # =========================================================

        self.all_findings = []


        # =========================================================
        # DEDUPLICATED UNIQUE FINDINGS
        # =========================================================

        self.findings = []


        # =========================================================
        # STATISTICS
        # =========================================================

        self.payload_reflections = 0

        self.unique_finding_keys = set()


    # =============================================================
    # ADD FINDING
    # =============================================================

    def add_finding(
        self,
        url,
        payload,
        method,
        xss_type,
        severity,
        analysis=None,
        parameter=None
    ):

        # ---------------------------------------------------------
        # Default analysis
        # ---------------------------------------------------------

        if analysis is None:

            analysis = {

                "reflected": False,

                "encoded": False,

                "context": "unknown",

                "potential_xss": False,

                "confidence": "low",

                "reason": "",

                "evidence": ""

            }


        # ---------------------------------------------------------
        # Create complete finding
        # ---------------------------------------------------------

        finding = {

            "url": url,

            "parameter": parameter,

            "payload": payload,

            "method": method,

            "type": xss_type,

            "severity": severity,

            "reflected": analysis.get(
                "reflected",
                False
            ),

            "encoded": analysis.get(
                "encoded",
                False
            ),
            

            "reflection_type": analysis.get(
                "reflection_type",
                "not reflected"
            ),
        
            "context": analysis.get(
                "context",
                "unknown"
            ),

            "potential_xss": analysis.get(
                "potential_xss",
                False
            ),

            "confidence": analysis.get(
                "confidence",
                "low"
            ),

            "reason": analysis.get(
                "reason",
                ""
            ),

            "evidence": analysis.get(
                "evidence",
                ""
            ),

            # -----------------------------------------------------
            # Browser verification
            # -----------------------------------------------------

            "browser_verified": False,

            "confirmed_xss": False,

            "verification": "NOT_TESTED",

            "verification_reason": "",

            "alert_text": None

        }


        # =========================================================
        # STORE RAW PAYLOAD-LEVEL RESULT
        # =========================================================

        self.all_findings.append(
            finding
        )


        # =========================================================
        # COUNT POTENTIAL REFLECTIONS
        # =========================================================

        if analysis.get(
            "potential_xss",
            False
        ):

            self.payload_reflections += 1


        # =========================================================
        # UNIQUE FINDING KEY
        # =========================================================
        #
        # URL
        # +
        # PARAMETER / INPUT
        # +
        # METHOD
        # +
        # XSS TYPE
        # +
        # CONTEXT
        #
        # This means different inputs are treated as
        # different injection points.
        #

        unique_key = (

            str(url),

            str(parameter),

            str(method).upper(),

            str(xss_type),

            str(
                analysis.get(
                    "context",
                    "unknown"
                )
            )

        )


        # =========================================================
        # FIRST FINDING FOR THIS INJECTION POINT
        # =========================================================

        if unique_key not in self.unique_finding_keys:

            self.unique_finding_keys.add(
                unique_key
            )


            finding[
                "payload_count"
            ] = 1


            finding[
                "successful_payloads"
            ] = [

                payload

            ]


            self.findings.append(
                finding
            )


        # =========================================================
        # SAME INJECTION POINT + DIFFERENT PAYLOAD
        # =========================================================

        else:

            for existing_finding in self.findings:

                existing_key = (

                    str(
                        existing_finding.get(
                            "url"
                        )
                    ),

                    str(
                        existing_finding.get(
                            "parameter"
                        )
                    ),

                    str(
                        existing_finding.get(
                            "method"
                        )
                    ).upper(),

                    str(
                        existing_finding.get(
                            "type"
                        )
                    ),

                    str(
                        existing_finding.get(
                            "context",
                            "unknown"
                        )
                    )

                )


                if existing_key == unique_key:

                    # ------------------------------------------------
                    # Increase successful payload count
                    # ------------------------------------------------

                    existing_finding[
                        "payload_count"
                    ] = (

                        existing_finding.get(
                            "payload_count",
                            0
                        )

                        + 1

                    )


                    # ------------------------------------------------
                    # Preserve successful payload
                    # ------------------------------------------------

                    existing_finding[
                        "successful_payloads"
                    ].append(
                        payload
                    )


                    break


    # =============================================================
    # UPDATE BROWSER VERIFICATION
    # =============================================================

    def update_verification(
        self,
        url,
        parameter,
        method,
        payload,
        verification_result
    ):

        # ---------------------------------------------------------
        # Extract browser result
        # ---------------------------------------------------------

        verified = verification_result.get(
            "verified",
            False
        )


        alert_text = verification_result.get(
            "alert_text",
            None
        )


        reason = verification_result.get(
            "reason",
            ""
        )


        # ---------------------------------------------------------
        # Find exact injection-point finding
        # ---------------------------------------------------------

        for finding in self.findings:

            same_url = (
                str(
                    finding.get(
                        "url"
                    )
                )
                ==
                str(url)
            )


            same_parameter = (
                str(
                    finding.get(
                        "parameter"
                    )
                )
                ==
                str(parameter)
            )


            same_method = (
                str(
                    finding.get(
                        "method"
                    )
                ).lower()
                ==
                str(method).lower()
            )


            payload_tested = (
                payload in
                finding.get(
                    "successful_payloads",
                    []
                )
            )


            if (
                same_url
                and
                same_parameter
                and
                same_method
                and
                payload_tested
            ):

                # ------------------------------------------------
                # Store verification result
                # ------------------------------------------------

                finding[
                    "browser_verified"
                ] = verified

                # ------------------------------------------------
                # Explicit confirmation state
                #
                # Potential XSS is determined by the detector.
                # confirmed_xss is set only after browser verification
                # actually observes JavaScript execution.
                # ------------------------------------------------

                finding[
                    "confirmed_xss"
                ] = bool(
                    verified
                )


                # ------------------------------------------------
                # Phase 6 - Browser-confirmed severity escalation
                #
                # Browser execution provides stronger evidence than
                # reflection alone. Upgrade the existing severity by
                # one level when JavaScript execution is confirmed.
                #
                # CRITICAL remains the maximum severity.
                # Unconfirmed findings retain their initial severity.
                # ------------------------------------------------

                if verified:

                    severity_order = [
                        "LOW",
                        "MEDIUM",
                        "HIGH",
                        "CRITICAL"
                    ]

                    current_severity = str(
                        finding.get(
                            "severity",
                            "LOW"
                        )
                    ).upper()

                    if current_severity in severity_order:

                        current_index = (
                            severity_order.index(
                                current_severity
                            )
                        )

                        if current_index < (
                            len(severity_order) - 1
                        ):

                            finding[
                                "severity"
                            ] = severity_order[
                                current_index + 1
                            ]


                # ------------------------------------------------
                # Human-readable verification status
                # ------------------------------------------------

                if verified:

                    finding[
                        "verification"
                    ] = "CONFIRMED"

                else:

                    finding[
                        "verification"
                    ] = "NOT_CONFIRMED"


                # ------------------------------------------------
                # Store verification reason
                # ------------------------------------------------

                finding[
                    "verification_reason"
                ] = reason


                # ------------------------------------------------
                # Store alert text
                # ------------------------------------------------

                finding[
                    "alert_text"
                ] = alert_text


                return True


        # Exact finding was not found

        return False


    # =============================================================
    # STATISTICS
    # =============================================================

    def get_statistics(
        self,
        payloads_tested=0
    ):

        confirmed = 0

        not_confirmed = 0

        not_tested = 0


        for finding in self.findings:

            verification = finding.get(
                "verification",
                "NOT_TESTED"
            )


            if verification == "CONFIRMED":

                confirmed += 1


            elif verification == "NOT_CONFIRMED":

                not_confirmed += 1


            else:

                not_tested += 1


        return {

            "payloads_tested":
                payloads_tested,

            "payload_reflections":
                self.payload_reflections,

            "unique_findings":
                len(
                    self.findings
                ),

            "raw_findings":
                len(
                    self.all_findings
                ),

            "confirmed":
                confirmed,

            "not_confirmed":
                not_confirmed,

            "not_tested":
                not_tested

        }


    # =============================================================
    # SAVE JSON REPORT
    # =============================================================

    def save_json(
        self,
        filename="report.json"
    ):

        statistics = self.get_statistics()


        report = {

            "summary": statistics,

            "findings":
                self.findings

        }


        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )


        print(
            f"[+] Report saved to {filename}"
        )