import html as html_utils
from datetime import datetime


class HTMLReporter:

    @staticmethod
    def generate(
        findings,
        filename="report.html",
        target_url="N/A",
        links_found=0,
        forms_found=0,
        payloads_tested=0,
        scan_start_time=None,
        scan_end_time=None,
        payload_reflections=None,
        unique_findings=None,
        raw_findings=None,
        payload_library=None,
        injection_points=None
    ):

        # ============================================================
        # CSS
        # ============================================================

        styles = """
        <style>

            :root {
                --bg-dark: #0b0c10;
                --bg-card: #1f2833;
                --text-main: #c5c6c7;
                --accent-cyan: #66fcf1;
                --accent-teal: #45a29e;

                --badge-get: #ffc107;
                --badge-post: #dc3545;

                --critical: #ff4d4d;
                --high: #ff8c00;
                --medium: #ffbf00;
                --low: #00c853;

                --success: #00c853;
                --danger: #ff4d4d;
            }


            * {
                box-sizing: border-box;
            }


            body {
                background-color: var(--bg-dark);
                color: var(--text-main);
                font-family: 'Segoe UI', sans-serif;
                padding: 20px;
            }


            .container {
                max-width: 1200px;
                margin: 0 auto;
            }


            .header {
                text-align: center;
                margin-bottom: 40px;
                border-bottom: 2px solid var(--accent-teal);
                padding-bottom: 20px;
            }


            .header h1 {
                color: var(--accent-cyan);
                text-transform: uppercase;
                letter-spacing: 2px;
            }


            .header p {
                color: var(--accent-teal);
            }


            .stats-card,
            .endpoint-summary-card,
            .severity-stats-card,
            .scan-info-card,
            .scan-timing-card,
            .most-vuln-card {
                background-color: var(--bg-card);
                padding: 25px;
                border-radius: 8px;
                margin-bottom: 30px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.4);
            }


            .stats-card {
                border-left: 5px solid var(--accent-cyan);
            }


            .severity-stats-card {
                border-left: 5px solid #ff4d4d;
            }


            .scan-info-card {
                border-left: 5px solid var(--accent-cyan);
            }


            .endpoint-summary-card {
                border-left: 5px solid var(--accent-teal);
            }


            h2 {
                color: var(--accent-cyan);
                border-bottom: 1px solid #2c3e50;
                padding-bottom: 12px;
                margin-bottom: 20px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }


            .severity-grid,
            .scan-info-grid,
            .scan-timing-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit,minmax(200px,1fr));
                gap: 15px;
            }


            .severity-tile,
            .scan-info-tile {
                padding: 18px;
                border-radius: 8px;
                text-align: center;
            }


            .scan-info-tile {
                background-color: rgba(69, 162, 158, 0.05);
                border: 1px solid #2c3e50;
            }


            .severity-tile-count {
                font-size: 2rem;
                font-weight: bold;
                margin-top: 8px;
            }


            .severity-tile-critical {
                border: 1px solid var(--critical);
            }


            .severity-tile-high {
                border: 1px solid var(--high);
            }


            .severity-tile-medium {
                border: 1px solid var(--medium);
            }


            .severity-tile-low {
                border: 1px solid var(--low);
            }


            .severity-critical-color {
                color: var(--critical);
            }


            .severity-high-color {
                color: var(--high);
            }


            .severity-medium-color {
                color: var(--medium);
            }


            .severity-low-color {
                color: var(--low);
            }


            table {
                width: 100%;
                border-collapse: collapse;
                background-color: var(--bg-card);
            }


            th {
                background: #121212;
                color: var(--accent-cyan);
                padding: 15px;
                text-align: left;
            }


            td {
                padding: 15px;
                border-bottom: 1px solid #2c3e50;
                vertical-align: top;
            }


            .payload-box,
            .evidence-box {
                background: #000;
                color: #00ff00;
                padding: 10px;
                border-radius: 4px;
                font-family: monospace;
                word-break: break-word;
                white-space: pre-wrap;
            }


            .evidence-box {
                color: #c5c6c7;
                max-height: 180px;
                overflow-y: auto;
            }


            .method-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 4px;
                color: #000;
                font-weight: bold;
            }


            .meta-info {
                display: flex;
                flex-direction: column;
                gap: 8px;
            }


            .summary-row {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 15px;
                padding: 12px;
                border-bottom: 1px solid #2c3e50;
            }


            .summary-count-badge,
            .endpoint-group-count {
                color: var(--accent-cyan);
                border: 1px solid var(--accent-teal);
                padding: 4px 14px;
                border-radius: 20px;
                white-space: nowrap;
            }


            .timestamp-badge {
                display: inline-block;
                margin-top: 10px;
                border: 1px solid var(--accent-teal);
                padding: 8px 18px;
                border-radius: 20px;
                color: var(--accent-cyan);
            }


            /* =========================================================
               Severity Progress Bars
               ========================================================= */

            .severity-progress-section {
                margin-top: 25px;
                padding-top: 20px;
                border-top: 1px solid #2c3e50;
            }


            .severity-progress-section h3 {
                color: var(--accent-cyan);
                font-size: 0.95rem;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 15px;
            }


            .progress-row {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 12px;
            }


            .progress-label {
                min-width: 80px;
                font-size: 0.82rem;
                font-weight: bold;
                text-transform: uppercase;
            }


            .progress-bar-bg {
                flex: 1;
                height: 20px;
                background-color: #121212;
                border-radius: 10px;
                overflow: hidden;
            }


            .progress-bar-fill {
                height: 100%;
                border-radius: 10px;
                transition: width 1.5s ease-out;
            }


            .progress-bar-fill.critical {
                background: linear-gradient(
                    90deg,
                    #ff4d4d,
                    #ff1a1a
                );
            }


            .progress-bar-fill.high {
                background: linear-gradient(
                    90deg,
                    #ff8c00,
                    #ff6600
                );
            }


            .progress-bar-fill.medium {
                background: linear-gradient(
                    90deg,
                    #ffbf00,
                    #ffa500
                );
            }


            .progress-bar-fill.low {
                background: linear-gradient(
                    90deg,
                    #00c853,
                    #00a844
                );
            }


            .progress-pct {
                min-width: 55px;
                font-size: 0.82rem;
                color: var(--text-main);
                text-align: right;
            }


            /* =========================================================
               Most Vulnerable Endpoint
               ========================================================= */

            .most-vuln-card {
                background:
                    linear-gradient(
                        135deg,
                        rgba(255, 0, 0, 0.08),
                        rgba(255, 77, 77, 0.03)
                    );

                border: 1px solid rgba(255, 77, 77, 0.3);
                border-left: 5px solid #ff4d4d;

                display: flex;
                justify-content: space-between;
                align-items: center;
            }


            .most-vuln-card h2 {
                color: #ff4d4d;
                margin: 0 0 8px 0;
                font-size: 1.1rem;
                border: none;
                padding: 0;
            }


            .most-vuln-url {
                font-family: 'Courier New', monospace;
                color: #fff;
                font-size: 1rem;
                word-break: break-all;
            }


            .most-vuln-count {
                font-size: 2.5rem;
                font-weight: bold;
                color: #ff4d4d;
                text-align: center;
            }


            .most-vuln-count-label {
                font-size: 0.75rem;
                color: #888;
                text-transform: uppercase;
            }


            .most-vuln-sev-badge {
                display: inline-block;
                margin-top: 6px;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 0.8rem;
                font-weight: bold;
            }


            .sev-badge-critical {
                background: rgba(255,0,0,0.15);
                color: #ff4d4d;
                border: 1px solid rgba(255,77,77,0.4);
            }


            .sev-badge-high {
                background: rgba(255,140,0,0.15);
                color: #ff8c00;
                border: 1px solid rgba(255,165,0,0.4);
            }


            .sev-badge-medium {
                background: rgba(255,191,0,0.15);
                color: #ffbf00;
                border: 1px solid rgba(255,191,0,0.4);
            }


            .sev-badge-low {
                background: rgba(0,200,83,0.15);
                color: #00c853;
                border: 1px solid rgba(0,200,83,0.4);
            }


            /* =========================================================
               Scan Timing
               ========================================================= */

            .scan-timing-card {
                border-left: 5px solid var(--accent-teal);
            }


            .scan-timing-card h2 {
                color: var(--accent-cyan);
            }


            .scan-timing-tile {
                background-color: rgba(69, 162, 158, 0.05);
                border: 1px solid #2c3e50;
                padding: 16px 20px;
                border-radius: 8px;
                text-align: center;
            }


            .scan-timing-label {
                font-size: 0.8rem;
                color: #888;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 6px;
            }


            .scan-timing-value {
                font-size: 1.1rem;
                color: #fff;
                font-weight: bold;
                word-break: break-all;
            }


            /* =========================================================
               Endpoint Groups
               ========================================================= */

            .endpoint-group {
                margin-bottom: 15px;
                border: 1px solid #2c3e50;
                border-radius: 8px;
                overflow: hidden;
                transition: border-color 0.2s ease;
            }


            .endpoint-group:hover {
                border-color: var(--accent-teal);
            }


            .endpoint-group-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 14px 20px;
                background:
                    linear-gradient(
                        135deg,
                        rgba(69, 162, 158, 0.1),
                        rgba(69, 162, 158, 0.03)
                    );
                cursor: pointer;
                user-select: none;
            }


            .endpoint-group-header:hover {
                background:
                    linear-gradient(
                        135deg,
                        rgba(69, 162, 158, 0.18),
                        rgba(69, 162, 158, 0.06)
                    );
            }


            .endpoint-group-header .arrow {
                color: var(--accent-cyan);
                transition: transform 0.3s ease;
                font-size: 0.9rem;
                margin-right: 12px;
            }


            .endpoint-group.open .arrow {
                transform: rotate(90deg);
            }


            .endpoint-group-title {
                font-family: 'Courier New', monospace;
                color: #fff;
                font-size: 0.92rem;
                word-break: break-all;
            }


            .endpoint-group-body {
                display: none;
                padding: 0;
            }


            .endpoint-group.open .endpoint-group-body {
                display: block;
            }


            .endpoint-group-body table {
                margin: 0;
                border-radius: 0;
                box-shadow: none;
            }


            /* =========================================================
               Detection Details
               ========================================================= */

            .finding-details {
                margin-top: 12px;
                padding-top: 12px;
                border-top: 1px solid #2c3e50;
            }


            .detail-grid {
                display: grid;
                grid-template-columns:
                    repeat(auto-fit, minmax(150px, 1fr));
                gap: 10px;
                margin-bottom: 15px;
            }


            .detail-item {
                background: rgba(69, 162, 158, 0.05);
                border: 1px solid #2c3e50;
                border-radius: 6px;
                padding: 10px;
            }


            .detail-label {
                display: block;
                color: #888;
                font-size: 0.72rem;
                text-transform: uppercase;
                margin-bottom: 5px;
            }


            .detail-value {
                color: #fff;
                font-weight: bold;
                word-break: break-word;
            }


            .status-yes {
                color: var(--success);
            }


            .status-no {
                color: var(--danger);
            }


            .confidence-low {
                color: var(--low);
            }


            .confidence-medium {
                color: var(--medium);
            }


            .confidence-high {
                color: var(--high);
            }


            .reason-box {
                background: rgba(102, 252, 241, 0.04);
                border-left: 3px solid var(--accent-cyan);
                padding: 12px;
                margin-bottom: 12px;
                line-height: 1.5;
            }


            .browser-status {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 12px;
                font-size: 0.75rem;
                font-weight: bold;
            }


            .browser-not-verified {
                color: #ffbf00;
                border: 1px solid #ffbf00;
                background: rgba(255,191,0,0.08);
            }


            .browser-verified {
                color: #00c853;
                border: 1px solid #00c853;
                background: rgba(0,200,83,0.08);
            }


            .potential-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 12px;
                color: #ffbf00;
                border: 1px solid #ffbf00;
                background: rgba(255,191,0,0.08);
                font-size: 0.75rem;
                font-weight: bold;
            }


            .context-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 12px;
                color: var(--accent-cyan);
                border: 1px solid var(--accent-teal);
                background: rgba(69,162,158,0.08);
                font-size: 0.75rem;
                font-weight: bold;
            }



            /* =========================================================
               Browser Verification Summary
               ========================================================= */

            .verification-card {
                background:
                    linear-gradient(
                        135deg,
                        rgba(0, 200, 83, 0.08),
                        rgba(69, 162, 158, 0.03)
                    );
                border: 1px solid rgba(0, 200, 83, 0.35);
                border-left: 5px solid var(--success);
                padding: 25px;
                border-radius: 8px;
                margin-bottom: 30px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.4);
            }

            .verification-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit,minmax(180px,1fr));
                gap: 15px;
                margin-top: 18px;
            }

            .verification-tile {
                background-color: rgba(0, 200, 83, 0.04);
                border: 1px solid #2c3e50;
                padding: 18px;
                border-radius: 8px;
                text-align: center;
            }

            .verification-label {
                display: block;
                color: #888;
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.7px;
                margin-bottom: 8px;
            }

            .verification-value {
                font-size: 1.8rem;
                font-weight: bold;
            }

            .verification-confirmed {
                color: var(--success);
            }

            .verification-warning {
                color: var(--medium);
            }

            .verification-danger {
                color: var(--danger);
            }

            .confirmed-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 12px;
                color: var(--success);
                border: 1px solid var(--success);
                background: rgba(0,200,83,0.08);
                font-size: 0.75rem;
                font-weight: bold;
            }

            .not-confirmed-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 12px;
                color: var(--medium);
                border: 1px solid var(--medium);
                background: rgba(255,191,0,0.08);
                font-size: 0.75rem;
                font-weight: bold;
            }

            .verification-reason-box {
                background: rgba(0, 200, 83, 0.04);
                border-left: 3px solid var(--success);
                padding: 12px;
                margin-top: 12px;
                line-height: 1.5;
            }


            @media (max-width: 700px) {

                body {
                    padding: 10px;
                }

                .most-vuln-card {
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 20px;
                }

                .summary-row {
                    flex-direction: column;
                    align-items: flex-start;
                }

                table {
                    display: block;
                    overflow-x: auto;
                }

            }

        </style>
        """


        # ============================================================
        # Helper Functions
        # ============================================================

        def get_method_badge(method):

            method = str(
                method or "GET"
            ).upper()

            color = (
                "var(--badge-post)"
                if method == "POST"
                else "var(--badge-get)"
            )

            return f"""
            <span class="method-badge"
                  style="background:{color}">
                {html_utils.escape(method)}
            </span>
            """


        def get_severity_level(finding):

            severity = finding.get(
                "severity"
            )

            if severity:
                return str(
                    severity
                ).upper()

            xss_type = finding.get(
                "type",
                "Reflected XSS"
            )

            if xss_type == "Stored XSS":
                return "CRITICAL"

            elif xss_type == "DOM XSS":
                return "MEDIUM"

            return "HIGH"


        def yes_no(value):

            return (
                '<span class="status-yes">YES</span>'
                if value
                else '<span class="status-no">NO</span>'
            )


        def confidence_html(value):

            confidence = str(
                value or "low"
            ).lower()

            return (
                f'<span class="confidence-{confidence}">'
                f'{html_utils.escape(confidence.upper())}'
                f'</span>'
            )


        # ============================================================
        # Finding / Payload Statistics
        # ============================================================
        #
        # Reporter keeps one unique finding per injection point while
        # storing all successful payloads in "successful_payloads".
        # Therefore we can derive payload-level statistics here without
        # changing the existing HTMLReporter call in main.py.
        #

        if unique_findings is None:
            unique_findings = len(findings)

        if raw_findings is None:
            raw_findings = sum(
                int(finding.get("payload_count", 1) or 1)
                for finding in findings
            )

        if payload_reflections is None:
            payload_reflections = raw_findings

        if payload_library is None:
            payload_library = 0

        if injection_points is None:
            injection_points = 0

        # ============================================================
        # Browser Verification Statistics
        # ============================================================
        #
        # BrowserScanner results are stored on each unique finding
        # using the "browser_verified" field. Count unique findings,
        # not individual payloads.
        #

        confirmed_findings = sum(
            1
            for finding in findings
            if bool(
                finding.get(
                    "browser_verified",
                    False
                )
            )
        )

        not_confirmed_findings = sum(
            1
            for finding in findings
            if "browser_verified" in finding
            and not bool(
                finding.get(
                    "browser_verified",
                    False
                )
            )
        )

        not_tested_findings = sum(
            1
            for finding in findings
            if "browser_verified" not in finding
        )

        verified_percentage = (
            round(
                confirmed_findings /
                len(findings) *
                100,
                1
            )
            if findings
            else 0
        )


        # ============================================================
        # Severity Statistics
        # ============================================================

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }


        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    "LOW"
                )
            ).upper()

            if severity in severity_counts:
                severity_counts[severity] += 1


        severity_tiles_html = ""


        severity_tile_map = {

            "CRITICAL": (
                "severity-tile-critical",
                "severity-critical-color"
            ),

            "HIGH": (
                "severity-tile-high",
                "severity-high-color"
            ),

            "MEDIUM": (
                "severity-tile-medium",
                "severity-medium-color"
            ),

            "LOW": (
                "severity-tile-low",
                "severity-low-color"
            )
        }


        for sev_level, count in severity_counts.items():

            tile_class, color_class = (
                severity_tile_map[
                    sev_level
                ]
            )


            severity_tiles_html += f"""
            <div class="severity-tile {tile_class}">

                <div class="{color_class}">
                    {sev_level}
                </div>

                <div class="severity-tile-count {color_class}">
                    {count}
                </div>

            </div>
            """


        # ============================================================
        # Severity Progress Bars
        # ============================================================

        total_findings_count = (
            len(findings)
            if findings
            else 1
        )


        severity_percentages = {

            key: round(
                value /
                total_findings_count *
                100,
                1
            )

            for key, value
            in severity_counts.items()
        }


        progress_bars_html = ""


        progress_bar_map = {

            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low"

        }


        for sev_level, percentage in (
            severity_percentages.items()
        ):

            bar_class = progress_bar_map[
                sev_level
            ]

            count = severity_counts[
                sev_level
            ]


            progress_bars_html += f"""
            <div class="progress-row">

                <span class="progress-label
                             severity-{bar_class}-color">

                    {sev_level}

                </span>

                <div class="progress-bar-bg">

                    <div
                        class="progress-bar-fill {bar_class}"
                        style="width:0%"
                        data-width="{percentage}%">
                    </div>

                </div>

                <span class="progress-pct">
                    {percentage}% ({count})
                </span>

            </div>
            """


        # ============================================================
        # Scan Timing
        # ============================================================

        scan_timestamp = datetime.now().strftime(
            "%d %b %Y, %I:%M:%S %p"
        )


        if scan_start_time:

            if isinstance(
                scan_start_time,
                str
            ):

                scan_start_display = (
                    scan_start_time
                )

            else:

                scan_start_display = (
                    scan_start_time.strftime(
                        "%d %b %Y, %I:%M:%S %p"
                    )
                )

        else:

            scan_start_display = "N/A"


        if scan_end_time:

            if isinstance(
                scan_end_time,
                str
            ):

                scan_end_display = (
                    scan_end_time
                )

            else:

                scan_end_display = (
                    scan_end_time.strftime(
                        "%d %b %Y, %I:%M:%S %p"
                    )
                )

        else:

            scan_end_display = "N/A"


        if (
            scan_start_time
            and
            scan_end_time
        ):

            try:

                if isinstance(
                    scan_start_time,
                    str
                ):

                    start_dt = datetime.strptime(
                        scan_start_time,
                        "%d %b %Y, %I:%M:%S %p"
                    )

                else:

                    start_dt = scan_start_time


                if isinstance(
                    scan_end_time,
                    str
                ):

                    end_dt = datetime.strptime(
                        scan_end_time,
                        "%d %b %Y, %I:%M:%S %p"
                    )

                else:

                    end_dt = scan_end_time


                duration_seconds = round(
                    (
                        end_dt -
                        start_dt
                    ).total_seconds(),
                    2
                )


                scan_duration_display = (
                    f"{duration_seconds:.2f} Seconds"
                )


            except (
                ValueError,
                TypeError
            ):

                scan_duration_display = "N/A"

        else:

            scan_duration_display = "N/A"


        # ============================================================
        # Endpoint Severity Breakdown
        # ============================================================

        endpoint_sev_breakdown = {}


        for finding in findings:

            endpoint = finding.get(
                "url",
                "N/A"
            )

            level = get_severity_level(
                finding
            )


            if endpoint not in endpoint_sev_breakdown:

                endpoint_sev_breakdown[
                    endpoint
                ] = {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                }


            endpoint_sev_breakdown[
                endpoint
            ][level] += 1


        # ============================================================
        # Endpoint Summary
        # ============================================================

        endpoint_summary = {}


        for finding in findings:

            url = finding.get(
                "url"
            )

            endpoint_summary[
                url
            ] = (
                endpoint_summary.get(
                    url,
                    0
                ) + 1
            )


        summary_rows_html = ""


        for endpoint, count in (
            endpoint_summary.items()
        ):

            ep_sevs = endpoint_sev_breakdown.get(
                endpoint,
                {}
            )


            if ep_sevs.get(
                "CRITICAL",
                0
            ) > 0:

                endpoint_severity = "CRITICAL"

            elif ep_sevs.get(
                "HIGH",
                0
            ) > 0:

                endpoint_severity = "HIGH"

            elif ep_sevs.get(
                "MEDIUM",
                0
            ) > 0:

                endpoint_severity = "MEDIUM"

            else:

                endpoint_severity = "LOW"


            summary_rows_html += f"""
            <div class="summary-row">

                <span>
                    {html_utils.escape(
                        str(endpoint)
                    )}
                </span>

                <span class="sev-badge-{endpoint_severity.lower()}">
                    {endpoint_severity}
                </span>

                <span class="summary-count-badge">
                    {count}
                </span>

            </div>
            """


        # ============================================================
        # Most Vulnerable Endpoint
        # ============================================================

        severity_rank = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1
        }


        highest_score = 0
        most_vuln_endpoint = "N/A"
        most_vuln_count = 0
        most_vuln_top_severity = "LOW"


        for endpoint, sev_counts in (
            endpoint_sev_breakdown.items()
        ):

            if sev_counts["CRITICAL"] > 0:

                top_severity = "CRITICAL"

            elif sev_counts["HIGH"] > 0:

                top_severity = "HIGH"

            elif sev_counts["MEDIUM"] > 0:

                top_severity = "MEDIUM"

            else:

                top_severity = "LOW"


            count = sum(
                sev_counts.values()
            )


            score = (
                severity_rank[
                    top_severity
                ] * 100000
                +
                count
            )


            if score > highest_score:

                highest_score = score

                most_vuln_endpoint = endpoint

                most_vuln_count = count

                most_vuln_top_severity = (
                    top_severity
                )


        # ============================================================
        # Endpoint Finding Groups
        # ============================================================

        endpoint_groups = {}


        for finding in findings:

            url = finding.get(
                "url",
                "N/A"
            )


            if url not in endpoint_groups:

                endpoint_groups[url] = []


            endpoint_groups[
                url
            ].append(
                finding
            )


        collapsible_groups_html = ""


        for endpoint_url, endpoint_findings in (
            endpoint_groups.items()
        ):

            escaped_endpoint = html_utils.escape(
                str(endpoint_url)
            )


            group_rows = ""


            for finding in endpoint_findings:

                payload = html_utils.escape(
                    str(
                        finding.get(
                            "payload",
                            "N/A"
                        )
                    )
                )


                method = finding.get(
                    "method",
                    "GET"
                )


                severity = str(
                    finding.get(
                        "severity",
                        "LOW"
                    )
                ).upper()


                xss_type = html_utils.escape(
                    str(
                        finding.get(
                            "type",
                            "Reflected XSS"
                        )
                    )
                )


                reflected = finding.get(
                    "reflected",
                    False
                )


                encoded = finding.get(
                    "encoded",
                    False
                )
                reflection_type = finding.get(
                    "reflection_type",
                    "not reflected"
                )


                context = finding.get(
                    "context",
                    "unknown"
                )


                potential_xss = finding.get(
                    "potential_xss",
                    False
                )


                confidence = finding.get(
                    "confidence",
                    "low"
                )


                reason = finding.get(
                    "reason",
                    ""
                )


                evidence = finding.get(
                    "evidence",
                    ""
                )


                browser_verified = finding.get(
                    "browser_verified",
                    False
                )

                confirmed_xss = finding.get(
                    "confirmed_xss",
                    False
                )

                verification = finding.get(
                    "verification",
                    ""
                )

                verification_reason = finding.get(
                    "verification_reason",
                    ""
                )

                alert_text = finding.get(
                    "alert_text",
                    None
                )

                # Machine-readable reflection metadata.
                # These attributes allow validation tools/tests to verify
                # the exact detector fields without changing the visual UI.
                reflection_type_value = html_utils.escape(
                    str(reflection_type)
                )
                reflected_value = str(bool(reflected))
                encoded_value = str(bool(encoded))
                potential_xss_value = str(bool(potential_xss))
                context_value = html_utils.escape(
                    str(context)
                )

                browser_verified_value = str(bool(browser_verified))
                confirmed_xss_value = str(bool(confirmed_xss))
                verification_value = html_utils.escape(str(verification))
                verification_reason_value = html_utils.escape(
                    str(verification_reason)
                )


                browser_status = (
                    '<span class="browser-status '
                    'browser-verified">'
                    'VERIFIED'
                    '</span>'
                    if browser_verified
                    else
                    '<span class="browser-status '
                    'browser-not-verified">'
                    'NOT VERIFIED'
                    '</span>'
                )


                potential_status = (
                    '<span class="potential-badge">'
                    'POTENTIAL XSS'
                    '</span>'
                    if potential_xss
                    else
                    '<span class="context-badge">'
                    'NOT POTENTIAL'
                    '</span>'
                )


                group_rows += f"""
                <tr>

                    <td>
                        {get_method_badge(method)}
                    </td>

                    <td>
                        <div class="meta-info">

                            <strong>
                                {xss_type}
                            </strong>

                            <strong>
                                {html_utils.escape(
                                    severity
                                )}
                            </strong>

                            {potential_status}

                        </div>
                    </td>


                    <td>

                        <div class="payload-box">
                            {payload}
                        </div>

                        <div style="margin-top:8px;color:#888;font-size:0.78rem;">
                            Successful payloads for this injection point:
                            <strong style="color:var(--accent-cyan);">
                                {finding.get("payload_count", 1)}
                            </strong>
                        </div>


                        <div class="finding-details">

                            <div
                                class="report-metadata"
                                data-field="reflection_type"
                                data-reflection_type="{reflection_type_value}"
                                data-reflected="{reflected_value}"
                                data-encoded="{encoded_value}"
                                data-context="{context_value}"
                                data-potential_xss="{potential_xss_value}"
                                data-reflection-type-value="{reflection_type_value}"
                                data-reflected-bool="{reflected_value}"
                                data-browser-verified="{browser_verified_value}"
                                data-confirmed-xss="{confirmed_xss_value}"
                                data-verification="{verification_value}"
                                data-verification-reason="{verification_reason_value}"
                            >
                                reflection_type={reflection_type_value}
                                reflected={reflected_value}
                                encoded={encoded_value}
                                context={context_value}
                                potential_xss={potential_xss_value}
                                browser_verified={browser_verified_value}
                                confirmed_xss={confirmed_xss_value}
                                verification={verification_value}
                                verification_reason={verification_reason_value}
                                Browser Verified={browser_verified_value}
                                Confirmed XSS={confirmed_xss_value}
                                Verification={verification_value}
                            </div>

                            <div class="detail-grid">

                                <div class="detail-item">

                                    <span class="detail-label">
                                        Reflection
                                    </span>

                                    <span class="detail-value">
                                        {yes_no(reflected)}
                                    </span>

                                </div>


                                <div class="detail-item">

                                    <span class="detail-label">
                                        Encoding
                                    </span>

                                    <span class="detail-value">
                                        {yes_no(encoded)}
                                    </span>

                                </div>


                                <div class="detail-item">

                                    <span class="detail-label">
                                        Reflection Type
                                    </span>

                                    <span class="detail-value">
                                        {reflection_type_value}
                                    </span>

                                </div>


                                <div class="detail-item">

                                    <span class="detail-label">
                                        Context
                                    </span>

                                    <span class="detail-value">
                                        <span class="context-badge">
                                            {html_utils.escape(
                                                str(context)
                                            )}
                                        </span>
                                    </span>

                                </div>


                                <div class="detail-item">

                                    <span class="detail-label">
                                        Confidence
                                    </span>

                                    <span class="detail-value">
                                        {confidence_html(
                                            confidence
                                        )}
                                    </span>

                                </div>


                                <div class="detail-item">

                                    <span class="detail-label">
                                        Browser Verification
                                    </span>

                                    <span class="detail-value">
                                        {browser_status}
                                    </span>

                                </div>

                            </div>


                            <div class="reason-box">

                                <strong>
                                    Detection Reason
                                </strong>

                                <br>

                                {html_utils.escape(
                                    str(reason)
                                )}

                            </div>


                            <div>

                                <strong>
                                    Response Evidence
                                </strong>

                                <div class="evidence-box">
                                    {html_utils.escape(
                                        str(evidence)
                                    )}
                                </div>

                            </div>

                            {(
                                f'''
                                <div class="verification-reason-box">
                                    <strong>Browser Verification Result</strong>
                                    <br>
                                    {html_utils.escape(str(verification_reason))}
                                </div>
                                '''
                                if verification_reason
                                else ""
                            )}

                            {(
                                f'''
                                <div style="margin-top:10px;">
                                    <strong>Alert Text:</strong>
                                    <span style="color:var(--success);">
                                        {html_utils.escape(str(alert_text))}
                                    </span>
                                </div>
                                '''
                                if alert_text is not None
                                else ""
                            )}

                        </div>

                    </td>

                </tr>
                """


            collapsible_groups_html += f"""
            <div class="endpoint-group">

                <div
                    class="endpoint-group-header"
                    onclick="
                        this.parentElement.classList.toggle('open')
                    "
                >

                    <div
                        style="
                            display:flex;
                            align-items:center;
                        "
                    >

                        <i class="arrow">
                            &#9654;
                        </i>

                        <span class="endpoint-group-title">
                            {escaped_endpoint}
                        </span>

                    </div>


                    <span class="endpoint-group-count">
                        {len(endpoint_findings)} unique findings
                    </span>

                </div>


                <div class="endpoint-group-body">

                    <table>

                        <thead>

                            <tr>

                                <th>
                                    Method
                                </th>

                                <th>
                                    Finding
                                </th>

                                <th>
                                    Detection Details
                                </th>

                            </tr>

                        </thead>


                        <tbody>

                            {group_rows}

                        </tbody>

                    </table>

                </div>

            </div>
            """


        # ============================================================
        # Final HTML
        # ============================================================

        html = f"""
<!DOCTYPE html>

<html>

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>
        XSS Vulnerability Report
    </title>

    {styles}

</head>


<body>

<div class="container">


    <!-- =========================================================
         HEADER
         ========================================================= -->

    <div class="header">

        <h1>
            ⚙ XSS Vulnerability Report
        </h1>

        <p>
            Automated Security Scan Results
        </p>

        <div class="timestamp-badge">

            Scan Generated:
            {scan_timestamp}

        </div>

    </div>


    <!-- =========================================================
         TOTAL FINDINGS
         ========================================================= -->

    <div class="stats-card">

        <div>

            <h2>
                Unique Findings:
                {unique_findings}
            </h2>

            <p>
                Unique injection-point findings identified by
                static HTTP analysis
            </p>

            <p style="color:#888;">
                Payload-level reflections:
                <strong>{payload_reflections}</strong>
                &nbsp; | &nbsp;
                Raw payload findings:
                <strong>{raw_findings}</strong>
            </p>

        </div>

    </div>


    <!-- =========================================================
         SEVERITY STATISTICS
         ========================================================= -->

    <div class="severity-stats-card">

        <h2>
            Severity Statistics
        </h2>


        <div class="severity-grid">

            {severity_tiles_html}

        </div>


        <div class="severity-progress-section">

            <h3>
                Severity Distribution
            </h3>

            {progress_bars_html}

        </div>

    </div>


    <!-- =========================================================
         BROWSER VERIFICATION
         ========================================================= -->

    <div class="verification-card">

        <h2 style="color:var(--success);">
            Browser Verification
        </h2>

        <p style="color:#aaa;">
            Selenium browser verification checks whether JavaScript
            execution occurred for each unique injection point.
        </p>

        <div class="verification-grid">

            <div class="verification-tile">
                <span class="verification-label">
                    Confirmed XSS
                </span>
                <div class="verification-value verification-confirmed">
                    {confirmed_findings}
                </div>
            </div>

            <div class="verification-tile">
                <span class="verification-label">
                    Not Confirmed
                </span>
                <div class="verification-value verification-warning">
                    {not_confirmed_findings}
                </div>
            </div>

            <div class="verification-tile">
                <span class="verification-label">
                    Not Tested
                </span>
                <div class="verification-value verification-danger">
                    {not_tested_findings}
                </div>
            </div>

            <div class="verification-tile">
                <span class="verification-label">
                    Verification Rate
                </span>
                <div class="verification-value verification-confirmed">
                    {verified_percentage}%
                </div>
            </div>

        </div>

    </div>


    <!-- =========================================================
         SCAN INFORMATION
         ========================================================= -->

    <div class="scan-info-card">

        <h2>
            Scan Information
        </h2>


        <div class="scan-info-grid">

            <div class="scan-info-tile">

                <strong>
                    Target URL
                </strong>

                <br>

                {html_utils.escape(
                    str(target_url)
                )}

            </div>


            <div class="scan-info-tile">

                <strong>
                    Links Found
                </strong>

                <br>

                {links_found}

            </div>


            <div class="scan-info-tile">

                <strong>
                    Forms Found
                </strong>

                <br>

                {forms_found}

            </div>


            <div class="scan-info-tile">

                <strong>
                    Payload Library
                </strong>

                <br>

                {payload_library}

            </div>


            <div class="scan-info-tile">

                <strong>
                    Injection Points
                </strong>

                <br>

                {injection_points}

            </div>


            <div class="scan-info-tile">

                <strong>
                    Payload Tests
                </strong>

                <br>

                {payloads_tested}

            </div>


            <div class="scan-info-tile">

                <strong>
                    Reflections
                </strong>

                <br>

                {payload_reflections}

            </div>


            <div class="scan-info-tile">

                <strong>
                    Unique Findings
                </strong>

                <br>

                {unique_findings}

            </div>

        </div>

    </div>


    <!-- =========================================================
         SCAN TIMING
         ========================================================= -->

    <div class="scan-timing-card">

        <h2>
            Scan Timing
        </h2>


        <div class="scan-timing-grid">


            <div class="scan-timing-tile">

                <div class="scan-timing-label">
                    Start Time
                </div>

                <div class="scan-timing-value">

                    {html_utils.escape(
                        scan_start_display
                    )}

                </div>

            </div>


            <div class="scan-timing-tile">

                <div class="scan-timing-label">
                    End Time
                </div>

                <div class="scan-timing-value">

                    {html_utils.escape(
                        scan_end_display
                    )}

                </div>

            </div>


            <div class="scan-timing-tile">

                <div class="scan-timing-label">
                    Duration
                </div>

                <div class="scan-timing-value">

                    {html_utils.escape(
                        scan_duration_display
                    )}

                </div>

            </div>


        </div>

    </div>


    <!-- =========================================================
         MOST VULNERABLE ENDPOINT
         ========================================================= -->

    <div class="most-vuln-card">

        <div>

            <h2>
                Most Vulnerable Endpoint
            </h2>


            <div class="most-vuln-url">

                {html_utils.escape(
                    str(most_vuln_endpoint)
                )}

            </div>


            <span
                class="
                    most-vuln-sev-badge
                    sev-badge-{most_vuln_top_severity.lower()}
                "
            >

                {most_vuln_top_severity}

            </span>

        </div>


        <div style="text-align:center;">

            <div class="most-vuln-count">

                {most_vuln_count}

            </div>

            <div class="most-vuln-count-label">

                Findings

            </div>

        </div>

    </div>


    <!-- =========================================================
         ENDPOINT SUMMARY
         ========================================================= -->

    <div class="endpoint-summary-card">

        <h2>
            Endpoint Summary
        </h2>

        {summary_rows_html}

    </div>


    <!-- =========================================================
         FINDINGS
         ========================================================= -->

    <div
        class="severity-stats-card"
        style="border-left:5px solid var(--accent-teal);"
    >

        <h2>
            Vulnerability Findings
        </h2>


        <p style="color:#888;">

            Findings are deduplicated by injection point.
            Multiple successful payloads can belong to one unique finding.
            Browser verification status is shown for every unique finding.
            Confirmed findings indicate that Selenium detected JavaScript execution.

        </p>


        {collapsible_groups_html}

    </div>


</div>


<div style="
    max-width:1200px;
    margin:0 auto;
    padding:0 20px 30px 20px;
    color:#666;
    text-align:center;
    font-size:0.75rem;
">
    Generated by ShadowXSS automated security scanner
</div>


<!-- =============================================================
     JAVASCRIPT
     ============================================================= -->

<script>

document.addEventListener(
    'DOMContentLoaded',
    function() {{

        setTimeout(
            function() {{

                var bars =
                    document.querySelectorAll(
                        '.progress-bar-fill'
                    );


                bars.forEach(
                    function(bar) {{

                        var width =
                            bar.getAttribute(
                                'data-width'
                            );


                        bar.style.width =
                            width;

                    }}
                );

            }},
            300
        );

    }}
);

</script>


</body>

</html>
"""


        # ============================================================
        # Write Report
        # ============================================================

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                html
            )


        print(
            f"[+] Styled HTML Report Saved: {filename}"
        )