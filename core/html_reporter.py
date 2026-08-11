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
        scan_end_time=None
    ):

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

            .stats-card,
            .endpoint-summary-card,
            .severity-stats-card,
            .scan-info-card {
                background-color: var(--bg-card);
                padding: 25px;
                border-radius: 8px;
                margin-bottom: 30px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.4);
            }

            .stats-card {
                border-left: 5px solid var(--accent-cyan);
                display: flex;
                justify-content: space-between;
                align-items: center;
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
            .scan-info-grid {
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

            .severity-tile-count {
                font-size: 2rem;
                font-weight: bold;
            }

            .severity-tile-critical {
                border: 1px solid #ff4d4d;
            }

            .severity-tile-high {
                border: 1px solid #ff8c00;
            }

            .severity-tile-medium {
                border: 1px solid #ffbf00;
            }

            .severity-tile-low {
                border: 1px solid #00c853;
            }

            .severity-critical-color {
                color: #ff4d4d;
            }

            .severity-high-color {
                color: #ff8c00;
            }

            .severity-medium-color {
                color: #ffbf00;
            }

            .severity-low-color {
                color: #00c853;
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
            }

            .payload-box {
                background: #000;
                color: #00ff00;
                padding: 10px;
                border-radius: 4px;
                font-family: monospace;
            }

            .method-badge {
                padding: 5px 10px;
                border-radius: 4px;
                color: #000;
                font-weight: bold;
            }

            .meta-info {
                display: flex;
                flex-direction: column;
                gap: 6px;
            }

            .summary-row {
                display: flex;
                justify-content: space-between;
                padding: 12px;
                border-bottom: 1px solid #2c3e50;
            }

            .summary-count-badge {
                color: var(--accent-cyan);
                border: 1px solid var(--accent-teal);
                padding: 4px 14px;
                border-radius: 20px;
            }

            .timestamp-badge {
                display: inline-block;
                margin-top: 10px;
                border: 1px solid var(--accent-teal);
                padding: 8px 18px;
                border-radius: 20px;
                color: var(--accent-cyan);
            }

            /* =============================================
               Severity Progress Bars (#1)
               ============================================= */
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
            .progress-bar-fill.critical { background: linear-gradient(90deg, #ff4d4d, #ff1a1a); }
            .progress-bar-fill.high { background: linear-gradient(90deg, #ff8c00, #ff6600); }
            .progress-bar-fill.medium { background: linear-gradient(90deg, #ffbf00, #ffa500); }
            .progress-bar-fill.low { background: linear-gradient(90deg, #00c853, #00a844); }
            .progress-pct {
                min-width: 55px;
                font-size: 0.82rem;
                color: var(--text-main);
                text-align: right;
            }

            /* =============================================
               Most Vulnerable Endpoint Card (#2)
               ============================================= */
            .most-vuln-card {
                background: linear-gradient(135deg, rgba(255, 0, 0, 0.08), rgba(255, 77, 77, 0.03));
                border: 1px solid rgba(255, 77, 77, 0.3);
                border-left: 5px solid #ff4d4d;
                padding: 25px 30px;
                border-radius: 8px;
                margin-bottom: 30px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.4);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .most-vuln-card h2 {
                color: #ff4d4d;
                margin: 0 0 8px 0;
                font-size: 1.1rem;
                text-transform: uppercase;
                letter-spacing: 1px;
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
            .sev-badge-critical { background: rgba(255,0,0,0.15); color: #ff4d4d; border: 1px solid rgba(255,77,77,0.4); }
            .sev-badge-high { background: rgba(255,140,0,0.15); color: #ff8c00; border: 1px solid rgba(255,165,0,0.4); }
            .sev-badge-medium { background: rgba(255,191,0,0.15); color: #ffbf00; border: 1px solid rgba(255,191,0,0.4); }
            .sev-badge-low { background: rgba(0,200,83,0.15); color: #00c853; border: 1px solid rgba(0,200,83,0.4); }

            /* =============================================
               Scan Timing Card (#3)
               ============================================= */
            .scan-timing-card {
                background-color: var(--bg-card);
                border-left: 5px solid var(--accent-teal);
                padding: 25px 30px;
                border-radius: 8px;
                margin-bottom: 30px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.4);
            }
            .scan-timing-card h2 {
                color: var(--accent-cyan);
                border-bottom: 1px solid #2c3e50;
                padding-bottom: 12px;
                margin-bottom: 20px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .scan-timing-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
            }
            .scan-timing-tile {
                background-color: rgba(69, 162, 158, 0.05);
                border: 1px solid #2c3e50;
                padding: 16px 20px;
                border-radius: 8px;
                text-align: center;
                transition: border-color 0.2s ease;
            }
            .scan-timing-tile:hover {
                border-color: var(--accent-teal);
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

            /* =============================================
               Collapsible Endpoint Groups (#4)
               ============================================= */
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
                background: linear-gradient(135deg, rgba(69, 162, 158, 0.1), rgba(69, 162, 158, 0.03));
                cursor: pointer;
                user-select: none;
                transition: background-color 0.2s ease;
            }
            .endpoint-group-header:hover {
                background: linear-gradient(135deg, rgba(69, 162, 158, 0.18), rgba(69, 162, 158, 0.06));
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
            .endpoint-group-count {
                color: var(--accent-cyan);
                border: 1px solid var(--accent-teal);
                padding: 4px 14px;
                border-radius: 20px;
                font-weight: bold;
                font-size: 0.9rem;
                white-space: nowrap;
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
        </style>
        """

        def get_method_badge(method):
            color = (
                "var(--badge-post)"
                if method.upper() == "POST"
                else "var(--badge-get)"
            )
            return f"""
            <span class="method-badge" style="background:{color}">
                {method.upper()}
            </span>
            """

        # Helper to determine severity level from finding
        def get_severity_level(finding):
            sev = finding.get("severity", None)
            if sev:
                return sev.upper()
            xss_type = finding.get("type", "Reflected XSS")
            if xss_type == "Stored XSS":
                return "CRITICAL"
            elif xss_type == "DOM XSS":
                return "MEDIUM"
            return "HIGH"

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in severity_counts:
                severity_counts[severity] += 1

        severity_tiles_html = ""
        severity_tile_map = {
            "CRITICAL": ("severity-tile-critical", "severity-critical-color"),
            "HIGH": ("severity-tile-high", "severity-high-color"),
            "MEDIUM": ("severity-tile-medium", "severity-medium-color"),
            "LOW": ("severity-tile-low", "severity-low-color")
        }

        for sev_level, count in severity_counts.items():
            tile_class, color_class = severity_tile_map[sev_level]
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

        # =============================================
        # Severity Progress Bars (#1)
        # =============================================
        total_findings_count = len(findings) if findings else 1
        severity_percentages = {
            k: round(v / total_findings_count * 100, 1)
            for k, v in severity_counts.items()
        }

        progress_bars_html = ""
        progress_bar_map = {
            "CRITICAL": ("severity-critical-color", "critical"),
            "HIGH": ("severity-high-color", "high"),
            "MEDIUM": ("severity-medium-color", "medium"),
            "LOW": ("severity-low-color", "low"),
        }
        for sev_level, pct in severity_percentages.items():
            color_class, bar_class = progress_bar_map[sev_level]
            count = severity_counts[sev_level]
            progress_bars_html += f"""
            <div class="progress-row">
                <span class="progress-label {color_class}">{sev_level}</span>
                <div class="progress-bar-bg">
                    <div class="progress-bar-fill {bar_class}" style="width: 0%" data-width="{pct}%"></div>
                </div>
                <span class="progress-pct">{pct}% ({count})</span>
            </div>
            """

        scan_timestamp = datetime.now().strftime("%d %b %Y, %I:%M:%S %p")

        # =============================================
        # Scan Timing Information (#3)
        # =============================================
        if scan_start_time:
            if isinstance(scan_start_time, str):
                scan_start_display = scan_start_time
            else:
                scan_start_display = scan_start_time.strftime("%d %b %Y, %I:%M:%S %p")
        else:
            scan_start_display = "N/A"

        if scan_end_time:
            if isinstance(scan_end_time, str):
                scan_end_display = scan_end_time
            else:
                scan_end_display = scan_end_time.strftime("%d %b %Y, %I:%M:%S %p")
        else:
            scan_end_display = "N/A"

        if scan_start_time and scan_end_time:
            try:
                if isinstance(scan_start_time, str):
                    start_dt = datetime.strptime(scan_start_time, "%d %b %Y, %I:%M:%S %p")
                else:
                    start_dt = scan_start_time
                if isinstance(scan_end_time, str):
                    end_dt = datetime.strptime(scan_end_time, "%d %b %Y, %I:%M:%S %p")
                else:
                    end_dt = scan_end_time
                scan_duration_seconds = round((end_dt - start_dt).total_seconds(), 2)
                scan_duration_display = f"{scan_duration_seconds:.2f} Seconds"
            except (ValueError, TypeError):
                scan_duration_display = "N/A"
        else:
            scan_duration_display = "N/A"

        endpoint_sev_breakdown = {}
        for finding in findings:
            ep_url = finding.get("url", "N/A")
            level = get_severity_level(finding)
            if ep_url not in endpoint_sev_breakdown:
                endpoint_sev_breakdown[ep_url] = {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                }
            endpoint_sev_breakdown[ep_url][level] += 1

        endpoint_summary = {}
        for finding in findings:
            url = finding.get("url")
            endpoint_summary[url] = endpoint_summary.get(url, 0) + 1

        summary_rows_html = ""
        for endpoint, count in endpoint_summary.items():
            ep_sevs = endpoint_sev_breakdown.get(endpoint, {})
            if ep_sevs.get("CRITICAL", 0) > 0:
                endpoint_severity = "CRITICAL"
            elif ep_sevs.get("HIGH", 0) > 0:
                endpoint_severity = "HIGH"
            elif ep_sevs.get("MEDIUM", 0) > 0:
                endpoint_severity = "MEDIUM"
            else:
                endpoint_severity = "LOW"

            summary_rows_html += f"""
            <div class="summary-row">
                <span>{endpoint}</span>
                <span>{endpoint_severity}</span>
                <span class="summary-count-badge">{count}</span>
            </div>
            """

        # =============================================
        # Most Vulnerable Endpoint (#2)
        # =============================================
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

        for ep, sev_counts in endpoint_sev_breakdown.items():
            if sev_counts["CRITICAL"] > 0:
                top_sev = "CRITICAL"
            elif sev_counts["HIGH"] > 0:
                top_sev = "HIGH"
            elif sev_counts["MEDIUM"] > 0:
                top_sev = "MEDIUM"
            else:
                top_sev = "LOW"

            count = sum(sev_counts.values())
            score = severity_rank[top_sev] * 100000 + count

            if score > highest_score:
                highest_score = score
                most_vuln_endpoint = ep
                most_vuln_count = count
                most_vuln_top_severity = top_sev

        # =============================================
        # Collapsible Endpoint Groups (#4)
        # =============================================
        endpoint_groups = {}
        for finding in findings:
            url = finding.get("url", "N/A")
            if url not in endpoint_groups:
                endpoint_groups[url] = []
            endpoint_groups[url].append(finding)

        collapsible_groups_html = ""
        for ep_url, ep_findings in endpoint_groups.items():
            escaped_ep = html_utils.escape(ep_url)
            group_rows = ""
            for finding in ep_findings:
                payload = html_utils.escape(finding.get("payload", "N/A"))
                method = finding.get("method", "GET")
                severity = finding.get("severity", "LOW")
                group_rows += f"""
                <tr>
                    <td>{get_method_badge(method)}</td>
                    <td>{severity}</td>
                    <td>
                        <div class="payload-box">
                            {payload}
                        </div>
                    </td>
                </tr>
                """

            collapsible_groups_html += f"""
            <div class="endpoint-group">
                <div class="endpoint-group-header" onclick="this.parentElement.classList.toggle('open')">
                    <div style="display:flex;align-items:center;">
                        <i class="arrow">&#9654;</i>
                        <span class="endpoint-group-title">{escaped_ep}</span>
                    </div>
                    <span class="endpoint-group-count">{len(ep_findings)} findings</span>
                </div>
                <div class="endpoint-group-body">
                    <table>
                        <thead>
                            <tr>
                                <th>Method</th>
                                <th>Severity</th>
                                <th>Payload</th>
                            </tr>
                        </thead>
                        <tbody>
                            {group_rows}
                        </tbody>
                    </table>
                </div>
            </div>
            """

        table_rows = ""
        for finding in findings:
            url = finding.get("url")
            payload = html_utils.escape(finding.get("payload"))
            method = finding.get("method")
            xss_type = finding.get("type")
            severity = finding.get("severity", "LOW")

            table_rows += f"""
            <tr>
                <td>{url}</td>
                <td>
                    <div class="meta-info">
                        {get_method_badge(method)}
                        <span>{xss_type}</span>
                        <span>{severity}</span>
                    </div>
                </td>
                <td>
                    <div class="payload-box">
                        {payload}
                    </div>
                </td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS Vulnerability Report</title>
    {styles}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS Vulnerability Report</h1>
            <p>Automated Security Scan Results</p>
            <div class="timestamp-badge">
                Scan Generated: {scan_timestamp}
            </div>
        </div>

        <div class="stats-card">
            <div>
                <h2>Total Findings: {len(findings)}</h2>
            </div>
        </div>

        <div class="severity-stats-card">
            <h2>Severity Statistics</h2>
            <div class="severity-grid">
                {severity_tiles_html}
            </div>
            <div class="severity-progress-section">
                <h3>Severity Distribution</h3>
                {progress_bars_html}
            </div>
        </div>

        <div class="scan-info-card">
            <h2>Scan Information</h2>
            <div class="scan-info-grid">
                <div class="scan-info-tile">{target_url}</div>
                <div class="scan-info-tile">Links: {links_found}</div>
                <div class="scan-info-tile">Forms: {forms_found}</div>
                <div class="scan-info-tile">Payloads: {payloads_tested}</div>
                <div class="scan-info-tile">Findings: {len(findings)}</div>
            </div>
        </div>

        <div class="scan-timing-card">
            <h2>Scan Timing</h2>
            <div class="scan-timing-grid">
                <div class="scan-timing-tile">
                    <div class="scan-timing-label">Start Time</div>
                    <div class="scan-timing-value">{html_utils.escape(scan_start_display)}</div>
                </div>
                <div class="scan-timing-tile">
                    <div class="scan-timing-label">End Time</div>
                    <div class="scan-timing-value">{html_utils.escape(scan_end_display)}</div>
                </div>
                <div class="scan-timing-tile">
                    <div class="scan-timing-label">Duration</div>
                    <div class="scan-timing-value" style="color: var(--accent-cyan);">{html_utils.escape(scan_duration_display)}</div>
                </div>
            </div>
        </div>

        <div class="most-vuln-card">
            <div>
                <h2>Most Vulnerable Endpoint</h2>
                <div class="most-vuln-url">{html_utils.escape(most_vuln_endpoint)}</div>
                <span class="most-vuln-sev-badge sev-badge-{most_vuln_top_severity.lower()}">{most_vuln_top_severity}</span>
            </div>
            <div style="text-align:center;">
                <div class="most-vuln-count">{most_vuln_count}</div>
                <div class="most-vuln-count-label">Findings</div>
            </div>
        </div>

        <div class="endpoint-summary-card">
            <h2>Endpoint Summary</h2>
            {summary_rows_html}
        </div>

        <div class="severity-stats-card" style="border-left: 5px solid var(--accent-teal);">
            <h2>Vulnerability Findings</h2>
            {collapsible_groups_html}
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            setTimeout(function() {{
                var bars = document.querySelectorAll('.progress-bar-fill');
                bars.forEach(function(bar) {{
                    var w = bar.getAttribute('data-width');
                    bar.style.width = w;
                }});
            }}, 300);
        }});
    </script>
</body>
</html>
"""

        with open(filename, "w") as file:
            file.write(html)

        print(f"[+] Styled HTML Report Saved: {filename}")