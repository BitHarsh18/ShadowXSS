import html as html_utils

class HTMLReporter:

    @staticmethod
    def generate(
        findings,
        filename="report.html"
    ):
        # CSS Styles for Dark Cyber Theme
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
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
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
            .stats-card {
                background-color: var(--bg-card);
                border-left: 5px solid var(--accent-cyan);
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 4px 6px rgba(0,0,0,0.3);
            }
            table {
                width: 100%;
                border-collapse: collapse;
                background-color: var(--bg-card);
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 15px rgba(0,0,0,0.5);
            }
            th {
                background-color: #121212;
                color: var(--accent-cyan);
                padding: 15px;
                text-align: left;
                font-weight: bold;
                text-transform: uppercase;
                font-size: 0.9rem;
            }
            td {
                padding: 15px;
                border-bottom: 1px solid #2c3e50;
                vertical-align: top;
            }
            tr:hover {
                background-color: rgba(102, 252, 241, 0.05);
            }
            .payload-box {
                background-color: #000;
                color: #0f0;
                padding: 10px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 0.85rem;
                word-break: break-all;
                border: 1px solid #333;
            }
            .method-badge {
                padding: 5px 10px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 0.8rem;
                color: #000;
                display: inline-block;
            }
            .url-text {
                color: #fff;
                text-decoration: none;
            }
            .url-text:hover {
                color: var(--accent-cyan);
                text-decoration: underline;
            }
            .severity-high { color: #ff4d4d; font-weight: bold; }
            .severity-medium { color: #ffbf00; font-weight: bold; }
            
            /* New Styles for Alignment */
            .meta-info {
                display: flex;
                flex-direction: column;
                gap: 6px; /* Spacing between badge and text */
                align-items: flex-start;
            }
            .meta-text {
                font-size: 0.9rem;
                line-height: 1.4;
                margin: 0;
            }
        </style>
        """

        # Helper function to determine severity
        def get_severity(xss_type):
            if xss_type == "Stored XSS":
                return '<span class="severity-high">CRITICAL</span>'
            elif xss_type == "DOM XSS":
                return '<span class="severity-medium">MEDIUM</span>'
            return '<span class="severity-medium">HIGH</span>'

        # Helper for Method Badge Color
        def get_method_badge(method):
            color = 'var(--badge-post)' if method.upper() == 'POST' else 'var(--badge-get)'
            return f'<span class="method-badge" style="background-color: {color}">{method.upper()}</span>'

        # Build Table Rows
        table_rows = ""
        for finding in findings:
            url = finding.get('url', 'N/A')
            payload = html_utils.escape(finding.get('payload', 'N/A'))
            method = finding.get('method', 'GET')
            xss_type = finding.get("type", "Reflected XSS")
            
            # Fixed formatting here to ensure clean HTML structure
            table_rows += f"""
            <tr>
                <td>
                    <div class="url-text">{url}</div>
                </td>
                <td>
                    <div class="meta-info">
                        {get_method_badge(method)}
                        <span class="meta-text">{xss_type}</span>
                        <span class="meta-text">{get_severity(xss_type)}</span>
                    </div>
                </td>
                <td><div class="payload-box">{payload}</div></td>
            </tr>
            """

        # Full HTML Document
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Vulnerability Scan Report</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
            {styles}
        </head>
        <body>

        <div class="container">
            <div class="header">
                <h1><i class="fas fa-bug"></i> XSS Vulnerability Report</h1>
                <p style="color: var(--accent-teal);">Automated Security Scan Results</p>
            </div>

            <div class="stats-card">
                <div>
                    <h2 style="margin:0;">Total Findings: {len(findings)}</h2>
                    <span style="font-size: 0.9rem; color: #888;">Scan completed successfully</span>
                </div>
                <div style="text-align: right;">
                    <i class="fas fa-shield-virus" style="font-size: 3rem; color: var(--accent-teal); opacity: 0.5;"></i>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th style="width: 40%;">Target URL</th>
                        <th style="width: 20%;">Method & Severity</th>
                        <th style="width: 40%;">Injected Payload</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
            
            <footer style="margin-top: 50px; text-align: center; font-size: 0.8rem; color: #555;">
                <p>Report generated by Automated XSS Scanner | Educational Purpose Only</p>
            </footer>
        </div>

        </body>
        </html>
        """

        with open(filename, "w") as file:
            file.write(html)

        print(f"[+] Styled HTML Report Saved: {filename}")