import json

class Reporter:

    def __init__(self):

        self.findings = []

    def add_finding(
        self,
        url,
        payload,
        method,
        xss_type
    ):

        finding = {
            "url": url,
            "payload": payload,
            "method": method,
            "type":xss_type
        }

        self.findings.append(
            finding
        )

    def save_json(
        self,
        filename="report.json"
    ):

        with open(
            filename,
            "w"
        ) as file:

            json.dump(
                self.findings,
                file,
                indent=4
            )

        print(
            f"[+] Report saved to {filename}"
        )