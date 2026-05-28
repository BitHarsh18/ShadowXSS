import requests
from colorama import Fore, Style

from core.crawler import WebCrawler
from core.injector import Injector
from core.detector import XSSDetector
from core.scanner import URLScanner


def load_payloads():

    with open(
        "payloads/basic.txt",
        "r"
    ) as file:

        return [
            line.strip()
            for line in file
            if line.strip()
        ]


def scan_xss(url):

    session = requests.Session()

    crawler = WebCrawler(session)

    injector = Injector(session)

    # -----------------------------
    # GET ALL LINKS
    # -----------------------------

    links = crawler.get_links(url)

    all_urls = [url] + links

    print(
        f"\n[+] Found {len(links)} links\n"
    )

    for link in links:

        print(f"[LINK] {link}")

    payloads = load_payloads()

    vulnerabilities = []

    # -----------------------------
    # SCAN EACH PAGE
    # -----------------------------

    for current_url in all_urls:

        print(
            f"\n[SCANNING] {current_url}"
        )

        forms = crawler.get_forms(
            current_url
        )

        print(
            f"[+] Found {len(forms)} forms"
        )

        # -----------------------------
        # URL PARAMETER SCANNING
        # -----------------------------

        print(
            "[+] Testing URL parameters...\n"
        )

        for payload in payloads:

            result = URLScanner.scan_url(
                session,
                current_url,
                payload
            )

            if result:

                response, tested_url = result

                if XSSDetector.is_vulnerable(
                    response,
                    payload
                ):

                    print(
                        f"{Fore.RED}"
                        "[URL VULNERABLE]"
                        f"{Style.RESET_ALL}"
                    )

                    print(
                        f"URL: {tested_url}"
                    )

                    print(
                        f"Payload: {payload}\n"
                    )

                    vulnerabilities.append({

                        "url":
                        tested_url,

                        "payload":
                        payload
                    })

                    break

        # -----------------------------
        # FORM SCANNING
        # -----------------------------

        for form in forms:

            form_details = (
                crawler.get_form_details(form)
            )

            for payload in payloads:

                response = injector.submit_form(
                    form_details,
                    current_url,
                    payload
                )

                if XSSDetector.is_vulnerable(
                    response,
                    payload
                ):

                    print(
                        f"{Fore.RED}"
                        "[FORM VULNERABLE]"
                        f"{Style.RESET_ALL}"
                    )

                    print(
                        f"URL: "
                        f"{form_details['action']}"
                    )

                    print(
                        f"Payload: {payload}\n"
                    )

                    vulnerabilities.append({

                        "url":
                        form_details["action"],

                        "payload":
                        payload
                    })

                    break

    return vulnerabilities


if __name__ == "__main__":

    target_url = input(
        "Enter target URL: "
    )

    scan_xss(target_url)