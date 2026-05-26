import requests
from colorama import Fore, Style

from core.crawler import WebCrawler
from core.injector import Injector
from core.detector import XSSDetector


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

    forms = crawler.get_forms(url)

    print(
        f"\n[+] Found {len(forms)} forms\n"
    )

    payloads = load_payloads()

    vulnerabilities = []

    for form in forms:

        form_details = (
            crawler.get_form_details(form)
        )

        for payload in payloads:

            response = injector.submit_form(
                form_details,
                url,
                payload
            )

            if XSSDetector.is_vulnerable(
                response,
                payload
            ):

                print(
                    f"{Fore.RED}"
                    "[VULNERABLE]"
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