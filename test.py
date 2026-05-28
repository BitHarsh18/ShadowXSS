from core.crawler import WebCrawler

from core.injector import Injector

from core.detector import XSSDetector


crawler = WebCrawler()

injector = Injector()


payload = "<script>alert(1)</script>"


forms = crawler.get_forms(
    "http://127.0.0.1:5000/search"
)


for form in forms:

    form_details = crawler.get_form_details(
        form
    )

    response = injector.submit_form(
        form_details,
        "http://127.0.0.1:5000/search",
        payload
    )

    is_vulnerable = XSSDetector.is_vulnerable(
        response,
        payload
    )

    print(is_vulnerable)