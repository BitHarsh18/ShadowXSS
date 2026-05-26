import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class WebCrawler:

    def __init__(self, session):

        self.session = session

    def get_forms(self, url):

        try:

            response = self.session.get(url)

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            return soup.find_all("form")

        except Exception as e:

            print(f"[ERROR] {e}")

            return []

    def get_form_details(self, form):

        details = {}

        # Get form action
        action = form.attrs.get("action")

        # Get form method
        method = form.attrs.get(
            "method",
            "get"
        ).lower()

        inputs = []

        # Extract all input fields
        for input_tag in form.find_all(
            ["input", "textarea", "select"]
        ):

            input_type = input_tag.attrs.get(
                "type",
                "text"
            )

            input_name = input_tag.attrs.get(
                "name"
            )

            input_value = input_tag.attrs.get(
                "value",
                ""
            )

            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })

        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs

        return details
