import requests

from bs4 import BeautifulSoup

from urllib.parse import (
    urljoin,
    urlparse
)


class WebCrawler:

    def __init__(
        self,
        session
    ):

        self.session = session


    def get_forms(
        self,
        url
    ):

        try:

            response = self.session.get(
                url
            )

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            forms = soup.find_all(
                "form"
            )

            return forms

        except Exception as e:

            print(
                f"[ERROR] {e}"
            )

            return []


    def get_form_details(
        self,
        form
    ):

        details = {}

        action = form.attrs.get(
            "action"
        )

        method = form.attrs.get(
            "method",
            "get"
        ).lower()

        inputs = []

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

            inputs.append(
                {
                    "type": input_type,
                    "name": input_name,
                    "value": input_value
                }
            )

        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs

        return details


    def get_links(
        self,
        url
    ):

        links = []

        try:

            response = self.session.get(
                url
            )

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            for tag in soup.find_all(
                "a"
            ):

                href = tag.get(
                    "href"
                )

                if not href:
                    continue


                # -------------------------------------------------
                # Ignore non-navigation links
                # -------------------------------------------------
                #
                # These are not HTTP resources that the crawler
                # should request.
                #
                # Examples:
                #
                # javascript:...
                # mailto:...
                # tel:...
                # data:...
                # -------------------------------------------------

                parsed_href = urlparse(
                    href.strip()
                )

                scheme = (
                    parsed_href.scheme.lower()
                )


                if scheme and scheme not in (
                    "http",
                    "https"
                ):

                    continue


                # -------------------------------------------------
                # Ignore fragment-only links
                # -------------------------------------------------

                if (
                    href.strip().startswith(
                        "#"
                    )
                ):

                    continue


                # -------------------------------------------------
                # Build absolute URL
                # -------------------------------------------------

                full_url = urljoin(
                    url,
                    href
                )


                # -------------------------------------------------
                # Final safety check
                # -------------------------------------------------

                parsed_url = urlparse(
                    full_url
                )

                if parsed_url.scheme.lower() not in (
                    "http",
                    "https"
                ):

                    continue


                links.append(
                    full_url
                )


        except Exception as e:

            print(
                f"[ERROR] {e}"
            )


        return links