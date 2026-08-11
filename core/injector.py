import requests

from urllib.parse import urljoin


class Injector:

    def __init__(
        self,
        session
    ):

        self.session = session

    def submit_form(
        self,
        form_details,
        url,
        payload
    ):

        target_url = urljoin(
            url,
            form_details["action"]
        )

        data = {}

        for input_tag in form_details["inputs"]:

            input_name = input_tag.get(
                "name"
            )

            if input_name:

                data[input_name] = payload

        if form_details["method"] == "post":

            response = self.session.post(
                target_url,
                data=data
            )

        else:

            response = self.session.get(
                target_url,
                params=data
            )

        return response