from urllib.parse import urljoin


class Injector:

    def __init__(self, session):

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

        inputs = form_details["inputs"]

        data = {}

        for input_field in inputs:

            input_name = input_field.get(
                "name"
            )

            input_type = input_field.get(
                "type"
            )

            #<input type="text" name="search">

            if input_name:

                if input_type == "submit":

                    continue

                data[input_name] = payload

        if form_details["method"] == "post":

            return self.session.post(
                target_url,
                data=data
            )

        return self.session.get(
            target_url,
            params=data
        )