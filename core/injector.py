import requests

from urllib.parse import urljoin


class Injector:

    def __init__(
        self,
        session
    ):

        self.session = session


    # =============================================================
    # Get form input names
    # =============================================================

    @staticmethod
    def get_input_names(
        form_details
    ):

        input_names = []

        for input_tag in form_details.get(
            "inputs",
            []
        ):

            input_name = input_tag.get(
                "name"
            )

            if input_name:
                input_names.append(
                    input_name
                )

        return input_names


    # =============================================================
    # Submit payload to ONE specific input
    # =============================================================

    def submit_input(
        self,
        form_details,
        url,
        input_name,
        payload
    ):

        target_url = urljoin(
            url,
            form_details["action"]
        )


        data = {}


        # ---------------------------------------------------------
        # Preserve all form inputs
        # ---------------------------------------------------------
        #
        # Only the selected input receives the XSS payload.
        # Other fields receive their original/default value.
        #

        for input_tag in form_details.get(
            "inputs",
            []
        ):

            name = input_tag.get(
                "name"
            )


            if not name:
                continue


            value = input_tag.get(
                "value",
                ""
            )


            if name == input_name:

                value = payload


            data[name] = value


        # ---------------------------------------------------------
        # Submit form
        # ---------------------------------------------------------

        method = form_details.get(
            "method",
            "get"
        ).lower()


        if method == "post":

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


    # =============================================================
    # Backward-compatible method
    # =============================================================
    #
    # This keeps your old method available, but the scanner should
    # use submit_input() for accurate injection-point testing.
    #

    def submit_form(
        self,
        form_details,
        url,
        payload
    ):

        input_names = self.get_input_names(
            form_details
        )


        if not input_names:

            return None


        # Legacy behavior:
        # inject into the first available input.

        return self.submit_input(
            form_details,
            url,
            input_names[0],
            payload
        )