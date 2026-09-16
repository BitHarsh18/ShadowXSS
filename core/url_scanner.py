from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse
)

import requests


class URLScanner:

    @staticmethod
    def build_test_url(
        url,
        parameter,
        payload
    ):

        parsed = urlparse(url)

        params = parse_qsl(
            parsed.query,
            keep_blank_values=True
        )

        updated_params = []

        for key, value in params:

            if key == parameter:

                updated_params.append(
                    (
                        key,
                        payload
                    )
                )

            else:

                updated_params.append(
                    (
                        key,
                        value
                    )
                )


        new_query = urlencode(
            updated_params
        )


        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            )
        )


    @staticmethod
    def scan_parameter(
        url,
        parameter,
        payload
    ):

        target_url = URLScanner.build_test_url(
            url,
            parameter,
            payload
        )


        response = requests.get(
            target_url
        )


        return response, target_url


    @staticmethod
    def get_parameters(
        url
    ):

        parsed = urlparse(url)

        params = parse_qsl(
            parsed.query,
            keep_blank_values=True
        )


        return [
            key
            for key, value in params
        ]