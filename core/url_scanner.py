from urllib.parse import urlparse
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlunparse
import requests


class URLScanner:

    @staticmethod
    def scan_url(url, payload):

        parsed = urlparse(url)

        params = parse_qs(
            parsed.query
        )

        for key in params:

            params[key] = [payload]

        new_query = urlencode(
            params,
            doseq=True
        )

        target_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            )
        )

        response = requests.get(
            target_url
        )

        return response