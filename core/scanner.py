from urllib.parse import (
    urlparse,
    parse_qs,
    urlencode,
    urlunparse
)


class URLScanner:

    @staticmethod
    def scan_url(
        session,
        url,
        payload
    ):

        parsed = urlparse(url)

        query_params = parse_qs(
            parsed.query
        )

        if not query_params:

            return None

        for key in query_params:

            query_params[key] = payload

        encoded_query = urlencode(
            query_params,
            doseq=True
        )

        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            encoded_query,
            parsed.fragment
        ))

        response = session.get(new_url)

        return response, new_url