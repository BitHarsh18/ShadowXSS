class XSSDetector:

    @staticmethod
    def is_vulnerable(
        response,
        payload
    ):
        if not payload:
            return False

        return payload in response.text