class XSSDetector:

    @staticmethod
    def is_vulnerable(
        response,
        payload
    ):

        content = response.text

        if payload in content:

            return True

        return False