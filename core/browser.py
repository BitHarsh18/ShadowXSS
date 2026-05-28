from selenium import webdriver
from selenium.common.exceptions import (
    NoAlertPresentException
)

import time


class BrowserScanner:

    def __init__(self):

        options = webdriver.ChromeOptions()

        options.add_argument(
            "--headless"
        )

        options.add_argument(
            "--no-sandbox"
        )

        options.add_argument(
            "--disable-dev-shm-usage"
        )

        self.driver = webdriver.Chrome(
            options=options
        )

    def test_xss(
        self,
        url,
        payload
    ):

        target_url = (
            f"{url}?q={payload}"
        )

        try:

            self.driver.get(target_url)

            time.sleep(2)

            alert = self.driver.switch_to.alert

            alert_text = alert.text

            alert.accept()

            return True, alert_text

        except NoAlertPresentException:

            return False, None

    def close(self):

        self.driver.quit()