from selenium import webdriver

from selenium.common.exceptions import (
    NoAlertPresentException,
    TimeoutException,
    WebDriverException
)

from selenium.webdriver.support.ui import WebDriverWait

from selenium.webdriver.common.by import By

from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse,
    urljoin
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

        options.add_argument(
            "--disable-gpu"
        )

        self.driver = webdriver.Chrome(
            options=options
        )


    # ============================================================
    # URL PARAMETER INJECTION
    # ============================================================

    @staticmethod
    def inject_into_url(
        url,
        parameter,
        payload
    ):

        parsed = urlparse(
            url
        )

        parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True
        )

        if not parameters:

            return None


        updated_parameters = []


        for name, value in parameters:

            if name == parameter:

                updated_parameters.append(
                    (
                        name,
                        payload
                    )
                )

            else:

                # Keep other parameters unchanged

                updated_parameters.append(
                    (
                        name,
                        value
                    )
                )


        new_query = urlencode(
            updated_parameters
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


    # ============================================================
    # WAIT FOR JAVASCRIPT ALERT
    # ============================================================

    def _check_alert(
        self,
        timeout=3
    ):

        try:

            alert = WebDriverWait(
                self.driver,
                timeout
            ).until(
                lambda driver:
                driver.switch_to.alert
            )


            alert_text = alert.text


            alert.accept()


            return {
                "verified": True,
                "alert": True,
                "alert_text": alert_text,
                "reason": (
                    "Browser detected a JavaScript "
                    "alert after payload execution"
                )
            }


        except (
            NoAlertPresentException,
            TimeoutException
        ):

            return {
                "verified": False,
                "alert": False,
                "alert_text": None,
                "reason": (
                    "Payload was executed in the browser "
                    "but no JavaScript alert was detected"
                )
            }


    # ============================================================
    # VERIFY URL PARAMETER
    # ============================================================

    def test_url_parameter(
        self,
        url,
        parameter,
        payload
    ):

        target_url = self.inject_into_url(
            url,
            parameter,
            payload
        )


        if not target_url:

            return {
                "verified": False,
                "alert": False,
                "alert_text": None,
                "reason": (
                    "No URL parameters were available "
                    "for browser verification"
                )
            }


        try:

            self.driver.get(
                target_url
            )


            # Give reflected JavaScript time to execute

            time.sleep(
                0.5
            )


            result = self._check_alert(
                timeout=3
            )


            result.update({

                "verification_type":
                    "URL_PARAMETER",

                "parameter":
                    parameter,

                "tested_url":
                    target_url

            })


            return result


        except WebDriverException as error:

            return {

                "verified": False,

                "alert": False,

                "alert_text": None,

                "verification_type":
                    "URL_PARAMETER",

                "parameter":
                    parameter,

                "tested_url":
                    target_url,

                "reason":
                    (
                        "Browser verification failed: "
                        + str(error)
                    )
            }


    # ============================================================
    # FIND FORM
    # ============================================================

    def _find_form(
        self,
        url,
        form_details
    ):

        action = form_details.get(
            "action",
            ""
        )

        method = form_details.get(
            "method",
            "get"
        ).lower()


        target_action = urljoin(
            url,
            action
        )


        forms = self.driver.find_elements(
            By.TAG_NAME,
            "form"
        )


        for form in forms:

            form_action = form.get_attribute(
                "action"
            )

            form_method = form.get_attribute(
                "method"
            )


            if not form_method:

                form_method = "get"


            form_action = urljoin(
                self.driver.current_url,
                form_action or ""
            )


            if (
                form_action == target_action
                and
                form_method.lower() == method
            ):

                return form


        # If exact action/method matching fails,
        # fall back to the first form.

        if forms:

            return forms[0]


        return None


    # ============================================================
    # VERIFY FORM INPUT
    # ============================================================

    def test_form_input(
        self,
        url,
        form_details,
        input_name,
        payload
    ):

        try:

            # ----------------------------------------------------
            # First open the original page
            # ----------------------------------------------------

            self.driver.get(
                url
            )


            time.sleep(
                0.3
            )


            # ----------------------------------------------------
            # Locate target form
            # ----------------------------------------------------

            form = self._find_form(
                url,
                form_details
            )


            if form is None:

                return {

                    "verified": False,

                    "alert": False,

                    "alert_text": None,

                    "verification_type":
                        "FORM_INPUT",

                    "parameter":
                        input_name,

                    "reason":
                        "Target form could not be located"
                }


            # ----------------------------------------------------
            # Locate ONLY the selected input
            # ----------------------------------------------------

            input_elements = form.find_elements(
                By.NAME,
                input_name
            )


            if not input_elements:

                return {

                    "verified": False,

                    "alert": False,

                    "alert_text": None,

                    "verification_type":
                        "FORM_INPUT",

                    "parameter":
                        input_name,

                    "reason":
                        (
                            "Target form input could not "
                            "be located"
                        )
                }


            target_input = input_elements[0]


            # ----------------------------------------------------
            # Inject payload into ONLY this input
            # ----------------------------------------------------

            target_input.clear()

            target_input.send_keys(
                payload
            )


            # ----------------------------------------------------
            # Submit form
            # ----------------------------------------------------

            submit_buttons = form.find_elements(
                By.CSS_SELECTOR,
                "button[type='submit'], "
                "input[type='submit']"
            )


            if submit_buttons:

                submit_buttons[0].click()

            else:

                self.driver.execute_script(
                    "arguments[0].submit();",
                    form
                )


            # ----------------------------------------------------
            # Give browser time to process response
            # ----------------------------------------------------

            time.sleep(
                0.5
            )


            # ----------------------------------------------------
            # Check JavaScript alert
            # ----------------------------------------------------

            result = self._check_alert(
                timeout=3
            )


            result.update({

                "verification_type":
                    "FORM_INPUT",

                "parameter":
                    input_name,

                "tested_url":
                    self.driver.current_url

            })


            return result


        except WebDriverException as error:

            return {

                "verified": False,

                "alert": False,

                "alert_text": None,

                "verification_type":
                    "FORM_INPUT",

                "parameter":
                    input_name,

                "reason":
                    (
                        "Browser verification failed: "
                        + str(error)
                    )
            }


    # ============================================================
    # GENERIC COMPATIBILITY METHOD
    # ============================================================

    def test_xss(
        self,
        url,
        payload,
        parameter=None,
        form_details=None
    ):

        # --------------------------------------------------------
        # URL parameter verification
        # --------------------------------------------------------

        if parameter and not form_details:

            return self.test_url_parameter(
                url,
                parameter,
                payload
            )


        # --------------------------------------------------------
        # Form input verification
        # --------------------------------------------------------

        if (
            parameter
            and
            form_details
        ):

            return self.test_form_input(
                url,
                form_details,
                parameter,
                payload
            )


        return {

            "verified": False,

            "alert": False,

            "alert_text": None,

            "reason": (
                "An exact parameter/input name is required "
                "for browser verification"
            )
        }


    # ============================================================
    # CLOSE BROWSER
    # ============================================================

    def close(self):

        try:

            self.driver.quit()

        except Exception:

            pass