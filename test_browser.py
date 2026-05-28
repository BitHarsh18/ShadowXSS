from core.browser import BrowserScanner

scanner = BrowserScanner()

payload = "<script>alert(1)</script>"

result, alert_text = scanner.test_xss(
    "http://127.0.0.1:5000",
    payload
)

if result:

    print("[XSS DETECTED]")

    print(f"Alert Text: {alert_text}")

else:

    print("[SAFE]")

scanner.close()