from core.url_scanner import URLScanner

payload = "<script>alert(1)</script>"

response = URLScanner.scan_url(
    "http://127.0.0.1:5000/profile?name=test",
    payload
)

print(response.status_code)

print(payload in response.text)