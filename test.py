from core.reporter import Reporter

reporter = Reporter()

reporter.add_finding(
    "http://127.0.0.1:5000/search",
    "<script>alert(1)</script>",
    "GET"
)

reporter.save_json()