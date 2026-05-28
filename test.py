from core.crawler import WebCrawler

crawler = WebCrawler()

links = crawler.get_links("http://127.0.0.1:5000")

# for form in forms:
#     details = crawler.get_links(form)

#     print(details)
print(links)

