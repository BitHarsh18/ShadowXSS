import requests

url = "https://chat.z.ai/space/k1ghd4dtqmp1-art"

response = requests.get(url)

print(response.text[:3000])