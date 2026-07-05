import requests
import sys

url = "http://10.130.148.75:5003/api/process"
payload = {"data": "debug"}

try:
    response = requests.post(url, json=payload, timeout=5)
except requests.exceptions.RequestException as e:
    print(f"[ERR] {url} -> {e}")
    sys.exit()

code = response.status_code
print(f"[{code}] {url}")
print(response.text)
