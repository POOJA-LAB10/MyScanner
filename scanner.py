import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_url(url):
    results = []

    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        results.append(f"Status Code: {response.status_code}")

        forms = soup.find_all("form")
        links = soup.find_all("a")

        results.append(f"Forms found: {len(forms)}")
        results.append(f"Links found: {len(links)}")

        if "X-Frame-Options" not in response.headers:
            results.append("Low: Missing X-Frame-Options header")

        if "Content-Security-Policy" not in response.headers:
            results.append("Low: Missing Content-Security-Policy")

        xss_payload = "<script>alert(1)</script>"

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            target_url = urljoin(url, action)

            data = {}
            inputs = form.find_all("input")

            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    data[name] = xss_payload

            try:
                if method == "post":
                    test_response = requests.post(target_url, data=data, timeout=5)
                else:
                    test_response = requests.get(target_url, params=data, timeout=5)

                if xss_payload in test_response.text:
                    results.append("High: XSS vulnerability detected")

            except:
                results.append("Info: Could not test one form")

    except requests.exceptions.Timeout:
        results.append("Error: Website timeout")
    except Exception as e:
        results.append(f"Error: {str(e)}")

    return results