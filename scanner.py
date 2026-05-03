import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_url(url):
    results = []

    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        # 🔹 Basic info
        results.append(f"Status Code: {response.status_code}")

        # 🔹 Forms and links
        forms = soup.find_all("form")
        links = soup.find_all("a")

        results.append(f"Forms found: {len(forms)}")
        results.append(f"Links found: {len(links)}")

        # 🔹 Security headers
        if "X-Frame-Options" not in response.headers:
            results.append("Low: Missing X-Frame-Options header")

        if "Content-Security-Policy" not in response.headers:
            results.append("Low: Missing Content-Security-Policy")

        # 🔹 XSS Test
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
                    res = requests.post(target_url, data=data, timeout=5)
                else:
                    res = requests.get(target_url, params=data, timeout=5)

                if xss_payload in res.text:
                    results.append("High: XSS vulnerability detected")

            except:
                results.append("Info: XSS test skipped for one form")

        # 🔹 SQL Injection Test
        sqli_payload = "' OR '1'='1"

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            target_url = urljoin(url, action)

            data = {}
            inputs = form.find_all("input")

            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    data[name] = sqli_payload

            try:
                if method == "post":
                    res = requests.post(target_url, data=data, timeout=5)
                else:
                    res = requests.get(target_url, params=data, timeout=5)

                # Basic SQL error detection
                if "sql" in res.text.lower() or "database" in res.text.lower():
                    results.append("High: Possible SQL Injection detected")

            except:
                results.append("Info: SQLi test skipped for one form")

    except requests.exceptions.Timeout:
        results.append("Error: Website timeout")
    except Exception as e:
        results.append(f"Error: {str(e)}")

    return results