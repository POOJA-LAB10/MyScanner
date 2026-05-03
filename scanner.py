import requests

def scan_url(url):
    results = []

    try:
        response = requests.get(url, timeout=10)

        # Basic info
        results.append(f"Status Code: {response.status_code}")

        # 🔹 XSS Test
        xss_payload = "<script>alert(1)</script>"
        if xss_payload in response.text:
            results.append("High: Possible XSS vulnerability")

        # 🔹 SQL Injection Test
        sqli_payload = "' OR '1'='1"
        if sqli_payload in response.text:
            results.append("High: Possible SQL Injection")

        # 🔹 Security Headers Check
        if "X-Frame-Options" not in response.headers:
            results.append("Low: Missing X-Frame-Options header")

        if "Content-Security-Policy" not in response.headers:
            results.append("Low: Missing Content-Security-Policy")

    except requests.exceptions.Timeout:
        results.append("Error: Website timeout")
    except Exception as e:
        results.append(f"Error: {str(e)}")

    return results