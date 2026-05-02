import requests
from bs4 import BeautifulSoup

def scan_url(url):
    results = []

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        # Find forms
        forms = soup.find_all("form")
        results.append(f"Forms found: {len(forms)}")

        # Basic XSS test
        test_script = "<script>alert(1)</script>"
        if test_script in response.text:
            results.append("Possible XSS vulnerability detected")

        # Get links
        links = soup.find_all("a")
        results.append(f"Links found: {len(links)}")

    except Exception as e:
        results.append(f"Error: {e}")

    return results