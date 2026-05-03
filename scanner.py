import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def is_same_domain(base_url, target_url):
    return urlparse(base_url).netloc == urlparse(target_url).netloc


def get_internal_links(url):
    links = set()

    try:
        response = requests.get(url, timeout=8)
        soup = BeautifulSoup(response.text, "html.parser")

        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(url, a_tag["href"])

            if full_url.startswith("http") and is_same_domain(url, full_url):
                links.add(full_url)

    except:
        pass

    return list(links)


def scan_single_page(url):
    results = []

    try:
        response = requests.get(url, timeout=8)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")
        links = soup.find_all("a")

        results.append(f"Page scanned: {url}")
        results.append(f"Status Code: {response.status_code}")
        results.append(f"Forms found: {len(forms)}")
        results.append(f"Links found: {len(links)}")

        # HTTPS check
        if not url.startswith("https://"):
            results.append("Medium: Website is not using HTTPS")

        # Security headers
        if "X-Frame-Options" not in response.headers:
            results.append("Low: Missing X-Frame-Options header")

        if "Content-Security-Policy" not in response.headers:
            results.append("Low: Missing Content-Security-Policy")

        if "Strict-Transport-Security" not in response.headers:
            results.append("Low: Missing HSTS header")

        # Server header leak
        server = response.headers.get("Server")
        if server:
            results.append(f"Low: Server header exposed ({server})")

        # Directory listing check
        if "index of /" in response.text.lower():
            results.append("Medium: Possible directory listing enabled")

        # Basic authentication detection
        if response.status_code == 401:
            results.append("Info: Basic authentication detected")

        # SQL error detection
        sql_errors = [
            "sql syntax",
            "mysql",
            "sqlite",
            "postgresql",
            "database error",
            "odbc",
            "you have an error in your sql syntax"
        ]

        for error in sql_errors:
            if error in response.text.lower():
                results.append("High: Possible SQL Injection error found")
                break

        # XSS form test
        xss_payload = "<script>alert(1)</script>"

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            target_url = urljoin(url, action)

            data = {}

            for input_tag in form.find_all("input"):
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
                results.append("Info: XSS test skipped for one form")

        # SQL Injection form test
        sqli_payload = "' OR '1'='1"

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            target_url = urljoin(url, action)

            data = {}

            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                if name:
                    data[name] = sqli_payload

            try:
                if method == "post":
                    test_response = requests.post(target_url, data=data, timeout=5)
                else:
                    test_response = requests.get(target_url, params=data, timeout=5)

                response_text = test_response.text.lower()

                if (
                    "sql" in response_text
                    or "mysql" in response_text
                    or "database" in response_text
                    or "syntax" in response_text
                ):
                    results.append("High: Possible SQL Injection detected")

            except:
                results.append("Info: SQLi test skipped for one form")

    except requests.exceptions.Timeout:
        results.append(f"Error: Timeout while scanning {url}")

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return results


def scan_url(start_url):
    final_results = []

    max_pages = 5
    visited = set()
    queue = [start_url]

    while queue and len(visited) < max_pages:
        current_url = queue.pop(0)

        if current_url in visited:
            continue

        visited.add(current_url)

        page_results = scan_single_page(current_url)
        final_results.extend(page_results)

        new_links = get_internal_links(current_url)

        for link in new_links:
            if link not in visited and link not in queue and len(queue) < max_pages:
                queue.append(link)

    final_results.insert(0, f"Total pages scanned: {len(visited)}")

    return final_results