import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def normalize_url(url):
    parsed = urlparse(url)
    parsed = parsed._replace(fragment="")
    return parsed.geturl().rstrip("/")


def crawl_website(base_url, max_depth=1, logger=None):
    visited = set()
    found_links = []

    request_headers = {
        "User-Agent": "Mozilla/5.0"
    }

    base_domain = urlparse(base_url).netloc

    def crawl(url, depth):
        normalized_url = normalize_url(url)

        if depth > max_depth:
            return

        if normalized_url in visited:
            return

        visited.add(normalized_url)

        try:
            response = requests.get(
                normalized_url,
                headers=request_headers,
                timeout=15,
                allow_redirects=True
            )

            if logger:
                logger.info(f"Crawled URL: {normalized_url} Status: {response.status_code}")

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                link = urljoin(normalized_url, tag["href"])
                link = normalize_url(link)

                if urlparse(link).netloc == base_domain:
                    if link not in found_links:
                        found_links.append(link)

                    crawl(link, depth + 1)

        except requests.RequestException as error:
            print(f"[-] Error crawling {normalized_url}: {error}")

            if logger:
                logger.error(f"Error crawling {normalized_url}: {error}")

    crawl(base_url, 0)

    print(f"[+] Found {len(found_links)} internal links")
    return found_links