import requests
from urllib.parse import urljoin


def discover_common_files(base_url, logger=None):
    common_files = [
        "robots.txt",
        "sitemap.xml",
        ".git/",
        ".env",
        "backup.zip",
        "config.php.bak"
    ]

    findings = []

    for file_path in common_files:
        test_url = urljoin(base_url, file_path)

        try:
            response = requests.get(
                test_url,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            if response.status_code == 200:
                risk = "Low"

                if file_path in [".git/", ".env", "backup.zip", "config.php.bak"]:
                    risk = "High"

                findings.append({
                    "url": test_url,
                    "status_code": response.status_code,
                    "risk": risk
                })

                if logger:
                    logger.warning(f"Common file discovered: {test_url}")

        except requests.RequestException:
            continue

    return findings