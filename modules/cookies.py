import requests


def check_cookies(url, logger=None):
    findings = []

    try:
        response = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})

        for cookie in response.cookies:
            issues = []

            if not cookie.secure:
                issues.append("Missing Secure flag")

            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("Missing HttpOnly flag")

            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("Missing SameSite attribute")

            if issues:
                findings.append({
                    "cookie": cookie.name,
                    "issues": issues,
                    "risk": "Medium"
                })

        if logger:
            logger.info(f"Cookie check completed. Findings: {len(findings)}")

    except requests.RequestException as error:
        if logger:
            logger.error(f"Cookie check failed: {error}")

    return findings