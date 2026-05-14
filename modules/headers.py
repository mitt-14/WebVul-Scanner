import requests


def check_security_headers(url, logger=None):
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy"
    ]

    results = {}

    request_headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(url, headers=request_headers, timeout=15)
        response_headers = response.headers

        for header in required_headers:
            if header in response_headers:
                results[header] = "Present"
            else:
                results[header] = "Missing"

        if logger:
            logger.info("Security header check completed")

        return results

    except requests.RequestException as error:
        if logger:
            logger.error(f"Header check failed: {error}")

        return {"error": str(error)}