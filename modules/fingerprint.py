import requests


def fingerprint_technology(url, logger=None):
    technologies = {}

    try:
        response = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        headers = response.headers
        body = response.text.lower()

        technologies["Server"] = headers.get("Server", "Not disclosed")
        technologies["Powered-By"] = headers.get("X-Powered-By", "Not disclosed")

        detected = []

        if "wp-content" in body:
            detected.append("WordPress")

        if "drupal" in body:
            detected.append("Drupal")

        if "joomla" in body:
            detected.append("Joomla")

        if "php" in body or ".php" in body:
            detected.append("PHP")

        if "react" in body:
            detected.append("React")

        if "jquery" in body:
            detected.append("jQuery")

        technologies["Detected Technologies"] = detected if detected else ["Unknown"]

        if logger:
            logger.info("Technology fingerprinting completed")

    except requests.RequestException as error:
        technologies["error"] = str(error)

        if logger:
            logger.error(f"Technology fingerprinting failed: {error}")

    return technologies