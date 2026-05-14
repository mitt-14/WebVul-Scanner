import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def build_test_url(url, parameter, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    test_params = query_params.copy()
    test_params[parameter] = payload

    new_query = urlencode(test_params, doseq=True)

    return urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        new_query,
        parsed_url.fragment
    ))


def test_sqli(urls, logger=None):
    payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1"
    ]

    error_signatures = [
        "sql syntax",
        "mysql",
        "mysqli",
        "syntax error",
        "ora-",
        "oracle",
        "postgresql",
        "sqlite",
        "database error",
        "pdoexception",
        "you have an error in your sql syntax"
    ]

    findings = []
    seen_findings = set()

    request_headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for url in urls:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            continue

        for parameter in query_params:
            for payload in payloads:
                test_url = build_test_url(url, parameter, payload)

                try:
                    response = requests.get(test_url, headers=request_headers, timeout=10)
                    response_text = response.text.lower()

                    for error in error_signatures:
                        if error in response_text:
                            finding_key = (parsed_url.path, parameter, payload, error)

                            if finding_key not in seen_findings:
                                seen_findings.add(finding_key)

                                findings.append({
                                    "url": test_url,
                                    "parameter": parameter,
                                    "payload": payload,
                                    "risk": "High",
                                    "evidence": error,
                                    "type": "Possible SQL Injection / Error Disclosure"
                                })

                                if logger:
                                    logger.warning(f"Possible SQLi/Error Disclosure found: {test_url}")

                            break

                except requests.RequestException as error:
                    if logger:
                        logger.error(f"SQLi test failed for {test_url}: {error}")

                    continue

    print(f"[+] SQLi/Error Disclosure scan completed. Found {len(findings)} possible issues")
    return findings