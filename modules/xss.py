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


def test_xss(urls, logger=None):
    payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>"
    ]

    vulnerable_urls = []
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

                    if payload in response.text:
                        finding_key = (test_url, parameter, payload)

                        if finding_key not in seen_findings:
                            seen_findings.add(finding_key)

                            vulnerable_urls.append({
                                "url": test_url,
                                "parameter": parameter,
                                "payload": payload,
                                "risk": "High"
                            })

                            if logger:
                                logger.warning(f"Possible XSS found: {test_url}")

                except requests.RequestException as error:
                    if logger:
                        logger.error(f"XSS test failed for {test_url}: {error}")

                    continue

    print(f"[+] XSS scan completed. Found {len(vulnerable_urls)} possible issues")
    return vulnerable_urls