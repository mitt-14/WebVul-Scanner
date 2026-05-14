import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def test_open_redirect(urls, logger=None):
    payload = "https://evil.com"
    redirect_params = ["url", "next", "redirect", "return", "returnUrl", "continue", "dest", "destination"]

    findings = []
    seen = set()

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            continue

        for param in params:
            if param.lower() not in [p.lower() for p in redirect_params]:
                continue

            test_params = params.copy()
            test_params[param] = payload

            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(test_params, doseq=True),
                parsed.fragment
            ))

            try:
                response = requests.get(
                    test_url,
                    timeout=10,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )

                location = response.headers.get("Location", "")

                if payload in location:
                    key = (parsed.path, param)

                    if key not in seen:
                        seen.add(key)

                        findings.append({
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "risk": "High"
                        })

                        if logger:
                            logger.warning(f"Possible open redirect found: {test_url}")

            except requests.RequestException:
                continue

    return findings