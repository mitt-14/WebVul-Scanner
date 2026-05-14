from datetime import datetime
import os
import json


def calculate_severity_score(header_results, xss_results, sqli_results, cookie_results, redirect_results, discovery_results):
    score = 0

    score += len([h for h, status in header_results.items() if status == "Missing"]) * 2
    score += len(xss_results) * 8
    score += len(sqli_results) * 9
    score += len(cookie_results) * 3
    score += len(redirect_results) * 7
    score += len([item for item in discovery_results if item["risk"] == "High"]) * 8

    if score >= 25:
        return "Critical", score
    elif score >= 15:
        return "High", score
    elif score >= 7:
        return "Medium", score
    else:
        return "Low", score


def generate_report(
    target_url,
    links,
    header_results,
    xss_results,
    sqli_results,
    cookie_results,
    redirect_results,
    tech_results,
    discovery_results
):
    os.makedirs("reports", exist_ok=True)

    txt_path = "reports/report.txt"
    json_path = "reports/report.json"
    html_path = "reports/report.html"

    missing_headers = [
        header for header, status in header_results.items()
        if status == "Missing"
    ]

    overall_risk, risk_score = calculate_severity_score(
        header_results,
        xss_results,
        sqli_results,
        cookie_results,
        redirect_results,
        discovery_results
    )

    report_data = {
        "target": target_url,
        "scan_time": str(datetime.now()),
        "overall_risk": overall_risk,
        "risk_score": risk_score,
        "summary": {
            "internal_links": len(links),
            "missing_headers": len(missing_headers),
            "xss_findings": len(xss_results),
            "sqli_error_disclosure_findings": len(sqli_results),
            "cookie_findings": len(cookie_results),
            "open_redirect_findings": len(redirect_results),
            "discovery_findings": len(discovery_results)
        },
        "links": links,
        "security_headers": header_results,
        "cookies": cookie_results,
        "technology_fingerprint": tech_results,
        "common_file_discovery": discovery_results,
        "xss": xss_results,
        "sqli_error_disclosure": sqli_results,
        "open_redirect": redirect_results
    }

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

    with open(txt_path, "w", encoding="utf-8") as file:
        file.write("WEB VULNERABILITY ASSESSMENT REPORT\n")
        file.write("=" * 50 + "\n\n")

        file.write(f"Target URL: {target_url}\n")
        file.write(f"Scan Time: {report_data['scan_time']}\n")
        file.write(f"Overall Risk: {overall_risk}\n")
        file.write(f"Risk Score: {risk_score}\n\n")

        file.write("1. Executive Summary\n")
        file.write("-" * 40 + "\n")
        file.write(
            "The target was scanned for common web security issues including "
            "security headers, cookies, reflected XSS indicators, SQL error disclosure, "
            "open redirect indicators, exposed common files, and technology fingerprinting.\n\n"
        )

        file.write("Summary of Findings:\n")
        for key, value in report_data["summary"].items():
            file.write(f"- {key.replace('_', ' ').title()}: {value}\n")

        file.write("\n2. Technology Fingerprinting\n")
        file.write("-" * 40 + "\n")
        for key, value in tech_results.items():
            file.write(f"{key}: {value}\n")

        file.write("\n3. Crawled Internal Links\n")
        file.write("-" * 40 + "\n")
        for link in links:
            file.write(f"[+] {link}\n")

        file.write("\n4. Security Header Analysis\n")
        file.write("-" * 40 + "\n")
        for header, status in header_results.items():
            risk = "Medium Risk" if status == "Missing" else "Low Risk"
            file.write(f"{header}: {status} ({risk})\n")

        file.write("\n5. Cookie Security Findings\n")
        file.write("-" * 40 + "\n")
        if cookie_results:
            for item in cookie_results:
                file.write(f"[!] Cookie: {item['cookie']}\n")
                file.write(f"Issues: {', '.join(item['issues'])}\n")
                file.write(f"Risk: {item['risk']}\n\n")
        else:
            file.write("No insecure cookie indicators found.\n")

        file.write("\n6. Common File Discovery\n")
        file.write("-" * 40 + "\n")
        if discovery_results:
            for item in discovery_results:
                file.write(f"[!] Found: {item['url']}\n")
                file.write(f"Status Code: {item['status_code']}\n")
                file.write(f"Risk: {item['risk']}\n\n")
        else:
            file.write("No sensitive common files discovered.\n")

        file.write("\n7. XSS Findings\n")
        file.write("-" * 40 + "\n")
        if xss_results:
            for item in xss_results:
                file.write("[!] Possible Reflected XSS Found\n")
                file.write(f"URL: {item['url']}\n")
                file.write(f"Parameter: {item['parameter']}\n")
                file.write(f"Payload: {item['payload']}\n")
                file.write(f"Risk: {item['risk']}\n\n")
        else:
            file.write("No reflected XSS indicators found.\n")

        file.write("\n8. SQL Injection / Error Disclosure Findings\n")
        file.write("-" * 40 + "\n")
        if sqli_results:
            for item in sqli_results:
                file.write(f"[!] {item['type']}\n")
                file.write(f"URL: {item['url']}\n")
                file.write(f"Parameter: {item['parameter']}\n")
                file.write(f"Payload: {item['payload']}\n")
                file.write(f"Evidence: {item['evidence']}\n")
                file.write(f"Risk: {item['risk']}\n")
                file.write("Note: Manual validation is required.\n\n")
        else:
            file.write("No SQL injection/error disclosure indicators found.\n")

        file.write("\n9. Open Redirect Findings\n")
        file.write("-" * 40 + "\n")
        if redirect_results:
            for item in redirect_results:
                file.write("[!] Possible Open Redirect Found\n")
                file.write(f"URL: {item['url']}\n")
                file.write(f"Parameter: {item['parameter']}\n")
                file.write(f"Payload: {item['payload']}\n")
                file.write(f"Risk: {item['risk']}\n\n")
        else:
            file.write("No open redirect indicators found.\n")

        file.write("\n10. Recommendations\n")
        file.write("-" * 40 + "\n")
        file.write("- Implement missing HTTP security headers.\n")
        file.write("- Use HttpOnly, Secure, and SameSite cookie attributes.\n")
        file.write("- Use prepared statements for database queries.\n")
        file.write("- Encode user-controlled output to prevent XSS.\n")
        file.write("- Validate redirect destinations using allowlists.\n")
        file.write("- Disable detailed production error messages.\n")
        file.write("- Remove exposed backup/configuration files.\n\n")

        file.write("11. Limitations\n")
        file.write("-" * 40 + "\n")
        file.write(
            "This tool performs automated checks only. Manual validation is required. "
            "It may miss issues requiring authentication, JavaScript execution, "
            "business logic testing, or complex workflows.\n"
        )

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Web Vulnerability Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f7f7f7; }}
        h1 {{ color: #222; }}
        h2 {{ color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }}
        .card {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; }}
        .risk {{ font-weight: bold; }}
        .Critical {{ color: darkred; }}
        .High {{ color: red; }}
        .Medium {{ color: orange; }}
        .Low {{ color: green; }}
        pre {{ background: #eee; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Web Vulnerability Assessment Report</h1>

    <div class="card">
        <p><strong>Target:</strong> {target_url}</p>
        <p><strong>Scan Time:</strong> {report_data['scan_time']}</p>
        <p><strong>Overall Risk:</strong> <span class="risk {overall_risk}">{overall_risk}</span></p>
        <p><strong>Risk Score:</strong> {risk_score}</p>
    </div>

    <div class="card">
        <h2>Summary</h2>
        <pre>{json.dumps(report_data["summary"], indent=4)}</pre>
    </div>

    <div class="card">
        <h2>Technology Fingerprinting</h2>
        <pre>{json.dumps(tech_results, indent=4)}</pre>
    </div>

    <div class="card">
        <h2>Security Headers</h2>
        <pre>{json.dumps(header_results, indent=4)}</pre>
    </div>

    <div class="card">
        <h2>Cookie Findings</h2>
        <pre>{json.dumps(cookie_results, indent=4)}</pre>
    </div>

    <div class="card">
        <h2>Discovery Findings</h2>
        <pre>{json.dumps(discovery_results, indent=4)}</pre>
    </div>

    <div class="card">
        <h2>XSS Findings</h2>
        <pre>{json.dumps(xss_results, indent=4)}</pre>
    </div>

    <div class="card">
        <h2>SQLi / Error Disclosure Findings</h2>
        <pre>{json.dumps(sqli_results, indent=4)}</pre>
    </div>

    <div class="card">
        <h2>Open Redirect Findings</h2>
        <pre>{json.dumps(redirect_results, indent=4)}</pre>
    </div>
</body>
</html>
"""

    with open(html_path, "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"[+] TXT report generated: {txt_path}")
    print(f"[+] JSON report generated: {json_path}")
    print(f"[+] HTML report generated: {html_path}")