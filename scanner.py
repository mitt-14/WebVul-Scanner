import argparse

from modules.crawler import crawl_website
from modules.headers import check_security_headers
from modules.cookies import check_cookies
from modules.redirect import test_open_redirect
from modules.fingerprint import fingerprint_technology
from modules.discovery import discover_common_files
from modules.xss import test_xss
from modules.sqli import test_sqli
from modules.reporter import generate_report
from modules.logger import setup_logger


def main():
    logger = setup_logger()

    parser = argparse.ArgumentParser(description="Advanced Python Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target website URL")
    parser.add_argument("--depth", type=int, default=1, help="Crawling depth")
    parser.add_argument("--no-xss", action="store_true", help="Disable XSS scan")
    parser.add_argument("--no-sqli", action="store_true", help="Disable SQL injection scan")

    args = parser.parse_args()
    target_url = args.url

    print(f"[+] Starting scan on: {target_url}")
    logger.info(f"Scan started for target: {target_url}")

    links = crawl_website(target_url, max_depth=args.depth, logger=logger)
    header_results = check_security_headers(target_url, logger=logger)
    cookie_results = check_cookies(target_url, logger=logger)
    tech_results = fingerprint_technology(target_url, logger=logger)
    discovery_results = discover_common_files(target_url, logger=logger)
    redirect_results = test_open_redirect(links, logger=logger)

    xss_results = [] if args.no_xss else test_xss(links, logger=logger)
    sqli_results = [] if args.no_sqli else test_sqli(links, logger=logger)

    generate_report(
        target_url=target_url,
        links=links,
        header_results=header_results,
        xss_results=xss_results,
        sqli_results=sqli_results,
        cookie_results=cookie_results,
        redirect_results=redirect_results,
        tech_results=tech_results,
        discovery_results=discovery_results
    )

    logger.info("Scan finished")

    print("[+] Scan completed.")
    print("[+] TXT report saved in reports/report.txt")
    print("[+] JSON report saved in reports/report.json")
    print("[+] HTML report saved in reports/report.html")
    print("[+] Logs saved in logs/scanner.log")


if __name__ == "__main__":
    main()