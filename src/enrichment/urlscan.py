"""
urlscan.py
----------
Queries URLScan.io to analyze suspicious URLs.

URLScan.io visits the URL in a sandboxed browser and:
- Takes a screenshot of the landing page
- Records all network requests made
- Identifies the final URL after redirects
- Flags phishing/malicious content
- Extracts page title and technologies used

This lets us see phishing pages safely without clicking them.
"""

import requests
import time
from colorama import Fore, Style, init

init(autoreset=True)

URLSCAN_BASE = "https://urlscan.io/api/v1"


def scan_url(url: str, api_key: str) -> dict:
    """
    Submit a URL to URLScan.io for analysis.
    Returns verdict, screenshot URL, and page details.
    """
    print(f"{Fore.CYAN}  [URLSCAN] Scanning URL: {url}{Style.RESET_ALL}")

    # Step 1: Submit URL for scanning
    submit_result = _submit_scan(url, api_key)
    if "error" in submit_result:
        return submit_result

    scan_uuid = submit_result.get("uuid")
    if not scan_uuid:
        return {"error": "No UUID returned", "ioc": url, "type": "url"}

    print(
        f"{Fore.YELLOW}  [URLSCAN] Scan submitted. UUID: {scan_uuid}"
        f" — waiting 15s for results...{Style.RESET_ALL}"
    )

    # Step 2: Wait for scan to complete
    time.sleep(15)

    # Step 3: Retrieve results
    return _get_result(scan_uuid, url, api_key)


def search_existing(url: str, api_key: str) -> dict:
    """
    Search URLScan.io for existing scans of this URL.
    Avoids re-scanning URLs already in the database.
    """
    print(f"{Fore.CYAN}  [URLSCAN] Searching existing scans for: {url}{Style.RESET_ALL}")

    headers = {"API-Key": api_key}
    params = {"q": f'page.url:"{url}"', "size": 1}

    try:
        response = requests.get(
            f"{URLSCAN_BASE}/search/",
            headers=headers,
            params=params,
            timeout=15
        )
    except requests.RequestException as e:
        return {"error": str(e), "ioc": url, "type": "url"}

    if response.status_code == 200:
        results = response.json().get("results", [])
        if results:
            scan_uuid = results[0].get("task", {}).get("uuid")
            print(
                f"{Fore.GREEN}  [URLSCAN] Found existing scan: {scan_uuid}"
                f"{Style.RESET_ALL}"
            )
            return _get_result(scan_uuid, url, api_key)

    # No existing scan found — submit new one
    return scan_url(url, api_key)


def _submit_scan(url: str, api_key: str) -> dict:
    """Submit URL to URLScan.io for scanning."""
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "url": url,
        "visibility": "public"
    }

    try:
        response = requests.post(
            f"{URLSCAN_BASE}/scan/",
            headers=headers,
            json=payload,
            timeout=15
        )
    except requests.RequestException as e:
        print(f"{Fore.RED}  [!] URLScan submit failed: {e}{Style.RESET_ALL}")
        return {"error": str(e)}

    if response.status_code == 200:
        data = response.json()
        return {
            "uuid": data.get("uuid"),
            "result_url": data.get("result"),
            "screenshot_url": data.get("screenshot")
        }
    elif response.status_code == 429:
        print(f"{Fore.YELLOW}  [URLSCAN] Rate limited — free tier allows 5 scans/minute{Style.RESET_ALL}")
        return {"error": "rate_limited", "ioc": url}
    elif response.status_code == 400:
        print(f"{Fore.YELLOW}  [URLSCAN] URL rejected (may be private/localhost){Style.RESET_ALL}")
        return {"error": "rejected", "ioc": url}
    else:
        print(f"{Fore.RED}  [URLSCAN] Submit error {response.status_code}{Style.RESET_ALL}")
        return {"error": response.status_code}


def _get_result(uuid: str, url: str, api_key: str,
                retries: int = 3) -> dict:
    """Retrieve scan results by UUID."""
    headers = {"API-Key": api_key}

    for attempt in range(retries):
        try:
            response = requests.get(
                f"{URLSCAN_BASE}/result/{uuid}/",
                headers=headers,
                timeout=15
            )
        except requests.RequestException as e:
            return {"error": str(e), "ioc": url, "type": "url"}

        if response.status_code == 200:
            data = response.json()

            verdict_data = data.get("verdicts", {}).get("overall", {})
            page_data = data.get("page", {})
            task_data = data.get("task", {})

            malicious = verdict_data.get("malicious", False)
            score = verdict_data.get("score", 0)
            categories = verdict_data.get("categories", [])
            brands = verdict_data.get("brands", [])

            final_url = page_data.get("url", url)
            page_title = page_data.get("title", "")
            page_domain = page_data.get("domain", "")
            country = page_data.get("country", "")

            screenshot_url = (
                f"https://urlscan.io/screenshots/{uuid}.png"
            )
            result_page = f"https://urlscan.io/result/{uuid}/"

            result = {
                "ioc": url,
                "type": "url",
                "source": "urlscan",
                "scan_uuid": uuid,
                "malicious": malicious,
                "score": score,
                "categories": categories,
                "brands_targeted": brands,
                "final_url": final_url,
                "page_title": page_title,
                "page_domain": page_domain,
                "country": country,
                "screenshot_url": screenshot_url,
                "result_page": result_page,
                "verdict": "malicious" if malicious else
                           "suspicious" if score > 50 else "clean"
            }

            _print_result(result)
            return result

        elif response.status_code == 404:
            if attempt < retries - 1:
                print(
                    f"{Fore.YELLOW}  [URLSCAN] Results not ready yet, "
                    f"waiting 10s... (attempt {attempt + 1}/{retries})"
                    f"{Style.RESET_ALL}"
                )
                time.sleep(10)
            else:
                return {
                    "ioc": url, "type": "url", "source": "urlscan",
                    "verdict": "unknown",
                    "error": "scan_not_ready"
                }
        else:
            return {"error": response.status_code, "ioc": url, "type": "url"}

    return {"ioc": url, "type": "url", "source": "urlscan", "verdict": "unknown"}


def _print_result(result: dict):
    """Print colored URLScan result."""
    verdict = result.get("verdict", "unknown")
    score = result.get("score", 0)
    title = result.get("page_title", "")
    final_url = result.get("final_url", "")
    screenshot = result.get("screenshot_url", "")
    brands = result.get("brands_targeted", [])

    color = Fore.RED if verdict == "malicious" else \
            Fore.YELLOW if verdict == "suspicious" else Fore.GREEN

    print(
        f"{color}  [URLSCAN] Verdict: {verdict.upper()} | "
        f"Score: {score} | Title: {title}{Style.RESET_ALL}"
    )

    if final_url:
        print(f"  [URLSCAN] Final URL: {final_url}")

    if brands:
        print(
            f"{Fore.RED}  [URLSCAN] ⚠ Brands targeted: "
            f"{', '.join(brands)}{Style.RESET_ALL}"
        )

    if screenshot:
        print(f"  [URLSCAN] Screenshot: {screenshot}")
