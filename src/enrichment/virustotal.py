"""
virustotal.py
-------------
Queries the VirusTotal API v3 for:
- IP address reputation
- URL analysis
- File hash lookup

VirusTotal aggregates results from 90+ security vendors.
A high detection count = high confidence malicious.
"""

import requests
import time
import base64
from colorama import Fore, Style, init

init(autoreset=True)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def check_ip(ip: str, api_key: str) -> dict:
    """
    Query VirusTotal for an IP address reputation.
    Returns detection counts and categories.
    """
    print(f"{Fore.CYAN}  [VT] Checking IP: {ip}{Style.RESET_ALL}")

    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}/ip_addresses/{ip}"

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as e:
        print(f"{Fore.RED}  [!] VT IP request failed: {e}{Style.RESET_ALL}")
        return {"error": str(e), "ioc": ip, "type": "ip"}

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        country = data.get("data", {}).get("attributes", {}).get(
            "country", "Unknown"
        )
        owner = data.get("data", {}).get("attributes", {}).get(
            "as_owner", "Unknown"
        )

        result = {
            "ioc": ip,
            "type": "ip",
            "source": "virustotal",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "country": country,
            "as_owner": owner,
            "verdict": _verdict(malicious, suspicious)
        }

        _print_result(result)
        return result

    elif response.status_code == 404:
        print(f"{Fore.YELLOW}  [VT] IP not found in VirusTotal database{Style.RESET_ALL}")
        return {
            "ioc": ip, "type": "ip", "source": "virustotal",
            "verdict": "unknown", "malicious_count": 0
        }

    elif response.status_code == 429:
        print(f"{Fore.YELLOW}  [VT] Rate limit hit — waiting 60 seconds{Style.RESET_ALL}")
        time.sleep(60)
        return check_ip(ip, api_key)

    else:
        print(f"{Fore.RED}  [VT] Error {response.status_code}: {response.text[:100]}{Style.RESET_ALL}")
        return {"error": response.status_code, "ioc": ip, "type": "ip"}


def check_url(url: str, api_key: str) -> dict:
    """
    Query VirusTotal for a URL.
    VT v3 requires the URL to be base64 encoded.
    """
    print(f"{Fore.CYAN}  [VT] Checking URL: {url}{Style.RESET_ALL}")

    headers = {"x-apikey": api_key}

    # VT API v3 requires URL encoded as base64 without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    try:
        response = requests.get(endpoint, headers=headers, timeout=15)
    except requests.RequestException as e:
        print(f"{Fore.RED}  [!] VT URL request failed: {e}{Style.RESET_ALL}")
        return {"error": str(e), "ioc": url, "type": "url"}

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        categories = data.get("data", {}).get("attributes", {}).get(
            "categories", {}
        )

        result = {
            "ioc": url,
            "type": "url",
            "source": "virustotal",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "categories": categories,
            "verdict": _verdict(malicious, suspicious)
        }

        _print_result(result)
        return result

    elif response.status_code == 404:
        # URL not in VT yet — submit it for scanning
        print(f"{Fore.YELLOW}  [VT] URL not in database, submitting for scan...{Style.RESET_ALL}")
        return _submit_url(url, api_key)

    elif response.status_code == 429:
        print(f"{Fore.YELLOW}  [VT] Rate limit hit — waiting 60 seconds{Style.RESET_ALL}")
        time.sleep(60)
        return check_url(url, api_key)

    else:
        print(f"{Fore.RED}  [VT] Error {response.status_code}{Style.RESET_ALL}")
        return {"error": response.status_code, "ioc": url, "type": "url"}


def check_hash(file_hash: str, api_key: str) -> dict:
    """
    Query VirusTotal for a file hash (MD5/SHA256).
    Used for email attachment analysis.
    """
    print(f"{Fore.CYAN}  [VT] Checking hash: {file_hash}{Style.RESET_ALL}")

    headers = {"x-apikey": api_key}
    endpoint = f"{VT_BASE_URL}/files/{file_hash}"

    try:
        response = requests.get(endpoint, headers=headers, timeout=15)
    except requests.RequestException as e:
        return {"error": str(e), "ioc": file_hash, "type": "hash"}

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        name = data.get("data", {}).get("attributes", {}).get(
            "meaningful_name", "unknown"
        )

        result = {
            "ioc": file_hash,
            "type": "hash",
            "source": "virustotal",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "file_name": name,
            "verdict": _verdict(malicious, suspicious)
        }

        _print_result(result)
        return result

    elif response.status_code == 404:
        print(f"{Fore.YELLOW}  [VT] Hash not found — file may be new/unknown{Style.RESET_ALL}")
        return {
            "ioc": file_hash, "type": "hash", "source": "virustotal",
            "verdict": "unknown", "malicious_count": 0
        }

    else:
        return {"error": response.status_code, "ioc": file_hash, "type": "hash"}


def _submit_url(url: str, api_key: str) -> dict:
    """Submit a new URL to VirusTotal for scanning."""
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        response = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data=f"url={url}",
            timeout=15
        )
        if response.status_code == 200:
            print(f"{Fore.GREEN}  [VT] URL submitted for scanning{Style.RESET_ALL}")
            time.sleep(15)
            return check_url(url, api_key)
    except Exception as e:
        return {"error": str(e), "ioc": url, "type": "url"}

    return {"ioc": url, "type": "url", "source": "virustotal", "verdict": "unknown"}


def _verdict(malicious: int, suspicious: int) -> str:
    """Determine verdict based on detection counts."""
    if malicious >= 5:
        return "malicious"
    elif malicious >= 1 or suspicious >= 3:
        return "suspicious"
    else:
        return "clean"


def _print_result(result: dict):
    """Print colored result summary."""
    verdict = result.get("verdict", "unknown")
    ioc = result.get("ioc", "")
    malicious = result.get("malicious_count", 0)
    total = result.get("total_engines", 0)

    color = Fore.RED if verdict == "malicious" else \
            Fore.YELLOW if verdict == "suspicious" else Fore.GREEN

    print(
        f"{color}  [VT] Result: {verdict.upper()} | "
        f"Detections: {malicious}/{total} engines{Style.RESET_ALL}"
    )
