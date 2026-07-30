"""
abuseipdb.py
------------
Queries AbuseIPDB for IP reputation.

AbuseIPDB is a community-driven database where network
administrators report malicious IPs. It tells us:
- How many times an IP has been reported
- What categories of abuse (spam, brute force, phishing)
- A confidence score (0-100%) that it is malicious
- The country and ISP of the IP
"""

import requests
from colorama import Fore, Style, init

init(autoreset=True)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB abuse category codes mapped to human-readable names
CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}


def check_ip(ip: str, api_key: str) -> dict:
    """
    Query AbuseIPDB for an IP address.
    Returns confidence score, report count, and abuse categories.
    """
    print(f"{Fore.CYAN}  [ABUSEIPDB] Checking IP: {ip}{Style.RESET_ALL}")

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=15
        )
    except requests.RequestException as e:
        print(f"{Fore.RED}  [!] AbuseIPDB request failed: {e}{Style.RESET_ALL}")
        return {"error": str(e), "ioc": ip, "type": "ip"}

    if response.status_code == 200:
        data = response.json().get("data", {})

        confidence = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        country = data.get("countryCode", "Unknown")
        isp = data.get("isp", "Unknown")
        domain = data.get("domain", "Unknown")
        is_tor = data.get("isTor", False)
        is_public = data.get("isPublic", True)

        # Get abuse categories from recent reports
        reports = data.get("reports", [])
        category_ids = set()
        for report in reports[:10]:
            for cat in report.get("categories", []):
                category_ids.add(cat)

        category_names = [
            CATEGORIES.get(c, f"Category {c}") for c in category_ids
        ]

        result = {
            "ioc": ip,
            "type": "ip",
            "source": "abuseipdb",
            "confidence_score": confidence,
            "total_reports": total_reports,
            "country": country,
            "isp": isp,
            "domain": domain,
            "is_tor": is_tor,
            "abuse_categories": category_names,
            "verdict": _verdict(confidence, total_reports, is_tor)
        }

        _print_result(result)
        return result

    elif response.status_code == 422:
        print(f"{Fore.YELLOW}  [ABUSEIPDB] Invalid IP format or private IP{Style.RESET_ALL}")
        return {
            "ioc": ip, "type": "ip", "source": "abuseipdb",
            "verdict": "private_or_invalid", "confidence_score": 0
        }

    elif response.status_code == 429:
        print(f"{Fore.YELLOW}  [ABUSEIPDB] Rate limit reached for today{Style.RESET_ALL}")
        return {
            "ioc": ip, "type": "ip", "source": "abuseipdb",
            "verdict": "rate_limited", "confidence_score": 0
        }

    else:
        print(
            f"{Fore.RED}  [ABUSEIPDB] Error {response.status_code}: "
            f"{response.text[:100]}{Style.RESET_ALL}"
        )
        return {"error": response.status_code, "ioc": ip, "type": "ip"}


def _verdict(confidence: int, reports: int, is_tor: bool) -> str:
    """
    Determine verdict based on AbuseIPDB data.
    Tor exit nodes are always flagged — phishing emails
    often route through Tor to hide origin.
    """
    if is_tor:
        return "malicious"
    if confidence >= 75:
        return "malicious"
    elif confidence >= 25 or reports >= 5:
        return "suspicious"
    else:
        return "clean"


def _print_result(result: dict):
    """Print colored result."""
    verdict = result.get("verdict", "unknown")
    confidence = result.get("confidence_score", 0)
    reports = result.get("total_reports", 0)
    country = result.get("country", "?")
    isp = result.get("isp", "?")
    is_tor = result.get("is_tor", False)
    categories = result.get("abuse_categories", [])

    color = Fore.RED if verdict == "malicious" else \
            Fore.YELLOW if verdict == "suspicious" else Fore.GREEN

    print(
        f"{color}  [ABUSEIPDB] Confidence: {confidence}% | "
        f"Reports: {reports} | Country: {country} | "
        f"ISP: {isp}{Style.RESET_ALL}"
    )

    if is_tor:
        print(f"{Fore.RED}  [ABUSEIPDB] ⚠ This is a TOR exit node{Style.RESET_ALL}")

    if categories:
        print(
            f"{color}  [ABUSEIPDB] Abuse types: "
            f"{', '.join(categories)}{Style.RESET_ALL}"
        )
