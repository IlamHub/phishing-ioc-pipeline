"""
email_parser.py
---------------
Entry point of the phishing pipeline.
Reads a .eml file and extracts:
- All email headers (From, To, Subject, Received chain)
- Authentication results (SPF, DKIM, DMARC)
- Originating IP address
- All URLs found in the body
- Attachment info (filename, hash)
"""

import re
import hashlib
import mailparser
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)


def parse_email(filepath: str) -> dict:
    """
    Parse a .eml file and return a structured dictionary
    of all extracted data.
    """
    print(f"{Fore.CYAN}[*] Parsing email: {filepath}{Style.RESET_ALL}")

    try:
        mail = mailparser.parse_from_file(filepath)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to parse email: {e}{Style.RESET_ALL}")
        return {}

    result = {
        "file": filepath,
        "headers": {},
        "authentication": {},
        "originating_ip": None,
        "urls": [],
        "attachments": [],
        "flags": [],
        "raw_body": ""
    }

    # --- Basic headers ---
    result["headers"] = {
        "from": str(mail.from_),
        "to": str(mail.to),
        "subject": mail.subject or "",
        "date": str(mail.date),
        "reply_to": str(mail.reply_to) if mail.reply_to else None,
        "message_id": mail.message_id or "",
        "x_mailer": mail.headers.get("X-Mailer", None)
    }

    print(f"{Fore.GREEN}  [+] From     : {result['headers']['from']}")
    print(f"  [+] Subject  : {result['headers']['subject']}")
    print(f"  [+] Reply-To : {result['headers']['reply_to']}{Style.RESET_ALL}")

    # --- Authentication Results ---
    auth_header = mail.headers.get("Authentication-Results", "")
    result["authentication"] = {
        "spf": _extract_auth_result(auth_header, "spf"),
        "dkim": _extract_auth_result(auth_header, "dkim"),
        "dmarc": _extract_auth_result(auth_header, "dmarc"),
        "raw": auth_header
    }

    spf = result["authentication"]["spf"]
    dkim = result["authentication"]["dkim"]
    dmarc = result["authentication"]["dmarc"]

    print(f"\n{Fore.YELLOW}  [AUTH] SPF : {spf}")
    print(f"  [AUTH] DKIM: {dkim}")
    print(f"  [AUTH] DMARC: {dmarc}{Style.RESET_ALL}")

    # --- Raise flags based on auth failures ---
    if spf and "fail" in spf.lower():
        result["flags"].append("SPF_FAIL")
        print(f"{Fore.RED}  [!] FLAG: SPF failed — sender not authorized{Style.RESET_ALL}")

    if dkim and "fail" in dkim.lower():
        result["flags"].append("DKIM_FAIL")
        print(f"{Fore.RED}  [!] FLAG: DKIM failed — email may be forged{Style.RESET_ALL}")

    if dmarc and "fail" in dmarc.lower():
        result["flags"].append("DMARC_FAIL")
        print(f"{Fore.RED}  [!] FLAG: DMARC failed — domain policy violation{Style.RESET_ALL}")

    # --- Extract originating IP from Received headers ---
    received_headers = mail.received or []
    result["originating_ip"] = _extract_originating_ip(mail.headers)

    if result["originating_ip"]:
        print(f"\n{Fore.CYAN}  [IP] Originating IP: {result['originating_ip']}{Style.RESET_ALL}")

    # --- Check Reply-To mismatch ---
    from_domain = _extract_domain_from_email(result["headers"]["from"])
    reply_to_domain = _extract_domain_from_email(
        result["headers"]["reply_to"] or ""
    )

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        result["flags"].append("REPLY_TO_MISMATCH")
        print(
            f"{Fore.RED}  [!] FLAG: Reply-To domain ({reply_to_domain}) "
            f"differs from From domain ({from_domain}){Style.RESET_ALL}"
        )

    # --- Extract URLs from body ---
    body_html = mail.body or ""
    result["raw_body"] = body_html
    result["urls"] = _extract_urls(body_html)

    if result["urls"]:
        print(f"\n{Fore.YELLOW}  [URLs] Found {len(result['urls'])} URL(s):{Style.RESET_ALL}")
        for url in result["urls"]:
            print(f"    → {url}")

    # --- Extract attachments ---
    for att in mail.attachments:
        att_data = {
            "filename": att.get("filename", "unknown"),
            "content_type": att.get("mail_content_type", ""),
            "md5": None,
            "sha256": None
        }
        payload = att.get("payload", "")
        if payload:
            try:
                import base64
                decoded = base64.b64decode(payload)
                att_data["md5"] = hashlib.md5(decoded).hexdigest()
                att_data["sha256"] = hashlib.sha256(decoded).hexdigest()
            except Exception:
                pass

        result["attachments"].append(att_data)
        print(
            f"\n{Fore.YELLOW}  [ATT] Attachment: {att_data['filename']} "
            f"| SHA256: {att_data['sha256']}{Style.RESET_ALL}"
        )

    # --- Urgency language check ---
    urgent_words = ["urgent", "suspended", "immediately", "verify now",
                    "account will be", "click here", "24 hours", "action required"]
    body_lower = body_html.lower()
    found_urgent = [w for w in urgent_words if w in body_lower]
    if found_urgent:
        result["flags"].append("URGENCY_LANGUAGE")
        print(
            f"\n{Fore.RED}  [!] FLAG: Urgency language detected: "
            f"{', '.join(found_urgent)}{Style.RESET_ALL}"
        )

    print(f"\n{Fore.GREEN}  [+] Total flags raised: {len(result['flags'])}")
    print(f"  [+] Flags: {result['flags']}{Style.RESET_ALL}")

    return result


def _extract_auth_result(auth_header: str, protocol: str) -> str:
    """Extract pass/fail result for SPF, DKIM, or DMARC."""
    pattern = rf"{protocol}=(\S+)"
    match = re.search(pattern, auth_header, re.IGNORECASE)
    return match.group(1).rstrip(";") if match else "not_found"


def _extract_originating_ip(headers: dict) -> str:
    """
    Extract the true originating IP from Received headers.
    The LAST Received header in the chain is the external sender.
    We look for IPs that are NOT private/internal.
    """
    received_raw = headers.get("Received", "")
    if isinstance(received_raw, list):
        received_raw = " ".join(received_raw)

    # Find all IPs in Received headers
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', received_raw)

    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.",
                        "172.18.", "127.", "0.")

    for ip in reversed(ips):
        if not any(ip.startswith(p) for p in private_prefixes):
            return ip

    return None


def _extract_domain_from_email(email_str: str) -> str:
    """Extract domain from an email address string."""
    match = re.search(r'@([\w.-]+)', email_str)
    return match.group(1).lower() if match else None


def _extract_urls(body: str) -> list:
    """Extract all URLs from HTML or plain text body."""
    urls = []

    # Extract from href attributes
    soup = BeautifulSoup(body, "html.parser")
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith("http"):
            urls.append(href)

    # Also regex-extract any raw URLs
    raw_urls = re.findall(
        r'https?://[^\s<>"\']+', body
    )
    for url in raw_urls:
        if url not in urls:
            urls.append(url)

    # Deduplicate
    return list(set(urls))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 email_parser.py <path_to_email.eml>")
        sys.exit(1)

    result = parse_email(sys.argv[1])
    print("\n" + "="*50)
    print("PARSED EMAIL SUMMARY")
    print("="*50)
    import json
    print(json.dumps(result, indent=2, default=str))
