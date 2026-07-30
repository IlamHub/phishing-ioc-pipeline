"""
pipeline.py
-----------
Main pipeline runner.
Orchestrates the full phishing investigation workflow:

1. Parse the email (.eml file)
2. Extract IOCs (IPs, URLs, hashes)
3. Enrich each IOC via VT, AbuseIPDB, URLScan
4. Score each IOC
5. Print investigation summary
6. (Next: push to Elasticsearch, generate Suricata rules, write report)
"""

import sys
import json
import yaml
from datetime import datetime
from colorama import Fore, Style, init

# Import our modules
from email_parser import parse_email
from enrichment.virustotal import check_ip as vt_ip
from enrichment.virustotal import check_url as vt_url
from enrichment.abuseipdb import check_ip as abuse_ip
from enrichment.urlscan import search_existing as urlscan_url
from scorer import score_ioc

init(autoreset=True)


def load_config(config_path: str = "../config/config.yaml") -> dict:
    """Load configuration file."""
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Config file not found: {config_path}{Style.RESET_ALL}")
        print("    Copy config/config.yaml.template to config/config.yaml and add your API keys")
        sys.exit(1)


def run_pipeline(email_path: str, config: dict) -> dict:
    """
    Run the full phishing investigation pipeline
    on a single .eml file.
    """
    api_keys = config.get("api_keys", {})
    vt_key = api_keys.get("virustotal", "")
    abuse_key = api_keys.get("abuseipdb", "")
    urlscan_key = api_keys.get("urlscan", "")

    investigation = {
        "timestamp": datetime.utcnow().isoformat(),
        "email_file": email_path,
        "parsed_email": {},
        "ioc_results": [],
        "scored_iocs": [],
        "malicious_iocs": [],
        "suspicious_iocs": [],
        "summary": {}
    }

    # ─────────────────────────────────────────
    # PHASE 1: Parse the email
    # ─────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'='*60}")
    print("PHASE 1: EMAIL PARSING")
    print(f"{'='*60}{Style.RESET_ALL}")

    parsed = parse_email(email_path)
    if not parsed:
        print(f"{Fore.RED}[!] Email parsing failed. Aborting.{Style.RESET_ALL}")
        return investigation

    investigation["parsed_email"] = parsed
    flags = parsed.get("flags", [])

    # ─────────────────────────────────────────
    # PHASE 2: Enrich IOCs
    # ─────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'='*60}")
    print("PHASE 2: IOC ENRICHMENT")
    print(f"{'='*60}{Style.RESET_ALL}")

    all_scored = []

    # --- Enrich originating IP ---
    orig_ip = parsed.get("originating_ip")
    if orig_ip:
        print(f"\n{Fore.YELLOW}[*] Enriching IP: {orig_ip}{Style.RESET_ALL}")
        ip_results = []

        if vt_key:
            ip_results.append(vt_ip(orig_ip, vt_key))
        if abuse_key:
            ip_results.append(abuse_ip(orig_ip, abuse_key))

        if ip_results:
            scored = score_ioc(ip_results, flags)
            all_scored.append(scored)
            investigation["ioc_results"].extend(ip_results)

    # --- Enrich URLs ---
    urls = parsed.get("urls", [])
    for url in urls:
        print(f"\n{Fore.YELLOW}[*] Enriching URL: {url}{Style.RESET_ALL}")
        url_results = []

        if vt_key:
            url_results.append(vt_url(url, vt_key))
        if urlscan_key:
            url_results.append(urlscan_url(url, urlscan_key))

        if url_results:
            scored = score_ioc(url_results, flags)
            all_scored.append(scored)
            investigation["ioc_results"].extend(url_results)

    # --- Enrich attachment hashes ---
    from enrichment.virustotal import check_hash as vt_hash
    for att in parsed.get("attachments", []):
        sha256 = att.get("sha256")
        if sha256 and vt_key:
            print(f"\n{Fore.YELLOW}[*] Enriching hash: {sha256}{Style.RESET_ALL}")
            hash_result = [vt_hash(sha256, vt_key)]
            scored = score_ioc(hash_result, flags)
            all_scored.append(scored)
            investigation["ioc_results"].extend(hash_result)

    investigation["scored_iocs"] = all_scored

    # ─────────────────────────────────────────
    # PHASE 3: Final Summary
    # ─────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'='*60}")
    print("PHASE 3: INVESTIGATION SUMMARY")
    print(f"{'='*60}{Style.RESET_ALL}")

    malicious = [i for i in all_scored if i["verdict"] == "MALICIOUS"]
    suspicious = [i for i in all_scored if i["verdict"] == "SUSPICIOUS"]
    clean = [i for i in all_scored if i["verdict"] == "CLEAN"]

    investigation["malicious_iocs"] = malicious
    investigation["suspicious_iocs"] = suspicious

    # Overall email verdict
    if malicious:
        overall = "MALICIOUS"
        color = Fore.RED
    elif suspicious:
        overall = "SUSPICIOUS"
        color = Fore.YELLOW
    else:
        overall = "LIKELY CLEAN"
        color = Fore.GREEN

    print(f"\n{color}  Overall Verdict  : {overall}")
    print(f"  Email Subject    : {parsed['headers'].get('subject', '')}")
    print(f"  From             : {parsed['headers'].get('from', '')}")
    print(f"  Originating IP   : {parsed.get('originating_ip', 'N/A')}")
    print(f"  Parser Flags     : {', '.join(flags) if flags else 'None'}")
    print(f"  Malicious IOCs   : {len(malicious)}")
    print(f"  Suspicious IOCs  : {len(suspicious)}")
    print(f"  Clean IOCs       : {len(clean)}")

    if malicious:
        print(f"\n  Malicious IOCs:")
        for ioc in malicious:
            print(f"    🔴 {ioc['ioc']} (score: {ioc['confidence_score']}/100)")

    if suspicious:
        print(f"\n  Suspicious IOCs:")
        for ioc in suspicious:
            print(f"    🟡 {ioc['ioc']} (score: {ioc['confidence_score']}/100)")

    print(f"{Style.RESET_ALL}")

    investigation["summary"] = {
        "overall_verdict": overall,
        "total_iocs": len(all_scored),
        "malicious_count": len(malicious),
        "suspicious_count": len(suspicious),
        "clean_count": len(clean),
        "flags": flags
    }

    return investigation


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pipeline.py <path_to_email.eml>")
        print("Example: python3 pipeline.py ../samples/test-phishing-01.eml")
        sys.exit(1)

    config = load_config("../config/config.yaml")
    result = run_pipeline(sys.argv[1], config)

    # Save raw results
    output_file = f"../reports/investigation-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\n{Fore.GREEN}[+] Raw results saved to: {output_file}{Style.RESET_ALL}")
