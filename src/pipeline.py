"""
pipeline.py
-----------
Main pipeline runner — now with Elasticsearch integration.

Full flow:
1. Parse email
2. Extract IOCs
3. Check Elasticsearch for existing IOCs (avoid re-querying APIs)
4. Enrich new IOCs via VT, AbuseIPDB, URLScan
5. Score each IOC
6. Push results to Elasticsearch
7. Print investigation summary
"""

import sys
import json
import yaml
import uuid
from datetime import datetime, timezone
from colorama import Fore, Style, init

from email_parser import parse_email
from enrichment.virustotal import check_ip as vt_ip
from enrichment.virustotal import check_url as vt_url
from enrichment.virustotal import check_hash as vt_hash
from enrichment.abuseipdb import check_ip as abuse_ip
from enrichment.urlscan import search_existing as urlscan_url
from scorer import score_ioc
from elastic_client import (
    get_client, create_indices,
    push_ioc, push_investigation,
    check_existing_ioc
)

init(autoreset=True)


def load_config(config_path: str = "../config/config.yaml") -> dict:
    """Load configuration file."""
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(
            f"{Fore.RED}[!] Config file not found: {config_path}"
            f"{Style.RESET_ALL}"
        )
        sys.exit(1)


def run_pipeline(email_path: str, config: dict) -> dict:
    """Run the full phishing investigation pipeline."""

    api_keys = config.get("api_keys", {})
    vt_key = api_keys.get("virustotal", "")
    abuse_key = api_keys.get("abuseipdb", "")
    urlscan_key = api_keys.get("urlscan", "")

    es_config = config.get("elasticsearch", {})

    investigation_id = str(uuid.uuid4())[:8].upper()

    investigation = {
        "investigation_id": investigation_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
    print(f"INVESTIGATION ID: {investigation_id}")
    print("PHASE 1: EMAIL PARSING")
    print(f"{'='*60}{Style.RESET_ALL}")

    parsed = parse_email(email_path)
    if not parsed:
        print(f"{Fore.RED}[!] Email parsing failed. Aborting.{Style.RESET_ALL}")
        return investigation

    investigation["parsed_email"] = parsed
    flags = parsed.get("flags", [])

    # ─────────────────────────────────────────
    # PHASE 2: Connect to Elasticsearch
    # ─────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'='*60}")
    print("PHASE 2: ELASTICSEARCH CONNECTION")
    print(f"{'='*60}{Style.RESET_ALL}")

    es_client = get_client(
        host=es_config.get("host", "localhost"),
        port=es_config.get("port", 9200)
    )

    if es_client:
        create_indices(es_client)

    # ─────────────────────────────────────────
    # PHASE 3: IOC Enrichment
    # ─────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'='*60}")
    print("PHASE 3: IOC ENRICHMENT")
    print(f"{'='*60}{Style.RESET_ALL}")

    all_scored = []

    # --- Enrich originating IP ---
    orig_ip = parsed.get("originating_ip")
    if orig_ip:
        print(f"\n{Fore.YELLOW}[*] Enriching IP: {orig_ip}{Style.RESET_ALL}")

        # Check if we already know this IOC
        existing = check_existing_ioc(es_client, orig_ip) if es_client else None
        if existing:
            print(
                f"{Fore.CYAN}  [ES] Already investigated this IP: "
                f"{existing.get('verdict')} "
                f"(score: {existing.get('confidence_score')}){Style.RESET_ALL}"
            )
            all_scored.append({
                "ioc": orig_ip,
                "type": "ip",
                "verdict": existing.get("verdict", "UNKNOWN"),
                "confidence_score": existing.get("confidence_score", 0),
                "contributing_factors": ["Previously investigated — cached result"],
                "cached": True
            })
        else:
            ip_results = []
            if vt_key:
                ip_results.append(vt_ip(orig_ip, vt_key))
            if abuse_key:
                ip_results.append(abuse_ip(orig_ip, abuse_key))

            if ip_results:
                scored = score_ioc(ip_results, flags)
                all_scored.append(scored)
                investigation["ioc_results"].extend(ip_results)

                # Push to Elasticsearch
                if es_client:
                    push_ioc(es_client, scored, ip_results, investigation)

    # --- Enrich URLs ---
    urls = parsed.get("urls", [])
    for url in urls:
        print(f"\n{Fore.YELLOW}[*] Enriching URL: {url}{Style.RESET_ALL}")

        existing = check_existing_ioc(es_client, url) if es_client else None
        if existing:
            print(
                f"{Fore.CYAN}  [ES] Already investigated this URL: "
                f"{existing.get('verdict')}{Style.RESET_ALL}"
            )
            all_scored.append({
                "ioc": url,
                "type": "url",
                "verdict": existing.get("verdict", "UNKNOWN"),
                "confidence_score": existing.get("confidence_score", 0),
                "contributing_factors": ["Previously investigated — cached result"],
                "cached": True
            })
        else:
            url_results = []
            if vt_key:
                url_results.append(vt_url(url, vt_key))
            if urlscan_key:
                url_results.append(urlscan_url(url, urlscan_key))

            if url_results:
                scored = score_ioc(url_results, flags)
                all_scored.append(scored)
                investigation["ioc_results"].extend(url_results)

                if es_client:
                    push_ioc(es_client, scored, url_results, investigation)

    # --- Enrich attachment hashes ---
    for att in parsed.get("attachments", []):
        sha256 = att.get("sha256")
        if sha256 and vt_key:
            print(f"\n{Fore.YELLOW}[*] Enriching hash: {sha256}{Style.RESET_ALL}")
            hash_results = [vt_hash(sha256, vt_key)]
            scored = score_ioc(hash_results, flags)
            all_scored.append(scored)
            investigation["ioc_results"].extend(hash_results)

            if es_client:
                push_ioc(es_client, scored, hash_results, investigation)

    investigation["scored_iocs"] = all_scored

    # ─────────────────────────────────────────
    # PHASE 4: Final Summary + ES Push
    # ─────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'='*60}")
    print("PHASE 4: INVESTIGATION SUMMARY")
    print(f"{'='*60}{Style.RESET_ALL}")

    malicious = [i for i in all_scored if i["verdict"] == "MALICIOUS"]
    suspicious = [i for i in all_scored if i["verdict"] == "SUSPICIOUS"]
    clean = [i for i in all_scored if i["verdict"] == "CLEAN"]

    investigation["malicious_iocs"] = malicious
    investigation["suspicious_iocs"] = suspicious

    if malicious:
        overall = "MALICIOUS"
        color = Fore.RED
    elif suspicious:
        overall = "SUSPICIOUS"
        color = Fore.YELLOW
    else:
        overall = "LIKELY CLEAN"
        color = Fore.GREEN

    investigation["summary"] = {
        "overall_verdict": overall,
        "total_iocs": len(all_scored),
        "malicious_count": len(malicious),
        "suspicious_count": len(suspicious),
        "clean_count": len(clean),
        "flags": flags
    }

    # Push full investigation summary to ES
    if es_client:
        push_investigation(es_client, investigation)

    print(f"\n{color}  Investigation ID : {investigation_id}")
    print(f"  Overall Verdict  : {overall}")
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
            print(
                f"    🔴 {ioc['ioc']} "
                f"(score: {ioc['confidence_score']}/100)"
            )

    if suspicious:
        print(f"\n  Suspicious IOCs:")
        for ioc in suspicious:
            print(
                f"    🟡 {ioc['ioc']} "
                f"(score: {ioc['confidence_score']}/100)"
            )

    print(f"{Style.RESET_ALL}")

    return investigation


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pipeline.py <path_to_email.eml>")
        sys.exit(1)

    config = load_config("../config/config.yaml")
    result = run_pipeline(sys.argv[1], config)

    # Save raw JSON results
    ts = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    inv_id = result.get("investigation_id", "unknown")
    output_file = f"../reports/investigation-{inv_id}-{ts}.json"

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(
        f"{Fore.GREEN}[+] Full results saved to: {output_file}"
        f"{Style.RESET_ALL}"
    )
