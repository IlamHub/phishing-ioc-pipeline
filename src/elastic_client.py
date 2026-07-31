"""
elastic_client.py
-----------------
Handles all Elasticsearch operations for the phishing pipeline.

What it does:
- Creates the phishing-iocs index with proper field mappings
- Pushes each IOC investigation result as a document
- Pushes the full email investigation summary
- Allows searching existing IOCs to avoid re-investigating known ones

Index structure:
- phishing-iocs: individual IOC records (one per IP/URL/hash)
- phishing-investigations: full email investigation records
"""

import json
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from colorama import Fore, Style, init

init(autoreset=True)


def get_client(host: str = "localhost", port: int = 9200) -> Elasticsearch:
    """Create and return Elasticsearch client."""
    try:
        client = Elasticsearch(
            hosts=[{"host": host, "port": port, "scheme": "http"}],
            request_timeout=30,
            verify_certs=False
        )
        info = client.info()
        print(f"{Fore.GREEN}  [ES] Connected to Elasticsearch "
              f"v{info['version']['number']}{Style.RESET_ALL}")
        return client
    except Exception as e:
        print(f"{Fore.RED}  [ES] Connection error: {e}{Style.RESET_ALL}")
        return None


def create_indices(client: Elasticsearch):
    """
    Create Elasticsearch indices with proper mappings.
    Mappings tell Elasticsearch what type each field is —
    geo_point for coordinates, keyword for exact-match fields,
    text for full-text search.
    """
    # --- IOC index mapping ---
    ioc_mapping = {
        "mappings": {
            "properties": {
                "@timestamp":        {"type": "date"},
                "ioc":               {"type": "keyword"},
                "ioc_type":          {"type": "keyword"},
                "verdict":           {"type": "keyword"},
                "confidence_score":  {"type": "integer"},
                "source":            {"type": "keyword"},
                "email_file":        {"type": "keyword"},
                "email_subject":     {"type": "text"},
                "email_from":        {"type": "keyword"},
                "email_flags":       {"type": "keyword"},
                "malicious_count":   {"type": "integer"},
                "total_engines":     {"type": "integer"},
                "abuseipdb_confidence": {"type": "integer"},
                "abuseipdb_reports": {"type": "integer"},
                "country":           {"type": "keyword"},
                "isp":               {"type": "keyword"},
                "is_tor":            {"type": "boolean"},
                "abuse_categories":  {"type": "keyword"},
                "page_title":        {"type": "text"},
                "screenshot_url":    {"type": "keyword"},
                "contributing_factors": {"type": "text"},
                "investigation_id":  {"type": "keyword"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }

    # --- Investigation index mapping ---
    investigation_mapping = {
        "mappings": {
            "properties": {
                "@timestamp":        {"type": "date"},
                "investigation_id":  {"type": "keyword"},
                "email_file":        {"type": "keyword"},
                "email_subject":     {"type": "text"},
                "email_from":        {"type": "keyword"},
                "email_to":          {"type": "keyword"},
                "originating_ip":    {"type": "ip"},
                "flags":             {"type": "keyword"},
                "overall_verdict":   {"type": "keyword"},
                "total_iocs":        {"type": "integer"},
                "malicious_count":   {"type": "integer"},
                "suspicious_count":  {"type": "integer"},
                "clean_count":       {"type": "integer"},
                "malicious_iocs":    {"type": "keyword"},
                "suspicious_iocs":   {"type": "keyword"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }

    # Create IOC index
    if not client.indices.exists(index="phishing-iocs"):
        client.indices.create(index="phishing-iocs", body=ioc_mapping)
        print(f"{Fore.GREEN}  [ES] Created index: phishing-iocs{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}  [ES] Index already exists: phishing-iocs{Style.RESET_ALL}")

    # Create investigations index
    if not client.indices.exists(index="phishing-investigations"):
        client.indices.create(
            index="phishing-investigations",
            body=investigation_mapping
        )
        print(
            f"{Fore.GREEN}  [ES] Created index: "
            f"phishing-investigations{Style.RESET_ALL}"
        )
    else:
        print(
            f"{Fore.YELLOW}  [ES] Index already exists: "
            f"phishing-investigations{Style.RESET_ALL}"
        )


def push_ioc(client: Elasticsearch, scored_ioc: dict,
             enrichment_results: list, investigation: dict) -> bool:
    """
    Push a single scored IOC document to Elasticsearch.
    Combines scorer output with raw enrichment data for full context.
    """
    if not client:
        return False

    parsed = investigation.get("parsed_email", {})
    headers = parsed.get("headers", {})
    timestamp = datetime.now(timezone.utc).isoformat()
    investigation_id = investigation.get("investigation_id", "unknown")

    # Build the base document
    doc = {
        "@timestamp": timestamp,
        "investigation_id": investigation_id,
        "ioc": scored_ioc.get("ioc", ""),
        "ioc_type": scored_ioc.get("type", ""),
        "verdict": scored_ioc.get("verdict", ""),
        "confidence_score": scored_ioc.get("confidence_score", 0),
        "contributing_factors": scored_ioc.get("contributing_factors", []),
        "email_file": investigation.get("email_file", ""),
        "email_subject": headers.get("subject", ""),
        "email_from": headers.get("from", ""),
        "email_flags": parsed.get("flags", [])
    }

    # Add enrichment details from each source
    for result in enrichment_results:
        source = result.get("source", "")

        if source == "virustotal":
            doc["vt_malicious_count"] = result.get("malicious_count", 0)
            doc["vt_total_engines"] = result.get("total_engines", 0)
            doc["vt_verdict"] = result.get("verdict", "")
            doc["country"] = result.get("country", "")
            doc["as_owner"] = result.get("as_owner", "")

        elif source == "abuseipdb":
            doc["abuseipdb_confidence"] = result.get("confidence_score", 0)
            doc["abuseipdb_reports"] = result.get("total_reports", 0)
            doc["country"] = result.get("country", "")
            doc["isp"] = result.get("isp", "")
            doc["is_tor"] = result.get("is_tor", False)
            doc["abuse_categories"] = result.get("abuse_categories", [])

        elif source == "urlscan":
            doc["page_title"] = result.get("page_title", "")
            doc["screenshot_url"] = result.get("screenshot_url", "")
            doc["final_url"] = result.get("final_url", "")
            doc["urlscan_score"] = result.get("score", 0)
            doc["brands_targeted"] = result.get("brands_targeted", [])

    try:
        response = client.index(index="phishing-iocs", document=doc)
        verdict = doc.get("verdict", "")
        color = Fore.RED if verdict == "MALICIOUS" else \
                Fore.YELLOW if verdict == "SUSPICIOUS" else Fore.GREEN
        print(
            f"{color}  [ES] Indexed IOC: {doc['ioc']} → "
            f"{verdict} (ID: {response['_id']}){Style.RESET_ALL}"
        )
        return True
    except Exception as e:
        print(f"{Fore.RED}  [ES] Failed to index IOC: {e}{Style.RESET_ALL}")
        return False


def push_investigation(client: Elasticsearch,
                       investigation: dict) -> bool:
    """
    Push the full investigation summary to Elasticsearch.
    One document per email analyzed.
    """
    if not client:
        return False

    parsed = investigation.get("parsed_email", {})
    headers = parsed.get("headers", {})
    summary = investigation.get("summary", {})
    timestamp = datetime.now(timezone.utc).isoformat()

    malicious_iocs = [
        i["ioc"] for i in investigation.get("malicious_iocs", [])
    ]
    suspicious_iocs = [
        i["ioc"] for i in investigation.get("suspicious_iocs", [])
    ]

    # Try to parse originating IP safely
    orig_ip = parsed.get("originating_ip")

    doc = {
        "@timestamp": timestamp,
        "investigation_id": investigation.get("investigation_id", ""),
        "email_file": investigation.get("email_file", ""),
        "email_subject": headers.get("subject", ""),
        "email_from": headers.get("from", ""),
        "email_to": headers.get("to", ""),
        "originating_ip": orig_ip,
        "flags": parsed.get("flags", []),
        "overall_verdict": summary.get("overall_verdict", ""),
        "total_iocs": summary.get("total_iocs", 0),
        "malicious_count": summary.get("malicious_count", 0),
        "suspicious_count": summary.get("suspicious_count", 0),
        "clean_count": summary.get("clean_count", 0),
        "malicious_iocs": malicious_iocs,
        "suspicious_iocs": suspicious_iocs
    }

    try:
        response = client.index(
            index="phishing-investigations",
            document=doc
        )
        print(
            f"{Fore.GREEN}  [ES] Investigation indexed "
            f"(ID: {response['_id']}){Style.RESET_ALL}"
        )
        return True
    except Exception as e:
        print(f"{Fore.RED}  [ES] Failed to index investigation: {e}{Style.RESET_ALL}")
        return False


def check_existing_ioc(client: Elasticsearch, ioc: str) -> dict:
    """
    Check if we've already investigated this IOC.
    Avoids re-querying APIs for known malicious indicators.
    """
    if not client:
        return None

    try:
        response = client.search(
            index="phishing-iocs",
            body={
                "query": {"term": {"ioc": ioc}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 1
            }
        )
        hits = response.get("hits", {}).get("hits", [])
        if hits:
            return hits[0].get("_source", {})
    except Exception:
        pass

    return None
