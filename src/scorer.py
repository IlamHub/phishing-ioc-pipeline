"""
scorer.py
---------
Combines results from multiple enrichment sources
into a single IOC confidence score and verdict.

Scoring logic:
- VirusTotal malicious detections carry most weight
- AbuseIPDB confidence score contributes directly
- URLScan malicious flag adds to score
- Multiple sources agreeing = higher confidence

Final verdict:
- MALICIOUS  : score >= 70
- SUSPICIOUS : score >= 30
- CLEAN      : score < 30
"""

from colorama import Fore, Style, init

init(autoreset=True)


def score_ioc(enrichment_results: list, flags: list = None) -> dict:
    """
    Take a list of enrichment results for one IOC
    and produce a combined confidence score.

    enrichment_results: list of dicts from VT, AbuseIPDB, URLScan
    flags: list of parser flags (SPF_FAIL, etc.) for context
    """
    score = 0
    contributing_factors = []
    ioc = enrichment_results[0].get("ioc", "") if enrichment_results else ""
    ioc_type = enrichment_results[0].get("type", "") if enrichment_results else ""

    for result in enrichment_results:
        source = result.get("source", "unknown")
        verdict = result.get("verdict", "unknown")

        if source == "virustotal":
            malicious = result.get("malicious_count", 0)
            total = result.get("total_engines", 1) or 1
            detection_rate = (malicious / total) * 100

            if malicious >= 10:
                score += 50
                contributing_factors.append(
                    f"VT: {malicious} engines flagged as malicious"
                )
            elif malicious >= 5:
                score += 35
                contributing_factors.append(
                    f"VT: {malicious} engines flagged as malicious"
                )
            elif malicious >= 1:
                score += 20
                contributing_factors.append(
                    f"VT: {malicious} engine(s) flagged"
                )

            suspicious = result.get("suspicious_count", 0)
            if suspicious >= 3:
                score += 10
                contributing_factors.append(f"VT: {suspicious} suspicious detections")

        elif source == "abuseipdb":
            confidence = result.get("confidence_score", 0)
            reports = result.get("total_reports", 0)
            is_tor = result.get("is_tor", False)

            if is_tor:
                score += 40
                contributing_factors.append("AbuseIPDB: TOR exit node")

            if confidence >= 75:
                score += 40
                contributing_factors.append(
                    f"AbuseIPDB: {confidence}% confidence malicious"
                )
            elif confidence >= 25:
                score += 20
                contributing_factors.append(
                    f"AbuseIPDB: {confidence}% confidence malicious"
                )
            elif confidence >= 10:
                score += 10
                contributing_factors.append(
                    f"AbuseIPDB: {confidence}% confidence"
                )

            if reports >= 100:
                score += 15
                contributing_factors.append(
                    f"AbuseIPDB: {reports} community reports"
                )
            elif reports >= 10:
                score += 5
                contributing_factors.append(
                    f"AbuseIPDB: {reports} reports"
                )

        elif source == "urlscan":
            malicious = result.get("malicious", False)
            url_score = result.get("score", 0)
            brands = result.get("brands_targeted", [])

            if malicious:
                score += 40
                contributing_factors.append("URLScan: flagged as malicious")

            if url_score >= 75:
                score += 20
                contributing_factors.append(
                    f"URLScan: risk score {url_score}"
                )
            elif url_score >= 50:
                score += 10
                contributing_factors.append(
                    f"URLScan: risk score {url_score}"
                )

            if brands:
                score += 15
                contributing_factors.append(
                    f"URLScan: impersonating {', '.join(brands)}"
                )

    # Add points for parser flags (email context)
    if flags:
        flag_score_map = {
            "SPF_FAIL": 5,
            "DKIM_FAIL": 5,
            "DMARC_FAIL": 5,
            "REPLY_TO_MISMATCH": 10,
            "URGENCY_LANGUAGE": 5
        }
        for flag in flags:
            points = flag_score_map.get(flag, 0)
            if points:
                score += points
                contributing_factors.append(f"Email flag: {flag}")

    # Cap score at 100
    score = min(score, 100)

    # Determine final verdict
    if score >= 70:
        verdict = "MALICIOUS"
        color = Fore.RED
    elif score >= 30:
        verdict = "SUSPICIOUS"
        color = Fore.YELLOW
    else:
        verdict = "CLEAN"
        color = Fore.GREEN

    result = {
        "ioc": ioc,
        "type": ioc_type,
        "confidence_score": score,
        "verdict": verdict,
        "contributing_factors": contributing_factors
    }

    print(f"\n{color}{'='*50}")
    print(f"  IOC VERDICT: {verdict}")
    print(f"  IOC: {ioc}")
    print(f"  Confidence Score: {score}/100")
    print(f"  Factors:")
    for factor in contributing_factors:
        print(f"    - {factor}")
    print(f"{'='*50}{Style.RESET_ALL}")

    return result
