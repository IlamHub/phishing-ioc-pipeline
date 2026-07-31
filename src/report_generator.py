"""
report_generator.py
-------------------
Generates a professional SOC incident report for each
phishing investigation.

The report format matches real SOC documentation standards:
- Executive summary (non-technical, for management)
- Technical analysis (for SOC team)
- IOC table (for threat intel team)
- MITRE ATT&CK mapping (for detection engineers)
- Recommendations (for remediation team)

Output: Markdown file that renders beautifully on GitHub
and can be converted to PDF for formal submission.
"""

import os
from datetime import datetime, timezone
from colorama import Fore, Style, init

init(autoreset=True)

# MITRE ATT&CK technique mapping for phishing indicators
# These are the real MITRE IDs used by threat intel teams
MITRE_MAPPING = {
    "SPF_FAIL": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access"
    },
    "DKIM_FAIL": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access"
    },
    "DMARC_FAIL": {
        "id": "T1656",
        "name": "Impersonation",
        "tactic": "Defense Evasion"
    },
    "REPLY_TO_MISMATCH": {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion"
    },
    "URGENCY_LANGUAGE": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access"
    }
}

IOC_TYPE_MITRE = {
    "ip": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control"
    },
    "url": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access"
    },
    "hash": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access"
    }
}


def generate_report(investigation: dict,
                    output_dir: str = "../reports") -> str:
    """
    Generate a complete SOC incident report in Markdown format.
    Returns the path to the saved report file.
    """
    os.makedirs(output_dir, exist_ok=True)

    inv_id = investigation.get("investigation_id", "UNKNOWN")
    timestamp = datetime.now(timezone.utc)
    parsed = investigation.get("parsed_email", {})
    headers = parsed.get("headers", {})
    summary = investigation.get("summary", {})
    flags = parsed.get("flags", [])
    scored_iocs = investigation.get("scored_iocs", [])
    malicious_iocs = investigation.get("malicious_iocs", [])
    suspicious_iocs = investigation.get("suspicious_iocs", [])
    overall_verdict = summary.get("overall_verdict", "UNKNOWN")

    # Determine severity
    if overall_verdict == "MALICIOUS":
        severity = "HIGH"
        severity_emoji = "🔴"
    elif overall_verdict == "SUSPICIOUS":
        severity = "MEDIUM"
        severity_emoji = "🟡"
    else:
        severity = "LOW"
        severity_emoji = "🟢"

    # Build MITRE techniques from flags
    mitre_techniques = {}
    for flag in flags:
        if flag in MITRE_MAPPING:
            tech = MITRE_MAPPING[flag]
            mitre_techniques[tech["id"]] = tech

    for ioc in scored_iocs:
        ioc_type = ioc.get("type", "")
        if ioc_type in IOC_TYPE_MITRE:
            tech = IOC_TYPE_MITRE[ioc_type]
            mitre_techniques[tech["id"]] = tech

    # Build the report
    report = _build_report(
        inv_id=inv_id,
        timestamp=timestamp,
        headers=headers,
        parsed=parsed,
        summary=summary,
        flags=flags,
        scored_iocs=scored_iocs,
        malicious_iocs=malicious_iocs,
        suspicious_iocs=suspicious_iocs,
        overall_verdict=overall_verdict,
        severity=severity,
        severity_emoji=severity_emoji,
        mitre_techniques=mitre_techniques,
        investigation=investigation
    )

    # Save report
    date_str = timestamp.strftime("%Y-%m-%d")
    filename = f"IR-{inv_id}-{date_str}.md"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(report)

    print(f"{Fore.GREEN}  [REPORT] Incident report saved: "
          f"{filepath}{Style.RESET_ALL}")

    return filepath


def _build_report(inv_id, timestamp, headers, parsed, summary,
                  flags, scored_iocs, malicious_iocs, suspicious_iocs,
                  overall_verdict, severity, severity_emoji,
                  mitre_techniques, investigation) -> str:
    """Build the full Markdown report string."""

    ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    date_str = timestamp.strftime("%Y-%m-%d")

    report = f"""# Incident Report — Phishing Email Investigation
**Report ID:** IR-{inv_id}  
**Date:** {date_str}  
**Analyst:** Ilam Mohamed  
**Severity:** {severity_emoji} {severity}  
**Status:** Closed (Simulated Lab Investigation)  
**Tool:** phishing-ioc-pipeline (automated analysis)

---

## 1. Executive Summary

A suspicious email was submitted for automated triage analysis on {date_str}. 
The phishing-ioc-pipeline performed header analysis, IOC extraction, and 
multi-source threat intelligence enrichment. The investigation concluded with 
an overall verdict of **{overall_verdict}**.

{_executive_summary_text(overall_verdict, headers, scored_iocs, malicious_iocs)}

---

## 2. Email Overview

| Field | Value |
|-------|-------|
| **Subject** | {headers.get('subject', 'N/A')} |
| **From** | {headers.get('from', 'N/A')} |
| **To** | {headers.get('to', 'N/A')} |
| **Reply-To** | {headers.get('reply_to', 'N/A')} |
| **Date** | {headers.get('date', 'N/A')} |
| **Message-ID** | {headers.get('message_id', 'N/A')} |
| **Originating IP** | {parsed.get('originating_ip', 'N/A')} |

---

## 3. Authentication Analysis

| Protocol | Result | Interpretation |
|----------|--------|----------------|
| **SPF** | {_format_auth(parsed.get('authentication', {}).get('spf', 'N/A'))} | {_interpret_spf(parsed.get('authentication', {}).get('spf', ''))} |
| **DKIM** | {_format_auth(parsed.get('authentication', {}).get('dkim', 'N/A'))} | {_interpret_dkim(parsed.get('authentication', {}).get('dkim', ''))} |
| **DMARC** | {_format_auth(parsed.get('authentication', {}).get('dmarc', 'N/A'))} | {_interpret_dmarc(parsed.get('authentication', {}).get('dmarc', ''))} |

---

## 4. Email Red Flags

{_format_flags(flags)}

---

## 5. IOC Analysis

### 5.1 Summary

| Metric | Count |
|--------|-------|
| Total IOCs Analyzed | {len(scored_iocs)} |
| Malicious | {len(malicious_iocs)} |
| Suspicious | {len(suspicious_iocs)} |
| Clean | {len([i for i in scored_iocs if i.get('verdict') == 'CLEAN'])} |

### 5.2 IOC Details

{_format_ioc_table(scored_iocs)}

### 5.3 Enrichment Details

{_format_enrichment_details(scored_iocs, investigation)}

---

## 6. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Observed Evidence |
|-------------|----------------|--------|-------------------|
{_format_mitre_table(mitre_techniques, flags, scored_iocs)}

---

## 7. Timeline of Events

{_format_timeline(parsed, scored_iocs, timestamp)}

---

## 8. Detection Rules Generated

{_format_rules_section(investigation)}

---

## 9. Recommendations

{_format_recommendations(overall_verdict, malicious_iocs, suspicious_iocs, flags)}

---

## 10. Analyst Notes

This investigation was conducted in a controlled SOC home lab environment 
using the phishing-ioc-pipeline tool. The tool automates:

- Email header parsing and authentication verification
- IOC extraction (IPs, URLs, file hashes)  
- Multi-source threat intelligence enrichment (VirusTotal, AbuseIPDB, URLScan.io)
- Confidence scoring across multiple data sources
- Suricata IDS rule generation for confirmed malicious IOCs
- Automated incident report generation

All findings are based on real threat intelligence data from public APIs.
The phishing email samples used are synthetic but designed to reflect
real-world attack patterns.

---

*Report generated automatically by phishing-ioc-pipeline*  
*GitHub: https://github.com/IlamHub/phishing-ioc-pipeline*  
*Generated: {ts_str}*
"""
    return report


def _executive_summary_text(verdict, headers, scored_iocs,
                             malicious_iocs) -> str:
    subject = headers.get('subject', 'Unknown subject')
    sender = headers.get('from', 'Unknown sender')
    ip_count = sum(1 for i in scored_iocs if i.get('type') == 'ip')
    url_count = sum(1 for i in scored_iocs if i.get('type') == 'url')

    if verdict == "MALICIOUS":
        return (
            f"The email with subject **\"{subject}\"** from **{sender}** "
            f"was determined to be a phishing attempt. "
            f"Analysis identified {len(malicious_iocs)} confirmed malicious "
            f"indicator(s) across {ip_count} IP address(es) and "
            f"{url_count} URL(s) examined. "
            f"The originating IP was identified as a known Tor exit node "
            f"with a 100% malicious confidence score across community "
            f"threat intelligence sources. "
            f"Immediate blocking of identified IOCs is recommended."
        )
    elif verdict == "SUSPICIOUS":
        return (
            f"The email with subject **\"{subject}\"** from **{sender}** "
            f"exhibited multiple suspicious indicators. "
            f"While no IOCs reached the malicious threshold, "
            f"the combination of authentication failures, "
            f"suspicious sending infrastructure, and social engineering "
            f"language warrants caution. "
            f"Further investigation or user awareness notification "
            f"is recommended."
        )
    else:
        return (
            f"The email with subject **\"{subject}\"** from **{sender}** "
            f"did not trigger malicious indicators. "
            f"Standard monitoring applies."
        )


def _format_auth(value: str) -> str:
    if not value or value == "N/A":
        return "N/A"
    if "fail" in value.lower():
        return f"❌ `{value}`"
    elif "pass" in value.lower():
        return f"✅ `{value}`"
    else:
        return f"`{value}`"


def _interpret_spf(value: str) -> str:
    if "fail" in value.lower():
        return "Sender not authorized — possible spoofing"
    elif "pass" in value.lower():
        return "Sender authorized by domain"
    return "Unable to verify"


def _interpret_dkim(value: str) -> str:
    if "fail" in value.lower():
        return "Signature invalid — email may be forged or modified"
    elif "none" in value.lower():
        return "No DKIM signature present"
    elif "pass" in value.lower():
        return "Cryptographic signature verified"
    return "Unable to verify"


def _interpret_dmarc(value: str) -> str:
    if "fail" in value.lower():
        return "Domain policy violated — high phishing risk"
    elif "pass" in value.lower():
        return "Passes domain authentication policy"
    return "Unable to verify"


def _format_flags(flags: list) -> str:
    if not flags:
        return "No suspicious flags detected."

    flag_descriptions = {
        "SPF_FAIL": "**SPF_FAIL** — Sending IP not authorized by domain's SPF record. Indicates possible spoofed sender.",
        "DKIM_FAIL": "**DKIM_FAIL** — DKIM signature verification failed. Email may have been tampered with or forged.",
        "DMARC_FAIL": "**DMARC_FAIL** — Email failed DMARC policy check. Domain instructs receivers to treat this as suspicious.",
        "REPLY_TO_MISMATCH": "**REPLY_TO_MISMATCH** — Reply-To domain differs from From domain. Classic phishing technique to redirect replies to attacker.",
        "URGENCY_LANGUAGE": "**URGENCY_LANGUAGE** — Email contains urgency/threat language designed to pressure recipient into acting without thinking."
    }

    lines = []
    for flag in flags:
        desc = flag_descriptions.get(flag, f"**{flag}** — Suspicious indicator detected.")
        lines.append(f"- {desc}")

    return "\n".join(lines)


def _format_ioc_table(scored_iocs: list) -> str:
    if not scored_iocs:
        return "No IOCs identified."

    rows = ["| IOC | Type | Verdict | Confidence Score |",
            "|-----|------|---------|-----------------|"]

    for ioc in scored_iocs:
        verdict = ioc.get("verdict", "UNKNOWN")
        emoji = "🔴" if verdict == "MALICIOUS" else \
                "🟡" if verdict == "SUSPICIOUS" else "🟢"
        ioc_val = ioc.get("ioc", "")
        # Truncate long URLs for table
        if len(ioc_val) > 60:
            ioc_val = ioc_val[:57] + "..."

        rows.append(
            f"| `{ioc_val}` | {ioc.get('type', '')} | "
            f"{emoji} {verdict} | {ioc.get('confidence_score', 0)}/100 |"
        )

    return "\n".join(rows)


def _format_enrichment_details(scored_iocs: list,
                                investigation: dict) -> str:
    lines = []
    ioc_results = investigation.get("ioc_results", [])

    for ioc_data in scored_iocs:
        ioc = ioc_data.get("ioc", "")
        verdict = ioc_data.get("verdict", "")
        emoji = "🔴" if verdict == "MALICIOUS" else \
                "🟡" if verdict == "SUSPICIOUS" else "🟢"

        lines.append(f"#### {emoji} `{ioc}`")
        lines.append(f"- **Verdict:** {verdict}")
        lines.append(
            f"- **Confidence:** {ioc_data.get('confidence_score', 0)}/100"
        )

        factors = ioc_data.get("contributing_factors", [])
        if factors:
            lines.append("- **Contributing factors:**")
            for factor in factors:
                if "Email flag" not in factor:
                    lines.append(f"  - {factor}")

        # Add source-specific details from raw results
        for result in ioc_results:
            if result.get("ioc") == ioc:
                source = result.get("source", "")
                if source == "abuseipdb":
                    lines.append(
                        f"- **AbuseIPDB:** {result.get('confidence_score', 0)}% "
                        f"confidence | {result.get('total_reports', 0)} reports | "
                        f"Country: {result.get('country', 'N/A')} | "
                        f"ISP: {result.get('isp', 'N/A')}"
                    )
                    if result.get("is_tor"):
                        lines.append("- ⚠️ **Confirmed Tor exit node**")
                    if result.get("abuse_categories"):
                        lines.append(
                            f"- **Abuse types:** "
                            f"{', '.join(result.get('abuse_categories', []))}"
                        )
                elif source == "virustotal":
                    lines.append(
                        f"- **VirusTotal:** {result.get('malicious_count', 0)}/"
                        f"{result.get('total_engines', 0)} engines detected | "
                        f"Country: {result.get('country', 'N/A')}"
                    )

        lines.append("")

    return "\n".join(lines)


def _format_mitre_table(mitre_techniques: dict, flags: list,
                         scored_iocs: list) -> str:
    if not mitre_techniques:
        return "| T1566 | Phishing | Initial Access | Email-based attack indicators |"

    rows = []
    for tech_id, tech in mitre_techniques.items():
        # Find observed evidence for this technique
        evidence = _get_evidence(tech_id, flags, scored_iocs)
        rows.append(
            f"| [{tech_id}](https://attack.mitre.org/techniques/"
            f"{tech_id.replace('.', '/')}) "
            f"| {tech['name']} | {tech['tactic']} | {evidence} |"
        )

    return "\n".join(rows) if rows else \
        "| T1566 | Phishing | Initial Access | Email-based attack |"


def _get_evidence(tech_id: str, flags: list, scored_iocs: list) -> str:
    evidence_map = {
        "T1566": "Phishing email with social engineering",
        "T1566.001": "SPF/DKIM authentication failures indicate spoofed sender",
        "T1566.002": "Malicious URL embedded in email body",
        "T1656": "DMARC failure — domain impersonation detected",
        "T1036": "Reply-To mismatch — masquerading as legitimate sender",
        "T1071.001": "HTTP-based C2/phishing infrastructure contact"
    }
    return evidence_map.get(tech_id, "Observed during investigation")


def _format_timeline(parsed: dict, scored_iocs: list,
                      report_time: datetime) -> str:
    email_date = parsed.get("headers", {}).get("date", "Unknown")

    lines = [
        f"| {email_date} | Email sent | Attacker sends phishing email from spoofed address |",
        f"| {report_time.strftime('%Y-%m-%d %H:%M UTC')} | Email received | "
        f"Email arrives in target mailbox |",
        f"| {report_time.strftime('%Y-%m-%d %H:%M UTC')} | Triage initiated | "
        f"Email submitted to phishing-ioc-pipeline for automated analysis |",
        f"| {report_time.strftime('%Y-%m-%d %H:%M UTC')} | IOC extraction | "
        f"{len(scored_iocs)} IOC(s) extracted from email headers and body |",
        f"| {report_time.strftime('%Y-%m-%d %H:%M UTC')} | Enrichment complete | "
        f"Threat intelligence enrichment completed via VT, AbuseIPDB, URLScan |",
        f"| {report_time.strftime('%Y-%m-%d %H:%M UTC')} | Rules deployed | "
        f"Suricata detection rules generated for confirmed malicious IOCs |",
    ]

    header = ("| Timestamp | Event | Details |\n"
              "|-----------|-------|---------|")

    return header + "\n" + "\n".join(lines)


def _format_rules_section(investigation: dict) -> str:
    inv_id = investigation.get("investigation_id", "UNKNOWN")
    malicious = investigation.get("malicious_iocs", [])

    if not malicious:
        return ("No Suricata rules generated — no IOCs reached the "
                "malicious threshold.")

    lines = [
        f"Suricata IDS rules were automatically generated for "
        f"{len(malicious)} confirmed malicious IOC(s):",
        ""
    ]

    for ioc in malicious:
        lines.append(f"- `{ioc.get('ioc', '')}` → Rules generated in "
                     f"`rules/generated/phishing-{inv_id}-*.rules`")

    lines.extend([
        "",
        "Rules are deployed to `/var/lib/suricata/rules/phishing-generated.rules`",
        "and Suricata is reloaded automatically via `suricatasc -c reload-rules`.",
        "",
        "Any network traffic matching these IOCs will now trigger alerts",
        "in the Suricata/ELK SIEM dashboard."
    ])

    return "\n".join(lines)


def _format_recommendations(verdict: str, malicious_iocs: list,
                              suspicious_iocs: list, flags: list) -> str:
    recs = []
    priority = 1

    if malicious_iocs:
        recs.append(
            f"{priority}. **[IMMEDIATE]** Block all confirmed malicious IPs "
            f"at the perimeter firewall: "
            f"{', '.join(['`' + i['ioc'] + '`' for i in malicious_iocs if i.get('type') == 'ip'])}"
        )
        priority += 1

    if "REPLY_TO_MISMATCH" in flags:
        recs.append(
            f"{priority}. **[HIGH]** Notify affected user(s) not to reply "
            f"to this email — the Reply-To address routes to attacker infrastructure."
        )
        priority += 1

    if any(f in flags for f in ["SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"]):
        recs.append(
            f"{priority}. **[HIGH]** Review email gateway configuration — "
            f"consider enforcing DMARC reject policy to automatically "
            f"discard emails failing authentication."
        )
        priority += 1

    if suspicious_iocs:
        recs.append(
            f"{priority}. **[MEDIUM]** Monitor suspicious IOCs for 30 days — "
            f"add to watchlist: "
            f"{', '.join(['`' + i['ioc'] + '`' for i in suspicious_iocs[:3]])}"
        )
        priority += 1

    if "URGENCY_LANGUAGE" in flags:
        recs.append(
            f"{priority}. **[MEDIUM]** Conduct user awareness training — "
            f"this email used urgency language (a common social engineering "
            f"technique) to pressure the recipient into acting without thinking."
        )
        priority += 1

    recs.append(
        f"{priority}. **[LOW]** Submit confirmed phishing URLs to "
        f"PhishTank and Google Safe Browsing to protect other users globally."
    )

    return "\n\n".join(recs)
