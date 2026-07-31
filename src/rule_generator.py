"""
rule_generator.py
-----------------
Automatically generates Suricata IDS rules from confirmed
malicious IOCs found during phishing investigations.

This closes the SOC feedback loop:
  phishing investigation → confirmed malicious IP
  → auto-generate Suricata rule
  → deploy to live Suricata
  → network traffic from that IP now triggers an alert

Why this matters:
  In a real SOC, threat intelligence from one investigation
  feeds directly into detection for ALL future traffic.
  If we find a malicious C2 IP in a phishing email,
  we immediately block/alert on that IP network-wide.

Rule types generated:
  - IP reputation rules (alert on any traffic from malicious IP)
  - DNS rules (alert if anyone resolves a malicious domain)
  - HTTP rules (alert on requests to malicious URLs)
"""

import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

# Starting SID for auto-generated rules
# Using 9000000+ range to avoid conflicts with
# your existing custom rules (1000001-1000012)
BASE_SID = 9000001


def generate_rules(scored_iocs: list, investigation_id: str,
                   email_subject: str = "") -> list:
    """
    Generate Suricata rules for all confirmed malicious
    or suspicious IOCs from an investigation.

    Returns a list of rule strings ready to write to file.
    """
    rules = []
    sid = _get_next_sid()

    print(f"\n{Fore.CYAN}[*] Generating Suricata rules for "
          f"investigation {investigation_id}{Style.RESET_ALL}")

    for ioc_data in scored_iocs:
        ioc = ioc_data.get("ioc", "")
        ioc_type = ioc_data.get("type", "")
        verdict = ioc_data.get("verdict", "")
        score = ioc_data.get("confidence_score", 0)

        # Only generate rules for malicious or high-confidence suspicious
        if verdict == "CLEAN":
            continue
        if verdict == "SUSPICIOUS" and score < 50:
            continue

        if ioc_type == "ip":
            new_rules = _generate_ip_rules(
                ioc, verdict, score, investigation_id, sid
            )
            rules.extend(new_rules)
            sid += len(new_rules)

        elif ioc_type == "url":
            new_rules = _generate_url_rules(
                ioc, verdict, score, investigation_id, sid
            )
            rules.extend(new_rules)
            sid += len(new_rules)

        elif ioc_type == "hash":
            # Suricata can't match file hashes directly in network
            # but we note it for documentation
            print(f"{Fore.YELLOW}  [RULES] Hash IOC noted "
                  f"(no network rule possible): {ioc[:16]}..."
                  f"{Style.RESET_ALL}")

    return rules


def _generate_ip_rules(ip: str, verdict: str, score: int,
                       investigation_id: str, sid: int) -> list:
    """
    Generate Suricata rules for a malicious IP address.
    Creates two rules:
    1. Alert on any INBOUND traffic FROM this IP
    2. Alert on any OUTBOUND traffic TO this IP
    """
    rules = []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    classtype = "trojan-activity" if verdict == "MALICIOUS" else "suspicious-login"
    action = "alert"

    # Rule 1: Inbound — attacker connecting TO us
    rule_inbound = (
        f'{action} ip {ip} any -> $HOME_NET any '
        f'(msg:"[PHISHING-PIPELINE] Malicious IP Inbound - '
        f'Investigation {investigation_id}"; '
        f'classtype:{classtype}; '
        f'reference:url,localhost/investigations/{investigation_id}; '
        f'metadata:confidence_score {score}, verdict {verdict}, '
        f'investigation_id {investigation_id}, created {timestamp}; '
        f'sid:{sid}; rev:1;)'
    )
    rules.append(rule_inbound)

    # Rule 2: Outbound — our machines connecting TO the attacker IP
    rule_outbound = (
        f'{action} ip $HOME_NET any -> {ip} any '
        f'(msg:"[PHISHING-PIPELINE] Malicious IP Outbound Contact - '
        f'Investigation {investigation_id}"; '
        f'classtype:{classtype}; '
        f'reference:url,localhost/investigations/{investigation_id}; '
        f'metadata:confidence_score {score}, verdict {verdict}, '
        f'investigation_id {investigation_id}, created {timestamp}; '
        f'sid:{sid + 1}; rev:1;)'
    )
    rules.append(rule_outbound)

    print(f"{Fore.GREEN}  [RULES] Generated 2 IP rules for: {ip} "
          f"(SIDs: {sid}, {sid+1}){Style.RESET_ALL}")

    return rules


def _generate_url_rules(url: str, verdict: str, score: int,
                        investigation_id: str, sid: int) -> list:
    """
    Generate Suricata HTTP rules for a malicious URL.
    Extracts the domain and path for matching.
    """
    rules = []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""

        # Clean domain for use in rule
        domain_clean = domain.replace('"', '').strip()

        if not domain_clean:
            return rules

        # Rule: Alert on HTTP requests to this domain
        rule = (
            f'alert http $HOME_NET any -> any any '
            f'(msg:"[PHISHING-PIPELINE] Phishing Domain Access - '
            f'Investigation {investigation_id}"; '
            f'flow:established,to_server; '
            f'http.host; content:"{domain_clean}"; nocase; '
            f'classtype:web-application-attack; '
            f'reference:url,localhost/investigations/{investigation_id}; '
            f'metadata:confidence_score {score}, verdict {verdict}, '
            f'investigation_id {investigation_id}, created {timestamp}; '
            f'sid:{sid}; rev:1;)'
        )
        rules.append(rule)

        print(f"{Fore.GREEN}  [RULES] Generated HTTP rule for domain: "
              f"{domain_clean} (SID: {sid}){Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}  [RULES] Failed to parse URL {url}: "
              f"{e}{Style.RESET_ALL}")

    return rules


def _get_next_sid() -> int:
    """
    Read existing generated rules to find the highest SID used,
    then return the next available SID.
    This prevents SID conflicts across investigations.
    """
    rules_dir = "../../rules/generated"
    if not os.path.exists(rules_dir):
        rules_dir = "../rules/generated"
    if not os.path.exists(rules_dir):
        return BASE_SID

    highest_sid = BASE_SID - 1

    for filename in os.listdir(rules_dir):
        if filename.endswith(".rules"):
            filepath = os.path.join(rules_dir, filename)
            try:
                with open(filepath, "r") as f:
                    content = f.read()
                sids = re.findall(r'sid:(\d+);', content)
                for sid in sids:
                    highest_sid = max(highest_sid, int(sid))
            except Exception:
                pass

    return highest_sid + 1


def save_rules(rules: list, investigation_id: str,
               output_dir: str = "../rules/generated") -> str:
    """
    Save generated rules to a file and optionally
    deploy them to the live Suricata instance.
    """
    if not rules:
        print(f"{Fore.YELLOW}  [RULES] No rules to save "
              f"(no qualifying IOCs){Style.RESET_ALL}")
        return None

    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"phishing-{investigation_id}-{timestamp}.rules"
    filepath = os.path.join(output_dir, filename)

    header = f"""# ================================================
# Auto-generated Suricata rules
# Investigation ID : {investigation_id}
# Generated        : {timestamp}
# Tool             : phishing-ioc-pipeline
# ================================================

"""
    with open(filepath, "w") as f:
        f.write(header)
        for rule in rules:
            f.write(rule + "\n")

    print(f"{Fore.GREEN}  [RULES] Saved {len(rules)} rules to: "
          f"{filepath}{Style.RESET_ALL}")

    return filepath


def deploy_to_suricata(rules_file: str,
                       suricata_rules_path: str = None) -> bool:
    """
    Deploy generated rules to the live Suricata instance.

    Appends the new rules to a dedicated phishing rules file
    that Suricata loads, then sends SIGUSR2 to reload rules
    without restarting Suricata.

    This is exactly how production SOCs push new threat intel
    rules to their IDS — no downtime, live reload.
    """
    if not rules_file or not os.path.exists(rules_file):
        return False

    # Default Suricata phishing rules path
    if not suricata_rules_path:
        suricata_rules_path = "/var/lib/suricata/rules/phishing-generated.rules"

    try:
        # Read our new rules
        with open(rules_file, "r") as f:
            new_rules = f.read()

        # Append to Suricata's phishing rules file
        with open(suricata_rules_path, "a") as f:
            f.write(f"\n{new_rules}")

        print(f"{Fore.GREEN}  [DEPLOY] Rules appended to: "
              f"{suricata_rules_path}{Style.RESET_ALL}")

        # Send SIGUSR2 to reload rules without restart
        import subprocess
        result = subprocess.run(
            ["sudo", "kill", "-USR2", "$(pidof suricata)"],
            shell=False,
            capture_output=True
        )

        # Try suricatasc as alternative
        result2 = subprocess.run(
            ["sudo", "suricatasc", "-c", "reload-rules"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if "OK" in result2.stdout:
            print(f"{Fore.GREEN}  [DEPLOY] Suricata rules reloaded "
                  f"successfully{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}  [DEPLOY] Rules written — reload Suricata "
                  f"manually with: sudo suricatasc -c reload-rules"
                  f"{Style.RESET_ALL}")
            return True

    except PermissionError:
        print(f"{Fore.YELLOW}  [DEPLOY] Permission denied writing to "
              f"{suricata_rules_path}")
        print(f"  Run: sudo python3 pipeline.py <email> to deploy rules"
              f"{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}  [DEPLOY] Deployment failed: {e}{Style.RESET_ALL}")
        return False
