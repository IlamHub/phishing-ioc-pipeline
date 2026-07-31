# Phishing IOC Analysis Pipeline

An automated phishing email investigation pipeline that performs header analysis, IOC extraction, multi-source threat intelligence enrichment, Suricata IDS rule generation, and incident report writing — end to end with zero manual steps.

Built as a SOC home lab project to demonstrate real Tier 1 analyst workflows.

---

## Architecture

~~~
[Phishing Email .eml]
        |
        v
[Phase 1: Email Parser]
  - Header extraction
  - SPF / DKIM / DMARC analysis
  - Originating IP extraction
  - URL extraction
  - Urgency language detection
        |
        v
[Phase 2: Elasticsearch]
  - IOC cache check
  - Index: phishing-iocs
  - Index: phishing-investigations
        |
        v
[Phase 3: IOC Enrichment]
  - VirusTotal API    (90+ AV engines)
  - AbuseIPDB API     (community IP reports)
  - URLScan.io API    (sandbox URL analysis)
        |
        v
[Phase 4: IOC Scoring]
  - Confidence score 0-100
  - Verdict: MALICIOUS / SUSPICIOUS / CLEAN
        |
        v
[Phase 5: Suricata Rule Generator]
  - Auto-generates IDS rules for malicious IOCs
  - Deploys to live Suricata instance
  - Reloads rules without restart
        |
        v
[Phase 6: Incident Report]
  - Professional Markdown report
  - MITRE ATT&CK mapping
  - IOC table, timeline, recommendations
~~~

---

## Stack

| Tool | Role |
|------|------|
| Python 3 | Core pipeline language |
| VirusTotal API | IP / URL / hash threat intelligence |
| AbuseIPDB API | IP reputation and abuse history |
| URLScan.io API | Sandboxed URL analysis |
| Elasticsearch 8.13 | IOC storage and search |
| Kibana 8.13 | IOC visualization dashboard |
| Suricata 8.x | IDS rule deployment |

---

## Phishing Scenarios Covered

| # | Scenario | Technique |
|---|----------|-----------|
| 1 | Fake Microsoft credential harvest | T1566.002 - Spearphishing Link |
| 2 | Fake PayPal account limitation | T1656 - Impersonation |
| 3 | Fake DHL delivery fee | T1036 - Masquerading |

---

## MITRE ATT&CK Techniques Detected

| ID | Name | Tactic |
|----|------|--------|
| T1566 | Phishing | Initial Access |
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1566.002 | Spearphishing Link | Initial Access |
| T1656 | Impersonation | Defense Evasion |
| T1036 | Masquerading | Defense Evasion |
| T1071.001 | Web Protocol C2 | Command and Control |

---

## Detection Signals

- SPF / DKIM / DMARC authentication failures
- Reply-To domain mismatch
- Urgency language patterns
- Tor exit node identification
- VirusTotal multi-engine detection
- AbuseIPDB community confidence scoring

---

## Quick Start

~~~bash
# 1. Clone
git clone https://github.com/IlamHub/phishing-ioc-pipeline.git
cd phishing-ioc-pipeline

# 2. Set up environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Configure API keys
cp config/config.yaml.template config/config.yaml
nano config/config.yaml

# 4. Run pipeline
cd src
python3 pipeline.py ../samples/test-phishing-01.eml
~~~

---

## Project Structure

~~~
phishing-ioc-pipeline/
├── src/
│   ├── pipeline.py           <- Main runner (6 phases)
│   ├── email_parser.py       <- Header + IOC extraction
│   ├── scorer.py             <- Multi-source confidence scoring
│   ├── rule_generator.py     <- Suricata rule auto-generation
│   ├── report_generator.py   <- Incident report writer
│   └── enrichment/
│       ├── virustotal.py     <- VT API wrapper
│       ├── abuseipdb.py      <- AbuseIPDB API wrapper
│       └── urlscan.py        <- URLScan.io API wrapper
├── samples/                  <- Phishing email samples (.eml)
├── reports/                  <- Generated incident reports (IR-*.md)
├── rules/generated/          <- Auto-generated Suricata rules
├── config/
│   └── config.yaml.template  <- API key template
└── docs/screenshots/         <- Portfolio evidence
~~~

---

## Pipeline Output

For each email analyzed the pipeline produces:

1. **Terminal output** - live colored investigation feed across 6 phases
2. **Elasticsearch documents** - IOCs and investigation indexed for search
3. **Kibana dashboard** - visual IOC analysis (verdicts, scores, countries)
4. **Suricata rules** - deployed to live IDS, reloaded without restart
5. **Incident report** - reports/IR-{ID}-{date}.md with full documentation
6. **JSON export** - raw investigation data for further processing

---

## Sample Output

~~~
INVESTIGATION ID: 17DA33B9
PHASE 1: EMAIL PARSING
  [+] From     : security-alert@micros0ft-verify.com
  [+] Subject  : [URGENT] Your Microsoft Account Will Be Suspended
  [AUTH] SPF : fail
  [AUTH] DKIM: fail
  [AUTH] DMARC: fail
  [!] FLAG: SPF failed - sender not authorized
  [!] FLAG: Reply-To domain differs from From domain
  [IP] Originating IP: 185.220.101.45

PHASE 3: IOC ENRICHMENT
  [VT] Result: MALICIOUS | Detections: 15/91 engines
  [ABUSEIPDB] Confidence: 100% | Reports: 136 | TOR exit node

  IOC VERDICT: MALICIOUS
  IOC: 185.220.101.45
  Confidence Score: 100/100

PHASE 5: SURICATA RULE GENERATION
  [RULES] Generated 2 IP rules (SIDs: 9000009, 9000010)
  [DEPLOY] Suricata rules reloaded successfully

PHASE 6: INCIDENT REPORT
  [REPORT] Incident report saved: reports/IR-17DA33B9-2026-07-31.md
~~~

---

## Skills Demonstrated

- Email forensics (header analysis, SPF/DKIM/DMARC)
- Threat intelligence enrichment (multi-source API integration)
- IOC confidence scoring logic
- Detection engineering (Suricata rule writing and deployment)
- SIEM integration (Elasticsearch indexing, Kibana dashboards)
- SOC incident documentation (professional IR report writing)
- MITRE ATT&CK framework mapping
- Python automation for security workflows

---

## Complementary Project

This pipeline feeds into the [kali-soc-lab](https://github.com/IlamHub/kali-soc-lab) — a full Suricata + ELK SOC detection lab. Malicious IOCs discovered during phishing investigations are automatically deployed as Suricata detection rules, closing the threat intelligence feedback loop.

---

## API Keys Required

| Service | Free Tier | Link |
|---------|-----------|------|
| VirusTotal | 500 requests/day | https://www.virustotal.com |
| AbuseIPDB | 1000 requests/day | https://www.abuseipdb.com |
| URLScan.io | 5 scans/minute | https://urlscan.io |

---

*Ilam Mohamed - SOC Home Lab Portfolio*
*LinkedIn: linkedin.com/in/ilam-mtr*
*GitHub: github.com/IlamHub*
