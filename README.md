# SRA Report Generator

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![PDF: ReportLab 4+](https://img.shields.io/badge/PDF-ReportLab%204%2B-lightgrey.svg)](https://www.reportlab.com/)
[![Python tests](https://github.com/Omiixx-nova/sra-report-generator/actions/workflows/python-tests.yml/badge.svg)](https://github.com/Omiixx-nova/sra-report-generator/actions/workflows/python-tests.yml)
[![CyberOps](https://img.shields.io/badge/CyberOps-SRA%20Reports-black.svg)](https://cyberops-ivory.vercel.app)

**Convert [`lawfirm-scanner`](https://github.com/Omiixx-nova/lawfirm-scanner) JSON into a professional, black-and-white PDF cyber security assessment report for UK law firms.**

The generator is designed for SRA submission packs, managing-partner briefings, professional-indemnity insurance renewal and IT-provider remediation work. It reads the scanner's native nested findings format, maps each issue to SRA cyber-security control themes, reproduces the scanner's scoring model, and renders a confidential multi-page PDF with ReportLab.

> **Important:** The report is an assessment aid, not legal advice, an SRA certificate, or a formal compliance determination. See [Legal disclaimer](#legal-disclaimer).

---

## Features

- **Scanner-native parsing** — supports `findings.<category>.checks[]` from `lawfirm-scanner`, plus flat lists and common scanner aliases.
- **Exact scoring parity** — mirrors `lawfirm-scanner/modules/scoring.py`: 100-point security score, severity deductions, A–F grade and CRITICAL/HIGH/MEDIUM/LOW level.
- **SRA mapping** — covers SSL/TLS, security headers, dangerous ports, email security, SPF/DMARC, exposed admin portals, data exposure, patching, asset inventory and governance.
- **Professional PDF** — cover, executive summary, one detailed page per CRITICAL/HIGH/MEDIUM finding, and a prioritised remediation roadmap.
- **Plain English** — business impact, evidence, recommendations, estimated effort and target timelines written for law-firm decision makers.
- **Safe rendering** — all scan-derived text is XML-escaped before it reaches ReportLab; Helvetica is used throughout.
- **CI tested** — unit tests, a CLI smoke test and PDF validation run on Python 3.10, 3.11 and 3.12.

## Installation

```bash
git clone https://github.com/Omiixx-nova/sra-report-generator.git
cd sra-report-generator

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Verify the CLI:

```bash
python generate.py --help
```

## Usage

```bash
python generate.py \
  --input reports/scan_example-lawfirm-co-uk_20261113_103000.json \
  --firm "Smith & Co Solicitors" \
  --output output \
  --date "13 November 2026"
```

Short options are also supported:

```bash
python generate.py -i scan.json -f "Jones Law" -o my_reports
```

Generate the included fictional demonstration report:

```bash
python generate.py \
  --input sample_input/example_scan.json \
  --firm "Example Law Firm LLP" \
  --output sample_output \
  --date "13 November 2026"
```

The output filename is derived from the firm name and assessment date, for example:

```text
sample_output/example_law_firm_llp_SRA_Assessment_20261113.pdf
```

Generated PDFs are intentionally git-ignored.

### CLI options

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--input`, `-i` | Yes | — | Path to a `lawfirm-scanner` JSON result |
| `--firm`, `-f` | Yes | — | Law firm name printed on the report |
| `--output`, `-o` | No | `output` | Directory for the generated PDF |
| `--date`, `-d` | No | today | Human-readable assessment date |

## Input format

The parser accepts the scanner's native shape:

```json
{
  "target": "example-lawfirm.co.uk",
  "scan_date": "2026-11-13T10:30:00Z",
  "scanner": "LawFirm Scanner v1.0 — CyberOps",
  "findings": {
    "ports": {
      "checks": [
        {
          "name": "Port 3389 (RDP)",
          "status": "FAIL",
          "detail": "OPEN — Remote desktop — major attack vector",
          "severity": "CRITICAL",
          "recommendation": "Block TCP/3389 at the perimeter firewall."
        }
      ],
      "open_ports": [80, 443, 3389]
    }
  },
  "score": {
    "score": 75,
    "grade": "B",
    "risk_level": "LOW",
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

Each normalised finding contains `title`, `severity`, `description`, `evidence`, `recommendation` and `category`, plus report-only fields such as `business_impact`, `fix_effort`, `timeline`, `timeline_bucket` and `action`. Optional scanner fields are preserved where useful; missing plain-English fields are generated from category and keyword templates. Checks with severity `NONE` are skipped.

A flat list such as `[{"title": "...", "severity": "HIGH", "evidence": "...", "recommendation": "..."}]` also works.

## Sample PDF

`sample_input/example_scan.json` is entirely fictional and uses `example-lawfirm.co.uk`. It contains **3 CRITICAL, 2 HIGH and 4 MEDIUM findings** across SSL/TLS, network security, email authentication, exposed services and HTTP security headers.

The generated sample PDF is black text on white paper with grey severity boxes and includes:

1. **Cover** — large report title, firm, date, author, random `CYBEROPS-2026-####` reference, assessed domain, a light-grey `CONFIDENTIAL` watermark and the CyberOps footer.
2. **Executive summary** — prominent assessment score, risk level, risk-exposure index, severity-count table, top three issues in plain English, SRA compliance status and a managing-partner paragraph.
3. **Detailed findings** — one page for each of the nine CRITICAL/HIGH/MEDIUM findings with severity box, description, evidence, business impact, SRA reference, recommendation and estimated fix effort.
4. **Remediation roadmap** — tables grouped into Immediate (0–7 days), Short term (7–30 days) and Long term (30–90 days), a sign-off box and the scope-limitations disclaimer.

Every page has a confidentiality footer, page number and `Prepared by CyberOps — brucesec.mumbai@gmail.com`.

## Scoring methodology

The `score` value deliberately keeps `lawfirm-scanner` semantics: **100 is clean, 0 is worst**. The PDF also shows a conventional `risk_score` / risk-exposure index where **100 is riskiest** (`risk_score = 100 - score`).

| Severity | Points deducted |
| --- | ---: |
| CRITICAL | 25 |
| HIGH | 15 |
| MEDIUM | 8 |
| LOW | 3 |
| NONE / PASS | 0 |

| Security score | Grade | Risk level |
| --- | --- | --- |
| 90–100 | A | LOW |
| 75–89 | B | LOW |
| 60–74 | C | MEDIUM |
| 40–59 | D | HIGH |
| 0–39 | F | CRITICAL |

The score is clamped at zero. The SRA compliance status shown in the report is a triage indicator: any critical finding or CRITICAL level produces `NON-COMPLIANT`, any other finding produces `REQUIRES ATTENTION`, and a clean finding set produces `COMPLIANT`.

## SRA mapping

`modules/sra_mapper.py` contains a comprehensive keyword-driven dictionary. Representative mappings:

| Finding type | Control theme |
| --- | --- |
| SSL/TLS, certificate expiry, weak ciphers | Secure communications |
| Missing HSTS, CSP or other security headers | Technical controls |
| Public RDP, databases, FTP, Telnet, SMB | Network security |
| Email security gaps | Client communication protection |
| No / weak DMARC or SPF | Anti-fraud measures |
| Exposed admin portals | Access control |
| Exposed `.env`, backups, config or cloud storage | Confidentiality and data protection |
| Unpatched software and version disclosure | Patch and vulnerability management |
| Subdomains and unknown hosts | Asset inventory and monitoring |
| Policies, training, logs and recovery plans | Governance and incident response |

References point to the [SRA Standards and Regulations](https://www.sra.org.uk/solicitors/standards-regulations/), particularly effective governance/systems and controls and client confidentiality, together with published [SRA cyber-security guidance](https://www.sra.org.uk/solicitors/resources/cybercrime/cybersecurity-advice/) and [information and cyber-security guidance](https://www.sra.org.uk/sra/research-publications/risk-outlook-2020-21/information-and-cyber-security/). The wording is a review aid and should be checked against current SRA materials before formal reliance.

## Project structure

```text
sra-report-generator/
├── generate.py
├── modules/
│   ├── __init__.py
│   ├── pdf_builder.py
│   ├── findings_parser.py
│   ├── sra_mapper.py
│   └── risk_scorer.py
├── sample_input/
│   └── example_scan.json
├── sample_output/
│   └── .gitkeep
├── tests/
│   ├── __init__.py
│   └── test_sra_report_generator.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── .github/
    └── workflows/
        └── python-tests.yml
```

## Tests and CI

```bash
python -m pip install -r requirements.txt pypdf
python -m unittest discover -s tests -v
```

`.github/workflows/python-tests.yml` byte-compiles the project, runs the unit tests, generates the sample report through the CLI and validates the resulting PDF with `pypdf` on every push and pull request. A generated sample PDF is uploaded as a CI artifact.

## Security and privacy

- Scanner JSON may contain hostnames, software versions and technical evidence. Treat it as confidential.
- Do not commit real assessment reports; `*.pdf`, `output/`, `ci_output/`, `reports/` and `sample_output/*` are git-ignored.
- Validate findings before acting on them. External checks can produce false positives because of proxies, CDNs, WAFs or sites that return HTTP 200 for every path.
- Only supply scan results for targets the firm owns or has explicit written permission to assess.

## Legal disclaimer

This software and its output are provided under the [MIT License](LICENSE) on an "as is" basis. The report is generated from supplied scanner data only and is not a penetration test, internal audit, legal advice, professional certification, guarantee of security, or a determination by the Solicitors Regulation Authority, Information Commissioner's Office, insurer or any other regulator. The SRA does not endorse this tool. It does not assess written policies, internal endpoints, backups, staff training, supplier controls or incident-response capability. The firm remains responsible for independent verification, remediation, current regulatory advice and any required notifications. Use of the scanner that produces the input must comply with the Computer Misuse Act 1990 and all other applicable law.

## Author

**Omkar Sawant — CyberOps**

- Website: [cyberops-ivory.vercel.app](https://cyberops-ivory.vercel.app)
- GitHub: [@Omiixx-nova](https://github.com/Omiixx-nova)
- Email: [brucesec.mumbai@gmail.com](mailto:brucesec.mumbai@gmail.com)

## License

MIT © 2026 Omkar Sawant.
