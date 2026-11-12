"""Map technical findings to SRA cyber-security themes and control language.

The mappings are *guidance-aligned reference aids*. They point to the SRA
Standards and Regulations and published SRA information/cyber-security
guidance; they are not a legal determination or an SRA certificate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

SRA_GENERAL_REFERENCE = (
    "SRA Standards and Regulations — Code of Conduct for Firms 2.1 "
    "(effective governance, systems and controls) and paragraph 6.3 of the "
    "Codes of Conduct (client confidentiality); SRA information and cyber "
    "security guidance."
)

# Comprehensive, keyword-driven mapping dictionary. Each entry supplies a
# short control theme, a formal-looking reference string for the report, and
# the plain-English requirement text used by the PDF builder.
SRA_MAPPINGS: dict[str, dict[str, Any]] = {
    "ssl_tls": {
        "theme": "Secure communications",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Secure communications",
        "requirement": (
            "Maintain effective systems and controls for secure client "
            "communications: enforce HTTPS, keep TLS certificates valid, verify "
            "certificate chains and retire obsolete protocols or weak ciphers."
        ),
        "keywords": (
            "ssl", "tls", "certificate", "cert expiry", "expired", "expiry",
            "https", "cipher", "protocol", "chain", "secure communication",
        ),
        "category_hints": ("ssl", "tls", "certificate"),
        "priority": 9,
    },
    "security_headers": {
        "theme": "Technical controls",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Technical controls",
        "requirement": (
            "Keep public-facing systems protected with appropriate technical "
            "measures, including browser-enforced security headers, secure "
            "configuration and timely patching to protect client information."
        ),
        "keywords": (
            "header", "hsts", "strict-transport-security", "content-security-policy",
            "csp", "x-frame-options", "x-content-type-options", "referrer-policy",
            "permissions-policy", "clickjacking", "mime sniffing", "xss",
            "server header", "information disclosure", "x-powered-by",
        ),
        "category_hints": ("header", "technical control", "web application"),
        "priority": 9,
    },
    "network_security": {
        "theme": "Network security",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Network security",
        "requirement": (
            "Review network exposure and maintain effective firewall and access "
            "controls. Management, remote-access and database services should not "
            "be reachable from the public internet unless explicitly justified."
        ),
        "keywords": (
            "port", "rdp", "3389", "ftp", "telnet", "smb", "ssh", "vnc", "mysql",
            "postgresql", "mongodb", "mssql", "database", "firewall", "open",
            "remote desktop", "network",
        ),
        "category_hints": ("port", "network", "firewall"),
        "priority": 9,
    },
    "client_communications": {
        "theme": "Client communication protection",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Client communication protection",
        "requirement": (
            "Protect client correspondence and client money from interception "
            "and impersonation. Maintain secure email configuration, staff "
            "reporting lines and a verified process for changes to bank details."
        ),
        "keywords": (
            "email", "mail", "mx", "webmail", "client communication", "correspondence",
            "phishing", "invoice", "bank detail", "secure email", "interception",
        ),
        "category_hints": ("email", "communication"),
        "priority": 7,
    },
    "admin_access": {
        "theme": "Access control",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Access control",
        "requirement": (
            "Restrict administrative portals and privileged access to authorised "
            "users. Apply least privilege, multi-factor authentication, unique "
            "accounts, strong passwords and monitoring of failed log-ins."
        ),
        "keywords": (
            "admin", "administrator", "wp-admin", "wp-login", "login portal",
            "cpanel", "phpmyadmin", "server manager", "webmail", "authentication",
            "mfa", "2fa", "password", "privileged", "access control", "default account",
        ),
        "category_hints": ("access", "authentication", "admin"),
        "priority": 8,
    },
    "anti_fraud": {
        "theme": "Anti-fraud measures",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Anti-fraud measures",
        "requirement": (
            "Maintain effective controls against email modification fraud and "
            "bogus-firm impersonation, including SPF, DKIM where available, an "
            "enforcing DMARC policy and independent verification of payment details."
        ),
        "keywords": (
            "dmarc", "spf", "dkim", "no dmarc", "no spf", "email modification fraud",
            "invoice fraud", "spoof", "impersonat", "bank detail", "payment diversion",
        ),
        "category_hints": ("anti-fraud", "email authentication"),
        "priority": 10,
    },
    "data_protection": {
        "theme": "Confidentiality and data protection",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Client data protection",
        "requirement": (
            "Keep confidential client information and legally privileged material "
            "inaccessible to unauthorised persons. Remove exposed files, restrict "
            "storage and backups, and use appropriate technical measures under data "
            "protection law."
        ),
        "keywords": (
            ".env", "environment file", "secret", "credential", "api key", "backup",
            ".git", "config", "directory", "bucket", "exposed", "publicly accessible",
            "client data", "confidential", "privileged", "information leak",
        ),
        "category_hints": ("exposure", "storage", "data"),
        "priority": 8,
    },
    "vulnerability_management": {
        "theme": "Patch and vulnerability management",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Patch management",
        "requirement": (
            "Keep software and operating systems supported and updated, maintain "
            "an asset inventory, assess known vulnerabilities and retest after fixes."
        ),
        "keywords": (
            "outdated", "unpatched", "cve", "version", "apache", "nginx", "wordpress",
            "plugin", "patch", "update", "end of life", "unsupported",
        ),
        "category_hints": ("patch", "vulnerability", "version"),
        "priority": 6,
    },
    "asset_management": {
        "theme": "Asset inventory and monitoring",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Asset management",
        "requirement": (
            "Maintain an up-to-date inventory of internet-facing assets, review "
            "discovered subdomains and services, and assign an owner to each asset."
        ),
        "keywords": (
            "subdomain", "dns", "certificate transparency", "discovered", "inventory",
            "attack surface", "unknown host", "forgotten", "monitor",
        ),
        "category_hints": ("subdomain", "dns", "inventory", "surface"),
        "priority": 5,
    },
    "incident_response": {
        "theme": "Policies, training and incident response",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Governance and incident response",
        "requirement": (
            "Maintain written cyber-security policies, staff training, incident "
            "reporting, tested backups and a recovery plan. Record cyber incidents "
            "and weaknesses and review them for patterns."
        ),
        "keywords": (
            "policy", "procedure", "training", "incident", "response plan", "recovery",
            "disaster recovery", "log", "no blame", "reporting line", "backup test",
        ),
        "category_hints": ("policy", "governance", "training", "incident"),
        "priority": 5,
    },
    "effective_systems": {
        "theme": "Effective systems and controls",
        "standard": "SRA Cyber Security Standards (guidance-aligned) — Effective systems and controls",
        "requirement": (
            "Maintain effective governance, systems and controls to protect client "
            "information and money. Record the finding, assign an owner, remediate "
            "it and retain evidence of review and retesting."
        ),
        "keywords": (),
        "category_hints": (),
        "priority": 0,
    },
}

# Alias for callers that prefer a requirements-oriented name.
SRA_REQUIREMENTS = SRA_MAPPINGS

_CATEGORY_BIASES = {
    "ssl / tls": "ssl_tls",
    "network security": "network_security",
    "security headers": "security_headers",
    "email security": "client_communications",
    "exposed services": "data_protection",
    "attack surface": "asset_management",
    "cloud storage": "data_protection",
    "web application": "security_headers",
}


def _finding_text(finding: Mapping[str, Any]) -> str:
    fields = (
        "title", "description", "evidence", "recommendation", "category",
        "business_impact", "scanner_category", "status",
    )
    return " ".join(str(finding.get(field, "")) for field in fields).lower()


def _keyword_score(mapping: dict[str, Any], haystack: str) -> int:
    score = 0
    for keyword in mapping.get("keywords", ()):
        if keyword in haystack:
            score += 2 + (2 * len(keyword.split()))
    return score


def _choose_mapping(finding: Mapping[str, Any]) -> str:
    haystack = _finding_text(finding)
    category = str(finding.get("category", "")).lower()

    # Explicit control families take precedence over the broad category bias.
    # Exposed administrative interfaces must always map to access control.
    admin_tokens = (
        "admin portal", "/admin", "wp-admin", "wp-login", "administrator",
        "administrative login", "login portal", "login page", "cpanel",
        "phpmyadmin", "server manager",
    )
    if any(token in haystack for token in admin_tokens):
        return "admin_access"

    # SPF/DKIM/DMARC findings are anti-fraud controls first, even though they
    # also sit under the broader email/communications theme.
    if any(token in haystack for token in ("dmarc", "spf", "dkim")):
        return "anti_fraud"

    scores = {key: _keyword_score(value, haystack) for key, value in SRA_MAPPINGS.items()}
    for mapping in SRA_MAPPINGS.values():
        for hint in mapping.get("category_hints", ()):
            if hint in category:
                scores_key = next(
                    key for key, value in SRA_MAPPINGS.items() if value is mapping
                )
                scores[scores_key] += 3

    bias_key = _CATEGORY_BIASES.get(category)
    if bias_key in scores:
        scores[bias_key] += 8

    return max(
        scores,
        key=lambda key: (scores[key], SRA_MAPPINGS[key]["priority"]),
    )


def get_mapping(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Return the SRA mapping record selected for one finding."""
    key = _choose_mapping(finding)
    result = dict(SRA_MAPPINGS[key])
    result["mapping_key"] = key
    result["reference"] = f"{SRA_GENERAL_REFERENCE} Control theme: {result['theme']}."
    return result


def map_to_sra(findings: Sequence[Mapping[str, Any] | Any]) -> list[dict[str, Any]]:
    """Return copies of findings enriched with SRA reference text."""
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        raise ValueError("findings must be a list of finding dictionaries")

    mapped: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise ValueError("every finding must be a dictionary")
        record = get_mapping(finding)
        enriched = dict(finding)
        enriched.update({
            "sra_mapping_key": record["mapping_key"],
            "sra_theme": record["theme"],
            "sra_standard": record["standard"],
            "sra_reference": record["reference"],
            "sra_requirement": record["requirement"],
        })
        mapped.append(enriched)
    return mapped
