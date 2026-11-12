"""Normalise lawfirm-scanner JSON into a clean, report-ready findings list.

The parser accepts the scanner's native nested shape::

    {"findings": {"ports": {"checks": [{"name", "status", "detail",
                                        "severity", ...}]}}}

It also accepts a top-level list of findings and common aliases used by other
scanners. Only actionable severities (CRITICAL, HIGH, MEDIUM, LOW) are kept;
passed checks with severity ``NONE`` are deliberately discarded.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Iterator

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
REPORTABLE_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

_ROOT_KEYS = ("findings", "results", "vulnerabilities", "issues", "checks")
_NESTED_ROOT_KEYS = ("scan", "data", "report", "result")
_CHECK_CONTAINER_KEYS = ("checks", "findings", "results", "issues", "items")
_METADATA_KEYS = {
    "target", "domain", "host", "url", "firm", "scan_date", "scanner",
    "score", "summary", "metadata", "assessment", "date", "version",
}
_SEVERITY_KEYS = ("severity", "risk", "risk_level", "riskLevel", "level", "priority")
_STATUS_KEYS = ("status", "state", "result_status")
_TITLE_KEYS = ("title", "name", "finding", "check", "issue", "check_name")
_BODY_KEYS = (
    "detail", "description", "evidence", "message", "observation", "output",
    "value", "result", "what_was_found",
)
_ID_KEYS = ("id", "finding_id", "check_id", "findingId")
_CATEGORY_KEYS = ("category", "type", "finding_type", "check_type", "module", "source")
_DESCRIPTION_KEYS = ("description", "plain_english", "plainEnglish", "summary", "message")
_EVIDENCE_KEYS = ("evidence", "what_was_found", "whatWasFound", "observed", "raw_evidence", "output")
_RECOMMENDATION_KEYS = (
    "recommendation", "remediation", "fix", "solution", "action",
    "remediation_action", "mitigation",
)
_IMPACT_KEYS = ("business_impact", "impact", "businessImpact", "risk_statement")
_EFFORT_KEYS = ("fix_effort", "effort", "estimated_effort", "estimatedEffort")
_TIMELINE_KEYS = ("timeline", "remediation_timeline", "target_timeline", "remediation_window")

_CATEGORY_LABELS = {
    "ssl": "SSL / TLS",
    "tls": "SSL / TLS",
    "ports": "Network Security",
    "port": "Network Security",
    "headers": "Security Headers",
    "email": "Email Security",
    "exposures": "Exposed Services",
    "exposure": "Exposed Services",
    "subdomains": "Attack Surface",
    "dns": "Attack Surface",
    "web": "Web Application",
    "cloud": "Cloud Storage",
}

_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL", "CRIT": "CRITICAL", "SEVERE": "CRITICAL",
    "VERY HIGH": "CRITICAL", "VERY_HIGH": "CRITICAL", "P1": "CRITICAL",
    "HIGH": "HIGH", "MAJOR": "HIGH", "P2": "HIGH",
    "MEDIUM": "MEDIUM", "MED": "MEDIUM", "MODERATE": "MEDIUM", "P3": "MEDIUM",
    "LOW": "LOW", "MINOR": "LOW", "INFO": "LOW", "INFORMATIONAL": "LOW",
    "INFORMATION": "LOW", "NOTE": "LOW", "P4": "LOW",
    "NONE": "", "N/A": "", "NA": "", "NULL": "", "OK": "", "PASS": "",
    "CLEAN": "", "NO FINDING": "", "NOT APPLICABLE": "", "0": "",
}

_PLAIN_DESCRIPTIONS = (
    (("rdp", "3389", "remote desktop"),
     "A remote-desktop service is reachable from the public internet. Attackers can use this exposure to try stolen passwords, exploit remote-access weaknesses and attempt to reach internal systems."),
    (("dmarc",),
     "The domain does not publish an effective DMARC policy. Criminals can send email that looks as though it came from the firm, which is a common route to invoice and bank-detail fraud."),
    (("spf",),
     "The sender policy for the firm's domain is incomplete or too permissive. Some unauthorised messages may still be delivered to clients as though they came from the firm."),
    (("environment file", ".env", "secret", "credential", "api key"),
     "A configuration file or credential-bearing resource is accessible from the public web server. These files often contain passwords or keys that should never leave the firm's private infrastructure."),
    (("admin portal", "/admin", "wp-admin", "administrator", "login page", "cpanel", "phpmyadmin"),
     "An administrative login page is visible from the internet. This gives attackers a place to guess passwords, reuse leaked credentials and probe for weak access controls."),
    (("hsts", "strict-transport-security", "forces https"),
     "The website does not instruct browsers to use an encrypted connection every time. Client and staff sessions are more vulnerable to interception on untrusted networks."),
    (("content-security-policy", "csp missing", "x-frame-options", "clickjacking", "mime sniffing"),
     "A browser security header is missing. The website has less protection against common attacks such as cross-site scripting, clickjacking or content-type confusion."),
    (("certificate expiry", "expires in", "expired", "tls certificate", "ssl certificate"),
     "The website's TLS certificate is close to expiry or no longer valid. Secure connections may fail or display warnings to clients and fee earners."),
    (("information disclosure", "server header", "x-powered-by", "software version"),
     "The web server reveals technical version information. This helps attackers match known software vulnerabilities to the firm's public systems."),
    (("backup",),
     "A backup location is visible on the public web server. If access rules change or directory listing is enabled, confidential client data and recovery copies may be exposed."),
    (("port", "ftp", "telnet", "smb", "database", "firewall"),
     "A network service that should be private is exposed to the internet. Public management and database services are frequent targets for automated attacks."),
)

_BUSINESS_IMPACTS = (
    (("rdp", "3389", "remote desktop"),
     "Internet-facing remote access could lead to ransomware, unauthorised access to matter files and interruption of time-critical conveyancing or client-money work."),
    (("dmarc", "spf", "email", "invoice", "spoof", "impersonat"),
     "Clients may act on fraudulent payment instructions, causing direct financial loss, complaints, SRA notification considerations and disputes with the firm's PI insurer."),
    ((".env", "environment file", "secret", "credential", "api key"),
     "Leaked credentials could allow access to client records, case-management systems or email, with confidentiality, data-protection and privileged-document consequences."),
    (("admin", "login", "portal", "cpanel", "phpmyadmin"),
     "A compromised administrative account could expose uploaded documents, alter client-facing content or provide a foothold for further access."),
    (("hsts", "ssl", "tls", "certificate", "https"),
     "Clients and staff may lose secure access to online services or receive browser warnings, weakening confidence in the firm's protection of confidential information."),
    (("backup", "cloud", "bucket", "directory"),
     "Client records and privileged documents could be disclosed, and recovery from a ransomware or system-failure incident may be impaired."),
    (("port", "database", "firewall", "network"),
     "Public services increase the likelihood of unauthorised access, service disruption and exploitation of unpatched software."),
)

_DEFAULT_IMPACTS = {
    "CRITICAL": "Client confidentiality, client money and the firm's ability to operate could be placed at direct and immediate risk.",
    "HIGH": "The issue materially increases the chance of unauthorised access, fraud or disruption to client services.",
    "MEDIUM": "The issue weakens the firm's security controls and should be corrected before it is combined with another weakness.",
    "LOW": "The issue has limited immediate impact but should be recorded, owned and reviewed as part of routine security hygiene.",
}

_RECOMMENDATIONS = (
    (("dmarc",),
     "Publish a DMARC TXT record, align SPF and DKIM, review aggregate reports, and move to an enforcing quarantine or reject policy. Use a callback process to verify changes to bank details."),
    (("spf",),
     "Review all authorised mail senders, tighten the SPF record to a hard-fail policy and verify alignment with DMARC."),
    (("rdp", "3389", "remote desktop"),
     "Block public remote-desktop access at the firewall, use a VPN and multi-factor authentication for any remaining remote access, restrict source addresses and review authentication logs."),
    (("environment file", ".env", "secret", "credential", "api key"),
     "Remove the resource from the web root, deny access to hidden files, rotate all exposed credentials and review access logs for suspicious activity."),
    (("admin", "login", "portal", "cpanel", "phpmyadmin"),
     "Restrict administrative access to authorised networks, enforce multi-factor authentication and least privilege, remove default accounts and enable failed-login monitoring."),
    (("hsts", "strict-transport-security"),
     "Configure HSTS with a suitable max-age, redirect HTTP to HTTPS and confirm that all included subdomains support TLS."),
    (("content-security-policy", "csp"),
     "Define and test a Content-Security-Policy, then deploy it in report-only mode before enforcement."),
    (("certificate", "expiry", "tls", "ssl"),
     "Renew the certificate, automate renewal monitoring, verify the chain and disable obsolete protocols and weak ciphers."),
    (("backup",),
     "Move backups outside the public document root, restrict and test restores, and keep at least one segregated or offline copy."),
    (("port", "database", "firewall"),
     "Close unnecessary public ports, restrict management services to trusted networks, update the firewall policy and record the approved exposure."),
)


def _clean(value: Any, limit: int | None = None) -> str:
    """Convert any JSON value to a clean, printable string."""
    text = _as_text(value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 3)].rstrip() + "..."
    return text


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        try:
            return json.dumps(dict(value), indent=2, sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return str(value)
    if isinstance(value, set):
        return "\n".join(_as_text(v) for v in sorted(value, key=str))
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return "\n".join(_as_text(v) for v in value if v is not None)
    return str(value)


def _first(mapping: Mapping[str, Any], keys: Sequence[str], default: str = "") -> str:
    for key in keys:
        if key in mapping and mapping[key] not in (None, "", [], {}):
            return _clean(mapping[key])
    return default


def normalize_severity(value: Any, status: str = "") -> str:
    """Normalise severity aliases to one of the four reportable levels.

    Returns an empty string for passed checks / no finding.
    """
    raw = _clean(value).upper()
    state = _clean(status).upper()

    if raw:
        if raw in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[raw]
        if raw.isdigit():
            numeric = int(raw)
            if numeric <= 0:
                return ""
            if numeric == 1:
                return "LOW"
            if numeric == 2:
                return "MEDIUM"
            if numeric == 3:
                return "HIGH"
            return "CRITICAL"
        compact = re.sub(r"[\s_-]+", " ", raw)
        if compact in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[compact]
        # Unknown but explicitly stated severity: fail safe, do not under-report.
        return "MEDIUM"

    if state in {"PASS", "OK", "CLEAN", "SUCCESS", "NONE"}:
        return ""
    if state in {"FAIL", "ERROR", "VULNERABLE"}:
        return "HIGH"
    if state in {"WARN", "WARNING"}:
        return "MEDIUM"
    if state in {"INFO", "INFORMATION", "NOTE"}:
        return "LOW"
    return ""


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if value is None:
        return []
    return [value]


def _category_label(raw_key: Any, item: Mapping[str, Any] | None = None) -> str:
    if item:
        explicit = _first(item, _CATEGORY_KEYS)
        if explicit:
            return explicit
    key = re.sub(r"[_-]+", " ", _clean(raw_key)).strip().lower()
    return _CATEGORY_LABELS.get(key, key.title() if key else "General")


def _looks_like_finding(node: Mapping[str, Any]) -> bool:
    has_severity_or_status = (
        any(key in node for key in _SEVERITY_KEYS)
        or any(key in node for key in _STATUS_KEYS)
    )
    has_body = any(key in node for key in _TITLE_KEYS + _BODY_KEYS)
    return has_severity_or_status and has_body


def _iter_checks(
    node: Any,
    category: str | None = None,
    depth: int = 0,
    group: Mapping[str, Any] | None = None,
) -> Iterator[tuple[str, Mapping[str, Any] | None, Mapping[str, Any]]]:
    """Yield ``(category, group_metadata, finding)`` from nested scanner JSON."""
    if depth > 6 or node is None:
        return

    if isinstance(node, Mapping):
        container_key = next(
            (key for key in _CHECK_CONTAINER_KEYS if key in node),
            None,
        )
        if container_key:
            resolved = category or _category_label(container_key, node)
            resolved_group = group or node
            for item in _as_list(node[container_key]):
                yield from _iter_checks(item, resolved, depth + 1, resolved_group)
            return

        if _looks_like_finding(node):
            yield category or "General", group, node
            return

        for key, value in node.items():
            if str(key).lower() in _METADATA_KEYS:
                continue
            child_category = category or _category_label(key, value if isinstance(value, Mapping) else None)
            child_group = group or (value if isinstance(value, Mapping) else None)
            yield from _iter_checks(value, child_category, depth + 1, child_group)
        return

    if isinstance(node, (list, tuple)):
        for item in node:
            yield from _iter_checks(item, category, depth + 1, group)


def _root_payload(scan_data: Any) -> Any:
    if isinstance(scan_data, (list, tuple)):
        return list(scan_data)
    if not isinstance(scan_data, Mapping):
        raise ValueError("Scan data must be a JSON object or a list of findings")

    for key in _ROOT_KEYS:
        if key in scan_data:
            return scan_data[key]
    for key in _NESTED_ROOT_KEYS:
        nested = scan_data.get(key)
        if isinstance(nested, Mapping):
            for root_key in _ROOT_KEYS:
                if root_key in nested:
                    return nested[root_key]
    if _looks_like_finding(scan_data):
        return scan_data
    raise ValueError("No recognised findings/results/checks section was found in the scan JSON")


def _matching_text(groups: Sequence[tuple[Sequence[str], str]], haystack: str) -> str:
    for keywords, text in groups:
        if any(keyword in haystack for keyword in keywords):
            return text
    return ""


def _derive_plain_description(title: str, detail: str, category: str) -> str:
    haystack = f"{title} {detail} {category}".lower()
    derived = _matching_text(_PLAIN_DESCRIPTIONS, haystack)
    if derived:
        return derived
    if detail:
        return (
            f"The scanner reported: {detail.rstrip('.')}. This weakens the firm's "
            "technical controls and should be validated and corrected so client "
            "information remains protected."
        )
    return "A security weakness was identified during the external assessment and should be reviewed by the firm's IT provider."


def _derive_business_impact(title: str, detail: str, category: str, severity: str) -> str:
    haystack = f"{title} {detail} {category}".lower()
    return _matching_text(_BUSINESS_IMPACTS, haystack) or _DEFAULT_IMPACTS[severity]


def _derive_recommendation(title: str, detail: str, category: str, severity: str) -> str:
    haystack = f"{title} {detail} {category}".lower()
    derived = _matching_text(_RECOMMENDATIONS, haystack)
    if derived:
        return derived
    return (
        "Ask the firm's IT provider to validate the observation, agree a safe fix, "
        f"apply the change and retest. Record the owner and completion date for this "
        f"{severity.lower()}-severity finding."
    )


def _normalise_effort(value: Any, severity: str, recommendation: str) -> str:
    raw = _clean(value).upper()
    if raw in {"LOW", "MEDIUM", "HIGH"}:
        return raw
    if raw in {"SMALL", "MINOR", "TRIVIAL", "EASY"}:
        return "LOW"
    if raw in {"LARGE", "MAJOR", "COMPLEX", "SIGNIFICANT"}:
        return "HIGH"
    haystack = recommendation.lower()
    if any(word in haystack for word in ("rebuild", "migrate", "replace the system", "application redesign", "rotate every credential")):
        return "HIGH"
    if any(word in haystack for word in ("rotate", "multi-factor", "patch", "review logs", "audit", "test")):
        return "MEDIUM"
    return {"CRITICAL": "MEDIUM", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}[severity]


def _normalise_timeline(value: Any, severity: str) -> str:
    raw = _clean(value).lower()
    if "0-7" in raw or "0–7" in raw or "immediate" in raw or "24 hour" in raw or "7 days" in raw:
        return "0-7 days"
    if "7-30" in raw or "7–30" in raw or "short term" in raw or "30 days" in raw:
        return "7-30 days"
    if "30-90" in raw or "30–90" in raw or "long term" in raw or "90 days" in raw:
        return "30-90 days"
    return {"CRITICAL": "0-7 days", "HIGH": "7-30 days", "MEDIUM": "30-90 days", "LOW": "30-90 days"}[severity]


def timeline_bucket(timeline: str, severity: str) -> str:
    """Return one of the three roadmap section names."""
    raw = _clean(timeline).lower()
    if "0-7" in raw or "0–7" in raw or "immediate" in raw:
        return "Immediate (0-7 days)"
    if "7-30" in raw or "7–30" in raw or "short" in raw:
        return "Short term (7-30 days)"
    if "30-90" in raw or "30–90" in raw or "long" in raw:
        return "Long term (30-90 days)"
    return timeline_bucket(
        {"CRITICAL": "0-7 days", "HIGH": "7-30 days", "MEDIUM": "30-90 days", "LOW": "30-90 days"}[severity],
        severity,
    )


def _shorten(text: str, limit: int = 115) -> str:
    compact = " ".join(_clean(text).split())
    if len(compact) <= limit:
        return compact
    return compact[: max(0, limit - 3)].rsplit(" ", 1)[0].rstrip() + "..."


def _build_evidence(
    item: Mapping[str, Any],
    group: Mapping[str, Any] | None,
    category: str,
    target: str,
    scanner: str,
) -> str:
    parts: list[str] = []
    detail = _first(item, ("detail", "observation", "result", "value", "message"))
    if detail:
        parts.append(f"Observed: {detail}")
    for key in _EVIDENCE_KEYS:
        if key in item and key != "message":
            value = _clean(item[key], 2200)
            if value and value not in parts:
                parts.append(value)

    status = _first(item, _STATUS_KEYS)
    if status:
        parts.append(f"Scanner status: {status}")
    if category:
        parts.append(f"Check group: {category}")
    if target:
        parts.append(f"Assessed target: {target}")
    if scanner:
        parts.append(f"Source: {scanner}")

    if isinstance(group, Mapping):
        for key in ("open_ports", "subdomains", "spf_record", "dmarc_record", "paths_checked"):
            if key in group and group[key] not in (None, "", []):
                label = key.replace("_", " ").title()
                parts.append(f"{label}: {_clean(group[key], 900)}")

    unique: list[str] = []
    seen: set[str] = set()
    for part in parts:
        part = _clean(part, 2400)
        if part and part not in seen:
            seen.add(part)
            unique.append(part)
    return "\n".join(unique) if unique else "No technical evidence was supplied with this finding."


def parse_findings(scan_data: Any) -> list[dict[str, Any]]:
    """Parse scanner JSON and return a clean, severity-sorted findings list."""
    payload = _root_payload(scan_data)
    metadata = scan_data if isinstance(scan_data, Mapping) else {}
    target = _first(metadata, ("target", "domain", "host", "url"))
    scanner = _first(metadata, ("scanner", "tool", "generator", "source"))

    parsed: list[dict[str, Any]] = []
    for source_index, (category, group, item) in enumerate(_iter_checks(payload), start=1):
        if not isinstance(item, Mapping):
            continue
        raw_severity = _first(item, _SEVERITY_KEYS)
        status = _first(item, _STATUS_KEYS)
        severity = normalize_severity(raw_severity, status)
        if severity not in SEVERITY_ORDER:
            continue

        title = _first(item, _TITLE_KEYS) or f"Security finding {source_index}"
        detail = _first(item, ("detail", "observation", "result", "value", "message"))
        resolved_category = _category_label(category, item)
        description = _first(item, _DESCRIPTION_KEYS, "") or _derive_plain_description(
            title, detail, resolved_category
        )
        recommendation = _first(item, _RECOMMENDATION_KEYS, "") or _derive_recommendation(
            title, detail, resolved_category, severity
        )
        business_impact = _first(item, _IMPACT_KEYS, "") or _derive_business_impact(
            title, detail, resolved_category, severity
        )
        timeline = _normalise_timeline(_first(item, _TIMELINE_KEYS), severity)
        effort = _normalise_effort(_first(item, _EFFORT_KEYS), severity, recommendation)
        evidence = _build_evidence(item, group, resolved_category, target, scanner)
        action = _first(item, ("action", "short_action", "remediation_action")) or _shorten(recommendation)
        finding_id = _first(item, _ID_KEYS)

        parsed.append({
            "id": finding_id,
            "title": _clean(title, 300),
            "severity": severity,
            "description": _clean(description, 1800),
            "evidence": _clean(evidence, 5000),
            "recommendation": _clean(recommendation, 2500),
            "category": _clean(resolved_category, 120),
            "business_impact": _clean(business_impact, 1800),
            "fix_effort": effort,
            "timeline": timeline,
            "timeline_bucket": timeline_bucket(timeline, severity),
            "action": _clean(action, 220),
            "status": _clean(status, 40),
            "scanner_category": _clean(category, 80),
            "raw_severity": _clean(raw_severity, 40),
            "source_index": source_index,
        })

    parsed.sort(key=lambda finding: (SEVERITY_ORDER[finding["severity"]], finding["source_index"]))

    used_ids: set[str] = set()
    for number, finding in enumerate(parsed, start=1):
        finding["finding_number"] = number
        candidate = finding.get("id") or f"F-{number:03d}"
        if candidate in used_ids:
            candidate = f"{candidate}-{number:03d}"
        finding["id"] = candidate
        used_ids.add(candidate)
    return parsed
