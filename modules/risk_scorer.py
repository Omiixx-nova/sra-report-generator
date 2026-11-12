"""Risk scoring for SRA PDF reports.

This module deliberately mirrors ``modules/scoring.py`` in the public
``Omiixx-nova/lawfirm-scanner`` repository:

* start from a 100-point *security* score (100 = clean, 0 = worst);
* deduct 25 / 15 / 8 / 3 points for CRITICAL / HIGH / MEDIUM / LOW;
* clamp at zero; and
* use the scanner's A-F grade thresholds to derive the risk level.

For readers expecting a higher-is-riskier number, the returned dictionary also
contains ``risk_score`` (100 minus the scanner security score).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

# Exact parity with lawfirm-scanner/modules/scoring.py.
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "NONE": 0,
}

GRADE_THRESHOLDS = [
    (90, "A", "LOW"),
    (75, "B", "LOW"),
    (60, "C", "MEDIUM"),
    (40, "D", "HIGH"),
    (0, "F", "CRITICAL"),
]

_ROOT_KEYS = ("findings", "results", "vulnerabilities", "issues", "checks")


def _normalise_input(findings: Any) -> list[Mapping[str, Any]]:
    """Accept parsed findings, or scanner-native nested findings for parity."""
    if isinstance(findings, Mapping):
        from modules.findings_parser import parse_findings

        if any(key in findings for key in _ROOT_KEYS):
            return parse_findings(findings)
        return parse_findings({"findings": findings})

    if isinstance(findings, Sequence) and not isinstance(findings, (str, bytes)):
        result: list[Mapping[str, Any]] = []
        for item in findings:
            if not isinstance(item, Mapping):
                raise ValueError("every finding must be a dictionary")
            result.append(item)
        return result

    raise ValueError("findings must be a list or a scanner findings dictionary")


def calculate_risk(findings: Any) -> dict[str, Any]:
    """Calculate overall score, grade, risk level and severity counts."""
    from modules.findings_parser import normalize_severity

    normalised = _normalise_input(findings)
    score = 100
    deductions = 0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in normalised:
        severity = normalize_severity(
            finding.get("severity", finding.get("risk_level", "")),
            str(finding.get("status", "")),
        )
        if severity not in SEVERITY_WEIGHTS:
            continue
        penalty = SEVERITY_WEIGHTS[severity]
        score -= penalty
        deductions += penalty
        if severity in counts:
            counts[severity] += 1

    score = max(0, score)
    grade = "F"
    level = "CRITICAL"
    for threshold, candidate_grade, candidate_level in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = candidate_grade
            level = candidate_level
            break

    total = sum(counts.values())
    if counts["CRITICAL"] > 0 or level == "CRITICAL":
        compliance_status = "NON-COMPLIANT"
    elif total > 0:
        compliance_status = "REQUIRES ATTENTION"
    else:
        compliance_status = "COMPLIANT"

    return {
        # ``score`` retains lawfirm-scanner semantics: higher is safer.
        "score": score,
        "security_score": score,
        # Convenience field for a conventional higher-is-riskier display.
        "risk_score": 100 - score,
        "grade": grade,
        "level": level,
        "risk_level": level,
        "compliance_status": compliance_status,
        "counts": counts,
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "total_findings": total,
        "deductions": deductions,
        "method": (
            "lawfirm-scanner parity: 100 - (25*critical + 15*high + 8*medium "
            "+ 3*low), clamped to 0-100"
        ),
    }


def calculate_score(findings_by_category: Mapping[str, Any]) -> dict[str, Any]:
    """Compatibility alias for the lawfirm-scanner ``calculate_score`` shape."""
    return calculate_risk({"findings": findings_by_category})
