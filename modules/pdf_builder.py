"""Build the professional black-and-white SRA assessment PDF with ReportLab."""

from __future__ import annotations

import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Frame,
    HRFlowable,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from modules.risk_scorer import GRADE_THRESHOLDS
from modules.sra_mapper import SRA_GENERAL_REFERENCE

AUTHOR_EMAIL = "brucesec.mumbai@gmail.com"
AUTHOR_NAME = "CyberOps — Omkar Sawant"
FOOTER_RIGHT = f"Prepared by CyberOps — {AUTHOR_EMAIL}"

BLACK = colors.black
WHITE = colors.white
DARK_GREY = colors.HexColor("#444444")
MEDIUM_GREY = colors.HexColor("#CCCCCC")
LIGHT_GREY = colors.HexColor("#F3F3F3")
RULE_GREY = colors.HexColor("#999999")
WATERMARK_GREY = colors.HexColor("#F0F0F0")

MARGIN_X = 48
TOP_MARGIN = 48
BOTTOM_MARGIN = 68
FRAME_WIDTH = A4[0] - (2 * MARGIN_X)
FRAME_HEIGHT = A4[1] - TOP_MARGIN - BOTTOM_MARGIN

SEVERITY_STYLES = {
    "CRITICAL": {"background": BLACK, "text": WHITE, "border": BLACK},
    "HIGH": {"background": DARK_GREY, "text": WHITE, "border": DARK_GREY},
    "MEDIUM": {"background": MEDIUM_GREY, "text": BLACK, "border": MEDIUM_GREY},
    "LOW": {"background": WHITE, "text": BLACK, "border": BLACK},
}

ROADMAP_BUCKETS = (
    "Immediate (0-7 days)",
    "Short term (7-30 days)",
    "Long term (30-90 days)",
)

DISCLAIMER = (
    "This report is based solely on the supplied lawfirm-scanner JSON and the "
    "external, non-invasive observations available at the scan time. It is not a "
    "penetration test, internal audit, legal advice, certification, or a formal "
    "determination by the Solicitors Regulation Authority. Internal systems, "
    "endpoints, written policies, backups, staff training, supplier controls and "
    "incident-response arrangements were not assessed. Public scan results can "
    "become stale as systems change and can include false positives caused by "
    "proxies, hosting providers, web application firewalls or websites that return "
    "HTTP 200 for every path. The firm remains responsible for validating each "
    "finding, implementing appropriate controls, obtaining professional advice, "
    "and making any required notification to the SRA, ICO, insurer or clients."
)

_BASE = getSampleStyleSheet()
STYLES = {
    "eyebrow": ParagraphStyle(
        "Eyebrow", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=8,
        leading=11, textColor=BLACK, spaceAfter=6, allCaps=True,
    ),
    "cover_brand": ParagraphStyle(
        "CoverBrand", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=11,
        leading=14, alignment=TA_CENTER, textColor=BLACK, spaceAfter=8,
    ),
    "cover_heading": ParagraphStyle(
        "CoverHeading", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=25,
        leading=30, alignment=TA_CENTER, textColor=BLACK, spaceAfter=12,
    ),
    "cover_subheading": ParagraphStyle(
        "CoverSubheading", parent=_BASE["Normal"], fontName="Helvetica", fontSize=10,
        leading=14, alignment=TA_CENTER, textColor=BLACK, spaceAfter=8,
    ),
    "cover_confidential": ParagraphStyle(
        "CoverConfidential", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=11,
        leading=14, alignment=TA_CENTER, textColor=BLACK, spaceAfter=8,
    ),
    "cover_note": ParagraphStyle(
        "CoverNote", parent=_BASE["Normal"], fontName="Helvetica", fontSize=8.5,
        leading=12, alignment=TA_CENTER, textColor=BLACK, spaceAfter=4,
        splitLongWords=1, wordWrap="LTR",
    ),
    "h1": ParagraphStyle(
        "H1", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=17,
        leading=21, textColor=BLACK, spaceBefore=2, spaceAfter=10,
    ),
    "h2": ParagraphStyle(
        "H2", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=10.5,
        leading=14, textColor=BLACK, spaceBefore=9, spaceAfter=5,
    ),
    "body": ParagraphStyle(
        "Body", parent=_BASE["Normal"], fontName="Helvetica", fontSize=9.3,
        leading=13.5, alignment=TA_JUSTIFY, textColor=BLACK, spaceAfter=6,
        splitLongWords=1, wordWrap="LTR", allowWidows=0, allowOrphans=0,
    ),
    "small": ParagraphStyle(
        "Small", parent=_BASE["Normal"], fontName="Helvetica", fontSize=8.2,
        leading=11.5, alignment=TA_JUSTIFY, textColor=BLACK, spaceAfter=5,
        splitLongWords=1, wordWrap="LTR", allowWidows=0, allowOrphans=0,
    ),
    "label": ParagraphStyle(
        "Label", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=9,
        leading=12, textColor=BLACK, spaceAfter=0,
    ),
    "value": ParagraphStyle(
        "Value", parent=_BASE["Normal"], fontName="Helvetica", fontSize=9,
        leading=12, textColor=BLACK, spaceAfter=0, splitLongWords=1, wordWrap="LTR",
    ),
    "score_label": ParagraphStyle(
        "ScoreLabel", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=8,
        leading=10, alignment=TA_CENTER, textColor=BLACK,
    ),
    "score_number": ParagraphStyle(
        "ScoreNumber", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=38,
        leading=40, alignment=TA_CENTER, textColor=BLACK,
    ),
    "score_large": ParagraphStyle(
        "ScoreLarge", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=23,
        leading=27, alignment=TA_CENTER, textColor=BLACK,
    ),
    "micro": ParagraphStyle(
        "Micro", parent=_BASE["Normal"], fontName="Helvetica", fontSize=7.5,
        leading=9, alignment=TA_CENTER, textColor=BLACK,
    ),
    "table_header": ParagraphStyle(
        "TableHeader", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=8,
        leading=10, textColor=WHITE, alignment=TA_LEFT, splitLongWords=1,
    ),
    "table_cell": ParagraphStyle(
        "TableCell", parent=_BASE["Normal"], fontName="Helvetica", fontSize=7.6,
        leading=9.5, textColor=BLACK, alignment=TA_LEFT, splitLongWords=1,
        wordWrap="LTR",
    ),
    "status_box": ParagraphStyle(
        "StatusBox", parent=_BASE["Normal"], fontName="Helvetica-Bold", fontSize=12,
        leading=16, alignment=TA_CENTER, textColor=WHITE,
    ),
    "bullet": ParagraphStyle(
        "Bullet", parent=_BASE["Normal"], fontName="Helvetica", fontSize=9,
        leading=13, alignment=TA_LEFT, textColor=BLACK, leftIndent=12,
        firstLineIndent=-10, spaceAfter=4, splitLongWords=1, wordWrap="LTR",
    ),
}


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.replace("\r\n", "\n").replace("\r", "\n")
    if isinstance(value, Mapping):
        return "\n".join(f"{key}: {_to_text(item)}" for key, item in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return "\n".join(_to_text(item) for item in value)
    return str(value)


def _clean(value: Any) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", _to_text(value))
    return text.strip()


def _p(value: Any, style: str | ParagraphStyle = "body") -> Paragraph:
    text = _clean(value) or "Not supplied."
    safe = xml_escape(text).replace("\n", "<br/>")
    paragraph_style = STYLES[style] if isinstance(style, str) else style
    return Paragraph(safe, paragraph_style)


def _shorten(value: Any, limit: int = 100) -> str:
    text = " ".join(_clean(value).split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rsplit(" ", 1)[0].rstrip() + "..."


def _first_sentence(value: Any, limit: int = 220) -> str:
    text = " ".join(_clean(value).split())
    match = re.search(r"[.!?](?:\s|$)", text)
    if match:
        text = text[: match.end()].strip()
    return _shorten(text, limit)


def _fit_canvas_text(text: str, max_width: float, font: str = "Helvetica", size: float = 7) -> str:
    if stringWidth(text, font, size) <= max_width:
        return text
    ellipsis = "..."
    while text and stringWidth(text + ellipsis, font, size) > max_width:
        text = text[:-1]
    return text.rstrip() + ellipsis


def _first(mapping: Mapping[str, Any] | Any, keys: Sequence[str], default: str = "") -> str:
    if not isinstance(mapping, Mapping):
        return default
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}):
            return _clean(value)
    return default


def _date_parts(date: Any) -> tuple[int, str]:
    if isinstance(date, datetime):
        return date.year, date.strftime("%Y%m%d")
    text = _clean(date)
    formats = (
        "%d %B %Y", "%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%B %d, %Y",
        "%b %d %Y", "%Y/%m/%d",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.year, parsed.strftime("%Y%m%d")
        except ValueError:
            continue
    match = re.search(r"\b(?:19|20)\d{2}\b", text)
    year = int(match.group(0)) if match else datetime.now().year
    return year, datetime.now().strftime("%Y%m%d")


def _severity_badge(severity: Any) -> Table:
    label = _clean(severity).upper() or "LOW"
    if label not in SEVERITY_STYLES:
        label = "LOW"
    spec = SEVERITY_STYLES[label]
    style = ParagraphStyle(
        f"Badge_{label}", parent=_BASE["Normal"], fontName="Helvetica-Bold",
        fontSize=8.5, leading=10, alignment=TA_CENTER, textColor=spec["text"],
    )
    table = Table(
        [[Paragraph(label, style)]],
        colWidths=[74],
        rowHeights=[18],
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), spec["background"]),
        ("BOX", (0, 0), (-1, -1), 0.8, spec["border"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    return table


def _metadata_table(rows: Sequence[tuple[str, Any]]) -> Table:
    data = [[_p(label, "label"), _p(value, "value")] for label, value in rows]
    table = Table(data, colWidths=[155, FRAME_WIDTH - 155], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.35, RULE_GREY),
        ("LINEBELOW", (0, -1), (-1, -1), 0.8, BLACK),
    ]))
    return table


def _section(title: str) -> Paragraph:
    return _p(title, "h2")


def _page_chrome(firm_name: str):
    firm = _clean(firm_name) or "Law Firm"

    def draw(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        page_number = canvas.getPageNumber()
        width, height = A4

        if page_number == 1:
            canvas.saveState()
            canvas.setFillColor(WATERMARK_GREY)
            canvas.setFont("Helvetica-Bold", 94)
            canvas.translate(width / 2.0, height / 2.0)
            canvas.rotate(45)
            canvas.drawCentredString(0, -28, "CONFIDENTIAL")
            canvas.restoreState()

        canvas.setStrokeColor(BLACK)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN_X, 52, width - MARGIN_X, 52)
        canvas.setFillColor(BLACK)

        left = f"CONFIDENTIAL — CyberOps Assessment Report — {firm}"
        left_size = 7.0
        while left_size > 5.0 and stringWidth(left, "Helvetica", left_size) > FRAME_WIDTH:
            left_size -= 0.25
        if stringWidth(left, "Helvetica", left_size) > FRAME_WIDTH:
            left = _fit_canvas_text(left, FRAME_WIDTH, size=left_size)
        canvas.setFont("Helvetica", left_size)
        canvas.drawString(MARGIN_X, 41, left)

        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(width - MARGIN_X, 30, FOOTER_RIGHT)
        canvas.drawCentredString(width / 2.0, 18, f"Page {page_number}")
        canvas.restoreState()

    return draw


def _risk_data(risk: Mapping[str, Any] | None, findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not risk:
        from modules.risk_scorer import calculate_risk
        risk = calculate_risk(list(findings))
    data = dict(risk)
    counts = dict(data.get("counts") or {})
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        counts[severity] = int(counts.get(severity, data.get(severity.lower(), 0)) or 0)
    score = int(data.get("score", data.get("security_score", 100)) or 0)
    risk_score = int(data.get("risk_score", max(0, min(100, 100 - score))))
    level = _clean(data.get("level") or data.get("risk_level") or "LOW").upper()
    if level not in SEVERITY_STYLES:
        level = "LOW"
    grade = _clean(data.get("grade"))
    if not grade:
        grade = next((g for threshold, g, _ in GRADE_THRESHOLDS if score >= threshold), "F")
    status = _clean(data.get("compliance_status"))
    if not status:
        total = sum(counts.values())
        if counts["CRITICAL"] > 0 or level == "CRITICAL":
            status = "NON-COMPLIANT"
        elif total:
            status = "REQUIRES ATTENTION"
        else:
            status = "COMPLIANT"
    data.update({
        "counts": counts,
        "score": score,
        "risk_score": risk_score,
        "level": level,
        "grade": grade,
        "compliance_status": status,
        "total_findings": int(data.get("total_findings", sum(counts.values()))),
    })
    return data


def _cover_story(
    firm_name: str,
    scan_data: Mapping[str, Any],
    date: str,
    reference: str,
) -> list[Any]:
    target = _first(scan_data, ("target", "domain", "host", "url"), "Not supplied")
    scanner = _first(scan_data, ("scanner", "tool", "generator", "source"), "lawfirm-scanner JSON")
    story: list[Any] = [
        Spacer(1, 52),
        _p("CYBEROPS", "cover_brand"),
        HRFlowable(width="100%", thickness=0.8, color=BLACK, spaceBefore=2, spaceAfter=26),
        Spacer(1, 28),
        _p("CYBER SECURITY ASSESSMENT REPORT", "cover_heading"),
        _p("SRA SUBMISSION  ·  PI INSURANCE RENEWAL  ·  CONFIDENTIAL", "cover_subheading"),
        HRFlowable(width="45%", thickness=0.5, color=RULE_GREY, spaceBefore=6, spaceAfter=24),
        Spacer(1, 12),
        _metadata_table([
            ("PREPARED FOR:", firm_name),
            ("ASSESSMENT DATE:", date),
            ("PREPARED BY:", AUTHOR_NAME),
            ("REFERENCE:", reference),
            ("ASSESSED DOMAIN:", target),
            ("SOURCE DATA:", scanner),
        ]),
        Spacer(1, 26),
        _p("CONFIDENTIAL", "cover_confidential"),
        _p(
            "This document contains security assessment information intended solely "
            "for the named firm and its authorised advisers.",
            "cover_note",
        ),
        Spacer(1, 10),
        _p(f"CyberOps  ·  {AUTHOR_EMAIL}  ·  cyberops-ivory.vercel.app", "cover_note"),
    ]
    return story


def _score_panel(risk: Mapping[str, Any]) -> Table:
    data = [
        [
            _p("OVERALL ASSESSMENT SCORE", "score_label"),
            _p("RISK LEVEL", "score_label"),
            _p("RISK EXPOSURE", "score_label"),
        ],
        [
            _p(f"{risk['score']}/100", "score_number"),
            _severity_badge(risk["level"]),
            _p(f"{risk['risk_score']}/100", "score_large"),
        ],
        [
            _p("100 = clean; 0 = critical", "micro"),
            _p(f"Grade {risk['grade']}", "micro"),
            _p("Higher = more risk", "micro"),
        ],
    ]
    table = Table(data, colWidths=[FRAME_WIDTH / 3.0] * 3, rowHeights=[18, 50, 14], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1.0, BLACK),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, RULE_GREY),
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT_GREY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


def _counts_table(risk: Mapping[str, Any]) -> Table:
    from modules.risk_scorer import SEVERITY_WEIGHTS

    rows: list[list[Any]] = [[
        _p("Severity", "table_header"),
        _p("Finding count", "table_header"),
        _p("Points deducted", "table_header"),
    ]]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = int(risk["counts"].get(severity, 0))
        rows.append([
            _severity_badge(severity),
            _p(str(count), "value"),
            _p(str(count * SEVERITY_WEIGHTS[severity]), "value"),
        ])
    table = Table(rows, colWidths=[130, 160, FRAME_WIDTH - 290], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLACK),
        ("GRID", (0, 0), (-1, -1), 0.45, BLACK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _status_box(status: str) -> Table:
    background = BLACK if status in {"NON-COMPLIANT", "REQUIRES ATTENTION"} else WHITE
    text_color = WHITE if background == BLACK else BLACK
    style = ParagraphStyle(
        "ComplianceStatus", parent=STYLES["status_box"], textColor=text_color,
    )
    table = Table([[_p(status, style)]], colWidths=[FRAME_WIDTH], rowHeights=[28], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("BOX", (0, 0), (-1, -1), 1.0, BLACK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return table


def _executive_summary_story(
    firm_name: str,
    findings: Sequence[Mapping[str, Any]],
    risk: Mapping[str, Any],
    scan_data: Mapping[str, Any],
    date: str,
) -> list[Any]:
    counts = risk["counts"]
    target = _first(scan_data, ("target", "domain", "host", "url"), "the assessed domain")
    total = risk["total_findings"]

    story: list[Any] = [
        _p("EXECUTIVE SUMMARY", "h1"),
        _p(
            f"This report summarises an external cyber security assessment for "
            f"{firm_name}, prepared on {date}. The source scan covered {target}.",
            "small",
        ),
        _score_panel(risk),
        Spacer(1, 10),
        _section("FINDINGS BY SEVERITY"),
        _counts_table(risk),
        Spacer(1, 4),
        _section("KEY FINDINGS — TOP 3 ISSUES IN PLAIN ENGLISH"),
    ]

    top_three = list(findings[:3])
    if top_three:
        for index, finding in enumerate(top_three, start=1):
            description = _first_sentence(finding.get("description") or finding.get("title"), 260)
            story.append(_p(f"{index}.  {finding.get('title', 'Finding')}: {description}", "bullet"))
    else:
        story.append(_p("No actionable findings were supplied with this scan.", "body"))

    story.extend([
        _section("SRA COMPLIANCE STATUS"),
        _status_box(risk["compliance_status"]),
        _p(
            "This status is a report triage indicator based on the supplied external "
            "findings only. It is not an SRA certification or legal determination.",
            "small",
        ),
        _section("SUMMARY FOR THE MANAGING PARTNER"),
    ])

    if total and findings:
        first_action = _first_sentence(findings[0].get("recommendation"), 190)
        partner_summary = (
            f"The assessment recorded {total} findings, including "
            f"{counts['CRITICAL']} critical and {counts['HIGH']} high issues. "
            f"The lawfirm-scanner security score is {risk['score']}/100 "
            f"(Grade {risk['grade']}), giving a {risk['level'].lower()} risk level "
            f"and an SRA compliance status of {risk['compliance_status']}. "
            f"The most urgent issue is \"{findings[0].get('title', 'the first finding')}\". "
            f"{first_action} A managing partner should assign an owner and completion "
            "date for every immediate action, require written evidence of remediation, "
            "and sign off the roadmap at the end of this report."
        )
    else:
        partner_summary = (
            "No actionable findings were supplied. The firm should still retain this "
            "report with its written cyber security policy, confirm that the scan scope "
            "was agreed, and repeat the assessment after material changes to public systems."
        )
    story.append(_p(partner_summary, "body"))
    return story


def _mapped_lookup(
    sra_mapped: Sequence[Mapping[str, Any]] | None,
) -> tuple[dict[str, Mapping[str, Any]], list[Mapping[str, Any]]]:
    ordered = [item for item in (sra_mapped or []) if isinstance(item, Mapping)]
    by_id = {
        _clean(item.get("id")): item
        for item in ordered
        if _clean(item.get("id"))
    }
    return by_id, ordered


def _finding_meta_table(finding: Mapping[str, Any]) -> Table:
    rows = [
        ("Finding ID", finding.get("id") or "Not supplied"),
        ("Category", finding.get("category") or "General"),
        ("Scanner status", finding.get("status") or "Not supplied"),
        ("Target timeline", finding.get("timeline") or "Not supplied"),
        ("Estimated fix effort", finding.get("fix_effort") or "MEDIUM"),
    ]
    return _metadata_table(rows)


def _detailed_findings_story(
    findings: Sequence[Mapping[str, Any]],
    sra_mapped: Sequence[Mapping[str, Any]] | None,
) -> list[Any]:
    reportable = [
        finding for finding in findings
        if _clean(finding.get("severity")).upper() in {"CRITICAL", "HIGH", "MEDIUM"}
    ]
    by_id, ordered = _mapped_lookup(sra_mapped)
    story: list[Any] = []

    if not reportable:
        return [
            _p("DETAILED FINDINGS", "h1"),
            _p(
                "No CRITICAL, HIGH or MEDIUM findings were supplied. LOW findings, "
                "if any, are listed in the remediation roadmap.",
                "body",
            ),
        ]

    for index, finding in enumerate(reportable):
        if index:
            story.append(PageBreak())
        elif not story:
            story.append(Spacer(1, 0))

        mapped = by_id.get(_clean(finding.get("id")))
        if mapped is None and index < len(ordered):
            mapped = ordered[index]
        mapped = mapped or {}

        sra_reference = (
            mapped.get("sra_reference")
            or finding.get("sra_reference")
            or SRA_GENERAL_REFERENCE
        )
        sra_requirement = (
            mapped.get("sra_requirement")
            or finding.get("sra_requirement")
            or "Maintain effective systems and controls, record ownership, remediate the finding and retain evidence of review."
        )
        theme = mapped.get("sra_theme") or "Effective systems and controls"

        header = KeepTogether([
            _p("DETAILED FINDINGS", "eyebrow"),
            _p(
                f"FINDING {int(finding.get('finding_number', index + 1))}: "
                f"{finding.get('title', 'Security finding')}",
                "h1",
            ),
            _severity_badge(finding.get("severity")),
            HRFlowable(width="100%", thickness=0.8, color=BLACK, spaceBefore=8, spaceAfter=8),
        ])
        story.append(header)
        story.append(_section("DESCRIPTION IN PLAIN ENGLISH"))
        story.append(_p(finding.get("description"), "body"))
        story.append(_section("WHAT WAS FOUND (EVIDENCE)"))
        story.append(_p(finding.get("evidence"), "small"))
        story.append(_section("BUSINESS IMPACT — WHAT THIS MEANS FOR THE FIRM"))
        story.append(_p(finding.get("business_impact"), "body"))
        story.append(_section("SRA REQUIREMENT REFERENCE"))
        story.append(_p(f"Control theme: {theme}", "small"))
        story.append(_p(sra_reference, "small"))
        story.append(_p(sra_requirement, "body"))
        story.append(_section("RECOMMENDATION — SPECIFIC STEPS TO FIX IT"))
        story.append(_p(finding.get("recommendation"), "body"))
        story.append(_section("REMEDIATION DETAILS"))
        story.append(_finding_meta_table(finding))

    return story


def _roadmap_bucket(finding: Mapping[str, Any]) -> str:
    bucket = _clean(finding.get("timeline_bucket"))
    if bucket in ROADMAP_BUCKETS:
        return bucket
    timeline = _clean(finding.get("timeline")).lower()
    severity = _clean(finding.get("severity")).upper()
    if "0-7" in timeline or "0–7" in timeline or "immediate" in timeline:
        return ROADMAP_BUCKETS[0]
    if "7-30" in timeline or "7–30" in timeline or "short" in timeline:
        return ROADMAP_BUCKETS[1]
    if "30-90" in timeline or "30–90" in timeline or "long" in timeline:
        return ROADMAP_BUCKETS[2]
    if severity == "CRITICAL":
        return ROADMAP_BUCKETS[0]
    if severity == "HIGH":
        return ROADMAP_BUCKETS[1]
    return ROADMAP_BUCKETS[2]


def _roadmap_table(rows: Sequence[Sequence[Any]], empty: bool = False) -> Table:
    table = Table(
        rows,
        colWidths=[105, 65, 175, 90, 55],
        repeatRows=1,
        hAlign="LEFT",
    )
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), BLACK),
        ("GRID", (0, 0), (-1, -1), 0.4, BLACK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
    ]
    if empty:
        commands.append(("SPAN", (0, 1), (-1, 1)))
    table.setStyle(TableStyle(commands))
    return table


def _roadmap_story(findings: Sequence[Mapping[str, Any]]) -> list[Any]:
    story: list[Any] = [
        _p("REMEDIATION ROADMAP", "h1"),
        _p(
            "Actions are grouped by target completion window. Assign a named owner "
            "for every row, retain change records and rescan after remediation.",
            "small",
        ),
    ]

    grouped: dict[str, list[Mapping[str, Any]]] = {bucket: [] for bucket in ROADMAP_BUCKETS}
    for finding in findings:
        grouped[_roadmap_bucket(finding)].append(finding)

    for bucket in ROADMAP_BUCKETS:
        story.append(_p(bucket.upper(), "h2"))
        rows: list[list[Any]] = [[
            _p("Finding", "table_header"),
            _p("Severity", "table_header"),
            _p("Action", "table_header"),
            _p("Timeline", "table_header"),
            _p("Effort", "table_header"),
        ]]
        bucket_findings = grouped[bucket]
        if bucket_findings:
            for finding in bucket_findings:
                rows.append([
                    _p(f"{finding.get('id', 'F')} — {_shorten(finding.get('title'), 62)}", "table_cell"),
                    _p(_clean(finding.get("severity")).upper(), "table_cell"),
                    _p(_shorten(finding.get("action") or finding.get("recommendation"), 125), "table_cell"),
                    _p(finding.get("timeline") or bucket, "table_cell"),
                    _p(_clean(finding.get("fix_effort")).upper() or "MEDIUM", "table_cell"),
                ])
            story.append(_roadmap_table(rows))
        else:
            rows.append([
                _p("No findings scheduled in this window.", "table_cell"),
                "", "", "", "",
            ])
            story.append(_roadmap_table(rows, empty=True))
        story.append(Spacer(1, 7))

    signoff = Table(
        [[_p("Report reviewed by: ____________________     Date: ____________________", "value")]],
        colWidths=[FRAME_WIDTH],
        rowHeights=[34],
        hAlign="LEFT",
    )
    signoff.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.9, BLACK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.extend([
        _section("SIGN-OFF"),
        signoff,
        Spacer(1, 4),
        _section("SCOPE LIMITATIONS AND DISCLAIMER"),
        _p(DISCLAIMER, "small"),
    ])
    return story


def build_pdf(
    firm_name: str,
    scan_data: Mapping[str, Any] | Any,
    findings: Sequence[Mapping[str, Any]],
    sra_mapped: Sequence[Mapping[str, Any]],
    risk: Mapping[str, Any],
    date: str,
    output_dir: str,
) -> str:
    """Build the complete PDF and return the generated file path."""
    firm = _clean(firm_name) or "Law Firm"
    metadata = scan_data if isinstance(scan_data, Mapping) else {}
    findings_list = [item for item in (findings or []) if isinstance(item, Mapping)]
    mapped_list = [item for item in (sra_mapped or []) if isinstance(item, Mapping)]
    risk_data = _risk_data(risk, findings_list)
    report_date = _clean(date) or datetime.now().strftime("%d %B %Y")
    year, compact_date = _date_parts(report_date)
    reference = f"CYBEROPS-{year}-{secrets.randbelow(9000) + 1000:04d}"

    slug = re.sub(r"[^A-Za-z0-9]+", "_", firm).strip("_").lower() or "law_firm"
    out_dir = Path(output_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / f"{slug}_SRA_Assessment_{compact_date}.pdf"

    story: list[Any] = []
    story.extend(_cover_story(firm, metadata, report_date, reference))
    story.append(PageBreak())
    story.extend(_executive_summary_story(firm, findings_list, risk_data, metadata, report_date))
    story.append(PageBreak())
    story.extend(_detailed_findings_story(findings_list, mapped_list))
    story.append(PageBreak())
    story.extend(_roadmap_story(findings_list))

    doc = BaseDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN,
        title=f"Cyber Security Assessment Report — {firm}",
        author=AUTHOR_NAME,
        subject="SRA cyber security assessment and remediation roadmap",
        creator="sra-report-generator",
        keywords=f"SRA, CyberOps, {reference}, {firm}",
        pageCompression=1,
    )
    frame = Frame(
        MARGIN_X,
        BOTTOM_MARGIN,
        FRAME_WIDTH,
        FRAME_HEIGHT,
        id="body",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    doc.addPageTemplates([
        PageTemplate(id="main", frames=[frame], onPage=_page_chrome(firm)),
    ])

    try:
        doc.build(story)
    except Exception as exc:  # Convert layout/rendering failures into a clean CLI error.
        output_path.unlink(missing_ok=True)
        raise RuntimeError(f"PDF rendering failed: {exc}") from exc

    return str(output_path.resolve())
