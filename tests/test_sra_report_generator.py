"""Unit, integration and PDF-rendering tests for the SRA report generator."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.findings_parser import parse_findings  # noqa: E402
from modules.pdf_builder import build_pdf  # noqa: E402
from modules.risk_scorer import calculate_risk, calculate_score  # noqa: E402
from modules.sra_mapper import map_to_sra  # noqa: E402

try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover - CI installs pypdf explicitly.
    PdfReader = None

SAMPLE_INPUT = ROOT / "sample_input" / "example_scan.json"


class FindingsParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sample = json.loads(SAMPLE_INPUT.read_text(encoding="utf-8"))

    def test_sample_has_expected_severity_counts(self) -> None:
        findings = parse_findings(self.sample)
        counts = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        for finding in findings:
            counts[finding["severity"]] += 1
        self.assertEqual(counts, {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 4, "LOW": 0})
        self.assertEqual(len(findings), 9)

    def test_every_finding_has_required_fields(self) -> None:
        findings = parse_findings(self.sample)
        required = {
            "id", "title", "severity", "description", "evidence", "recommendation",
            "category", "business_impact", "fix_effort", "timeline",
            "timeline_bucket", "action", "finding_number",
        }
        for finding in findings:
            self.assertTrue(required.issubset(finding), finding.get("title"))
            self.assertTrue(all(_meaningful(finding[key]) for key in required))

    def test_native_scanner_shape_skips_pass_checks(self) -> None:
        raw = {
            "findings": {
                "ports": {
                    "checks": [
                        {"name": "Port 3389 (RDP)", "status": "FAIL",
                         "detail": "OPEN", "severity": "CRITICAL"},
                        {"name": "Port 443 (HTTPS)", "status": "PASS",
                         "detail": "Expected", "severity": "NONE"},
                    ],
                    "open_ports": [443, 3389],
                }
            }
        }
        findings = parse_findings(raw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("open ports", findings[0]["evidence"].lower())

    def test_flat_list_and_severity_aliases(self) -> None:
        findings = parse_findings([
            {"title": "Legacy TLS protocol", "risk": "moderate",
             "evidence": "TLSv1.0 enabled", "remediation": "Disable TLSv1.0"},
            {"title": "Informational host", "status": "INFO",
             "detail": "Discovered in certificate transparency logs"},
        ])
        self.assertEqual([item["severity"] for item in findings], ["MEDIUM", "LOW"])
        self.assertEqual(findings[0]["recommendation"], "Disable TLSv1.0")

    def test_findings_are_sorted_by_severity(self) -> None:
        findings = parse_findings(self.sample)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        ranks = [order[item["severity"]] for item in findings]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual([item["finding_number"] for item in findings], list(range(1, 10)))


class RiskScorerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sample = json.loads(SAMPLE_INPUT.read_text(encoding="utf-8"))

    def test_matches_lawfirm_scanner_sample_score(self) -> None:
        findings = parse_findings(self.sample)
        risk = calculate_risk(findings)
        expected = self.sample["score"]
        self.assertEqual(risk["score"], expected["score"])
        self.assertEqual(risk["grade"], expected["grade"])
        self.assertEqual(risk["level"], expected["risk_level"])
        self.assertEqual(risk["risk_level"], expected["risk_level"])
        self.assertEqual(risk["critical"], expected["critical"])
        self.assertEqual(risk["high"], expected["high"])
        self.assertEqual(risk["medium"], expected["medium"])
        self.assertEqual(risk["low"], expected["low"])
        self.assertEqual(risk["risk_score"], 100 - expected["score"])
        self.assertEqual(risk["compliance_status"], "NON-COMPLIANT")

    def test_scanner_findings_dictionary_parity(self) -> None:
        score = calculate_score(self.sample["findings"])
        self.assertEqual(score["score"], self.sample["score"]["score"])
        self.assertEqual(score["grade"], self.sample["score"]["grade"])
        self.assertEqual(score["risk_level"], self.sample["score"]["risk_level"])

    def test_exact_weighted_formula(self) -> None:
        risk = calculate_risk([
            {"severity": "HIGH", "status": "FAIL"},
            {"severity": "LOW", "status": "WARN"},
        ])
        self.assertEqual(risk["score"], 82)  # 100 - 15 - 3
        self.assertEqual(risk["grade"], "B")
        self.assertEqual(risk["level"], "LOW")
        self.assertEqual(risk["risk_score"], 18)

    def test_clean_scan(self) -> None:
        risk = calculate_risk([])
        self.assertEqual(risk["score"], 100)
        self.assertEqual(risk["grade"], "A")
        self.assertEqual(risk["level"], "LOW")
        self.assertEqual(risk["compliance_status"], "COMPLIANT")


class SraMapperTests(unittest.TestCase):
    def test_required_control_themes(self) -> None:
        synthetic = [
            {"id": "ssl", "title": "Expired TLS certificate", "category": "SSL / TLS",
             "description": "Certificate expiry"},
            {"id": "headers", "title": "Strict-Transport-Security missing",
             "category": "Security Headers", "description": "Security header missing"},
            {"id": "ports", "title": "Port 3389 (RDP)", "category": "Network Security",
             "description": "Dangerous port open"},
            {"id": "email", "title": "Client email correspondence gap",
             "category": "Email Security", "description": "Client communication protection is weak"},
            {"id": "admin", "title": "Admin portal (/admin)", "category": "Exposed Services",
             "description": "Administrative login portal reachable"},
            {"id": "dmarc", "title": "No DMARC record", "category": "Email Security",
             "description": "Domain can be impersonated; SPF soft fail"},
        ]
        mapped = {item["id"]: item for item in map_to_sra(synthetic)}
        self.assertEqual(mapped["ssl"]["sra_theme"], "Secure communications")
        self.assertEqual(mapped["headers"]["sra_theme"], "Technical controls")
        self.assertEqual(mapped["ports"]["sra_theme"], "Network security")
        self.assertEqual(mapped["email"]["sra_theme"], "Client communication protection")
        self.assertEqual(mapped["admin"]["sra_theme"], "Access control")
        self.assertEqual(mapped["dmarc"]["sra_theme"], "Anti-fraud measures")
        for item in mapped.values():
            self.assertIn("SRA Standards and Regulations", item["sra_reference"])
            self.assertTrue(item["sra_requirement"])

    def test_mapping_does_not_mutate_source(self) -> None:
        finding = {"id": "x", "title": "No DMARC record", "severity": "CRITICAL"}
        mapped = map_to_sra([finding])[0]
        self.assertNotIn("sra_reference", finding)
        self.assertIn("sra_reference", mapped)


@unittest.skipIf(PdfReader is None, "pypdf is not installed")
class PdfBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sample = json.loads(SAMPLE_INPUT.read_text(encoding="utf-8"))

    def _render_sample(self, output_dir: Path) -> Path:
        findings = parse_findings(self.sample)
        mapped = map_to_sra(findings)
        risk = calculate_risk(findings)
        path = Path(build_pdf(
            firm_name="Example Law Firm LLP",
            scan_data=self.sample,
            findings=findings,
            sra_mapped=mapped,
            risk=risk,
            date="13 November 2026",
            output_dir=str(output_dir),
        ))
        return path

    def test_sample_pdf_structure_and_footers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._render_sample(Path(tmp))
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 12_000)
            self.assertTrue(path.read_bytes().startswith(b"%PDF-"))

            reader = PdfReader(str(path))
            self.assertGreaterEqual(len(reader.pages), 12)
            page_text = [page.extract_text() or "" for page in reader.pages]
            normalised = re.sub(r"\s+", " ", " ".join(page_text))
            for phrase in (
                "CYBER SECURITY ASSESSMENT REPORT",
                "PREPARED FOR:",
                "EXECUTIVE SUMMARY",
                "DETAILED FINDINGS",
                "BUSINESS IMPACT",
                "SRA REQUIREMENT REFERENCE",
                "REMEDIATION ROADMAP",
                "Report reviewed by:",
                "CONFIDENTIAL",
            ):
                self.assertIn(phrase, normalised, phrase)
            self.assertRegex(normalised, r"CYBEROPS-2026-\d{4}")
            for number, text in enumerate(page_text, start=1):
                self.assertIn(AUTHOR_EMAIL_SENTINEL, text, f"footer email missing on page {number}")
                self.assertIn(f"Page {number}", text, f"page number missing on page {number}")

    def test_empty_findings_pdf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(build_pdf(
                firm_name="Clean Example LLP",
                scan_data={"target": "clean.example", "scanner": "lawfirm-scanner"},
                findings=[],
                sra_mapped=[],
                risk=calculate_risk([]),
                date="13 November 2026",
                output_dir=str(tmp),
            ))
            self.assertTrue(path.read_bytes().startswith(b"%PDF-"))
            reader = PdfReader(str(path))
            text = re.sub(r"\s+", " ", " ".join(page.extract_text() or "" for page in reader.pages))
            self.assertIn("COMPLIANT", text)
            self.assertIn("No actionable findings were supplied", text)


class CommandLineTests(unittest.TestCase):
    def test_cli_generates_sample_pdf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT)
            env["PYTHONIOENCODING"] = "utf-8"
            result = subprocess.run(
                [
                    sys.executable, "generate.py",
                    "--input", str(SAMPLE_INPUT),
                    "--firm", "Example Law Firm LLP",
                    "--output", tmp,
                    "--date", "13 November 2026",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PDF generated", result.stdout)
            reports = list(Path(tmp).glob("*.pdf"))
            self.assertEqual(len(reports), 1)
            self.assertTrue(reports[0].read_bytes().startswith(b"%PDF-"))

    def test_cli_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            invalid = Path(tmp) / "invalid.json"
            invalid.write_text("{not json", encoding="utf-8")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT)
            env["PYTHONIOENCODING"] = "utf-8"
            result = subprocess.run(
                [sys.executable, "generate.py", "--input", str(invalid), "--firm", "Example"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("Invalid JSON", result.stdout)


AUTHOR_EMAIL_SENTINEL = "brucesec.mumbai@gmail.com"


def _meaningful(value: object) -> bool:
    return value is not None and str(value).strip() != ""


if __name__ == "__main__":
    unittest.main(verbosity=2)
