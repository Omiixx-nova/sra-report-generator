#!/usr/bin/env python3
"""
SRA Report Generator — Converts vulnerability scan
JSON into SRA-compliant PDF reports for UK law firms.
Author: Omkar Sawant — CyberOps
GitHub: https://github.com/Omiixx-nova
Contact: brucesec.mumbai@gmail.com
"""

import argparse
import json
import sys
import os
from datetime import datetime

try:
    from modules.findings_parser import parse_findings
    from modules.sra_mapper import map_to_sra
    from modules.risk_scorer import calculate_risk
    from modules.pdf_builder import build_pdf
except ImportError as exc:
    print(f"  ✗ Missing dependency: {exc}")
    print("    Run: python -m pip install -r requirements.txt")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="SRA Report Generator — CyberOps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate.py --input reports/scan.json --firm "Smith & Co Solicitors"
  python generate.py --input scan.json --firm "Jones Law" --output my_reports
        """
    )
    parser.add_argument("--input", "-i", required=True,
                       help="Path to scanner JSON output")
    parser.add_argument("--firm", "-f", required=True,
                       help="Law firm name for the report")
    parser.add_argument("--output", "-o", default="output",
                       help="Output directory (default: output)")
    parser.add_argument("--date", "-d",
                       default=datetime.now().strftime("%d %B %Y"),
                       help="Assessment date (default: today)")
    args = parser.parse_args()

    if not args.firm.strip():
        parser.error("--firm must not be empty")

    print("\n  SRA Report Generator — CyberOps")
    print("  ─────────────────────────────────")

    # Load scan data
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
        print(f"  ✓ Loaded scan data: {args.input}")
    except FileNotFoundError:
        print(f"  ✗ File not found: {args.input}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"  ✗ Invalid JSON: {args.input}")
        sys.exit(1)
    except OSError as exc:
        print(f"  ✗ Could not read {args.input}: {exc}")
        sys.exit(1)

    try:
        # Parse findings
        findings = parse_findings(scan_data)
        print(f"  ✓ Parsed {len(findings)} findings")

        # Map to SRA standards
        sra_mapped = map_to_sra(findings)
        print(f"  ✓ Mapped to SRA Cyber Security Standards")

        # Calculate risk
        risk = calculate_risk(findings)
        print(f"  ✓ Risk score: {risk['score']}/100 — {risk['level']}")

        # Build PDF
        os.makedirs(args.output, exist_ok=True)
        output_path = build_pdf(
            firm_name=args.firm,
            scan_data=scan_data,
            findings=findings,
            sra_mapped=sra_mapped,
            risk=risk,
            date=args.date,
            output_dir=args.output
        )
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"  ✗ Report generation failed: {exc}")
        sys.exit(1)

    print(f"  ✓ PDF generated: {output_path}")
    print(f"\n  Report ready for SRA submission and PI insurance renewal.")
    print(f"  CyberOps — brucesec.mumbai@gmail.com\n")


if __name__ == "__main__":
    main()
