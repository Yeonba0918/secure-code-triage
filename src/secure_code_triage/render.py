"""Render scan reports."""

from __future__ import annotations

import json

from .models import Finding, Report
from .scanner import SEVERITIES


def render_markdown(report: Report) -> str:
    lines = [
        "# Secure code triage report",
        "",
        f"Target: {report.target}",
        "",
        "## Snapshot",
        "",
        f"- Files scanned: {report.summary.files_scanned}",
        f"- Files skipped: {report.summary.files_skipped}",
    ]

    for severity in SEVERITIES:
        count = report.summary.findings_by_severity.get(severity)
        if count:
            lines.append(f"- {severity.title()}: {count}")

    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings detected.")
    else:
        for finding in report.findings:
            lines.extend(_render_finding(finding))

    return "\n".join(lines) + "\n"


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


def _render_finding(finding: Finding) -> list[str]:
    return [
        f"- {finding.severity.title()} `{finding.rule_id}` at `{finding.path}:{finding.line}`",
        f"  {finding.title}",
        f"  Evidence: {finding.evidence}",
        f"  Fix: {finding.recommendation}",
    ]
