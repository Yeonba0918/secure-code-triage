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


def render_sarif(report: Report) -> str:
    rules = {}
    results = []
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.recommendation},
            "properties": {
                "severity": finding.severity,
                "tags": list(finding.tags),
            },
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": f"{finding.title}: {finding.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
            }
        )

    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secure-code-triage",
                        "informationUri": "https://github.com/Yeonba0918/secure-code-triage",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _render_finding(finding: Finding) -> list[str]:
    return [
        f"- {finding.severity.title()} `{finding.rule_id}` at `{finding.path}:{finding.line}`",
        f"  {finding.title}",
        f"  Evidence: {finding.evidence}",
        f"  Fix: {finding.recommendation}",
    ]


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
