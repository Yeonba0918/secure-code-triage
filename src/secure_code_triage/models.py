"""Data models for secure code triage reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Rule:
    """A scanner rule definition."""

    rule_id: str
    title: str
    severity: str
    recommendation: str = ""
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """One security-relevant finding."""

    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    evidence: str
    recommendation: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Summary:
    """Aggregate scan information."""

    target: Path
    files_scanned: int
    files_skipped: int
    findings_by_severity: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Report:
    """Full security triage report."""

    target: Path
    summary: Summary
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": str(self.target),
            "summary": {
                "files_scanned": self.summary.files_scanned,
                "files_skipped": self.summary.files_skipped,
                "findings_by_severity": self.summary.findings_by_severity,
            },
            "findings": [finding.__dict__ for finding in self.findings],
        }
