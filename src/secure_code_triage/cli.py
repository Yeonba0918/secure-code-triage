"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .render import render_json, render_markdown
from .scanner import SEVERITIES, SEVERITY_RANK, scan_repository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secure-code-triage",
        description="Run a defensive security triage scan against a local code repository.",
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Local repository path to scan.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format. Defaults to markdown.",
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="Scan hidden files and directories beyond .github and .env files.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1_000_000,
        help="Skip files larger than this many bytes. Defaults to 1000000.",
    )
    parser.add_argument(
        "--fail-on",
        choices=(*SEVERITIES, "none"),
        default="none",
        help="Exit with status 2 when a finding at this severity or higher is present.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write the report to a file instead of stdout.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args(argv)
    report = scan_repository(
        args.target,
        include_hidden=args.include_hidden,
        max_bytes=args.max_bytes,
    )
    output = render_json(report) if args.format == "json" else render_markdown(report)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)

    if args.fail_on != "none" and _has_findings_at_or_above(report, args.fail_on):
        return 2
    return 0


def _has_findings_at_or_above(report, threshold: str) -> bool:
    threshold_rank = SEVERITY_RANK[threshold]
    return any(SEVERITY_RANK[finding.severity] <= threshold_rank for finding in report.findings)


if __name__ == "__main__":
    raise SystemExit(main())
