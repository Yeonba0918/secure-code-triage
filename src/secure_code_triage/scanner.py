"""Repository scanner for defensive security triage."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Finding, Report, Rule, Summary

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
}

TEXT_EXTENSIONS = {
    ".bash",
    ".c",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".env",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".md",
    ".php",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

ENV_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
}

IGNORE_MARKER = "secure-code-triage: ignore"

SECURITY_POLICY_NAMES = {
    "SECURITY",
    "SECURITY.md",
    ".github/SECURITY.md",
}


@dataclass(frozen=True)
class PatternRule:
    rule: Rule
    pattern: re.Pattern[str]
    extensions: tuple[str, ...] = ()


PATTERN_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        Rule(
            "secret-private-key",
            "Private key material",
            "critical",
            "Remove the key from the repository, rotate it, and store replacements in a secret manager.",
            ("secret",),
        ),
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    PatternRule(
        Rule(
            "secret-aws-access-key",
            "AWS access key identifier",
            "high",
            "Rotate the key and move credentials to IAM roles, environment variables, or a secret manager.",
            ("secret", "cloud"),
        ),
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    PatternRule(
        Rule(
            "secret-github-token",
            "GitHub token",
            "high",
            "Revoke the token and use GitHub Actions secrets or a scoped runtime credential.",
            ("secret", "github"),
        ),
        re.compile(r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    PatternRule(
        Rule(
            "secret-slack-token",
            "Slack token",
            "high",
            "Revoke the token and move it to a managed secret store.",
            ("secret", "slack"),
        ),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    PatternRule(
        Rule(
            "secret-generic-assignment",
            "Hardcoded secret-like assignment",
            "high",
            "Move secrets to a managed secret store or runtime environment variable.",
            ("secret",),
        ),
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"\n]{12,}['\"]"
        ),
    ),
    PatternRule(
        Rule(
            "python-eval-exec",
            "Dynamic code execution",
            "high",
            "Avoid eval/exec on untrusted input; replace it with explicit parsing or dispatch tables.",
            ("python", "injection"),
        ),
        re.compile(r"\b(eval|exec)\s*\("),
        (".py",),
    ),
    PatternRule(
        Rule(
            "python-subprocess-shell",
            "Subprocess with shell=True",
            "high",
            "Pass argument lists to subprocess APIs and keep shell=True disabled for untrusted input.",
            ("python", "command-injection"),
        ),
        re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\([^;\n]*shell\s*=\s*True"),
        (".py",),
    ),
    PatternRule(
        Rule(
            "python-pickle-load",
            "Unsafe pickle loading",
            "high",
            "Do not load pickle data from untrusted sources; use a safer serialization format.",
            ("python", "deserialization"),
        ),
        re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        (".py",),
    ),
    PatternRule(
        Rule(
            "python-yaml-load",
            "YAML load without obvious safe loader",
            "medium",
            "Use yaml.safe_load or pass SafeLoader explicitly.",
            ("python", "deserialization"),
        ),
        re.compile(r"\byaml\.load\s*\((?![^)]*SafeLoader)"),
        (".py",),
    ),
    PatternRule(
        Rule(
            "weak-hash",
            "Weak hash algorithm",
            "low",
            "Use SHA-256 or stronger for security-sensitive hashing.",
            ("crypto",),
        ),
        re.compile(r"\b(?:hashlib\.)?(?:md5|sha1)\s*\("),
        (".py", ".js", ".ts", ".go", ".java", ".php", ".rb"),
    ),
    PatternRule(
        Rule(
            "javascript-eval",
            "JavaScript eval",
            "high",
            "Avoid eval on dynamic input; use structured parsing or explicit command maps.",
            ("javascript", "injection"),
        ),
        re.compile(r"\beval\s*\("),
        (".js", ".jsx", ".ts", ".tsx"),
    ),
    PatternRule(
        Rule(
            "javascript-child-process-exec",
            "child_process.exec use",
            "high",
            "Prefer spawn with an argument array and strict input validation.",
            ("javascript", "command-injection"),
        ),
        re.compile(r"\b(?:child_process\.)?exec\s*\("),
        (".js", ".jsx", ".ts", ".tsx"),
    ),
    PatternRule(
        Rule(
            "javascript-inner-html",
            "Direct innerHTML assignment",
            "medium",
            "Prefer textContent or a sanitizer when rendering untrusted HTML.",
            ("javascript", "xss"),
        ),
        re.compile(r"\.innerHTML\s*="),
        (".js", ".jsx", ".ts", ".tsx", ".html"),
    ),
    PatternRule(
        Rule(
            "c-unsafe-string-api",
            "Unsafe C string API",
            "high",
            "Use bounded alternatives and validate destination buffer sizes.",
            ("c", "memory-safety"),
        ),
        re.compile(r"\b(?:gets|strcpy|strcat|sprintf)\s*\("),
        (".c", ".h", ".cpp", ".hpp"),
    ),
    PatternRule(
        Rule(
            "python-sql-fstring",
            "SQL execution with f-string",
            "medium",
            "Use parameterized queries instead of string interpolation.",
            ("python", "sql-injection"),
        ),
        re.compile(r"\bexecute\s*\(\s*f[\"']"),
        (".py",),
    ),
)


def scan_repository(
    target: Path,
    include_hidden: bool = False,
    max_bytes: int = 1_000_000,
) -> Report:
    """Scan a local repository path and return a report."""

    root = target.expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    if not root.is_dir():
        raise NotADirectoryError(root)

    findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0

    for path in iter_candidate_files(root, include_hidden=include_hidden):
        if _should_skip_file(path, max_bytes=max_bytes):
            files_skipped += 1
            continue

        files_scanned += 1
        findings.extend(_scan_file(root, path))

    findings.extend(_repository_hygiene_findings(root))
    findings.sort(key=lambda item: (SEVERITY_RANK[item.severity], item.path, item.line, item.rule_id))

    summary = Summary(
        target=root,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        findings_by_severity=_count_by_severity(findings),
    )
    return Report(target=root, summary=summary, findings=tuple(findings))


def iter_candidate_files(root: Path, include_hidden: bool = False) -> Iterable[Path]:
    """Yield text-like files, skipping common dependency and build directories."""

    for current_root, dirs, files in _walk(root):
        dirs[:] = [
            name
            for name in dirs
            if not _skip_dir_name(name, include_hidden=include_hidden)
        ]
        for name in files:
            path = current_root / name
            if _skip_hidden_file(path, root, include_hidden=include_hidden):
                continue
            if _is_text_candidate(path):
                yield path


def _walk(root: Path):
    import os

    for current_root, dirs, files in os.walk(root):
        yield Path(current_root), dirs, files


def _scan_file(root: Path, path: Path) -> list[Finding]:
    rel = path.relative_to(root).as_posix()
    findings: list[Finding] = []

    if path.name in ENV_FILE_NAMES:
        findings.append(
            Finding(
                "committed-env-file",
                "Committed environment file",
                "high",
                rel,
                1,
                "[redacted]",
                "Remove committed environment files and keep only sanitized .env.example templates.",
                ("secret", "repository-hygiene"),
            )
        )

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for line_number, line in enumerate(lines, start=1):
        normalized = line.strip()
        if not normalized or normalized.startswith(("#", "//")) or IGNORE_MARKER in line:
            continue
        for rule in PATTERN_RULES:
            if rule.extensions and path.suffix.lower() not in rule.extensions:
                continue
            if rule.pattern.search(line) and not _looks_like_placeholder(line):
                findings.append(_make_finding(rule.rule, rel, line_number, line))

    return findings


def _make_finding(rule: Rule, rel_path: str, line_number: int, line: str) -> Finding:
    return Finding(
        rule.rule_id,
        rule.title,
        rule.severity,
        rel_path,
        line_number,
        _redact(line) if "secret" in rule.tags else _compact(line),
        rule.recommendation,
        rule.tags,
    )


def _repository_hygiene_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    if not any((root / name).exists() for name in SECURITY_POLICY_NAMES):
        findings.append(
            Finding(
                "missing-security-policy",
                "Missing security policy",
                "low",
                ".",
                1,
                "No SECURITY.md file found",
                "Add SECURITY.md with vulnerability reporting expectations and supported versions.",
                ("repository-hygiene",),
            )
        )

    if not (root / ".gitignore").exists():
        findings.append(
            Finding(
                "missing-gitignore",
                "Missing .gitignore",
                "low",
                ".",
                1,
                "No .gitignore file found",
                "Add .gitignore entries for local credentials, build output, and dependency caches.",
                ("repository-hygiene",),
            )
        )

    return findings


def _skip_dir_name(name: str, include_hidden: bool) -> bool:
    if name in SKIP_DIRS:
        return True
    if name == ".github":
        return False
    return name.startswith(".") and not include_hidden


def _skip_hidden_file(path: Path, root: Path, include_hidden: bool) -> bool:
    if include_hidden:
        return False
    rel_parts = path.relative_to(root).parts
    if path.name in ENV_FILE_NAMES:
        return False
    return any(part.startswith(".") and part != ".github" for part in rel_parts)


def _is_text_candidate(path: Path) -> bool:
    if path.name in ENV_FILE_NAMES:
        return True
    if path.name in {"Dockerfile", "Makefile", "Jenkinsfile"}:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def _should_skip_file(path: Path, max_bytes: int) -> bool:
    try:
        stat = path.stat()
    except OSError:
        return True
    if stat.st_size > max_bytes:
        return True
    try:
        with path.open("rb") as handle:
            chunk = handle.read(2048)
    except OSError:
        return True
    return b"\x00" in chunk


def _looks_like_placeholder(line: str) -> bool:
    lowered = line.lower()
    placeholders = ("example", "dummy", "sample", "placeholder", "changeme", "not-a-real", "test-token")
    return any(word in lowered for word in placeholders)


def _redact(line: str) -> str:
    if "-----BEGIN" in line:
        return "[redacted private key marker]"
    assignment = re.search(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]", line)
    if assignment:
        return f"{assignment.group(1)} = [redacted]"
    return "[redacted]"


def _compact(line: str, limit: int = 160) -> str:
    text = " ".join(line.strip().split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _count_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return {severity: count for severity, count in counts.items() if count}
