from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secure_code_triage.scanner import scan_repository


class ScannerTest(unittest.TestCase):
    def test_detects_python_risky_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / "SECURITY.md").write_text("Report issues by email.\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import subprocess\n"
                "subprocess.run(user_input, shell=True)\n"  # secure-code-triage: ignore
                "eval(user_input)\n",  # secure-code-triage: ignore
                encoding="utf-8",
            )

            report = scan_repository(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("python-subprocess-shell", rule_ids)
        self.assertIn("python-eval-exec", rule_ids)

    def test_detects_and_redacts_secret_like_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / "SECURITY.md").write_text("Report issues by email.\n", encoding="utf-8")
            (root / "settings.py").write_text(
                'API_KEY = "super-secret-value-12345"\n',  # secure-code-triage: ignore
                encoding="utf-8",
            )

            report = scan_repository(root)

        findings = [finding for finding in report.findings if finding.rule_id == "secret-generic-assignment"]
        self.assertEqual(len(findings), 1)
        self.assertIn("[redacted]", findings[0].evidence)
        self.assertNotIn("super-secret-value", findings[0].evidence)

    def test_committed_env_file_is_high_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / "SECURITY.md").write_text("Report issues by email.\n", encoding="utf-8")
            (root / ".env").write_text("TOKEN=abc123456789abc123456789\n", encoding="utf-8")

            report = scan_repository(root)

        self.assertIn("high", report.summary.findings_by_severity)
        self.assertIn("committed-env-file", {finding.rule_id for finding in report.findings})

    def test_repository_hygiene_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")

            report = scan_repository(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("missing-security-policy", rule_ids)
        self.assertIn("missing-gitignore", rule_ids)


if __name__ == "__main__":
    unittest.main()
