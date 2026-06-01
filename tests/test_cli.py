from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from secure_code_triage.cli import main


class CliTest(unittest.TestCase):
    def test_fail_on_high_returns_status_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / "SECURITY.md").write_text("Report issues by email.\n", encoding="utf-8")
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")  # secure-code-triage: ignore

            with redirect_stdout(StringIO()):
                status = main([str(root), "--fail-on", "high"])

        self.assertEqual(status, 2)

    def test_clean_repo_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / "SECURITY.md").write_text("Report issues by email.\n", encoding="utf-8")
            (root / "app.py").write_text("print('hello')\n", encoding="utf-8")

            with redirect_stdout(StringIO()):
                status = main([str(root), "--fail-on", "high"])

        self.assertEqual(status, 0)
