from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secure_code_triage.render import render_sarif
from secure_code_triage.scanner import scan_repository


class RenderTest(unittest.TestCase):
    def test_sarif_renderer_outputs_standard_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / "SECURITY.md").write_text("Report issues by email.\n", encoding="utf-8")
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")  # secure-code-triage: ignore
            report = scan_repository(root)

        payload = json.loads(render_sarif(report))

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "secure-code-triage")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "python-eval-exec")


if __name__ == "__main__":
    unittest.main()
