"""Release metadata and a real CLI scan must identify the same GrantTrace build."""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from core import __version__
from core.reporter import SecurityReportGenerator
from mock_server.server import TargetMockHandler


ROOT = Path(__file__).resolve().parents[1]


class ReleaseIdentityTests(unittest.TestCase):
    def test_project_metadata_matches_runtime_version(self):
        manifest = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        project = re.search(r"(?ms)^\[project\]\s*\n(.*?)(?=^\[|\Z)", manifest)
        self.assertIsNotNone(project)
        declared = re.search(r'^version\s*=\s*"([^"]+)"\s*$', project[1], re.MULTILINE)
        self.assertIsNotNone(declared)
        self.assertEqual(declared[1], __version__)

    def test_report_api_creates_the_default_report(self):
        with tempfile.TemporaryDirectory(prefix="granttrace-report-default-") as directory:
            previous = Path.cwd()
            try:
                os.chdir(directory)
                SecurityReportGenerator.generate({}, [], "https://example.test")
            finally:
                os.chdir(previous)
            report = Path(directory) / "granttrace_report.html"
            self.assertTrue(report.is_file())
            self.assertIn(f">v{__version__}</span>", report.read_text(encoding="utf-8"))

    def test_real_scan_uses_default_filename_and_runtime_version_everywhere(self):
        class RecordingHandler(TargetMockHandler):
            user_agents = []

            def do_GET(self):
                self.user_agents.append(self.headers.get("User-Agent"))
                super().do_GET()

        RecordingHandler.reset_database()
        server = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="granttrace-cli-default-") as directory:
                outside = Path(directory)
                result = subprocess.run(
                    [sys.executable, str(ROOT / "api_sentinel.py"),
                     "--spec", str(ROOT / "openapi.json"),
                     "--config", str(ROOT / "config.example.json"),
                     "--target", f"http://127.0.0.1:{server.server_port}",
                     "--delay", "0", "--export-json", "result.json"],
                    cwd=outside, capture_output=True, text=True, encoding="utf-8",
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"auditing  v{__version__}", result.stdout)
                self.assertIn(f"GrantTrace {__version__} safety-first audit", result.stdout)
                report = outside / "granttrace_report.html"
                self.assertTrue(report.is_file(), result.stdout + result.stderr)
                self.assertIn(f">v{__version__}</span>", report.read_text(encoding="utf-8"))
                exported = json.loads((outside / "result.json").read_text(encoding="utf-8"))
                self.assertEqual(exported["tool_version"], __version__)
                self.assertEqual(exported["stats"]["conclusive_coverage_pct"], 60.0)
                self.assertTrue(RecordingHandler.user_agents)
                self.assertEqual(set(RecordingHandler.user_agents), {f"GrantTrace/{__version__}"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            RecordingHandler.reset_database()


if __name__ == "__main__":
    unittest.main()
