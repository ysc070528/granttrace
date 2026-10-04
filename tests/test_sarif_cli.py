"""Real loopback CLI scans can export SARIF without changing audit behavior."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import api_sentinel
from core import __version__, demo


ROOT = Path(__file__).resolve().parents[1]


class SarifCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-sarif-cli-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        spec, config, self.database = demo.load_assets()
        self.spec = self.folder / "spec.json"
        self.config = self.folder / "config.json"
        self.spec.write_text(json.dumps(spec), encoding="utf-8")
        self.config.write_text(json.dumps(config), encoding="utf-8")

    def arguments(self, target, sarif=None):
        arguments = ["--spec", str(self.spec), "--config", str(self.config), "--target", target,
                     "--delay", "0", "--output", str(self.folder / "report.html"),
                     "--export-json", str(self.folder / "result.json")]
        if sarif is not None:
            arguments += ["--export-sarif", str(sarif)]
        return arguments

    def call_cli(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = api_sentinel.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def subprocess_cli(self, arguments):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT)
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["NO_PROXY"] = "127.0.0.1,localhost"
        environment["no_proxy"] = "127.0.0.1,localhost"
        return subprocess.run([sys.executable, str(ROOT / "api_sentinel.py"), *arguments],
                              cwd=self.folder, env=environment, capture_output=True, text=True,
                              encoding="utf-8", timeout=30)

    def read_json(self):
        return json.loads((self.folder / "result.json").read_text(encoding="utf-8"))

    def test_real_readonly_scan_exports_html_json_sarif_and_sends_zero_patch(self):
        output = self.folder / "new" / "nested" / "result.sarif"
        with demo.DemoServer(self.database) as server:
            completed = self.subprocess_cli(self.arguments(server.target, output))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(server.handler.DATABASE, self.database)
            self.assertTrue(server.handler.requests)
            self.assertNotIn("PATCH", {request["method"] for request in server.handler.requests})
        self.assertFalse(server.thread.is_alive())
        self.assertEqual(server.server.socket.fileno(), -1)
        self.assertTrue((self.folder / "report.html").is_file())
        self.assertIn(f">v{__version__}</span>", (self.folder / "report.html").read_text(encoding="utf-8"))
        report = self.read_json()
        self.assertEqual(Counter(item["verdict"] for item in report["results"]),
                         Counter({"CONFIRMED": 1, "PUBLIC": 1, "SECURE": 1, "SKIPPED": 2}))
        self.assertEqual(report["tool_version"], __version__)
        sarif = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual([item["ruleId"] for item in sarif["runs"][0]["results"]], ["GT-BOLA-001"])
        self.assertIn("[OK] SARIF report:", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)

    def test_real_active_scan_exports_confirmed_only_and_restores_complete_database(self):
        output = self.folder / "active.sarif"
        with demo.DemoServer(self.database) as server:
            before = copy.deepcopy(server.handler.DATABASE)
            completed = self.subprocess_cli([*self.arguments(server.target, output), "--allow-write-tests"])
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(server.handler.DATABASE, before)
            requests = server.handler.requests
            writes = [index for index, request in enumerate(requests) if request["method"] == "PATCH"]
            self.assertGreaterEqual(len(writes), 2)
            self.assertTrue(any(request["method"] == "GET" and request["path"].endswith("/profile")
                                for request in requests[writes[0] + 1:writes[1]]))
        self.assertFalse(server.thread.is_alive())
        self.assertEqual(server.server.socket.fileno(), -1)
        report = self.read_json()
        self.assertEqual(Counter(item["verdict"] for item in report["results"]),
                         Counter({"CONFIRMED": 2, "PUBLIC": 1, "SECURE": 2}))
        mass = next(item for item in report["findings"] if item["cwe"] == "CWE-915")
        self.assertTrue(mass["evidence"]["rollback_verified"])
        self.assertNotEqual(mass["evidence"]["target_url"], mass["evidence"]["readback_url"])
        results = json.loads(output.read_text(encoding="utf-8"))["runs"][0]["results"]
        self.assertEqual({item["ruleId"] for item in results}, {"GT-BOLA-001", "GT-MASS-001"})
        self.assertEqual(len(results), 2)

    def test_dry_run_sarif_is_rejected_before_auditor_files_or_network(self):
        output = self.folder / "must-not-exist.sarif"
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")), \
             patch("socket.socket", side_effect=AssertionError("Network opened")):
            code, stdout, stderr = self.call_cli([
                "--dry-run", "--export-sarif", str(output), "--spec", str(self.folder / "missing.json"),
            ])
        self.assertEqual(code, 2, stdout + stderr)
        self.assertIn("--dry-run", stderr)
        self.assertIn("--export-sarif", stderr)
        self.assertFalse(output.exists())
        self.assertNotIn("Traceback", stdout + stderr)

    def test_other_offline_modes_reject_sarif_without_creating_files_or_auditor(self):
        output = self.folder / "offline.sarif"
        before = {path.name: path.read_bytes() for path in self.folder.iterdir()}
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")), \
             patch("socket.socket", side_effect=AssertionError("Network opened")):
            for mode in (["--validate-config"], ["--init-config", str(self.folder / "draft.json")]):
                with self.subTest(mode=mode):
                    code, stdout, stderr = self.call_cli([*mode, "--export-sarif", str(output)])
                    self.assertEqual(code, 2, stdout + stderr)
                    self.assertIn("--export-sarif", stderr)
                    self.assertNotIn("Traceback", stdout + stderr)
        self.assertEqual({path.name: path.read_bytes() for path in self.folder.iterdir()}, before)

    def test_sarif_cannot_overwrite_html_or_json_output(self):
        for path in (self.folder / "report.html", self.folder / "result.json"):
            with self.subTest(path=path.name), \
                 patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
                path.write_text("preserve existing output", encoding="utf-8")
                code, stdout, stderr = self.call_cli(self.arguments("http://127.0.0.1:1", path))
                self.assertEqual(code, 2, stdout + stderr)
                self.assertEqual(path.read_text(encoding="utf-8"), "preserve existing output")
                self.assertNotIn("Traceback", stdout + stderr)

    def test_triple_export_rejects_html_json_alias_before_scan(self):
        shared = self.folder / "shared-report.json"
        shared.write_text("preserve existing shared output", encoding="utf-8")
        sarif = self.folder / "separate.sarif"
        arguments = self.arguments("http://127.0.0.1:1", sarif)
        arguments[arguments.index("--output") + 1] = str(shared)
        arguments[arguments.index("--export-json") + 1] = str(shared)
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")), \
             patch("socket.socket", side_effect=AssertionError("Network opened")):
            code, stdout, stderr = self.call_cli(arguments)
        self.assertEqual(code, 2, stdout + stderr)
        self.assertEqual(shared.read_text(encoding="utf-8"), "preserve existing shared output")
        self.assertFalse(sarif.exists())
        self.assertNotIn("Traceback", stdout + stderr)

    def test_sarif_cannot_overwrite_spec_or_config(self):
        for path in (self.spec, self.config):
            original = path.read_bytes()
            with self.subTest(path=path.name), \
                 patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
                code, stdout, stderr = self.call_cli(self.arguments("http://127.0.0.1:1", path))
                self.assertEqual(code, 2, stdout + stderr)
                self.assertEqual(path.read_bytes(), original)
                self.assertNotIn("Traceback", stdout + stderr)

    def test_resolved_output_alias_is_rejected_before_scan(self):
        output = self.folder / "subfolder" / ".." / "report.html"
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
            code, stdout, stderr = self.call_cli(self.arguments("http://127.0.0.1:1", output))
        self.assertEqual(code, 2, stdout + stderr)
        self.assertFalse((self.folder / "report.html").exists())
        self.assertNotIn("Traceback", stdout + stderr)

    def test_existing_hardlinked_input_alias_is_rejected_without_damage(self):
        output = self.folder / "hardlinked.sarif"
        os.link(self.config, output)
        original = self.config.read_bytes()
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
            code, stdout, stderr = self.call_cli(self.arguments("http://127.0.0.1:1", output))
        self.assertEqual(code, 2, stdout + stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(output.read_bytes(), original)
        self.assertNotIn("Traceback", stdout + stderr)

    def test_empty_or_nul_sarif_path_returns_two_without_network_or_traceback(self):
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")), \
             patch("socket.socket", side_effect=AssertionError("Network opened")):
            for path in ("", "invalid\0report.sarif"):
                with self.subTest(path=repr(path)):
                    code, stdout, stderr = self.call_cli(self.arguments("http://127.0.0.1:1", path))
                    self.assertEqual(code, 2, stdout + stderr)
                    self.assertIn("[ERROR]", stderr)
                    self.assertNotIn("[OK] SARIF report:", stdout)
                    self.assertNotIn("Traceback", stdout + stderr)

    def test_sarif_directory_io_error_returns_two_preserving_html_and_json(self):
        directory = self.folder / "output-directory"
        directory.mkdir()
        with demo.DemoServer(self.database) as server:
            code, stdout, stderr = self.call_cli(self.arguments(server.target, directory))
            self.assertEqual(server.handler.DATABASE, self.database)
        self.assertEqual(code, 2, stdout + stderr)
        self.assertTrue((self.folder / "report.html").is_file())
        self.assertEqual(self.read_json()["stats"]["bola_confirmed"], 1)
        self.assertNotIn("[OK] SARIF report:", stdout)
        self.assertIn("[ERROR]", stderr)
        self.assertNotIn("Traceback", stdout + stderr)

    def test_sarif_parent_file_io_error_returns_two_without_false_success(self):
        parent = self.folder / "existing-file"
        parent.write_text("preserve existing user file", encoding="utf-8")
        output = parent / "report.sarif"
        with demo.DemoServer(self.database) as server:
            completed = self.subprocess_cli(self.arguments(server.target, output))
            self.assertEqual(server.handler.DATABASE, self.database)
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
        self.assertEqual(parent.read_text(encoding="utf-8"), "preserve existing user file")
        self.assertTrue((self.folder / "report.html").is_file())
        self.assertTrue((self.folder / "result.json").is_file())
        self.assertNotIn("[OK] SARIF report:", completed.stdout)
        self.assertNotIn("Traceback", completed.stdout + completed.stderr)

    def test_inprocess_sarif_export_creates_missing_parent_and_retains_sensitive_optin_boundary(self):
        output = self.folder / "new" / "subfolder" / "report.sarif"
        with demo.DemoServer(self.database) as server:
            code, stdout, stderr = self.call_cli([
                *self.arguments(server.target, output), "--include-sensitive-evidence",
            ])
            self.assertEqual(server.handler.DATABASE, self.database)
        self.assertEqual(code, 0, stdout + stderr)
        json_report = self.read_json()
        self.assertIn("Fictional demo salary", json.dumps(json_report))
        self.assertIn("Demo Owner", json.dumps(json_report))
        sarif_text = output.read_text(encoding="utf-8")
        for private in ("Fictional demo salary", "Demo Owner", "Disposable demo content", "Fictional demo document"):
            self.assertNotIn(private, sarif_text)
        self.assertEqual(len(json.loads(sarif_text)["runs"][0]["results"]), 1)
        self.assertIn("[OK] SARIF report:", stdout)

    def test_successful_sarif_export_preserves_existing_fail_on_vulnerability_exit(self):
        output = self.folder / "confirmed.sarif"
        with demo.DemoServer(self.database) as server:
            code, stdout, stderr = self.call_cli([
                *self.arguments(server.target, output), "--fail-on-vuln",
            ])
        self.assertEqual(code, 1, stdout + stderr)
        self.assertTrue(output.is_file())
        self.assertEqual(len(json.loads(output.read_text(encoding="utf-8"))["runs"][0]["results"]), 1)


if __name__ == "__main__":
    unittest.main()
