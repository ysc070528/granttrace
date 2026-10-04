"""Report exports preserve inputs and redact known credentials in metadata."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import api_sentinel
from core.evidence import sanitize_url
from core.reporter import SecurityReportGenerator


class ReportBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-report-boundaries-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.spec = self.folder / "spec.json"
        self.config = self.folder / "config.json"
        self.secret = "SYNTHETIC_SESSION_A9/part+tail"
        self.spec.write_text(json.dumps({
            "openapi": "3.0.3", "info": {"title": "offline report probe", "version": "1"},
            "paths": {},
        }), encoding="utf-8")
        self.config.write_text(json.dumps({"identities": {
            "owner": {"id": "1", "token": "Bearer SYNTHETIC_OWNER"},
            "visitor": {"id": "2", "token": "Bearer " + self.secret},
            "anonymous": {},
        }}), encoding="utf-8")

    def arguments(self):
        return ["--spec", str(self.spec), "--config", str(self.config),
                "--output", str(self.folder / "report.html")]

    def call_cli(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = api_sentinel.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_exports_reject_input_aliases_before_loading_or_network(self):
        before = {p.name: p.read_bytes() for p in self.folder.iterdir()}
        for output in ("--output", "--export-json"):
            for source in (self.spec, self.config):
                for dry_run in ((False, True) if output == "--export-json" else (False,)):
                    with self.subTest(output=output, source=source.name, dry_run=dry_run), \
                         patch("api_sentinel._load_config", side_effect=AssertionError("Loaded input")), \
                         patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")), \
                         patch("socket.socket", side_effect=AssertionError("Network opened")):
                        args = self.arguments() + [output, str(source)]
                        if dry_run:
                            args.append("--dry-run")
                        code, stdout, stderr = self.call_cli(args)
                        self.assertEqual(code, 2, stdout + stderr)
                        self.assertIn("separate path from spec/config", stderr)
        self.assertEqual({p.name: p.read_bytes() for p in self.folder.iterdir()}, before)

    def test_html_json_collision_is_rejected_without_sarif(self):
        output = self.folder / "shared.json"
        output.write_text("preserve output", encoding="utf-8")
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
            code, stdout, stderr = self.call_cli(self.arguments() + [
                "--output", str(output), "--export-json", str(output),
            ])
        self.assertEqual(code, 2, stdout + stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "preserve output")

    def test_local_reference_inputs_cannot_be_overwritten_before_audit(self):
        dependency = self.folder / "parameters.json"
        dependency.write_text(json.dumps({"UserId": {
            "name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"},
        }}), encoding="utf-8")
        self.spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {"/users/{user_id}": {
            "get": {"parameters": [{"$ref": "parameters.json#/UserId"}],
                    "responses": {"200": {"description": "User"}}},
        }}}), encoding="utf-8")
        original = dependency.read_bytes()
        hardlink = self.folder / "reference-alias.json"
        os.link(dependency, hardlink)
        for output in (dependency, hardlink):
            for option, dry_run in (("--output", False), ("--export-json", False), ("--export-json", True)):
                with self.subTest(output=output.name, option=option, dry_run=dry_run), \
                     patch("core.auditor.APISentinelAuditor.run", side_effect=AssertionError("Audit started")), \
                     patch("socket.socket", side_effect=AssertionError("Network opened")):
                    args = self.arguments() + [option, str(output)]
                    if dry_run:
                        args.append("--dry-run")
                    code, stdout, stderr = self.call_cli(args)
                    self.assertEqual(code, 2, stdout + stderr)
                    self.assertEqual(dependency.read_bytes(), original)
                    self.assertEqual(hardlink.read_bytes(), original)
                    self.assertIn("separate path from spec/config", stderr)

    def test_hardlinked_and_resolved_json_aliases_preserve_config(self):
        original = self.config.read_bytes()
        hardlink = self.folder / "hardlinked.json"
        os.link(self.config, hardlink)
        for output in (hardlink, self.folder / "subfolder" / ".." / "config.json"):
            with self.subTest(output=str(output)), \
                 patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
                code, stdout, stderr = self.call_cli(self.arguments() + [
                    "--dry-run", "--export-json", str(output),
                ])
                self.assertEqual(code, 2, stdout + stderr)
                self.assertEqual(self.config.read_bytes(), original)
                self.assertEqual(hardlink.read_bytes(), original)

    def test_invalid_html_json_paths_are_rejected_before_audit(self):
        for option in ("--output", "--export-json"):
            for output in ("", "   ", "invalid\0file", "invalid\nfile"):
                with self.subTest(option=option, output=repr(output)), \
                     patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
                    code, stdout, stderr = self.call_cli(self.arguments() + [option, output])
                    self.assertEqual(code, 2, stdout + stderr)
                    self.assertNotIn("Traceback", stderr)

    def test_unused_html_path_does_not_block_dry_run(self):
        original = self.config.read_bytes()
        with patch("socket.socket", side_effect=AssertionError("Network opened")):
            code, stdout, stderr = self.call_cli(self.arguments() + [
                "--dry-run", "--output", str(self.config),
                "--export-json", str(self.folder / "plan.json"),
            ])
        self.assertEqual(code, 0, stdout + stderr)
        self.assertEqual(self.config.read_bytes(), original)
        plan = json.loads((self.folder / "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["requests_sent"], 0)

    def test_tilde_outputs_use_the_checked_expanded_path(self):
        literal = self.folder / "~" / "config.json"
        literal.parent.mkdir()
        literal.write_bytes(self.config.read_bytes())
        original = literal.read_bytes()
        expanded = self.folder / "expanded-home" / "config.json"

        def expand(path):
            return expanded if str(path).replace("\\", "/") == "~/config.json" else path

        previous = Path.cwd()
        try:
            os.chdir(self.folder)
            with patch.object(Path, "expanduser", autospec=True, side_effect=expand), \
                 patch("socket.socket", side_effect=AssertionError("Network opened")):
                code, stdout, stderr = self.call_cli([
                    "--spec", str(self.spec), "--config", str(literal),
                    "--dry-run", "--export-json", "~/config.json",
                ])
            self.assertEqual(code, 0, stdout + stderr)
            self.assertEqual(literal.read_bytes(), original)
            self.assertEqual(json.loads(expanded.read_text(encoding="utf-8"))["requests_sent"], 0)
        finally:
            os.chdir(previous)

    def test_real_cli_redacts_raw_and_encoded_target_secrets_in_both_reports(self):
        # Empty local spec lets the complete CLI/report pipeline run with zero
        # requests; no mocked auditor/report writer can hide an output leak.
        for path in (self.secret, quote(self.secret, safe=""),
                     "%53YNTHETIC_SESSION_A9/part+tail", "SYNTHETIC_SESSION_A9/%70art+tail",
                     quote(self.secret, safe="").replace("%2F", "%2f")):
            for sensitive in (False, True):
                with self.subTest(path=path, sensitive=sensitive), \
                     patch("socket.socket", side_effect=AssertionError("Network opened")):
                    args = self.arguments() + [
                        "--target", "https://api.example.test/" + path,
                        "--export-json", str(self.folder / "report.json"),
                    ]
                    if sensitive:
                        args.append("--include-sensitive-evidence")
                    code, stdout, stderr = self.call_cli(args)
                    self.assertEqual(code, 0, stdout + stderr)
                    html = (self.folder / "report.html").read_text(encoding="utf-8")
                    report = json.loads((self.folder / "report.json").read_text(encoding="utf-8"))
                    for text in (html, report["target"]):
                        self.assertNotIn(self.secret, text)
                        self.assertNotIn(quote(self.secret, safe=""), text)
                        self.assertNotIn(path, text)
                        self.assertIn("[REDACTED]", text)
                    self.assertEqual(report["results"], [])
                    self.assertEqual(report["stats"]["total_endpoints"], 0)

    def test_direct_reporter_and_url_sanitizer_accept_known_credentials(self):
        url = "https://api.example.test/" + self.secret
        self.assertNotIn(self.secret, sanitize_url(url, secret_values=["Bearer " + self.secret]))
        output = self.folder / "direct.html"
        SecurityReportGenerator.generate({}, [], url, str(output), secret_values=[self.secret])
        text = output.read_text(encoding="utf-8")
        self.assertNotIn(self.secret, text)
        self.assertIn("[REDACTED]", text)

    def test_known_path_credentials_do_not_disable_generic_path_redaction(self):
        for suffix in ("password=EXTRA_PRIVATE_VALUE", "user@example.com", "%75ser%40example.com"):
            with self.subTest(suffix=suffix):
                result = sanitize_url("https://api.example.test/" + self.secret + "/" + suffix,
                                      secret_values=[self.secret])
                self.assertNotIn(self.secret, result)
                self.assertNotIn("EXTRA_PRIVATE_VALUE", result)
                self.assertNotIn("user%40example.com", result)
                self.assertNotIn("user@example.com", result)
                self.assertIn("REDACTED", result)
