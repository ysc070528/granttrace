"""A real scan of a non-loopback target needs configured identities.

Without identities the auditor falls back to its built-in mock identities:
placeholder credentials and resource IDs meant only for the bundled mock
server. The CLI refuses such a scan before any network activity. Loopback
scans keep working with a warning; offline modes, the demo and configured
scans are unchanged.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import List, Sequence, Tuple
from unittest.mock import patch

import api_sentinel
from core.auditor import APISentinelAuditor
from core.scan_safety import is_loopback_target
from mock_server.server import TargetMockHandler

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "openapi.json"
CONFIGURED = ROOT / "config.example.json"
MOCK_PLACEHOLDERS = ("TOKEN_ALICE_OWNER_1001", "TOKEN_BOB_VISITOR_1002")
REFUSAL = "Refusing to scan a non-loopback target without configured identities"
WARNING = "built-in MOCK identities"


class LoopbackTargetTests(unittest.TestCase):
    def test_accepts_only_unambiguous_loopback_targets(self):
        for target in (
            "http://127.0.0.1:8080", "http://127.0.0.1", "https://127.0.0.1/api/", "http://127.8.9.10:1",
            "http://localhost:8080", "http://LOCALHOST:8080/base", "http://[::1]:8080", "https://[::1]",
            "http://[::ffff:127.0.0.1]:80",
        ):
            with self.subTest(target=target):
                self.assertTrue(is_loopback_target(target))

    def test_look_alike_and_ambiguous_targets_count_as_remote(self):
        for target in (
            # Remote and private hosts.
            "https://api.example.test", "http://10.0.0.1", "http://192.168.1.10:8080", "http://0.0.0.0",
            "http://[::ffff:8.8.8.8]", "http://[2001:db8::1]",
            # Names that merely start or end like a loopback host.
            "http://localhost.evil.com", "http://localhost.evil.com:8080", "http://127.0.0.1.nip.io",
            "http://localhost.", "http://evil-localhost", "http://mylocalhost",
            # User information and parser differentials.
            "http://localhost@evil.com", "http://127.0.0.1@evil.com", "http://user:pass@127.0.0.1",
            "http://evil.com#@localhost", "http://evil.com?@localhost", "http://evil.com\\@127.0.0.1",
            "http://localhost\t.evil.com", "http://local host", " http://127.0.0.1", "http://127.0.0.1\n",
            # Alternative IPv4 spellings, zone indexes and non-ASCII digits or letters.
            "http://2130706433", "http://0x7f000001", "http://0177.0.0.1", "http://127.1",
            "http://[::1%25lo]", "http://[fe80::1%25lo]",
            "http://ｌｏｃａｌｈｏｓｔ", "http://１２７.0.0.1",
            # Not an http(s) URL with a valid host and port.
            "ftp://127.0.0.1", "127.0.0.1:8080", "http://", "", "http://127.0.0.1:99999", "http://127.0.0.1:port",
        ):
            with self.subTest(target=target):
                self.assertFalse(is_loopback_target(target))

    def test_non_string_input_is_remote(self):
        for value in (None, b"http://127.0.0.1", 127001):
            with self.subTest(value=value):
                self.assertFalse(is_loopback_target(value))  # type: ignore[arg-type]


class CliIdentityGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-identity-guard-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.html = self.folder / "report.html"
        self.exported = self.folder / "report.json"

    def write_config(self, name: str, content: object) -> Path:
        path = self.folder / name
        path.write_text(json.dumps(content), encoding="utf-8")
        return path

    def call_cli(self, arguments: Sequence[str]) -> Tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = api_sentinel.main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    @contextlib.contextmanager
    def no_network(self):
        failure = AssertionError("network opened")
        with patch("socket.socket", side_effect=failure) as sockets, \
                patch("socket.create_connection", side_effect=failure) as connections, \
                patch("urllib.request.OpenerDirector.open", side_effect=failure) as opener:
            yield
        sockets.assert_not_called()
        connections.assert_not_called()
        opener.assert_not_called()

    def assert_no_mock_placeholders(self, *texts: str) -> None:
        for text in texts:
            for marker in MOCK_PLACEHOLDERS:
                self.assertNotIn(marker, text)

    def test_remote_scan_without_identities_is_refused_before_any_request(self):
        path_marker = "SYNTHETIC_TARGET_PATH_Q7"
        empty = self.write_config("empty.json", {})
        no_identities = self.write_config("no-identities.json", {"identities": {}})
        cases = {
            "no --config": [],
            "config without identities": ["--config", str(empty)],
            "empty identities": ["--config", str(no_identities)],
            "write endpoint without config": ["--allow-write-tests",
                                              "--write-endpoint", "PATCH /api/users/{user_id}/settings"],
        }
        targets = (
            ["--target", "https://api.example.test/" + path_marker],
            ["--target", "http://localhost.evil.com:8080/" + path_marker, "--allow-http"],
            ["--target", "http://127.0.0.1.nip.io/" + path_marker, "--allow-http"],
            ["--target", "http://10.0.0.5:8080/" + path_marker, "--allow-http"],
        )
        for name, extra in cases.items():
            for target in targets:
                with self.subTest(case=name, target=target[1]), self.no_network(), \
                        patch.object(api_sentinel, "APISentinelAuditor",
                                     side_effect=AssertionError("auditor created")) as auditor:
                    code, stdout, stderr = self.call_cli([
                        "--spec", str(SPEC), *target, *extra, "--delay", "0",
                        "--output", str(self.html), "--export-json", str(self.exported),
                    ])
                self.assertEqual(code, 2, stdout + stderr)
                auditor.assert_not_called()
                self.assertIn(REFUSAL, stderr)
                self.assertIn("No requests were sent", stderr)
                for step in ("--init-config", "--validate-config", "--dry-run"):
                    self.assertIn(step, stderr)
                self.assertNotIn(path_marker, stdout + stderr)
                self.assert_no_mock_placeholders(stdout, stderr)
                self.assertFalse(self.html.exists())
                self.assertFalse(self.exported.exists())

    def test_refusal_happens_for_any_scan_options(self):
        for extra in (["--fail-on-error"], ["--fail-on-vuln"], ["--insecure"], ["--workers", "1"],
                      ["--export-sarif", str(self.folder / "report.sarif")]):
            with self.subTest(options=extra), self.no_network():
                code, _, stderr = self.call_cli(["--spec", str(SPEC), "--target", "https://api.example.test",
                                                 "--output", str(self.html), *extra])
            self.assertEqual(code, 2)
            self.assertIn(REFUSAL, stderr)
            self.assertFalse(self.html.exists())

    def test_loopback_scan_without_identities_runs_with_mock_identity_warning(self):
        TargetMockHandler.reset_database()
        server = ThreadingHTTPServer(("127.0.0.1", 0), TargetMockHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            code, stdout, stderr = self.call_cli([
                "--spec", str(SPEC), "--target", f"http://127.0.0.1:{server.server_port}", "--delay", "0",
                "--output", str(self.html), "--export-json", str(self.exported),
            ])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(code, 0, stdout + stderr)
        self.assertIn("[WARNING]", stderr)
        self.assertIn(WARNING, stderr)
        self.assertIn("--init-config", stderr)
        self.assertNotIn(REFUSAL, stderr)
        self.assert_no_mock_placeholders(stdout, stderr)
        self.assertIn(f"Scan target: http://127.0.0.1:{server.server_port}", stdout)
        report = json.loads(self.exported.read_text(encoding="utf-8"))
        self.assertGreater(report["stats"]["http_requests_sent"], 0)
        self.assertTrue(self.html.is_file())

    def test_other_loopback_spellings_are_not_refused(self):
        calls: List[str] = []
        for target in ("http://localhost:8080", "http://[::1]:8080", "http://127.0.0.2:8080"):
            with self.subTest(target=target), self.no_network(), \
                    patch.object(APISentinelAuditor, "run", autospec=True,
                                 side_effect=lambda auditor: calls.append(auditor.target_base_url)):
                code, stdout, stderr = self.call_cli(["--spec", str(SPEC), "--target", target,
                                                      "--output", str(self.html)])
            self.assertEqual(code, 0, stdout + stderr)
            self.assertIn(WARNING, stderr)
            self.assertNotIn(REFUSAL, stderr)
        self.assertEqual(len(calls), 3)

    def test_configured_remote_scan_is_unchanged_and_shows_a_sanitized_target(self):
        # Public, fixed synthetic data: never loaded from an account, environment
        # or credential store. It exercises auth-derived redaction of the target.
        example_marker = "SYNTHETIC_VISITOR_MARKER_K3"
        config = self.write_config("configured.json", {"identities": {
            "owner": {"id": "1001", "token": "Bearer SYNTHETIC_OWNER_MARKER"},
            "visitor": {"id": "1002", "token": "Bearer " + example_marker},
            "anonymous": {},
        }})
        calls: List[str] = []
        for arguments in (["--config", str(CONFIGURED), "--target", "https://api.example.test"],
                          ["--config", str(config), "--target", "https://api.example.test/" + example_marker]):
            with self.subTest(arguments=arguments), self.no_network(), \
                    patch.object(APISentinelAuditor, "run", autospec=True,
                                 side_effect=lambda auditor: calls.append(auditor.target_base_url)):
                code, stdout, stderr = self.call_cli(["--spec", str(SPEC), *arguments,
                                                      "--output", str(self.html)])
            self.assertEqual(code, 0, stdout + stderr)
            self.assertNotIn(REFUSAL, stderr)
            self.assertNotIn(WARNING, stderr)
            self.assertIn("Scan target: https://api.example.test", stdout)
            self.assertNotIn(example_marker, stdout + stderr)
            self.assertTrue(self.html.is_file())
        self.assertEqual(calls, ["https://api.example.test", "https://api.example.test/" + example_marker])

    def test_dry_run_without_identities_stays_offline_and_points_to_init_config(self):
        for target in ("https://api.example.test", "http://127.0.0.1:8080"):
            with self.subTest(target=target), self.no_network():
                code, stdout, stderr = self.call_cli(["--spec", str(SPEC), "--target", target, "--dry-run",
                                                      "--export-json", str(self.exported)])
            self.assertEqual(code, 0, stdout + stderr)
            self.assertEqual(json.loads(self.exported.read_text(encoding="utf-8"))["requests_sent"], 0)
            self.assertNotIn(REFUSAL, stderr)
            self.assertIn(WARNING, stderr)
            self.assertIn("--init-config", stderr)
            self.assertNotIn("Recommended first real scan", stderr)
            self.assert_no_mock_placeholders(stdout, stderr)

    def test_configured_dry_run_still_recommends_the_first_scan(self):
        with self.no_network():
            code, stdout, stderr = self.call_cli(["--spec", str(SPEC), "--config", str(CONFIGURED),
                                                  "--target", "https://api.example.test", "--dry-run"])
        self.assertEqual(code, 0, stdout + stderr)
        self.assertIn("Recommended first real scan", stderr)
        self.assertNotIn(WARNING, stderr)

    def test_init_and_validate_config_are_unaffected_for_remote_targets(self):
        draft = self.folder / "draft.json"
        empty = self.write_config("empty.json", {})
        with self.no_network():
            init_code, _, init_err = self.call_cli(["--spec", str(SPEC), "--target", "https://api.example.test",
                                                    "--init-config", str(draft)])
            validate_code, _, validate_err = self.call_cli(["--spec", str(SPEC), "--config", str(empty),
                                                            "--target", "https://api.example.test",
                                                            "--validate-config"])
        self.assertEqual(init_code, 0, init_err)
        self.assertTrue(draft.is_file())
        self.assertEqual(validate_code, 0, validate_err)
        for stderr in (init_err, validate_err):
            self.assertNotIn(REFUSAL, stderr)
            self.assertNotIn(WARNING, stderr)

    def test_demo_is_dispatched_before_the_guard(self):
        code, stdout, stderr = self.call_cli(["demo", "--output-dir", str(self.folder)])
        self.assertEqual(code, 0, stdout + stderr)
        for line in ("BOLA / IDOR: 1 confirmed", "Mass Assignment: 1 confirmed", "Rollback verified: yes",
                     "Mock database restored: yes", "Local server stopped: yes"):
            self.assertIn(line, stdout)
        self.assertNotIn(REFUSAL, stdout + stderr)
        self.assertNotIn(WARNING, stdout + stderr)


class CliDescriptionTests(unittest.TestCase):
    def test_help_describes_the_actual_scope(self):
        text = " ".join(api_sentinel.build_argument_parser().format_help().split())
        self.assertIn("read-only authorization auditing for OpenAPI APIs", text)
        self.assertNotIn("mass-assignment auditor", text)
        self.assertNotIn("Enable allowlisted PATCH", text)
        self.assertIn("Only the built-in demo can verify state and rollback", text)
        self.assertIn("against --target these checks stop before any write", text)
        self.assertIn("No write is sent to --target", text)
        self.assertIn("default: http://127.0.0.1:8080, the bundled mock server", text)
        self.assertIn("refused unless the configuration defines identities", text)


if __name__ == "__main__":
    unittest.main()
