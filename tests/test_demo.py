"""The packaged demo stays local, restores its data and works outside a checkout."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from importlib import resources
from pathlib import Path
from unittest.mock import patch
from urllib.request import ProxyHandler

import api_sentinel
from core import __version__, demo
from core.config_validator import ConfigValidator
from core.models import HTTPResult
from mock_server.server import TargetMockHandler


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def working_directory(directory):
    previous = Path.cwd()
    try:
        os.chdir(directory)
        yield
    finally:
        os.chdir(previous)


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="granttrace-demo-tests-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.servers = []
        original = demo.DemoServer
        owner = self

        class TrackingServer(original):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                owner.servers.append(self)

        self.server_patch = patch.object(demo, "DemoServer", TrackingServer)

    def call_demo(self, output_dir=None, read_only=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with self.server_patch, redirect_stdout(stdout), redirect_stderr(stderr):
            code = demo.run_demo(output_dir=str(output_dir or self.folder), read_only=read_only)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_stopped(self, server):
        self.assertFalse(server.thread.is_alive(), "Demo serving thread survived cleanup")
        self.assertEqual(server.server.socket.fileno(), -1, "Demo listening socket survived cleanup")

    def read_report(self, directory=None):
        reports = list((directory or self.folder).rglob("granttrace_report.json"))
        self.assertEqual(len(reports), 1)
        return reports[0], json.loads(reports[0].read_text(encoding="utf-8"))

    def make_auditor(self, target):
        spec, config, _ = demo.load_assets()
        spec_path = self.folder / "temporary-spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        return demo._LocalDemoAuditor(
            spec_path=str(spec_path), target_base_url=target,
            identities_config=config["identities"],
            parameter_values=config["parameter_values"],
            readback_config=config["readbacks"],
            write_allowlist=config["write_allowlist"],
            bola_config=config["bola"], request_delay=0,
        )

    def test_resources_are_packaged_and_valid_without_credentials(self):
        assets = resources.files("core.demo_assets")
        expected = {"openapi.json", "demo-config.json", "mock-data.json"}
        self.assertTrue(expected.issubset({entry.name for entry in assets.iterdir()}))
        for name in expected:
            self.assertIsInstance(json.loads(assets.joinpath(name).read_text(encoding="utf-8")), dict)
        spec, config, database = demo.load_assets()
        validation = ConfigValidator.validate(config, raw_spec=spec)
        self.assertTrue(validation.is_valid, [item.format() for item in validation.errors])
        self.assertEqual(set(config["identities"]), {"owner", "visitor", "anonymous"})
        for identity in config["identities"].values():
            self.assertFalse(identity.get("token"))
            self.assertFalse({key.lower() for key in identity.get("headers", {})}
                             & {"authorization", "cookie", "x-api-key"})
        self.assertEqual(set(database), {"users", "documents", "articles"})
        manifest = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[tool.setuptools.package-data]", manifest)
        self.assertIn("core.demo_assets", manifest)

    def test_resource_loading_is_independent_of_cwd_and_returns_fresh_data(self):
        expected = demo.load_assets()
        with working_directory(self.folder):
            self.assertEqual(demo.load_assets(), expected)
            spec, config, database = demo.load_assets()
            spec.clear()
            config["identities"]["owner"].clear()
            database["users"].clear()
            self.assertEqual(demo.load_assets(), expected)
            self.assertEqual(list(self.folder.iterdir()), [])

    def test_server_uses_loopback_dynamic_port_and_closes_after_context(self):
        _, _, database = demo.load_assets()
        with demo.DemoServer(database) as server:
            self.assertEqual(server.server.server_address[0], "127.0.0.1")
            self.assertGreater(server.server.server_port, 0)
            self.assertEqual(server.target, f"http://127.0.0.1:{server.server.server_port}")
            self.assertTrue(server.thread.is_alive())
            self.assertTrue(server.handler.requests, "Readiness was not confirmed over HTTP")
        self.assert_stopped(server)
        server.close()
        self.assert_stopped(server)

    def test_separate_servers_do_not_share_or_mutate_repository_mock_data(self):
        _, _, database = demo.load_assets()
        original = copy.deepcopy(TargetMockHandler.DATABASE)
        with demo.DemoServer(database) as first, demo.DemoServer(database) as second:
            self.assertNotEqual(first.server.server_port, second.server.server_port)
            first.handler.DATABASE["users"]["1002"]["role"] = "isolated-test-role"
            self.assertEqual(second.handler.DATABASE, database)
            self.assertEqual(first.handler.INITIAL_DATABASE, database)
            self.assertEqual(TargetMockHandler.DATABASE, original)
        self.assert_stopped(first)
        self.assert_stopped(second)

    def test_server_start_failure_closes_its_socket(self):
        _, _, database = demo.load_assets()
        server = demo.DemoServer(database)
        with patch.object(server.thread, "start", side_effect=RuntimeError("cannot start serving thread")):
            with self.assertRaises(RuntimeError):
                server.__enter__()
        self.assert_stopped(server)
        server.close()

    def test_thread_constructor_failure_closes_the_already_bound_real_socket(self):
        _, _, database = demo.load_assets()
        original = demo.ThreadingHTTPServer
        created = []

        def create_server(*args, **kwargs):
            server = original(*args, **kwargs)
            created.append(server)
            self.addCleanup(server.server_close)
            self.assertGreaterEqual(server.socket.fileno(), 0)
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertGreater(server.server_port, 0)
            return server

        for exception in (RuntimeError("cannot construct thread"), KeyboardInterrupt()):
            with self.subTest(exception=type(exception).__name__), \
                 patch.object(demo, "ThreadingHTTPServer", new=create_server), \
                 patch.object(demo.threading, "Thread", side_effect=exception), \
                 self.assertRaises(type(exception)):
                demo.DemoServer(database)
            self.assertEqual(created[-1].socket.fileno(), -1,
                             "Constructor failure leaked the real bound listening socket")
        self.assertEqual(len(created), 2)

    def test_server_readiness_failure_stops_a_started_thread(self):
        _, _, database = demo.load_assets()
        server = demo.DemoServer(database)
        with patch.object(demo, "build_opener") as factory:
            factory.return_value.open.side_effect = OSError("readiness request failed")
            with self.assertRaises(OSError):
                server.__enter__()
        self.assert_stopped(server)

    def test_full_demo_confirms_identity_comparison_readback_and_rollback(self):
        code, stdout, stderr = self.call_demo()
        self.assertEqual(code, 0, stdout + stderr)
        report_path, report = self.read_report()
        html_path = report_path.with_name("granttrace_report.html")
        self.assertTrue(html_path.is_file())
        self.assertIn(f">v{__version__}</span>", html_path.read_text(encoding="utf-8"))
        self.assertEqual(report["tool_version"], __version__)
        self.assertEqual(report["report_schema_version"], 2)
        self.assertEqual(report["stats"]["bola_confirmed"], 1)
        self.assertEqual(report["stats"]["mass_assignment_confirmed"], 1)
        self.assertEqual(report["stats"]["error_count"], 0)
        self.assertEqual(report["stats"]["inconclusive_count"], 0)
        self.assertEqual({finding["cwe"] for finding in report["findings"]}, {"CWE-639", "CWE-915"})
        self.assertTrue({"PUBLIC", "SECURE", "CONFIRMED"}.issubset(
            {result["verdict"] for result in report["results"]}))
        bola = next(item for item in report["findings"] if item["cwe"] == "CWE-639")
        self.assertEqual(bola["evidence"]["owner"]["status"], 200)
        self.assertEqual(bola["evidence"]["visitor_cross"]["status"], 200)
        self.assertEqual(bola["evidence"]["decision_evidence"]["expected_visitor_access"], "deny")
        mass = next(item for item in report["findings"] if item["cwe"] == "CWE-915")
        evidence = mass["evidence"]
        self.assertTrue(evidence["rollback_verified"])
        self.assertEqual(evidence["readback_consistency"], "strong")
        self.assertNotEqual(evidence["target_url"], evidence["readback_url"])
        self.assertEqual(evidence["after"]["status"], 200)
        self.assertEqual(evidence["restored"]["status"], 200)
        self.assertTrue(report["demo"]["rollback_verified"])
        self.assertTrue(report["demo"]["database_restored"])
        self.assertTrue(report["demo"]["server_stopped"])
        self.assertTrue(report["demo"]["target_bound_to_loopback"])
        self.assertEqual(set(report["demo"]["request_methods"]), {"GET", "PATCH"})
        self.assertEqual(set(report["demo"]["user_agents"]), {f"GrantTrace/{__version__}"})
        self.assertEqual(len(self.servers), 1)
        server = self.servers[0]
        self.assertEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        self.assert_stopped(server)
        for path in (html_path, report_path):
            self.assertIn(str(path.resolve()), stdout)
        requests = server.handler.requests
        writes = [index for index, request in enumerate(requests) if request["method"] == "PATCH"]
        self.assertGreaterEqual(len(writes), 2, "Mutation and real rollback must both reach the mock")
        self.assertTrue(any(request["method"] == "GET" and request["path"].endswith("/profile")
                            for request in requests[writes[0] + 1:writes[1]]),
                        "An independent GET readback must occur between mutation and rollback")

    def test_read_only_demo_never_sends_patch_even_when_write_configuration_exists(self):
        code, stdout, stderr = self.call_demo(read_only=True)
        self.assertEqual(code, 0, stdout + stderr)
        _, report = self.read_report()
        self.assertTrue(report["demo"]["read_only"])
        self.assertIsNone(report["demo"]["rollback_verified"])
        self.assertEqual(report["stats"]["bola_confirmed"], 1)
        self.assertEqual(report["stats"]["mass_assignment_confirmed"], 0)
        self.assertEqual(set(report["demo"]["request_methods"]), {"GET"})
        self.assertTrue(all(item["method"] == "GET" for item in self.servers[0].handler.requests))
        self.assertEqual(self.servers[0].handler.DATABASE, self.servers[0].handler.INITIAL_DATABASE)
        self.assert_stopped(self.servers[0])

    def test_default_output_from_outside_checkout_does_not_need_local_files(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with working_directory(self.folder), self.server_patch, redirect_stdout(stdout), redirect_stderr(stderr):
            code = demo.run_demo(read_only=True)
        self.assertEqual(code, 0, stdout.getvalue() + stderr.getvalue())
        self.assertFalse((self.folder / "openapi.json").exists())
        self.assertFalse((self.folder / "config.example.json").exists())
        report_path, _ = self.read_report(self.folder / "granttrace-demo")
        self.assertTrue(report_path.with_name("granttrace_report.html").is_file())
        self.assertEqual({path.name for path in self.folder.iterdir()}, {"granttrace-demo"})

    def test_repeated_runs_preserve_existing_files_and_reports(self):
        sentinel = self.folder / "granttrace_report.json"
        sentinel.write_text("existing user report", encoding="utf-8")
        for _ in range(2):
            code, stdout, stderr = self.call_demo(read_only=True)
            self.assertEqual(code, 0, stdout + stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing user report")
        reports = [item for item in self.folder.rglob("granttrace_report.json") if item != sentinel]
        self.assertEqual(len(reports), 2)
        self.assertNotEqual(reports[0].parent, reports[1].parent)
        for report in reports:
            self.assertTrue(report.with_name("granttrace_report.html").is_file())

    def test_invalid_output_file_is_not_overwritten(self):
        destination = self.folder / "user-file"
        destination.write_text("preserve this", encoding="utf-8")
        code, _, _ = self.call_demo(output_dir=destination)
        self.assertEqual(code, 2)
        self.assertEqual(destination.read_text(encoding="utf-8"), "preserve this")
        for server in self.servers:
            self.assert_stopped(server)

    def test_demo_cli_refuses_remote_target_and_scan_configuration_options(self):
        rejected = (
            ["--target", "https://external.example.test"],
            ["--spec", "remote.json"], ["--config", "user.json"],
            ["--allow-http"], ["--allow-write-tests"],
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments), patch.object(demo, "run_demo") as runner, \
                 redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                api_sentinel.main(["demo", *arguments])
            self.assertEqual(error.exception.code, 2)
            runner.assert_not_called()

    def test_demo_dispatch_does_not_replace_existing_cli_parser(self):
        with patch.object(demo, "run_demo", return_value=0) as runner:
            self.assertEqual(api_sentinel.main(["demo", "--output-dir", str(self.folder), "--read-only"]), 0)
            self.assertEqual(runner.call_args.kwargs["output_dir"], str(self.folder))
            self.assertTrue(runner.call_args.kwargs["read_only"])
        arguments = api_sentinel.build_argument_parser().parse_args([
            "--spec", "demo", "--target", "https://example.test", "--config", "demo", "--dry-run",
        ])
        self.assertEqual(arguments.spec, "demo")
        self.assertEqual(arguments.config, "demo")
        self.assertTrue(arguments.dry_run)
        with patch.object(demo, "run_demo") as runner, redirect_stdout(io.StringIO()), \
             self.assertRaises(SystemExit) as error:
            api_sentinel.main(["--version"])
        self.assertEqual(error.exception.code, 0)
        runner.assert_not_called()

    def test_existing_spec_cli_dry_run_still_executes_without_demo_dispatch(self):
        spec, config, _ = demo.load_assets()
        spec_path, config_path = self.folder / "spec.json", self.folder / "config.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(demo, "run_demo") as runner, \
             patch.object(api_sentinel.APISentinelAuditor, "_http_request",
                          side_effect=AssertionError("Dry run sent a request")), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = api_sentinel.main([
                "--spec", str(spec_path), "--config", str(config_path),
                "--target", "http://127.0.0.1:1", "--dry-run",
            ])
        self.assertEqual(code, 0, stdout.getvalue() + stderr.getvalue())
        self.assertIn("GET /api/users/{user_id}/profile", stdout.getvalue())
        runner.assert_not_called()

    def test_real_cli_demo_runs_from_an_empty_directory(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "api_sentinel.py"), "demo", "--read-only"],
            cwd=self.folder, capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("GrantTrace Demo", result.stdout)
        _, report = self.read_report(self.folder / "granttrace-demo")
        self.assertEqual(report["tool_version"], __version__)
        self.assertTrue(report["demo"]["server_stopped"])

    def test_scan_exceptions_and_keyboard_interrupt_always_stop_server(self):
        exceptions = (RuntimeError("scan failed"), json.JSONDecodeError("bad response", "{", 1), KeyboardInterrupt())
        for index, exception in enumerate(exceptions):
            with self.subTest(exception=type(exception).__name__), \
                 patch.object(demo._LocalDemoAuditor, "run", side_effect=exception):
                code, stdout, stderr = self.call_demo(output_dir=self.folder / str(index))
            self.assertEqual(code, 130 if isinstance(exception, KeyboardInterrupt) else 2, stdout + stderr)
            self.assert_stopped(self.servers[-1])
            self.assertFalse(list((self.folder / str(index)).rglob("granttrace_report.json")))

    def test_interrupt_after_real_patch_still_restores_data_and_stops_server(self):
        original = demo._LocalDemoAuditor._http_request
        interrupted = False

        def interrupt_after_patch(auditor, method, url, *args, **kwargs):
            nonlocal interrupted
            response = original(auditor, method, url, *args, **kwargs)
            if method == "PATCH" and not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            return response

        with patch.object(demo._LocalDemoAuditor, "_http_request", new=interrupt_after_patch):
            code, stdout, stderr = self.call_demo()
        self.assertEqual(code, 130, stdout + stderr)
        self.assertTrue(interrupted)
        server = self.servers[0]
        self.assertEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        self.assertGreaterEqual(sum(item["method"] == "PATCH" for item in server.handler.requests), 2)
        self.assert_stopped(server)

    def test_bad_packaged_json_does_not_start_server(self):
        with patch.object(demo, "load_assets", side_effect=json.JSONDecodeError("bad resource", "{", 1)):
            code, _, _ = self.call_demo()
        self.assertEqual(code, 2)
        self.assertEqual(self.servers, [])

    def test_failed_independent_readback_aborts_demo_but_real_rollback_restores_data(self):
        original = demo._LocalDemoAuditor._http_request
        patch_count = 0
        failed_readback = False

        def fail_mutation_readbacks(auditor, method, url, *args, **kwargs):
            nonlocal patch_count, failed_readback
            if method == "GET" and patch_count == 1 and url.endswith("/profile"):
                failed_readback = True
                return HTTPResult(0, "", error="Independent readback unavailable")
            response = original(auditor, method, url, *args, **kwargs)
            if method == "PATCH":
                patch_count += 1
            return response

        with patch.object(demo._LocalDemoAuditor, "_http_request", new=fail_mutation_readbacks):
            code, _, _ = self.call_demo()
        self.assertEqual(code, 2)
        self.assertTrue(failed_readback)
        server = self.servers[0]
        self.assertEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        self.assert_stopped(server)
        self.assertFalse(list(self.folder.rglob("granttrace_report.json")))

    def test_missing_rollback_verification_cannot_produce_a_success_report(self):
        original = demo._LocalDemoAuditor.run

        def remove_verification(auditor):
            original(auditor)
            for result in auditor.results:
                if result["check"] == "MASS_ASSIGNMENT":
                    result["evidence"].pop("rollback_verified", None)

        with patch.object(demo._LocalDemoAuditor, "run", new=remove_verification):
            code, _, _ = self.call_demo()
        self.assertEqual(code, 2)
        server = self.servers[0]
        self.assertEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        self.assert_stopped(server)
        self.assertFalse(list(self.folder.rglob("granttrace_report.json")))

    def test_changed_database_is_reported_as_failure_and_not_reset_during_shutdown(self):
        original = demo._LocalDemoAuditor.run

        def corrupt_after_scan(auditor):
            original(auditor)
            self.servers[-1].handler.DATABASE["users"]["1002"]["unexpected_change"] = True

        with patch.object(demo._LocalDemoAuditor, "run", new=corrupt_after_scan):
            code, _, _ = self.call_demo()
        self.assertEqual(code, 2)
        server = self.servers[0]
        self.assertNotEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        self.assert_stopped(server)
        self.assertFalse(list(self.folder.rglob("granttrace_report.json")))

    def test_html_report_failure_still_stops_server_after_rollback(self):
        with patch.object(demo.SecurityReportGenerator, "generate", side_effect=OSError("cannot write HTML")):
            code, _, _ = self.call_demo()
        self.assertEqual(code, 2)
        server = self.servers[0]
        self.assertEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        self.assert_stopped(server)

    def test_json_report_failure_does_not_leave_server_running(self):
        original = Path.write_text

        def fail_json(path, *args, **kwargs):
            if path.name == "granttrace_report.json":
                raise OSError("cannot write JSON report")
            return original(path, *args, **kwargs)

        with patch.object(Path, "write_text", new=fail_json):
            code, _, _ = self.call_demo()
        self.assertEqual(code, 2)
        server = self.servers[0]
        self.assertEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        self.assert_stopped(server)

    def test_local_auditor_never_sends_other_origins_or_post_put(self):
        _, _, database = demo.load_assets()
        with demo.DemoServer(database) as server:
            auditor = self.make_auditor(server.target)
            with patch.object(auditor._opener, "open") as network:
                for method, url in (
                    ("GET", "https://external.example.test/api"),
                    ("PATCH", "http://127.0.0.1:1/api"),
                    ("GET", server.target.replace("127.0.0.1", "localhost") + "/api"),
                    ("POST", server.target + "/api"), ("PUT", server.target + "/api"),
                ):
                    with self.subTest(method=method, url=url):
                        try:
                            response = auditor._http_request(method, url)
                        except ValueError:
                            pass
                        else:
                            self.assertEqual(response.status, 0)
                            self.assertTrue(response.error)
                network.assert_not_called()
        self.assert_stopped(server)

    def test_local_auditor_disables_environment_proxies(self):
        proxies = {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
                   "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": "", "no_proxy": ""}
        with patch.dict(os.environ, proxies):
            code, stdout, stderr = self.call_demo(read_only=True)
        self.assertEqual(code, 0, stdout + stderr)
        _, _, database = demo.load_assets()
        with demo.DemoServer(database) as server:
            auditor = self.make_auditor(server.target)
            self.assertFalse(any(isinstance(handler, ProxyHandler) and handler.proxies
                                 for handler in auditor._opener.handlers))

    def test_local_auditor_does_not_follow_redirect_to_another_server(self):
        _, _, database = demo.load_assets()
        with demo.DemoServer(database) as first, demo.DemoServer(database) as second:
            auditor = self.make_auditor(first.target)
            before = len(second.handler.requests)

            def redirect(handler):
                handler.send_response(302)
                handler.send_header("Location", second.target + "/api/public/articles/101")
                handler.send_header("Content-Length", "0")
                handler.end_headers()

            with patch.object(first.handler, "do_GET", new=redirect):
                response = auditor._http_request("GET", first.target + "/redirect")
            self.assertEqual(response.status, 302)
            self.assertEqual(len(second.handler.requests), before)
        self.assert_stopped(first)
        self.assert_stopped(second)


if __name__ == "__main__":
    unittest.main()
