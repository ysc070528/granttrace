import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from api_sentinel import build_argument_parser
from core.auditor import APISentinelAuditor
from core.models import HTTPResult
from core.reporter import SecurityReportGenerator
from mock_server.server import TargetMockHandler


ROOT = Path(__file__).resolve().parents[1]


class AuditorIntegrationTests(unittest.TestCase):
    def setUp(self):
        TargetMockHandler.reset_database()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), TargetMockHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.target = f"http://127.0.0.1:{self.server.server_port}"
        with (ROOT / "config.example.json").open("r", encoding="utf-8") as handle:
            self.config = json.load(handle)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        TargetMockHandler.reset_database()

    def make_auditor(self, allow_write_tests=False):
        return APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url=self.target,
            max_workers=3,
            request_delay=0,
            identities_config=self.config["identities"],
            parameter_values=self.config["parameter_values"],
            readback_config=self.config["readbacks"],
            allow_write_tests=allow_write_tests,
            write_allowlist=self.config["write_allowlist"],
        )

    def test_default_mode_is_read_only_and_reports_skips(self):
        auditor = self.make_auditor(allow_write_tests=False)
        auditor.run()

        self.assertEqual(auditor.stats["bola_confirmed"], 1)
        self.assertEqual(auditor.stats["mass_assignment_confirmed"], 0)
        self.assertEqual(auditor.stats["skipped_count"], 2)
        self.assertEqual(TargetMockHandler.DATABASE["users"]["1002"]["role"], "user")
        self.assertTrue(any(item["verdict"] == "PUBLIC" for item in auditor.results))
        self.assertTrue(any(item["verdict"] == "SECURE" for item in auditor.results))
        document_result = next(
            item for item in auditor.results if item["endpoint"] == "GET /api/documents/{doc_uuid}"
        )
        self.assertEqual(document_result["verdict"], "SECURE")
        self.assertNotEqual(
            document_result["evidence"]["target_url"],
            document_result["evidence"]["visitor_self_url"],
        )

    def test_active_mode_confirms_then_rolls_back(self):
        auditor = self.make_auditor(allow_write_tests=True)
        auditor.run()

        self.assertEqual(auditor.stats["bola_confirmed"], 1)
        self.assertEqual(auditor.stats["mass_assignment_confirmed"], 1)
        self.assertEqual(auditor.stats["raw_filtered_count"], 1)
        self.assertEqual(auditor.stats["error_count"], 0)
        self.assertEqual(TargetMockHandler.DATABASE["users"]["1002"]["role"], "user")
        mass = [item for item in auditor.findings if item["cwe"] == "CWE-915"]
        self.assertEqual(len(mass), 1)
        self.assertTrue(mass[0]["evidence"]["rollback_verified"])
        write_results = [item for item in auditor.results if item["check"] == "MASS_ASSIGNMENT"]
        self.assertEqual(len(write_results), 2)
        for result in write_results:
            self.assertIn("/api/users/1002/", result["evidence"]["target_url"])
            self.assertTrue(result["evidence"]["rollback_verified"])
        safe_write = next(item for item in write_results if item["verdict"] == "SECURE")
        self.assertFalse(safe_write["evidence"]["cases"][0]["persisted"])

    def test_sensitive_evidence_is_redacted(self):
        auditor = self.make_auditor(allow_write_tests=False)
        auditor.run()
        serialized = json.dumps(auditor.findings, ensure_ascii=False)
        self.assertNotIn("25,000 USD", serialized)
        self.assertNotIn("Alice", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_cli_tls_verification_is_enabled_by_default(self):
        args = build_argument_parser().parse_args([])
        self.assertFalse(args.insecure)
        self.assertFalse(args.allow_write_tests)

    def test_active_mode_without_allowlist_sends_no_writes(self):
        auditor = APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url=self.target,
            max_workers=2,
            request_delay=0,
            identities_config=self.config["identities"],
            parameter_values=self.config["parameter_values"],
            readback_config=self.config["readbacks"],
            allow_write_tests=True,
        )
        auditor.run()

        self.assertEqual(auditor.stats["mass_assignment_confirmed"], 0)
        self.assertEqual(TargetMockHandler.DATABASE["users"]["1002"]["role"], "user")
        write_results = [item for item in auditor.results if item["check"] == "MASS_ASSIGNMENT"]
        self.assertTrue(write_results)
        self.assertTrue(all(item["verdict"] == "SKIPPED" for item in write_results))

    def test_generated_valid_baseline_is_kept_in_mutation_case(self):
        auditor = self.make_auditor(allow_write_tests=False)
        schema = {
            "type": "object",
            "required": ["display_name"],
            "properties": {
                "display_name": {"type": "string", "minLength": 3},
                "role": {"type": "string"},
            },
        }
        role_case = next(
            item for item in auditor._normalise_mutation_cases(schema) if item["field_path"] == "role"
        )
        self.assertIn("display_name", role_case["payload"])
        self.assertEqual(role_case["payload"]["role"], "admin")


class UnreachableTargetTests(unittest.TestCase):
    def test_non_loopback_plain_http_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            APISentinelAuditor(
                spec_path=str(ROOT / "openapi.json"),
                target_base_url="http://example.invalid",
            )

    def test_target_rejects_query_or_fragment(self):
        for target in ("https://example.invalid?token=secret", "https://example.invalid/#private"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                APISentinelAuditor(
                    spec_path=str(ROOT / "openapi.json"),
                    target_base_url=target,
                )

    def test_identity_roles_require_distinct_credentials_and_true_anonymous(self):
        duplicate = {
            "owner": {"id": "1", "token": "Bearer SAME"},
            "visitor": {"id": "2", "token": "Bearer SAME"},
            "anonymous": {"id": None, "token": None},
        }
        with self.assertRaises(ValueError):
            APISentinelAuditor(
                spec_path=str(ROOT / "openapi.json"),
                target_base_url="http://127.0.0.1:8080",
                identities_config=duplicate,
            )

        authenticated_anon = {
            "owner": {"id": "1", "token": "Bearer OWNER"},
            "visitor": {"id": "2", "token": "Bearer VISITOR"},
            "anonymous": {"id": None, "token": "Bearer NOT_ANONYMOUS"},
        }
        with self.assertRaises(ValueError):
            APISentinelAuditor(
                spec_path=str(ROOT / "openapi.json"),
                target_base_url="http://127.0.0.1:8080",
                identities_config=authenticated_anon,
            )

    def test_transport_failure_is_error_not_secure(self):
        auditor = APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url="http://127.0.0.1:1",
            max_workers=2,
            request_delay=0,
            request_timeout=0.2,
        )
        auditor.run()
        self.assertGreater(auditor.stats["error_count"], 0)
        self.assertEqual(auditor.stats["secure_endpoints"], 0)


class RollbackSafetyTests(unittest.TestCase):
    def test_invalid_post_write_readback_still_restores_original_value(self):
        operation = "PATCH /api/users/{user_id}/settings"
        auditor = APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url="http://127.0.0.1:8080",
            request_delay=0,
            allow_write_tests=True,
            write_allowlist=[operation],
            readback_config={
                operation: {
                    "method": "GET",
                    "path": "/api/users/{user_id}/profile",
                    "field_map": {"role": "role"},
                    "readback_attempts": 1,
                }
            },
        )
        endpoint = next(
            item for item in auditor.parser.get_endpoints() if auditor._operation_key(item) == operation
        )
        readbacks = [
            ("readback", HTTPResult(200, '{"role":"user"}')),
            ("readback", HTTPResult(200, "not-json")),
            ("readback", HTTPResult(200, '{"role":"user"}')),
        ]
        writes = []

        def fake_write(method, url, data=None, identity_name="anonymous"):
            writes.append(data)
            return HTTPResult(200, '{"ok":true}')

        with patch.object(auditor, "_readback_result", side_effect=readbacks), patch.object(
            auditor, "_http_request", side_effect=fake_write
        ):
            auditor.audit_endpoint_mass_assignment(endpoint, auditor.parser.get_endpoints())

        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[0]["role"], "admin")
        self.assertEqual(writes[1]["role"], "user")
        self.assertEqual(auditor.stats["error_count"], 0)
        self.assertEqual(auditor.results[-1]["verdict"], "INCONCLUSIVE")


class ReportTests(unittest.TestCase):
    def test_report_escapes_dynamic_content_and_shows_errors(self):
        stats = {
            "total_endpoints": 1,
            "confirmed": 0,
            "error_count": 1,
            "inconclusive_count": 0,
            "skipped_count": 0,
            "coverage_pct": 100.0,
            "conclusive_coverage_pct": 0.0,
        }
        results = [
            {
                "verdict": "ERROR",
                "check": "BOLA",
                "endpoint": "GET /<script>alert(1)</script>",
                "reason": "network <failure>",
            }
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.html"
            SecurityReportGenerator.generate(
                stats,
                [],
                "https://example.invalid/<script>",
                str(output),
                results=results,
            )
            rendered = output.read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertIn("不能把未完成的检查解释为安全", rendered)


if __name__ == "__main__":
    unittest.main()

