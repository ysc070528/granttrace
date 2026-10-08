"""Read-only semantic preflight and zero-request regression coverage."""

import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.parameters import ParameterSerializationError
from core.scan_safety import read_only_risk


class StaticReadOnlySafetyTests(unittest.TestCase):
    def test_explicit_actions_are_identified_without_target_specific_rules(self):
        cases = [
            ({"operation_id": "create_service_report"}, "operation_id"),
            ({"operation_id": "convertVideo"}, "operation_id"),
            ({"path": "/videos/convert_video"}, "path"),
            ({"summary": "Creates and assigns a service report"}, "summary"),
            ({"description": "This endpoint creates a report and assigns it to a mechanic."}, "description"),
            ({"description": "Returns the report and updates its delivery state."}, "description"),
            ({"description": "This operation may trigger video conversion."}, "description"),
            ({"description": "Creating a service report"}, "description"),
            ({"description": "Deleting a report"}, "description"),
            ({"description": "Updating the object"}, "description"),
            ({"description": "This endpoint is used to create a report."}, "description"),
            ({"description": "This GET creates a report."}, "description"),
            ({"description": "The GET endpoint is updating the report."}, "description"),
        ]
        for metadata, signal in cases:
            with self.subTest(metadata=metadata):
                risk = read_only_risk({"method": "GET", "path": "/records/{id}", **metadata})
                self.assertIsNotNone(risk)
                self.assertEqual(risk["safety_signal"], signal)

    def test_ordinary_queries_and_historical_mutation_mentions_remain_eligible(self):
        for metadata in [
            {"operation_id": "getConversionStatus"},
            {"path": "/reports/created/{id}"},
            {"path": "/records/{create_report}"},
            {"summary": "Get the created report"},
            {"description": "Returns reports created by POST /reports."},
            {"description": "This endpoint does not create, update or delete records."},
            {"description": "This GET does not create a report."},
            {"description": "This endpoint is not used to create a report."},
            {"description": "Returns existing documents and does not delete them."},
            {"description": "This endpoint is used to retrieve a previously created report."},
            {"description": "To create a report, use POST /reports. This GET returns existing reports."},
            {"description": "Retrieve the report. Updates are available using PATCH /reports."},
        ]:
            with self.subTest(metadata=metadata):
                self.assertIsNone(read_only_risk({"method": "GET", "path": "/records/{id}", **metadata}))

    def test_read_summary_cannot_override_explicit_action_metadata(self):
        self.assertIsNotNone(read_only_risk({"method": "GET", "path": "/reports/create_report",
                                           "summary": "Retrieve a report"}))

    def test_static_rules_do_not_claim_to_identify_undocumented_effects(self):
        # A handler named "lookup" may write in its implementation. The rule
        # cannot infer an undisclosed effect from neutral operation metadata.
        self.assertIsNone(read_only_risk({"method": "GET", "path": "/lookup/{id}",
                                          "description": "Return a record"}))

    def test_specification_content_is_not_echoed_in_safety_reason(self):
        risk = read_only_risk({"method": "GET", "path": "/records/{id}",
                               "description": "Create secret-example-token record"})
        self.assertNotIn("secret-example-token", json.dumps(risk))


class ReadOnlyExecutionTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        recorded = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                recorded.append((self.command, self.path))
                auth = self.headers.get("Authorization", "")
                resource_id = self.path.rsplit("/", 1)[-1]
                if not auth:
                    status, body = 401, {"message": "JWT Token required!"}
                elif "BOB" in auth and resource_id == "1001":
                    status, body = 403, {"message": "Insufficient permission"}
                else:
                    status, body = 200, {"id": resource_id, "owner_id": resource_id, "value": "private record"}
                payload = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.target = f"http://127.0.0.1:{self.server.server_port}"
        self.temp = tempfile.TemporaryDirectory()
        self.spec_path = Path(self.temp.name) / "spec.json"
        selector = {"name": "report_id", "in": "query", "schema": {"type": "integer", "default": 1}}
        self.spec = {"openapi": "3.0.3", "paths": {
            "/workshop/api/mechanic/receive_report": {"get": {
                "operationId": "create_service_report", "description": "Creates and assigns a service report",
                "parameters": [selector]}},
            "/identity/api/v2/user/videos/convert_video": {"get": {"parameters": [selector]}},
            "/records/{user_id}": {"get": {"summary": "Retrieve an existing record"}},
            "/settings/{user_id}": {"patch": {"requestBody": {"content": {"application/json": {"schema": {
                "type": "object", "properties": {"role": {"type": "string", "readOnly": True,
                                                           "enum": ["user", "admin"]}}}}}}}},
        }}
        self.write_spec()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def write_spec(self):
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")

    def auditor(self, **kwargs):
        return APISentinelAuditor(str(self.spec_path), self.target, request_delay=0, **kwargs)

    def test_parser_preserves_description_for_semantic_checks(self):
        ep = self.auditor().parser.get_endpoints()[0]
        self.assertEqual(ep["description"], "Creates and assigns a service report")

    def test_known_unsafe_gets_are_skipped_and_ordinary_get_executes(self):
        auditor = self.auditor()
        with contextlib.redirect_stdout(io.StringIO()):
            auditor.run()
        skips = [item for item in auditor.results if item["endpoint"].startswith("GET /")
                 and item["verdict"] == "SKIPPED"]
        self.assertEqual(len(skips), 2)
        for result in skips:
            self.assertEqual(result["evidence"]["reason_category"], "safety_policy")
            self.assertEqual(result["evidence"]["requests_attempted"], 0)
        self.assertEqual(len(self.requests), 4)
        self.assertTrue(all(path.startswith("/records/") for _, path in self.requests))

    def test_write_opt_in_does_not_bypass_get_safety(self):
        auditor = self.auditor(allow_write_tests=True)
        for ep in auditor.parser.get_endpoints()[:2]:
            auditor.audit_endpoint_bola(ep)
        self.assertEqual(self.requests, [])
        self.assertTrue(all(item["verdict"] == "SKIPPED" for item in auditor.results))

    def test_description_alone_blocks_opaque_get_before_object_selector_check(self):
        self.spec["paths"]["/opaque"] = {"get": {"description": "This endpoint creates a report."}}
        self.write_spec()
        auditor = self.auditor()
        ep = next(ep for ep in auditor.parser.get_endpoints() if ep["path"] == "/opaque")
        auditor.audit_endpoint_bola(ep)
        self.assertEqual(auditor.results[0]["evidence"]["safety_signal"], "description")
        self.assertEqual(self.requests, [])

    def test_direct_request_executor_cannot_bypass_semantic_preflight(self):
        auditor = self.auditor()
        for method in ("GET", "HEAD"):
            for path in ("/workshop/api/mechanic/receive_report", "/identity/api/v2/user/videos/convert_video",
                         "/undocumented/create_report"):
                result = auditor._http_request(method, self.target + path, identity_name="owner")
                self.assertEqual(result.status, 0)
                self.assertIn("safety policy", result.error)
        self.assertEqual(self.requests, [])

    def test_action_like_resource_id_is_not_an_endpoint_action(self):
        auditor = self.auditor()
        result = auditor._http_request("GET", self.target + "/records/create_report", identity_name="owner")
        self.assertEqual(result.status, 200)
        self.assertEqual(self.requests, [("GET", "/records/create_report")])

    def test_encoded_unsafe_static_route_is_not_hidden_by_a_neutral_template(self):
        self.spec["paths"].update({
            "/opaque/{id}": {"get": {"operationId": "getRecord"}},
            "/opaque/create_report": {"get": {"operationId": "createReport"}},
        })
        self.write_spec()
        auditor = self.auditor()
        with patch.object(auditor._opener, "open", side_effect=AssertionError("network forbidden")) as opener:
            result = auditor._http_request("GET", self.target + "/opaque/%63reate_report", identity_name="owner")
        opener.assert_not_called()
        self.assertEqual(result.status, 0)
        self.assertIn("safety policy", result.error)
        self.assertEqual(self.requests, [])

    def test_renamed_unsafe_readback_template_keeps_declared_semantics(self):
        self.spec["paths"]["/opaque/{id}"] = {"get": {"operationId": "createReport"}}
        self.write_spec()
        mapping = {"method": "GET", "path": "/opaque/{other_id}", "field_map": {"role": "role"}}
        auditor = self.auditor(allow_write_tests=True, write_allowlist=["PATCH /settings/{user_id}"],
                               readback_config={"PATCH /settings/{user_id}": mapping})
        ep = next(ep for ep in auditor.parser.get_endpoints() if ep["method"] == "PATCH")
        entry = next(item for item in auditor.build_plan()["operations"] if item["check"] == "MASS_ASSIGNMENT")
        self.assertFalse(entry["writes_enabled"])
        self.assertTrue(entry["safety_blocked"])
        with patch.object(auditor, "_http_request") as transport:
            auditor.audit_endpoint_mass_assignment(ep, auditor.parser.get_endpoints())
        transport.assert_not_called()
        self.assertEqual(auditor.results[0]["verdict"], "SKIPPED")
        self.assertEqual(auditor.results[0]["evidence"]["safety_signal"], "operation_id")
        self.assertEqual(self.requests, [])

    def test_safe_renamed_readback_keeps_existing_parameter_fallback(self):
        self.spec["paths"]["/opaque/{id}"] = {"get": {"operationId": "getRecord", "parameters": [
            {"name": "id", "in": "path", "schema": {"type": "string"}}]}}
        self.write_spec()
        auditor = self.auditor()
        ep = {"method": "PATCH", "path": "/settings/{other_id}", "parameters": [
            {"name": "other_id", "in": "path", "schema": {"type": "string"}}]}
        url, result = auditor._readback_result(ep, {"method": "GET", "path": "/opaque/{other_id}"}, "visitor")
        self.assertTrue(url.endswith("/opaque/1002"))
        self.assertEqual(result.status, 200)
        self.assertEqual(self.requests, [("GET", "/opaque/1002")])

    def test_configured_owner_or_visitor_selector_cannot_reach_unsafe_static_route(self):
        self.spec["paths"].update({
            "/opaque/{id}": {"get": {"operationId": "getRecord"}},
            "/opaque/create_report": {"get": {"operationId": "createReport"}},
        })
        self.write_spec()
        for identity in ("owner", "visitor"):
            with self.subTest(identity=identity):
                auditor = self.auditor(parameter_values={"GET /opaque/{id}": {
                    "owner": {"id": "1001"}, "visitor": {"id": "1002"}, identity: {"id": "create_report"}}})
                ep = next(ep for ep in auditor.parser.get_endpoints() if ep["path"] == "/opaque/{id}")
                with patch.object(auditor, "_http_request") as transport:
                    auditor.audit_endpoint_bola(ep)
                transport.assert_not_called()
                result = auditor.results[0]
                self.assertEqual(result["verdict"], "SKIPPED")
                self.assertEqual(result["evidence"]["reason_category"], "safety_policy")
                self.assertEqual(result["evidence"]["requests_attempted"], 0)
                entry = next(item for item in auditor.build_plan()["operations"] if item["endpoint"] == "GET /opaque/{id}")
                self.assertTrue(entry["safety_blocked"])
        self.assertEqual(self.requests, [])

    def test_concrete_unsafe_readback_route_is_blocked_before_baseline_and_patch(self):
        self.spec["paths"].update({
            "/opaque/{id}": {"get": {"operationId": "getRecord"}},
            "/opaque/create_report": {"get": {"operationId": "createReport"}},
        })
        self.write_spec()
        mapping = {"method": "GET", "path": "/opaque/{id}", "parameter_values": {"id": "create_report"},
                   "field_map": {"role": "role"}, "consistency": "strong"}
        auditor = self.auditor(allow_write_tests=True, write_allowlist=["PATCH /settings/{user_id}"],
                               readback_config={"PATCH /settings/{user_id}": mapping})
        ep = next(ep for ep in auditor.parser.get_endpoints() if ep["method"] == "PATCH")
        with patch.object(auditor, "_http_request") as transport:
            auditor.audit_endpoint_mass_assignment(ep, auditor.parser.get_endpoints())
            with self.assertRaises(ParameterSerializationError):
                auditor._readback_result(ep, mapping, "visitor")
        transport.assert_not_called()
        result = auditor.results[0]
        self.assertEqual(result["verdict"], "SKIPPED")
        self.assertEqual(result["evidence"]["reason_category"], "safety_policy")
        self.assertEqual(result["evidence"]["requests_attempted"], 0)
        entry = next(item for item in auditor.build_plan()["operations"] if item["check"] == "MASS_ASSIGNMENT")
        self.assertFalse(entry["writes_enabled"])
        self.assertTrue(entry["safety_blocked"])
        self.assertEqual(self.requests, [])

    def test_direct_bola_does_not_switch_or_execute_write_methods(self):
        auditor = self.auditor(allow_write_tests=True)
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            auditor.audit_endpoint_bola({"method": method, "path": "/records/{user_id}"})
        self.assertEqual(self.requests, [])
        self.assertTrue(all(item["verdict"] == "SKIPPED" for item in auditor.results))

    def test_direct_mass_assignment_does_not_switch_unsupported_methods(self):
        auditor = self.auditor(allow_write_tests=True)
        for method in ("GET", "POST", "PUT", "DELETE"):
            auditor.audit_endpoint_mass_assignment({"method": method, "path": "/records/{user_id}"}, [])
        self.assertEqual(self.requests, [])
        self.assertTrue(all(item["verdict"] == "SKIPPED" for item in auditor.results))

    def test_unsafe_readback_prevents_both_get_and_patch_before_writes(self):
        mapping = {"method": "GET", "path": "/workshop/api/mechanic/receive_report",
                   "field_map": {"role": "role"}, "consistency": "strong"}
        auditor = self.auditor(allow_write_tests=True, write_allowlist=["PATCH /settings/{user_id}"],
                               readback_config={"PATCH /settings/{user_id}": mapping})
        ep = next(ep for ep in auditor.parser.get_endpoints() if ep["method"] == "PATCH")
        with patch.object(auditor, "_http_request") as transport:
            auditor.audit_endpoint_mass_assignment(ep, auditor.parser.get_endpoints())
        transport.assert_not_called()
        self.assertEqual(auditor.results[0]["verdict"], "SKIPPED")
        self.assertEqual(auditor.results[0]["evidence"]["reason_category"], "safety_policy")
        self.assertEqual(self.requests, [])
        plan_entry = next(item for item in auditor.build_plan()["operations"] if item["check"] == "MASS_ASSIGNMENT")
        self.assertFalse(plan_entry["writes_enabled"])
        self.assertTrue(plan_entry["safety_blocked"])

    def test_direct_readback_rejects_unsafe_get_and_never_substitutes_methods(self):
        auditor = self.auditor()
        ep = {"method": "PATCH", "path": "/settings/{user_id}"}
        for mapping in ({"path": "/workshop/api/mechanic/receive_report"},
                        {"path": "/convert_video"}, {"method": "POST", "path": "/records/{user_id}"}):
            with self.subTest(mapping=mapping), self.assertRaises(ParameterSerializationError):
                auditor._readback_result(ep, mapping, "visitor")
        self.assertEqual(self.requests, [])

    def test_local_plan_includes_safety_reasons_without_network(self):
        auditor = self.auditor()
        with patch.object(auditor._opener, "open", side_effect=AssertionError("network forbidden")):
            plan = auditor.build_plan()
        self.assertEqual(plan["requests_sent"], 0)
        self.assertEqual(sum(item.get("safety_blocked", False) for item in plan["operations"]), 2)
        self.assertEqual(self.requests, [])

    def test_cli_dry_run_and_config_validation_make_zero_requests(self):
        config_path = Path(self.temp.name) / "config.json"
        config_path.write_text("{}", encoding="utf-8")
        for flag in ("--dry-run", "--validate-config"):
            with self.subTest(flag=flag), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network forbidden")):
                self.assertEqual(main(["--spec", str(self.spec_path), "--target", self.target,
                                       "--config", str(config_path), flag]), 0)
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
