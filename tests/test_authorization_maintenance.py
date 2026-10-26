"""Maintenance regressions for complete state evidence and existing coverage."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.diff import ResponseDiffEngine as Diff
from core.generator import SmartDataGenerator as Generator
from core.models import HTTPResult
from core.parser import OpenAPIParser
from core.sarif import SarifReportGenerator
from scripts.verify_authorization_coverage import SCENARIOS, run_scenario


def response(status, data):
    return status, json.dumps(data)


class CompleteReadbackTests(unittest.TestCase):
    def test_only_complete_200_can_supply_state(self):
        for status in (201, 202, 203, 204, 205, 206, 226, 304, 401, 403, 500):
            with self.subTest(status=status):
                self.assertIsNone(APISentinelAuditor._json_object(HTTPResult(status, '{"role":"user"}')))
        self.assertEqual({"role": "user"}, APISentinelAuditor._json_object(HTTPResult(200, '{"role":"user"}')))

    def test_content_range_cannot_certify_state_even_with_200(self):
        for header in ("Content-Range", "content-range", "CONTENT-RANGE"):
            with self.subTest(header=header):
                result = HTTPResult(200, '{"role":"user"}', headers={header: "bytes 0-9/100"})
                self.assertIsNone(APISentinelAuditor._json_object(result))

    def test_transport_truncation_and_invalid_json_remain_unusable(self):
        for result in (
            HTTPResult(200, '{"role":"user"}', truncated=True),
            HTTPResult(200, '{"role":"user"}', error="synthetic error"),
            *(HTTPResult(200, body) for body in ("", "{", "{}", "[]", "null", '{"role":NaN}',
                                                '{"error":"Forbidden"}')),
        ):
            with self.subTest(result=result):
                self.assertIsNone(APISentinelAuditor._json_object(result))

    def test_204_mutation_and_restore_acknowledgements_still_work(self):
        result = run_scenario({"name": "patch_persist_restore", "kind": "patch", "expected": "CONFIRMED",
                               "vulnerable": True, "write_status": 204})
        self.assertTrue(result["matches_expectation"], result)
        self.assertEqual(2, result["patch_requests"])
        self.assertTrue(result["rollback_verified"])
        self.assertTrue(result["resource_restored"])


class ErrorBodyEvidenceTests(unittest.TestCase):
    owner = response(200, {"id": "owner-record", "salary": 25000})
    own = response(200, {"id": "visitor-record", "salary": 18000})
    denied = response(401, {"error": "Unauthorized"})

    def evaluate(self, visitor, own=None, anonymous=None, **kwargs):
        return Diff.evaluate_bola(self.owner, visitor, anonymous or self.denied,
                                  visitor_self=own or self.own, **kwargs)

    def test_client_and_server_errors_with_specific_data_are_leads_only(self):
        for status in (400, 404, 409, 422, 500, 503):
            with self.subTest(status=status):
                result = self.evaluate((status, self.owner[1]))
                self.assertEqual("LOW_SUSPICION", result["verdict"])
                self.assertTrue(result["evidence"]["exact_value_match"])
                self.assertFalse(result["evidence"]["visitor_cross_baseline_valid"])
                self.assertEqual([], result["evidence"]["confirmation_signals"])
                self.assertIn("visitor_cross_response", result["evidence"]["missing_evidence"])

    def test_error_body_trusted_identifier_can_supply_a_lead(self):
        result = self.evaluate(response(500, {"id": "owner-record"}), resource_id_paths=["id"])
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_echo_metadata_generic_errors_and_self_data_are_not_owner_leaks(self):
        for body in ({"error": "Temporary failure"}, {"request_id": "owner-record"},
                     {"id": "visitor-record", "salary": 18000}, {"id": "owner-record"}):
            with self.subTest(body=body):
                result = self.evaluate(response(500, body))
                self.assertEqual("INCONCLUSIVE", result["verdict"])

    def test_missing_or_invalid_baselines_do_not_gain_error_body_confidence(self):
        for own in (None, response(403, {"error": "Forbidden"}), self.owner):
            result = Diff.evaluate_bola(self.owner, (500, self.owner[1]), self.denied, visitor_self=own)
            self.assertEqual("INCONCLUSIVE", result["verdict"])
        result = self.evaluate((500, self.owner[1]), anonymous=response(500, {"error": "Failure"}))
        self.assertEqual("INCONCLUSIVE", result["verdict"])

    def test_structural_similarity_alone_is_insufficient(self):
        result = self.evaluate(response(500, {"id": "other-record", "salary": 17000}))
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertEqual(1.0, result["evidence"]["structure_similarity"])

    def test_live_error_leads_do_not_inflate_conclusive_coverage_or_sarif(self):
        scenario = next(item for item in SCENARIOS if item["name"] == "error_500_owner_data")
        result = run_scenario(scenario)
        self.assertEqual("SUSPICIOUS", result["actual"])
        self.assertEqual(100.0, result["stats"]["coverage_pct"])
        self.assertEqual(0.0, result["stats"]["conclusive_coverage_pct"])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "audit.sarif"
            SarifReportGenerator.generate(result["results"], "http://127.0.0.1", str(output))
            self.assertEqual([], json.loads(output.read_text())["runs"][0]["results"])


class ExistingCoverageSelectionTests(unittest.TestCase):
    def test_readonly_candidates_use_annotations_and_preserve_normal_baseline(self):
        schema = {"type": "object", "properties": {
            "server_marker": {"type": "boolean", "readOnly": True},
            "ordinary_field": {"type": "string"},
        }}
        cases = {item["field_path"] for item in Generator.build_mass_assignment_cases(schema)}
        self.assertEqual({"server_marker"}, cases)
        self.assertNotIn("server_marker", Generator.build_baseline_body(schema))

    def test_nested_array_readonly_leaf_is_selected(self):
        schema = {"type": "object", "properties": {"entries": {
            "type": "array", "items": {"type": "object", "properties": {
                "server_marker": {"type": "boolean", "readOnly": True}
            }}
        }}}
        cases = {item["field_path"] for item in Generator.build_mass_assignment_cases(schema)}
        self.assertIn("entries[0].server_marker", cases)

    def test_media_selection_retains_original_spelling_and_supported_json_priority(self):
        self.assertEqual("Application/JSON ; charset=utf-8", OpenAPIParser._preferred_content_type({
            "application/xml": {}, "Application/JSON ; charset=utf-8": {}, "application/vnd.example+json": {},
        }))
        self.assertEqual("application/vnd.example+json", OpenAPIParser._preferred_content_type({
            "application/xml": {}, "application/vnd.example+json": {},
        }))

    def test_swagger_root_and_operation_consumes_both_choose_json(self):
        for operation_consumes in (False, True):
            with self.subTest(operation_consumes=operation_consumes), tempfile.TemporaryDirectory() as directory:
                operation = {"parameters": [{"name": "body", "in": "body", "schema": {"type": "object"}}]}
                spec = {"swagger": "2.0", "paths": {"/profile": {"patch": operation}}}
                (operation if operation_consumes else spec)["consumes"] = ["application/xml", "application/json"]
                path = Path(directory) / "spec.json"
                path.write_text(json.dumps(spec))
                self.assertEqual("application/json", OpenAPIParser(str(path)).get_endpoints()[0]["request_content_type"])


class OfflinePlanExplanationTests(unittest.TestCase):
    def test_existing_preflight_reasons_match_execution_without_network(self):
        spec = {"openapi": "3.0.3", "paths": {
            "/records": {"get": {"responses": {}}},
            "/records/{id}/delete": {"get": {"responses": {}}},
            "/records/{id}": {"get": {"responses": {}, "parameters": [
                {"name": "X-Business-Context", "in": "header", "required": True, "schema": {"type": "string"}}
            ]}},
            "/unsupported": {"post": {"responses": {}}},
        }}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spec.json"
            path.write_text(json.dumps(spec))
            auditor = APISentinelAuditor(str(path), "http://127.0.0.1:8080", request_delay=0)
            with patch("socket.socket", side_effect=AssertionError("Unexpected network")):
                plan = auditor.build_plan()
                with contextlib.redirect_stdout(io.StringIO()):
                    auditor.run()
            self.assertEqual(0, plan["requests_sent"])
            self.assertEqual(0, auditor.stats["attempted_endpoints"])
            actual = {item["endpoint"]: item["evidence"]["reason_category"] for item in auditor.results}
            self.assertEqual({entry["endpoint"]: entry["reason_category"] for entry in plan["operations"]}, actual)
            self.assertEqual({"not_applicable", "safety_policy", "invalid_input", "detector_unimplemented"},
                             set(actual.values()))


class LocalAcceptanceMatrixTests(unittest.TestCase):
    def test_fixed_truth_scenarios_and_recovery_invariants(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario["name"]):
                result = run_scenario(scenario)
                self.assertTrue(result["matches_expectation"], result)


if __name__ == "__main__":
    unittest.main()
