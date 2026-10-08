"""Invalid business policy must fail before transport, including direct API use."""

import json
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import HTTPResult

ROOT = Path(__file__).resolve().parents[1]


class AuthorizationPolicyPreflightTests(unittest.TestCase):
    def make_auditor(self, policy):
        auditor = APISentinelAuditor(
            str(ROOT / "openapi.json"), "http://127.0.0.1:8080", request_delay=0,
            bola_config={"GET /api/users/{user_id}/profile": policy},
        )
        endpoint = next(ep for ep in auditor.parser.get_endpoints()
                        if ep["path"] == "/api/users/{user_id}/profile")
        return auditor, endpoint

    def test_invalid_policies_send_zero_requests(self):
        for policy in ([], {"expected_visitor_access": True}, {"expected_public": "true"},
                       {"resource_id_paths": [None]}, {"resource_id_paths": ["data..id"]},
                       {"expected_visitr_access": "allow"}):
            with self.subTest(policy=policy):
                auditor, endpoint = self.make_auditor(policy)
                with patch.object(auditor, "_http_request") as http:
                    auditor.audit_endpoint_bola(endpoint)
                http.assert_not_called()
                auditor.stats["total_endpoints"] = 1
                auditor._finalise_coverage()
                result = auditor.results[0]
                self.assertEqual("INCONCLUSIVE", result["verdict"])
                self.assertEqual("invalid_input", result["evidence"]["reason_category"])
                self.assertEqual(0, result["evidence"]["requests_attempted"])
                self.assertEqual(0.0, auditor.stats["coverage_pct"])

    def test_owner_404_is_missing_resource_and_has_no_finding(self):
        auditor, endpoint = self.make_auditor({})
        responses = [HTTPResult(404, '{"message":"Not found"}')]
        responses.extend(HTTPResult(401, '{"message":"JWT Token required!"}') for _ in range(3))
        with patch.object(auditor, "_http_request", side_effect=responses):
            auditor.audit_endpoint_bola(endpoint)
        self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
        self.assertEqual("missing_resource_id", auditor.results[0]["evidence"]["reason_category"])
        self.assertEqual([], auditor.findings)

    def test_existing_array_identifier_paths_pass_offline_and_runtime_policy_validation(self):
        policy = {"resource_id_paths": ["items[].id"]}
        auditor, endpoint = self.make_auditor(policy)
        self.assertTrue(ConfigValidator.validate({"bola": {auditor._operation_key(endpoint): policy}}).is_valid)
        responses = [HTTPResult(200, '{"items":[{"id":"owner-resource"}]}') for _ in range(2)]
        responses.extend([HTTPResult(401, '{"message":"JWT Token required!"}'),
                          HTTPResult(200, '{"items":[{"id":"visitor-resource"}]}')])
        with patch.object(auditor, "_http_request", side_effect=responses) as http:
            auditor.audit_endpoint_bola(endpoint)
        self.assertEqual(4, http.call_count)
        self.assertEqual("CONFIRMED", auditor.results[0]["verdict"])
        self.assertEqual(["items[].id"], auditor.results[0]["evidence"]["decision_evidence"]
                         ["owner_only_shared_resource_identifier_paths"])

    def test_ordinary_transport_error_counts_attempted_endpoint(self):
        auditor, endpoint = self.make_auditor({})
        with patch.object(auditor._opener, "open", side_effect=OSError("isolated network failure")) as transport:
            auditor.audit_endpoint_bola(endpoint)
        self.assertEqual(4, transport.call_count)
        auditor.stats["total_endpoints"] = 1
        auditor._finalise_coverage()
        self.assertEqual("ERROR", auditor.results[0]["verdict"])
        self.assertEqual(4, auditor.results[0]["evidence"]["requests_attempted"])
        self.assertEqual(100.0, auditor.stats["coverage_pct"])
        self.assertEqual(0.0, auditor.stats["conclusive_coverage_pct"])
        self.assertEqual(1, auditor.stats["audited_count"])
        self.assertNotIn("TOKEN_ALICE", json.dumps(auditor.results))

    def test_worker_exception_preserves_attempt_and_resets_next_task(self):
        auditor, endpoint = self.make_auditor({})
        auditor.max_workers = 1
        second = {"method": "GET", "path": "/items"}

        def fail_after_attempt(ep):
            if ep == endpoint:
                auditor._http_request("GET", "http://127.0.0.1:8080/api/users/1001/profile")
                raise RuntimeError("isolated error after transport")
            raise RuntimeError("isolated error before transport")

        with patch.object(auditor.parser, "get_endpoints", return_value=[endpoint, second]), \
             patch.object(auditor, "audit_endpoint_bola", side_effect=fail_after_attempt), \
             patch.object(auditor._opener, "open", side_effect=OSError("isolated transport failure")) as transport, \
             redirect_stdout(io.StringIO()):
            auditor.run()
        self.assertEqual(1, transport.call_count)
        self.assertEqual([1, 0], [item["evidence"]["requests_attempted"] for item in auditor.results])
        self.assertEqual(1, auditor.stats["attempted_endpoints"])
        self.assertEqual(50.0, auditor.stats["coverage_pct"])
        self.assertEqual(0.0, auditor.stats["conclusive_coverage_pct"])


if __name__ == "__main__":
    unittest.main()
