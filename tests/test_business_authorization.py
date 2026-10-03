"""Business truth, explicit sharing expectations and rejection boundaries."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import HTTPResult
from scripts.verify_business_scenarios import run_scenarios

ROOT = Path(__file__).resolve().parents[1]


class BusinessAuthorizationTests(unittest.TestCase):
    def test_live_business_matrix_matches_independent_truth(self):
        result = run_scenarios()
        self.assertTrue(result["matches_expectation"], result)
        self.assertEqual(
            (0, 0, 0),
            (result["false_positives"], result["false_negatives"], result["inconclusive"]),
        )

    def test_expected_access_is_strict_enum_in_validator(self):
        for value in (True, False, None, 1, [], {}, "ALLOW", "anyone"):
            with self.subTest(value=value):
                result = ConfigValidator.validate(
                    {"bola": {"GET /documents/{id}": {"expected_visitor_access": value}}}
                )
                self.assertFalse(result.is_valid)
                self.assertTrue(
                    any("expected_visitor_access" in issue.path for issue in result.errors)
                )

    def evaluate(self, cross_status=200, anonymous_status=401, self_status=200, policy="allow"):
        auditor = APISentinelAuditor(
            str(ROOT / "openapi.json"),
            "http://127.0.0.1:8080",
            request_delay=0,
            bola_config={
                "GET /api/users/{user_id}/profile": {"expected_visitor_access": policy}
            },
        )
        endpoint = next(
            ep
            for ep in auditor.parser.get_endpoints()
            if ep["path"] == "/api/users/{user_id}/profile"
        )

        def response(method, url, data=None, identity_name="owner", **kwargs):
            body = {"id": "1001", "title": "Owner data", "private_note": "Owner note"}
            status = 200
            if identity_name == "anonymous":
                status = anonymous_status
            elif identity_name == "visitor" and "/1002/" in url:
                status = self_status
                body = {
                    "id": "1002",
                    "title": "Visitor data",
                    "private_note": "Visitor note",
                }
            elif identity_name == "visitor":
                status = cross_status
            if status in (401, 403):
                body = {"error": "Forbidden"}
            return HTTPResult(status, json.dumps(body))

        with patch.object(auditor, "_http_request", side_effect=response):
            auditor.audit_endpoint_bola(endpoint)
        return auditor

    def test_sharing_expectation_does_not_exempt_anonymous_leak(self):
        auditor = self.evaluate(anonymous_status=200)
        self.assertEqual("SUSPICIOUS", auditor.results[0]["verdict"])
        self.assertEqual(0, auditor.stats["conclusive_count"])

    def test_allowed_but_denied_is_not_conclusive(self):
        self.assertEqual("INCONCLUSIVE", self.evaluate(cross_status=403).results[0]["verdict"])

    def test_invalid_visitor_self_baseline_cannot_prove_allowed_access(self):
        self.assertEqual("INCONCLUSIVE", self.evaluate(self_status=403).results[0]["verdict"])

    def test_explicit_allow_records_policy_and_no_vulnerability(self):
        auditor = self.evaluate()
        self.assertEqual("AUTHORIZED", auditor.results[0]["verdict"])
        self.assertEqual(
            "allow",
            auditor.results[0]["evidence"]["decision_evidence"]["expected_visitor_access"],
        )
        self.assertEqual([], auditor.findings)
        self.assertEqual(1, auditor.stats["authorized_endpoints"])
        self.assertEqual(1, auditor.stats["conclusive_count"])

    def test_denied_expectation_retains_confirmed_vulnerability(self):
        self.assertEqual("CONFIRMED", self.evaluate(policy="deny").results[0]["verdict"])


if __name__ == "__main__":
    unittest.main()
