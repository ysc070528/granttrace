"""Release regressions for complete BOLA rejection evidence and coverage."""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.diff import ResponseDiffEngine
from core.models import HTTPResult


ROOT = Path(__file__).resolve().parents[1]
OWNER = {"id": "1001", "name": "Alice", "salary": 25000}
VISITOR_SELF = {"id": "1002", "name": "Bob", "salary": 18000}
CLEAN_DENIAL = json.dumps({"error": "Forbidden"})
INVALID_BODY = "<html>untrusted gateway response</html>"


def response(status, value):
    return status, json.dumps(value)


def anonymous_cases():
    """HTTP 200 denial envelopes are valid denials; other statuses are not."""
    for status in (200, 302, 404, 500):
        for body_kind, body in (
            ("invalid", INVALID_BODY),
            ("clean_denial", CLEAN_DENIAL),
            ("business_data", json.dumps(OWNER)),
        ):
            if status == 200 and body_kind == "clean_denial":
                expected = "SECURE_ENFORCED"
            elif body_kind == "business_data":
                expected = "LOW_SUSPICION"
            else:
                expected = "INCONCLUSIVE"
            yield status, body_kind, body, expected


class CompleteRejectionEvidenceTests(unittest.TestCase):
    def evaluate(self, anonymous, requires_auth=False, expected_public=False):
        return ResponseDiffEngine.evaluate_bola(
            response(200, OWNER), (403, CLEAN_DENIAL), anonymous,
            visitor_self=response(200, VISITOR_SELF),
            requires_auth=requires_auth, expected_public=expected_public,
        )

    def test_anonymous_status_body_matrix_requires_consistent_denial(self):
        for requires_auth in (False, True):
            for status, kind, body, expected in anonymous_cases():
                with self.subTest(requires_auth=requires_auth, status=status, body=kind):
                    result = self.evaluate((status, body), requires_auth)
                    self.assertEqual(expected, result["verdict"])
                    if expected != "SECURE_ENFORCED":
                        self.assertNotEqual("PUBLIC_ENDPOINT", result["verdict"])
                        self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_clean_401_and_403_anonymous_denials_remain_secure(self):
        for requires_auth in (False, True):
            for status in (401, 403):
                for body in ("", "Forbidden", CLEAN_DENIAL):
                    with self.subTest(requires_auth=requires_auth, status=status, body=body):
                        self.assertEqual("SECURE_ENFORCED", self.evaluate((status, body), requires_auth)["verdict"])

    def test_denial_status_with_business_data_remains_suspicious(self):
        for requires_auth in (False, True):
            for status in (200, 401, 403):
                with self.subTest(requires_auth=requires_auth, status=status):
                    leaked = {"code": 403, **OWNER}
                    result = self.evaluate(response(status, leaked), requires_auth)
                    self.assertEqual("LOW_SUSPICION", result["verdict"])
                    self.assertTrue(result["evidence"]["denial_body_conflict"])

    def test_public_projection_and_cross_denial_are_not_endpoint_safety(self):
        for requires_auth in (False, True):
            with self.subTest(requires_auth=requires_auth):
                result = self.evaluate(response(200, {"id": "1001", "title": "Public summary"}),
                                       requires_auth, expected_public=True)
                self.assertEqual("LOW_SUSPICION", result["verdict"])

    def test_explicit_public_equivalent_data_remains_public(self):
        public = response(200, {"id": "1001", "title": "Public summary"})
        result = ResponseDiffEngine.evaluate_bola(public, public, public, expected_public=True)
        self.assertEqual("PUBLIC_ENDPOINT", result["verdict"])

    def test_nonfinite_json_cannot_supply_owner_or_anonymous_baseline(self):
        for literal in ("NaN", "Infinity", "-Infinity", "1e400"):
            body = '{"id":"1001","name":"Alice","salary":' + literal + '}'
            with self.subTest(literal=literal):
                classification = ResponseDiffEngine.classify_response(200, body)
                self.assertEqual(ResponseDiffEngine.RESPONSE_INVALID, classification["kind"])
                owner_result = ResponseDiffEngine.evaluate_bola(
                    (200, body), (403, CLEAN_DENIAL), (401, CLEAN_DENIAL),
                    visitor_self=response(200, VISITOR_SELF),
                )
                self.assertEqual("INCONCLUSIVE", owner_result["verdict"])
                self.assertEqual("INCONCLUSIVE", self.evaluate((200, body))["verdict"])


class AuditorCoverageRegressionTests(unittest.TestCase):
    def audit(self, anonymous, requires_auth=False):
        ep = {
            "method": "GET", "path": "/users/{user_id}", "parameters": [],
            "security": [{"bearer": []}] if requires_auth else [],
            "security_declared": requires_auth,
        }
        auditor = APISentinelAuditor(str(ROOT / "openapi.json"), "http://127.0.0.1:8080", request_delay=0)
        responses = (
            HTTPResult(*response(200, OWNER)), HTTPResult(403, CLEAN_DENIAL),
            HTTPResult(*anonymous), HTTPResult(*response(200, VISITOR_SELF)),
        )
        with patch.object(auditor, "_http_request", side_effect=responses) as http:
            auditor.audit_endpoint_bola(ep)
        self.assertEqual(4, http.call_count)
        self.assertEqual(["owner", "visitor", "anonymous", "visitor"],
                         [call.kwargs["identity_name"] for call in http.call_args_list])
        self.assertNotEqual(http.call_args_list[0].args[1], http.call_args_list[3].args[1])
        auditor.stats["total_endpoints"] = 1
        auditor._finalise_coverage()
        return auditor

    def test_anonymous_status_body_matrix_controls_conclusive_coverage(self):
        mapped = {"SECURE_ENFORCED": "SECURE", "LOW_SUSPICION": "SUSPICIOUS", "INCONCLUSIVE": "INCONCLUSIVE"}
        for requires_auth in (False, True):
            for status, kind, body, expected in anonymous_cases():
                with self.subTest(requires_auth=requires_auth, status=status, body=kind):
                    auditor = self.audit((status, body), requires_auth)
                    self.assertEqual(mapped[expected], auditor.results[0]["verdict"])
                    self.assertEqual(100.0, auditor.stats["coverage_pct"])
                    self.assertEqual(100.0 if expected == "SECURE_ENFORCED" else 0.0,
                                     auditor.stats["conclusive_coverage_pct"])
                    self.assertEqual(1 if expected == "SECURE_ENFORCED" else 0,
                                     auditor.stats["secure_endpoints"])
                    self.assertEqual([], auditor.findings)

    def test_clean_anonymous_denial_retains_conclusive_coverage(self):
        for requires_auth in (False, True):
            with self.subTest(requires_auth=requires_auth):
                auditor = self.audit((401, CLEAN_DENIAL), requires_auth)
                self.assertEqual("SECURE", auditor.results[0]["verdict"])
                self.assertEqual(100.0, auditor.stats["conclusive_coverage_pct"])


if __name__ == "__main__":
    unittest.main()
