# -*- coding: utf-8 -*-
"""Focused regression tests for the response-differencing decision engine."""

import json
import unittest

from core.diff import ResponseDiffEngine


def response(status, value):
    if isinstance(value, str):
        return status, value
    return status, json.dumps(value, ensure_ascii=False)


class ResponseClassificationTests(unittest.TestCase):
    def test_transport_failure_is_not_authorization_denial(self):
        result = ResponseDiffEngine.classify_response(0, "connection refused")
        self.assertEqual(ResponseDiffEngine.RESPONSE_TRANSPORT_ERROR, result["kind"])
        self.assertFalse(result["is_auth_denial"])

    def test_only_401_and_403_http_statuses_are_explicit_denials(self):
        for status in (401, 403):
            with self.subTest(status=status):
                result = ResponseDiffEngine.classify_response(status, "")
                self.assertEqual(ResponseDiffEngine.RESPONSE_AUTH_DENIED, result["kind"])
                self.assertTrue(result["is_auth_denial"])

        for status in (400, 404, 409, 422, 429):
            with self.subTest(status=status):
                result = ResponseDiffEngine.classify_response(status, '{"error":"request failed"}')
                self.assertEqual(ResponseDiffEngine.RESPONSE_HTTP_CLIENT_ERROR, result["kind"])
                self.assertFalse(result["is_auth_denial"])

    def test_all_server_errors_are_classified_as_errors(self):
        for status in (500, 501, 502, 503, 599):
            with self.subTest(status=status):
                is_error, reason = ResponseDiffEngine.is_soft_error(status, '{"data":true}')
                self.assertTrue(is_error)
                self.assertIn("服务端错误", reason)

    def test_empty_and_invalid_success_responses_are_not_valid_baselines(self):
        empty = ResponseDiffEngine.classify_response(200, "  ")
        invalid = ResponseDiffEngine.classify_response(200, "<html>gateway page</html>")
        empty_json = ResponseDiffEngine.classify_response(200, "{}")

        self.assertEqual(ResponseDiffEngine.RESPONSE_EMPTY, empty["kind"])
        self.assertEqual(ResponseDiffEngine.RESPONSE_INVALID, invalid["kind"])
        self.assertEqual(ResponseDiffEngine.RESPONSE_EMPTY, empty_json["kind"])

    def test_nested_authorization_wrapper_is_detected(self):
        body = {
            "meta": {"request_id": "abc"},
            "payload": {"result": {"error": {"code": 403, "message": "Permission denied"}}},
        }
        result = ResponseDiffEngine.classify_response(200, json.dumps(body))
        self.assertEqual(ResponseDiffEngine.RESPONSE_AUTH_DENIED, result["kind"])
        self.assertTrue(result["is_auth_denial"])

    def test_nested_non_auth_business_error_is_not_a_denial(self):
        body = {"payload": [{"result": {"status": "failed", "message": "validation failed"}}]}
        result = ResponseDiffEngine.classify_response(200, json.dumps(body))
        self.assertEqual(ResponseDiffEngine.RESPONSE_APPLICATION_ERROR, result["kind"])
        self.assertFalse(result["is_auth_denial"])


class BolaEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.denied = response(401, {"error": "Authentication required"})

    def assert_consistent_result_shape(self, result):
        self.assertEqual(
            {"verdict", "confidence", "reason", "similarity", "evidence"},
            set(result),
        )
        self.assertIn("responses", result["evidence"])
        self.assertIn("structure_similarity", result["evidence"])
        self.assertIn("value_similarity", result["evidence"])
        self.assertIn("confirmation_signals", result["evidence"])

    def test_identical_owner_and_cross_response_with_denied_anonymous_is_confirmed(self):
        alice = response(
            200,
            {"name": "Alice", "role": "user", "salary": "25,000 USD", "department": "Engineering"},
        )
        bob = response(
            200,
            {"name": "Bob", "role": "user", "salary": "18,000 USD", "department": "Marketing"},
        )
        result = ResponseDiffEngine.evaluate_bola(alice, alice, self.denied, visitor_self=bob)

        self.assertEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertTrue(result["evidence"]["anonymous_denied"])
        self.assertTrue(result["evidence"]["exact_value_match"])
        self.assertIn("exact_business_value_match", result["evidence"]["confirmation_signals"])
        self.assert_consistent_result_shape(result)

    def test_same_keys_with_alice_and_bob_values_never_confirms(self):
        owner = response(200, {"name": "Alice", "role": "user", "department": "Engineering"})
        cross = response(200, {"name": "Bob", "role": "user", "department": "Marketing"})
        result = ResponseDiffEngine.evaluate_bola(owner, cross, self.denied)

        self.assertEqual(1.0, result["evidence"]["structure_similarity"])
        self.assertNotEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_matching_nested_resource_identifier_is_value_evidence(self):
        owner = response(200, {"data": {"user_id": "1001", "name": "Alice", "salary": "25000"}})
        cross = response(200, {"data": {"user_id": "1001", "name": "Alice", "salary": "redacted"}})
        visitor_self = response(
            200, {"data": {"user_id": "1002", "name": "Bob", "salary": "18000"}}
        )
        result = ResponseDiffEngine.evaluate_bola(
            owner, cross, self.denied, visitor_self=visitor_self,
            resource_id_paths=["data.user_id"],
        )

        self.assertEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertIn("matching_resource_identifier", result["evidence"]["confirmation_signals"])
        self.assertEqual(1, result["evidence"]["shared_resource_identifier_count"])

    def test_visitor_self_baseline_blocks_return_current_user_false_positive(self):
        owner = response(200, {"user_id": "1001", "name": "Alice"})
        visitor_record = response(200, {"user_id": "1002", "name": "Bob"})
        result = ResponseDiffEngine.evaluate_bola(
            owner,
            visitor_record,
            self.denied,
            visitor_self=visitor_record,
        )

        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertTrue(result["evidence"]["visitor_self_exact_match"])
        self.assertNotEqual("BOLA_CONFIRMED", result["verdict"])

    def test_visitor_transport_or_server_failure_is_inconclusive_not_secure(self):
        owner = response(200, {"user_id": "1001", "name": "Alice"})
        visitors = (
            (0, "timed out"),
            response(404, {"error": "missing"}),
            response(503, {"error": "down"}),
        )
        for visitor in visitors:
            with self.subTest(visitor=visitor[0]):
                result = ResponseDiffEngine.evaluate_bola(owner, visitor, self.denied)
                self.assertEqual("INCONCLUSIVE", result["verdict"])
                self.assertNotEqual("SECURE_ENFORCED", result["verdict"])
                self.assert_consistent_result_shape(result)

    def test_explicit_cross_visitor_denial_is_secure(self):
        owner = response(200, {"user_id": "1001", "name": "Alice"})
        visitor = response(403, {"error": "Forbidden"})
        visitor_self = response(200, {"user_id": "1002", "name": "Bob"})
        result = ResponseDiffEngine.evaluate_bola(
            owner, visitor, self.denied, visitor_self=visitor_self
        )

        self.assertEqual("SECURE_ENFORCED", result["verdict"])
        self.assert_consistent_result_shape(result)

    def test_cross_denial_without_valid_visitor_baseline_is_inconclusive(self):
        owner = response(200, {"user_id": "1001", "name": "Alice"})
        visitor = response(403, {"error": "Forbidden"})
        for visitor_self in (None, response(401, {"error": "Expired token"})):
            with self.subTest(visitor_self=visitor_self):
                result = ResponseDiffEngine.evaluate_bola(
                    owner, visitor, self.denied, visitor_self=visitor_self
                )
                self.assertEqual("INCONCLUSIVE", result["verdict"])

    def test_dynamic_self_response_and_shared_tenant_id_do_not_confirm(self):
        owner = response(
            200,
            {"user_id": "1001", "tenant_id": "tenant-a", "name": "Alice", "timestamp": 1},
        )
        visitor_record = response(
            200,
            {"user_id": "1002", "tenant_id": "tenant-a", "name": "Bob", "timestamp": 2},
        )
        visitor_self = response(
            200,
            {"user_id": "1002", "tenant_id": "tenant-a", "name": "Bob", "timestamp": 3},
        )
        result = ResponseDiffEngine.evaluate_bola(
            owner, visitor_record, self.denied, visitor_self=visitor_self
        )

        self.assertNotEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertEqual(0, result["evidence"]["owner_only_shared_resource_identifier_count"])

    def test_non_denial_anonymous_error_cannot_support_confirmation(self):
        alice = response(200, {"user_id": "1001", "name": "Alice"})
        result = ResponseDiffEngine.evaluate_bola(alice, alice, response(500, {"error": "down"}))

        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertFalse(result["evidence"]["anonymous_denied"])

    def test_public_endpoint_requires_matching_values_not_only_keys(self):
        owner = response(200, {"article_id": 1, "title": "Public article"})
        visitor = response(200, {"article_id": 1, "title": "Public article"})
        anonymous = response(200, {"article_id": 1, "title": "Public article"})
        result = ResponseDiffEngine.evaluate_bola(owner, visitor, anonymous, expected_public=True)

        self.assertEqual("PUBLIC_ENDPOINT", result["verdict"])
        self.assertTrue(result["evidence"]["anonymous_exact_match"])


if __name__ == "__main__":
    unittest.main()
