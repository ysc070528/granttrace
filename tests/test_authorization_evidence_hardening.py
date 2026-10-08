"""Synthetic authorization-denial and object-evidence regression cases."""

import json
import unittest

from core.diff import ResponseDiffEngine


def response(status, value):
    return status, json.dumps(value, ensure_ascii=False)


class AuthenticationDenialSemanticTests(unittest.TestCase):
    def setUp(self):
        self.owner = response(200, {"id": "owner-object", "name": "Owner fixture"})
        self.visitor_self = response(200, {"id": "visitor-object", "name": "Visitor fixture"})
        self.denied = response(401, {"message": "JWT Token required!"})

    def evaluate_denial(self, denial, anonymous=None):
        return ResponseDiffEngine.evaluate_bola(
            self.owner, denial, anonymous or self.denied,
            visitor_self=self.visitor_self,
        )

    def test_authentication_message_variants_are_clean_full_responses(self):
        messages = (
            "JWT Token required!", "  jwt   token is required. ",
            "Missing access token", "JWT token is missing",
            "Invalid token", "Bearer token is invalid!", "Token has expired.",
            "JWT expired", "JWT signature verification failed",
            "Authentication credentials were not provided.",
            "Authentication required!", "Authentication failed.",
            "Permission denied.", "Insufficient permissions",
            "You do not have permission to access this resource.",
            "令牌已过期", "权限不足！",
        )
        for status in (401, 403):
            for message in messages:
                with self.subTest(status=status, message=message):
                    result = self.evaluate_denial(response(status, {"message": message}))
                    self.assertEqual("SECURE_ENFORCED", result["verdict"])
                    self.assertFalse(result["evidence"]["denial_body_conflict"])

    def test_semantic_messages_also_classify_soft_auth_denials(self):
        for message in ("JWT Token required!", "Token has expired.", "Invalid access token"):
            with self.subTest(message=message):
                result = self.evaluate_denial(response(200, {"message": message}))
                self.assertEqual("SECURE_ENFORCED", result["verdict"])
                self.assertEqual("AUTH_DENIED", result["evidence"]["responses"]["visitor_cross"]["kind"])

    def test_plain_text_and_json_string_denials_use_same_full_match(self):
        for denial in ((401, "JWT Token required!"), response(403, "Token has expired.")):
            with self.subTest(denial=denial):
                self.assertEqual("SECURE_ENFORCED", self.evaluate_denial(denial)["verdict"])

    def test_http_success_json_string_denial_cannot_establish_owner_baseline(self):
        denial = response(200, "JWT Token required!")
        result = ResponseDiffEngine.evaluate_bola(
            denial, denial, self.denied, visitor_self=self.visitor_self,
        )
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertFalse(result["evidence"]["owner_baseline_valid"])
        self.assertEqual("AUTH_DENIED", result["evidence"]["responses"]["owner"]["kind"])
        self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_http_success_json_string_visitor_denial_is_clean(self):
        for message in ("JWT Token required!", "Token has expired."):
            with self.subTest(message=message):
                result = self.evaluate_denial(response(200, message))
                self.assertEqual("SECURE_ENFORCED", result["verdict"])
                self.assertTrue(result["evidence"]["visitor_denial_body_clean"])
                self.assertEqual("AUTH_DENIED", result["evidence"]["responses"]["visitor_cross"]["kind"])

    def test_scalar_business_text_is_not_a_denial_substring_match(self):
        for text in (
            "JWT token requirements for this service",
            "Token has expired. Details for synthetic customer",
            "A report about missing access tokens",
        ):
            with self.subTest(text=text):
                assessment = ResponseDiffEngine.classify_response(*response(200, text))
                self.assertEqual("VALID", assessment["kind"])
                self.assertFalse(assessment["is_auth_denial"])

    def test_denial_prefix_cannot_hide_business_data_or_credentials(self):
        for message in (
            "JWT Token required! salary=25000",
            "Invalid token: synthetic-secret-value",
            "Token has expired. Bearer synthetic-credential",
            "Unauthorized; order total: 42",
            "Permission denied for customer synthetic-person",
            "JWT Token required!\n{\"payment\":\"synthetic-account\"}",
        ):
            with self.subTest(message=message):
                result = self.evaluate_denial(response(401, {"message": message}))
                self.assertNotEqual("SECURE_ENFORCED", result["verdict"])
                self.assertTrue(result["evidence"]["denial_body_conflict"])

    def test_recognized_message_does_not_exempt_business_fields(self):
        for business in (
            {"payment": {"amount": 42, "account": "synthetic-account"}},
            {"data": {"location": {"latitude": 1, "longitude": 2}}},
            {"account": {"message": "Unauthorized"}},
            {"private_record": None},
            {"details": [{"message": "JWT Token required!"}]},
        ):
            with self.subTest(business=business):
                result = self.evaluate_denial(response(401, {"message": "JWT Token required!", **business}))
                self.assertNotEqual("SECURE_ENFORCED", result["verdict"])
                self.assertTrue(result["evidence"]["denial_body_conflict"])

    def test_error_message_structures_remain_conservative(self):
        for body in (
            {"message": {"token": "missing"}},
            {"errors": [{"message": "Invalid token", "sensitive": "synthetic-data"}]},
            {"message": "Token validation returned an unknown result"},
        ):
            with self.subTest(body=body):
                result = self.evaluate_denial(response(403, body))
                self.assertNotEqual("SECURE_ENFORCED", result["verdict"])
                self.assertTrue(result["evidence"]["denial_body_conflict"])

    def test_nested_denial_with_scalar_tracing_metadata_is_clean(self):
        result = self.evaluate_denial(response(401, {
            "error": {"message": "JWT Token required!", "code": 401},
            "meta": {"request_id": "synthetic-request", "timestamp": 1},
            "data": None,
        }))
        self.assertEqual("SECURE_ENFORCED", result["verdict"])

    def test_tracing_metadata_cannot_exempt_credentials_or_business_text(self):
        values = (
            "Bearer SYNTHETIC_REFLECTED_TOKEN", "Basic SYNTHETIC_CREDENTIAL",
            "token=SYNTHETIC_REFLECTED_TOKEN", "salary=25000",
            '{"payment":"synthetic-account"}', '["synthetic-private-record"]',
            "Unknown business details for synthetic customer",
            "eyJzdWIiOiJzeW50aGV0aWMifQ.payload.signature",
        )
        for field in ("request_id", "trace_id", "timestamp"):
            for value in values:
                with self.subTest(field=field, value=value):
                    result = self.evaluate_denial(response(403, {
                        "message": "JWT Token required!", field: value,
                    }))
                    self.assertNotEqual("SECURE_ENFORCED", result["verdict"])
                    self.assertTrue(result["evidence"]["denial_body_conflict"])

    def test_regular_tracing_identifiers_and_timestamps_remain_clean(self):
        cases = (
            {"trace_id": "00000000-0000-4000-8000-000000000001"},
            {"meta": {"request_id": "synthetic-request-123"}},
            {"timestamp": "2026-10-08T12:34:56.123Z"},
            {"timestamp": "2026-10-08T12:34:56+08:00"},
            {"timestamp": 1}, {"timestamp": 1.25},
        )
        for metadata in cases:
            with self.subTest(metadata=metadata):
                result = self.evaluate_denial(response(401, {"message": "JWT Token required!", **metadata}))
                self.assertEqual("SECURE_ENFORCED", result["verdict"])

    def test_historical_token_errors_are_not_current_denials(self):
        owner = {"id": "owner-object", "name": "Owner fixture"}
        leaked = {**owner, "history": [{"message": "JWT Token required!"}]}
        result = ResponseDiffEngine.evaluate_bola(
            response(200, owner), response(200, leaked), self.denied,
            visitor_self=self.visitor_self,
        )
        self.assertEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertEqual("VALID", result["evidence"]["responses"]["visitor_cross"]["kind"])

    def test_unknown_error_message_does_not_echo_credentials_in_reason(self):
        marker = "synthetic-private-credential"
        rejected = response(200, {"error": "Invalid token: " + marker})
        assessment = ResponseDiffEngine.classify_response(*rejected)
        self.assertEqual("APPLICATION_ERROR", assessment["kind"])
        self.assertNotIn(marker, json.dumps(assessment))
        result = self.evaluate_denial(rejected)
        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual("INCONCLUSIVE", result["verdict"])


class ObjectAuthorizationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.denied = response(401, {"message": "JWT Token required!"})
        self.owner = response(200, {
            "id": "owner-object", "latitude": 1, "longitude": 2, "label": "Owner fixture",
        })
        self.visitor_self = response(200, {
            "id": "visitor-object", "latitude": 3, "longitude": 4, "label": "Visitor fixture",
        })

    def test_vehicle_values_with_clean_jwt_denial_confirm_object_access(self):
        result = ResponseDiffEngine.evaluate_bola(
            self.owner, self.owner, self.denied, visitor_self=self.visitor_self,
            requires_auth=True, resource_id_paths=["id"],
        )
        self.assertEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertTrue(result["evidence"]["visitor_self_baseline_valid"])
        self.assertTrue(result["evidence"]["owner_self_distinct"])
        self.assertTrue(result["evidence"]["anonymous_denial_body_clean"])
        self.assertFalse(result["evidence"]["anonymous_authentication_violation"])
        self.assertEqual([], result["evidence"]["missing_evidence"])

    def test_orders_anonymous_access_is_distinct_from_object_confirmation(self):
        owner = response(200, {"order_id": "owner-order", "amount": 42, "payment": "synthetic-payment"})
        visitor_self = response(200, {"order_id": "visitor-order", "amount": 17, "payment": "visitor-payment"})
        result = ResponseDiffEngine.evaluate_bola(
            owner, owner, owner, visitor_self=visitor_self,
            requires_auth=True, resource_id_paths=["order_id"],
        )
        evidence = result["evidence"]
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertTrue(evidence["anonymous_authentication_violation"])
        self.assertTrue(evidence["anonymous_owner_value_match"])
        self.assertTrue(evidence["anonymous_owner_identifier_match"])
        self.assertIn("exact_business_value_match", evidence["object_access_signals"])
        self.assertEqual([], evidence["confirmation_signals"])
        self.assertEqual(["anonymous_denial_baseline"], evidence["missing_evidence"])

    def test_community_resource_with_explicit_public_policy_is_public(self):
        article = response(200, {"id": "shared-article", "title": "Synthetic community post"})
        result = ResponseDiffEngine.evaluate_bola(article, article, article, expected_public=True)
        self.assertEqual("PUBLIC_ENDPOINT", result["verdict"])
        self.assertFalse(result["evidence"]["anonymous_authentication_violation"])
        self.assertEqual([], result["evidence"]["object_access_signals"])

    def test_invalid_owner_404_is_inconclusive_without_object_signals(self):
        result = ResponseDiffEngine.evaluate_bola(
            response(404, {"message": "Resource not found"}), self.owner, self.denied,
            visitor_self=self.visitor_self,
        )
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertFalse(result["evidence"]["owner_baseline_valid"])
        self.assertEqual([], result["evidence"]["object_access_signals"])
        self.assertEqual(["owner_baseline"], result["evidence"]["missing_evidence"])

    def test_missing_or_invalid_self_baseline_cannot_supply_object_signals(self):
        for baseline in (None, response(401, {"message": "Invalid token"})):
            with self.subTest(baseline=baseline):
                result = ResponseDiffEngine.evaluate_bola(
                    self.owner, self.owner, self.denied, visitor_self=baseline,
                )
                self.assertEqual("INCONCLUSIVE", result["verdict"])
                self.assertFalse(result["evidence"]["visitor_self_baseline_valid"])
                self.assertEqual([], result["evidence"]["object_access_signals"])
                self.assertEqual(["visitor_self_baseline"], result["evidence"]["missing_evidence"])

    def test_equal_owner_and_self_data_cannot_prove_resource_distinction(self):
        result = ResponseDiffEngine.evaluate_bola(
            self.owner, self.owner, self.denied, visitor_self=self.owner,
        )
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertFalse(result["evidence"]["owner_self_distinct"])
        self.assertEqual([], result["evidence"]["object_access_signals"])
        self.assertIn("distinct_visitor_self_resource", result["evidence"]["missing_evidence"])

    def test_denied_response_leak_records_cleanliness_conflict(self):
        result = ResponseDiffEngine.evaluate_bola(
            self.owner, response(403, {"message": "Forbidden", "amount": 42}), self.denied,
            visitor_self=self.visitor_self,
        )
        self.assertFalse(result["evidence"]["visitor_denial_body_clean"])
        self.assertTrue(result["evidence"]["anonymous_denial_body_clean"])
        self.assertTrue(result["evidence"]["denial_body_conflict"])
        self.assertEqual(["clean_visitor_denial_body"], result["evidence"]["missing_evidence"])


if __name__ == "__main__":
    unittest.main()
