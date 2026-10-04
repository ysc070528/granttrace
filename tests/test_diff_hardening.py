"""Counterexamples for denial-body leaks, public deltas and reflected identifiers."""

import json
import unittest

from core.diff import ResponseDiffEngine


def response(status, value):
    return status, json.dumps(value)


class DenialBodyRegressionTests(unittest.TestCase):
    def setUp(self):
        self.alice = {"id": 1, "name": "Alice", "salary": 25000}
        self.bob = {"id": 2, "name": "Bob", "salary": 18000}
        self.denied = response(401, {"error": "Authentication required"})

    def evaluate(self, cross, anon=None):
        return ResponseDiffEngine.evaluate_bola(
            response(200, self.alice), cross, anon or self.denied,
            visitor_self=response(200, self.bob),
        )

    def test_403_body_containing_owner_data_is_not_safe(self):
        result = self.evaluate(response(403, self.alice))
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertTrue(result["evidence"]["denial_body_conflict"])
        self.assertEqual(["name", "salary"], result["evidence"]["owner_specific_shared_value_paths"])

    def test_soft_denial_wrapper_with_owner_data_is_not_safe(self):
        result = self.evaluate(response(200, {"code": 403, **self.alice}))
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertTrue(result["evidence"]["denial_body_conflict"])

    def test_historical_business_message_does_not_deny_current_request(self):
        leaked = {**self.alice, "history": [{"message": "permission denied yesterday"}]}
        result = self.evaluate(response(200, leaked))
        self.assertEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertEqual("VALID", result["evidence"]["responses"]["visitor_cross"]["kind"])

    def test_historical_auth_code_does_not_deny_current_request(self):
        leaked = {**self.alice, "history": [{"code": 403, "description": "Forbidden"}]}
        result = self.evaluate(response(200, leaked))
        self.assertEqual("BOLA_CONFIRMED", result["verdict"])

    def test_unknown_plain_text_denial_is_not_assumed_to_withhold_data(self):
        result = self.evaluate((403, "Forbidden; salary=25000"))
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertTrue(result["evidence"]["denial_body_conflict"])

    def test_clean_nested_denial_remains_secure(self):
        result = self.evaluate(response(200, {
            "payload": {"result": {"error": {"code": 403, "message": "Permission denied"}}},
            "meta": {"request_id": "synthetic-123"},
        }))
        self.assertEqual("SECURE_ENFORCED", result["verdict"])

    def test_anonymous_403_body_leak_cannot_be_ignored(self):
        result = self.evaluate(response(403, {"error": "Forbidden"}), response(403, self.alice))
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertTrue(result["evidence"]["denial_body_conflict"])


class PublicExposureRegressionTests(unittest.TestCase):
    def setUp(self):
        self.public = {f"public_field_{i}": i for i in range(10)}

    def test_high_similarity_cannot_hide_private_increment(self):
        owner = {**self.public, "salary": 25000}
        result = ResponseDiffEngine.evaluate_bola(
            response(200, owner), response(200, owner), response(200, self.public),
            visitor_self=response(200, {**self.public, "salary": 18000}),
            expected_public=True,
        )
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertGreater(result["evidence"]["anonymous_value_similarity"], 0.9)
        self.assertEqual(["salary"], result["evidence"]["owner_shared_nonpublic_value_paths"])

    def test_same_json_requires_explicit_public_policy(self):
        record = response(200, self.public)
        implicit = ResponseDiffEngine.evaluate_bola(record, record, record)
        explicit = ResponseDiffEngine.evaluate_bola(record, record, record, expected_public=True)
        self.assertEqual("LOW_SUSPICION", implicit["verdict"])
        self.assertEqual("PUBLIC_ENDPOINT", explicit["verdict"])

    def test_auth_requirement_prevents_public_classification(self):
        record = response(200, {"name": "Alice", "salary": 25000})
        result = ResponseDiffEngine.evaluate_bola(
            record, record, record, expected_public=True, requires_auth=True,
        )
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertTrue(result["evidence"]["requires_auth"])

    def test_owner_private_extra_prevents_whole_endpoint_public_verdict(self):
        result = ResponseDiffEngine.evaluate_bola(
            response(200, {**self.public, "salary": 25000}),
            response(200, self.public), response(200, self.public), expected_public=True,
        )
        self.assertNotEqual("PUBLIC_ENDPOINT", result["verdict"])

    def test_auth_required_anonymous_leak_cannot_be_hidden_by_cross_denial(self):
        owner = response(200, {"name": "Alice", "salary": 25000})
        result = ResponseDiffEngine.evaluate_bola(
            owner, response(403, {"error": "Forbidden"}), owner,
            visitor_self=response(200, {"name": "Bob", "salary": 18000}), requires_auth=True,
        )
        self.assertEqual("LOW_SUSPICION", result["verdict"])

    def test_anonymous_identifier_only_response_still_violates_auth_policy(self):
        result = ResponseDiffEngine.evaluate_bola(
            response(200, {"id": 1}), response(403, {"error": "Forbidden"}),
            response(200, {"id": 1}), visitor_self=response(200, {"id": 2}), requires_auth=True,
        )
        self.assertEqual("LOW_SUSPICION", result["verdict"])


class ReflectedIdentifierRegressionTests(unittest.TestCase):
    def setUp(self):
        self.denied = response(401, {"error": "Authentication required"})
        self.alice = {"name": "Alice", "salary": 25000}
        self.bob = {"name": "Bob", "salary": 18000}

    def test_request_echo_is_not_resource_identity_even_if_configured(self):
        for key in ("requested_id", "trace_id", "requestId"):
            with self.subTest(key=key):
                result = ResponseDiffEngine.evaluate_bola(
                    response(200, {key: 1, "data": self.alice}),
                    response(200, {key: 1, "data": self.bob}),
                    self.denied,
                    visitor_self=response(200, {key: 2, "data": self.bob}),
                    resource_id_paths=[key],
                )
                self.assertEqual("LOW_SUSPICION", result["verdict"])
                self.assertEqual(0, result["evidence"]["shared_resource_identifier_count"])
                self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_metadata_id_cannot_certify_owner_resource(self):
        result = ResponseDiffEngine.evaluate_bola(
            response(200, {"metadata": {"id": 1}, "data": self.alice}),
            response(200, {"metadata": {"id": 1}, "data": self.bob}),
            self.denied,
            visitor_self=response(200, {"metadata": {"id": 2}, "data": self.bob}),
            resource_id_paths=["metadata.id"],
        )
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_untrusted_identifier_only_response_never_confirms(self):
        result = ResponseDiffEngine.evaluate_bola(
            response(200, {"opaque_id": 1}), response(200, {"opaque_id": 1}), self.denied,
            visitor_self=response(200, {"opaque_id": 2}),
        )
        self.assertNotEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_trusted_business_id_can_confirm_without_equal_non_id_values(self):
        result = ResponseDiffEngine.evaluate_bola(
            response(200, {"data": {"user_id": 1, "name": "Alice", "salary": 25000}}),
            response(200, {"data": {"user_id": 1, "name": "Alice", "salary": "redacted"}}),
            self.denied,
            visitor_self=response(200, {"data": {"user_id": 2, "name": "Bob", "salary": 18000}}),
            resource_id_paths=["data.user_id"],
        )
        self.assertEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertEqual(["data.user_id"], result["evidence"]["owner_only_shared_resource_identifier_paths"])

    def test_trusted_array_path_uses_business_path_not_any_id_suffix(self):
        result = ResponseDiffEngine.evaluate_bola(
            response(200, {"items": [{"id": 1}]}),
            response(200, {"items": [{"id": 1}]}), self.denied,
            visitor_self=response(200, {"items": [{"id": 2}]}), resource_id_paths=["items[].id"],
        )
        self.assertEqual("BOLA_CONFIRMED", result["verdict"])


class ArrayRecordAssociationTests(unittest.TestCase):
    def setUp(self):
        self.denied = response(401, {"error": "Authentication required"})
        self.owner = {"rows": [
            {"id": "owner-1", "color": "red", "amount": 10},
            {"id": "owner-2", "color": "blue", "amount": 20},
        ]}
        self.visitor_self = {"rows": [
            {"id": "visitor-1", "color": "green", "amount": 30},
            {"id": "visitor-2", "color": "orange", "amount": 40},
        ]}

    def evaluate(self, cross):
        return ResponseDiffEngine.evaluate_bola(
            response(200, self.owner), response(200, cross), self.denied,
            visitor_self=response(200, self.visitor_self),
        )

    def test_reassociated_fields_from_unrelated_records_do_not_confirm(self):
        unrelated = {"rows": [
            {"id": "other-1", "color": "red", "amount": 20},
            {"id": "other-2", "color": "blue", "amount": 10},
        ]}
        result = self.evaluate(unrelated)
        self.assertEqual("LOW_SUSPICION", result["verdict"])
        self.assertFalse(result["evidence"]["exact_value_match"])
        self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_reordered_complete_records_retain_confirmation(self):
        result = self.evaluate({"rows": list(reversed(self.owner["rows"]))})
        self.assertEqual("BOLA_CONFIRMED", result["verdict"])
        self.assertTrue(result["evidence"]["exact_value_match"])

    def test_duplicate_records_are_not_discarded(self):
        cross = {"rows": self.owner["rows"] + [self.owner["rows"][0]]}
        result = self.evaluate(cross)
        self.assertFalse(result["evidence"]["exact_value_match"])
        self.assertEqual("LOW_SUSPICION", result["verdict"])

    def test_nested_arrays_preserve_record_association_and_counts(self):
        owner = {"groups": [{"entries": self.owner["rows"]}]}
        reordered = {"groups": [{"entries": list(reversed(self.owner["rows"]))}]}
        duplicated = {"groups": [{"entries": self.owner["rows"] * 2}]}
        self.assertEqual(1.0, ResponseDiffEngine.calculate_value_similarity(
            json.dumps(owner), json.dumps(reordered)))
        self.assertEqual(0.0, ResponseDiffEngine.calculate_value_similarity(
            json.dumps(owner), json.dumps(duplicated)))

    def test_primitive_array_multiplicity_is_preserved(self):
        similarity = ResponseDiffEngine.calculate_value_similarity
        self.assertEqual(1.0, similarity('{"values":[1,2,1]}', '{"values":[1,1,2]}'))
        self.assertEqual(0.0, similarity('{"values":[1,2,1]}', '{"values":[1,2]}'))


if __name__ == "__main__":
    unittest.main()
