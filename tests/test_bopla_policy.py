"""Exact property authorization evidence; all canaries are synthetic."""

import copy
import json
import unittest
from pathlib import Path

from core.bopla import BOPLAEvidence, validate_bopla_policy
from core.config_validator import ConfigValidator
from core.models import HTTPResult, Verdict


CANARY = "SYNTHETIC-owner-only-project-note-8314"


def policy(path="private_note", binding=None):
    return {"policy_id": "document-fields-v1", "context_id": "selected-owner-document",
            "resource_binding": binding or {"id": "1001"},
            "fields": [{"rule_id": "private-note", "path": path,
                        "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                        "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}


def response(payload, status=200, **kwargs):
    return HTTPResult(status, json.dumps(payload), **kwargs)


class BOPLAPolicyTests(unittest.TestCase):
    def evaluate(self, other=None, owner=None, configured=None, identity="visitor", **kwargs):
        configured = configured if configured is not None else policy()
        result = BOPLAEvidence.evaluate(
            owner or response({"id": "1001", "title": "Shared", "private_note": CANARY}),
            other or response({"id": "1001", "title": "Shared", "private_note": CANARY}),
            policy=configured, field=configured["fields"][0], identity=identity, **kwargs,
        )
        self.assertNotIn(CANARY, json.dumps(result))
        return result

    def test_shared_object_private_field_is_confirmed(self):
        result = self.evaluate()
        self.assertEqual(Verdict.CONFIRMED, result["verdict"])
        self.assertTrue(result["evidence"]["owner_baseline_valid"])
        self.assertTrue(result["evidence"]["resource_binding_valid"])
        self.assertEqual(["private_note"], result["evidence"]["matched_private_data_paths"])

    def test_public_object_anonymous_private_field_is_confirmed(self):
        self.assertEqual(Verdict.CONFIRMED, self.evaluate(identity="anonymous")["verdict"])

    def test_nested_field_is_compared_at_its_exact_path(self):
        data = response({"id": "1001", "profile": {"note": CANARY}})
        result = self.evaluate(data, data, policy("profile.note"))
        self.assertEqual(Verdict.CONFIRMED, result["verdict"])
        self.assertEqual(["profile.note"], result["evidence"]["matched_private_data_paths"])

    def test_array_field_needs_same_entry_and_fixed_index(self):
        configured = policy("items[0].note", {"items[0].id": "1001"})
        owner = response({"items": [{"id": "1001", "note": CANARY}]})
        self.assertEqual(Verdict.CONFIRMED, self.evaluate(owner, owner, configured)["verdict"])
        moved = response({"items": [{"id": "1002", "note": "different"},
                                    {"id": "1001", "note": CANARY}]})
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(moved, owner, configured)["verdict"])

    def test_repeated_array_entity_is_ambiguous(self):
        configured = policy("items[0].note", {"items[0].id": "1001"})
        data = response({"items": [{"id": "1001", "note": CANARY}, {"id": "1001", "note": CANARY}]})
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(data, data, configured)["verdict"])

    def test_same_name_different_value_or_path_never_confirms(self):
        for payload in ({"id": "1001", "private_note": "different"},
                        {"id": "1001", "other": {"private_note": CANARY}},
                        {"id": "1001", "private_note": CANARY + "-suffix"}):
            with self.subTest(payload=payload):
                self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(response(payload))["verdict"])

    def test_visitor_own_resource_even_with_same_private_value_is_not_confirmed(self):
        result = self.evaluate(response({"id": "1002", "private_note": CANARY}))
        self.assertEqual(Verdict.INCONCLUSIVE, result["verdict"])
        self.assertFalse(result["evidence"]["resource_binding_valid"])

    def test_composite_tenant_binding_is_required(self):
        configured = policy(binding={"id": "1001", "tenant_id": "tenant-a"})
        owner = response({"id": "1001", "tenant_id": "tenant-a", "private_note": CANARY})
        other = response({"id": "1001", "tenant_id": "tenant-b", "private_note": CANARY})
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(other, owner, configured)["verdict"])

    def test_value_also_present_in_visitor_self_baseline_is_not_identifying(self):
        own = response({"id": "1002", "private_note": CANARY})
        result = self.evaluate(visitor_self=own)
        self.assertEqual(Verdict.INCONCLUSIVE, result["verdict"])
        self.assertIn("resource_specific_value", result["evidence"]["missing_evidence"])

    def test_explicit_field_sharing_is_authorized(self):
        configured = policy()
        configured["fields"][0]["access"]["visitor"] = "allow"
        self.assertEqual(Verdict.AUTHORIZED, self.evaluate(configured=configured)["verdict"])

    def test_missing_identity_rule_never_defaults_to_deny_or_secure(self):
        configured = policy()
        del configured["fields"][0]["access"]["visitor"]
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(configured=configured)["verdict"])

    def test_missing_business_attestation_cannot_confirm_common_values(self):
        for key in ("baseline_representation", "value_is_resource_specific"):
            configured = policy()
            del configured["fields"][0][key]
            self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(configured=configured)["verdict"])

    def test_invalid_owner_prevents_confirmation_and_secure(self):
        for owner in (response({"error": "Not found"}, 404), response({}),
                      response({"id": "1002", "private_note": CANARY}),
                      response({"id": "1001", "private_note": CANARY}, truncated=True)):
            for other in (response({"id": "1001", "private_note": CANARY}), response({"error": "Forbidden"}, 403)):
                with self.subTest(owner=owner, other=other):
                    self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(other, owner)["verdict"])

    def test_error_body_matching_private_data_is_only_suspicious(self):
        for status in (200, 401, 403, 500):
            with self.subTest(status=status):
                other = response({"error": "Forbidden", "id": "1001", "private_note": CANARY}, status)
                self.assertEqual(Verdict.SUSPICIOUS, self.evaluate(other)["verdict"])

    def test_clean_denial_is_only_local_secure_with_valid_rule_and_baseline(self):
        result = self.evaluate(response({"error": "Forbidden"}, 403))
        self.assertEqual(Verdict.SECURE, result["verdict"])
        self.assertTrue(result["evidence"]["denial_body_clean"])

    def test_empty_missing_masked_or_unfinished_data_is_inconclusive(self):
        for value in (None, "", True, "***", "SYNTHETIC-owner-***"):
            other = response({"id": "1001", "private_note": value})
            self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(other)["verdict"])
        for other in (response({"id": "1001"}), response({"id": "1001", "private_note": CANARY}, 206),
                      response({"id": "1001", "private_note": CANARY}, truncated=True),
                      response({"id": "1001", "private_note": CANARY}, error="timeout"),
                      response({"id": "1001", "private_note": CANARY}, headers={"Content-Range": "bytes 0-9/100"})):
            self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(other)["verdict"])

    def test_owner_masked_value_is_not_a_full_private_reference(self):
        data = response({"id": "1001", "private_note": "[REDACTED]"})
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(data, data)["verdict"])

    def test_json_types_do_not_coerce(self):
        owner = response({"id": "1001", "private_note": 913724})
        for value in ("913724", 913724.0, True):
            other = response({"id": "1001", "private_note": value})
            self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(other, owner)["verdict"])
        self.assertEqual(Verdict.CONFIRMED, self.evaluate(owner, owner)["verdict"])

    def test_duplicate_json_keys_are_ambiguous(self):
        other = HTTPResult(200, '{"id":"1002","id":"1001","private_note":' + json.dumps(CANARY) + '}')
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(other)["verdict"])

    def test_metadata_and_binding_paths_cannot_be_private_identity_evidence(self):
        configured = policy("id")
        self.assertTrue(validate_bopla_policy(configured))
        configured = policy("request.private_note")
        data = response({"id": "1001", "request": {"private_note": CANARY}})
        self.assertNotEqual(Verdict.CONFIRMED, self.evaluate(data, data, configured)["verdict"])


class BOPLAValidationTests(unittest.TestCase):
    def test_valid_policy_and_schema(self):
        configured = policy()
        self.assertEqual([], validate_bopla_policy(configured))
        self.assertTrue(ConfigValidator.validate({"bopla": {"GET /documents/{id}": configured}}).is_valid)
        schema = json.loads((Path(__file__).resolve().parents[1] / "config.schema.json").read_text())
        self.assertIn("bopla", schema["properties"])

    def test_bad_config_diagnostics_do_not_echo_private_values(self):
        for configured in (None, {"resource_binding": {CANARY: CANARY}},
                           {**policy(), CANARY: CANARY}):
            result = ConfigValidator.validate({"bopla": {"GET /documents/{id}": configured}})
            self.assertFalse(result.is_valid)
            self.assertNotIn(CANARY, str(result.issues))

    def test_non_get_and_unknown_spec_operation_are_rejected(self):
        for key in ("POST /documents", "GET /absent"):
            spec = {"openapi": "3.0.3", "paths": {"/documents": {"get": {"responses": {"200": {"description": "OK"}}}}}}
            self.assertFalse(ConfigValidator.validate({"bopla": {key: policy()}}, spec).is_valid)

    def test_missing_attestations_and_identity_permission_are_valid_but_insufficient(self):
        configured = policy()
        del configured["fields"][0]["value_is_resource_specific"]
        del configured["fields"][0]["access"]["visitor"]
        self.assertEqual([], validate_bopla_policy(configured))

    def test_conflicts_wildcards_and_array_without_entry_anchor_are_invalid(self):
        invalid = []
        duplicate = policy()
        duplicate["fields"].append(copy.deepcopy(duplicate["fields"][0]))
        invalid.append(duplicate)
        conflicting = policy()
        conflicting["fields"].append({"rule_id": "nested", "path": "private_note.child", "access": {"owner": "allow"}})
        invalid.append(conflicting)
        for path in ("items[].note", "items[*].note", "items[0].note", " private_note", "private_note\n"):
            invalid.append(policy(path))
        for configured in invalid:
            with self.subTest(configured=configured):
                self.assertTrue(validate_bopla_policy(configured))

    def test_array_resource_anchor_must_select_an_object_property(self):
        self.assertTrue(validate_bopla_policy(policy(binding={"items[0]": "1001"})))

    def test_nonfinite_and_unbounded_numeric_binding_diagnostics_are_safe(self):
        for value in (float("inf"), float("nan"), 10 ** 1000):
            configured = policy(binding={"id": value})
            result = ConfigValidator.validate({"bopla": {"GET /documents/{id}": configured}})
            self.assertFalse(result.is_valid)
            self.assertNotIn(str(value), str(result.issues))


if __name__ == "__main__":
    unittest.main()
