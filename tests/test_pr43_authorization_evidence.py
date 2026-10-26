"""Positive, negative and boundary evidence for the three new read-only checks."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.authorization import AuthorizationEvidence
from core.config_validator import ConfigValidator
from core.models import HTTPResult, Verdict
from core.parser import OpenAPIParser


def response(payload, status=200, **kwargs):
    return HTTPResult(status, json.dumps(payload), **kwargs)


class AuthorizationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.owner = response({"private_note": "Owner-private-unshared-value"})
        self.denied = response({"error": "Forbidden"}, 403)
        self.paths = ["private_note"]
        self.role_policy = {"required_role": "administrator", "owner_role": "administrator",
                            "visitor_role": "member"}

    def auth(self, anonymous=None, owner=None, **kwargs):
        options = {"requires_auth": True, "private_data_paths": self.paths}
        options.update(kwargs)
        return AuthorizationEvidence.evaluate_auth(
            owner or self.owner, anonymous or self.owner, **options,
        )

    def bfla(self, visitor=None, owner=None, anonymous=None, **kwargs):
        options = {"role_policy": self.role_policy, "private_data_paths": self.paths, "candidate": True}
        options.update(kwargs)
        return AuthorizationEvidence.evaluate_bfla(
            owner or self.owner, visitor or self.owner, anonymous or self.denied, **options,
        )

    def collection(self, visitor=None, owner=None, anonymous=None, **kwargs):
        options = {"policy": {"private_data_paths": self.paths}}
        options.update(kwargs)
        return AuthorizationEvidence.evaluate_collection(
            owner or self.owner, visitor or self.owner, anonymous or self.denied, **options,
        )

    def test_auth_confirms_only_positive_owner_private_data_exposure(self):
        result = self.auth()
        self.assertEqual(Verdict.CONFIRMED, result["verdict"])
        self.assertEqual(["private_note"], result["evidence"]["matched_private_data_paths"])
        self.assertNotIn("Owner-private-unshared-value", json.dumps(result))

    def test_auth_http_200_and_valid_public_data_are_only_candidates_without_private_policy(self):
        public = response({"title": "Public API documentation"})
        self.assertEqual(Verdict.SUSPICIOUS,
                         self.auth(public, owner=public, private_data_paths=[])["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE, self.auth(public)["verdict"])

    def test_auth_explicit_public_policy_needs_equivalent_complete_baselines(self):
        public = response({"title": "Public API documentation"})
        self.assertEqual(Verdict.PUBLIC, self.auth(public, owner=public, requires_auth=False,
                                                expected_public=True, private_data_paths=[])["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.auth(public, requires_auth=False, expected_public=True)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE, self.auth(expected_public=True)["verdict"])

    def test_auth_absent_auth_requirement_does_not_prove_sensitive_exposure(self):
        self.assertEqual(Verdict.INCONCLUSIVE, self.auth(requires_auth=False)["verdict"])

    def test_auth_public_policy_and_private_data_paths_are_contradictory(self):
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.auth(expected_public=True, requires_auth=False)["verdict"])

    def test_auth_clean_denial_is_secure_with_a_valid_owner_baseline(self):
        for status in (200, 401, 403):
            with self.subTest(status=status):
                self.assertEqual(Verdict.SECURE,
                                 self.auth(response({"message": "Authentication required"}, status))["verdict"])

    def test_auth_dirty_denial_is_never_secure(self):
        for payload in ({"error": "Forbidden", "private_note": "Owner-private-unshared-value"},
                        {"error": "Forbidden", "unknown_data": "unclassified business data"}):
            with self.subTest(payload=payload):
                result = self.auth(response(payload, 403))
                self.assertNotIn(result["verdict"], (Verdict.SECURE, Verdict.CONFIRMED))

    def test_auth_error_responses_with_matching_private_values_are_only_suspicious(self):
        for status in (200, 400, 401, 403, 404, 500):
            with self.subTest(status=status):
                error = response({"error": "Forbidden", "private_note": "Owner-private-unshared-value"}, status)
                self.assertEqual(Verdict.SUSPICIOUS, self.auth(error)["verdict"])

    def test_auth_empty_collection_error_and_invalid_json_are_not_confirmed(self):
        for anonymous in (response([]), response({}), response(None), response({"error": "failure"}),
                          HTTPResult(200, "<html>sign in</html>"), HTTPResult(204, "")):
            with self.subTest(anonymous=anonymous):
                self.assertNotEqual(Verdict.CONFIRMED, self.auth(anonymous)["verdict"])

    def test_auth_missing_owner_baseline_prevents_confirmation_or_secure_claim(self):
        for owner in (response([], 200), response({"error": "Not found"}, 404)):
            for anonymous in (self.owner, self.denied):
                with self.subTest(owner=owner, anonymous=anonymous):
                    self.assertEqual(Verdict.INCONCLUSIVE, self.auth(anonymous, owner=owner)["verdict"])

    def test_auth_truncation_and_transport_errors_never_confirm(self):
        for incomplete in (response({"private_note": "Owner-private-unshared-value"}, truncated=True),
                           response({"private_note": "Owner-private-unshared-value"}, error="timeout")):
            with self.subTest(incomplete=incomplete):
                self.assertEqual(Verdict.INCONCLUSIVE, self.auth(incomplete)["verdict"])
                self.assertEqual(Verdict.INCONCLUSIVE, self.auth(owner=incomplete)["verdict"])

    def test_bfla_explicit_roles_and_private_data_confirm_unauthorized_function_access(self):
        self.assertEqual(Verdict.CONFIRMED, self.bfla()["verdict"])

    def test_bfla_admin_keyword_without_explicit_roles_is_only_candidate(self):
        result = self.bfla(role_policy={})
        self.assertEqual(Verdict.SUSPICIOUS, result["verdict"])
        self.assertIn("explicit_privilege_boundary", result["evidence"]["missing_evidence"])

    def test_bfla_no_candidate_or_roles_has_no_privilege_conclusion(self):
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(role_policy={}, candidate=False)["verdict"])

    def test_bfla_public_policy_conflicts_with_required_privilege_or_private_data(self):
        policy = dict(self.role_policy, expected_public=True)
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(role_policy=policy)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.bfla(self.denied, role_policy=policy)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.bfla(role_policy={"expected_public": True})["verdict"])

    def test_bfla_incomplete_roles_cannot_confirm(self):
        for key in self.role_policy:
            with self.subTest(missing=key):
                policy = dict(self.role_policy)
                policy.pop(key)
                self.assertEqual(Verdict.SUSPICIOUS, self.bfla(role_policy=policy)["verdict"])

    def test_bfla_owner_is_not_automatically_an_administrator(self):
        policy = dict(self.role_policy, owner_role="member")
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(role_policy=policy)["verdict"])

    def test_bfla_visitor_with_required_role_is_authorized_after_positive_comparison(self):
        policy = dict(self.role_policy, visitor_role="administrator")
        self.assertEqual(Verdict.AUTHORIZED, self.bfla(role_policy=policy)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.bfla(response({"public_metrics": 12}), role_policy=policy)["verdict"])

    def test_bfla_role_names_are_exact_and_do_not_imply_hierarchy(self):
        policy = dict(self.role_policy, owner_role="Administrator")
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(role_policy=policy)["verdict"])

    def test_bfla_public_or_empty_http_200_response_has_no_positive_protected_evidence(self):
        for visitor in (response({"status": "ok"}), response([]), response({"error": "failure"})):
            with self.subTest(visitor=visitor):
                self.assertNotEqual(Verdict.CONFIRMED, self.bfla(visitor)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(private_data_paths=[])["verdict"])

    def test_bfla_clean_denial_requires_valid_privileged_and_anonymous_baselines(self):
        self.assertEqual(Verdict.SECURE, self.bfla(self.denied)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(self.denied, owner=response([]))["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(self.denied, anonymous=self.owner)["verdict"])

    def test_bfla_dirty_denial_cannot_prove_role_enforcement(self):
        dirty = response({"error": "Forbidden", "private_note": "Owner-private-unshared-value"}, 403)
        self.assertEqual(Verdict.SUSPICIOUS, self.bfla(dirty)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(anonymous=dirty)["verdict"])

    def test_bfla_unfinished_responses_are_inconclusive(self):
        incomplete = response({"private_note": "Owner-private-unshared-value"}, truncated=True)
        self.assertEqual(Verdict.INCONCLUSIVE, self.bfla(incomplete)["verdict"])

    def test_collection_leak_without_owner_id_is_confirmed_by_owner_private_baseline(self):
        owner = response([{"private_note": "Alice-private-order-contents"}])
        result = self.collection(owner, owner=owner, policy={"private_data_paths": ["[0].private_note"]})
        self.assertEqual(Verdict.CONFIRMED, result["verdict"])
        self.assertNotIn("1001", owner.body)

    def test_collection_owner_id_absence_does_not_imply_secure_isolation(self):
        result = self.collection(response({"private_note": "Visitor-other-data"}))
        self.assertEqual(Verdict.INCONCLUSIVE, result["verdict"])

    def test_collection_owner_id_substring_and_reflected_metadata_are_not_ownership(self):
        owner = response({"requested_user_id": "1001", "private_note": "Owner-private-value"})
        visitor = response({"requested_user_id": "1001", "private_note": "Visitor-owned-100100-data"})
        result = self.collection(visitor, owner=owner, policy={"private_data_paths": ["requested_user_id"]})
        self.assertEqual(Verdict.INCONCLUSIVE, result["verdict"])

    def test_collection_missing_private_policy_cannot_confirm_identical_business_bodies(self):
        self.assertEqual(Verdict.INCONCLUSIVE, self.collection(policy={})["verdict"])

    def test_collection_clean_denial_is_secure_only_for_denied_policy(self):
        self.assertEqual(Verdict.SECURE, self.collection(self.denied)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.collection(self.denied, policy={"expected_visitor_access": "allow"})["verdict"])

    def test_collection_explicit_sharing_needs_private_data_and_clean_anonymous_denial(self):
        policy = {"private_data_paths": self.paths, "expected_visitor_access": "allow"}
        self.assertEqual(Verdict.AUTHORIZED, self.collection(policy=policy)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.collection(response({"public": "overview"}), policy=policy)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.collection(anonymous=self.owner, policy=policy)["verdict"])

    def test_collection_explicit_public_policy_needs_all_three_equivalent_baselines(self):
        policy = {"expected_public": True}
        self.assertEqual(Verdict.PUBLIC,
                         self.collection(anonymous=self.owner, policy=policy, requires_auth=False)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.collection(policy=policy, requires_auth=False)["verdict"])
        self.assertEqual(Verdict.INCONCLUSIVE, self.collection(policy=policy)["verdict"])

    def test_collection_public_policy_conflicts_with_private_data_assertion(self):
        policy = {"expected_public": True, "private_data_paths": self.paths}
        self.assertEqual(Verdict.INCONCLUSIVE,
                         self.collection(anonymous=self.owner, policy=policy, requires_auth=False)["verdict"])

    def test_collection_missing_owner_data_cannot_be_secure_or_confirmed(self):
        for owner in (response([]), response({"error": "Not found"}, 404)):
            for visitor in (self.owner, self.denied):
                with self.subTest(owner=owner, visitor=visitor):
                    self.assertEqual(Verdict.INCONCLUSIVE, self.collection(visitor, owner=owner)["verdict"])

    def test_collection_empty_error_or_truncated_visitor_response_cannot_be_secure(self):
        for visitor in (response([]), response({"error": "failure"}),
                        response({"private_note": "Owner-private-unshared-value"}, truncated=True)):
            with self.subTest(visitor=visitor):
                self.assertNotIn(self.collection(visitor)["verdict"], (Verdict.SECURE, Verdict.CONFIRMED))

    def test_collection_dirty_visitor_denial_with_owner_values_is_only_suspicious(self):
        dirty = response({"error": "Forbidden", "private_note": "Owner-private-unshared-value"}, 403)
        self.assertEqual(Verdict.SUSPICIOUS, self.collection(dirty)["verdict"])

    def test_private_values_use_strict_json_types(self):
        owner = response({"private_note": 1})
        for visitor in (response({"private_note": True}), response({"private_note": "1"}),
                        response({"private_note": 1.0})):
            with self.subTest(visitor=visitor):
                self.assertEqual(Verdict.INCONCLUSIVE, self.collection(visitor, owner=owner)["verdict"])

    def test_empty_or_boolean_values_and_metadata_never_establish_private_identity(self):
        for value in (None, "", "  ", True, False, {}, []):
            with self.subTest(value=value):
                body = response({"private_note": value})
                self.assertNotEqual(Verdict.CONFIRMED, self.collection(body, owner=body)["verdict"])
        for path in ("request.private_note", "metadata.private_note", "message", "trace_id"):
            with self.subTest(path=path):
                body = response({"request": {"private_note": "owner"}, "metadata": {"private_note": "owner"},
                                 "message": "owner", "trace_id": "owner"})
                self.assertEqual(Verdict.INCONCLUSIVE,
                                 self.collection(body, owner=body, policy={"private_data_paths": [path]})["verdict"])

    def test_exact_array_paths_do_not_guess_other_positions_or_match_substrings(self):
        owner = response({"items": [{"private_note": "Owner-secret"}]})
        for visitor in (response({"items": [{"private_note": "Owner-secret-extra"}]}),
                        response({"items": [{"private_note": "Visitor"}, {"private_note": "Owner-secret"}]})):
            with self.subTest(visitor=visitor):
                self.assertEqual(Verdict.INCONCLUSIVE,
                                 self.collection(visitor, owner=owner,
                                                 policy={"private_data_paths": ["items[0].private_note"]})["verdict"])


class AuthorizationPolicyConfigurationTests(unittest.TestCase):
    def validate(self, **policy):
        return ConfigValidator.validate({"bola": {"GET /collections": policy}})

    def test_offline_validator_accepts_explicit_private_and_role_policies(self):
        result = self.validate(private_data_paths=["data.items[0].private_note", "[0].invoice_number"],
                               required_role="administrator", owner_role="administrator", visitor_role="member")
        self.assertTrue(result.is_valid, result.errors)

    def test_private_path_validation_rejects_wrong_types_wildcards_and_malformed_paths(self):
        for paths in (None, "private_note", [None], [""], [" items[0].note"], ["items[].note"],
                      ["items[-1].note"], ["items..note"], ["items[0]garbage"]):
            with self.subTest(paths=paths):
                result = self.validate(private_data_paths=paths)
                self.assertFalse(result.is_valid)
                self.assertTrue(any(issue.path.endswith(".private_data_paths") for issue in result.errors))

    def test_role_validation_rejects_non_string_empty_whitespace_and_controls(self):
        for key in ("required_role", "owner_role", "visitor_role"):
            for value in (None, True, 1, [], {}, "", " ", " admin", "admin ", "ad\nmin", "ad\x00min"):
                with self.subTest(key=key, value=value):
                    result = self.validate(**{key: value})
                    self.assertFalse(result.is_valid)
                    self.assertTrue(any(issue.path.endswith("." + key) for issue in result.errors))

    def test_incomplete_role_policy_is_valid_input_but_cannot_confirm_privilege(self):
        self.assertTrue(self.validate(required_role="administrator").is_valid)

    def test_json_schema_and_semantic_validator_share_new_policy_fields(self):
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "config.schema.json").read_text(encoding="utf-8"))
        fields = schema["definitions"]["bola_entry"]["properties"]
        for key in ("private_data_paths", "required_role", "owner_role", "visitor_role"):
            self.assertIn(key, fields)
            self.assertIn(key, ConfigValidator.KNOWN_BOLA_KEYS)


class OpenAPISecurityInheritanceTests(unittest.TestCase):
    def test_global_and_operation_security_are_preserved_without_role_inference(self):
        for version in ("3.0.3", "2.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as folder:
                spec = {"info": {"title": "Security inheritance", "version": "1"},
                        "security": [{"globalBearer": []}], "paths": {
                            "/inherited": {"get": {}},
                            "/public": {"get": {"security": []}},
                            "/optional": {"get": {"security": [{}, {"globalBearer": []}]}},
                            "/override": {"get": {"security": [{"operationKey": []}]}},
                        }}
                spec["swagger" if version == "2.0" else "openapi"] = version
                path = Path(folder) / "spec.json"
                path.write_text(json.dumps(spec), encoding="utf-8")
                endpoints = {ep["path"]: ep for ep in OpenAPIParser(str(path)).get_endpoints()}
                self.assertEqual([{"globalBearer": []}], endpoints["/inherited"]["security"])
                self.assertEqual([], endpoints["/public"]["security"])
                self.assertEqual([{}, {"globalBearer": []}], endpoints["/optional"]["security"])
                self.assertEqual([{"operationKey": []}], endpoints["/override"]["security"])
                self.assertTrue(all(ep["security_declared"] for ep in endpoints.values()))
                for ep in endpoints.values():
                    self.assertNotIn("required_role", ep)

    def test_absent_security_is_distinct_from_explicit_public_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            spec = {"openapi": "3.0.3", "info": {"title": "No security", "version": "1"},
                    "paths": {"/unknown": {"get": {}}}}
            path = Path(folder) / "spec.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            endpoint = OpenAPIParser(str(path)).get_endpoints()[0]
            self.assertEqual([], endpoint["security"])
            self.assertFalse(endpoint["security_declared"])


class AuthorizationAuditorWiringTests(unittest.TestCase):
    def test_openapi_public_or_optional_security_cannot_be_overridden_by_role_candidate(self):
        for security in ([], [{}], [{}, {"bearerAuth": []}]):
            with self.subTest(security=security), tempfile.TemporaryDirectory() as folder:
                spec = {"openapi": "3.0.3", "info": {"title": "Explicit public role conflict", "version": "1"},
                        "security": [{"globalAuth": []}], "paths": {
                            "/api/admin/config": {"get": {"security": security}},
                        }}
                path = Path(folder) / "spec.json"
                path.write_text(json.dumps(spec), encoding="utf-8")
                policy = {"private_data_paths": ["cluster_secret"], "required_role": "administrator",
                          "owner_role": "administrator", "visitor_role": "member"}
                auditor = APISentinelAuditor(str(path), "http://127.0.0.1:1", request_delay=0,
                                            bola_config={"GET /api/admin/config": policy})
                data = response({"cluster_secret": "Owner-private-cluster-secret"})
                denied = response({"error": "Forbidden"}, 403)
                with patch.object(auditor, "_http_request", side_effect=[data, data, denied]) as http:
                    auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
                self.assertEqual(3, http.call_count)
                result = next(item for item in auditor.results if item["check"] == "BFLA")
                self.assertEqual("INCONCLUSIVE", result["verdict"])
                self.assertEqual([], auditor.findings)

    def test_invalid_private_policy_stops_a_collection_before_transport(self):
        with tempfile.TemporaryDirectory() as folder:
            spec = {"openapi": "3.0.3", "info": {"title": "Invalid policy", "version": "1"},
                    "paths": {"/collections": {"get": {"security": [{"bearerAuth": []}]}}}}
            path = Path(folder) / "spec.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            auditor = APISentinelAuditor(str(path), "http://127.0.0.1:1", request_delay=0,
                                        bola_config={"GET /collections": {"private_data_paths": ["items[].secret"]}})
            with patch.object(auditor, "_http_request") as http:
                auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
            http.assert_not_called()
            self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
            self.assertEqual("invalid_input", auditor.results[0]["evidence"]["reason_category"])


if __name__ == "__main__":
    unittest.main()
