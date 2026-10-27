"""Independent final-review counterexamples for PR44 policy and leak grouping.

Every payload is synthetic. Transport is isolated so these tests exercise the
production auditor/evaluator without contacting any external API.
"""

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from core.auditor import APISentinelAuditor
from core.bopla import BOPLAEvidence, resource_scope, validate_bopla_policy
from core.models import HTTPResult, Verdict
from core.reporter import SecurityReportGenerator
from core.sarif import SarifReportGenerator


SECRET_A = "independent-owner-private-note-54bd9"
SECRET_B = "independent-owner-private-extra-7ce31"


def http(payload, status=200, **kwargs):
    return HTTPResult(status, json.dumps(payload), **kwargs)


def rule(path="private_note", *, rule_id="note", visitor="deny", anonymous="deny"):
    return {"rule_id": rule_id, "path": path, "baseline_representation": "full_private_value",
            "value_is_resource_specific": True,
            "access": {"owner": "allow", "visitor": visitor, "anonymous": anonymous}}


def policy(*fields, bindings=None):
    return {"policy_id": "independent-field-policy", "context_id": "tenant-a-member-context",
            "resource_binding": bindings if bindings is not None else {"id": "resource-a", "tenant_id": "tenant-a"},
            "fields": list(fields) if fields else [rule()]}


def document(**extra):
    return {"id": "resource-a", "tenant_id": "tenant-a", "private_note": SECRET_A, **extra}


class IndependentPolicyTests(unittest.TestCase):
    def evaluate(self, owner, other, configured=None, *, identity="visitor", index=0, self_response=None):
        configured = configured if configured is not None else policy()
        return BOPLAEvidence.evaluate(owner, other, policy=configured,
                                      field=configured["fields"][index], identity=identity,
                                      visitor_self=self_response)

    def test_public_object_does_not_grant_a_denied_anonymous_field(self):
        data = http(document())
        result = self.evaluate(data, data, identity="anonymous")
        self.assertEqual(Verdict.CONFIRMED, result["verdict"])
        self.assertTrue(result["evidence"]["resource_bound"])

    def test_explicit_visitor_field_allow_is_authorized_and_never_a_leak(self):
        configured = policy(rule(visitor="allow"))
        result = self.evaluate(http(document()), http(document()), configured)
        self.assertEqual(Verdict.AUTHORIZED, result["verdict"])

    def test_missing_subject_permission_does_not_default_to_deny(self):
        configured = policy()
        configured["fields"][0]["access"].pop("visitor")
        result = self.evaluate(http(document()), http(document()), configured)
        self.assertEqual(Verdict.INCONCLUSIVE, result["verdict"])
        self.assertIn("identity_field_permission", result["evidence"]["missing_evidence"])

    def test_invalid_null_or_partial_owner_cannot_support_confirmed_or_secure(self):
        own = [http(document(private_note=None)), http(document(private_note="[MASKED]")),
               http(document(private_note="prefix-***-tail")), http({"id": "resource-a", "tenant_id": "tenant-a"}),
               http(document(), status=206), http(document(), truncated=True),
               http(document(), error="independent timeout"),
               http(document(), headers={"Content-Range": "items 0-0/10"}),
               http({"error": "Forbidden"}, status=403)]
        for owner in own:
            for low in (http(document()), http({"error": "Forbidden"}, status=403)):
                with self.subTest(owner_status=owner.status, low_status=low.status,
                                  owner_body=owner.body, truncated=owner.truncated, error=owner.error):
                    self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(owner, low)["verdict"])

    def test_recognizable_bullet_mask_is_not_an_identifiable_full_private_owner_value(self):
        for masked in ("••••", "••••1234", "…"):
            with self.subTest(mask=masked):
                masked_response = http(document(private_note=masked))
                result = self.evaluate(masked_response, masked_response)
                self.assertEqual(Verdict.INCONCLUSIVE, result["verdict"])

    def test_same_private_value_cannot_override_resource_or_tenant_binding(self):
        for changed in ({"id": "resource-b"}, {"tenant_id": "tenant-b"},
                        {"id": "resource-b", "tenant_id": "tenant-b"}):
            with self.subTest(changed=changed):
                result = self.evaluate(http(document()), http(document(**changed)))
                self.assertEqual(Verdict.INCONCLUSIVE, result["verdict"])
                self.assertFalse(result["evidence"]["resource_bound"])

    def test_fixed_array_slot_with_different_entity_or_duplicate_id_is_not_bound(self):
        configured = policy(rule("items[0].private_note"), bindings={"items[0].id": "resource-a"})
        owner = http({"items": [{"id": "resource-a", "private_note": SECRET_A},
                                 {"id": "resource-b", "private_note": SECRET_B}]})
        cases = [http({"items": [{"id": "resource-b", "private_note": SECRET_A},
                                  {"id": "resource-a", "private_note": SECRET_A}]}),
                 http({"items": [{"id": "resource-a", "private_note": SECRET_A},
                                  {"id": "resource-a", "private_note": SECRET_B}]})]
        for low in cases:
            with self.subTest(body=low.body):
                self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(owner, low, configured)["verdict"])

    def test_nested_array_binding_is_checked_at_every_selected_entry(self):
        configured = policy(rule("teams[0].documents[0].private_note"),
                            bindings={"teams[0].id": "tenant-a",
                                      "teams[0].documents[0].id": "resource-a"})
        owner = {"teams": [{"id": "tenant-a", "documents": [{"id": "resource-a", "private_note": SECRET_A}]}]}
        self.assertEqual([], validate_bopla_policy(configured))
        self.assertEqual(Verdict.CONFIRMED, self.evaluate(http(owner), http(owner), configured)["verdict"])
        other = copy.deepcopy(owner)
        other["teams"][0]["documents"][0]["id"] = "resource-b"
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(http(owner), http(other), configured)["verdict"])

    def test_composite_array_anchor_remains_unique_when_tenant_is_shared(self):
        configured = policy(rule("items[0].private_note"),
                            bindings={"items[0].id": "resource-a", "items[0].tenant_id": "tenant-a"})
        payload = http({"items": [{"id": "resource-a", "tenant_id": "tenant-a", "private_note": SECRET_A},
                                   {"id": "resource-b", "tenant_id": "tenant-a", "private_note": SECRET_B}]})
        self.assertEqual([], validate_bopla_policy(configured))
        self.assertEqual(Verdict.CONFIRMED, self.evaluate(payload, payload, configured)["verdict"])

    def test_duplicate_full_composite_array_identity_is_still_ambiguous(self):
        configured = policy(rule("items[0].private_note"),
                            bindings={"items[0].id": "resource-a", "items[0].tenant_id": "tenant-a"})
        payload = http({"items": [{"id": "resource-a", "tenant_id": "tenant-a", "private_note": SECRET_A},
                                   {"id": "resource-a", "tenant_id": "tenant-a", "private_note": SECRET_B}]})
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(payload, payload, configured)["verdict"])

    def test_low_privilege_error_data_is_only_suspicious(self):
        for status in (200, 401, 403, 409, 500):
            with self.subTest(status=status):
                low = http(document(error="Forbidden"), status=status)
                self.assertEqual(Verdict.SUSPICIOUS, self.evaluate(http(document()), low)["verdict"])

    def test_timeout_and_truncation_cannot_use_matching_partial_data(self):
        for low in (http(document(), error="timeout"), http(document(), truncated=True),
                    http(document(), headers={"content-range": "bytes 0-50/100"})):
            with self.subTest(error=low.error, truncated=low.truncated, headers=low.headers):
                self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(http(document()), low)["verdict"])

    def test_field_name_readonly_and_equal_status_do_not_replace_a_policy_attestation(self):
        configured = policy(rule("password"))
        configured["fields"][0].pop("value_is_resource_specific")
        payload = http(document(password=SECRET_A))
        self.assertEqual(Verdict.INCONCLUSIVE, self.evaluate(payload, payload, configured)["verdict"])


class IndependentAuditorGroupingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="granttrace-pr44-independent-policy-")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.calls = []

    def auditor(self, configured, *, path="/documents/{id}", public=False, legacy=None):
        operation = {"security": [] if public else [{"bearer": []}],
                     "parameters": [{"name": "id", "in": "path", "required": True,
                                     "schema": {"type": "string"}}] if "{" in path else [],
                     "responses": {"200": {"description": "Independent final review"}}}
        source = self.folder / "spec.json"
        source.write_text(json.dumps({"openapi": "3.0.3", "paths": {path: {"get": operation}}}), encoding="utf-8")
        identities = {"owner": {"id": "resource-a", "parameters": {"id": "resource-a"}, "token": "Bearer OWNER"},
                      "visitor": {"id": "visitor-self", "parameters": {"id": "visitor-self"}, "token": "Bearer VISITOR"},
                      "anonymous": {}}
        key = "GET " + path
        return APISentinelAuditor(str(source), "http://127.0.0.1:1", request_delay=0,
                                  identities_config=identities, bopla_config={key: configured} if configured else {},
                                  bola_config={key: legacy if legacy is not None else {"expected_visitor_access": "allow"}})

    def scan(self, auditor, owner, *, visitor=None, anonymous=None):
        visitor = visitor if visitor is not None else owner
        anonymous = anonymous if anonymous is not None else http({"error": "Forbidden"}, status=403)

        def isolated(method, url, data=None, identity_name="anonymous", **unused):
            self.calls.append((method, url, identity_name))
            self.assertEqual("GET", method)
            if identity_name == "visitor" and urlsplit(url).path.endswith("visitor-self"):
                return http({"id": "visitor-self", "tenant_id": "tenant-a", "private_note": "visitor-own-note"})
            return {"owner": owner, "visitor": visitor, "anonymous": anonymous}[identity_name]

        with patch.object(auditor, "_http_request", side_effect=isolated), redirect_stdout(io.StringIO()):
            auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
        auditor.stats["total_endpoints"] = 1
        auditor._finalise_coverage()
        return [item for item in auditor.results if item["check"] == "BOPLA"]

    def test_shared_object_allow_preserves_denied_field_confirmation(self):
        auditor = self.auditor(policy())
        fields = self.scan(auditor, http(document()))
        self.assertEqual("AUTHORIZED", next(item["verdict"] for item in auditor.results if item["check"] == "BOLA"))
        self.assertEqual("CONFIRMED", next(item["verdict"] for item in fields
                                           if item["evidence"]["decision_evidence"]["subject_identity"] == "visitor"))
        self.assertEqual(4, len(self.calls))

    def test_two_denied_fields_on_one_resource_are_one_read_leak_with_all_field_evidence(self):
        auditor = self.auditor(policy(rule(), rule("extra_note", rule_id="extra")))
        fields = self.scan(auditor, http(document(extra_note=SECRET_B)))
        confirmed = [item for item in fields if item["verdict"] == "CONFIRMED"]
        self.assertEqual({"private_note", "extra_note"},
                         {item["evidence"]["decision_evidence"]["field_path"] for item in confirmed})
        self.assertEqual(1, len({item["evidence"]["leak_group"] for item in confirmed}))
        self.assertEqual(1, auditor.stats["unique_confirmed_vulnerabilities"])
        self.assertEqual(2, auditor.stats["bopla_fields_confirmed"])
        self.assertEqual(4, len(self.calls))

    def test_two_distinct_array_resources_do_not_lose_an_independent_leak(self):
        configured = policy(rule("items[0].private_note", rule_id="item-a"),
                            rule("items[1].private_note", rule_id="item-b"),
                            bindings={"items[0].id": "resource-a", "items[1].id": "resource-b"})
        auditor = self.auditor(configured, path="/collection", public=True)
        payload = http({"items": [{"id": "resource-a", "private_note": SECRET_A},
                                   {"id": "resource-b", "private_note": SECRET_B}]})
        fields = self.scan(auditor, payload)
        confirmed = [item for item in fields if item["verdict"] == "CONFIRMED"]
        self.assertEqual(2, len(confirmed))
        self.assertEqual(2, len({item["evidence"]["leak_group"] for item in confirmed}))
        self.assertEqual(2, auditor.stats["unique_confirmed_vulnerabilities"])
        self.assertEqual(3, len(self.calls))

    def test_two_selected_resources_at_same_url_and_context_are_not_deduplicated(self):
        auditor = self.auditor(policy(), path="/selected-document", public=True)
        self.scan(auditor, http(document()))
        second = policy(bindings={"id": "resource-b", "tenant_id": "tenant-a"})
        auditor.bopla_config["GET /selected-document"] = second
        self.scan(auditor, http(document(id="resource-b", private_note=SECRET_B)))
        self.assertEqual(2, len([item for item in auditor.results
                                 if item["check"] == "BOPLA" and item["verdict"] == "CONFIRMED"]))
        self.assertEqual(2, auditor.stats["unique_confirmed_vulnerabilities"])
        self.assertEqual(2, auditor.stats["bopla_fields_confirmed"])

    def test_two_low_privilege_identities_have_distinct_leak_groups(self):
        auditor = self.auditor(policy(), public=True)
        payload = http(document())
        fields = self.scan(auditor, payload, anonymous=payload)
        confirmed = [item for item in fields if item["verdict"] == "CONFIRMED"]
        self.assertEqual(2, len(confirmed))
        self.assertEqual(2, len({item["evidence"]["leak_group"] for item in confirmed}))
        self.assertEqual(2, auditor.stats["unique_confirmed_vulnerabilities"])

    def test_bfla_and_bopla_shared_response_preserve_each_detection_and_type_counter(self):
        legacy = {"expected_visitor_access": "deny", "private_data_paths": ["private_note"],
                  "required_role": "administrator", "owner_role": "administrator", "visitor_role": "member"}
        auditor = self.auditor(policy(), path="/admin/documents/{id}", legacy=legacy)
        fields = self.scan(auditor, http(document()))
        self.assertTrue(any(item["verdict"] == "CONFIRMED" for item in fields))
        for check in ("BOLA", "BFLA", "BOPLA"):
            self.assertTrue(any(item["check"] == check and item["verdict"] == "CONFIRMED"
                                for item in auditor.results), check)
        confirmed_bfla = sum(item["check"] == "BFLA" and item["verdict"] == "CONFIRMED"
                             for item in auditor.results)
        self.assertEqual(confirmed_bfla, auditor.stats["bfla_confirmed"])
        self.assertEqual(4, len(self.calls))

    def test_without_bopla_no_property_result_is_synthesized(self):
        auditor = self.auditor(None, legacy={"expected_visitor_access": "deny"})
        self.assertEqual([], self.scan(auditor, http(document())))
        self.assertEqual("CONFIRMED", next(item["verdict"] for item in auditor.results if item["check"] == "BOLA"))
        self.assertEqual(1, auditor.stats["confirmed"])
        self.assertEqual(4, len(self.calls))

    def test_missing_object_selector_still_compares_selected_field_safely(self):
        auditor = self.auditor(policy(), path="/selected-document", public=True)
        fields = self.scan(auditor, http(document()))
        self.assertEqual("SKIPPED", next(item["verdict"] for item in auditor.results if item["check"] == "BOLA"))
        self.assertTrue(any(item["verdict"] == "CONFIRMED" for item in fields))
        self.assertEqual(3, len(self.calls))

    def test_error_in_legacy_bola_does_not_upgrade_field_timeout_to_confirmation(self):
        auditor = self.auditor(policy())
        fields = self.scan(auditor, http(document()), visitor=http(document(), error="independent timeout"))
        self.assertEqual("ERROR", next(item["verdict"] for item in auditor.results if item["check"] == "BOLA"))
        visitor = next(item for item in fields if item["evidence"]["decision_evidence"]["subject_identity"] == "visitor")
        self.assertEqual("INCONCLUSIVE", visitor["verdict"])

    def test_repeated_resource_observations_and_added_field_do_not_add_a_leak_root(self):
        configured = policy()
        auditor = self.auditor(configured)
        self.scan(auditor, http(document()))
        configured["fields"].append(rule("extra_note", rule_id="extra"))
        fields = self.scan(auditor, http(document(extra_note=SECRET_B)))
        confirmed = [item for item in fields if item["verdict"] == "CONFIRMED"]
        self.assertEqual(3, len(confirmed))
        self.assertEqual(1, len({item["evidence"]["resource_group"] for item in confirmed}))
        self.assertEqual(1, auditor.stats["unique_confirmed_vulnerabilities"])
        self.assertEqual(2, auditor.stats["bopla_fields_confirmed"])

    def test_internal_resource_scope_is_opaque_in_results_and_exports(self):
        selected_id = "internal-only-resource-binding-651ad"
        configured = policy(bindings={"id": selected_id, "tenant_id": "tenant-a"})
        auditor = self.auditor(configured, path="/selected-document", public=True)
        fields = self.scan(auditor, http(document(id=selected_id)))
        confirmed = next(item for item in fields if item["verdict"] == "CONFIRMED")
        self.assertIs(type(confirmed["evidence"]["resource_group"]), int)
        html, sarif = self.folder / "scope.html", self.folder / "scope.sarif"
        SecurityReportGenerator.generate(auditor.stats, auditor.findings, auditor.target_base_url,
                                         str(html), results=auditor.results)
        SarifReportGenerator.generate(results=auditor.results, target_url=auditor.target_base_url,
                                      output_path=str(sarif))
        digest = hashlib.sha256(selected_id.encode()).hexdigest()
        for output in (json.dumps(auditor.results), json.dumps(auditor.findings),
                       html.read_text(encoding="utf-8"), sarif.read_text(encoding="utf-8")):
            self.assertNotIn(selected_id, output)
            self.assertNotIn(digest, output)

    def test_same_url_context_distinguishes_exact_json_resource_key_types(self):
        auditor = self.auditor(policy(bindings={"id": 1}), path="/selected-document", public=True)
        self.scan(auditor, http(document(id=1)))
        auditor.bopla_config["GET /selected-document"] = policy(bindings={"id": 1.0})
        fields = self.scan(auditor, http(document(id=1.0, private_note=SECRET_B)))
        confirmed = [item for item in fields if item["verdict"] == "CONFIRMED"]
        self.assertEqual(2, len(confirmed))
        self.assertEqual(2, len({item["evidence"]["resource_group"] for item in confirmed}))
        self.assertEqual(2, auditor.stats["unique_confirmed_vulnerabilities"])
        self.assertEqual(2, auditor.stats["bopla_fields_confirmed"])


class ResourceScopeTests(unittest.TestCase):
    def test_same_resource_fields_share_scope_but_distinct_array_entities_do_not(self):
        configured = policy(rule("items[0].private_note"), rule("items[1].private_note", rule_id="other"),
                            bindings={"tenant_id": "tenant-a", "items[0].id": "resource-a", "items[1].id": "resource-b"})
        first = resource_scope(configured, "items[0].private_note")
        self.assertEqual(first, resource_scope(configured, "items[0].extra_note"))
        self.assertNotEqual(first, resource_scope(configured, "items[1].private_note"))
        self.assertIsInstance(hash(first), int)
        sibling_changed = copy.deepcopy(configured)
        sibling_changed["resource_binding"]["items[1].id"] = "resource-c"
        self.assertEqual(first, resource_scope(sibling_changed, "items[0].private_note"))
        sibling_changed["resource_binding"]["tenant_id"] = "tenant-b"
        self.assertNotEqual(first, resource_scope(sibling_changed, "items[0].private_note"))

    def test_nested_scope_retains_parent_anchor_and_excludes_other_child(self):
        configured = policy(bindings={"teams[0].id": "team-a", "teams[0].documents[0].id": "doc-a",
                                     "teams[0].documents[1].id": "doc-b", "teams[1].id": "team-b"})
        first = resource_scope(configured, "teams[0].documents[0].note")
        changed = copy.deepcopy(configured)
        changed["resource_binding"]["teams[0].documents[1].id"] = "doc-c"
        changed["resource_binding"]["teams[1].id"] = "team-c"
        self.assertEqual(first, resource_scope(changed, "teams[0].documents[0].note"))
        changed["resource_binding"]["teams[0].id"] = "team-z"
        self.assertNotEqual(first, resource_scope(changed, "teams[0].documents[0].note"))

    def test_root_scope_matches_legacy_check_and_is_canonical_and_typed(self):
        configured = policy(bindings={"tenant_id": "tenant-a", "id": 1, "items[0].id": "child-a"})
        root = resource_scope(configured)
        self.assertEqual(root, resource_scope(configured, "profile.private_note"))
        reordered = policy(bindings={"items[0].id": "child-b", "id": 1, "tenant_id": "tenant-a"})
        self.assertEqual(root, resource_scope(reordered, "private_note"))
        reordered["resource_binding"]["id"] = 1.0
        self.assertNotEqual(root, resource_scope(reordered, "private_note"))
        negative_zero = policy(bindings={"id": -0.0})
        positive_zero = policy(bindings={"id": 0.0})
        self.assertNotEqual(resource_scope(negative_zero), resource_scope(positive_zero))

    def test_root_without_root_anchor_keeps_all_selected_binding_context(self):
        configured = policy(bindings={"items[0].id": "doc-a"})
        changed = policy(bindings={"items[0].id": "doc-b"})
        self.assertNotEqual(resource_scope(configured), resource_scope(changed))


if __name__ == "__main__":
    unittest.main()
