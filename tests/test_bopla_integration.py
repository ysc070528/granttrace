"""Independent loopback truth cases for read-only property authorization.

The server supplies real JSON and records what each identity actually received.
Only transport responses are controlled; the auditor decides every verdict.
"""

import copy
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import api_sentinel
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.reporter import SecurityReportGenerator
from core.sarif import SarifReportGenerator


OWNER_VALUE = "owner-document-unique-9237-canary"
VISITOR_VALUE = "visitor-document-unique-8273-canary"


class PropertyServer(BaseHTTPRequestHandler):
    observations = []
    responses = {}

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        identity = "owner" if "ALICE" in authorization else "visitor" if "BOB" in authorization else "anonymous"
        path = urlsplit(self.path).path
        status, payload = self.responses.get((path, identity), (404, {"error": "Not found"}))
        body = json.dumps(payload).encode("utf-8")
        self.observations.append({"method": "GET", "identity": identity, "path": self.path,
                                  "status": status, "payload": copy.deepcopy(payload)})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _unexpected_write(self):
        self.observations.append({"method": self.command, "path": self.path})
        self.send_error(405)

    do_POST = do_PUT = do_PATCH = do_DELETE = _unexpected_write

    def log_message(self, *args):
        return


class BoplaIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), PropertyServer)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-bopla-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        PropertyServer.observations = []
        PropertyServer.responses = {}

    @staticmethod
    def policy(path="private_note", binding=None, **field_options):
        field = {"rule_id": "owner-note", "path": path,
                 "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                 "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}
        field.update(field_options)
        return {"policy_id": "document-fields-v1", "context_id": "selected-owner-document",
                "resource_binding": binding or {"id": "1001"}, "fields": [field]}

    def serve(self, owner=None, visitor=None, anonymous=None, *, route="/documents/1001"):
        default = {"id": "1001", "title": "Shared document", "private_note": OWNER_VALUE}
        for identity, response in (("owner", owner), ("visitor", visitor), ("anonymous", anonymous)):
            PropertyServer.responses[(route, identity)] = copy.deepcopy(response or (200, default))
        PropertyServer.responses[("/documents/1002", "visitor")] = (
            200, {"id": "1002", "title": "Visitor document", "private_note": VISITOR_VALUE})

    def auditor(self, policy, *, public=False, endpoint="/documents/{id}", sensitive=False,
                legacy_policy=None, readonly=False, **options):
        operation = {"security": [] if public else [{"bearer": []}],
                     "parameters": [{"name": "id", "in": "path", "required": True,
                                     "schema": {"type": "string"}}] if "{" in endpoint else [],
                     "responses": {"200": {"description": "Selected document"}}}
        if readonly:
            operation["responses"]["200"]["content"] = {"application/json": {"schema": {
                "type": "object", "properties": {"private_note": {"type": "string", "readOnly": True}}}}}
        spec = self.folder / "spec.json"
        spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {endpoint: {"get": operation}}}),
                        encoding="utf-8")
        identities = {
            "owner": {"id": "1001", "token": "Bearer ALICE_OWNER_TOKEN", "parameters": {"id": "1001"}},
            "visitor": {"id": "1002", "token": "Bearer BOB_VISITOR_TOKEN", "parameters": {"id": "1002"}},
            "anonymous": {"id": None, "token": None, "parameters": {}},
        }
        key = "GET " + endpoint
        with patch("urllib.request.getproxies", return_value={}):
            auditor = APISentinelAuditor(str(spec), self.target, request_delay=0,
                                        identities_config=identities,
                                        include_sensitive_evidence=sensitive,
                                        bola_config={key: legacy_policy or {"expected_visitor_access": "allow"}},
                                        bopla_config={} if policy is None else {key: policy}, **options)
        return auditor

    def scan(self, auditor):
        with redirect_stdout(io.StringIO()):
            auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
        auditor.stats["total_endpoints"] = 1
        auditor._finalise_coverage()
        self.assertTrue(all(item["method"] == "GET" for item in PropertyServer.observations))
        return [item for item in auditor.results if item["check"] == "BOPLA"]

    def subject(self, results, identity="visitor", path="private_note"):
        selected = [item for item in results
                    if item["evidence"]["decision_evidence"]["subject_identity"] == identity
                    and item["evidence"]["decision_evidence"]["field_path"] == path]
        self.assertEqual(1, len(selected))
        return selected[0]

    def assert_confirmed(self, item, path="private_note"):
        self.assertEqual("CONFIRMED", item["verdict"])
        evidence = item["evidence"]["decision_evidence"]
        self.assertTrue(evidence["owner_baseline_valid"])
        self.assertTrue(evidence["resource_bound"])
        self.assertEqual([path], evidence["matched_private_data_paths"])
        self.assertEqual("document-fields-v1", evidence["policy_id"])
        self.assertEqual("selected-owner-document", evidence["context_id"])

    def test_public_object_leaks_anonymous_owner_only_field(self):
        self.serve()
        auditor = self.auditor(self.policy(), public=True)
        results = self.scan(auditor)
        self.assert_confirmed(self.subject(results, "anonymous"))
        sent = next(item for item in PropertyServer.observations if item["identity"] == "anonymous")
        self.assertEqual(OWNER_VALUE, sent["payload"]["private_note"])
        self.assertEqual(4, len(PropertyServer.observations))

    def test_shared_object_retains_authorized_bola_and_confirms_private_field(self):
        self.serve(anonymous=(403, {"error": "Forbidden"}))
        auditor = self.auditor(self.policy())
        results = self.scan(auditor)
        self.assert_confirmed(self.subject(results))
        self.assertEqual("AUTHORIZED", next(item for item in auditor.results if item["check"] == "BOLA")["verdict"])
        sent = next(item for item in PropertyServer.observations if item["identity"] == "visitor")
        self.assertEqual(OWNER_VALUE, sent["payload"]["private_note"])
        self.assertEqual(4, len(PropertyServer.observations))

    def test_nested_owner_only_field_in_shared_object(self):
        payload = {"id": "1001", "title": "Shared document", "profile": {"note": OWNER_VALUE}}
        self.serve(owner=(200, payload), visitor=(200, payload), anonymous=(403, {"error": "Forbidden"}))
        results = self.scan(self.auditor(self.policy("profile.note")))
        self.assert_confirmed(self.subject(results, path="profile.note"), "profile.note")

    def test_fixed_array_collection_field_has_explicit_item_anchor(self):
        payload = {"items": [{"id": "1001", "title": "Shared document", "note": OWNER_VALUE}]}
        self.serve(owner=(200, payload), visitor=(200, payload), route="/documents")
        results = self.scan(self.auditor(self.policy("items[0].note", {"items[0].id": "1001"}),
                                         public=True, endpoint="/documents"))
        self.assert_confirmed(self.subject(results, path="items[0].note"), "items[0].note")
        self.assertEqual(3, len(PropertyServer.observations))

    def test_explicit_public_field_does_not_become_a_finding(self):
        self.serve()
        policy = self.policy(access={"owner": "allow", "visitor": "allow", "anonymous": "allow"})
        auditor = self.auditor(policy, public=True)
        results = self.scan(auditor)
        self.assertEqual("AUTHORIZED", self.subject(results, "anonymous")["verdict"])
        self.assertFalse(any(item["check"] == "BOPLA" and item["verdict"] == "CONFIRMED"
                             for item in results))
        self.assertFalse(any(item.get("cwe") == "CWE-200" for item in auditor.findings))

    def test_explicit_field_sharing_preserves_authorized_result(self):
        self.serve(anonymous=(403, {"error": "Forbidden"}))
        policy = self.policy(access={"owner": "allow", "visitor": "allow", "anonymous": "deny"})
        auditor = self.auditor(policy)
        results = self.scan(auditor)
        self.assertEqual("AUTHORIZED", self.subject(results)["verdict"])
        self.assertFalse(any(item["check"] == "BOPLA" and item["verdict"] == "CONFIRMED"
                             for item in results))

    def test_same_field_name_different_value_is_not_leak_evidence(self):
        self.serve(visitor=(200, {"id": "1001", "title": "Shared document", "private_note": VISITOR_VALUE}))
        result = self.subject(self.scan(self.auditor(self.policy())))
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertEqual([], result["evidence"]["decision_evidence"]["matched_private_data_paths"])

    def test_visitor_own_resource_with_equal_value_has_no_owner_binding(self):
        self.serve(visitor=(200, {"id": "1002", "title": "Visitor document", "private_note": OWNER_VALUE}))
        result = self.subject(self.scan(self.auditor(self.policy())))
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertFalse(result["evidence"]["decision_evidence"]["resource_bound"])

    def test_missing_field_policy_never_synthesizes_a_field_check(self):
        self.serve(anonymous=(403, {"error": "Forbidden"}))
        auditor = self.auditor(None)
        self.assertEqual([], self.scan(auditor))
        self.assertEqual(4, len(PropertyServer.observations))
        self.assertFalse(any(item["check"] == "BOPLA" for item in auditor.results))

    def test_openapi_readonly_is_not_a_field_authorization_policy(self):
        self.serve()
        auditor = self.auditor(None, public=True, readonly=True)
        self.assertEqual([], self.scan(auditor))
        self.assertFalse(any(item["check"] == "BOPLA" for item in auditor.results))

    def test_invalid_owner_baseline_prevents_both_confirmed_and_secure(self):
        self.serve(owner=(401, {"error": "Owner token expired"}), anonymous=(403, {"error": "Forbidden"}))
        results = self.scan(self.auditor(self.policy()))
        for identity in ("visitor", "anonymous"):
            result = self.subject(results, identity)
            self.assertEqual("INCONCLUSIVE", result["verdict"])
            self.assertFalse(result["evidence"]["decision_evidence"]["owner_baseline_valid"])

    def test_http_200_business_error_with_private_value_is_suspicious(self):
        self.serve(visitor=(200, {"id": "1001", "error": "Forbidden", "private_note": OWNER_VALUE}))
        result = self.subject(self.scan(self.auditor(self.policy())))
        self.assertEqual("SUSPICIOUS", result["verdict"])
        self.assertEqual(["private_note"], result["evidence"]["decision_evidence"]["matched_private_data_paths"])
        served = next(item for item in PropertyServer.observations if item["identity"] == "visitor")
        self.assertEqual(200, served["status"])
        self.assertIn("error", served["payload"])

    def test_absent_empty_null_and_masked_field_remain_uncertain(self):
        for value in (None, "", "owner-document-***", False, [], {}):
            with self.subTest(kind=type(value).__name__, masked=value == "owner-document-***"):
                PropertyServer.observations = []
                payload = {"id": "1001", "title": "Shared document", "private_note": value}
                self.serve(visitor=(200, payload))
                result = self.subject(self.scan(self.auditor(self.policy())))
                self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.serve(visitor=(200, {"id": "1001", "title": "Shared document"}))
        self.assertEqual("INCONCLUSIVE", self.subject(self.scan(self.auditor(self.policy())))["verdict"])

    def test_same_name_at_unconfigured_path_does_not_match(self):
        self.serve(visitor=(200, {"id": "1001", "title": "Shared document", "profile": {"private_note": OWNER_VALUE}}))
        result = self.subject(self.scan(self.auditor(self.policy())))
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertEqual([], result["evidence"]["decision_evidence"]["matched_private_data_paths"])

    def test_partial_http_response_is_not_confirmed(self):
        self.serve(visitor=(206, {"id": "1001", "title": "Partial", "private_note": OWNER_VALUE}))
        result = self.subject(self.scan(self.auditor(self.policy())))
        self.assertIn(result["verdict"], ("INCONCLUSIVE", "SUSPICIOUS"))
        self.assertFalse(any(item.get("check") == "BOPLA" and item["verdict"] == "CONFIRMED"
                             for item in [result]))

    def test_equal_private_value_in_unbound_tenant_is_not_confirmed(self):
        owner = {"tenant_id": "owner-tenant", "id": "1001", "private_note": OWNER_VALUE}
        visitor = {"tenant_id": "visitor-tenant", "id": "1001", "private_note": OWNER_VALUE}
        self.serve(owner=(200, owner), visitor=(200, visitor))
        result = self.subject(self.scan(self.auditor(self.policy(binding={"tenant_id": "owner-tenant", "id": "1001"}))))
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertFalse(result["evidence"]["decision_evidence"]["resource_bound"])

    def test_fixed_index_must_refer_to_same_collection_entity(self):
        owner = {"items": [{"id": "1001", "note": OWNER_VALUE}, {"id": "1002", "note": VISITOR_VALUE}]}
        visitor = {"items": [{"id": "1002", "note": OWNER_VALUE}, {"id": "1001", "note": OWNER_VALUE}]}
        self.serve(owner=(200, owner), visitor=(200, visitor), route="/documents")
        result = self.subject(self.scan(self.auditor(self.policy("items[0].note", {"items[0].id": "1001"}),
                                                   endpoint="/documents", public=True)), path="items[0].note")
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertFalse(result["evidence"]["decision_evidence"]["resource_bound"])

    def test_common_baseline_without_resource_specific_attestation_cannot_confirm(self):
        payload = {"id": "1001", "title": "Shared document", "private_note": "active"}
        self.serve(owner=(200, payload), visitor=(200, payload))
        policy = self.policy()
        policy["fields"][0].pop("value_is_resource_specific")
        result = self.subject(self.scan(self.auditor(policy)))
        self.assertEqual("INCONCLUSIVE", result["verdict"])

    def test_value_also_in_visitor_self_baseline_cannot_identify_owner_data(self):
        self.serve()
        PropertyServer.responses[("/documents/1002", "visitor")] = (
            200, {"id": "1002", "title": "Visitor document", "private_note": OWNER_VALUE})
        result = self.subject(self.scan(self.auditor(self.policy())))
        self.assertEqual("INCONCLUSIVE", result["verdict"])

    def test_unknown_identity_permission_is_inconclusive(self):
        self.serve()
        result = self.subject(self.scan(self.auditor(self.policy(access={"owner": "allow", "anonymous": "deny"}))))
        self.assertEqual("INCONCLUSIVE", result["verdict"])

    def test_clean_denial_is_secure_only_for_selected_rule_identity_and_context(self):
        self.serve(visitor=(403, {"error": "Forbidden"}), anonymous=(401, {"error": "Authentication required"}))
        result = self.subject(self.scan(self.auditor(self.policy())))
        self.assertEqual("SECURE", result["verdict"])
        decision = result["evidence"]["decision_evidence"]
        self.assertEqual("private_note", decision["field_path"])
        self.assertEqual("selected-owner-document", decision["context_id"])
        self.assertTrue(decision["owner_baseline_valid"])

    def test_dirty_denial_echoing_private_value_is_not_secure_or_confirmed(self):
        self.serve(visitor=(403, {"error": "Forbidden", "private_note": OWNER_VALUE}))
        result = self.subject(self.scan(self.auditor(self.policy())))
        self.assertEqual("SUSPICIOUS", result["verdict"])

    def test_invalid_conflicting_field_rules_are_rejected_before_requests(self):
        self.serve()
        policy = self.policy()
        opposite = copy.deepcopy(policy["fields"][0])
        opposite["rule_id"] = "contradictory-copy"
        opposite["access"]["visitor"] = "allow"
        policy["fields"].append(opposite)
        self.assertFalse(ConfigValidator.validate({"bopla": {"GET /documents/{id}": policy}}).is_valid)
        try:
            auditor = self.auditor(policy)
        except ValueError:
            self.assertEqual([], PropertyServer.observations)
            return
        results = self.scan(auditor)
        self.assertTrue(results)
        self.assertTrue(all(item["verdict"] == "INCONCLUSIVE" for item in results))
        self.assertEqual([], PropertyServer.observations)

    def test_unsafe_get_is_never_sent_for_field_rules(self):
        self.serve()
        auditor = self.auditor(self.policy(), endpoint="/documents/{id}/delete")
        results = self.scan(auditor)
        self.assertEqual([], PropertyServer.observations)
        self.assertFalse(any(item["verdict"] == "CONFIRMED" for item in results))

    def test_new_private_values_are_forcibly_redacted_in_all_reports(self):
        private_number = 928374652
        payload = {"id": "1001", "title": "Shared document", "memo": OWNER_VALUE, "amount": private_number,
                   "reflection": "echo " + OWNER_VALUE}
        for sensitive in (False, True):
            with self.subTest(sensitive=sensitive):
                self.serve(owner=(200, payload), visitor=(200, payload))
                policy = self.policy("memo")
                amount = copy.deepcopy(policy["fields"][0])
                amount.update(rule_id="amount", path="amount")
                policy["fields"].append(amount)
                auditor = self.auditor(policy, sensitive=sensitive, public=True)
                output = io.StringIO()
                with redirect_stdout(output):
                    results = self.scan(auditor)
                    html, sarif = self.folder / "report.html", self.folder / "report.sarif"
                    SecurityReportGenerator.generate(auditor.stats, auditor.findings, auditor.target_base_url,
                                                     str(html), results=auditor.results)
                    SarifReportGenerator.generate(results=auditor.results, output_path=str(sarif),
                                                  target_url=auditor.target_base_url)
                self.assert_confirmed(self.subject(results, path="memo"), "memo")
                texts = (json.dumps(auditor.results), json.dumps(auditor.findings), output.getvalue(),
                         html.read_text(encoding="utf-8"), sarif.read_text(encoding="utf-8"))
                for text in texts:
                    for secret in (OWNER_VALUE, str(private_number), "ALICE_OWNER_TOKEN", "BOB_VISITOR_TOKEN"):
                        self.assertNotIn(secret, text)
                self.assertTrue(json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"])

    def test_two_fields_and_existing_detector_share_one_confirmed_leak_observation(self):
        payload = {"id": "1001", "title": "Shared document", "private_note": OWNER_VALUE,
                   "extra_note": "owner-document-extra-unique-81725"}
        self.serve(owner=(200, payload), visitor=(200, payload), anonymous=(403, {"error": "Forbidden"}))
        policy = self.policy()
        extra = copy.deepcopy(policy["fields"][0])
        extra.update(rule_id="extra", path="extra_note")
        policy["fields"].append(extra)
        legacy = {"expected_visitor_access": "deny", "private_data_paths": ["private_note"]}
        auditor = self.auditor(policy, legacy_policy=legacy)
        results = self.scan(auditor)
        self.assert_confirmed(self.subject(results))
        self.assert_confirmed(self.subject(results, path="extra_note"), "extra_note")
        self.assertEqual("CONFIRMED", next(item for item in auditor.results if item["check"] == "BOLA")["verdict"])
        self.assertEqual(4, len(PropertyServer.observations))
        self.assertEqual(4, auditor.stats["http_requests_sent"])
        self.assertEqual(4, auditor.stats["bopla_field_checks"])
        self.assertEqual(2, auditor.stats["bopla_fields_checked"])
        self.assertEqual(2, auditor.stats["bopla_fields_confirmed"])
        self.assertEqual(1, auditor.stats["unique_confirmed_vulnerabilities"])
        self.assertEqual(1, auditor.stats["confirmed"])
        self.assertEqual(1, len(auditor.findings))

    def test_one_confirmed_field_does_not_hide_another_inconclusive_field(self):
        owner = {"id": "1001", "title": "Shared document", "private_note": OWNER_VALUE,
                 "extra_note": "owner-document-extra-unique-81725"}
        visitor = {"id": "1001", "title": "Shared document", "private_note": OWNER_VALUE}
        self.serve(owner=(200, owner), visitor=(200, visitor), anonymous=(403, {"error": "Forbidden"}))
        policy = self.policy()
        extra = copy.deepcopy(policy["fields"][0])
        extra.update(rule_id="extra", path="extra_note")
        policy["fields"].append(extra)
        auditor = self.auditor(policy)
        results = self.scan(auditor)
        self.assert_confirmed(self.subject(results))
        self.assertEqual("INCONCLUSIVE", self.subject(results, path="extra_note")["verdict"])
        self.assertEqual(0, auditor.stats["conclusive_endpoints"])
        self.assertGreaterEqual(auditor.stats["bopla_inconclusive_count"], 1)
        self.assertEqual(1, auditor.stats["bopla_fields_confirmed"])

    def test_exception_evidence_cannot_echo_protected_reference_value(self):
        self.serve()
        auditor = self.auditor(self.policy(), sensitive=True, public=True)
        results = self.scan(auditor)
        self.assert_confirmed(self.subject(results))
        output = io.StringIO()
        with redirect_stdout(output):
            auditor._record_task_error(auditor.parser.get_endpoints()[0], "BOPLA",
                                       RuntimeError("failed while processing " + OWNER_VALUE))
        self.assertNotIn(OWNER_VALUE, json.dumps(auditor.results))
        self.assertNotIn(OWNER_VALUE, output.getvalue())

    def test_context_specific_field_permissions_are_isolated_between_scans(self):
        self.serve()
        denied_policy = self.policy()
        denied_policy["context_id"] = "owner-only-context"
        denied = self.subject(self.scan(self.auditor(denied_policy)))
        allowed_policy = self.policy(access={"owner": "allow", "visitor": "allow", "anonymous": "allow"})
        allowed_policy["context_id"] = "legitimate-sharing-context"
        allowed = self.subject(self.scan(self.auditor(allowed_policy)))
        self.assertEqual("CONFIRMED", denied["verdict"])
        self.assertEqual("AUTHORIZED", allowed["verdict"])
        self.assertEqual("owner-only-context", denied["evidence"]["decision_evidence"]["context_id"])
        self.assertEqual("legitimate-sharing-context", allowed["evidence"]["decision_evidence"]["context_id"])

    def test_cli_uses_field_configuration_and_exports_actual_safe_reports(self):
        self.serve()
        policy = self.policy()
        prepared = self.auditor(policy, public=True)
        config = self.folder / "config.json"
        config.write_text(json.dumps({
            "identities": prepared.identities,
            "bola": {"GET /documents/{id}": {"expected_visitor_access": "allow"}},
            "bopla": {"GET /documents/{id}": policy},
        }), encoding="utf-8")
        html, exported, sarif = self.folder / "cli.html", self.folder / "cli.json", self.folder / "cli.sarif"
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("urllib.request.getproxies", return_value={}), redirect_stdout(stdout), redirect_stderr(stderr):
            code = api_sentinel.main(["--spec", str(self.folder / "spec.json"), "--config", str(config),
                                      "--target", self.target, "--delay", "0", "--output", str(html),
                                      "--export-json", str(exported), "--export-sarif", str(sarif),
                                      "--include-sensitive-evidence"])
        self.assertEqual(0, code, stderr.getvalue())
        report = json.loads(exported.read_text(encoding="utf-8"))
        decisions = [item for item in report["results"] if item["check"] == "BOPLA"]
        self.assert_confirmed(self.subject(decisions, "anonymous"))
        self.assertEqual(4, len(PropertyServer.observations))
        self.assertTrue(all(item["method"] == "GET" for item in PropertyServer.observations))
        for text in (stdout.getvalue(), stderr.getvalue(), html.read_text(encoding="utf-8"),
                     exported.read_text(encoding="utf-8"), sarif.read_text(encoding="utf-8")):
            self.assertNotIn(OWNER_VALUE, text)
            self.assertNotIn("ALICE_OWNER_TOKEN", text)
            self.assertNotIn("BOB_VISITOR_TOKEN", text)

    def test_numeric_private_values_do_not_rewrite_transport_metadata(self):
        for private_number in (4, 200):
            with self.subTest(private_number=private_number):
                PropertyServer.observations = []
                payload = {"id": "1001", "title": "Shared document", "private_note": private_number}
                self.serve(owner=(200, payload), visitor=(200, payload), anonymous=(403, {"error": "Forbidden"}))
                policy = self.policy(value_is_resource_specific=False)
                auditor = self.auditor(policy, sensitive=True)
                results = self.scan(auditor)
                self.assertEqual("INCONCLUSIVE", self.subject(results)["verdict"])
                self.assertEqual(4, len(PropertyServer.observations))
                self.assertEqual(4, auditor.stats["http_requests_sent"])
                for result in auditor.results:
                    attempts = result["evidence"]["requests_attempted"]
                    self.assertIs(type(attempts), int)
                    self.assertEqual(4, attempts)
                legacy = next(result for result in auditor.results if result["check"] == "BOLA")
                self.assertIs(type(legacy["evidence"]["owner"]["status"]), int)
                self.assertEqual(200, legacy["evidence"]["owner"]["status"])

    def test_later_owner_reference_scrubs_earlier_cross_operation_echo(self):
        self.serve(anonymous=(403, {"error": "Forbidden"}))
        echo = {"id": "1001", "title": "Public echo", "unrelated_echo": OWNER_VALUE}
        self.serve(owner=(200, echo), visitor=(200, echo), anonymous=(200, echo), route="/echo/1001")
        PropertyServer.responses[("/echo/1002", "visitor")] = (
            200, {"id": "1002", "title": "Visitor echo", "unrelated_echo": "visitor own echo"})
        prepared = self.auditor(self.policy(), sensitive=True)
        spec_path = self.folder / "spec.json"
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        spec["paths"]["/echo/{id}"] = copy.deepcopy(spec["paths"]["/documents/{id}"])
        spec["paths"]["/echo/{id}"]["get"]["security"] = []
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        with patch("urllib.request.getproxies", return_value={}):
            auditor = APISentinelAuditor(str(spec_path), self.target, request_delay=0,
                                        identities_config=prepared.identities,
                                        include_sensitive_evidence=True,
                                        bola_config={"GET /echo/{id}": {"expected_visitor_access": "allow"},
                                                     "GET /documents/{id}": {"expected_visitor_access": "allow"}},
                                        bopla_config={"GET /documents/{id}": self.policy()})
        endpoints = {ep["path"]: ep for ep in auditor.parser.get_endpoints()}
        auditor.audit_endpoint_bola(endpoints["/echo/{id}"])
        self.assertIn(OWNER_VALUE, json.dumps(auditor.results))
        auditor.audit_endpoint_bola(endpoints["/documents/{id}"])
        auditor.stats["total_endpoints"] = 2
        auditor._finalise_coverage()
        results = [item for item in auditor.results if item["check"] == "BOPLA"]
        self.assert_confirmed(self.subject(results))
        html, sarif = self.folder / "echo.html", self.folder / "echo.sarif"
        SecurityReportGenerator.generate(auditor.stats, auditor.findings, auditor.target_base_url,
                                         str(html), results=auditor.results)
        SarifReportGenerator.generate(results=auditor.results, output_path=str(sarif), target_url=self.target)
        for output in (json.dumps(auditor.results), json.dumps(auditor.findings),
                       html.read_text(encoding="utf-8"), sarif.read_text(encoding="utf-8")):
            self.assertNotIn(OWNER_VALUE, output)
        self.assertEqual(8, len(PropertyServer.observations))

    def test_same_operation_distinct_context_resource_leaks_are_not_merged(self):
        for second_resource in ("1001", "1003"):
            with self.subTest(second_resource=second_resource):
                PropertyServer.observations = []
                self.serve(anonymous=(403, {"error": "Forbidden"}))
                first_policy = self.policy()
                first_policy["context_id"] = "first-owner-context"
                auditor = self.auditor(first_policy)
                first = self.scan(auditor)
                self.assertEqual("CONFIRMED", self.subject(first)["verdict"])
                second_policy = self.policy(binding={"id": second_resource})
                second_policy["context_id"] = "second-owner-context"
                auditor.bopla_config["GET /documents/{id}"] = second_policy
                auditor.identities["owner"]["parameters"]["id"] = second_resource
                payload = {"id": second_resource, "title": "Shared document", "private_note": OWNER_VALUE}
                self.serve(owner=(200, payload), visitor=(200, payload),
                           anonymous=(403, {"error": "Forbidden"}), route="/documents/" + second_resource)
                with redirect_stdout(io.StringIO()):
                    auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
                auditor._finalise_coverage()
                confirmed = [item for item in auditor.results if item["check"] == "BOPLA"
                             and item["verdict"] == "CONFIRMED"]
                self.assertEqual(2, len(confirmed))
                contexts = {item["evidence"]["decision_evidence"]["context_id"] for item in confirmed}
                self.assertEqual({"first-owner-context", "second-owner-context"}, contexts)
                self.assertEqual(2, auditor.stats["bopla_fields_confirmed"])
                self.assertEqual(2, auditor.stats["unique_confirmed_vulnerabilities"])
                self.assertEqual(2, auditor.stats["confirmed"])
                self.assertEqual(2, len(auditor.findings))


if __name__ == "__main__":
    unittest.main()
