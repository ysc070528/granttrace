"""Independent PR44 privacy regressions; synthetic values, no external transport."""

import copy
import hashlib
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from core.auditor import APISentinelAuditor
from core.evidence import sanitize_evidence, sanitize_property_record
from core.models import HTTPResult
from core.reporter import SecurityReportGenerator
from core.reproduction import build_reproduction_templates
from core.sarif import SarifReportGenerator


class IndependentPrivacyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-pr44-privacy-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    @staticmethod
    def policy(path="memo", context="selected-owner"):
        return {"policy_id": "independent-private-fields", "context_id": context,
                "resource_binding": {"id": "1001"}, "fields": [{
                    "rule_id": "selected-private-field", "path": path,
                    "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                    "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}

    def setup_auditor(self, private, *, sensitive=True, later=None):
        policies = {"GET /private/{id}": self.policy()}
        if later is not None:
            policies["GET /later/{id}"] = self.policy(context="second-selected-owner")
        operation = {"parameters": [{"name": "id", "in": "path", "required": True,
                                      "schema": {"type": "string"}}],
                     "responses": {"200": {"description": "Selected document"}}}
        paths = {path: {"get": copy.deepcopy(operation)}
                 for path in ("/early/{id}", "/private/{id}", "/later/{id}")}
        paths["/early/{id}"]["get"]["security"] = []
        paths["/private/{id}"]["get"]["security"] = [{"bearer": []}]
        paths["/later/{id}"]["get"]["security"] = [{"bearer": []}]
        spec = self.folder / "spec.json"
        spec.write_text(json.dumps({"openapi": "3.0.3", "paths": paths}), encoding="utf-8")
        identities = {"owner": {"id": "1001", "parameters": {"id": "1001"},
                                 "token": "Bearer SYNTHETIC-OWNER-CREDENTIAL"},
                      "visitor": {"id": "1002", "parameters": {"id": "1002"},
                                  "token": "Bearer SYNTHETIC-VISITOR-CREDENTIAL"},
                      "anonymous": {}}
        auditor = APISentinelAuditor(str(spec), "http://127.0.0.1:48987", request_delay=0,
                                    identities_config=identities, include_sensitive_evidence=sensitive,
                                    bola_config={"GET /early/{id}": {"expected_public": True},
                                                 "GET /private/{id}": {"expected_visitor_access": "allow"},
                                                 "GET /later/{id}": {"expected_visitor_access": "allow"}},
                                    bopla_config=policies)
        endpoints = {ep["path"]: ep for ep in auditor.parser.get_endpoints()}
        exposed = later if later is not None else private
        early = {"id": "1001", "ordinary_echo": exposed}

        def response(method, url, data=None, identity_name="anonymous", **kwargs):
            self.assertEqual("GET", method)
            path = urlsplit(url).path
            if path.endswith("/1002"):
                return HTTPResult(200, '{"id":"1002","memo":"Visitor own unrelated value"}')
            if path.startswith("/early/"):
                return HTTPResult(200, json.dumps(early))
            if identity_name == "anonymous":
                return HTTPResult(403, '{"error":"Forbidden"}')
            value = later if path.startswith("/later/") else private
            return HTTPResult(200, json.dumps({"id": "1001", "memo": value}))

        return auditor, endpoints, response, early

    @staticmethod
    def scan(auditor, endpoint):
        with redirect_stdout(io.StringIO()):
            auditor.audit_endpoint_bola(endpoint)

    def render(self, auditor, *, results=None, label="report"):
        path = self.folder / (label + ".html")
        SecurityReportGenerator.generate(auditor.stats, auditor.findings, auditor.target_base_url,
                                         str(path), results=auditor.results if results is None else results,
                                         secret_values=auditor._secret_values)
        return path.read_text(encoding="utf-8")

    def test_late_reference_cannot_leave_enumerable_hash_of_earlier_response(self):
        for sensitive in (False, True):
            with self.subTest(sensitive=sensitive):
                private = "P17"
                auditor, eps, response, early = self.setup_auditor(private, sensitive=sensitive)
                raw = json.dumps(early)
                oracle = hashlib.sha256(raw.encode()).hexdigest()
                with patch.object(auditor, "_http_request", side_effect=response):
                    self.scan(auditor, eps["/early/{id}"])
                    self.scan(auditor, eps["/private/{id}"])
                serialized = json.dumps(auditor.results)
                self.assertNotIn(private, serialized)
                self.assertNotIn(oracle, serialized,
                                 "The retained response digest distinguishes a finite private-value dictionary")

    def test_returned_record_and_shallow_list_alias_receive_late_redaction(self):
        private = "independent-retained-alias-private-9276"
        auditor, eps, response, _ = self.setup_auditor(private)
        with patch.object(auditor, "_http_request", side_effect=response):
            self.scan(auditor, eps["/early/{id}"])
            retained_list = auditor.results
            retained_record = auditor.results[0]
            retained_shallow_copy = list(auditor.results)
            self.scan(auditor, eps["/private/{id}"])
        for retained in (retained_list, retained_record, retained_shallow_copy):
            self.assertNotIn(private, json.dumps(retained),
                             "Replacing the auditor's list leaves old exported references recoverable")

    def test_report_during_late_owner_observation_omits_pending_response_and_hash(self):
        private = "independent-concurrent-report-private-1743"
        auditor, eps, response, early = self.setup_auditor(private)
        owner_entered = threading.Event()
        owner_release = threading.Event()
        errors = []

        def delayed(method, url, data=None, identity_name="anonymous", **kwargs):
            if "/private/" in url and identity_name == "owner":
                owner_entered.set()
                if not owner_release.wait(4):
                    raise AssertionError("Independent barrier was not released")
            return response(method, url, data=data, identity_name=identity_name, **kwargs)

        def audit_private():
            try:
                self.scan(auditor, eps["/private/{id}"])
            except BaseException as exc:
                errors.append(exc)

        with patch.object(auditor, "_http_request", side_effect=delayed):
            self.scan(auditor, eps["/early/{id}"])
            worker = threading.Thread(target=audit_private)
            worker.start()
            self.assertTrue(owner_entered.wait(3))
            try:
                before_reference = self.render(auditor, results=list(auditor.results), label="concurrent")
            finally:
                owner_release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual([], errors)
        self.assertNotIn(private, before_reference)
        self.assertNotIn(hashlib.sha256(json.dumps(early).encode()).hexdigest(), before_reference)

    def test_earlier_confirmed_finding_alias_receives_late_redaction(self):
        private = "independent-historical-finding-private-7614"
        auditor, eps, response, _ = self.setup_auditor(private)
        eps["/early/{id}"]["security"] = [{"bearer": []}]
        auditor.bola_config["GET /early/{id}"] = {"expected_visitor_access": "deny"}

        def protected(method, url, data=None, identity_name="anonymous", **kwargs):
            if "/early/" in url and identity_name == "anonymous":
                return HTTPResult(403, '{"error":"Forbidden"}')
            return response(method, url, data=data, identity_name=identity_name, **kwargs)

        with patch.object(auditor, "_http_request", side_effect=protected):
            self.scan(auditor, eps["/early/{id}"])
            self.assertEqual(1, len(auditor.findings))
            retained_list = auditor.findings
            retained_finding = auditor.findings[0]
            self.scan(auditor, eps["/private/{id}"])
        self.assertEqual(2, len(auditor.findings))
        self.assertEqual("CONFIRMED", auditor.results[0]["verdict"])
        for retained in (retained_list, retained_finding, list(retained_list)):
            self.assertNotIn(private, json.dumps(retained))

    def test_short_then_long_reference_does_not_leave_private_suffix_in_history(self):
        short = "independent-prefix-773"
        suffix = "::owner-only-suffix-98125"
        long = short + suffix
        auditor, eps, response, _ = self.setup_auditor(short, later=long)
        with patch.object(auditor, "_http_request", side_effect=response):
            for path in ("/early/{id}", "/private/{id}", "/later/{id}"):
                self.scan(auditor, eps[path])
        self.assertNotIn(short, json.dumps(auditor.results))
        self.assertNotIn(long, json.dumps(auditor.results))
        self.assertNotIn(suffix, json.dumps(auditor.results),
                         "Learning a short prefix first must not make a later longer value unredactable")
        self.assertNotIn(suffix, self.render(auditor))

    def test_private_value_equal_to_verdict_does_not_destroy_detection_metadata(self):
        auditor, eps, response, _ = self.setup_auditor("CONFIRMED")
        with patch.object(auditor, "_http_request", side_effect=response):
            self.scan(auditor, eps["/private/{id}"])
        bopla = [item for item in auditor.results if item["check"] == "BOPLA"]
        visitor = next(item for item in bopla if item["evidence"]["decision_evidence"]["subject_identity"] == "visitor")
        self.assertEqual("CONFIRMED", visitor["verdict"])
        auditor.stats["total_endpoints"] = 1
        auditor._finalise_coverage()
        self.assertEqual(1, auditor.stats["confirmed"])
        self.assertEqual(1, auditor.stats["bopla_fields_confirmed"])
        sarif = self.folder / "enum.sarif"
        SarifReportGenerator.generate(auditor.results, auditor.target_base_url, str(sarif),
                                      secret_values=auditor._secret_values)
        self.assertTrue(json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"])

    def test_private_value_equal_to_detector_preserves_bopla_results(self):
        auditor, eps, response, _ = self.setup_auditor("BOPLA")
        with patch.object(auditor, "_http_request", side_effect=response):
            self.scan(auditor, eps["/private/{id}"])
        self.assertEqual(2, len([item for item in auditor.results if item["check"] == "BOPLA"]))

    def test_numeric_private_reference_preserves_real_statuses_and_attempt_counts(self):
        for value in (4, 200):
            with self.subTest(value=value):
                auditor, eps, response, _ = self.setup_auditor(value)
                with patch.object(auditor, "_http_request", side_effect=response):
                    self.scan(auditor, eps["/private/{id}"])
                for result in auditor.results:
                    self.assertIs(type(result["evidence"]["requests_attempted"]), int)
                    self.assertEqual(4, result["evidence"]["requests_attempted"])
                legacy = next(item for item in auditor.results if item["check"] == "BOLA")
                self.assertEqual(200, legacy["evidence"]["owner"]["status"])
                self.assertEqual(403, legacy["evidence"]["anonymous"]["status"])

    def test_sensitive_optin_cannot_release_bopla_or_cross_operation_echoes(self):
        private = "independent-sensitive-optin-private-9276"
        auditor, eps, response, _ = self.setup_auditor(private, sensitive=True)
        with patch.object(auditor, "_http_request", side_effect=response):
            for path in ("/private/{id}", "/early/{id}"):
                self.scan(auditor, eps[path])
        texts = [json.dumps(auditor.results), json.dumps(auditor.findings), self.render(auditor)]
        sarif = self.folder / "optin.sarif"
        SarifReportGenerator.generate(auditor.results, auditor.target_base_url, str(sarif),
                                      secret_values=auditor._secret_values)
        texts.append(sarif.read_text(encoding="utf-8"))
        templates = build_reproduction_templates(auditor.findings, auditor._identity_headers("visitor"),
                                                 auditor._secret_values)
        texts.extend(template.command for template in templates.values())
        for text in texts:
            self.assertNotIn(private, text)
        self.assertTrue(any(item["check"] == "BOPLA" and item["verdict"] == "CONFIRMED"
                            for item in auditor.results))

    def test_property_snapshot_preserves_tool_schema_but_not_business_status_or_keys(self):
        record = {"check": "BOPLA", "verdict": "CONFIRMED", "evidence": {
            "requests_attempted": 4, "resource_group": 4,
            "owner": {"status": 200, "body": '{"ordinary":"owner"}', "sha256": "f" * 64, "truncated": False},
            "business_data": {"status": 200, "resource_group": 4},
            "decision_evidence": {"subject_identity": "visitor", "owner_baseline_valid": True,
                                  "role_policy": {"required_role": "administrator", "owner_role": "administrator",
                                                  "visitor_role": "member"},
                                  "policy_id": "owner-policy", "context_id": "owner-context", "rule_id": "owner-rule"}}}
        private = ("owner", "BOPLA", "CONFIRMED", "4", "200")
        safe = sanitize_property_record(record, private, omit_responses=True)
        self.assertEqual(("BOPLA", "CONFIRMED"), (safe["check"], safe["verdict"]))
        self.assertEqual(4, safe["evidence"]["requests_attempted"])
        self.assertEqual(4, safe["evidence"]["resource_group"])
        self.assertEqual(200, safe["evidence"]["owner"]["status"])
        self.assertIsNone(safe["evidence"]["owner"]["sha256"])
        self.assertEqual("administrator", safe["evidence"]["decision_evidence"]["role_policy"]["owner_role"])
        self.assertNotIn("owner", safe["evidence"]["owner"]["body"])
        self.assertEqual("[REDACTED]", safe["evidence"]["business_data"]["status"])
        self.assertEqual("[REDACTED]", safe["evidence"]["business_data"]["resource_group"])
        generic = sanitize_evidence({"owner": {"status": 200}}, secret_values=private)
        self.assertEqual({"[REDACTED]": {"status": "[REDACTED]"}}, generic)

    def test_report_without_property_selection_retains_legacy_missing_evidence_behavior(self):
        record = {"endpoint": "GET /legacy/{id}", "check": "BOLA", "verdict": "SECURE", "evidence": None}
        output = self.folder / "legacy.html"
        SecurityReportGenerator.generate({}, [], "http://127.0.0.1:48987", str(output), results=[record])
        rendered = output.read_text(encoding="utf-8")
        self.assertIn("GET /legacy/{id}", rendered)
        self.assertIn("SECURE", rendered)

    def test_pending_export_omits_nested_and_unclassified_business_evidence(self):
        private = "unclassified-pending-owner-note-43817"
        digest = hashlib.sha256(private.encode()).hexdigest()
        observation = {"status": 200, "body": json.dumps({"memo": private}), "sha256": digest,
                       "truncated": False, "error": None}
        record = {"check": "MASS_ASSIGNMENT", "verdict": "INCONCLUSIVE",
                  "injected_payload": {"ordinary": private}, "evidence": {
                      "property_privacy_pending": True, "requests_attempted": 4,
                      "business_data": {"ordinary_echo": private, "status": 200},
                      "cases": [{"field": "role", "readback_field": "role", "persisted": False,
                                 "requests_attempted": 4, "rollback_verified": True, "recovery_sent": True,
                                 "target_url": "http://127.0.0.1/documents/" + private,
                                 "before": observation, "restored": observation,
                                 "arbitrary_extension": {"ordinary_echo": private}}]}}
        safe = sanitize_property_record(record, omit_responses=True)
        serialized = json.dumps(safe)
        self.assertNotIn(private, serialized)
        self.assertNotIn(digest, serialized)
        self.assertEqual(4, safe["evidence"]["requests_attempted"])
        case = safe["evidence"]["cases"][0]
        self.assertEqual(4, case["requests_attempted"])
        self.assertEqual("role", case["field"])
        self.assertEqual(200, case["before"]["status"])
        self.assertEqual(200, case["restored"]["status"])
        self.assertIs(case["persisted"], False)
        self.assertIs(case["rollback_verified"], True)
        self.assertIs(case["recovery_sent"], True)

    def test_pending_report_does_not_render_a_previously_built_concrete_curl(self):
        private = "pending-cached-reproduction-private-71368"
        finding = {"check": "BOLA", "cwe": "CWE-639", "endpoint": "GET /documents/{id}",
                   "evidence": {"target_url": "http://127.0.0.1/documents/" + private}}
        templates = build_reproduction_templates([finding], {"Authorization": "Bearer synthetic-visitor"})
        self.assertIn(private, templates[0].command, "Construct an actual retained pre-baseline template")
        finding["evidence"]["property_privacy_pending"] = True
        output = self.folder / "cached-template.html"
        SecurityReportGenerator.generate({"confirmed": 1}, [finding], "http://127.0.0.1", str(output),
                                         reproduction_templates=templates)
        rendered = output.read_text(encoding="utf-8")
        self.assertNotIn(private, rendered)
        self.assertIn("CWE-639", rendered, "Omitting an automatic cURL must preserve the confirmed finding")

    def test_many_history_updates_and_report_snapshots_are_atomic(self):
        private = "independent-stress-history-private-98142"
        auditor, eps, response, _ = self.setup_auditor(private)
        owner_entered = threading.Event()
        owner_release = threading.Event()
        errors = []
        reports = []

        def delayed(method, url, data=None, identity_name="anonymous", **kwargs):
            if "/private/" in url and identity_name == "owner":
                owner_entered.set()
                if not owner_release.wait(5):
                    raise AssertionError("Stress barrier was not released")
            return response(method, url, data=data, identity_name=identity_name, **kwargs)

        def writer():
            try:
                self.scan(auditor, eps["/private/{id}"])
            except BaseException as exc:
                errors.append(exc)

        with patch.object(auditor, "_http_request", side_effect=delayed):
            for _ in range(6):
                self.scan(auditor, eps["/early/{id}"])
            thread = threading.Thread(target=writer)
            thread.start()
            self.assertTrue(owner_entered.wait(3))
            try:
                reports.append(self.render(auditor, label="stress-before"))
                owner_release.set()
                for index in range(12):
                    reports.append(self.render(auditor, label="stress-" + str(index)))
            finally:
                owner_release.set()
                thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)
        self.assertTrue(all(private not in report for report in reports))
        self.assertTrue(any(item["check"] == "BOPLA" and item["verdict"] == "CONFIRMED"
                            for item in auditor.results))


if __name__ == "__main__":
    unittest.main()
