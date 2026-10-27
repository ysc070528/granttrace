"""BOPLA output preserves field scope, proof requirements and safe reproduction."""

import copy
import html
import json
import re
import shlex
import tempfile
import unittest
from pathlib import Path

from core.reporter import SecurityReportGenerator
from core.reproduction import build_reproduction_templates
from core.sarif import SarifReportGenerator


class BOPLAReportTests(unittest.TestCase):
    def record(self, subject="visitor"):
        return {
            "check": "BOPLA", "verdict": "CONFIRMED", "cwe": "CWE-200",
            "type": "BOPLA (Broken Object Property Level Authorization)",
            "endpoint": "GET /documents/{id}",
            "evidence": {
                "target_url": "https://example.test/documents/1001", "requests_attempted": 3,
                "decision_evidence": {
                    "policy_id": "document-fields-v1", "context_id": "selected-document",
                    "rule_id": "note-owner-only", "field_path": "profile.private_note",
                    "subject_identity": subject, "field_access": "deny",
                    "owner_baseline_valid": True, "resource_bound": True,
                    "private_value_identifiable": True, "other_response_valid": True, "missing_evidence": [],
                    "matched_private_data_paths": ["profile.private_note"],
                },
            },
        }

    def sarif(self, records):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.sarif"
            SarifReportGenerator.generate(records, "https://example.test", str(path))
            return json.loads(path.read_text(encoding="utf-8"))["runs"][0]

    def test_summary_explains_independent_field_permission_without_object_denial(self):
        summary = SecurityReportGenerator._summarize(self.record())
        self.assertIn("profile.private_note", summary["summary"])
        self.assertIn("visitor", summary["summary"])
        self.assertIn("字段级", summary["verification"])
        self.assertIn("对象", summary["remediation"])
        self.assertNotIn("已确认对象级越权", summary["verification"])

    def test_each_missing_proof_prevents_confirmation_language(self):
        for key in ("policy_id", "context_id", "rule_id", "field_path", "subject_identity",
                    "field_access", "owner_baseline_valid", "resource_bound",
                    "private_value_identifiable", "other_response_valid", "matched_private_data_paths"):
            with self.subTest(key=key):
                item = self.record()
                del item["evidence"]["decision_evidence"][key]
                summary = SecurityReportGenerator._summarize(item)
                self.assertIn("摘要不足", summary["verification"])
                self.assertNotIn("已确认字段级", summary["verification"])

    def test_secure_summary_remains_scoped_to_one_field_identity_and_resource(self):
        item = self.record()
        item["verdict"] = "SECURE"
        summary = SecurityReportGenerator._summarize(item)
        self.assertIn("本次", summary["verification"])
        self.assertIn("字段", summary["verification"])
        self.assertIn("整个对象", summary["verification"])

    def test_sarif_adds_bopla_rule_only_when_selected_and_requires_complete_proof(self):
        self.assertEqual(len(self.sarif([])["tool"]["driver"]["rules"]), 4)
        report = self.sarif(iter([self.record()]))
        self.assertEqual(report["tool"]["driver"]["rules"][-1]["id"], "GT-BOPLA-001")
        result = report["results"][0]
        self.assertEqual(result["ruleId"], "GT-BOPLA-001")
        self.assertEqual(result["ruleIndex"], 4)
        self.assertEqual(result["properties"]["cwe"], "CWE-200")
        self.assertEqual(result["properties"]["fieldPath"], "profile.private_note")
        for key in ("resource_bound", "owner_baseline_valid", "private_value_identifiable"):
            item = self.record()
            item["evidence"]["decision_evidence"][key] = False
            self.assertEqual(self.sarif([item])["results"], [])

    def test_sarif_omits_nonconfirmed_and_duplicate_correlated_observations(self):
        items = []
        for verdict in ("SECURE", "SUSPICIOUS", "INCONCLUSIVE", "confirmed"):
            item = self.record()
            item["verdict"] = verdict
            items.append(item)
        self.assertEqual(self.sarif(items)["results"], [])
        item = self.record()
        item["evidence"]["duplicate_of"] = "existing-private-value-observation"
        self.assertEqual(self.sarif([item])["results"], [])

    def test_bopla_anonymous_reproduction_never_uses_visitor_credentials(self):
        item = self.record("anonymous")
        template = build_reproduction_templates([item], {"Authorization": "Bearer TEST-CREDENTIAL"})[0]
        arguments = shlex.split(template.command)
        self.assertNotIn("-H", arguments)
        self.assertIn("匿名", template.note)
        self.assertNotIn("TEST-CREDENTIAL", template.command)

    def test_bopla_anonymous_reproduction_does_not_require_visitor_headers(self):
        template = build_reproduction_templates([self.record("anonymous")], {})[0]
        self.assertNotIn("-H", shlex.split(template.command))

    def test_bopla_visitor_reproduction_contains_only_placeholders(self):
        template = build_reproduction_templates([self.record()], {
            "Authorization": "Bearer TEST-CREDENTIAL", "Cookie": "sid=PRIVATE-COOKIE",
        })[0]
        self.assertIn("<VISITOR_TOKEN>", template.command)
        self.assertNotIn("TEST-CREDENTIAL", template.command)
        self.assertNotIn("PRIVATE-COOKIE", template.command)
        self.assertNotIn("--data", template.command)

    def test_bopla_reproduction_rejects_unproven_or_write_findings(self):
        for change in ("missing-proof", "PUT", "unsafe-get"):
            item = self.record()
            if change == "missing-proof":
                item["evidence"]["decision_evidence"]["resource_bound"] = False
            elif change == "PUT":
                item["endpoint"] = "PUT /documents/{id}"
            else:
                item["endpoint"] = "GET /documents/delete"
                item["evidence"]["target_url"] = "https://example.test/documents/delete"
            self.assertEqual(build_reproduction_templates([item], {"Authorization": "Bearer t"}), {})

    def test_private_numeric_value_does_not_replace_tool_request_and_field_counts(self):
        item = self.record()
        item["evidence"]["requests_attempted"] = 4
        item["evidence"]["owner"] = {"body": '{"ordinary": 4}'}
        stats = {"total_endpoints": 4, "http_requests_sent": 4, "bopla_fields_checked": 4,
                 "bopla_fields_confirmed": 4, "bopla_field_checks": 4,
                 "bopla_inconclusive_count": 0, "bopla_skipped_count": 0,
                 "unique_confirmed_vulnerabilities": 1}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            SecurityReportGenerator.generate(stats, [], "https://example.test", str(output),
                                             [item], secret_values=("4",))
            report = output.read_text(encoding="utf-8")
        self.assertIn("实际发送 HTTP 请求 4 次", report)
        self.assertIn("BOPLA 字段 4 个", report)
        self.assertIn("请求尝试：4 次", report)
        self.assertNotIn("&quot;ordinary&quot;: 4", report)
        self.assertNotIn('\\&quot;ordinary\\&quot;: 4', report)
        self.assertIn("[REDACTED]", report)

    def test_private_numeric_value_does_not_replace_http_status_metadata(self):
        item = self.record()
        for identity in ("owner", "visitor_cross", "anonymous", "visitor_self"):
            item["evidence"][identity] = {
                "status": 200, "body": '{"status": 200, "ordinary": 200}',
                "sha256": None, "truncated": False,
            }
        item["evidence"]["business_data"] = {"status": 200}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            SecurityReportGenerator.generate({}, [], "https://example.test", str(output),
                                             [item], secret_values=("200",))
            report = output.read_text(encoding="utf-8")
        serialized = re.search(r"<pre>(.*?)</pre>", report, re.S)
        self.assertIsNotNone(serialized)
        evidence = json.loads(html.unescape(serialized.group(1)))
        for identity in ("owner", "visitor_cross", "anonymous", "visitor_self"):
            self.assertEqual(evidence[identity]["status"], 200)
            self.assertIs(type(evidence[identity]["status"]), int)
            self.assertNotIn("200", evidence[identity]["body"])
            self.assertIn("[REDACTED]", evidence[identity]["body"])
        self.assertEqual(evidence["business_data"]["status"], "[REDACTED]")

    def test_bopla_report_reapplies_mandatory_secret_redaction(self):
        marker = "SYNTHETIC-PRIVATE-REPORT-CANARY-817"
        credential = "SYNTHETIC-REPORT-CREDENTIAL-995"
        item = self.record()
        item["evidence"]["owner"] = {"body": json.dumps({"ordinary": marker})}
        item["reason"] = "echo " + marker + " credential " + credential
        finding = copy.deepcopy(item)
        finding["details"] = item["reason"]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            SecurityReportGenerator.generate({}, [finding], "https://example.test", str(output),
                                             [item], secret_values=(marker, credential))
            report = output.read_text(encoding="utf-8")
        self.assertNotIn(marker, report)
        self.assertNotIn(credential, report)
        self.assertIn("profile.private_note", report)
        self.assertIn("[REDACTED]", report)


if __name__ == "__main__":
    unittest.main()
