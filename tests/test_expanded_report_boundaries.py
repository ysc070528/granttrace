"""Expanded output must preserve confidence, authority and replacement semantics."""

import json
import shlex
import tempfile
import unittest
from pathlib import Path

from core.reporter import SecurityReportGenerator
from core.reproduction import build_reproduction_templates
from core.sarif import SarifReportGenerator


class ExpandedReportBoundaryTests(unittest.TestCase):
    def test_successful_anonymous_json_without_private_evidence_does_not_become_report_proof(self):
        summary = SecurityReportGenerator._summarize({
            "check": "BROKEN_AUTH", "verdict": "CONFIRMED",
            "evidence": {"anonymous": {"status": 200, "body": '{"message":"public"}'}},
        })
        self.assertIn("摘要不足", summary["verification"])
        self.assertIn("不能单独证明", summary["verification"])
        self.assertNotIn("已确认未授权访问", summary["verification"])

    def test_auth_summary_explains_positive_private_value_and_owner_baseline(self):
        summary = SecurityReportGenerator._summarize({
            "check": "BROKEN_AUTH", "verdict": "CONFIRMED",
            "evidence": {"decision_evidence": {
                "owner_baseline_valid": True, "requires_auth": True,
                "matched_private_data_paths": ["private_note"],
            }},
        })
        self.assertIn("Owner 私有", summary["verification"])
        self.assertIn("有效 Owner 基线", summary["verification"])

    def test_admin_naming_does_not_supply_report_privilege_evidence(self):
        summary = SecurityReportGenerator._summarize({
            "check": "BFLA", "verdict": "CONFIRMED", "endpoint": "GET /admin/settings",
        })
        self.assertIn("角色边界", summary["verification"])
        self.assertIn("不能单独证明", summary["verification"])
        self.assertTrue(any("Owner 身份本身不表示管理员" in step for step in summary["retest"]))

    def test_successful_readback_and_ack_do_not_supply_report_state_authority(self):
        summary = SecurityReportGenerator._summarize({
            "check": "MASS_ASSIGNMENT", "verdict": "CONFIRMED",
            "evidence": {"field": "role", "after": {"status": 200},
                         "rollback_verified": True, "recovery": {"status": 200}},
        })
        self.assertIn("不能单独证明持久变化", summary["verification"])
        self.assertIn("独立权威状态证据", summary["verification"])
        self.assertIn("ACK 不构成证明", summary["verification"])

    def test_put_partial_probe_cannot_be_reproduced_as_resource_replacement(self):
        finding = {
            "cwe": "CWE-915", "endpoint": "PUT /records/one", "verdict": "CONFIRMED",
            "injected_payload": {"role": "admin"},
            "evidence": {"target_url": "https://example.test/records/one",
                         "request_content_type": "application/json", "rollback_verified": True},
        }
        self.assertEqual(build_reproduction_templates([finding], {"Authorization": "Bearer secret"}), {})

    def test_anonymous_reproduction_omits_every_visitor_credential(self):
        finding = {"cwe": "CWE-306", "endpoint": "GET /profile", "verdict": "CONFIRMED",
                   "evidence": {"target_url": "https://example.test/profile"}}
        template = build_reproduction_templates([finding], {
            "Authorization": "Bearer secret", "X-API-Key": "private-key", "Cookie": "sid=private",
        })[0]
        arguments = shlex.split(template.command)
        self.assertNotIn("-H", arguments)
        self.assertIn("匿名", template.note)
        self.assertNotIn("secret", template.command)

    def test_all_expanded_sarif_categories_require_exact_confirmed_verdict(self):
        checks = {"BOLA": "GT-BOLA-001", "MASS_ASSIGNMENT": "GT-MASS-001",
                  "BROKEN_AUTH": "GT-AUTH-001", "BFLA": "GT-BFLA-001"}
        results = [{"check": check, "endpoint": "GET /private", "verdict": verdict}
                   for check in checks
                   for verdict in ("CONFIRMED", "SUSPICIOUS", "INCONCLUSIVE", "SECURE", "confirmed", None)]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.sarif"
            SarifReportGenerator.generate(results, "https://example.test", str(target))
            report = json.loads(target.read_text(encoding="utf-8"))
        exported = report["runs"][0]["results"]
        self.assertEqual(len(exported), len(checks))
        self.assertEqual({item["ruleId"] for item in exported}, set(checks.values()))
        self.assertTrue(all(item["properties"]["granttraceVerdict"] == "CONFIRMED" for item in exported))


if __name__ == "__main__":
    unittest.main()
