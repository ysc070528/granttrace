"""Report explanations must stay within recorded evidence and remain usable offline."""

import json
import shutil
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

from core.evidence import sanitize_evidence
from core.reporter import SecurityReportGenerator


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.items = []
        self.scripts = []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "data-audit-item" in attrs:
            self.items.append({
                "auditItem": attrs["data-audit-item"],
                "endpoint": attrs["data-endpoint"],
                "verdict": attrs["data-verdict"],
            })
        if tag == "script":
            self.in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts.append(data)


class ReportUsabilityTests(unittest.TestCase):
    def render(self, findings=None, results=None, target="https://example.test"):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            SecurityReportGenerator.generate(
                {"conclusive_count": 1}, findings or [], target, str(report), results=results,
            )
            return report.read_text(encoding="utf-8")

    def test_bola_summary_names_roles_resource_and_recorded_confirmation(self):
        item = {
            "check": "BOLA", "verdict": "CONFIRMED",
            "evidence": {
                "target_url": "https://example.test/documents/10?token=secret-value",
                "visitor_cross": {"status": 200},
                "decision_evidence": {"confirmation_signals": ["matching_resource_identifier"]},
            },
        }
        explanation = SecurityReportGenerator._summarize(item)
        self.assertIn("Visitor 身份访问配置为 Owner", explanation["summary"])
        self.assertIn("/documents/10", explanation["summary"])
        self.assertNotIn("secret-value", explanation["summary"])
        self.assertIn("资源标识一致", explanation["verification"])
        self.assertIn("团队共享", explanation["remediation"])
        self.assertTrue(any("两个独立账户" in step for step in explanation["retest"]))

    def test_missing_evidence_does_not_invent_request_or_response_match(self):
        explanation = SecurityReportGenerator._summarize({"cwe": "CWE-639"})
        self.assertIn("具体请求对照未记录", explanation["summary"])
        self.assertIn("摘要不足", explanation["verification"])
        self.assertNotIn("资源标识一致", explanation["verification"])

    def test_mass_assignment_explains_field_readback_and_recovery_scope(self):
        item = {
            "cwe": "CWE-915", "target_url": "https://example.test/users/20",
            "evidence": {
                "field": "isAdmin", "readback_field": "permissions.admin",
                "after": {"status": 200}, "rollback_verified": True,
                "ignored_readback_paths": ["updated_at"], "untested_fields": ["role"],
            },
        }
        explanation = SecurityReportGenerator._summarize(item)
        self.assertIn("Visitor 提交字段 isAdmin", explanation["summary"])
        self.assertIn("permissions.admin", explanation["summary"])
        self.assertIn("独立读回确认", explanation["verification"])
        self.assertIn("原状态已通过读回核验", explanation["verification"])
        self.assertIn("不含配置中忽略", explanation["verification"])
        self.assertIn("1 个配置字段未执行", explanation["verification"])

    def test_recovery_false_and_missing_cannot_be_presented_as_success(self):
        for flag in (False, None, "true"):
            with self.subTest(flag=flag):
                explanation = SecurityReportGenerator._summarize({
                    "cwe": "CWE-915", "evidence": {"field": "isAdmin", "rollback_verified": flag},
                })
                self.assertNotIn("原状态已通过", explanation["verification"])
                self.assertIn("恢复", explanation["verification"])
                self.assertIn("摘要不足", explanation["verification"])
                if flag is False:
                    self.assertIn("暂停写入测试", explanation["verification"])
                else:
                    self.assertIn("不能据此认为", explanation["verification"])

    def test_authorized_access_is_scoped_to_configured_pair_and_resource(self):
        explanation = SecurityReportGenerator._summarize({"check": "BOLA", "verdict": "AUTHORIZED"})
        self.assertIn("按配置获准读取", explanation["verification"])
        self.assertIn("仅适用于本次配置的身份与资源组合", explanation["verification"])
        self.assertNotIn("已确认对象级越权", explanation["verification"])
        report = self.render(results=[{"check": "BOLA", "verdict": "AUTHORIZED", "endpoint": "GET /teams/{id}"}])
        self.assertIn("<option value='AUTHORIZED'>", report)

    def test_explanations_appear_before_raw_evidence_and_all_dynamic_text_is_escaped(self):
        hostile = "<img src=x onerror=alert(1)>"
        finding = {
            "cwe": "CWE-915", "type": hostile, "endpoint": "PATCH /" + hostile,
            "severity": "Critical\" onclick=\"alert(1)", "details": hostile,
            "evidence": {"field": hostile, "after": {"status": 200}, "rollback_verified": False},
        }
        report = self.render(findings=[finding], results=[{
            "endpoint": "GET /" + hostile, "check": hostile, "reason": hostile,
            "verdict": "ERROR\" onmouseover=\"alert(1)",
        }])
        self.assertNotIn(hostile, report)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", report)
        self.assertIn("data-verdict='ERROR&quot; ONMOUSEOVER=&quot;ALERT(1)'", report)
        self.assertLess(report.index("Visitor 提交字段"), report.index("查看已最小化的证据"))
        self.assertLess(report.index("安全复验步骤", report.index('<article')), report.index("查看已最小化的证据"))
        parser = ReportParser()
        parser.feed(report)
        self.assertEqual(len(parser.items), 2)
        self.assertEqual(parser.items[0]["verdict"], "ERROR\" ONMOUSEOVER=\"ALERT(1)")
        self.assertEqual(len(parser.scripts), 1)
        self.assertNotIn(hostile, parser.scripts[0])

    def test_page_target_and_sanitized_evidence_do_not_disclose_credentials(self):
        # Public, fixed synthetic data: never taken from an account, environment,
        # or credential store. The fixture exercises credential redaction.
        example_marker = "REPORT-SECRET-CREDENTIAL"
        finding = sanitize_evidence({
            "cwe": "CWE-639", "endpoint": "GET /items/{id}",
            "evidence": {
                "target_url": "https://example.test/items/10?api_key=" + example_marker,
                "visitor_cross": {"body": json.dumps({"Authorization": "Bearer " + example_marker})},
            },
        }, secret_values=[example_marker])
        report = self.render(findings=[finding], target="https://user:" + example_marker + "@example.test?token=" + example_marker)
        self.assertNotIn(example_marker, report)
        self.assertNotIn("user:", report)
        self.assertIn("[REDACTED]", report)

    @unittest.skipUnless(shutil.which("node"), "Node.js is optional for offline report filter checks")
    def test_offline_filters_execute_search_status_combination_and_empty_state(self):
        rows = [
            {"endpoint": "GET /users/{id}", "check": "BOLA", "verdict": "CONFIRMED"},
            {"endpoint": "GET /teams/{id}", "check": "BOLA", "verdict": "AUTHORIZED"},
            {"endpoint": "PATCH /users/{id}", "check": "MASS_ASSIGNMENT", "verdict": "ERROR"},
        ]
        report = self.render(findings=[{"endpoint": "GET /users/{id}"}], results=rows)
        parser = ReportParser()
        parser.feed(report)
        script = "".join(parser.scripts)
        self.assertNotIn("fetch(", script)
        self.assertNotIn("innerHTML", script)
        harness = """
const assert = require('node:assert/strict');
const vm = require('node:vm');
const controls = {};
for (const id of ['endpoint-search', 'verdict-filter', 'filter-count', 'no-matching-results', 'no-matching-findings']) {
  controls[id] = {value: '', hidden: false, textContent: '', handlers: {},
    addEventListener(event, callback) { this.handlers[event] = callback; }};
}
const items = ITEMS.map(dataset => ({dataset, hidden: false}));
const document = {getElementById: id => controls[id],
  querySelectorAll: selector => selector === '[data-audit-item]' ? items : []};
vm.runInNewContext(SCRIPT, {document});
assert.equal(items.filter(item => !item.hidden).length, 4);
controls['endpoint-search'].value = '/USERS';
controls['endpoint-search'].handlers.input();
assert.equal(controls['filter-count'].textContent, '端点结果 2/3 条 · 确认漏洞 1/1 条');
controls['verdict-filter'].value = 'ERROR';
controls['verdict-filter'].handlers.change();
assert.equal(controls['filter-count'].textContent, '端点结果 1/3 条 · 确认漏洞 0/1 条');
assert.equal(controls['no-matching-findings'].hidden, false);
controls['endpoint-search'].value = '/teams';
controls['endpoint-search'].handlers.input();
assert.equal(controls['no-matching-results'].hidden, false);
controls['verdict-filter'].value = 'AUTHORIZED';
controls['verdict-filter'].handlers.change();
assert.equal(controls['filter-count'].textContent, '端点结果 1/3 条 · 确认漏洞 0/1 条');
assert.equal(controls['no-matching-results'].hidden, true);
controls['endpoint-search'].value = '';
controls['verdict-filter'].value = '';
controls['verdict-filter'].handlers.change();
assert.equal(items.filter(item => !item.hidden).length, 4);
"""
        harness = harness.replace("ITEMS", json.dumps(parser.items)).replace("SCRIPT", json.dumps(script))
        result = subprocess.run([shutil.which("node"), "-"], input=harness, text=True,
                                encoding="utf-8", capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
