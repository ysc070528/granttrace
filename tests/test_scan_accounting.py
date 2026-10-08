"""Request evidence, endpoint coverage and legacy report accounting boundaries."""

import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from core.auditor import APISentinelAuditor
from core.models import HTTPResult, Verdict
from core.reporter import SecurityReportGenerator


class ScanAccountingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-accounting-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.spec = self.folder / "spec.json"
        self.spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {}}), encoding="utf-8")

    def auditor(self, **kwargs):
        return APISentinelAuditor(str(self.spec), "http://127.0.0.1:8080", request_delay=0, **kwargs)

    def render(self, stats, results):
        output = self.folder / "report.html"
        SecurityReportGenerator.generate(stats, [], "http://127.0.0.1:8080", str(output), results=results)
        return output.read_text(encoding="utf-8")

    def test_mixed_scan_counts_transport_attempts_separately_from_conclusive_results(self):
        paths = {}
        for name in ("secure", "records", "reports", "public", "suspicious", "missing", "baseline", "error", "invalid"):
            paths[f"/{name}/{{id}}"] = {"get": {
                "security": [] if name == "public" else [{"bearer": []}],
                "parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "integer", "minimum": 1}}],
                "responses": {"200": {"description": "Selected resource"}},
            }}
        paths["/items"] = {"get": {"responses": {"200": {"description": "List"}}}}
        paths["/items/{id}/delete"] = {"get": {"operationId": "delete_item", "responses": {}}}
        paths["/unsupported"] = {"post": {"responses": {}}}
        paths["/write/{id}"] = {"patch": {"responses": {}}}
        self.spec.write_text(json.dumps({"openapi": "3.0.3", "paths": paths}), encoding="utf-8")
        auditor = self.auditor(
            max_workers=1,
            parameter_values={"GET /invalid/{id}": {"owner": {"id": 0}}},
            bola_config={"GET /reports/{id}": {"expected_visitor_access": "allow"}},
        )

        def response(method, url, data=None, identity_name="anonymous", **kwargs):
            self.assertEqual("GET", method)
            name, resource_id = urlsplit(url).path.strip("/").split("/")
            self.assertNotIn(name, {"invalid", "items", "unsupported", "write"})
            if name == "error":
                return HTTPResult(0, "", error="synthetic transport failure")
            if name == "missing" and identity_name == "owner":
                return HTTPResult(404, '{"message":"Resource not found"}')
            if name == "baseline" and identity_name == "visitor" and resource_id == "1002":
                return HTTPResult(403, '{"message":"Forbidden"}')
            if name != "public" and identity_name == "anonymous" and name != "suspicious":
                return HTTPResult(401, '{"message":"JWT Token required!"}')
            if name == "secure" and identity_name == "visitor" and resource_id == "1001":
                return HTTPResult(403, '{"message":"Forbidden"}')
            if name == "public":
                resource_id = "1001"
            body = {"id": resource_id, "title": f"Record {resource_id}", "private_note": f"Note {resource_id}"}
            return HTTPResult(200, json.dumps(body))

        with patch.object(auditor, "_http_request", side_effect=response) as transport, \
             patch("socket.socket", side_effect=AssertionError("Unexpected network access")), redirect_stdout(io.StringIO()):
            auditor.run()
        self.assertEqual(32, transport.call_count)
        expected = {
            "total_endpoints": 13, "total_checks": 13, "audited_count": 8,
            "attempted_endpoints": 8, "conclusive_count": 4, "conclusive_endpoints": 4,
            "confirmed": 1, "secure_endpoints": 1, "public_endpoints": 1,
            "authorized_endpoints": 1, "suspicious_count": 1, "inconclusive_count": 3,
            "skipped_count": 4, "error_count": 1, "coverage_pct": 61.5,
            "conclusive_coverage_pct": 30.8,
        }
        for key, value in expected.items():
            with self.subTest(stat=key):
                self.assertEqual(value, auditor.stats[key])
        by_endpoint = {item["endpoint"]: item for item in auditor.results}
        for endpoint, category in (
            ("GET /items", "not_applicable"),
            ("GET /items/{id}/delete", "safety_policy"),
            ("POST /unsupported", "detector_unimplemented"),
            ("PATCH /write/{id}", "safety_policy"),
            ("GET /invalid/{id}", "invalid_input"),
        ):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(0, by_endpoint[endpoint]["evidence"]["requests_attempted"])
                self.assertEqual(category, by_endpoint[endpoint]["evidence"]["reason_category"])
        for endpoint, category in (("GET /missing/{id}", "missing_resource_id"),
                                   ("GET /baseline/{id}", "missing_baseline"),
                                   ("GET /suspicious/{id}", "insufficient_evidence")):
            self.assertEqual(category, by_endpoint[endpoint]["evidence"]["reason_category"])
            self.assertEqual(4, by_endpoint[endpoint]["evidence"]["requests_attempted"])
        report = self.render(auditor.stats, auditor.results)
        self.assertIn("本次尝试端点 8/13，确定性端点 4/13", report)
        self.assertIn("检查结果记录 13 条", report)
        self.assertIn("已尝试的主检查 8 条，确定性主检查 4 条", report)
        for verdict in ("CONFIRMED", "SECURE", "PUBLIC", "AUTHORIZED"):
            self.assertIn(f"{verdict}: 1", report)
        self.assertIn("安全策略阻止执行 · 请求尝试：0 次", report)
        self.assertIn("缺少有效资源 ID · 请求尝试：4 次", report)

    def test_duplicate_primary_results_and_recovery_do_not_inflate_endpoint_coverage(self):
        auditor = self.auditor()
        ep = {"method": "GET", "path": "/items/{id}"}
        auditor.stats["total_endpoints"] = 1
        for verdict in (Verdict.CONFIRMED, Verdict.SECURE, Verdict.PUBLIC, Verdict.AUTHORIZED,
                        Verdict.SUSPICIOUS, Verdict.INCONCLUSIVE, Verdict.ERROR):
            auditor._record_result(ep, "BOLA", verdict, "Synthetic recorded result",
                                   evidence={"requests_attempted": 4})
        auditor._record_result(ep, "ROLLBACK", Verdict.ERROR, "Synthetic recovery failure",
                               evidence={"requests_attempted": 2})
        auditor._finalise_coverage()
        self.assertEqual(8, auditor.stats["total_checks"])
        self.assertEqual(7, auditor.stats["audited_count"])
        self.assertEqual(4, auditor.stats["conclusive_count"])
        self.assertEqual(1, auditor.stats["attempted_endpoints"])
        self.assertEqual(1, auditor.stats["conclusive_endpoints"])
        self.assertEqual(100.0, auditor.stats["coverage_pct"])
        self.assertEqual(100.0, auditor.stats["conclusive_coverage_pct"])

    def test_local_errors_and_zero_request_conclusive_records_are_not_coverage(self):
        auditor = self.auditor()
        auditor.stats["total_endpoints"] = 2
        auditor._record_result({"method": "GET", "path": "/local"}, "BOLA", Verdict.ERROR, "Preflight exception")
        auditor._record_result({"method": "GET", "path": "/unsupported"}, "BOLA", Verdict.SECURE,
                               "Caller supplied verdict without request evidence", evidence={"requests_attempted": 0})
        auditor._finalise_coverage()
        self.assertEqual(0, auditor.stats["audited_count"])
        self.assertEqual(0, auditor.stats["conclusive_count"])
        self.assertEqual(0.0, auditor.stats["coverage_pct"])
        self.assertEqual(0.0, auditor.stats["conclusive_coverage_pct"])

    def test_failed_network_attempt_is_counted_without_calling_real_network(self):
        auditor = self.auditor()
        with patch.object(auditor._opener, "open", side_effect=urllib.error.URLError("synthetic failure")) as opener:
            failed = auditor._http_request("GET", "http://127.0.0.1:8080/items/1001")
        opener.assert_called_once()
        self.assertEqual(0, failed.status)
        ep = {"method": "GET", "path": "/items/{id}"}
        result = auditor._record_result(ep, "BOLA", Verdict.ERROR, failed.error, {"owner": auditor._safe_body(failed)})
        auditor.stats["total_endpoints"] = 1
        auditor._finalise_coverage()
        self.assertEqual(1, result["evidence"]["requests_attempted"])
        self.assertEqual(1, auditor.stats["audited_count"])
        self.assertEqual(100.0, auditor.stats["coverage_pct"])
        self.assertEqual(0.0, auditor.stats["conclusive_coverage_pct"])

    def test_legacy_report_does_not_invent_execution_accounting(self):
        result = {"endpoint": "GET /items/{id}", "check": "BOLA", "verdict": "SECURE",
                  "evidence": {"owner": {"status": 200}, "visitor_cross": {"status": 403}}}
        report = self.render({"total_endpoints": 1, "coverage_pct": 100.0, "conclusive_coverage_pct": 100.0}, [result])
        self.assertIn("此报告未记录端点级请求计数", report)
        self.assertIn("请求尝试：未记录；不能据此判断是否发送请求", report)
        self.assertNotIn("本次尝试端点 1/1", report)
        self.assertNotIn("请求尝试：2 次", report)
        self.assertIn("100.0%", report)

    def test_execution_category_and_missing_evidence_are_escaped_and_scoped(self):
        hostile = "<img src=x onerror=alert(1)>"
        result = {"endpoint": "GET /orders/{id}", "check": "BOLA", "verdict": "SUSPICIOUS",
                  "evidence": {"reason_category": hostile, "requests_attempted": 4,
                               "decision_evidence": {"anonymous_authentication_violation": True,
                                                     "anonymous_owner_value_match": True,
                                                     "missing_evidence": ["anonymous_denial_baseline", hostile]}}}
        explanation = SecurityReportGenerator._summarize(result)
        self.assertIn("匿名访问与对象级授权分别评估", explanation["verification"])
        self.assertIn("所缺证据：有效匿名拒绝基线", explanation["verification"])
        self.assertNotIn("已确认对象级越权", explanation["verification"])
        report = self.render({}, [result])
        self.assertNotIn(hostile, report)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", report)


if __name__ == "__main__":
    unittest.main()
