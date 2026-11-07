"""Independent public-output checks before a configured private baseline exists."""

import io
import json
import re
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import api_sentinel
from core.auditor import APISentinelAuditor
from core.models import HTTPResult
from core.models import Verdict
from core.reporter import SecurityReportGenerator
from core.evidence import sanitize_url


class PendingPropertyExportTests(unittest.TestCase):
    def test_concurrent_report_uses_the_same_snapshot_for_stats_and_findings(self):
        with tempfile.TemporaryDirectory(prefix="independent-pr44-report-snapshot-") as directory:
            folder = Path(directory)
            spec = folder / "spec.json"
            spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {"/documents": {"get": {"responses": {}}}}}),
                            encoding="utf-8")
            policy = {"policy_id": "independent-snapshot", "context_id": "resource-x-context",
                      "resource_binding": {"id": "resource-x"}, "fields": [{
                          "rule_id": "field", "path": "memo", "access": {"owner": "allow", "visitor": "deny"},
                          "baseline_representation": "full_private_value", "value_is_resource_specific": True}]}
            auditor = APISentinelAuditor(str(spec), "http://127.0.0.1:1", request_delay=0,
                                        bopla_config={"GET /documents": policy})
            ep = auditor.parser.get_endpoints()[0]
            auditor.stats["total_endpoints"] = 1
            auditor._record_result(ep, "BOPLA", Verdict.INCONCLUSIVE, "Initial pending observation",
                                   {"requests_attempted": 3})
            snapshot_taken, writer_done = threading.Event(), threading.Event()
            errors = []

            def writer():
                try:
                    if not snapshot_taken.wait(3):
                        raise AssertionError("Report did not reach its post-snapshot output phase")
                    decision = {"policy_id": policy["policy_id"], "context_id": policy["context_id"],
                                "rule_id": "field", "field_path": "memo", "subject_identity": "visitor"}
                    evidence = {"requests_attempted": 3, "target_url": "http://127.0.0.1:1/documents",
                                "decision_evidence": decision}
                    auditor._record_result(ep, "BOPLA", Verdict.CONFIRMED, "New concurrent observation", evidence,
                                           {"check": "BOPLA", "type": "Synthetic concurrent finding", "cwe": "CWE-200",
                                            "endpoint": "GET /documents", "evidence": evidence})
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    writer_done.set()

            def after_snapshot(value, *args, **kwargs):
                # URL rendering follows the report's protected record snapshot.
                # A real writer completing here must not mutate that snapshot's stats.
                snapshot_taken.set()
                if not writer_done.wait(3):
                    raise AssertionError("Concurrent record append did not finish")
                return sanitize_url(value, *args, **kwargs)

            worker = threading.Thread(target=writer)
            worker.start()
            try:
                output = folder / "snapshot.html"
                with patch("core.reporter.sanitize_url", side_effect=after_snapshot):
                    SecurityReportGenerator.generate(auditor.stats, auditor.findings, auditor.target_base_url,
                                                     str(output), results=auditor.results)
            finally:
                snapshot_taken.set()
                worker.join(4)
            self.assertFalse(worker.is_alive())
            self.assertEqual([], errors)
            self.assertEqual(1, auditor.stats["confirmed"], "The writer genuinely added its later finding")
            rendered = output.read_text(encoding="utf-8")
            card = re.search(r'<div class="label">确认漏洞</div>\s*<div class="value"[^>]*>(\d+)</div>', rendered)
            finding_snapshot = re.search(r"const totals = \{result: \d+, finding: (\d+)\}", rendered)
            self.assertIsNotNone(card)
            self.assertIsNotNone(finding_snapshot)
            self.assertEqual(card.group(1), finding_snapshot.group(1),
                             "One HTML artifact must not combine new stats with an older finding snapshot")

    def test_failed_property_baseline_keeps_earlier_echoes_out_of_json_html_and_curl(self):
        private = "pending-owner-private-value-78164"
        with tempfile.TemporaryDirectory(prefix="independent-pr44-pending-export-") as directory:
            folder = Path(directory)
            operation = {"security": [{"bearer": []}], "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Selected resource"}}}
            spec = folder / "spec.json"
            spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {
                "/echo/{id}": {"get": operation}, "/protected/{id}": {"get": operation}}}), encoding="utf-8")
            config = folder / "config.json"
            config.write_text(json.dumps({
                "identities": {"owner": {"id": "resource-x", "token": "Bearer independent-owner-credential",
                                           "parameters": {}},
                               "visitor": {"id": "resource-y", "token": "Bearer independent-visitor-credential",
                                             "parameters": {}}, "anonymous": {}},
                "parameter_values": {"GET /echo/{id}": {"owner": {"id": private},
                                                          "visitor": {"id": "public-visitor-resource"}}},
                "bopla": {"GET /protected/{id}": {
                    "policy_id": "independent-pending-fields", "context_id": "selected-private-resource",
                    "resource_binding": {"id": "resource-x"}, "fields": [{
                        "rule_id": "protected-note", "path": "memo",
                        "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                        "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}},
            }), encoding="utf-8")
            wire = []

            def response(auditor, method, url, data=None, identity_name="anonymous", **kwargs):
                self.assertEqual("GET", method)
                path = urlsplit(url).path
                wire.append((method, path, identity_name))
                if path.startswith("/protected/"):
                    return HTTPResult(0, "", error="Synthetic baseline timeout")
                if identity_name == "anonymous":
                    return HTTPResult(403, '{"error":"Forbidden"}')
                if path.endswith("/public-visitor-resource"):
                    return HTTPResult(200, '{"id":"resource-y","title":"Visitor document","memo":"Visitor own memo"}')
                return HTTPResult(200, json.dumps({"id": "resource-x", "title": "Owner document", "memo": private}))

            html, exported, sarif = folder / "report.html", folder / "report.json", folder / "report.sarif"
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(APISentinelAuditor, "_http_request", new=response), \
                    patch("urllib.request.getproxies", return_value={}), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                code = api_sentinel.main(["--spec", str(spec), "--config", str(config),
                                          "--target", "http://127.0.0.1:48987", "--delay", "0",
                                          "--output", str(html), "--export-json", str(exported),
                                          "--export-sarif", str(sarif), "--include-sensitive-evidence"])
            self.assertEqual(0, code, stderr.getvalue())
            report = json.loads(exported.read_text(encoding="utf-8"))
            self.assertTrue(any(item["check"] == "BOLA" and item["verdict"] == "CONFIRMED"
                                for item in report["results"]),
                            "Do not hide the independent legacy finding: " + repr([
                                (item["check"], item["verdict"], item["reason"]) for item in report["results"]]))
            self.assertTrue(any(item["check"] == "BOPLA" and item["verdict"] == "INCONCLUSIVE"
                                for item in report["results"]))
            self.assertEqual(8, len(wire))
            for label, output in (("HTML/cURL", html.read_text(encoding="utf-8")),
                                  ("JSON", exported.read_text(encoding="utf-8")),
                                  ("SARIF", sarif.read_text(encoding="utf-8")),
                                  ("stdout", stdout.getvalue()), ("stderr", stderr.getvalue())):
                with self.subTest(output=label):
                    self.assertNotIn(private, output,
                                     "A failed or pending Owner baseline cannot release unclassified echoes or concrete URLs")


if __name__ == "__main__":
    unittest.main()
