"""Array evidence paths remain readable without bypassing secret redaction."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.evidence import sanitize_evidence
from core.models import HTTPResult
from core.reporter import SecurityReportGenerator
from core.sarif import SarifReportGenerator


class EvidencePathTests(unittest.TestCase):
    def test_exact_array_paths_survive_repeated_output_boundaries(self):
        evidence = {"decision_evidence": {
            key: ["[0].item", "records[2].note"]
            for key in ("private_data_paths", "owner_private_data_paths", "matched_private_data_paths")}}
        self.assertEqual(evidence, sanitize_evidence(sanitize_evidence(evidence)))

    def test_path_metadata_still_redacts_known_credentials(self):
        result = sanitize_evidence({"private_data_paths": ["[0].credentialvalue"]},
                                   secret_values=["credentialvalue"])
        self.assertNotIn("credentialvalue", str(result))

    def test_json_disguised_as_path_metadata_is_structurally_redacted(self):
        evidence = {"private_data_paths": ['[{"password":"secret-value"}]', '[0].item secret-value']}
        result = sanitize_evidence(evidence)
        self.assertNotIn("secret-value", result["private_data_paths"][0])
        self.assertIn("UNPARSEABLE", result["private_data_paths"][1])

    def test_business_body_does_not_gain_path_metadata_exemption(self):
        result = sanitize_evidence({"body": '{"private_data_paths":["[0].item"]}'})
        self.assertIn("UNPARSEABLE", result["body"])

    def test_configured_private_values_are_redacted_from_results_findings_html_and_sarif(self):
        for path in ("/collection", "/objects/{id}"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                spec = folder / "spec.json"
                spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {path: {"get": {
                    "security": [{"bearer": []}], "responses": {"200": {"description": "OK"}}}}}}), encoding="utf-8")
                policy = {"private_data_paths": ["arbitrary_business_field", "private_number"]}
                auditor = APISentinelAuditor(str(spec), "http://127.0.0.1:1", request_delay=0,
                                            bola_config={"GET " + path: policy})
                private_text = "owner-only-value-unique-83"
                private_number = 83472315
                owner = HTTPResult(200, json.dumps({"arbitrary_business_field": private_text,
                                                    "private_number": private_number, "id": "1001"}))
                visitor_self = HTTPResult(200, '{"id":"1002","arbitrary_business_field":"Visitor own value"}')
                observations = [owner, owner, owner] + ([visitor_self] if "{" in path else [])
                with patch.object(auditor, "_http_request", side_effect=observations):
                    auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
                self.assertTrue(any(item["check"] == "BROKEN_AUTH" and item["verdict"] == "CONFIRMED"
                                    for item in auditor.results))
                auditor.stats["total_endpoints"] = 1
                auditor._finalise_coverage()
                html = folder / "result.html"
                sarif = folder / "result.sarif"
                SecurityReportGenerator.generate(auditor.stats, auditor.findings, auditor.target_base_url,
                                                 str(html), results=auditor.results)
                SarifReportGenerator.generate(results=auditor.results, output_path=str(sarif), target_url=auditor.target_base_url)
                for output in (json.dumps(auditor.results), json.dumps(auditor.findings),
                               html.read_text(encoding="utf-8"), sarif.read_text(encoding="utf-8")):
                    self.assertNotIn(private_text, output)
                    self.assertNotIn(str(private_number), output)
                owner_evidence = next(item for item in auditor.results if item["check"] == "BROKEN_AUTH")["evidence"]["owner"]
                self.assertEqual(owner.status, owner_evidence["status"])
                self.assertIn("[REDACTED]", owner_evidence["body"])
                failed = auditor._safe_body(HTTPResult(0, "", error="error echoed " + private_text), [private_text])
                self.assertNotIn(private_text, str(failed))


if __name__ == "__main__":
    unittest.main()
