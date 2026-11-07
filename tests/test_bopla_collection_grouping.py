"""Independent final review: collection and property evidence share resource roots."""

import io
import copy
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.models import HTTPResult


class IndependentCollectionGroupingTests(unittest.TestCase):
    def test_collection_and_field_proofs_for_the_same_single_resource_share_one_finding(self):
        for count, only_last in ((1, False), (2, False), (2, True)):
            with self.subTest(resources=count, only_last_exposed=only_last):
                self.check_collection_grouping(count, only_last)

    def check_collection_grouping(self, count, only_last):
        with tempfile.TemporaryDirectory(prefix="pr44-final-collection-group-") as temporary:
            spec = Path(temporary) / "spec.json"
            spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {"/documents": {"get": {
                "security": [{"bearer": []}], "responses": {"200": {"description": "OK"}}}}}}), encoding="utf-8")
            key = "GET /documents"
            private_paths = [f"items[{index}].memo" for index in range(count)]
            policy = {"policy_id": "selected-document-field", "context_id": "selected-tenant-document",
                      "resource_binding": {f"items[{index}].{key}": value
                                           for index in range(count)
                                           for key, value in (("id", f"document-{index}"), ("tenant", "tenant-a"))},
                      "fields": [{"rule_id": f"private-memo-{index}", "path": private_path,
                                  "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                                  "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}
                                 for index, private_path in enumerate(private_paths)]}
            auditor = APISentinelAuditor(str(spec), "http://127.0.0.1:1", request_delay=0,
                                        bola_config={key: {"private_data_paths": private_paths,
                                                           "expected_visitor_access": "deny"}},
                                        bopla_config={key: policy})
            document = {"items": [{"id": f"document-{index}", "tenant": "tenant-a",
                                     "memo": f"independent-final-private-memo-{index}-7826"}
                                    for index in range(count)]}
            owner = HTTPResult(200, json.dumps(document))
            visitor_document = copy.deepcopy(document)
            if only_last:
                for item in visitor_document["items"][:-1]:
                    item["memo"] = "different-visitor-visible-memo"
            visitor = HTTPResult(200, json.dumps(visitor_document))
            denied = HTTPResult(403, '{"error":"Forbidden"}')
            with patch.object(auditor, "_http_request", side_effect=[owner, visitor, denied]) as transport, \
                    redirect_stdout(io.StringIO()):
                auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
            auditor.stats["total_endpoints"] = 1
            auditor._finalise_coverage()
            confirmed = [item for item in auditor.results if item["verdict"] == "CONFIRMED"]
            self.assertEqual({"BOLA", "BOPLA"}, {item["check"] for item in confirmed})
            self.assertEqual(3, transport.call_count)
            exposed_resources = 1 if only_last else count
            self.assertEqual(exposed_resources, len({item["evidence"]["leak_group"] for item in confirmed}),
                             "Both proofs concern the same document, field and low-privilege identity")
            self.assertEqual(exposed_resources, auditor.stats["unique_confirmed_vulnerabilities"])
            self.assertEqual(exposed_resources, len(auditor.findings))


if __name__ == "__main__":
    unittest.main()
