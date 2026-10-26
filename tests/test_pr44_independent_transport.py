"""Independent PR44 transport safety and observation accounting counterexamples."""

import copy
import io
import json
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from core.auditor import APISentinelAuditor
from core.models import HTTPResult
from core.reporter import SecurityReportGenerator


OWNER_SECRET = "independent-transport-owner-value-89154"


def field_policy():
    return {
        "policy_id": "independent-transport", "context_id": "resource-x-context",
        "resource_binding": {"id": "resource-x"},
        "fields": [{"rule_id": "confidential-field", "path": "confidential",
                    "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                    "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}],
    }


class LocalReadServer:
    """Separate wire journal; drops deliberately occur after receiving a request."""

    def __init__(self, mode="valid"):
        self.mode = mode
        self.requests = []
        self.release = threading.Event()
        state = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                header = self.headers.get("Authorization", "")
                identity = ("owner" if header == "Bearer independent-owner-credential" else
                            "visitor" if header == "Bearer independent-visitor-credential" else "anonymous")
                state.requests.append((self.command, self.path, identity))
                if state.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", "/delete_all_records")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if state.mode in {"drop", "timeout"} and identity != "owner":
                    if state.mode == "timeout":
                        state.release.wait(0.4)
                    self.close_connection = True
                    return
                secret = "owner" if state.mode == "metadata-secret" else OWNER_SECRET
                if identity == "owner":
                    status, data = 200, {"id": "resource-x", "confidential": secret}
                elif state.mode == "deny":
                    status, data = 403, {"error": "Forbidden"}
                elif state.mode == "error-data":
                    status, data = 500, {"id": "resource-x", "confidential": OWNER_SECRET}
                else:
                    status, data = 200, {"id": "resource-x", "confidential": secret}
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def write_request(self):
                state.requests.append((self.command, self.path, "WRITE"))
                self.send_error(405)

            do_PATCH = do_PUT = do_POST = do_DELETE = write_request

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.target = "http://127.0.0.1:" + str(self.server.server_port)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class IndependentPropertyTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="independent-pr44-transport-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def auditor(self, target="http://127.0.0.1:1", *, path="/documents", method="GET",
                operation=None, policy=None, legacy=None, enabled=True, **kwargs):
        operation = copy.deepcopy(operation or {"security": [], "responses": {"200": {"description": "OK"}}})
        if "{" in path:
            operation.setdefault("parameters", [{"name": "id", "in": "path", "required": True,
                                                  "schema": {"type": "string"}}])
        spec = self.folder / "spec.json"
        spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {path: {method.lower(): operation}}}),
                        encoding="utf-8")
        identities = {"owner": {"id": "resource-x", "token": "Bearer independent-owner-credential", "parameters": {"id": "resource-x"}},
                      "visitor": {"id": "resource-y", "token": "Bearer independent-visitor-credential", "parameters": {"id": "resource-y"}},
                      "anonymous": {}}
        key = method + " " + path
        with patch("urllib.request.getproxies", return_value={}):
            return APISentinelAuditor(str(spec), target, identities_config=identities, request_delay=0,
                                      request_timeout=0.1, bola_config={key: legacy} if legacy is not None else None,
                                      bopla_config={key: policy or field_policy()} if enabled else {}, **kwargs)

    def scan(self, auditor):
        with redirect_stdout(io.StringIO()):
            auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
        auditor.stats["total_endpoints"] = 1
        auditor._finalise_coverage()
        return [result for result in auditor.results if result["check"] == "BOPLA"]

    def test_public_no_selector_and_multiple_rules_use_one_observation_per_identity(self):
        policy = field_policy()
        extra = copy.deepcopy(policy["fields"][0])
        extra.update(rule_id="unobserved-field", path="absent")
        policy["fields"].append(extra)
        with LocalReadServer() as api:
            auditor = self.auditor(api.target, policy=policy)
            results = self.scan(auditor)
            self.assertEqual(3, len(api.requests))
            self.assertEqual({"GET"}, {request[0] for request in api.requests})
            self.assertEqual(4, len(results))
            self.assertEqual(3, auditor.stats["transport_attempts"])
            self.assertEqual("SKIPPED", next(item for item in auditor.results if item["check"] == "BOLA")["verdict"])
            self.assertTrue(any(item["verdict"] == "CONFIRMED" for item in results))

    def test_inapplicable_legacy_collection_policy_does_not_prevent_safe_field_probes(self):
        with LocalReadServer() as api:
            auditor = self.auditor(api.target, legacy={"resource_id_paths": ["id"]})
            results = self.scan(auditor)
            self.assertEqual(3, len(api.requests))
            self.assertTrue(all(item["verdict"] == "CONFIRMED" for item in results))

    def test_invalid_legacy_bola_policy_cannot_relax_bopla_transport_safety(self):
        with LocalReadServer() as api:
            auditor = self.auditor(api.target, legacy={"unknown-policy-setting": "invalid"})
            results = self.scan(auditor)
            self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
            self.assertEqual(0, auditor.results[0]["evidence"]["requests_attempted"])
            self.assertEqual(3, len(api.requests))
            self.assertTrue(all(item["verdict"] == "CONFIRMED" for item in results))

    def test_bopla_rejects_all_write_methods_before_transport(self):
        for method in ("PATCH", "PUT", "POST", "DELETE", "HEAD"):
            with self.subTest(method=method):
                auditor = self.auditor(method=method)
                with patch.object(auditor._opener, "open") as opener:
                    self.scan(auditor)
                opener.assert_not_called()
                self.assertEqual("SKIPPED", auditor.results[0]["verdict"])
                self.assertEqual(0, auditor.stats["transport_attempts"])

    def test_dangerous_get_metadata_or_static_path_is_blocked_before_transport(self):
        for path, metadata in (("/documents/{id}/delete", {}),
                               ("/documents", {"operationId": "deleteAllDocuments"}),
                               ("/documents", {"summary": "Deletes every document"})):
            with self.subTest(path=path, metadata=metadata):
                auditor = self.auditor(path=path, operation={"responses": {}, **metadata})
                with patch.object(auditor._opener, "open") as opener:
                    self.scan(auditor)
                opener.assert_not_called()
                self.assertEqual("SKIPPED", auditor.results[0]["verdict"])

    def test_ambiguous_concrete_owner_or_visitor_path_has_zero_opener_calls(self):
        for identity in ("owner", "visitor"):
            for value in ("../delete", "safe%2Fdelete", "safe\\delete", "safe\nreset"):
                with self.subTest(identity=identity, value=value):
                    auditor = self.auditor(path="/documents/{id}")
                    auditor.identities[identity]["parameters"]["id"] = value
                    with patch.object(auditor._opener, "open") as opener:
                        self.scan(auditor)
                    opener.assert_not_called()
                    self.assertFalse(any(item["verdict"] == "CONFIRMED" for item in auditor.results))

    def test_query_data_is_encoded_and_does_not_change_path_or_issue_extra_requests(self):
        operation = {"security": [], "parameters": [{"name": "search", "in": "query", "required": True,
                                                     "schema": {"type": "string"}}], "responses": {}}
        value = "/delete_all_records?act=delete&other=1"
        with LocalReadServer() as api:
            auditor = self.auditor(api.target, operation=operation,
                                   parameter_values={"GET /documents": {"common": {"search": value}}})
            self.scan(auditor)
            self.assertEqual(3, len(api.requests))
            for method, url, _ in api.requests:
                self.assertEqual("GET", method)
                self.assertEqual("/documents", urlsplit(url).path)
                self.assertEqual({"search": [value]}, parse_qs(urlsplit(url).query))

    def test_private_value_equal_to_owner_metadata_key_does_not_crash_or_drop_field_checks(self):
        policy = field_policy()
        policy["fields"][0]["value_is_resource_specific"] = False
        with LocalReadServer("metadata-secret") as api:
            auditor = self.auditor(api.target, path="/documents/{id}", policy=policy)
            results = self.scan(auditor)
            self.assertEqual(4, len(api.requests))
            self.assertEqual(2, len(results))
            self.assertTrue(all(item["verdict"] == "INCONCLUSIVE" for item in results))
            self.assertTrue(any(item["check"] == "BOLA" for item in auditor.results))

    def test_redirect_cannot_reach_state_changing_get_or_forward_credentials(self):
        with LocalReadServer("redirect") as api:
            auditor = self.auditor(api.target)
            results = self.scan(auditor)
            self.assertEqual(3, len(api.requests))
            self.assertEqual({"/documents"}, {request[1] for request in api.requests})
            self.assertTrue(all(item["verdict"] == "INCONCLUSIVE" for item in results))
            self.assertEqual(3, auditor.stats["transport_attempts"])
            self.assertEqual(3, auditor.stats["http_requests_sent"])

    def test_http_error_denials_keep_real_counts_and_scoped_secure_results(self):
        with LocalReadServer("deny") as api:
            auditor = self.auditor(api.target)
            results = self.scan(auditor)
            self.assertEqual({"SECURE"}, {item["verdict"] for item in results})
            self.assertEqual(len(api.requests), auditor.stats["transport_attempts"])
            self.assertEqual(len(api.requests), auditor.stats["http_requests_sent"])

    def test_http_error_data_is_suspicious_without_followup_write_or_confirmation(self):
        with LocalReadServer("error-data") as api:
            auditor = self.auditor(api.target)
            results = self.scan(auditor)
            self.assertEqual({"SUSPICIOUS"}, {item["verdict"] for item in results})
            self.assertEqual(3, len(api.requests))
            self.assertEqual({"GET"}, {item[0] for item in api.requests})

    def test_timeout_or_early_close_never_confirms_from_partial_observation(self):
        for mode in ("drop", "timeout"):
            with self.subTest(mode=mode), LocalReadServer(mode) as api:
                auditor = self.auditor(api.target)
                results = self.scan(auditor)
                self.assertEqual({"INCONCLUSIVE"}, {item["verdict"] for item in results})
                self.assertEqual(3, len(api.requests))
                self.assertEqual(3, auditor.stats["transport_attempts"])
                self.assertEqual(0, auditor.stats["confirmed"])

    def test_connection_refusal_does_not_become_confirmed_or_fabricate_http_response(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            target = "http://127.0.0.1:" + str(reserved.getsockname()[1])
            auditor = self.auditor(target)
            results = self.scan(auditor)
        self.assertEqual({"INCONCLUSIVE"}, {item["verdict"] for item in results})
        self.assertEqual(3, auditor.stats["transport_attempts"])
        self.assertEqual(0, auditor.stats["http_requests_sent"])

    def test_report_distinguishes_received_responses_from_actual_sent_requests(self):
        with LocalReadServer("drop") as api:
            auditor = self.auditor(api.target)
            self.scan(auditor)
            self.assertEqual(3, len(api.requests), "Server independently received all three GET requests")
            self.assertEqual(1, auditor.stats["http_requests_sent"], "Current counter actually counts received response headers")
            output = self.folder / "drop-report.html"
            SecurityReportGenerator.generate(auditor.stats, auditor.findings, api.target,
                                             str(output), results=auditor.results)
            html = output.read_text(encoding="utf-8")
            self.assertTrue("收到响应" in html,
                            "Report must qualify a response-based lower bound; it is not actual sent request count")

    def test_disabled_property_configuration_retains_legacy_object_detection(self):
        auditor = self.auditor(path="/documents/{id}", enabled=False,
                               legacy={"expected_visitor_access": "deny"})
        owner = HTTPResult(200, json.dumps({"id": "resource-x", "title": "Owner document", "note": OWNER_SECRET}))
        own_visitor = HTTPResult(200, '{"id":"resource-y","title":"Visitor document","note":"Visitor note"}')
        denied = HTTPResult(403, '{"error":"Forbidden"}')
        with patch.object(auditor, "_http_request", side_effect=[owner, owner, denied, own_visitor]) as executor:
            self.scan(auditor)
        self.assertEqual(4, executor.call_count)
        self.assertEqual(["BOLA"], [item["check"] for item in auditor.results])
        self.assertEqual("CONFIRMED", auditor.results[0]["verdict"])
        self.assertEqual(1, auditor.stats["confirmed"])
        self.assertEqual(1, len(auditor.findings))
        self.assertNotIn("bopla_fields_confirmed", auditor.stats)


if __name__ == "__main__":
    unittest.main()
