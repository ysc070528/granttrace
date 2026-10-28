"""Wire regressions for identity, BOPLA preflight, and read-only parameter boundaries."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from core.auditor import APISentinelAuditor
from core.models import Verdict
from tests import test_header_cookie_parameters as wire_fixture
from tests import test_release_transactions as transaction_fixture

ParameterRecordingHandler = wire_fixture.ParameterRecordingHandler


class MutationRecordingHandler(ParameterRecordingHandler):
    state = {"role": "user"}
    mutations = []

    def _reply(self) -> None:
        body = json.dumps(self.state).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        with self.lock:
            self.requests.append((self.command, self.path, dict(self.headers.items())))
        self._reply()

    def do_PATCH(self) -> None:  # noqa: N802
        with self.lock:
            self.requests.append((self.command, self.path, dict(self.headers.items())))
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.mutations.append(payload)
            self.state.update(payload)
        self._reply()


class HeaderCookieBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ParameterRecordingHandler)
        cls.target_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    def test_write_business_header_is_rejected_before_transport(self) -> None:
        """GET parameter support cannot enable new mutation requests without their headers."""
        MutationRecordingHandler.state = {"role": "user"}
        MutationRecordingHandler.mutations = []
        with ParameterRecordingHandler.lock:
            ParameterRecordingHandler.requests.clear()
        server = ThreadingHTTPServer(("127.0.0.1", 0), MutationRecordingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            auditor, endpoint = transaction_fixture.StrictReadbackTests().make_auditor()
            auditor.target_base_url = f"http://127.0.0.1:{server.server_port}"
            endpoint["parameters"] = [
                {"name": "X-Tenant-Context", "in": "header", "required": True,
                 "schema": {"type": "string"}},
            ]
            key = "PATCH " + endpoint["path"]
            auditor.parameter_values = {key: {"visitor": {"X-Tenant-Context": "tenant-visitor"}}}
            auditor.readback_config[key]["parameters"] = []
            auditor._authoritative_patch_state = lambda *args: copy.deepcopy(MutationRecordingHandler.state)
            with contextlib.redirect_stdout(io.StringIO()):
                auditor.audit_endpoint_mass_assignment(endpoint, [endpoint])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        self.assertEqual(ParameterRecordingHandler.requests, [])
        self.assertEqual(MutationRecordingHandler.mutations, [])
        self.assertEqual(MutationRecordingHandler.state, {"role": "user"})
        self.assertEqual(auditor.stats["transport_attempts"], 0)
        self.assertEqual(len(auditor.results), 1)
        result = auditor.results[0]
        self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE)
        self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
        self.assertEqual(result["evidence"]["requests_attempted"], 0)

    def test_owner_auth_cookie_rejects_shared_and_default_values(self) -> None:
        """A Visitor override cannot make a shared Owner credential identity-scoped."""
        for source in ("common", "flat", "default"):
            with self.subTest(source=source):
                with ParameterRecordingHandler.lock:
                    ParameterRecordingHandler.requests.clear()
                metadata = {"name": "session_token", "in": "cookie", "schema": {"type": "string"}}
                scoped_values = {"visitor": {"session_token": "VISITOR_COOKIE"}}
                if source == "common":
                    scoped_values["common"] = {"session_token": "SHARED_OWNER_COOKIE"}
                elif source == "flat":
                    scoped_values["session_token"] = "SHARED_OWNER_COOKIE"
                else:
                    metadata["schema"]["default"] = "SHARED_OWNER_COOKIE"
                spec = wire_fixture.HeaderCookieParameterTests._make_spec(self, [metadata])
                config = wire_fixture.HeaderCookieParameterTests._make_config(
                    self, parameter_values={"GET /api/documents/{doc_id}": scoped_values})
                auditor = wire_fixture.HeaderCookieParameterTests._run_audit(self, spec, config)
                self.assertEqual(ParameterRecordingHandler.requests, [])
                self.assertEqual(auditor.stats["transport_attempts"], 0)
                self.assertEqual(len(auditor.results), 1)
                result = auditor.results[0]
                self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE)
                self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
                self.assertEqual(result["evidence"]["requests_attempted"], 0)

    def test_invalid_anonymous_business_parameters_send_no_requests(self) -> None:
        """Missing required values and invalid optional values stop BOLA and BOPLA."""
        cases = [
            ("header", "X-Tenant-Context", True, None),
            ("cookie", "tracking_id", True, None),
            ("header", "X-Tenant-Context", False, "invalid\r\nInjected: value"),
            ("cookie", "tracking_id", False, "invalid; injected=value"),
        ]
        for location, name, required, anonymous_value in cases:
            with self.subTest(location=location, required=required):
                with ParameterRecordingHandler.lock:
                    ParameterRecordingHandler.requests.clear()
                metadata = {"name": name, "in": location, "required": required,
                            "schema": {"type": "string"}}
                spec = wire_fixture.HeaderCookieParameterTests._make_spec(self, [metadata])
                scoped_values = {"owner": {name: "owner-business-value"},
                                 "visitor": {name: "visitor-business-value"}}
                if anonymous_value is not None:
                    scoped_values["anonymous"] = {name: anonymous_value}
                config = wire_fixture.HeaderCookieParameterTests._make_config(
                    self, parameter_values={"GET /api/documents/{doc_id}": scoped_values})
                policy = {
                    "policy_id": "document-properties", "context_id": "selected-owner-document",
                    "resource_binding": {"id": "doc-owner"},
                    "fields": [{"rule_id": "private-title", "path": "title",
                                "baseline_representation": "full_private_value",
                                "value_is_resource_specific": True,
                                "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}],
                }
                with tempfile.TemporaryDirectory() as directory:
                    spec_path = Path(directory) / "spec.json"
                    spec_path.write_text(json.dumps(spec), encoding="utf-8")
                    auditor = APISentinelAuditor(
                        str(spec_path), self.target_url,
                        identities_config=config["identities"],
                        parameter_values=config["parameter_values"],
                        bola_config=config["bola"],
                        bopla_config={"GET /api/documents/{doc_id}": policy},
                        allow_http=True, request_delay=0,
                    )
                    with contextlib.redirect_stdout(io.StringIO()):
                        auditor.run()
                self.assertEqual(ParameterRecordingHandler.requests, [])
                self.assertEqual(auditor.stats["transport_attempts"], 0)
                self.assertTrue(auditor.results)
                for result in auditor.results:
                    self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE)
                    self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
                    self.assertEqual(result["evidence"]["requests_attempted"], 0)


if __name__ == "__main__":
    unittest.main()
