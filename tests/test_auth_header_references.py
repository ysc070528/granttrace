"""Wire regressions for Header authentication resolved through local references."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import Verdict
from core.reporter import SecurityReportGenerator
from core.sarif import SarifReportGenerator


class ProtectedHeaderHandler(BaseHTTPRequestHandler):
    """Use only X-Access-Key for authorization, regardless of Bearer headers."""

    requests = []
    echo_header = False
    lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        headers = {name.lower(): value for name, value in self.headers.items()}
        with self.lock:
            self.requests.append((self.path, headers))
        requested_id = self.path.rsplit("/", 1)[-1]
        role_id = {"OWNER_HEADER": "doc-owner", "VISITOR_HEADER": "doc-visitor"}.get(headers.get("x-access-key"))
        if role_id is None:
            status, payload = 401, {"error": "Unauthorized"}
        elif role_id != requested_id:
            status, payload = 403, {"error": "Forbidden"}
        else:
            status, payload = 200, {"id": requested_id, "private_note": "private-for-" + requested_id}
        if status == 200 and self.echo_header:
            payload["opaque_value"] = headers.get("x-access-key", "")
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass


class AuthenticationHeaderReferenceTests(unittest.TestCase):
    PATH = "/api/documents/{doc_id}"
    OPERATION = "GET " + PATH
    FORMS = ("direct", "internal", "external-yaml", "multi-hop")
    HEADER_SCHEME = {"type": "apiKey", "in": "header", "name": "X-Access-Key"}

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ProtectedHeaderHandler)
        cls.target_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    def setUp(self) -> None:
        ProtectedHeaderHandler.echo_header = False
        self._clear_requests()

    def _clear_requests(self) -> None:
        with ProtectedHeaderHandler.lock:
            ProtectedHeaderHandler.requests.clear()

    def _spec(self, form: str, *, parameter_name: str = "X-Access-Key", required: bool = True):
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Referenced Header authentication", "version": "1.0"},
            "paths": {self.PATH: {"get": {
                "parameters": [
                    {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": parameter_name, "in": "header", "required": required, "schema": {"type": "string"}},
                    {"name": "X-Request-Tracking", "in": "header", "schema": {"type": "string"}},
                ],
                "security": [{"HeaderAuth": []}],
                "responses": {"200": {"description": "Private document"}},
            }}},
            "components": {"securitySchemes": {}},
        }
        files = {}
        if form == "direct":
            scheme = copy.deepcopy(self.HEADER_SCHEME)
        elif form == "internal":
            scheme = {"$ref": "#/x-auth-definitions/Alias"}
            spec["x-auth-definitions"] = {
                "Alias": {"$ref": "#/x-auth-definitions/Header"},
                "Header": copy.deepcopy(self.HEADER_SCHEME),
            }
        elif form == "external-yaml":
            scheme = {"$ref": "auth/scheme.yaml#/Header"}
            files["auth/scheme.yaml"] = "Header:\n  type: apiKey\n  in: header\n  name: X-Access-Key\n"
        elif form == "multi-hop":
            scheme = {"$ref": "auth/alias.yaml#/Alias"}
            files["auth/alias.yaml"] = "Alias:\n  $ref: '#/First'\nFirst:\n  $ref: 'nested/header.json#/Header'\n"
            files["auth/nested/header.json"] = {"Header": copy.deepcopy(self.HEADER_SCHEME)}
        else:
            raise AssertionError(form)
        spec["components"]["securitySchemes"]["HeaderAuth"] = scheme
        return spec, files

    def _identities(self, *, include_header: bool = True, dummy_tokens: bool = False):
        identities = {
            "owner": {"id": "1001", "parameters": {"doc_id": "doc-owner"}},
            "visitor": {"id": "1002", "parameters": {"doc_id": "doc-visitor"}},
            "anonymous": {"id": None, "parameters": {}},
        }
        if include_header:
            identities["owner"]["headers"] = {"X-ACCESS-KEY": "OWNER_HEADER"}
            identities["visitor"]["headers"] = {"x-access-key": "VISITOR_HEADER"}
        if dummy_tokens:
            identities["owner"]["token"] = "Bearer OWNER_DUMMY"
            identities["visitor"]["token"] = "Bearer VISITOR_DUMMY"
        return identities

    def _run(self, spec, files, values, *, identities=None, validate_config=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, document in files.items():
                source = root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            if validate_config:
                config = {"identities": identities or self._identities(),
                          "parameter_values": {self.OPERATION: values}}
                validated = ConfigValidator.validate(config, raw_spec=spec, spec_path=str(spec_path))
                self.assertTrue(validated.is_valid, validated.issues)
            auditor = APISentinelAuditor(
                str(spec_path), self.target_url,
                identities_config=identities or self._identities(),
                parameter_values={self.OPERATION: values},
                bola_config={self.OPERATION: {
                    "expected_visitor_access": "deny", "resource_id_paths": ["id"],
                    "private_data_paths": ["private_note"],
                }},
                allow_http=True, request_delay=0,
            )
            with contextlib.redirect_stdout(io.StringIO()):
                auditor.run()
            return auditor

    def _assert_invalid_input(self, auditor) -> None:
        self.assertEqual(ProtectedHeaderHandler.requests, [])
        self.assertEqual(auditor.stats["transport_attempts"], 0)
        self.assertTrue(auditor.results)
        for result in auditor.results:
            self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE)
            self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
            self.assertEqual(result["evidence"]["requests_attempted"], 0)

    def test_neutral_header_fixture_does_not_use_authentication_heuristic(self) -> None:
        self.assertFalse(ConfigValidator.is_auth_header("X-Access-Key"))
        self.assertFalse(ConfigValidator.is_auth_header("x-access-key"))

    def test_referenced_header_only_identities_preserve_wire_isolation(self) -> None:
        """Referenced apiKey identity headers work without unrelated Bearer credentials."""
        for form in self.FORMS:
            for name in ("X-Access-Key", "x-access-key"):
                with self.subTest(form=form, parameter_name=name):
                    self._clear_requests()
                    spec, files = self._spec(form, parameter_name=name)
                    auditor = self._run(spec, files, {"common": {"X-Request-Tracking": "tracking-123"}})
                    self.assertEqual(len(ProtectedHeaderHandler.requests), 4)
                    observed = []
                    for path, headers in ProtectedHeaderHandler.requests:
                        self.assertNotIn("authorization", headers)
                        self.assertEqual(headers.get("x-request-tracking"), "tracking-123")
                        observed.append((path, headers.get("x-access-key")))
                    self.assertCountEqual(observed, [
                        ("/api/documents/doc-owner", "OWNER_HEADER"),
                        ("/api/documents/doc-owner", "VISITOR_HEADER"),
                        ("/api/documents/doc-visitor", "VISITOR_HEADER"),
                        ("/api/documents/doc-owner", None),
                    ])
                    self.assertTrue(auditor.results)
                    self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results),
                                    auditor.results)

    def test_business_parameter_values_cannot_override_identity_authentication(self) -> None:
        """Shared values cannot replace the requester's real authentication Header."""
        for form in self.FORMS:
            for source in ("common", "flat"):
                with self.subTest(form=form, source=source):
                    self._clear_requests()
                    spec, files = self._spec(form, parameter_name="x-access-key")
                    values = {"common": {"X-Request-Tracking": "tracking-123"}}
                    if source == "common":
                        values["common"]["x-access-key"] = "POISON_PARAMETER"
                    else:
                        values["x-access-key"] = "POISON_PARAMETER"
                    auditor = self._run(spec, files, values, identities=self._identities(dummy_tokens=True))
                    self.assertEqual(len(ProtectedHeaderHandler.requests), 4)
                    observed = [headers.get("x-access-key") for _, headers in ProtectedHeaderHandler.requests]
                    self.assertCountEqual(observed, ["OWNER_HEADER", "VISITOR_HEADER", "VISITOR_HEADER", None])
                    self.assertNotIn("POISON_PARAMETER", json.dumps(ProtectedHeaderHandler.requests))
                    self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results),
                                    auditor.results)

    def test_shared_authentication_headers_without_identity_credentials_send_no_requests(self) -> None:
        """Unresolved aliases must not turn common or flat apiKey values into anonymous credentials."""
        for form in self.FORMS:
            for name in ("X-Access-Key", "x-access-key"):
                for source in ("common", "flat"):
                    with self.subTest(form=form, parameter_name=name, source=source):
                        self._clear_requests()
                        spec, files = self._spec(form, parameter_name=name, required=False)
                        values = {"common": {name: "OWNER_HEADER"}} if source == "common" else {name: "OWNER_HEADER"}
                        auditor = self._run(spec, files, values,
                                            identities=self._identities(include_header=False, dummy_tokens=True))
                        self.assertFalse(any(result["verdict"] == Verdict.CONFIRMED for result in auditor.results),
                                         "A protected Header-only server must not produce a shared-credential finding")
                        self._assert_invalid_input(auditor)

    def test_anonymous_identity_cannot_define_referenced_authentication_header(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._clear_requests()
                spec, files = self._spec(form)
                # No Parameter Object can provide an earlier collision rejection.
                spec["paths"][self.PATH]["get"]["parameters"].pop(1)
                identities = self._identities(dummy_tokens=True)
                identities["anonymous"]["headers"] = {"x-AcCeSs-KeY": "OWNER_HEADER"}
                with self.assertRaisesRegex(ValueError, "anonymous"):
                    self._run(spec, files, {}, identities=identities)
                self.assertEqual(ProtectedHeaderHandler.requests, [])

    def test_header_only_config_validation_then_audit_preserves_wire_identity(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._clear_requests()
                spec, files = self._spec(form)
                auditor = self._run(spec, files, {}, validate_config=True)
                self.assertEqual(len(ProtectedHeaderHandler.requests), 4)
                self.assertCountEqual(
                    [headers.get("x-access-key") for _, headers in ProtectedHeaderHandler.requests],
                    ["OWNER_HEADER", "VISITOR_HEADER", "VISITOR_HEADER", None],
                )
                self.assertTrue(auditor.results)
                self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results))

    def test_raw_spec_validation_resolves_internal_header_authentication(self) -> None:
        for form in ("direct", "internal"):
            with self.subTest(form=form):
                spec, _ = self._spec(form)
                validated = ConfigValidator.validate({"identities": self._identities()}, raw_spec=spec)
                self.assertTrue(validated.is_valid, validated.issues)
                self.assertEqual(ProtectedHeaderHandler.requests, [])

    def test_invalid_direct_header_schemes_fail_before_transport(self) -> None:
        schemes = (
            {},
            {"in": "header", "name": "X-Access-Key"},
            {"type": "apiKey", "in": "header"},
            {"type": "apiKey", "name": "X-Access-Key"},
            {"type": [], "in": "header", "name": "X-Access-Key"},
            {"type": "apiKey", "in": [], "name": "X-Access-Key"},
            {"type": "apiKey", "in": "header", "name": []},
        )
        for scheme in schemes:
            with self.subTest(scheme=scheme):
                self._clear_requests()
                spec, files = self._spec("direct", required=False)
                spec["components"]["securitySchemes"]["HeaderAuth"] = scheme
                with self.assertRaisesRegex(ValueError, r"(?i)authentication|security|scheme|reference|\$ref"):
                    self._run(spec, files, {"common": {"X-Access-Key": "OWNER_HEADER"}},
                              identities=self._identities(include_header=False, dummy_tokens=True))
                self.assertEqual(ProtectedHeaderHandler.requests, [])

    def test_referenced_header_echo_is_redacted_in_json_html_and_sarif(self) -> None:
        """A real response echoes the neutral Header value under an opaque field."""
        spec, files = self._spec("multi-hop")
        ProtectedHeaderHandler.echo_header = True
        try:
            auditor = self._run(spec, files, {}, validate_config=True)
        finally:
            ProtectedHeaderHandler.echo_header = False
        self.assertEqual(len(ProtectedHeaderHandler.requests), 4)
        self.assertCountEqual(
            [headers.get("x-access-key") for _, headers in ProtectedHeaderHandler.requests],
            ["OWNER_HEADER", "VISITOR_HEADER", "VISITOR_HEADER", None],
        )
        self.assertTrue(auditor.results)
        self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results), auditor.results)
        self.assertIn("OWNER_HEADER", auditor._secret_values)
        self.assertIn("VISITOR_HEADER", auditor._secret_values)
        json_text = json.dumps({"stats": auditor.stats, "results": auditor.results})
        # This field only exists in actual successful HTTP responses, not test-injected evidence.
        self.assertIn("opaque_value", json_text)
        self.assertIn("[REDACTED]", json_text)
        with tempfile.TemporaryDirectory() as directory:
            html_path = Path(directory) / "report.html"
            sarif_path = Path(directory) / "report.sarif"
            findings = [result["finding"] for result in auditor.results if result.get("finding")]
            SecurityReportGenerator.generate(auditor.stats, findings, self.target_url,
                                             str(html_path), results=auditor.results)
            SarifReportGenerator.generate(auditor.results, self.target_url, str(sarif_path))
            reports = (json_text, html_path.read_text(encoding="utf-8"), sarif_path.read_text(encoding="utf-8"))
        for report in reports:
            self.assertNotIn("OWNER_HEADER", report)
            self.assertNotIn("VISITOR_HEADER", report)

    def test_invalid_yaml_reference_has_safe_diagnostic_and_zero_http(self) -> None:
        spec, files = self._spec("external-yaml")
        marker = "PRIVATE_SPEC_MARKER_934671"
        files["auth/scheme.yaml"] = "Header:\n  name: [" + marker + "\n"
        with self.assertRaisesRegex(ValueError, r"(?i)authentication|security|scheme|reference|\$ref") as raised:
            self._run(spec, files, {}, identities=self._identities(dummy_tokens=True))
        self.assertNotIn(marker, str(raised.exception))
        self.assertEqual(ProtectedHeaderHandler.requests, [])

    def test_invalid_api_key_header_names_fail_before_transport(self) -> None:
        for name in ("X Access Key", "X-Access-Key\r\nInjected: bad"):
            for referenced in (False, True):
                with self.subTest(name=name, referenced=referenced):
                    self._clear_requests()
                    spec, files = self._spec("direct", required=False)
                    malformed = {"type": "apiKey", "in": "header", "name": name}
                    spec["components"]["securitySchemes"]["HeaderAuth"] = (
                        {"$ref": "#/x-target"} if referenced else malformed
                    )
                    spec["x-target"] = malformed
                    with self.assertRaisesRegex(ValueError, r"(?i)authentication|security|scheme|reference|\$ref"):
                        self._run(spec, files, {}, identities=self._identities(dummy_tokens=True))
                    self.assertEqual(ProtectedHeaderHandler.requests, [])

    def test_invalid_header_scheme_references_fail_before_transport(self) -> None:
        schemes = (
            {"$ref": "#/components/securitySchemes/Missing"},
            {"$ref": "missing.yaml#/Header"},
            {"$ref": self.target_url + "/remote-scheme.yaml#/Header"},
            {"$ref": "../outside.yaml#/Header"},
            {"$ref": "#/components/securitySchemes/HeaderAuth"},
            {"$ref": "#/x-target"},
            {"$ref": "#/x-valid", "in": "query"},
            {"$ref": "#/x-nested"},
        )
        for scheme in schemes:
            with self.subTest(scheme=scheme):
                self._clear_requests()
                spec, files = self._spec("direct", required=False)
                spec["components"]["securitySchemes"]["HeaderAuth"] = scheme
                spec["x-target"] = {"type": "apiKey", "in": [], "name": "X-Access-Key"}
                spec["x-valid"] = copy.deepcopy(self.HEADER_SCHEME)
                spec["x-nested"] = {"$ref": "#/x-valid", "name": "Replaced-Name"}
                with self.assertRaisesRegex(ValueError, r"(?i)authentication|security|scheme|reference|\$ref"):
                    self._run(spec, files, {"common": {"X-Access-Key": "OWNER_HEADER"}})
                self.assertEqual(ProtectedHeaderHandler.requests, [])


if __name__ == "__main__":
    unittest.main()