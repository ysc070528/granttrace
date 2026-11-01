"""Wire regressions for authentication cookies declared through local references."""

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
from core.models import Verdict


class ProtectedCookieHandler(BaseHTTPRequestHandler):
    """Authenticate only the neutral cookie name, ignoring dummy Bearer headers."""

    requests = []
    lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        headers = {name.lower(): value for name, value in self.headers.items()}
        with self.lock:
            self.requests.append((self.path, headers))
        cookies = dict(
            part.strip().split("=", 1)
            for part in headers.get("cookie", "").split(";") if "=" in part
        )
        requested_id = self.path.rsplit("/", 1)[-1]
        role_id = {"OWNER_COOKIE": "doc-owner", "VISITOR_COOKIE": "doc-visitor"}.get(cookies.get("k"))
        if role_id is None:
            status, payload = 401, {"error": "Unauthorized"}
        elif role_id != requested_id:
            status, payload = 403, {"error": "Forbidden"}
        else:
            status, payload = 200, {"id": requested_id, "private_note": "private-for-" + requested_id}
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass


class AuthenticationCookieReferenceTests(unittest.TestCase):
    PATH = "/api/documents/{doc_id}"
    OPERATION = "GET " + PATH
    FORMS = ("direct", "internal", "external", "multi-hop")
    COOKIE_SCHEME = {"type": "apiKey", "in": "cookie", "name": "k"}

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ProtectedCookieHandler)
        cls.target_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    def setUp(self) -> None:
        self._clear_requests()

    def _clear_requests(self) -> None:
        with ProtectedCookieHandler.lock:
            ProtectedCookieHandler.requests.clear()

    def _spec(self, form: str, *, required: bool = True):
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Referenced cookie authentication", "version": "1.0"},
            "paths": {self.PATH: {"get": {
                "parameters": [
                    {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "k", "in": "cookie", "required": required, "schema": {"type": "string"}},
                    {"name": "theme", "in": "cookie", "schema": {"type": "string"}},
                ],
                "security": [{"CookieAuth": []}],
                "responses": {"200": {"description": "Private document"}},
            }}},
            "components": {"securitySchemes": {}},
        }
        files = {}
        if form == "direct":
            scheme = copy.deepcopy(self.COOKIE_SCHEME)
        elif form == "internal":
            scheme = {"$ref": "#/x-auth-definitions/Alias"}
            spec["x-auth-definitions"] = {
                "Alias": {"$ref": "#/x-auth-definitions/Cookie"},
                "Cookie": copy.deepcopy(self.COOKIE_SCHEME),
            }
        elif form == "external":
            scheme = {"$ref": "auth/scheme.json#/Cookie"}
            files["auth/scheme.json"] = {"Cookie": copy.deepcopy(self.COOKIE_SCHEME)}
        elif form == "multi-hop":
            scheme = {"$ref": "auth/alias.json#/Alias"}
            files["auth/alias.json"] = {
                "Alias": {"$ref": "#/First"},
                "First": {"$ref": "nested/cookie.json#/Cookie"},
            }
            files["auth/nested/cookie.json"] = {"Cookie": copy.deepcopy(self.COOKIE_SCHEME)}
        else:
            raise AssertionError(form)
        spec["components"]["securitySchemes"]["CookieAuth"] = scheme
        return spec, files

    def _identities(self):
        # Existing identity validation still requires distinct baseline identities.
        return {
            "owner": {"id": "1001", "token": "Bearer OWNER_DUMMY", "parameters": {"doc_id": "doc-owner"}},
            "visitor": {"id": "1002", "token": "Bearer VISITOR_DUMMY", "parameters": {"doc_id": "doc-visitor"}},
            "anonymous": {"id": None, "token": None, "parameters": {}},
        }

    def _run(self, spec, files, values, *, identities=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, document in files.items():
                source = root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(json.dumps(document), encoding="utf-8")
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
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
        self.assertEqual(ProtectedCookieHandler.requests, [])
        self.assertEqual(auditor.stats["transport_attempts"], 0)
        self.assertTrue(auditor.results)
        for result in auditor.results:
            self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE)
            self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
            self.assertEqual(result["evidence"]["requests_attempted"], 0)

    def test_shared_authentication_cookie_sources_send_no_requests(self) -> None:
        """References must not turn common, flat or default credentials into business cookies."""
        for form in self.FORMS:
            for source in ("common", "flat", "default"):
                with self.subTest(form=form, source=source):
                    self._clear_requests()
                    spec, files = self._spec(form, required=False)
                    values = {"visitor": {"k": "VISITOR_COOKIE"}}
                    if source == "common":
                        values["common"] = {"k": "OWNER_COOKIE"}
                    elif source == "flat":
                        values["k"] = "OWNER_COOKIE"
                    else:
                        spec["paths"][self.PATH]["get"]["parameters"][1]["schema"]["default"] = "OWNER_COOKIE"
                    auditor = self._run(spec, files, values)
                    self.assertFalse(any(result["verdict"] == Verdict.CONFIRMED for result in auditor.results),
                                     "A correctly protected cookie-only endpoint must not produce a credential-induced finding")
                    self._assert_invalid_input(auditor)

    def test_scoped_cookie_authentication_preserves_wire_isolation(self) -> None:
        """Required cookie auth remains isolated and cannot falsely confirm broken auth."""
        for form in self.FORMS:
            with self.subTest(form=form):
                self._clear_requests()
                spec, files = self._spec(form)
                auditor = self._run(spec, files, {
                    "owner": {"k": "OWNER_COOKIE"},
                    "visitor": {"k": "VISITOR_COOKIE"},
                    "common": {"theme": "dark"},
                })
                self.assertEqual(len(ProtectedCookieHandler.requests), 4)
                observed = []
                for path, headers in ProtectedCookieHandler.requests:
                    cookies = dict(part.strip().split("=", 1) for part in headers.get("cookie", "").split(";") if "=" in part)
                    self.assertEqual(cookies.get("theme"), "dark")
                    observed.append((path, cookies.get("k"), headers.get("authorization")))
                self.assertCountEqual(observed, [
                    ("/api/documents/doc-owner", "OWNER_COOKIE", "Bearer OWNER_DUMMY"),
                    ("/api/documents/doc-owner", "VISITOR_COOKIE", "Bearer VISITOR_DUMMY"),
                    ("/api/documents/doc-visitor", "VISITOR_COOKIE", "Bearer VISITOR_DUMMY"),
                    ("/api/documents/doc-owner", None, None),
                ])
                self.assertTrue(auditor.results)
                for result in auditor.results:
                    self.assertEqual(result["verdict"], Verdict.SECURE, result["reason"])
                    self.assertNotEqual(result["verdict"], Verdict.CONFIRMED)

    def test_identity_parameter_cookie_authentication_is_isolated(self) -> None:
        """Identity parameter credentials follow the same reference-aware rules."""
        spec, files = self._spec("multi-hop")
        identities = self._identities()
        identities["owner"]["parameters"]["k"] = "OWNER_COOKIE"
        identities["visitor"]["parameters"]["k"] = "VISITOR_COOKIE"
        auditor = self._run(spec, files, {"common": {"theme": "light"}}, identities=identities)
        self.assertEqual(len(ProtectedCookieHandler.requests), 4)
        for _, headers in ProtectedCookieHandler.requests:
            auth = headers.get("authorization")
            cookie = headers.get("cookie", "")
            self.assertIn("theme=light", cookie)
            if auth == "Bearer OWNER_DUMMY":
                self.assertIn("k=OWNER_COOKIE", cookie)
                self.assertNotIn("VISITOR_COOKIE", cookie)
            elif auth == "Bearer VISITOR_DUMMY":
                self.assertIn("k=VISITOR_COOKIE", cookie)
                self.assertNotIn("OWNER_COOKIE", cookie)
            else:
                self.assertNotIn("k=", cookie)
        self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results))

    def test_identical_referenced_authentication_cookies_send_no_requests(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._clear_requests()
                spec, files = self._spec(form, required=False)
                auditor = self._run(spec, files, {
                    "owner": {"k": "OWNER_COOKIE"},
                    "visitor": {"k": "OWNER_COOKIE"},
                })
                self._assert_invalid_input(auditor)

    def test_malformed_or_unresolved_scheme_targets_send_no_requests(self) -> None:
        targets = (
            {},
            {"in": "cookie", "name": "k"},
            {"type": "apiKey", "in": "cookie"},
            {"type": "apiKey", "name": "k"},
            {"type": [], "in": "cookie", "name": "k"},
            {"type": "apiKey", "in": [], "name": "k"},
            {"type": "apiKey", "in": "cookie", "name": []},
        )
        for target in targets:
            with self.subTest(target=target):
                self._clear_requests()
                spec, files = self._spec("direct", required=False)
                spec["components"]["securitySchemes"]["CookieAuth"] = {"$ref": "#/x-target"}
                spec["x-target"] = target
                with self.assertRaisesRegex(ValueError, r"(?i)security|scheme|reference|\$ref"):
                    self._run(spec, files, {"common": {"k": "OWNER_COOKIE"}})
                self.assertEqual(ProtectedCookieHandler.requests, [])

        self._clear_requests()
        spec, files = self._spec("direct", required=False)
        spec["components"]["securitySchemes"]["CookieAuth"] = {"$ref": "#/x-chain/0"}
        spec["x-chain"] = {str(index): {"$ref": "#/x-chain/" + str(index + 1)} for index in range(22)}
        spec["x-chain"]["22"] = copy.deepcopy(self.COOKIE_SCHEME)
        with self.assertRaisesRegex(ValueError, r"(?i)security|scheme|reference|\$ref"):
            self._run(spec, files, {"common": {"k": "OWNER_COOKIE"}})
        self.assertEqual(ProtectedCookieHandler.requests, [])

    def test_reference_siblings_cannot_override_authentication_contract(self) -> None:
        for nested in (False, True):
            with self.subTest(nested=nested):
                self._clear_requests()
                spec, files = self._spec("direct", required=False)
                spec["x-valid"] = copy.deepcopy(self.COOKIE_SCHEME)
                extended = {"$ref": "#/x-valid", "in": "query"}
                if nested:
                    spec["x-nested"] = extended
                    scheme = {"$ref": "#/x-nested"}
                else:
                    scheme = extended
                spec["components"]["securitySchemes"]["CookieAuth"] = scheme
                with self.assertRaisesRegex(ValueError, r"(?i)security|scheme|reference|\$ref"):
                    self._run(spec, files, {"common": {"k": "OWNER_COOKIE"}})
                self.assertEqual(ProtectedCookieHandler.requests, [])

    def test_invalid_security_scheme_references_fail_before_transport(self) -> None:
        invalid_cases = [
            {"$ref": "#/components/securitySchemes/Missing"},
            {"$ref": "missing.json#/Cookie"},
            {"$ref": self.target_url + "/security.json#/Cookie"},
            {"$ref": "/tmp/cookie-auth.json#/Cookie"},
            {"$ref": "auth/scheme.json?ignored=true#/Cookie"},
            {"$ref": "../outside.json#/Cookie"},
            {"$ref": ""},
            {"$ref": 17},
            {"$ref": "#/x-invalid"},
            {"$ref": "#/components/securitySchemes/CookieAuth"},
            {"$ref": "#/x-cycle/First"},
        ]
        for scheme in invalid_cases:
            with self.subTest(scheme=scheme):
                self._clear_requests()
                spec, files = self._spec("direct", required=False)
                spec["components"]["securitySchemes"]["CookieAuth"] = scheme
                spec["x-invalid"] = ["not", "a", "scheme"]
                spec["x-cycle"] = {"First": {"$ref": "#/x-cycle/Second"},
                                   "Second": {"$ref": "#/x-cycle/First"}}
                with self.assertRaises(ValueError) as raised:
                    self._run(spec, files, {"common": {"k": "OWNER_COOKIE"}})
                self.assertRegex(str(raised.exception).lower(), r"security|scheme|reference|\$ref")
                self.assertEqual(ProtectedCookieHandler.requests, [])


if __name__ == "__main__":
    unittest.main()