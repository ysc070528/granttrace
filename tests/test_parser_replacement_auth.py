"""Real HTTP regressions for authentication after a stopped parser replacement."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from core.auditor import APISentinelAuditor
from core.models import Verdict
from core.parser import OpenAPIParser
from core.reporter import SecurityReportGenerator
from core.sarif import SarifReportGenerator


class ReplacementAuthHandler(BaseHTTPRequestHandler):
    requests = []
    lock = threading.Lock()
    location = "header"
    credential_name = "x-previous-key"
    echo = False
    public_anonymous = False

    def do_GET(self) -> None:  # noqa: N802
        headers = {name.lower(): value for name, value in self.headers.items()}
        cookies = dict(part.strip().split("=", 1) for part in headers.get("cookie", "").split(";") if "=" in part)
        with self.lock:
            self.requests.append((self.path, headers, cookies))
        credential = (cookies if self.location == "cookie" else headers).get(self.credential_name)
        resource = self.path.rsplit("/", 1)[-1]
        role = {
            "OLD_OWNER": "doc-owner", "OLD_VISITOR": "doc-visitor",
            "NEW_OWNER": "doc-owner", "NEW_VISITOR": "doc-visitor",
            "COOKIE_OWNER": "doc-owner", "COOKIE_VISITOR": "doc-visitor",
        }.get(credential)
        if role is None and self.public_anonymous and resource == "doc-owner":
            role = resource
        if role is None:
            status, payload = 401, {"error": "Unauthorized"}
        elif role != resource:
            status, payload = 403, {"error": "Forbidden"}
        else:
            status, payload = 200, {"id": resource, "private_note": "private-for-" + resource}
            if self.echo:
                payload["opaque_current"] = credential
                payload["opaque_previous"] = headers.get("x-previous-key", "")
                payload["opaque_future"] = headers.get("x-access-key", "")
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self.do_GET()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass


class ParserReplacementAuthenticationTests(unittest.TestCase):
    PATH = "/api/documents/{doc_id}"
    OPERATION = "GET " + PATH
    FORMS = ("direct", "internal", "external", "multi-hop")

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ReplacementAuthHandler)
        cls.target_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self._reset_server()

    def _reset_server(self) -> None:
        with ReplacementAuthHandler.lock:
            ReplacementAuthHandler.requests.clear()
        ReplacementAuthHandler.location = "header"
        ReplacementAuthHandler.credential_name = "x-previous-key"
        ReplacementAuthHandler.echo = False
        ReplacementAuthHandler.public_anonymous = False

    def _spec(self, label, form="direct", *, name="X-Access-Key", location="header", retain_previous=False):
        scheme = {"type": "apiKey", "in": location, "name": name}
        spec = {
            "openapi": "3.0.3", "info": {"title": "Parser replacement", "version": "1"},
            "paths": {self.PATH: {"get": {
                "parameters": [
                    {"in": "path", "name": "doc_id", "required": True, "schema": {"type": "string"}},
                    {"in": location, "name": name, "required": True, "schema": {"type": "string"}},
                    {"in": "header", "name": "X-Tracking", "schema": {"type": "string"}},
                    {"in": "cookie", "name": "theme", "schema": {"type": "string"}},
                ],
                "security": [{"Auth": []}], "responses": {"200": {"description": "Document"}},
            }}},
            "components": {"securitySchemes": {}},
        }
        root = self.root / label
        root.mkdir(parents=True, exist_ok=True)
        if form == "direct":
            definition = scheme
        elif form == "internal":
            spec["x-auth"] = {"Final": scheme}
            definition = {"$ref": "#/x-auth/Final"}
        elif form == "external":
            (root / "security.yaml").write_text(
                "Final:\n  type: apiKey\n  in: " + location + "\n  name: " + name + "\n", encoding="utf-8")
            definition = {"$ref": "security.yaml#/Final"}
        elif form == "multi-hop":
            (root / "security.yaml").write_text(
                "First:\n  $ref: '#/Second'\nSecond:\n  $ref: './final.json#/Final'\n", encoding="utf-8")
            (root / "final.json").write_text(json.dumps({"Final": scheme}), encoding="utf-8")
            definition = {"$ref": "security.yaml#/First"}
        else:
            raise AssertionError(form)
        spec["components"]["securitySchemes"]["Auth"] = definition
        if retain_previous:
            spec["components"]["securitySchemes"]["Previous"] = {
                "type": "apiKey", "in": "header", "name": "X-Previous-Key",
            }
        path = root / "spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path, spec

    def _identities(self, *, new_header=True):
        identities = {
            "owner": {"id": "1001", "headers": {"X-Previous-Key": "OLD_OWNER"},
                      "parameters": {"doc_id": "doc-owner"}},
            "visitor": {"id": "1002", "headers": {"x-previous-key": "OLD_VISITOR"},
                        "parameters": {"doc_id": "doc-visitor"}},
            "anonymous": {"id": None, "parameters": {}},
        }
        if new_header:
            identities["owner"]["headers"]["X-ACCESS-KEY"] = "NEW_OWNER"
            identities["visitor"]["headers"]["x-access-key"] = "NEW_VISITOR"
        return identities

    def _auditor(self, path, identities, values=None):
        return APISentinelAuditor(
            str(path), self.target_url, identities_config=identities,
            parameter_values={self.OPERATION: values or {"common": {"X-Tracking": "trace", "theme": "dark"}}},
            bola_config={self.OPERATION: {"expected_visitor_access": "deny",
                "resource_id_paths": ["id"], "private_data_paths": ["private_note"]}},
            allow_http=True, request_delay=0,
        )

    def _run(self, auditor) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            auditor.run()

    def _reject_replacement(self, auditor, path, *, diagnostic, entry="run"):
        attempts = auditor.stats["transport_attempts"]
        count = len(ReplacementAuthHandler.requests)
        results = len(auditor.results)
        rejected = None
        try:
            auditor.parser = OpenAPIParser(str(path))
            if entry == "run":
                self._run(auditor)
            elif entry == "audit":
                auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
            elif entry == "plan":
                auditor.build_plan()
            elif entry in {"GET", "POST"}:
                response = auditor._http_request(entry, self.target_url + "/api/documents/doc-owner")
                if response.status == 0 and response.error:
                    rejected = response.error
            else:
                raise AssertionError(entry)
        except ValueError as error:
            rejected = str(error)
        self.assertEqual(auditor.stats["transport_attempts"] - attempts, 0)
        self.assertEqual(len(ReplacementAuthHandler.requests) - count, 0)
        if rejected is not None:
            self.assertRegex(rejected.lower(), diagnostic)
        else:
            fresh = auditor.results[results:]
            self.assertTrue(fresh, "Invalid replacement must have an explicit rejection")
            for result in fresh:
                self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE)
                self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
                self.assertEqual(result["evidence"]["requests_attempted"], 0)

    def _assert_wire_isolation(self, start, *, location="header", name="x-access-key"):
        requests = ReplacementAuthHandler.requests[start:]
        self.assertEqual(len(requests), 4)
        observed = []
        for path, headers, cookies in requests:
            self.assertNotIn("authorization", headers)
            self.assertEqual(headers.get("x-tracking"), "trace")
            self.assertEqual(cookies.get("theme"), "dark")
            observed.append((path, (cookies if location == "cookie" else headers).get(name)))
        owner, visitor = ("COOKIE_OWNER", "COOKIE_VISITOR") if location == "cookie" else ("NEW_OWNER", "NEW_VISITOR")
        self.assertCountEqual(observed, [
            ("/api/documents/doc-owner", owner), ("/api/documents/doc-owner", visitor),
            ("/api/documents/doc-visitor", visitor), ("/api/documents/doc-owner", None),
        ])

    def test_newly_classified_anonymous_header_rejects_before_transport(self) -> None:
        for form in self.FORMS:
            for spelling in ("X-Access-Key", "x-aCcEsS-kEy"):
                with self.subTest(form=form, spelling=spelling):
                    self._reset_server()
                    old, _ = self._spec("old", name="X-Previous-Key")
                    new, _ = self._spec("new", form)
                    identities = self._identities()
                    identities["anonymous"]["headers"] = {spelling: "NEW_OWNER"}
                    auditor = self._auditor(old, identities)
                    self._run(auditor)
                    self.assertEqual(len(ReplacementAuthHandler.requests), 4)
                    ReplacementAuthHandler.credential_name = "x-access-key"
                    self._reject_replacement(auditor, new, diagnostic="anonymous|authentication")

    def test_new_auditor_rejects_the_same_anonymous_configuration(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._reset_server()
                new, _ = self._spec("fresh", form)
                identities = self._identities()
                identities["anonymous"]["headers"] = {"x-aCcEsS-kEy": "NEW_OWNER"}
                with self.assertRaisesRegex(ValueError, "anonymous"):
                    self._auditor(new, identities)
                self.assertEqual(ReplacementAuthHandler.requests, [])

    def test_valid_stopped_replacement_preserves_wire_isolation(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._reset_server()
                old, _ = self._spec("old", name="X-Previous-Key")
                new, _ = self._spec("new", form, name="x-AcCeSs-KeY")
                auditor = self._auditor(old, self._identities())
                self._run(auditor)
                self.assertEqual(len(ReplacementAuthHandler.requests), 4)
                start, attempts = len(ReplacementAuthHandler.requests), auditor.stats["transport_attempts"]
                ReplacementAuthHandler.credential_name = "x-access-key"
                auditor.parser = OpenAPIParser(str(new))
                self._run(auditor)
                self._assert_wire_isolation(start)
                self.assertEqual(auditor.stats["transport_attempts"] - attempts, 4)
                self.assertTrue(auditor.results)
                self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results))

    def test_replacement_registers_new_secrets_and_keeps_previous_secrets_redacted(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._reset_server()
                old, _ = self._spec("old", name="X-Previous-Key")
                new, _ = self._spec("new", form)
                auditor = self._auditor(old, self._identities())
                ReplacementAuthHandler.echo = True
                ReplacementAuthHandler.public_anonymous = True
                self._run(auditor)
                historical = auditor.results[0]
                evidence_alias = historical["evidence"]
                before = json.dumps(auditor.results)
                self.assertIn("opaque_current", before)
                self.assertIn("[REDACTED]", before)
                self.assertNotIn("OLD_OWNER", before)
                self.assertNotIn("OLD_VISITOR", before)
                self.assertIn("NEW_OWNER", before)
                self.assertIn("NEW_VISITOR", before)
                start = len(ReplacementAuthHandler.requests)
                ReplacementAuthHandler.credential_name = "x-access-key"
                auditor.parser = OpenAPIParser(str(new))
                self._run(auditor)
                self._assert_wire_isolation(start)
                for alias in (historical, evidence_alias):
                    self.assertNotIn("NEW_OWNER", json.dumps(alias))
                    self.assertNotIn("NEW_VISITOR", json.dumps(alias))
                json_text = json.dumps({"stats": auditor.stats, "results": auditor.results})
                self.assertIn("opaque_current", json_text)
                self.assertIn("opaque_previous", json_text)
                self.assertIn("[REDACTED]", json_text)
                html = self.root / "report.html"
                sarif = self.root / "report.sarif"
                SecurityReportGenerator.generate(auditor.stats, auditor.findings, self.target_url,
                                                 str(html), results=auditor.results)
                SarifReportGenerator.generate(auditor.results, self.target_url, str(sarif),
                                              secret_values=auditor._secret_values)
                self.assertTrue(json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"])
                self.assertTrue(auditor.findings)
                for report in (json_text, html.read_text(encoding="utf-8"), sarif.read_text(encoding="utf-8")):
                    for secret in ("OLD_OWNER", "OLD_VISITOR", "NEW_OWNER", "NEW_VISITOR"):
                        self.assertNotIn(secret, report)


    def test_direct_entry_points_reject_new_anonymous_authentication(self) -> None:
        for entry in ("audit", "plan", "GET", "POST"):
            with self.subTest(entry=entry):
                self._reset_server()
                old, _ = self._spec("old", name="X-Previous-Key")
                new, _ = self._spec("new", "multi-hop")
                identities = self._identities()
                identities["anonymous"]["headers"] = {"x-aCcEsS-kEy": "NEW_OWNER"}
                auditor = self._auditor(old, identities)
                ReplacementAuthHandler.credential_name = "x-access-key"
                self._reject_replacement(auditor, new, diagnostic="anonymous|authentication", entry=entry)

    def test_invalid_references_reject_without_new_transport_or_wire_requests(self) -> None:
        cases = (
            {"$ref": "#/missing"}, {"$ref": "missing.yaml#/Final"},
            {"$ref": "#/components/securitySchemes/Auth"},
            {"$ref": self.target_url + "/remote.yaml#/Final"},
            {"$ref": "../outside.yaml#/Final"},
            {"$ref": "#/x-valid", "in": "cookie"},
            {"type": "apiKey", "in": "header", "name": []},
            {"$ref": "#/x-list"},
        )
        for index, definition in enumerate(cases):
            for entry in ("run", "POST"):
                with self.subTest(case=index, entry=entry):
                    self._reset_server()
                    old, _ = self._spec("old", name="X-Previous-Key")
                    new, spec = self._spec("invalid")
                    spec["components"]["securitySchemes"]["Auth"] = definition
                    spec["x-valid"] = {"type": "apiKey", "in": "header", "name": "X-Access-Key"}
                    spec["x-list"] = ["invalid"]
                    # No authentication Parameter Object should be needed to trigger validation.
                    spec["paths"][self.PATH]["get"]["parameters"].pop(1)
                    new.write_text(json.dumps(spec), encoding="utf-8")
                    auditor = self._auditor(old, self._identities())
                    self._run(auditor)
                    self.assertEqual(len(ReplacementAuthHandler.requests), 4)
                    self._reject_replacement(auditor, new, diagnostic="security|scheme|reference|authentication", entry=entry)

    def test_new_authentication_cannot_be_supplied_from_common_parameters(self) -> None:
        for form in self.FORMS:
            for location, name in (("header", "X-Access-Key"), ("cookie", "k")):
                with self.subTest(form=form, location=location):
                    self._reset_server()
                    old, _ = self._spec("old", name="X-Previous-Key")
                    new, _ = self._spec("new", form, name=name, location=location, retain_previous=True)
                    values = {"common": {name: "NEW_OWNER", "X-Tracking": "trace", "theme": "dark"}}
                    auditor = self._auditor(old, self._identities(new_header=False), values)
                    self._run(auditor)
                    self.assertEqual(len(ReplacementAuthHandler.requests), 4)
                    ReplacementAuthHandler.location = location
                    ReplacementAuthHandler.credential_name = name.lower()
                    self._reject_replacement(auditor, new, diagnostic="authentication|parameter|cookie")

    def test_common_header_values_cannot_override_new_identity_headers(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._reset_server()
                old, _ = self._spec("old", name="X-Previous-Key")
                new, _ = self._spec("new", form, name="x-access-key")
                values = {"common": {"x-access-key": "SHARED_POISON", "X-Tracking": "trace", "theme": "dark"}}
                auditor = self._auditor(old, self._identities(), values)
                self._run(auditor)
                start = len(ReplacementAuthHandler.requests)
                ReplacementAuthHandler.credential_name = "x-access-key"
                auditor.parser = OpenAPIParser(str(new))
                self._run(auditor)
                self._assert_wire_isolation(start)
                self.assertNotIn("SHARED_POISON", json.dumps(ReplacementAuthHandler.requests))
                self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results))

    def test_scoped_cookie_credentials_stay_isolated_after_replacement(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._reset_server()
                old, _ = self._spec("old", name="X-Previous-Key")
                new, _ = self._spec("new", form, name="k", location="cookie", retain_previous=True)
                values = {"owner": {"k": "COOKIE_OWNER"}, "visitor": {"k": "COOKIE_VISITOR"},
                          "common": {"X-Tracking": "trace", "theme": "dark"}}
                auditor = self._auditor(old, self._identities(), values)
                self._run(auditor)
                start = len(ReplacementAuthHandler.requests)
                ReplacementAuthHandler.location = "cookie"
                ReplacementAuthHandler.credential_name = "k"
                ReplacementAuthHandler.echo = True
                auditor.parser = OpenAPIParser(str(new))
                self._run(auditor)
                self._assert_wire_isolation(start, location="cookie", name="k")
                self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results))
                report = json.dumps(auditor.results)
                self.assertIn("opaque_current", report)
                self.assertNotIn("COOKIE_OWNER", report)
                self.assertNotIn("COOKIE_VISITOR", report)

    def test_build_plan_refreshes_historical_redaction_without_transport(self) -> None:
        self._reset_server()
        old, _ = self._spec("old", name="X-Previous-Key")
        new, _ = self._spec("new", "multi-hop")
        auditor = self._auditor(old, self._identities())
        ReplacementAuthHandler.echo = True
        self._run(auditor)
        previous = auditor.results[0]
        self.assertIn("NEW_OWNER", json.dumps(previous))
        attempts = auditor.stats["transport_attempts"]
        count = len(ReplacementAuthHandler.requests)
        auditor.parser = OpenAPIParser(str(new))
        plan = auditor.build_plan()
        self.assertTrue(plan)
        self.assertEqual(auditor.stats["transport_attempts"], attempts)
        self.assertEqual(len(ReplacementAuthHandler.requests), count)
        for secret in ("OLD_OWNER", "OLD_VISITOR", "NEW_OWNER", "NEW_VISITOR"):
            self.assertNotIn(secret, json.dumps(previous))
            self.assertNotIn(secret, json.dumps(plan))


    def test_rejected_parser_stays_blocked_and_valid_replacement_recovers(self) -> None:
        old, _ = self._spec("old", name="X-Previous-Key")
        bad, invalid = self._spec("bad")
        invalid["components"]["securitySchemes"]["Auth"] = {"$ref": "#/missing"}
        bad.write_text(json.dumps(invalid), encoding="utf-8")
        new, _ = self._spec("new", "multi-hop")
        auditor = self._auditor(old, self._identities())
        self._run(auditor)
        attempts = auditor.stats["transport_attempts"]
        count = len(ReplacementAuthHandler.requests)
        auditor.parser = OpenAPIParser(str(bad))
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "(?i)security|scheme|reference|authentication"):
                self._run(auditor)
            self.assertEqual(auditor.stats["transport_attempts"], attempts)
            self.assertEqual(len(ReplacementAuthHandler.requests), count)
        auditor.parser = OpenAPIParser(str(new))
        ReplacementAuthHandler.credential_name = "x-access-key"
        self._run(auditor)
        self._assert_wire_isolation(count)
        self.assertEqual(auditor.stats["transport_attempts"] - attempts, 4)
        self.assertTrue(all(result["verdict"] == Verdict.SECURE for result in auditor.results))

    def test_concurrent_first_requests_validate_replacement_before_transport(self) -> None:
        old, _ = self._spec("old", name="X-Previous-Key")
        new, _ = self._spec("new", "multi-hop")
        auditor = self._auditor(old, self._identities())
        ReplacementAuthHandler.echo = True
        self._run(auditor)
        previous = auditor.results[0]
        self.assertIn("NEW_OWNER", json.dumps(previous))
        count = len(ReplacementAuthHandler.requests)
        attempts = auditor.stats["transport_attempts"]
        auditor.parser = OpenAPIParser(str(new))
        ReplacementAuthHandler.credential_name = "x-access-key"
        roles = ("owner", "visitor", "anonymous") * 2
        barrier = threading.Barrier(len(roles))

        def request(role):
            resource = "doc-visitor" if role == "visitor" else "doc-owner"
            barrier.wait(timeout=5)
            return auditor._http_request("GET", self.target_url + "/api/documents/" + resource,
                                         identity_name=role)

        with ThreadPoolExecutor(max_workers=len(roles)) as pool:
            responses = list(pool.map(request, roles))
        self.assertEqual([response.status for response in responses], [200, 200, 401] * 2)
        self.assertEqual(auditor.stats["transport_attempts"] - attempts, len(roles))
        received = ReplacementAuthHandler.requests[count:]
        self.assertEqual(len(received), len(roles))
        self.assertCountEqual([headers.get("x-access-key") for _, headers, _ in received],
                              ["NEW_OWNER", "NEW_VISITOR", None] * 2)
        for secret in ("OLD_OWNER", "OLD_VISITOR", "NEW_OWNER", "NEW_VISITOR"):
            self.assertNotIn(secret, json.dumps(previous))


if __name__ == "__main__":
    unittest.main()
