"""Safety and evidence boundaries of the 2.7.0 detectors.

* Read-only POST BOLA: the ``read_only`` declaration is necessary but not
  sufficient. Mutation semantics (wider vocabulary than GET), a missing read
  action, a mutating concrete path, an invalid declaration or an invalid body
  each send zero requests. Bodies are literal; per-identity bodies are explicit.
* RBAC matrix: a lower role is CONFIRMED only with the BFLA evidence standard
  (valid privileged baseline, clean Anonymous denial, configured protected data
  in a valid role response). An HTTP 200 alone is never a violation.
* Sensitive-property heuristic: field names select candidates only; values are
  compared at exact paths, bounded on untrusted input, never reported, and
  CONFIRMED only on top of a confirmed object-level decision.

Every dynamic test talks to an in-process mock or a loopback test server.
"""

from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import api_sentinel
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import HTTPResult, Verdict
from core.reporter import SecurityReportGenerator
from core.sarif import SarifReportGenerator
from core.scan_safety import post_path_risk, read_only_risk


TARGET = "http://127.0.0.1:8080"
SECURED = [{"BearerAuth": []}]
DENIED = json.dumps({"error": "Unauthorized"})
IDENTITIES: Dict[str, Any] = {
    "owner": {"id": "1001", "token": "Bearer OWNER_TOKEN_0001"},
    "visitor": {"id": "1002", "token": "Bearer VISITOR_TOKEN_0002"},
    "anonymous": {},
}


def _operation(summary: str, *, operation_id: Optional[str] = None, description: Optional[str] = None,
               parameters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"summary": summary, "security": SECURED,
                                 "responses": {"200": {"description": "OK"}}}
    if operation_id:
        operation["operationId"] = operation_id
    if description:
        operation["description"] = description
    if parameters:
        operation["parameters"] = parameters
    return operation


ID_PARAMETER = [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]
SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "2.7 hardening", "version": "1"},
    "components": {"securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/documents/search": {"post": _operation("Search documents")},
        "/documents/{id}/lookup": {"post": _operation("Look up a document", operation_id="lookupDocument",
                                                      parameters=ID_PARAMETER)},
        "/documents": {"post": _operation("Create a document", operation_id="createDocument")},
        "/documents/delete": {"post": _operation("Search then purge", operation_id="findDocuments")},
        "/members": {"post": _operation("Add a member")},
        "/auth/login": {"post": _operation("Search session")},
        "/reports/query": {"post": _operation("Query reports",
                                              description="Returns reports. It also deletes the export cache.")},
        "/admin/post-action": {"post": _operation("Admin post action")},
        "/orders/search": {"post": _operation("Search orders")},
        "/admin/settings": {"get": _operation("Admin settings")},
        "/admin/audit/search": {"post": _operation("Search the admin audit log")},
        "/users/{id}": {"get": _operation("Get a user", parameters=ID_PARAMETER)},
        "/profile": {"get": _operation("Get the caller profile")},
    },
}


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.spec_path = self.folder / "spec.json"
        self.spec_path.write_text(json.dumps(SPEC), encoding="utf-8")

    def auditor(self, bola: Dict[str, Any], identities: Optional[Dict[str, Any]] = None,
                target: str = TARGET, **kwargs: Any) -> APISentinelAuditor:
        return APISentinelAuditor(str(self.spec_path), target, request_delay=0,
                                  identities_config=identities or IDENTITIES, bola_config=bola, **kwargs)

    @staticmethod
    def endpoint(auditor: APISentinelAuditor, method: str, path: str) -> Dict[str, Any]:
        return next(ep for ep in auditor.parser.get_endpoints() if ep["method"] == method and ep["path"] == path)

    @staticmethod
    def recorder(answer: Callable[[str, str, Any, str], HTTPResult]) -> Tuple[List[Dict[str, Any]], Callable[..., HTTPResult]]:
        sent: List[Dict[str, Any]] = []

        def transport(method: str, url: str, data: Any = None, identity_name: str = "anonymous",
                      headers: Optional[Dict[str, str]] = None, content_type: str = "application/json") -> HTTPResult:
            sent.append({"method": method, "url": url, "data": data, "identity": identity_name})
            return answer(method, url, data, identity_name)
        return sent, transport


def _ok(document: Any) -> HTTPResult:
    return HTTPResult(status=200, body=json.dumps(document))


class ReadOnlyPostSafetyTests(_Base):
    def run_post(self, path: str, policy: Dict[str, Any], identities: Optional[Dict[str, Any]] = None):
        auditor = self.auditor({f"POST {path}": policy}, identities)
        sent, transport = self.recorder(lambda m, u, d, i: _ok({"id": "doc-1", "owner": i}))
        auditor._http_request = transport
        auditor._audit_endpoint_bola(self.endpoint(auditor, "POST", path))
        return auditor, sent

    def test_mutation_semantics_block_a_declared_read_only_post_before_any_request(self):
        cases = {
            "/documents": "operation_id",        # createDocument
            "/documents/delete": "path",         # benign operationId cannot rescue the path
            "/members": "summary",               # "Add" is a POST mutation verb
            "/auth/login": "path",               # authentication changes session/lockout state
            "/reports/query": "description",     # "It also deletes ..."
        }
        for path, signal in cases.items():
            with self.subTest(path=path):
                auditor, sent = self.run_post(path, {"read_only": True, "body": {"q": "x"}})
                self.assertEqual(sent, [])
                result = auditor.results[0]
                self.assertEqual(result["verdict"], Verdict.SKIPPED.value)
                self.assertEqual(result["evidence"]["safety_signal"], signal)
                self.assertEqual(result["evidence"]["requests_attempted"], 0)

    def test_post_without_a_named_read_action_is_refused(self):
        auditor, sent = self.run_post("/admin/post-action", {"read_only": True, "body": {"cmd": "noop"}})
        self.assertEqual(sent, [])
        self.assertEqual(auditor.results[0]["evidence"]["safety_signal"], "post_read_intent")
        self.assertIn("read action", auditor.results[0]["reason"])

    def test_heuristics_are_only_a_gate(self):
        allowed = ({"method": "POST", "path": "/orders/search"}, {"method": "POST", "path": "/v1/_search"},
                   {"method": "POST", "path": "/rpc", "operation_id": "getUser"},
                   {"method": "POST", "path": "/reports/query"}, {"method": "POST", "path": "/archives/lookup"})
        for endpoint in allowed:
            with self.subTest(endpoint=endpoint):
                self.assertIsNone(read_only_risk(endpoint))
        refused = ({"method": "POST", "path": "/orders/{id}", "summary": "Get order and send email"},
                   {"method": "POST", "path": "/users/{id}/verify", "summary": "Check user"},
                   {"method": "POST", "path": "/cart/search", "operation_id": "checkoutCart"},
                   {"method": "POST", "path": "/things"})
        for endpoint in refused:
            with self.subTest(endpoint=endpoint):
                self.assertIsNotNone(read_only_risk(endpoint))
        # The wider vocabulary applies to POST only; GET decisions are unchanged.
        self.assertIsNone(read_only_risk({"method": "GET", "path": "/members/add-ons"}))

    def test_concrete_path_values_that_name_a_mutation_are_refused(self):
        identities = {**IDENTITIES, "owner": {"id": "delete", "token": "Bearer OWNER_TOKEN_0001"}}
        auditor, sent = self.run_post("/documents/{id}/lookup", {"read_only": True, "body": {"q": 1}}, identities)
        self.assertEqual(sent, [])
        self.assertEqual(auditor.results[0]["verdict"], Verdict.SKIPPED.value)
        self.assertEqual(auditor.results[0]["evidence"]["safety_signal"], "path")
        self.assertIsNotNone(post_path_risk("/documents/%64elete/lookup"))
        self.assertIsNotNone(post_path_risk("/documents/x;delete"))
        self.assertIsNone(post_path_risk("/documents/doc-1001/lookup"))

    def test_read_only_must_be_the_boolean_true(self):
        for value in ("true", 1, None, False):
            with self.subTest(read_only=value):
                auditor, sent = self.run_post("/documents/search", {"read_only": value, "body": {"q": "x"}})
                self.assertEqual(sent, [])
                self.assertEqual(auditor.results[0]["verdict"], Verdict.SKIPPED.value)
                self.assertEqual(auditor.results[0]["evidence"]["requests_sent"], 0)

    def test_missing_null_or_incomplete_bodies_send_nothing(self):
        for policy in ({"read_only": True}, {"read_only": True, "body": None},
                       {"read_only": True, "identity_bodies": {"visitor_self": {"id": 2}}},
                       {"read_only": True, "identity_bodies": {"owner": None}},
                       {"read_only": True, "identity_bodies": ["owner"]}):
            with self.subTest(policy=policy):
                auditor, sent = self.run_post("/documents/search", policy)
                self.assertEqual(sent, [])
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE.value)
                self.assertEqual(auditor.results[0]["evidence"]["requests_attempted"], 0)

    def test_invalid_policies_send_nothing(self):
        for policy in ({"read_only": True, "body": {"q": float("nan")}},
                       {"read_only": True, "body": {"q": 1}, "identity_bodies": {"owner": {"q": 1}}},
                       {"read_only": True, "identity_bodies": {"owner": {"q": 1}, "visitor": {"q": 2}}},
                       {"read_only": True, "body": "x" * 70000}):
            with self.subTest(policy=str(policy)[:80]):
                auditor, sent = self.run_post("/documents/search", policy)
                self.assertEqual(sent, [])
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE.value)
                self.assertEqual(auditor.results[0]["evidence"]["reason_category"], "invalid_input")

    def test_a_body_is_literal_and_never_an_identity_map(self):
        body = {"owner": "alice", "visitor": "bob"}
        auditor, sent = self.run_post("/documents/search", {"read_only": True, "body": body})
        self.assertGreaterEqual(len(sent), 3)
        self.assertTrue(all(item["data"] == body and item["method"] == "POST" for item in sent))

    def test_cross_and_anonymous_requests_repeat_the_owner_body(self):
        owner, own = {"doc_id": "D-1001"}, {"doc_id": "D-1002"}
        auditor, sent = self.run_post("/documents/search", {
            "read_only": True, "identity_bodies": {"owner": owner, "visitor_self": own}})
        pairs = [(item["identity"], item["data"]) for item in sent]
        self.assertEqual(pairs, [("owner", owner), ("visitor", owner), ("anonymous", owner), ("visitor", own)])

    def test_empty_and_falsy_bodies_are_sent_exactly_and_select_no_object(self):
        for body in ({}, [], "", False, 0):
            with self.subTest(body=body):
                auditor, sent = self.run_post("/documents/search", {"read_only": True, "body": body})
                self.assertEqual(len(sent), 3)  # Owner, Visitor, Anonymous; no own-resource baseline
                for item in sent:
                    self.assertEqual(json.dumps(item["data"]), json.dumps(body))
                selected = APISentinelAuditor._body_selects_object(body)
                self.assertEqual(selected, body == 0 and body is not False)

    def test_get_operations_never_carry_a_body(self):
        auditor = self.auditor({"GET /users/{id}": {"expected_visitor_access": "deny"}})
        sent, transport = self.recorder(lambda m, u, d, i: _ok({"id": "1001"}))
        auditor._http_request = transport
        auditor._audit_endpoint_bola(self.endpoint(auditor, "GET", "/users/{id}"))
        self.assertTrue(sent)
        self.assertTrue(all(item["data"] is None and item["method"] == "GET" for item in sent))
        for key in ("read_only", "body", "identity_bodies"):
            with self.subTest(key=key):
                value = True if key == "read_only" else {"owner": {"q": 1}} if key == "identity_bodies" else {"q": 1}
                auditor = self.auditor({"GET /users/{id}": {key: value}})
                sent, transport = self.recorder(lambda m, u, d, i: _ok({"id": "1001"}))
                auditor._http_request = transport
                auditor._audit_endpoint_bola(self.endpoint(auditor, "GET", "/users/{id}"))
                self.assertEqual(sent, [])
                self.assertEqual(auditor.results[0]["evidence"]["reason_category"], "invalid_input")

    def test_validator_reports_body_problems_without_echoing_values(self):
        secret = "PRIVATE-SELECTOR-77"
        cases = {
            "nan": {"read_only": True, "body": {"q": float("inf"), "s": secret}},
            "large": {"read_only": True, "body": {"q": secret * 5000}},
            "deep": {"read_only": True, "body": json.loads("[" * 40 + json.dumps(secret) + "]" * 40)},
            "both": {"read_only": True, "body": {"s": secret}, "identity_bodies": {"owner": {"s": secret}}},
            "unknown_identity": {"read_only": True, "identity_bodies": {"owner": {"s": secret}, "anonymous": {}}},
            "missing_body": {"read_only": True},
            "not_boolean": {"read_only": "yes", "body": {"s": secret}},
        }
        for name, policy in cases.items():
            with self.subTest(case=name):
                result = ConfigValidator.validate({"bola": {"POST /documents/search": policy}})
                self.assertFalse(result.is_valid)
                self.assertNotIn(secret, json.dumps([issue.format() for issue in result.issues]))
        warning = ConfigValidator.validate({"bola": {"POST /documents/search": {"body": {"q": 1}}}})
        self.assertTrue(warning.is_valid)
        self.assertTrue(any("read_only" in issue.path for issue in warning.warnings))
        valid = ConfigValidator.validate({"bola": {"POST /documents/search": {
            "read_only": True, "identity_bodies": {"owner": {"q": 1}, "visitor_self": {"q": 2}}}}})
        self.assertTrue(valid.is_valid, [issue.format() for issue in valid.errors])

    def test_dry_run_plan_matches_the_runtime_gate_and_sends_nothing(self):
        auditor = self.auditor({
            "POST /documents/search": {"read_only": True, "body": {"q": 1}},
            "POST /documents": {"read_only": True, "body": {"q": 1}},
            "POST /orders/search": {"read_only": True},
            "POST /members": {"body": {"q": 1}},
        })
        auditor._http_request = lambda *a, **k: self.fail("dry run sent a request")
        plan = {item["endpoint"]: item for item in auditor.build_plan()["operations"]}
        self.assertEqual(plan["POST /documents/search"]["check"], "BOLA")  # A nonempty body selects an object.
        self.assertTrue(plan["POST /documents/search"]["request_body_configured"])
        self.assertNotIn("safety_blocked", plan["POST /documents/search"])
        self.assertEqual(plan["POST /documents"]["safety_signal"], "operation_id")
        self.assertTrue(plan["POST /orders/search"]["safety_blocked"])
        self.assertFalse(plan["POST /orders/search"]["request_body_configured"])
        self.assertEqual(plan["POST /members"]["check"], "UNSUPPORTED")
        self.assertNotIn('"q"', json.dumps(plan))


class _RecordingHandler(BaseHTTPRequestHandler):
    calls: List[Dict[str, Any]] = []
    lock = threading.Lock()
    answers: Dict[Tuple[str, str], Tuple[int, Any]] = {}

    def log_message(self, *args: object) -> None:
        pass

    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        token = self.headers.get("Authorization", "")
        identity = token.split("_", 1)[0].replace("Bearer ", "").lower() if token else "anonymous"
        with self.lock:
            self.calls.append({"method": self.command, "path": self.path, "identity": identity,
                               "content_type": self.headers.get("Content-Type"), "body": raw.decode("utf-8")})
        status, document = self.answers.get((self.path, identity), (401, {"error": "Unauthorized"}))
        payload = json.dumps(document).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if status == 429:
            self.send_header("Retry-After", "0")
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _answer


class LoopbackTransportTests(_Base):
    """Real HTTP through the auditor's transport, against a loopback recorder."""

    def setUp(self) -> None:
        super().setUp()
        _RecordingHandler.calls = []
        _RecordingHandler.answers = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.identities = {
            "owner": {"id": "1001", "token": "Bearer OWNER_TOKEN_0001"},
            "visitor": {"id": "1002", "token": "Bearer VISITOR_TOKEN_0002"},
            "anonymous": {},
            "roles": {"admin": {"token": "Bearer ADMIN_TOKEN_0003", "role": "administrator"},
                      "viewer": {"token": "Bearer VIEWER_TOKEN_0004", "role": "viewer"}},
        }

    def test_full_scan_sends_only_declared_read_only_posts_with_exact_bodies(self):
        _RecordingHandler.answers = {
            ("/documents/search", "owner"): (200, {"items": [{"id": "D-1001", "title": "Owner"}]}),
            ("/documents/search", "visitor"): (429, {"error": "slow down"}),
        }
        auditor = self.auditor({
            "POST /documents/search": {"read_only": True, "identity_bodies": {
                "owner": {"owner_id": "1001"}, "visitor_self": {"owner_id": "1002"}}},
            "POST /documents": {"read_only": True, "body": {"title": "x"}},  # createDocument: refused
            "POST /members": {"body": {"name": "x"}},                          # not declared: skipped
        }, self.identities, target=self.base, max_workers=2)
        with redirect_stdout(io.StringIO()):
            auditor.run()
        posts = [call for call in _RecordingHandler.calls if call["method"] == "POST"]
        self.assertEqual({call["path"] for call in posts}, {"/documents/search"})
        self.assertEqual(sorted((call["identity"], json.loads(call["body"])["owner_id"]) for call in posts),
                         [("anonymous", "1001"), ("owner", "1001"), ("visitor", "1001"), ("visitor", "1002")])
        self.assertTrue(all(call["content_type"] == "application/json" for call in posts))
        # A rate-limited POST is answered once and never re-sent.
        self.assertEqual(sum(1 for call in posts if call["identity"] == "visitor"), 2)
        self.assertEqual(auditor.stats["rate_limit_retries"], 0)
        self.assertNotIn("/documents", [call["path"] for call in _RecordingHandler.calls])
        self.assertNotIn("/members", [call["path"] for call in _RecordingHandler.calls])

    def test_cli_reports_rbac_consistently_and_never_leak_role_tokens(self):
        protected = {"setting": "SIGNING-KEY-9F3A"}
        _RecordingHandler.answers = {
            ("/admin/settings", "owner"): (200, protected),
            ("/admin/settings", "admin"): (200, protected),
            ("/admin/settings", "viewer"): (200, protected),
            ("/admin/settings", "visitor"): (403, {"error": "Forbidden"}),
        }
        config = self.folder / "config.json"
        config.write_text(json.dumps({"identities": self.identities, "bola": {
            "GET /admin/settings": {"required_role": "administrator", "private_data_paths": ["setting"]}}}),
            encoding="utf-8")
        html, exported, sarif = self.folder / "r.html", self.folder / "r.json", self.folder / "r.sarif"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = api_sentinel.main(["--spec", str(self.spec_path), "--config", str(config), "--target", self.base,
                                      "--output", str(html), "--export-json", str(exported),
                                      "--export-sarif", str(sarif), "--delay", "0"])
        self.assertIn(code, (0, 1))
        report = json.loads(exported.read_text(encoding="utf-8"))
        rbac = [item for item in report["results"] if item["check"] == "RBAC"]
        self.assertEqual([(item["evidence"]["rbac_role"], item["verdict"]) for item in rbac], [("viewer", "CONFIRMED")])
        cell = report["rbac_matrix"]["GET /admin/settings"]["roles"]
        self.assertEqual((cell["admin"]["access"], cell["viewer"]["access"]), ("ALLOWED", "VIOLATION"))
        self.assertEqual([f["evidence"]["rbac_role"] for f in report["findings"] if f.get("check") == "RBAC"],
                         ["viewer"])
        rules = [item["ruleId"] for item in json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
                 if item["properties"]["check"] == "RBAC"]
        self.assertEqual(rules, ["GT-BFLA-001"])
        page = html.read_text(encoding="utf-8")
        self.assertIn('id="rbac-matrix"', page)
        self.assertIn("VIOLATION", page)
        for output in (page, exported.read_text(encoding="utf-8"), sarif.read_text(encoding="utf-8")):
            for secret in ("ADMIN_TOKEN_0003", "VIEWER_TOKEN_0004", "SIGNING-KEY-9F3A"):
                self.assertNotIn(secret, output)
        # Exactly one privileged baseline and one probe per other role were sent,
        # and the role results account for those requests (and only those).
        probes = [call["identity"] for call in _RecordingHandler.calls if call["identity"] in ("admin", "viewer")]
        self.assertEqual(sorted(probes), ["admin", "viewer"])
        self.assertEqual(sum(item["evidence"]["requests_attempted"] for item in rbac), 2)


class RbacEvidenceTests(_Base):
    ROLES = {"admin": {"token": "Bearer ADMIN_TOKEN_0003", "role": "administrator"},
             "viewer": {"token": "Bearer VIEWER_TOKEN_0004", "role": "viewer"}}

    def run_rbac(self, answers: Dict[str, HTTPResult], policy: Dict[str, Any],
                 roles: Optional[Dict[str, Any]] = None, path: str = "/admin/settings", method: str = "GET"):
        identities = {**IDENTITIES, "roles": roles or self.ROLES}
        auditor = self.auditor({f"{method} {path}": policy}, identities)
        default = HTTPResult(status=401, body=DENIED)
        sent, transport = self.recorder(lambda m, u, d, i: answers.get(i, default))
        auditor._http_request = transport
        auditor._audit_endpoint_bola(self.endpoint(auditor, method, path))
        cells = auditor.rbac_matrix.get(f"{method} {path}", {}).get("roles", {})
        rbac = [r for r in auditor.results if r["check"] == "RBAC"]
        return auditor, sent, cells, rbac

    def test_http_200_with_data_but_no_protected_data_evidence_is_not_a_violation(self):
        data = _ok({"setting": "value"})
        auditor, _, cells, rbac = self.run_rbac({"owner": data, "admin": data, "viewer": data},
                                                {"required_role": "administrator"})
        self.assertEqual(cells["viewer"]["access"], "UNPROVEN")
        self.assertFalse(cells["viewer"]["violation"])
        self.assertEqual([r["verdict"] for r in rbac], [Verdict.INCONCLUSIVE.value])
        self.assertFalse([f for f in auditor.findings if f.get("check") == "RBAC"])

    def test_violation_needs_a_clean_anonymous_denial(self):
        data = _ok({"setting": "SIGNING-KEY"})
        policy = {"required_role": "administrator", "private_data_paths": ["setting"]}
        auditor, _, cells, rbac = self.run_rbac(
            {"owner": data, "admin": data, "viewer": data, "anonymous": data}, policy)
        self.assertEqual(rbac[0]["verdict"], Verdict.INCONCLUSIVE.value)
        self.assertEqual(cells["viewer"]["access"], "UNPROVEN")
        _, _, cells, rbac = self.run_rbac({"owner": data, "admin": data, "viewer": data}, policy)
        self.assertEqual(rbac[0]["verdict"], Verdict.CONFIRMED.value)
        self.assertEqual(cells["viewer"]["access"], "VIOLATION")

    def test_denials_empty_and_missing_responses(self):
        data = _ok({"setting": "SIGNING-KEY"})
        policy = {"required_role": "administrator", "private_data_paths": ["setting"]}
        cases = {
            "clean_403": (HTTPResult(status=403, body=json.dumps({"error": "Forbidden"})), "DENIED", "SECURE"),
            "clean_401": (HTTPResult(status=401, body=DENIED), "DENIED", "SECURE"),
            "no_content": (HTTPResult(status=204, body=""), "EMPTY", "INCONCLUSIVE"),
            "not_found": (HTTPResult(status=404, body=json.dumps({"error": "Not found"})), "HTTP_404", "INCONCLUSIVE"),
            "login_page": (HTTPResult(status=200, body="<html>Sign in</html>"), "UNREADABLE", "INCONCLUSIVE"),
            "business_denial": (_ok({"code": 403, "error": "Access denied for this resource"}), "DENIED", "INCONCLUSIVE"),
        }
        for name, (answer, label, verdict) in cases.items():
            with self.subTest(case=name):
                _, _, cells, rbac = self.run_rbac({"owner": data, "admin": data, "viewer": answer}, policy)
                self.assertEqual((cells["viewer"]["access"], rbac[0]["verdict"]), (label, verdict))
                self.assertFalse(cells["viewer"]["violation"])
        _, _, cells, rbac = self.run_rbac(
            {"owner": data, "admin": data, "viewer": cases["not_found"][0]},
            dict(policy, not_found_is_denial=True))
        self.assertEqual((cells["viewer"]["access"], rbac[0]["verdict"]), ("DENIED", "SECURE"))

    def test_a_second_privileged_role_is_authorized_not_a_violation(self):
        data = _ok({"setting": "SIGNING-KEY"})
        roles = {**self.ROLES, "ops": {"token": "Bearer OPS_TOKEN_0005", "role": "administrator"}}
        _, _, cells, rbac = self.run_rbac({"owner": data, "admin": data, "viewer": data, "ops": data},
                                          {"required_role": "administrator", "private_data_paths": ["setting"]}, roles)
        self.assertEqual(cells["ops"]["access"], "ALLOWED")
        self.assertEqual({r["evidence"]["rbac_role"]: r["verdict"] for r in rbac},
                         {"viewer": "CONFIRMED", "ops": "AUTHORIZED"})

    def test_invalid_privileged_baseline_or_transport_errors(self):
        data = _ok({"setting": "SIGNING-KEY"})
        policy = {"required_role": "administrator", "private_data_paths": ["setting"]}
        auditor, sent, cells, rbac = self.run_rbac(
            {"owner": data, "admin": HTTPResult(status=401, body=DENIED), "viewer": data}, policy)
        self.assertNotIn("viewer", [item["identity"] for item in sent])
        self.assertEqual([(r["verdict"], r["evidence"]["rbac_role"]) for r in rbac], [("INCONCLUSIVE", "admin")])
        self.assertEqual(cells["admin"]["access"], "DENIED")
        _, _, cells, rbac = self.run_rbac(
            {"owner": data, "admin": data, "viewer": HTTPResult(status=0, body="", error="ConnectionResetError")}, policy)
        self.assertEqual((cells["viewer"]["access"], rbac[0]["verdict"]), ("ERROR", "ERROR"))
        _, sent, cells, rbac = self.run_rbac(
            {"owner": data, "admin": HTTPResult(status=0, body="", error="ConnectionResetError"), "viewer": data}, policy)
        self.assertEqual((cells["admin"]["access"], rbac[0]["verdict"]), ("ERROR", "INCONCLUSIVE"))
        self.assertNotIn("viewer", [item["identity"] for item in sent])

    def test_role_request_construction_failures_send_nothing_for_that_role(self):
        data = _ok({"setting": "SIGNING-KEY"})
        policy = {"required_role": "administrator", "private_data_paths": ["setting"]}
        broken = {"X-Role": "line\r\nbreak"}
        # Configuration with header injection is refused before any request.
        with self.assertRaises(ValueError):
            self.auditor({}, {**IDENTITIES, "roles": {"admin": {"headers": broken, "role": "administrator"}}})
        # Defensive path: a role that becomes unusable later fails alone.
        for failing, expected_probes, expected in (("admin", [], ("ERROR", "INCONCLUSIVE")),
                                                   ("viewer", ["admin"], ("ERROR", "ERROR"))):
            with self.subTest(failing=failing):
                identities = {**IDENTITIES, "roles": json.loads(json.dumps(self.ROLES))}
                auditor = self.auditor({"GET /admin/settings": policy}, identities)
                auditor.identities["roles"][failing]["headers"] = dict(broken)
                sent, transport = self.recorder(lambda m, u, d, i: data if i != "anonymous"
                                                else HTTPResult(status=401, body=DENIED))
                auditor._http_request = transport
                auditor._audit_endpoint_bola(self.endpoint(auditor, "GET", "/admin/settings"))
                probes = [item["identity"] for item in sent if item["identity"] in self.ROLES]
                rbac = [r for r in auditor.results if r["check"] == "RBAC"]
                cell = auditor.rbac_matrix["GET /admin/settings"]["roles"][failing]
                self.assertEqual(probes, expected_probes)
                self.assertEqual((cell["access"], rbac[0]["verdict"]), expected)

    def test_request_accounting_and_coverage_follow_every_role(self):
        data = _ok({"setting": "SIGNING-KEY"})
        roles = {**self.ROLES, "guest": {"token": "Bearer GUEST_TOKEN_0006", "role": "guest"}}
        auditor, sent, _, rbac = self.run_rbac(
            {"owner": data, "admin": data, "viewer": data, "guest": HTTPResult(status=403, body=json.dumps({"error": "Forbidden"}))},
            {"required_role": "administrator", "private_data_paths": ["setting"]}, roles)
        probes = [item for item in sent if item["identity"] in roles]
        self.assertEqual(len(probes), 3)  # One baseline plus one per lower role.
        self.assertEqual([r["verdict"] for r in rbac], ["CONFIRMED", "SECURE"])
        # Coverage needs every probed role to be conclusive (one result per role).
        for verdicts, conclusive in ((["CONFIRMED", "SECURE"], 1), (["CONFIRMED", "INCONCLUSIVE"], 0)):
            auditor.results = [{"endpoint": "GET /admin/settings", "check": "RBAC", "verdict": verdict,
                                "evidence": {"requests_attempted": 1}} for verdict in verdicts]
            auditor.stats["total_endpoints"] = 1
            auditor._finalise_coverage()
            self.assertEqual(auditor.stats["conclusive_endpoints"], conclusive, verdicts)

    def test_reserved_role_names_are_refused(self):
        roles = {"owner": {"token": "Bearer X_TOKEN_0007", "role": "viewer"},
                 "admin": {"token": "Bearer ADMIN_TOKEN_0003", "role": "administrator"}}
        result = ConfigValidator.validate({"identities": {**IDENTITIES, "roles": roles}})
        self.assertTrue(any("built-in identity" in issue.message for issue in result.errors))
        _, sent, _, rbac = self.run_rbac({"owner": _ok({"setting": "x"})}, {"required_role": "administrator"}, roles)
        self.assertEqual([item["identity"] for item in sent if item["identity"] == "admin"], [])
        self.assertEqual(rbac[0]["evidence"]["reason_category"], "invalid_input")

    def test_role_header_values_are_secrets_and_the_role_map_is_not_an_identity(self):
        roles = {"auth_header_names": {"token": "Bearer ODD_NAME_TOKEN_0008", "role": "viewer"},
                 "admin": {"headers": {"X-Role-Session": "ROLE-SESSION-SECRET-1"}, "role": "administrator"}}
        auditor = self.auditor({}, {**IDENTITIES, "roles": roles})
        secrets = auditor.secret_values()
        self.assertIn("ROLE-SESSION-SECRET-1", secrets)
        self.assertIn("ODD_NAME_TOKEN_0008", secrets)

    def test_role_bodies_apply_to_post_only(self):
        roles = {"admin": {"token": "Bearer ADMIN_TOKEN_0003", "role": "administrator", "body": {"r": "admin"}},
                 "viewer": {"token": "Bearer VIEWER_TOKEN_0004", "role": "viewer"}}
        data = _ok({"setting": "x"})
        _, sent, _, _ = self.run_rbac({"owner": data, "admin": data, "viewer": data},
                                      {"required_role": "administrator"}, roles)
        self.assertTrue(all(item["data"] is None for item in sent))
        _, sent, _, _ = self.run_rbac({"owner": data, "admin": data, "viewer": data},
                                      {"required_role": "administrator", "read_only": True, "body": {"q": "all"}},
                                      roles, path="/admin/audit/search", method="POST")
        bodies = {item["identity"]: item["data"] for item in sent if item["identity"] in roles}
        self.assertEqual(bodies, {"admin": {"r": "admin"}, "viewer": {"q": "all"}})

    def test_html_report_renders_the_matrix_only_when_present(self):
        matrix = {"GET /admin/settings": {"roles": {
            "admin": {"status": 200, "access": "ALLOWED", "verdict": "AUTHORIZED", "baseline": True},
            "viewer": {"status": 200, "access": "UNPROVEN", "verdict": "INCONCLUSIVE"}}}}
        for rbac_matrix, expected in ((matrix, True), (None, False), ({}, False)):
            with self.subTest(matrix=bool(rbac_matrix)):
                output = self.folder / "report.html"
                SecurityReportGenerator.generate(stats={}, findings=[], target_url=TARGET, results=[],
                                                 output_path=str(output), rbac_matrix=rbac_matrix)
                page = output.read_text(encoding="utf-8")
                self.assertEqual('id="rbac-matrix"' in page, expected)
                if expected:
                    self.assertIn("UNPROVEN", page)
                    self.assertIn("INCONCLUSIVE", page)


class SensitiveExposureTests(_Base):
    OWNER = {"id": "1001", "name": "Alice Owner", "phone": "13800138000", "salary": 250000}
    SELF = {"id": "1002", "name": "Bob Visitor", "phone": "13900139000", "salary": 180000}

    def run_object(self, cross: Any, own: Any, policy: Optional[Dict[str, Any]] = None,
                   owner: Optional[Any] = None):
        auditor = self.auditor({"GET /users/{id}": policy or {"expected_visitor_access": "deny",
                                                              "detect_sensitive_exposure": True}})

        def answer(method: str, url: str, data: Any, identity: str) -> HTTPResult:
            if identity == "owner":
                return _ok(owner if owner is not None else self.OWNER)
            if identity == "visitor":
                return _ok(cross if url.endswith("/1001") else own)
            return HTTPResult(status=401, body=DENIED)
        _, transport = self.recorder(answer)
        auditor._http_request = transport
        auditor._audit_endpoint_bola(self.endpoint(auditor, "GET", "/users/{id}"))
        exposure = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        bola = next(r for r in auditor.results if r["check"] == "BOLA")
        return auditor, bola, exposure

    def test_confirmed_only_on_a_confirmed_object_decision_with_owner_specific_values(self):
        auditor, bola, exposure = self.run_object(self.OWNER, self.SELF)
        self.assertEqual(bola["verdict"], Verdict.CONFIRMED.value)
        self.assertEqual(exposure[0]["verdict"], Verdict.CONFIRMED.value)
        self.assertEqual(exposure[0]["evidence"]["exposed_sensitive_paths"], ["phone", "salary"])
        findings = [f for f in auditor.findings if f.get("check") == "BOPLA_EXPOSURE"]
        self.assertEqual(len(findings), 1)
        sarif = self.folder / "r.sarif"
        SarifReportGenerator.generate(auditor.results, TARGET, str(sarif))
        document = json.loads(sarif.read_text(encoding="utf-8"))
        self.assertIn("GT-BOPLA-001", [rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]])
        self.assertIn("GT-BOPLA-001", [item["ruleId"] for item in document["runs"][0]["results"]])
        for text in (json.dumps(auditor.results), json.dumps(auditor.findings), sarif.read_text(encoding="utf-8")):
            self.assertNotIn("13800138000", text)
            self.assertNotIn("250000", text)

    def test_values_shared_with_the_visitors_own_record_are_not_exposure(self):
        own = dict(self.SELF, phone=self.OWNER["phone"])  # A shared switchboard number.
        _, _, exposure = self.run_object(self.OWNER, own)
        self.assertEqual(exposure[0]["evidence"]["exposed_sensitive_paths"], ["salary"])
        self.assertEqual(exposure[0]["evidence"]["shared_with_visitor_self_paths"], ["phone"])
        same = dict(self.SELF, phone=self.OWNER["phone"], salary=self.OWNER["salary"])
        _, _, exposure = self.run_object(self.OWNER, same)
        self.assertEqual(exposure, [])

    def test_object_decision_not_confirmed_keeps_a_lead(self):
        # The cross response equals the Visitor's own record: the API ignored the id.
        _, bola, exposure = self.run_object(self.SELF, self.SELF, owner=dict(self.OWNER, phone=self.SELF["phone"]))
        self.assertNotEqual(bola["verdict"], Verdict.CONFIRMED.value)
        self.assertEqual(exposure, [])
        _, _, exposure = self.run_object(self.OWNER, self.SELF, policy={"detect_sensitive_exposure": True})
        self.assertEqual(exposure[0]["verdict"], Verdict.SUSPICIOUS.value)
        self.assertIn("explicit_visitor_deny_policy", exposure[0]["evidence"]["missing_evidence"])

    def test_untrusted_shapes_are_bounded_and_private_keys_are_not_reported(self):
        deep: Any = {"phone": "13800138000"}
        for _ in range(40):
            deep = {"next": deep}
        _, _, exposure = self.run_object(deep, self.SELF, owner=deep)
        self.assertEqual(exposure[0]["verdict"], Verdict.INCONCLUSIVE.value)
        wide = {"rows": [{"n": index} for index in range(25000)], "phone": "13800138000"}
        _, _, exposure = self.run_object(wide, self.SELF, owner=wide)
        self.assertEqual(exposure[0]["verdict"], Verdict.INCONCLUSIVE.value)
        keyed = {"id": "1001", "contacts": {"alice.private@example.com": {"phone": "13700137000"}}}
        auditor, _, exposure = self.run_object(keyed, self.SELF, owner=keyed)
        self.assertEqual(exposure[0]["evidence"]["exposed_sensitive_paths"], ["contacts.*.phone"])
        self.assertNotIn("alice.private@example.com", json.dumps(auditor.results))

    def test_no_lead_without_two_valid_responses_or_on_public_operations(self):
        auditor = self.auditor({"GET /users/{id}": {"expected_visitor_access": "deny", "detect_sensitive_exposure": True}})
        _, transport = self.recorder(lambda m, u, d, i: _ok(self.OWNER) if i == "owner" else HTTPResult(
            status=403, body=json.dumps({"error": "Forbidden"})))
        auditor._http_request = transport
        auditor._audit_endpoint_bola(self.endpoint(auditor, "GET", "/users/{id}"))
        self.assertFalse([r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"])
        endpoint = dict(self.endpoint(auditor, "GET", "/users/{id}"), security=[], security_declared=True)
        auditor._detect_sensitive_property_exposure(
            endpoint, {"detect_sensitive_exposure": True}, _ok(self.OWNER), _ok(self.OWNER), None, None, {})
        self.assertFalse([r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"])
        # An unusable own-resource baseline cannot rule out shared values: a lead.
        auditor._detect_sensitive_property_exposure(
            self.endpoint(auditor, "GET", "/users/{id}"), {"expected_visitor_access": "deny"},
            _ok(self.OWNER), _ok(self.OWNER), HTTPResult(status=500, body="{}"), Verdict.CONFIRMED, {})
        lead = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertEqual(lead[0]["verdict"], Verdict.SUSPICIOUS.value)
        self.assertEqual(lead[0]["evidence"]["missing_evidence"], ["visitor_self_baseline"])

    def test_masks_placeholders_flags_and_scalar_lists(self):
        document = {"id": "1001", "phone": ["13800138000", "138****8000"], "email": "[REDACTED]",
                    "pin": True, "salary": None, "cvv": 0, "password": "n/a", "ssn": "xxx-xx-1234"}
        values, complete = APISentinelAuditor._extract_sensitive_values(document)
        self.assertTrue(complete)
        self.assertEqual(sorted(path for path, _ in values.values()), ["phone[0]"])


class ConfigurationSurfaceTests(unittest.TestCase):
    def test_schema_documents_the_post_and_role_contract(self):
        schema = json.loads((Path(__file__).resolve().parents[1] / "config.schema.json").read_text(encoding="utf-8"))
        bola = schema["definitions"]["bola_entry"]["properties"]
        self.assertEqual(bola["identity_bodies"]["required"], ["owner"])
        self.assertFalse(bola["identity_bodies"]["additionalProperties"])
        self.assertNotIn("boolean", bola["body"]["type"])
        roles = schema["properties"]["identities"]["properties"]["roles"]
        self.assertEqual(sorted(roles["propertyNames"]["not"]["enum"]), ["anonymous", "owner", "roles", "visitor"])


if __name__ == "__main__":
    unittest.main()
