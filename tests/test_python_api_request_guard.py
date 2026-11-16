"""The read-only request rules hold for the Python API, not only for the CLI.

The CLI validates the configuration before it builds an auditor. A program
that builds APISentinelAuditor directly skipped that step, so an identity
header such as X-HTTP-Method-Override: DELETE rode on every GET, and a role
body holding a GraphQL mutation was sent on the read-only POST role probe.

Two layers now apply the same rules as configuration validation
(core.scan_safety.method_override_risk and read_only_body_risk):

* the auditor refuses such identities when it is built (ValueError), and
* the transport refuses such a request before any connection is made, so a
  header or role body changed after construction is not sent either.

Every dynamic test talks to a loopback server in this process.
"""

from __future__ import annotations

import copy
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.auditor import APISentinelAuditor
from core.transport import HttpTransport

OVERRIDE = "X-HTTP-Method-Override"
OVERRIDE_HEADERS = ("x-http-method-override", "x-http-method", "x-method-override")


class _Api(BaseHTTPRequestHandler):
    """Records every request; the admin role sees the privileged settings, the viewer is refused."""

    seen: List[Dict[str, Optional[str]]] = []
    lock = threading.Lock()

    def log_message(self, *args: Any) -> None:
        pass

    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        auth = self.headers.get("Authorization")
        override = next((value for name, value in self.headers.items() if name.lower() in OVERRIDE_HEADERS), None)
        with self.lock:
            type(self).seen.append({"method": self.command, "path": self.path, "auth": auth,
                                    "override": override, "body": body})
        if not auth:
            status, document = 401, {"error": "Unauthorized"}
        elif "VIEWER" in auth:
            status, document = 403, {"error": "Forbidden"}
        else:
            status, document = 200, {"id": "1001", "signing_key": "sk-live-r3", "note": "n"}
        data = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _answer


def _operation(operation_id: str, parameters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"operationId": operation_id, "responses": {"200": {"description": "OK"}}}
    if parameters:
        operation["parameters"] = parameters
    return operation


SPEC = {
    "openapi": "3.0.3", "info": {"title": "Python API guard", "version": "1"}, "security": [{"bearer": []}],
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/users/{id}": {"get": _operation("getUser", [{"name": "id", "in": "path", "required": True,
                                                         "schema": {"type": "string"}}])},
        "/admin/settings": {"get": _operation("getAdminSettings")},
        "/reports/search": {"post": _operation("searchReports")},
    },
}
IDENTITIES: Dict[str, Any] = {
    "owner": {"id": "1001", "token": "Bearer OWNER_TOKEN_R3"},
    "visitor": {"id": "1002", "token": "Bearer VISITOR_TOKEN_R3"},
    "anonymous": {},
    "roles": {"admin": {"token": "Bearer ADMIN_TOKEN_R3", "role": "administrator"},
              "viewer": {"token": "Bearer VIEWER_TOKEN_R3", "role": "viewer"}},
}
BOLA = {
    "GET /admin/settings": {"required_role": "administrator", "private_data_paths": ["signing_key"]},
    "POST /reports/search": {"read_only": True, "body": {"q": "x"}, "required_role": "administrator",
                             "private_data_paths": ["signing_key"]},
}
# Requests a clean scan sends, by the identity whose token they carry.
CLEAN_COUNTS = {"OWNER": 3, "VISITOR": 4, "ANONYMOUS": 3, "ADMIN": 2, "VIEWER": 2}


def _who(auth: Optional[str]) -> str:
    return auth.split()[-1].split("_")[0] if auth else "ANONYMOUS"


def _changed(identities: Dict[str, Any], path: List[str], value: Any) -> Dict[str, Any]:
    changed = copy.deepcopy(identities)
    target = changed
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return changed


class _LoopbackCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.target = f"http://127.0.0.1:{cls.server.server_address[1]}"
        folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(folder.cleanup)
        cls.spec_path = Path(folder.name) / "spec.json"
        cls.spec_path.write_text(json.dumps(SPEC), encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        with _Api.lock:
            _Api.seen = []

    def auditor(self, identities: Dict[str, Any]) -> APISentinelAuditor:
        return APISentinelAuditor(str(self.spec_path), self.target, request_delay=0, max_workers=1,
                                  identities_config=copy.deepcopy(identities), bola_config=copy.deepcopy(BOLA))

    @staticmethod
    def run_scan(auditor: APISentinelAuditor) -> None:
        with redirect_stdout(io.StringIO()):
            auditor.run()

    def counts(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for item in _Api.seen:
            who = _who(item["auth"])
            result[who] = result.get(who, 0) + 1
        return result


class ConstructionTests(_LoopbackCase):
    """An auditor built from the Python API refuses what configuration validation refuses."""

    # Changed material, and configured text that the error must not repeat.
    REFUSED = {
        "owner header override": (["owner", "headers"], {OVERRIDE: "DELETE"}, ("DELETE",)),
        "visitor header override": (["visitor", "headers"], {"x-http-method-override": "patch"}, ("patch", "PATCH")),
        "anonymous header override": (["anonymous", "headers"], {"X-HTTP-Method": "DELETE"}, ("DELETE",)),
        "role header override": (["roles", "viewer", "headers"], {"X-Method-Override": "PUT"}, ("PUT",)),
        "role header override to POST": (["roles", "admin", "headers"], {OVERRIDE: "POST"}, ("POST",)),
        "role body GraphQL mutation": (["roles", "viewer", "body"], {"query": "mutation { resetAll { ok } }"},
                                       ("resetAll", "query")),
        "role body upsert flag": (["roles", "viewer", "body"], {"q": "x", "upsert": True}, ("upsert",)),
        "role body method override": (["roles", "admin", "body"], {"_method": "DELETE"}, ("_method",)),
    }

    def test_writing_identity_material_is_refused_before_any_request(self):
        for name, (path, value, not_echoed) in self.REFUSED.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as caught:
                    self.auditor(_changed(IDENTITIES, path, value))
                message = str(caught.exception)
                for text in (*not_echoed, "TOKEN"):
                    self.assertNotIn(text, message)
                self.assertEqual(_Api.seen, [])

    def test_read_only_identity_material_is_accepted(self):
        identities = _changed(IDENTITIES, ["visitor", "headers"], {OVERRIDE: "GET", "X-Tenant": "t-2"})
        identities = _changed(identities, ["owner", "headers"], {"X-HTTP-Method-Override": "HEAD", "X-Tenant": "t-1"})
        identities = _changed(identities, ["roles", "viewer", "body"], {"q": "reports", "filter": {"create_by": 1}})
        auditor = self.auditor(identities)
        self.run_scan(auditor)
        self.assertEqual(self.counts(), CLEAN_COUNTS)


class SendTimeTests(_LoopbackCase):
    """Identity material changed after construction is refused by the transport, per identity."""

    def scan_with_late_change(self, path: List[str], value: Any) -> APISentinelAuditor:
        auditor = self.auditor(IDENTITIES)
        target: Any = auditor.identities
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        self.run_scan(auditor)
        return auditor

    def test_clean_scan_request_counts_are_unchanged(self):
        auditor = self.auditor(IDENTITIES)
        self.run_scan(auditor)
        self.assertEqual(self.counts(), CLEAN_COUNTS)
        self.assertEqual(auditor.stats["transport_attempts"], sum(CLEAN_COUNTS.values()))
        self.assertTrue(all(item["override"] is None for item in _Api.seen))

    def test_a_late_header_override_blocks_only_that_identity_before_transmission(self):
        for identity, path, header in (
                ("OWNER", ["owner", "headers"], {OVERRIDE: "DELETE"}),
                ("VISITOR", ["visitor", "headers"], {"X-HTTP-Method": "PATCH"}),
                ("ANONYMOUS", ["anonymous", "headers"], {"X-Method-Override": "DELETE"}),
                ("VIEWER", ["roles", "viewer", "headers"], {OVERRIDE: "PUT"})):
            with self.subTest(identity=identity):
                with _Api.lock:
                    _Api.seen = []
                auditor = self.scan_with_late_change(path, header)
                counts = self.counts()
                # Nothing with an override reaches the server; the changed identity sends nothing.
                self.assertTrue(all(item["override"] is None for item in _Api.seen))
                self.assertEqual(counts.get(identity, 0), 0)
                # The other identities still send, each with its own credential only. When an
                # Owner, Visitor or Anonymous observation fails, the object check ends with
                # ERROR and skips its role probes, so their counts can only go down.
                others = {who: count for who, count in counts.items() if who != identity}
                self.assertTrue(others)
                for who, count in others.items():
                    self.assertLessEqual(count, CLEAN_COUNTS[who])
                if identity == "VIEWER":
                    self.assertEqual(others, {who: n for who, n in CLEAN_COUNTS.items() if who != identity})
                self.assertEqual(auditor.stats["transport_attempts"], len(_Api.seen))
                self.assertGreater(auditor.stats["error_count"], 0)
                refusals = [item["reason"] for item in auditor.results if "overrides the HTTP method" in item["reason"]]
                self.assertTrue(refusals)
                for reason in refusals:
                    self.assertNotIn(next(iter(header.values())), reason)

    def test_a_late_writing_role_body_is_not_sent(self):
        for body in ({"query": "mutation { resetAll { ok } }"}, {"q": "x", "upsert": True}):
            with self.subTest(body=body):
                with _Api.lock:
                    _Api.seen = []
                auditor = self.scan_with_late_change(["roles", "viewer", "body"], body)
                self.assertFalse(any("resetAll" in item["body"] or "upsert" in item["body"] for item in _Api.seen))
                posts = [item for item in _Api.seen if item["method"] == "POST"]
                self.assertEqual(sorted(_who(item["auth"]) for item in posts),
                                 ["ADMIN", "ANONYMOUS", "OWNER", "VISITOR"])
                viewer_get = [item for item in _Api.seen if _who(item["auth"]) == "VIEWER"]
                self.assertEqual([item["method"] for item in viewer_get], ["GET"])
                record = next(item for item in auditor.results
                              if item["check"] == "RBAC" and item["endpoint"] == "POST /reports/search"
                              and item["evidence"].get("rbac_role") == "viewer")
                self.assertEqual(record["verdict"], "ERROR")
                self.assertIn("no request was sent", record["reason"])
                self.assertNotIn("resetAll", record["reason"])
                self.assertEqual(auditor.stats["transport_attempts"], len(_Api.seen))


class SpecificationHeaderTests(_LoopbackCase):
    """A method override can also come from the specification, not only from an identity."""

    def test_a_declared_header_parameter_that_overrides_the_method_is_not_sent(self):
        header = {"name": OVERRIDE, "in": "header", "schema": {"type": "string", "default": "DELETE"}}
        spec = json.loads(json.dumps(SPEC))
        spec["paths"]["/users/{id}"]["get"]["parameters"].append(header)
        spec_path = Path(self.spec_path).with_name("override-spec.json")
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        auditor = APISentinelAuditor(str(spec_path), self.target, request_delay=0, max_workers=1,
                                     identities_config=copy.deepcopy(IDENTITIES), bola_config=copy.deepcopy(BOLA))
        self.run_scan(auditor)
        self.assertFalse(any(item["path"].startswith("/users/") for item in _Api.seen))
        self.assertTrue(all(item["override"] is None for item in _Api.seen))
        result = next(item for item in auditor.results if item["endpoint"] == "GET /users/{id}")
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("overrides the HTTP method", result["reason"])


class TransportTests(_LoopbackCase):
    """HttpTransport.send applies the rules itself, before the connection opens."""

    def send(self, method: str, headers: Dict[str, str], data: Any = None):
        transport = HttpTransport(request_delay=0, request_timeout=2, max_response_bytes=4096, insecure_ssl=False)
        attempts: List[int] = []
        result = transport.send(method, self.target + "/users/1001", headers, data,
                                on_attempt=lambda: attempts.append(1))
        return result, attempts

    def test_method_overrides_and_writing_post_bodies_never_leave(self):
        for method, headers, data in (
                ("GET", {OVERRIDE: "DELETE"}, None),
                ("GET", {"x-http-method": "Put"}, None),
                ("POST", {"authorization": "Bearer OWNER_TOKEN_R3"}, {"query": "mutation { a { b } }"}),
                ("POST", {}, [{"op": "replace", "path": "/role", "value": "admin"}]),
                ("PATCH", {"x-method-override": "DELETE"}, {"nickname": "x"})):
            with self.subTest(method=method, headers=headers):
                with _Api.lock:
                    _Api.seen = []
                result, attempts = self.send(method, headers, data)
                self.assertEqual((result.status, result.body), (0, ""))
                self.assertIn("no request was sent", result.error)
                self.assertEqual(attempts, [])
                self.assertEqual(_Api.seen, [])

    def test_query_write_switches_never_leave_on_read_requests(self):
        transport = HttpTransport(request_delay=0, request_timeout=2, max_response_bytes=4096, insecure_ssl=False)
        for method, query in (("GET", "?upsert=true"), ("HEAD", "?_method=DELETE"), ("POST", "?dry_run=false")):
            with self.subTest(method=method, query=query):
                with _Api.lock:
                    _Api.seen = []
                attempts: List[int] = []
                result = transport.send(method, self.target + "/users/1001" + query, {}, {"q": "x"} if method == "POST"
                                        else None, on_attempt=lambda: attempts.append(1))
                self.assertEqual((result.status, attempts, _Api.seen), (0, [], []))
                self.assertIn("no request was sent", result.error)
        # Ordinary query data is sent; PATCH and PUT are the gated writes and keep their query.
        for method, query in (("GET", "?page=2&include_deleted=true"), ("PATCH", "?upsert=true")):
            with self.subTest(method=method, query=query):
                with _Api.lock:
                    _Api.seen = []
                result = transport.send(method, self.target + "/users/1001" + query, {},
                                        {"nickname": "x"} if method == "PATCH" else None)
                self.assertIsNone(result.error)
                self.assertEqual(len(_Api.seen), 1)

    def test_a_check_that_cannot_run_fails_closed_without_raising(self):
        transport = HttpTransport(request_delay=0, request_timeout=2, max_response_bytes=4096, insecure_ssl=False)
        attempts: List[int] = []
        result = transport.send("GET", self.target + "/users/1001", None,  # type: ignore[arg-type]
                                on_attempt=lambda: attempts.append(1))
        self.assertEqual((result.status, attempts, _Api.seen), (0, [], []))
        self.assertIsNotNone(result.error)

    def test_ordinary_requests_are_sent(self):
        for method, headers, data in (
                ("GET", {"authorization": "Bearer OWNER_TOKEN_R3", OVERRIDE: "GET"}, None),
                ("GET", {"x-tenant": "t-1"}, None),
                ("POST", {"authorization": "Bearer OWNER_TOKEN_R3"}, {"q": "x", "filter": {"delete_flag": 1}}),
                ("PATCH", {"authorization": "Bearer OWNER_TOKEN_R3"}, {"upsert": True})):
            with self.subTest(method=method, headers=headers):
                with _Api.lock:
                    _Api.seen = []
                result, attempts = self.send(method, headers, data)
                self.assertIsNone(result.error)
                self.assertEqual(attempts, [1])
                self.assertEqual(len(_Api.seen), 1)


if __name__ == "__main__":
    unittest.main()
