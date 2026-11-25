"""P0-01 follow-up: one HTTP method spelling, an always-on base policy and an additive request guard.

IR-01  A method is checked and sent in exactly one spelling. "GET " or " GET" was neither
       recognised as a read by the safety checks nor rejected by http.client, and a server
       that splits the request line on whitespace (RFC 9112 section 3) routes it as GET.
IR-02  HttpTransport(request_guard=...) replaced the base concrete-request policy, so any
       custom guard (even an additive one) switched the base policy off.
IR-03  The transport backstop depended on overridable auditor methods (_request_risk,
       _read_request_risk, _relative_request_path).

Every network check uses a loopback server that records each parsed request line, including
methods the server does not implement. Nothing here contacts a host other than 127.0.0.1.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

import core.scan_safety as scan_safety
from core.auditor import APISentinelAuditor
from core.transport import HttpTransport

DANGEROUS = "/reports/withdraw"
BENIGN = "/reports/summary"

# Spellings that are not exactly one RFC 9110 method token.
INVALID_METHODS: Tuple[Any, ...] = (
    "GET ", " GET", "HEAD ", "POST ", "GET  ", "\tGET", "GET\x0b", "G ET", "", "GET ",
    "ＧＥＴ", "GET\r\nX-Injected: 1", "GET/1", "GE(T", None, b"GET", 7,
)


class _Recorder:
    """A 127.0.0.1 server that records every parsed request line, known method or not."""

    def __init__(self) -> None:
        self.lines: List[Tuple[str, str]] = []
        self.lock = threading.Lock()
        self.rate_limited: Dict[str, int] = {}
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def parse_request(self) -> bool:
                parsed = super().parse_request()
                if parsed:
                    with recorder.lock:
                        recorder.lines.append((self.command, self.path))
                return parsed

            def reply(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                path = urlsplit(self.path).path
                with recorder.lock:
                    remaining = recorder.rate_limited.get(path, 0)
                    if remaining:
                        recorder.rate_limited[path] = remaining - 1
                if remaining:
                    self.send_response(429)
                    self.send_header("Retry-After", "0")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps({"id": "1001", "owner": "alice"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_HEAD = do_POST = do_PATCH = do_PUT = do_DELETE = reply

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.httpd.server_port}"

    def clear(self) -> None:
        with self.lock:
            self.lines.clear()
            self.rate_limited.clear()

    def snapshot(self) -> List[Tuple[str, str]]:
        with self.lock:
            return list(self.lines)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def _write_spec(folder: Path, paths: Dict[str, Any]) -> str:
    spec = {"openapi": "3.0.3", "info": {"title": "boundary", "version": "1"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "paths": paths}
    target = folder / f"spec{len(list(folder.iterdir()))}.json"
    target.write_text(json.dumps(spec), encoding="utf-8")
    return str(target)


def _get(path_params: Tuple[str, ...] = ("kind",), summary: str = "Read one report") -> Dict[str, Any]:
    return {"get": {"operationId": "readReport", "summary": summary, "security": [{"bearer": []}],
                    "parameters": [{"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
                                   for name in path_params],
                    "responses": {"200": {"description": "ok"}}}}


IDENTITIES = {
    "owner": {"id": "1001", "token": "Bearer BOUNDARY-OWNER", "parameters": {}},
    "visitor": {"id": "1002", "token": "Bearer BOUNDARY-VISITOR", "parameters": {}},
    "anonymous": {"id": None, "token": None, "parameters": {}},
}


def _transport(**options: Any) -> HttpTransport:
    return HttpTransport(request_delay=0.0, request_timeout=3.0, max_response_bytes=4096, insecure_ssl=False,
                         **options)


class _LoopbackCase(unittest.TestCase):
    server: _Recorder

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _Recorder()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.close()

    def setUp(self) -> None:
        self.server.clear()
        folder = tempfile.TemporaryDirectory(prefix="granttrace-boundary-")
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def auditor(self, cls: type = APISentinelAuditor, paths: Optional[Dict[str, Any]] = None,
                prefix: str = "") -> APISentinelAuditor:
        spec = _write_spec(self.folder, paths or {"/reports/{kind}": _get()})
        return cls(spec, self.server.origin + prefix, request_delay=0, identities_config=IDENTITIES)


# ---------------------------------------------------------------------------
# IR-01: one method spelling for the checks and for the wire
# ---------------------------------------------------------------------------

class MethodTokenTests(unittest.TestCase):
    def test_valid_tokens_have_one_upper_case_spelling(self) -> None:
        canonical = getattr(scan_safety, "canonical_http_method", None)
        self.assertIsNotNone(canonical, "core.scan_safety must provide canonical_http_method")
        for method, expected in (("GET", "GET"), ("get", "GET"), ("Head", "HEAD"), ("POST", "POST"),
                                 ("patch", "PATCH"), ("PUT", "PUT"), ("DELETE", "DELETE"),
                                 ("PROPFIND", "PROPFIND"), ("M-SEARCH", "M-SEARCH"), ("x.y_z~1", "X.Y_Z~1")):
            with self.subTest(method=method):
                self.assertEqual(canonical(method), expected)

    def test_anything_but_one_token_is_rejected(self) -> None:
        canonical = getattr(scan_safety, "canonical_http_method", None)
        invalid = getattr(scan_safety, "InvalidHttpMethod", None)
        self.assertIsNotNone(canonical)
        self.assertIsNotNone(invalid)
        self.assertTrue(issubclass(invalid, ValueError))
        for method in INVALID_METHODS:
            with self.subTest(method=method):
                with self.assertRaises(invalid):
                    canonical(method)

    def test_every_risk_helper_refuses_an_invalid_method(self) -> None:
        url = "http://127.0.0.1:9/reports/summary"
        for method in INVALID_METHODS:
            with self.subTest(method=method):
                for risk in (scan_safety.concrete_path_risk(method, BENIGN),
                             scan_safety.concrete_request_risk(method, url),
                             scan_safety.read_only_risk({"method": method, "path": BENIGN})):
                    self.assertIsNotNone(risk)
                    self.assertEqual(risk["safety_signal"], "method")
                    self.assertIn("no request was sent", risk["safety_reason"])

    def test_valid_methods_keep_their_decisions(self) -> None:
        url = "http://127.0.0.1:9"
        for method in ("get", "GET", "head", "HEAD"):
            with self.subTest(method=method):
                self.assertIsNone(scan_safety.concrete_request_risk(method, url + BENIGN))
                self.assertEqual(scan_safety.concrete_request_risk(method, url + DANGEROUS)["safety_signal"], "path")
        # Writes and other non-read methods stay with their callers' gates (unchanged).
        for method in ("PATCH", "put", "DELETE", "PROPFIND"):
            with self.subTest(method=method):
                self.assertIsNone(scan_safety.concrete_request_risk(method, url + DANGEROUS))
                self.assertIsNone(scan_safety.concrete_path_risk(method, DANGEROUS))


class MethodSpellingEntryPointTests(_LoopbackCase):
    """No entry point may send a method spelling that the checks did not see."""

    def entry_points(self) -> List[Tuple[str, Callable[[Any, str], Any], APISentinelAuditor]]:
        auditor = self.auditor()
        standalone = _transport()
        headers = auditor.identity_headers("owner")
        return [
            ("_http_request", lambda m, u: auditor._http_request(m, u, identity_name="owner"), auditor),
            ("_send_http_request",
             lambda m, u: auditor._send_http_request(m, u, None, "owner", "application/json", None), auditor),
            ("auditor._transport.send", lambda m, u: auditor._transport.send(m, u, headers), auditor),
            ("HttpTransport.send", lambda m, u: standalone.send(m, u, headers), auditor),
        ]

    def test_invalid_method_spellings_never_reach_the_server(self) -> None:
        for name, send, auditor in self.entry_points():
            for method in INVALID_METHODS:
                for path in (DANGEROUS, BENIGN):
                    with self.subTest(entry=name, method=method, path=path):
                        self.server.clear()
                        sent_before = auditor.stats["http_requests_sent"]
                        result = send(method, self.server.origin + path)
                        self.assertEqual(self.server.snapshot(), [], "a request line reached the server")
                        self.assertEqual(result.status, 0)
                        self.assertIn("no request was sent", result.error or "")
                        self.assertEqual(auditor.stats["http_requests_sent"], sent_before)

    def test_invalid_method_is_refused_before_any_attempt_is_counted(self) -> None:
        attempts: List[str] = []
        for method in ("GET ", " HEAD", "", None):
            with self.subTest(method=method):
                result = _transport().send(method, self.server.origin + BENIGN, {},  # type: ignore[arg-type]
                                           on_attempt=lambda: attempts.append("attempt"))
                self.assertEqual(result.status, 0)
        self.assertEqual(attempts, [])
        self.assertEqual(self.server.snapshot(), [])

    def test_the_checked_method_is_the_method_on_the_wire(self) -> None:
        seen: List[Tuple[str, str]] = []

        def guard(method: str, url: str) -> None:
            seen.append((method, urlsplit(url).path))
            return None

        transport = _transport(request_guard=guard)
        for method in ("get", "Get", "GET", "head", "post"):
            with self.subTest(method=method):
                self.server.clear()
                path = "/reports/search" if method == "post" else BENIGN
                result = transport.send(method, self.server.origin + path, {},
                                        data={"q": 1} if method == "post" else None)
                self.assertEqual(result.status, 200)
                self.assertEqual(self.server.snapshot(), [(method.upper(), path)])
                self.assertEqual(seen[-1], (method.upper(), path))
        auditor = self.auditor()
        self.server.clear()
        self.assertEqual(auditor._http_request("get", self.server.origin + BENIGN, identity_name="owner").status, 200)
        self.assertEqual(self.server.snapshot(), [("GET", BENIGN)])

    def test_lower_case_read_is_still_checked_as_a_read(self) -> None:
        auditor = self.auditor()
        for method in ("get", "Get", "head"):
            with self.subTest(method=method):
                self.server.clear()
                self.assertEqual(auditor._http_request(method, self.server.origin + DANGEROUS,
                                                       identity_name="owner").status, 0)
                self.assertEqual(_transport().send(method, self.server.origin + DANGEROUS, {}).status, 0)
                self.assertEqual(self.server.snapshot(), [])

    def test_auditor_risk_methods_refuse_invalid_spellings(self) -> None:
        auditor = self.auditor()
        for method in INVALID_METHODS:
            with self.subTest(method=method):
                for risk in (auditor._request_risk(method, self.server.origin + BENIGN),
                             auditor._read_request_risk(method, self.server.origin + BENIGN)):
                    self.assertIsNotNone(risk)
                    self.assertEqual(risk["safety_signal"], "method")

    def test_normal_methods_keep_their_behaviour(self) -> None:
        transport = _transport()
        for method, data in (("GET", None), ("HEAD", None), ("PATCH", {"a": 1}), ("PUT", {"a": 1}),
                             ("DELETE", None), ("POST", {"q": 1})):
            with self.subTest(method=method):
                self.server.clear()
                path = "/reports/search" if method == "POST" else "/reports/1001"
                result = transport.send(method, self.server.origin + path, {}, data=data)
                self.assertEqual(result.status, 200)
                self.assertEqual(self.server.snapshot(), [(method, path)])

    def test_rate_limit_retry_uses_the_canonical_read_method(self) -> None:
        auditor = self.auditor()
        self.server.rate_limited[BENIGN] = 2
        result = auditor._http_request("get", self.server.origin + BENIGN, identity_name="owner")
        self.assertEqual(result.status, 200)
        self.assertEqual(self.server.snapshot(), [("GET", BENIGN)] * 3)
        self.assertEqual(auditor.stats["http_requests_sent"], 3)
        self.assertEqual(auditor.stats["transport_attempts"], 3)
        self.assertEqual(auditor.stats["rate_limit_retries"], 2)

    def test_specification_methods_are_canonical_tokens(self) -> None:
        # Operations come only from the fixed OpenAPI method keys; odd keys are not operations.
        auditor = self.auditor(paths={
            "/reports/{kind}": {**_get(), "get ": _get()["get"], "GET": _get()["get"], "Get": _get()["get"]},
        })
        methods = [endpoint["method"] for endpoint in auditor.parser.get_endpoints()]
        self.assertEqual(methods, ["GET"])
        for method in methods:
            self.assertEqual(scan_safety.canonical_http_method(method), method)


# ---------------------------------------------------------------------------
# IR-02: a custom guard can only add refusals
# ---------------------------------------------------------------------------

def _raise(*_: Any) -> None:
    raise RuntimeError("guard failure")


PERMISSIVE_GUARDS: Tuple[Tuple[str, Callable[[str, str], Any]], ...] = (
    ("returns None", lambda m, u: None),
    ("adds an /admin rule only", lambda m, u: {"safety_reason": "admin is off limits"} if "/admin" in u else None),
)
MALFORMED_GUARDS: Tuple[Tuple[str, Callable[[str, str], Any]], ...] = (
    ("returns {}", lambda m, u: {}),
    ("mapping without safety_reason", lambda m, u: {"safety_signal": "x"}),
    ("empty safety_reason", lambda m, u: {"safety_reason": ""}),
    ("non-string safety_reason", lambda m, u: {"safety_reason": 5}),
    ("returns a string", lambda m, u: "deny"),
    ("returns a list of pairs", lambda m, u: [("safety_reason", "x")]),
    ("returns True", lambda m, u: True),
    ("returns False", lambda m, u: False),
    ("returns 0", lambda m, u: 0),
    ("raises", _raise),
)


class GuardContractTests(_LoopbackCase):
    def test_no_guard_can_allow_what_the_base_policy_refuses(self) -> None:
        for name, guard in PERMISSIVE_GUARDS + MALFORMED_GUARDS:
            for method in ("GET", "HEAD", "POST"):
                with self.subTest(guard=name, method=method):
                    self.server.clear()
                    result = _transport(request_guard=guard).send(
                        method, self.server.origin + DANGEROUS, {}, data={"q": 1} if method == "POST" else None)
                    self.assertEqual(result.status, 0)
                    self.assertEqual(self.server.snapshot(), [])

    def test_a_guard_assigned_after_construction_cannot_allow_either(self) -> None:
        transport = _transport()
        transport.request_guard = lambda m, u: None
        self.assertEqual(transport.send("GET", self.server.origin + DANGEROUS, {}).status, 0)
        transport.request_guard = None
        self.assertEqual(transport.send("GET", self.server.origin + DANGEROUS, {}).status, 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_a_guard_can_add_refusals(self) -> None:
        transport = _transport(request_guard=PERMISSIVE_GUARDS[1][1])
        refused = transport.send("GET", self.server.origin + "/admin/users", {})
        self.assertEqual(refused.status, 0)
        self.assertEqual(refused.error, "admin is off limits")
        self.assertEqual(transport.send("GET", self.server.origin + BENIGN, {}).status, 200)
        self.assertEqual(self.server.snapshot(), [("GET", BENIGN)])

    def test_malformed_guard_decisions_fail_closed(self) -> None:
        for name, guard in MALFORMED_GUARDS:
            with self.subTest(guard=name):
                self.server.clear()
                result = _transport(request_guard=guard).send("GET", self.server.origin + BENIGN, {})
                self.assertEqual(result.status, 0)
                self.assertIn("no request was sent", result.error or "")
                self.assertEqual(self.server.snapshot(), [])

    def test_transport_refusals_always_include_the_base_policy(self) -> None:
        # Not a list of known samples: every path the base policy refuses stays refused under
        # any permissive guard, and every path it allows stays allowed under a no-op guard.
        values = ["summary", "1001", "created", "history", "a/b", "x;y", "report.v1", "deleted-items"]
        for verb in ("create", "update", "delete", "remove", "cancel", "reset", "revoke", "submit", "publish",
                     "transfer", "withdraw", "import", "upload", "schedule", "start", "stop", "execute"):
            values += [verb, verb.upper(), verb + "All", verb + "-x", "x;" + verb, "x/" + verb, verb + ".json"]
        base_url = "http://127.0.0.1:9/api"
        for name, guard in PERMISSIVE_GUARDS:
            transport = _transport(request_guard=guard)
            for value in values:
                for method in ("GET", "HEAD", "POST"):
                    url = base_url + "/reports/" + quote(value, safe="")
                    with self.subTest(guard=name, value=value, method=method):
                        base = scan_safety.concrete_request_risk(method, url)
                        refusal = transport.read_policy_refusal(method, url)
                        if base is not None:
                            self.assertEqual(refusal, base["safety_reason"])
                        elif name == "returns None":
                            self.assertIsNone(refusal)

    def test_guard_receives_the_canonical_method_and_url(self) -> None:
        calls: List[Tuple[str, str]] = []
        transport = _transport(request_guard=lambda m, u: calls.append((m, u)))
        transport.send("head", f"  <URL:{self.server.origin}{BENIGN}>  ", {})
        self.assertEqual(calls, [("HEAD", self.server.origin + BENIGN)])


# ---------------------------------------------------------------------------
# IR-03: the base policy does not depend on overridable auditor methods
# ---------------------------------------------------------------------------

class _SkipPrecheck(APISentinelAuditor):
    def _http_request(self, method, url, data=None, identity_name="anonymous",  # type: ignore[no-untyped-def]
                      content_type="application/json", headers=None):
        return self._send_http_request(method, url, data, identity_name, content_type, headers)


class _NoRequestRisk(_SkipPrecheck):
    def _request_risk(self, method, url):  # type: ignore[no-untyped-def]
        return None


class _NoReadRisk(_SkipPrecheck):
    def _read_request_risk(self, method, url):  # type: ignore[no-untyped-def]
        return None


class _RewritesPaths(_SkipPrecheck):
    def _relative_request_path(self, url):  # type: ignore[no-untyped-def]
        return "/"


class _NoTransportGuard(_SkipPrecheck):
    def _transport_request_risk(self, method, url):  # type: ignore[no-untyped-def]
        return None


class _RaisingRisk(_SkipPrecheck):
    def _request_risk(self, method, url):  # type: ignore[no-untyped-def]
        raise RuntimeError("policy bug")


class TransportBaseIndependenceTests(_LoopbackCase):
    def test_overriding_auditor_policy_methods_cannot_switch_off_the_base_policy(self) -> None:
        for cls in (_NoRequestRisk, _NoReadRisk, _RewritesPaths, _NoTransportGuard, _RaisingRisk):
            for prefix in ("", "/api/v1"):
                with self.subTest(subclass=cls.__name__, prefix=prefix):
                    self.server.clear()
                    auditor = self.auditor(cls, prefix=prefix)
                    for method in ("GET", "HEAD"):
                        result = auditor._http_request(method, self.server.origin + prefix + DANGEROUS,
                                                       identity_name="owner")
                        self.assertEqual(result.status, 0)
                    self.assertEqual(self.server.snapshot(), [])
                    self.assertEqual(auditor.stats["http_requests_sent"], 0)
                    self.assertEqual(auditor.stats["transport_attempts"], 0)

    def test_removing_or_replacing_the_auditor_guard_keeps_the_base_policy(self) -> None:
        auditor = self.auditor()
        auditor._transport.request_guard = None
        self.assertEqual(auditor._send_http_request("GET", self.server.origin + DANGEROUS, None, "owner",
                                                    "application/json", None).status, 0)
        auditor._transport.request_guard = lambda m, u: None
        self.assertEqual(auditor._transport.send("GET", self.server.origin + DANGEROUS, {}).status, 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_the_transport_knows_the_operator_base_url(self) -> None:
        auditor = self.auditor(prefix="/deposit-gw/api")
        self.assertEqual(getattr(auditor._transport, "base_url", None), auditor.target_base_url)
        # The configured base is operator configuration, not checked as data; what follows it is.
        self.assertEqual(auditor._transport.send("GET", auditor.target_base_url + BENIGN, {}).status, 200)
        self.assertEqual(auditor._transport.send("GET", auditor.target_base_url + DANGEROUS, {}).status, 0)
        # A transport without that base checks the whole path and is stricter.
        self.assertEqual(_transport().send("GET", auditor.target_base_url + BENIGN, {}).status, 0)
        self.assertEqual(self.server.snapshot(), [("GET", "/deposit-gw/api" + BENIGN)])

    def test_the_template_metadata_layer_still_refuses_through_the_transport(self) -> None:
        # Specification metadata is the auditor's additive layer: with the default guard it
        # refuses even when an override skips the pre-check.
        paths = {"/jobs/{id}": _get(("id",), summary="This endpoint will delete the job")}
        auditor = self.auditor(_SkipPrecheck, paths=paths)
        self.assertEqual(auditor._http_request("GET", self.server.origin + "/jobs/1001", identity_name="owner").status, 0)
        self.assertEqual(self.server.snapshot(), [])


if __name__ == "__main__":
    unittest.main()
