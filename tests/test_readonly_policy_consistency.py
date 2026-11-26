"""Read-only policy consistency on main after the P0-01 migration (third-round review follow-up).

R3-13  ``read_policy_refusal`` raised instead of refusing when a guard returned a mapping whose
       ``get`` raises, or a ``safety_reason`` that is a ``str`` subclass whose ``strip`` raises.
R3-10  The transport checked the caller's Python objects instead of the request urllib sends: a
       tuple in a read-only POST body travels as the JSON array the body rules refuse, and a
       wrapped ``<URL:...>`` query was caught only by the later base policy. Each layer must hold
       on its own, on the wire object.
RR-02  A case-insensitive router (ASP.NET Core and .NET ``OrdinalIgnoreCase``, Express or Spring
       with case-insensitive matching) routes ``wItHdRaW``, ``wıthdraw`` (dotless i) or ``SUBMİT``
       to the action; the concrete path check read them as unrelated words.
RR-01  A ``name=value`` pair in a path piece (matrix ``;action=delete``, an exploded object) is the
       same data channel as a query parameter but did not get the query string's write-switch
       rules. Values in data positions stay data, exactly as in a query string.
OVR    Method-override values in a query string or body were refused only for PUT, PATCH and
       DELETE. Frameworks that honour ``_method`` (Rack, Express method-override, Symfony) accept
       other state-changing methods too (PURGE, LINK, MOVE, COPY, LOCK, MKCOL...).
R3-03  An affirmative operation clause that starts with a manner adverb ("Permanently deletes
       the job") was not recognised as naming a write.
REF    A policy refusal is structured (safety_reason, safety_signal, policy_layer) on HTTPResult
       and in the report record, and a network failure is distinguishable from it. A check that
       had a request refused while it ran never concludes SECURE, PUBLIC or AUTHORIZED. Main's
       report semantics are kept: such a check ends as ERROR (test_python_api_request_guard).

Network checks use a loopback server that records every request it parses. Nothing here
contacts a host other than 127.0.0.1.
"""

from __future__ import annotations

import collections.abc as abc
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

import core.scan_safety as scan_safety
import core.transport as transport_module
from core.auditor import APISentinelAuditor
from core.models import HTTPResult, Verdict
from core.transport import HttpTransport

UNCHECKED = "Read-only safety policy could not check the request; no request was sent"


class _Recorder:
    """A 127.0.0.1 server that records the method, target and body of every parsed request."""

    def __init__(self) -> None:
        self.requests: List[Tuple[str, str, bytes]] = []
        self.lock = threading.Lock()
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def reply(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with recorder.lock:
                    recorder.requests.append((self.command, self.path, body))
                payload = json.dumps({"id": "1001", "owner": "alice"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = do_HEAD = do_POST = do_PATCH = do_PUT = do_DELETE = reply

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.httpd.server_port}"

    def clear(self) -> None:
        with self.lock:
            self.requests.clear()

    def snapshot(self) -> List[Tuple[str, str, bytes]]:
        with self.lock:
            return list(self.requests)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


IDENTITIES = {
    "owner": {"id": "1001", "token": "Bearer CONSISTENCY-OWNER-TOKEN", "parameters": {}},
    "visitor": {"id": "1002", "token": "Bearer CONSISTENCY-VISITOR-TOKEN", "parameters": {}},
    "anonymous": {"id": None, "token": None, "parameters": {}},
}


def _transport(**options: Any) -> HttpTransport:
    return HttpTransport(request_delay=0.0, request_timeout=3.0, max_response_bytes=4096, insecure_ssl=False,
                         **options)


def _get(summary: str = "Read one report", enum: Optional[List[str]] = None) -> Dict[str, Any]:
    schema: Dict[str, Any] = {"type": "string"}
    if enum is not None:
        schema["enum"] = enum
    return {"get": {"operationId": "readReport", "summary": summary, "security": [{"bearer": []}],
                    "parameters": [{"name": "kind", "in": "path", "required": True, "schema": schema}],
                    "responses": {"200": {"description": "ok"}}}}


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
        folder = tempfile.TemporaryDirectory(prefix="granttrace-consistency-")
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def auditor(self, paths: Dict[str, Any], cls: type = APISentinelAuditor) -> APISentinelAuditor:
        spec = {"openapi": "3.0.3", "info": {"title": "consistency", "version": "1"},
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                "paths": paths}
        target = self.folder / f"spec{len(list(self.folder.iterdir()))}.json"
        target.write_text(json.dumps(spec), encoding="utf-8")
        return cls(str(target), self.server.origin, request_delay=0, identities_config=IDENTITIES)


class _BrokenMapping(abc.Mapping):
    """A decision mapping whose every lookup raises."""

    def __getitem__(self, key: str) -> str:
        raise RuntimeError("broken mapping")

    def __iter__(self):  # noqa: ANN204
        return iter(())

    def __len__(self) -> int:
        return 1

    def get(self, key: str, default: Any = None) -> Any:
        raise RuntimeError("broken get")


class _HostileReason(str):
    """A refusal reason whose own string methods raise or lie."""

    def strip(self, *args: Any) -> str:  # type: ignore[override]
        raise RuntimeError("broken strip")

    def __str__(self) -> str:
        return ""


# ---------------------------------------------------------------------------
# R3-13: a malformed refusal decision refuses; it never raises
# ---------------------------------------------------------------------------

class RefusalDecisionTotalityTests(_LoopbackCase):
    def test_guard_mapping_whose_get_raises_refuses(self) -> None:
        transport = _transport(request_guard=lambda method, url: _BrokenMapping())
        self.assertEqual(transport.read_policy_refusal("GET", self.server.origin + "/reports/summary"), UNCHECKED)
        attempts: List[int] = []
        result = transport.send("GET", self.server.origin + "/reports/summary", {},
                                on_attempt=lambda: attempts.append(1))
        self.assertEqual((result.status, result.error), (0, UNCHECKED))
        self.assertEqual((attempts, self.server.snapshot()), ([], []))

    def test_reason_whose_strip_raises_refuses_with_the_generic_reason(self) -> None:
        transport = _transport(request_guard=lambda method, url: {"safety_reason": _HostileReason("blocked")})
        reason = transport.read_policy_refusal("GET", self.server.origin + "/reports/summary")
        self.assertEqual(type(reason), str)
        self.assertTrue(reason)
        self.assertEqual(transport.send("GET", self.server.origin + "/reports/summary", {}).status, 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_a_usable_str_subclass_reason_is_returned_as_a_plain_str(self) -> None:
        class Reason(str):
            pass

        transport = _transport(request_guard=lambda method, url: {"safety_reason": Reason("Guard said no")})
        reason = transport.read_policy_refusal("GET", self.server.origin + "/reports/summary")
        self.assertEqual((type(reason), reason), (str, "Guard said no"))

    def test_malformed_base_decision_refuses(self) -> None:
        transport = _transport()
        with patch.object(transport_module, "concrete_request_risk", lambda *args: _BrokenMapping()):
            self.assertEqual(transport.read_policy_refusal("GET", self.server.origin + "/reports/summary"),
                             UNCHECKED)
            self.assertEqual(transport.send("GET", self.server.origin + "/reports/summary", {}).error, UNCHECKED)
        self.assertEqual(self.server.snapshot(), [])


# ---------------------------------------------------------------------------
# R3-10: every check sees the object urllib sends
# ---------------------------------------------------------------------------

class WireObjectTests(_LoopbackCase):
    def test_tuple_in_a_read_only_post_body_is_checked_as_the_json_array_it_becomes(self) -> None:
        for body in ({"actions": ("create",)}, {"op": ("replace", "add")}, {"request": ({"mode": "upsert"},)}):
            with self.subTest(body=body):
                self.assertIsNotNone(scan_safety.read_only_body_risk(body))
                result = _transport().send("POST", self.server.origin + "/documents/search", {}, body)
                self.assertEqual(result.status, 0)
                self.assertIn("Read-only POST body contains", result.error or "")
        self.assertEqual(self.server.snapshot(), [])

    def test_a_body_json_cannot_carry_is_refused_by_the_body_rules(self) -> None:
        for body in ({"query": object()}, {"limit": float("nan")}, {"ids": {1, 2}}):
            with self.subTest(body=repr(body)):
                risk = scan_safety.read_only_body_risk(body)
                self.assertIsNotNone(risk)
                self.assertEqual(risk["safety_signal"], "request_body")
                self.assertEqual(_transport().send("POST", self.server.origin + "/documents/search", {}, body).status,
                                 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_request_rules_hold_on_the_unwrapped_url_without_the_base_policy(self) -> None:
        # Each layer must hold on its own: with the concrete-request policy switched off, the
        # request rules (method override, write query, write body) still refuse the URL urllib sends.
        transport = _transport()
        origin = self.server.origin
        with patch.object(transport_module, "concrete_request_risk", lambda *args: None):
            for url in (f"<URL:{origin}/reports/summary?_method=DELETE>", f" {origin}/reports/summary?upsert=true ",
                        f"<URL:{origin}/reports/summary?action=delete>"):
                with self.subTest(url=url):
                    result = transport.send("GET", url, {})
                    self.assertEqual(result.status, 0)
                    self.assertIn("query string", result.error or "")
        self.assertEqual(self.server.snapshot(), [])

    def test_wrapped_dangerous_paths_stay_refused(self) -> None:  # main-migration review M16 / M18
        origin = self.server.origin
        for url in (f"<URL:{origin}/reports/summary?_method=DELETE>", f"<URL:{origin}/reports/withdraw>",
                    f"<URL:{origin}/reports;action=delete>"):
            with self.subTest(url=url):
                self.assertEqual(_transport().send("GET", url, {}).status, 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_header_spellings_that_urllib_collapses_are_all_checked(self) -> None:
        headers = {"X-HTTP-Method-Override": "GET", "x-http-method-override": "DELETE"}
        self.assertEqual(_transport().send("GET", self.server.origin + "/reports/summary", headers).status, 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_a_request_whose_body_cannot_be_read_as_sent_is_refused(self) -> None:
        import urllib.request

        for data in (iter([b'{"q": 1}']), "not bytes", b"{not json"):
            with self.subTest(data=repr(data)):
                request = urllib.request.Request(self.server.origin + "/documents/search", data=data,  # type: ignore[arg-type]
                                                 method="POST")
                decision = _transport().request_decision(request)
                self.assertEqual(decision, {"safety_reason": UNCHECKED, "safety_signal": "policy_error",
                                            "policy_layer": "transport_request"})
        self.assertEqual(self.server.snapshot(), [])

    def test_the_request_rules_keep_their_string_and_structured_forms(self) -> None:
        url = self.server.origin + "/reports/summary"
        cases = (
            (("GET", url, {}, None), None),
            (("GET", url, {"X-HTTP-Method-Override": "DELETE"}, None), "method_override_header"),
            (("GET ", url, {}, None), "method"),
            ((None, url, {}, None), "method"),
            (("GET", url + "?_method=PURGE", {}, None), "query"),
            (("POST", url, {}, {"action": "delete"}), "request_body"),
            (("PATCH", url + "?upsert=true", {}, {"action": "delete"}), None),  # gated writes keep their data
        )
        for args, signal in cases:
            with self.subTest(args=args[:3]):
                risk = transport_module.request_refusal_risk(*args)
                reason = transport_module.request_refusal(*args)
                if signal is None:
                    self.assertIsNone(risk)
                    self.assertIsNone(reason)
                else:
                    self.assertEqual(risk["safety_signal"], signal)
                    self.assertEqual(reason, risk["safety_reason"])
                    self.assertIn("no request was sent", reason)
        self.assertEqual(self.server.snapshot(), [])

    def test_allowed_requests_send_exactly_what_was_checked(self) -> None:
        body = {"query": "mutation testing", "filters": ["open", "closed"], "page": 2}
        result = _transport().send("POST", self.server.origin + "/documents/search", {}, body)
        self.assertEqual(result.status, 200)
        (method, target, sent), = self.server.snapshot()
        self.assertEqual((method, target, json.loads(sent)), ("POST", "/documents/search", body))


# ---------------------------------------------------------------------------
# RR-02: the concrete path check reads a segment the way a case-insensitive router does
# ---------------------------------------------------------------------------

ROUTER_EQUIVALENT_ACTIONS = ("wItHdRaW", "WiThDrAw", "wıthdraw", "WİTHDRAW", "SUBMİT", "ReSeT",
                             "CaNcEl-order", "ＲｅＳｅｔ", "ſubmit", "dElEtE")
ORDINARY_MIXED_CASE_VALUES = ("Settings", "createdAt", "UpdatedBy", "StatusHistory", "PreviewOnly",
                              "Withdrawals", "ReSettlement", "iOSRelease", "CancellationPolicy", "summary")


class RouterCaseFoldingTests(_LoopbackCase):
    def test_router_equivalent_spellings_of_an_action_are_refused(self) -> None:
        for value in ROUTER_EQUIVALENT_ACTIONS:
            with self.subTest(value=value):
                risk = scan_safety.concrete_path_risk("GET", "/reports/" + value)
                self.assertIsNotNone(risk)
                self.assertEqual(risk["safety_signal"], "path")
                self.assertIsNotNone(scan_safety.concrete_path_risk("HEAD", "/reports/" + value))

    def test_ordinary_mixed_case_values_are_not_refused(self) -> None:
        for value in ORDINARY_MIXED_CASE_VALUES:
            with self.subTest(value=value):
                self.assertIsNone(scan_safety.concrete_path_risk("GET", "/reports/" + value))

    def test_the_router_reading_is_skipped_only_where_it_equals_the_word_reading(self) -> None:
        # concrete_path_risk skips _routed_words for ASCII pieces without upper-case letters;
        # this pins that both readings are identical there, so the skip changes no decision.
        import random

        generator = random.Random(20261125)
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_.~!$&'()*+,=@:%"
        corpus = set(scan_safety._word_forms(scan_safety._POST_ACTIONS)) | {"get-or-create", "kind=withdraw",
                                                                            "a,withdraw", "", "--", "1001"}
        corpus.update("".join(generator.choice(alphabet) for _ in range(generator.randint(1, 24)))
                      for _ in range(3000))
        for piece in sorted(corpus):
            if piece.isascii() and piece == piece.lower():
                self.assertEqual(scan_safety._routed_words(piece), scan_safety._words(piece), piece)

    def test_literal_and_filled_templates_agree(self) -> None:
        for value in ("wItHdRaW", "wıthdraw", "Settings"):
            with self.subTest(value=value):
                literal = scan_safety.read_only_risk({"method": "GET", "path": "/reports/" + value})
                filled = scan_safety.concrete_path_risk("GET", "/reports/" + value)
                self.assertEqual(literal is None, filled is None)

    def test_a_scan_sends_no_router_equivalent_action(self) -> None:
        auditor = self.auditor({"/reports/{kind}": _get(enum=["wItHdRaW"])})
        auditor.run()
        results = auditor.results
        self.assertEqual(self.server.snapshot(), [])
        self.assertTrue(results)
        self.assertTrue(all(result["verdict"] == "SKIPPED" for result in results))


# ---------------------------------------------------------------------------
# RR-01: name=value pairs in a path get the query string's rules; data positions stay data
# ---------------------------------------------------------------------------

class PathKeyValueTests(_LoopbackCase):
    WRITE_PAIRS = (("action", "delete"), ("_method", "DELETE"), ("upsert", "true"), ("dry_run", "false"),
                   ("op", "replace"), ("mode", "upsert"))
    DATA_PAIRS = (("kind", "withdraw"), ("q", "delete me"), ("include_deleted", "true"), ("page", "2"),
                  ("sort", "updated_at"), ("store", "1"))

    def test_matrix_and_exploded_object_pairs_follow_the_query_rules(self) -> None:
        for name, value in self.WRITE_PAIRS + self.DATA_PAIRS:
            query = scan_safety.query_write_risk(f"http://127.0.0.1:9/reports?{name}={value}")
            for path in (f"/reports;{name}={value}", f"/reports/x;{name}={value};page=1",
                         f"/reports/{name}={value},page=1", f"/reports/.{name}={value}.page=1"):
                with self.subTest(path=path):
                    risk = scan_safety.concrete_path_risk("GET", path.replace(" ", "%20"))
                    self.assertEqual(risk is None, query is None, (path, risk, query))
                    if risk is not None:
                        self.assertEqual(risk["safety_signal"], "path")
                        self.assertIn("no request was sent", risk["safety_reason"])

    def test_values_in_data_positions_are_data(self) -> None:
        # The router never dispatches on these: a matrix value, a later array element, a
        # value behind a literal template prefix. They match the literal-path rule.
        for path in ("/reports;kind=withdraw", "/reports/a,withdraw", "/reports/report-withdraw",
                     "/reports/.a.withdraw", "/reports;=upsert", "/reports/=upsert,=true"):
            with self.subTest(path=path):
                self.assertIsNone(scan_safety.concrete_path_risk("GET", path))

    def test_values_in_routed_positions_are_refused(self) -> None:
        for path in ("/reports/withdraw", "/reports/.withdraw", "/reports/withdraw,a", "/reports;withdraw",
                     "/reports/withdraw;kind=a", "/reports;=x;action=delete"):
            with self.subTest(path=path):
                self.assertIsNotNone(scan_safety.concrete_path_risk("GET", path))

    def test_the_transport_sends_no_path_write_switch(self) -> None:
        for path in ("/reports;action=delete", "/reports;_method=DELETE", "/reports/x;upsert=true"):
            with self.subTest(path=path):
                self.assertEqual(_transport().send("GET", self.server.origin + path, {}).status, 0)
        self.assertEqual(self.server.snapshot(), [])


# ---------------------------------------------------------------------------
# OVR: a method-override value naming any registered state-changing method is refused
# ---------------------------------------------------------------------------

UNSAFE_OVERRIDES = ("DELETE", "PUT", "PATCH", "PURGE", "LINK", "UNLINK", "MOVE", "COPY", "LOCK", "UNLOCK",
                    "MKCOL", "PROPPATCH", "MERGE", "MKCALENDAR", "ACL", "BIND", "REBIND", "UNBIND", "UPDATE")
SAFE_OVERRIDES = ("GET", "HEAD", "OPTIONS", "POST", "PROPFIND", "REPORT", "SEARCH", "TRACE")


class MethodOverrideValueTests(_LoopbackCase):
    def test_every_unsafe_override_value_is_refused_in_queries_and_bodies(self) -> None:
        for method in UNSAFE_OVERRIDES:
            for spelling in (method, method.lower(), f" {method.title()} "):
                with self.subTest(method=spelling):
                    self.assertIsNotNone(scan_safety.query_write_risk(f"http://127.0.0.1:9/s?_method={spelling}"))
                    self.assertIsNotNone(scan_safety.read_only_body_risk({"_method": spelling}))
                    self.assertIsNotNone(scan_safety.read_only_body_risk({"X-HTTP-Method-Override": spelling}))
                    self.assertTrue(scan_safety.method_override_risk("X-HTTP-Method-Override", spelling))

    def test_safe_overrides_and_data_fields_named_method_are_not_refused(self) -> None:
        for method in SAFE_OVERRIDES:
            with self.subTest(method=method):
                self.assertIsNone(scan_safety.query_write_risk(f"http://127.0.0.1:9/s?_method={method}"))
                self.assertIsNone(scan_safety.read_only_body_risk({"_method": method}))
        for body in ({"method": "card"}, {"payment": {"method": "bank_transfer"}}, {"sort_method": "desc"},
                     {"method": "token-exchange"}):
            with self.subTest(body=body):
                self.assertIsNone(scan_safety.read_only_body_risk(body))

    def test_only_string_override_values_name_a_method(self) -> None:
        # A value that is no string names no method; list elements are read under their key.
        for body in ({"_method": 7}, {"method": None}, {"X-HTTP-Method-Override": True}, {"_method": {"a": 1}},
                     {"method": 1.5}):
            with self.subTest(body=body):
                self.assertIsNone(scan_safety.read_only_body_risk(body))
        for body in ({"_method": ["purge"]}, {"_method": [7, "DELETE"]}):
            with self.subTest(body=body):
                self.assertIsNotNone(scan_safety.read_only_body_risk(body))

    def test_the_transport_sends_no_unsafe_override_query(self) -> None:
        for method in ("PURGE", "LINK", "MOVE"):
            with self.subTest(method=method):
                result = _transport().send("POST", self.server.origin + f"/documents/search?_method={method}", {},
                                           {"query": "x"})
                self.assertEqual(result.status, 0)
        self.assertEqual(self.server.snapshot(), [])


# ---------------------------------------------------------------------------
# R3-03: adverb-led affirmative clauses name the operation's own write
# ---------------------------------------------------------------------------

ADVERBIAL_WRITES = ("Permanently deletes the job", "Asynchronously triggers a rebuild of the index",
                    "Immediately cancels the order", "This endpoint permanently removes the file",
                    "Silently resets all counters", "Permanently delete the job",
                    "Returns nothing. Irreversibly revokes every token of the user",
                    "The operation automatically publishes this draft")
ADVERBIAL_READS = ("Weekly updates for the team", "Daily transfers summary", "Monthly imports report",
                   "Previously deleted jobs are listed", "Only returns the job", "Lists recently scheduled jobs",
                   "Hourly schedules for each region", "Returns the job permanently", "Weekly schedules",
                   "Early access reports for the account")


class AdverbialClauseTests(_LoopbackCase):
    def test_adverb_led_write_clauses_are_refused(self) -> None:
        for summary in ADVERBIAL_WRITES:
            for field in ("summary", "description"):
                with self.subTest(summary=summary, field=field):
                    risk = scan_safety.read_only_risk({"method": "GET", "path": "/jobs/{id}", field: summary})
                    self.assertIsNotNone(risk)
                    self.assertEqual(risk["safety_signal"], field)

    def test_adverbs_and_plural_nouns_that_are_not_clauses_are_not_refused(self) -> None:
        for summary in ADVERBIAL_READS:
            with self.subTest(summary=summary):
                self.assertIsNone(scan_safety.read_only_risk({"method": "GET", "path": "/jobs/{id}",
                                                              "summary": summary}))

    def test_a_scan_sends_nothing_to_an_adverb_led_write(self) -> None:
        auditor = self.auditor({"/jobs/{kind}": _get(summary="Permanently deletes the job", enum=["42"])})
        auditor.run()
        results = auditor.results
        self.assertEqual(self.server.snapshot(), [])
        self.assertTrue(results)
        self.assertTrue(all(result["evidence"].get("reason_category") == "safety_policy" for result in results))


# ---------------------------------------------------------------------------
# REF: structured refusals, and no conclusive verdict after a refusal
# ---------------------------------------------------------------------------

class _NoPreCheck(APISentinelAuditor):
    """An auditor whose own pre-check allows everything: only the transport decides."""

    def _request_risk(self, method: str, url: str) -> Optional[Dict[str, str]]:
        return None


class StructuredRefusalTests(_LoopbackCase):
    def assert_refusal(self, result: HTTPResult, signal: str, layer: str) -> None:
        refusal = getattr(result, "refusal", None)
        self.assertIsNotNone(refusal, result)
        self.assertEqual(result.status, 0)
        self.assertEqual(result.error, refusal["safety_reason"])
        self.assertTrue(refusal["safety_reason"].startswith("Read-only safety policy")
                        or refusal["safety_reason"].startswith("Read-only POST"), refusal)
        self.assertEqual((refusal["safety_signal"], refusal["policy_layer"]), (signal, layer))

    def test_every_transport_refusal_says_what_and_where(self) -> None:
        origin = self.server.origin
        cases = (
            (("GET ", origin + "/reports/summary", {}, None), "method", "transport_base"),
            (("GET", origin + "/reports/summary", {"X-HTTP-Method-Override": "DELETE"}, None),
             "method_override_header", "transport_request"),
            (("GET", origin + "/reports/summary?_method=DELETE", {}, None), "query", "transport_request"),
            (("POST", origin + "/documents/search", {}, {"action": "delete"}), "request_body", "transport_request"),
            (("GET", origin + "/reports/withdraw", {}, None), "path", "transport_base"),
        )
        for args, signal, layer in cases:
            with self.subTest(args=args[:3]):
                self.assert_refusal(_transport().send(*args), signal, layer)
        guarded = _transport(request_guard=lambda method, url: {"safety_reason": "Read-only safety policy: guard",
                                                                 "safety_signal": "template_metadata"})
        self.assert_refusal(guarded.send("GET", origin + "/reports/summary", {}), "template_metadata",
                            "transport_guard")
        broken = _transport(request_guard=lambda method, url: 1 / 0)
        self.assert_refusal(broken.send("GET", origin + "/reports/summary", {}), "policy_error", "transport_guard")
        self.assertEqual(self.server.snapshot(), [])

    def test_a_network_failure_is_not_a_refusal(self) -> None:
        listener = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        port = listener.server_port
        listener.server_close()
        result = _transport().send("GET", f"http://127.0.0.1:{port}/reports/summary", {})
        self.assertEqual(result.status, 0)
        self.assertIsNotNone(result.error)
        self.assertIsNone(getattr(result, "refusal", "missing"))

    def test_auditor_pre_check_refusals_are_structured(self) -> None:
        auditor = self.auditor({"/reports/{kind}": _get(enum=["summary"])})
        result = auditor._http_request("GET", self.server.origin + "/reports/withdraw")
        self.assert_refusal(result, "path", "auditor")
        self.assertEqual(self.server.snapshot(), [])

    def test_a_check_with_a_transport_refusal_records_the_structured_refusal(self) -> None:
        auditor = self.auditor({"/reports/{kind}": _get(enum=["withdraw"])}, cls=_NoPreCheck)
        auditor.run()
        results = auditor.results
        self.assertEqual(self.server.snapshot(), [])
        self.assertTrue(results)
        for result in results:
            with self.subTest(check=result["check"]):
                evidence = result["evidence"]
                # Main's semantics: a refused observation ends the check as ERROR, never conclusive.
                self.assertEqual(result["verdict"], "ERROR")
                self.assertEqual(evidence["requests_attempted"], 0)
                self.assertGreaterEqual(evidence["safety_refusals"], 1)
                self.assertEqual(evidence["safety_signal"], "path")
                self.assertEqual(evidence["policy_layer"], "transport_base")
                self.assertIn("Read-only safety policy", result["reason"])
        self.assertEqual(auditor.stats["http_requests_sent"], 0)
        self.assertGreater(auditor.stats["error_count"], 0)

    def test_no_conclusive_negative_verdict_after_a_refusal(self) -> None:
        auditor = self.auditor({"/reports/{kind}": _get(enum=["summary"])})
        endpoint = auditor.parser.get_endpoints()[0]
        for verdict, expected in ((Verdict.SECURE, "ERROR"), (Verdict.PUBLIC, "ERROR"), (Verdict.AUTHORIZED, "ERROR"),
                                  (Verdict.ERROR, "ERROR"), (Verdict.INCONCLUSIVE, "INCONCLUSIVE"),
                                  (Verdict.SKIPPED, "SKIPPED")):
            with self.subTest(verdict=verdict):
                auditor._http_request("GET", self.server.origin + "/reports/withdraw")
                auditor._record_result(endpoint, "BOLA", verdict, "detector decision", evidence={})
                recorded = auditor.results[-1]
                self.assertEqual(recorded["verdict"], expected)
                self.assertEqual(recorded["evidence"]["policy_layer"], "auditor")
                self.assertEqual(recorded["evidence"]["safety_signal"], "path")
                self.assertEqual(recorded["evidence"]["safety_refusals"], 1)
                if verdict != Verdict(expected):
                    self.assertIn("refused", recorded["reason"])
                    self.assertEqual(recorded["evidence"]["reason_category"], "error")
        # IND-01: with no new request and no new check, a further record belongs to the same
        # observation batch, so it keeps the refusal and cannot conclude either.
        auditor._record_result(endpoint, "BROKEN_AUTH", Verdict.SECURE, "same batch, another record", evidence={})
        self.assertEqual(auditor.results[-1]["verdict"], "ERROR")
        self.assertEqual(auditor.results[-1]["evidence"]["safety_refusals"], 1)
        # The next check starts without the earlier refusal.
        auditor._begin_check_accounting()  # what every check task does before it starts
        auditor._record_result(endpoint, "BOLA", Verdict.SECURE, "a later, independent check", evidence={})
        self.assertEqual(auditor.results[-1]["verdict"], "SECURE")
        self.assertEqual(self.server.snapshot(), [])

    def test_a_confirmed_finding_and_a_rollback_keep_their_verdicts(self) -> None:
        auditor = self.auditor({"/reports/{kind}": _get(enum=["summary"])})
        endpoint = auditor.parser.get_endpoints()[0]
        auditor._http_request("GET", self.server.origin + "/reports/withdraw")
        auditor._record_result(endpoint, "ROLLBACK", Verdict.ERROR, "rollback failed", evidence={})
        self.assertEqual(auditor.results[-1]["verdict"], "ERROR")
        auditor._record_result(endpoint, "BOLA", Verdict.CONFIRMED, "leak observed", evidence={})
        confirmed = auditor.results[-1]
        self.assertEqual(confirmed["verdict"], "CONFIRMED")
        self.assertEqual(confirmed["evidence"]["safety_refusals"], 1)


if __name__ == "__main__":
    unittest.main()
