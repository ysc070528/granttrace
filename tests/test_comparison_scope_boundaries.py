"""Hidden resource differences between two scans, through real scans, `granttrace diff` and its gate.

Evidence URLs are redacted, and query values always are, so `diff` only reads
a resource as unchanged when keyed fingerprints show the configuration that
built the request did not change. These tests pin where that holds and where
the scanner itself sends a different request every scan (a generated UUID or
the current time for a parameter without a configured value).

Active network tests only use 127.0.0.1.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

import api_sentinel
from core.generator import SmartDataGenerator
from core.report_diff import build_comparison_context

KEY = "3b8e1d6a9f2c5e7b0d4a8c1f6e3b9d2a5c7f0e4b8d1a6c3f9e2b5d7a0c4f8e1b"
OWNER, VISITOR = "Bearer OWN-scope-0001", "Bearer VIS-scope-0002"
OWNER_RESOURCES = {"1001", "alice@corp.example", "bob@corp.example", "doc-1111", "doc-3333"}
VISITOR_RESOURCES = {"1002", "vic@corp.example", "doc-2002"}


class _Api(BaseHTTPRequestHandler):
    """Every authenticated caller reads every resource until `fixed`; logs what it receives."""

    state: Dict[str, Any] = {}

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        resource = unquote(parts.path).rstrip("/").split("/")[-1]
        query = {name: values[0] for name, values in parse_qs(parts.query).items()}
        auth = self.headers.get("Authorization") or ""
        who = "owner" if auth == OWNER else "visitor" if auth == VISITOR else None
        state = type(self).state
        state.setdefault("log", []).append((who, unquote(parts.path), query))
        if who is None:
            code, doc = 401, {"error": "unauthorized"}
        else:
            allowed = who == "owner" or resource in VISITOR_RESOURCES or not state.get("fixed")
            if state.get("nonce_decides") and who == "visitor" and resource not in VISITOR_RESOURCES:
                # The server's answer depends on a value the scanner generates for every scan.
                allowed = query.get("nonce", "f")[0] in "01234567"
            if allowed:
                code, doc = 200, {"id": resource, "email": f"{resource}-owner@corp.example", "plan": "gold"}
                if state.get("echo"):
                    doc["email"] = resource  # the Owner's private value is the resource id itself
            else:
                code, doc = 403, {"error": "forbidden"}
        data = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _operation(path: str, op_id: str, params: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {path: {"get": {"operationId": op_id, "parameters": params, "responses": {"200": {"description": "OK"}}}}}


SPEC: Dict[str, Any] = {
    "openapi": "3.0.3", "info": {"title": "scope", "version": "1"},
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearer": []}],
    "paths": {
        **_operation("/users/{email}", "getUserByEmail",
                     [{"name": "email", "in": "path", "required": True, "schema": {"type": "string"}}]),
        **_operation("/docs/{doc_ref}", "getDoc",
                     [{"name": "doc_ref", "in": "path", "required": True, "schema": {"type": "string"}}]),
        **_operation("/orders/{order_id}", "getOrder",
                     [{"name": "order_id", "in": "path", "required": True, "schema": {"type": "string"}},
                      {"name": "as_of", "in": "query", "required": True,
                       "schema": {"type": "string", "format": "date-time"}}]),
        **_operation("/tickets/{ticket_id}", "getTicket",
                     [{"name": "ticket_id", "in": "path", "required": True, "schema": {"type": "string"}},
                      {"name": "nonce", "in": "query", "required": True,
                       "schema": {"type": "string", "format": "uuid"}}]),
    },
}
USERS, DOCS, ORDERS, TICKETS = ("GET /users/{email}", "GET /docs/{doc_ref}", "GET /orders/{order_id}",
                                "GET /tickets/{ticket_id}")


def _config(owner_email: str = "alice@corp.example", doc: str = "doc-1111",
            pinned: Optional[Dict[str, Tuple[str, str]]] = None) -> Dict[str, Any]:
    values: Dict[str, Any] = {
        USERS: {"owner": {"email": owner_email}, "visitor": {"email": "vic@corp.example"}},
        DOCS: {"owner": {"doc_ref": doc}, "visitor": {"doc_ref": "doc-2002"}},
    }
    for operation, (name, value) in (pinned or {}).items():
        values.setdefault(operation, {})["common"] = {name: value}
    return {"identities": {"owner": {"id": "1001", "token": OWNER}, "visitor": {"id": "1002", "token": VISITOR},
                           "anonymous": {"id": None, "token": None}},
            "parameter_values": values,
            # Owner values under sensitive keys become secrets that every later output redacts.
            "bola": {operation: {"private_data_paths": ["email"], "detect_sensitive_exposure": operation == DOCS}
                     for operation in (USERS, DOCS, ORDERS, TICKETS)}}


class _Scans(unittest.TestCase):
    def setUp(self) -> None:
        _Api.state = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.target = f"http://127.0.0.1:{self.server.server_address[1]}"
        temp = tempfile.TemporaryDirectory(prefix="gt-scope-")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        (self.folder / "spec.json").write_text(json.dumps(SPEC), encoding="utf-8")

    @staticmethod
    def cli(argv: List[str]) -> Tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"GRANTTRACE_COMPARISON_KEY": KEY}), \
                patch("urllib.request.getproxies", return_value={}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = api_sentinel.main(argv)
        return code, out.getvalue() + err.getvalue()

    def scan(self, name: str, config: Dict[str, Any], **state: Any) -> Path:
        _Api.state = dict(state, log=[])
        config_path, report = self.folder / f"{name}.config.json", self.folder / f"{name}.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        code, text = self.cli(["--spec", str(self.folder / "spec.json"), "--config", str(config_path),
                               "--target", self.target, "--delay", "0",
                               "--output", str(self.folder / f"{name}.html"), "--export-json", str(report)])
        self.assertIn(code, (0, 1), text[-2000:])
        return report

    def sent(self, prefix: str, identity: str = "visitor") -> List[Dict[str, str]]:
        return [query for who, path, query in _Api.state["log"] if who == identity and path.startswith(prefix)]

    @staticmethod
    def evidence(report: Path, operation: str) -> Tuple[str, Any]:
        [(verdict, url)] = [(item["verdict"], item["evidence"].get("target_url"))
                            for item in json.loads(report.read_text(encoding="utf-8"))["results"]
                            if item["endpoint"] == operation and item["check"] == "BOLA"]
        return verdict, url

    def diff(self, base: Path, cur: Path, operation: str) -> Dict[str, Any]:
        """The BOLA issue of one operation, its operation change, and each gate's exit and items for it."""
        out = self.folder / f"cmp-{base.stem}-{cur.stem}.json"
        code, text = self.cli(["diff", str(base), str(cur), "--export-json", str(out)])
        self.assertEqual(code, 0, text[-2000:])
        comparison = json.loads(out.read_text(encoding="utf-8"))
        [issue] = [item for item in comparison["issues"] if item["operation"] == operation and item["check"] == "BOLA"]
        changes = {item["operation"]: item["reasons"] for item in comparison["comparability"]["operation_changes"]}
        result: Dict[str, Any] = {"status": issue["status"], "reasons": issue.get("reasons", []),
                                  "blocking": comparison["comparability"]["blocking"],
                                  "change": changes.get(operation)}
        for flag in ("--fail-on-new", "--fail-on-not-comparable"):
            gate_out = self.folder / f"gate{flag}-{base.stem}-{cur.stem}.json"
            gate_code, _ = self.cli(["diff", str(base), str(cur), flag, "--export-json", str(gate_out)])
            gate = json.loads(gate_out.read_text(encoding="utf-8"))["gate"]
            result[flag] = (gate_code, sorted(item["reason"] for part in gate["conditions"]
                                              for item in part["regressions"] + part["unverified"]
                                              if item.get("operation") == operation))
        return result


class ConfiguredResourcesBehindRedactionTests(_Scans):
    """Questions 2, 3 and 5: configured resource values are fingerprinted, redacted or not."""

    def test_identical_redacted_urls_of_different_configured_resources_are_not_comparable(self) -> None:
        base = self.scan("alice_vulnerable", _config(owner_email="alice@corp.example"))
        fixed = self.scan("bob_fixed", _config(owner_email="bob@corp.example"), fixed=True)
        vulnerable = self.scan("bob_vulnerable", _config(owner_email="bob@corp.example"))
        secure = self.scan("alice_secure", _config(owner_email="alice@corp.example"), fixed=True)
        # Both scans write the same evidence URL for different accounts.
        self.assertEqual(self.evidence(base, USERS)[1], self.evidence(fixed, USERS)[1])
        self.assertIn("[REDACTED]", self.evidence(base, USERS)[1])
        # A confirmed finding on the other account is never persisting or new; a fix is never resolved.
        for before, after, new_items in ((base, fixed, []), (base, vulnerable, ["confirmed_not_comparable"]),
                                         (secure, vulnerable, ["confirmed_not_comparable"])):
            with self.subTest(before=before.stem, after=after.stem):
                result = self.diff(before, after, USERS)
                self.assertEqual((result["status"], result["change"]), ("not_comparable", ["resources_changed"]))
                self.assertEqual(result["blocking"], [])
                self.assertEqual(result["--fail-on-new"][1], new_items)
                self.assertNotEqual(result["--fail-on-new"][0], 0 if new_items else None)
                self.assertEqual(result["--fail-on-not-comparable"], (3, ["finding_not_comparable"]))

    def test_one_side_redacted_by_a_runtime_secret_matches_only_the_same_configured_resource(self) -> None:
        base = self.scan("echo_vulnerable", _config(doc="doc-1111"), echo=True)
        same = self.scan("same_fixed", _config(doc="doc-1111"), fixed=True)
        other = self.scan("other_fixed", _config(doc="doc-3333"), fixed=True)
        self.assertEqual(self.evidence(base, DOCS)[1], self.target + "/docs/[REDACTED]")
        self.assertEqual(self.evidence(same, DOCS)[1], self.target + "/docs/doc-1111")
        self.assertEqual(self.evidence(other, DOCS)[1], self.target + "/docs/doc-3333")
        self.assertEqual(self.diff(base, same, DOCS)["status"], "resolved")
        changed = self.diff(base, other, DOCS)
        self.assertEqual((changed["status"], changed["change"]), ("not_comparable", ["resources_changed"]))
        self.assertEqual(changed["--fail-on-not-comparable"], (3, ["finding_not_comparable"]))


class GeneratedParameterValuesTests(_Scans):
    """Question 4: a value the scanner generates for every scan is not the same request twice."""

    def test_generated_query_values_differ_while_evidence_and_fingerprints_do_not(self) -> None:
        base = self.scan("orders_vulnerable", _config())
        sent_base = {query["as_of"] for query in self.sent("/orders/1001")}
        fixed = self.scan("orders_fixed", _config(), fixed=True)
        sent_fixed = {query["as_of"] for query in self.sent("/orders/1001")}
        self.assertTrue(sent_base and sent_fixed and not sent_base & sent_fixed)
        self.assertEqual(self.evidence(base, ORDERS)[1], self.evidence(fixed, ORDERS)[1])
        result = self.diff(base, fixed, ORDERS)
        self.assertEqual((result["status"], result["change"]), ("not_comparable", ["context_incomplete"]))
        self.assertEqual(result["--fail-on-not-comparable"], (3, ["finding_not_comparable"]))
        # Operations whose requests are built from configuration alone keep their conclusion.
        self.assertEqual(self.diff(base, fixed, USERS)["status"], "resolved")

    def test_a_server_decision_on_a_generated_value_is_not_a_fix_or_a_regression(self) -> None:
        reports: Dict[str, Path] = {}
        for attempt in range(40):
            report = self.scan(f"tickets_{attempt}", _config(), fixed=True, nonce_decides=True)
            reports.setdefault(self.evidence(report, TICKETS)[0], report)
            if {"CONFIRMED", "SECURE"} <= set(reports):
                break
        self.assertTrue({"CONFIRMED", "SECURE"} <= set(reports), "the generated nonce never changed the answer")
        resolved = self.diff(reports["CONFIRMED"], reports["SECURE"], TICKETS)
        self.assertEqual((resolved["status"], resolved["change"]), ("not_comparable", ["context_incomplete"]))
        self.assertEqual(resolved["--fail-on-not-comparable"], (3, ["finding_not_comparable"]))
        appeared = self.diff(reports["SECURE"], reports["CONFIRMED"], TICKETS)
        self.assertEqual(appeared["status"], "not_comparable")
        self.assertEqual(appeared["--fail-on-new"], (3, ["confirmed_not_comparable"]))

    def test_a_value_pinned_in_parameter_values_is_fingerprinted(self) -> None:
        pinned = {ORDERS: ("as_of", "2026-01-01T00:00:00Z")}
        base = self.scan("pinned_vulnerable", _config(pinned=pinned))
        self.assertEqual({query["as_of"] for query in self.sent("/orders/1001")}, {"2026-01-01T00:00:00Z"})
        fixed = self.scan("pinned_fixed", _config(pinned=pinned), fixed=True)
        self.assertEqual(self.diff(base, fixed, ORDERS)["status"], "resolved")
        moved = self.scan("moved_fixed", _config(pinned={ORDERS: ("as_of", "2026-06-01T00:00:00Z")}), fixed=True)
        result = self.diff(base, moved, ORDERS)
        self.assertEqual((result["status"], result["change"]), ("not_comparable", ["resources_changed"]))


class GeneratedValueTrackingTests(unittest.TestCase):
    def test_only_per_scan_values_of_parameters_are_reported(self) -> None:
        cases = [
            ({"name": "as_of", "in": "query", "schema": {"type": "string", "format": "date-time"}}, None, True),
            ({"name": "day", "in": "query", "schema": {"type": "string", "format": "date"}}, None, True),
            ({"name": "nonce", "in": "query", "schema": {"type": "string", "format": "uuid"}}, None, True),
            ({"name": "nonce", "in": "query", "schema": {"type": "string", "format": "uuid",
                                                          "example": "6f1c0a52-3c1f-4d8e-9a3b-2f1e5d7c9b10"}}, None, False),
            ({"name": "order_uuid", "in": "path", "schema": {"type": "string", "format": "uuid"}},
             "6f1c0a52-3c1f-4d8e-9a3b-2f1e5d7c9b10", False),
            ({"name": "page", "in": "query", "schema": {"type": "integer"}}, None, False),
            ({"name": "q", "in": "query", "schema": {"type": "string"}}, None, False),
        ]
        for metadata, candidate, volatile in cases:
            with self.subTest(name=metadata["name"], schema=metadata["schema"]):
                with SmartDataGenerator.track_generated_values() as names:
                    SmartDataGenerator.generate_raw_value_for_param(metadata, candidate)
                self.assertEqual(names, [metadata["name"]] if volatile else [])
        # Outside tracking nothing is recorded, and request bodies (attack payloads) never count.
        SmartDataGenerator.generate_raw_value_for_param(cases[0][0])
        with SmartDataGenerator.track_generated_values() as names:
            SmartDataGenerator.build_mass_assignment_payload(
                {"type": "object", "properties": {"created_at": {"type": "string", "format": "date-time"}}})
        self.assertEqual(names, [])

    def test_context_has_no_resources_fingerprint_for_operations_with_generated_values(self) -> None:
        def context(volatile: Tuple[str, ...]) -> Dict[str, Any]:
            return build_comparison_context(
                key=KEY, target="http://127.0.0.1:8000",
                identities={"owner": {"id": "1", "token": OWNER}, "visitor": {"id": "2", "token": VISITOR},
                            "anonymous": {}},
                endpoints=[{"method": "GET", "path": "/orders/{order_id}"}, {"method": "GET", "path": "/users/{id}"}],
                secret_values=(OWNER, VISITOR), volatile_operations=volatile)
        plain, marked = context(()), context((ORDERS,))
        self.assertIsNotNone(plain["operations"][ORDERS]["resources"])
        self.assertIsNone(marked["operations"][ORDERS]["resources"])
        self.assertEqual(marked["operations"][ORDERS]["definition"], plain["operations"][ORDERS]["definition"])
        self.assertEqual(marked["operations"]["GET /users/{id}"], plain["operations"]["GET /users/{id}"])


if __name__ == "__main__":
    unittest.main()
