"""Review hardening of the P0-01 comparison context (follow-up to the stable comparison context).

* Evidence URLs whose redaction markers hide different values are never shown
  to be the same resource: literal text between markers, and query parameters
  cut off by the evidence limit.
* ``granttrace diff --fail-on-*`` judges resources by the rule ``diff`` uses.
* Short configured values do not corrupt operation templates or operationIds,
  and an operationId keeps its JSON type.
* A parameter that names a resource (``session_id``, ``ticket_id``) is a
  resource value, not a credential, unless a security scheme or
  ``auth_header_names`` declares it.

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
from typing import Any, Dict, Iterable, List, Optional, Tuple
from unittest.mock import patch

import api_sentinel
from core.auditor import APISentinelAuditor
from core import evidence
from core.evidence import sanitize_operation_key, sanitize_url
from core.models import Verdict
from core.report_diff import (
    build_comparison_context,
    compare_reports,
    load_report,
    result_states,
    specification_security_schemes,
)
from core.report_gate import evaluate_gate
from core.sarif import SarifReportGenerator

KEY = "4e1c8a7f2d9b0e6c3a5f7d1b9e2c4a8f6d0b3e5c7a9f1d2b4c6e8a0f3d5b7c9e"
TARGET = "http://127.0.0.1:8000"
FILES = "GET /files/{name}"


def _context(secret_values: Iterable[str] = ("Bearer segsecret-0001", "segsecret-0001", "Bearer vis-0002",
                                             "vis-0002"),
             endpoints: Iterable[Dict[str, Any]] = ({"method": "GET", "path": "/files/{name}"},)) -> Dict[str, Any]:
    return build_comparison_context(
        key=KEY, target=TARGET,
        identities={"owner": {"id": "1", "token": "Bearer segsecret-0001"},
                    "visitor": {"id": "2", "token": "Bearer vis-0002"}, "anonymous": {}},
        endpoints=list(endpoints), secret_values=tuple(secret_values))


def _report(context: Optional[Dict[str, Any]], verdict: str, target_url: str, check: str = "BOLA",
            operation: str = FILES) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "tool_version": "2.8.0", "report_schema_version": 2, "target": TARGET,
        "results": [{"endpoint": operation, "check": check, "verdict": verdict, "reason": "x",
                     "evidence": {"requests_attempted": 4, "target_url": target_url}}]}
    if context is not None:
        report["comparison_context"] = context
    return report


def _issue(baseline: Dict[str, Any], current: Dict[str, Any], **assumptions: bool) -> Dict[str, Any]:
    comparison = compare_reports(baseline, current, **assumptions)
    [issue] = comparison["issues"]
    return issue


def _gate(baseline: Dict[str, Any], current: Dict[str, Any], *, allow: bool = False,
          **assumptions: bool) -> Dict[str, Any]:
    comparison = compare_reports(baseline, current, **assumptions)
    return evaluate_gate(comparison, result_states(baseline), result_states(current), conditions=["new"],
                         allow_assumptions=allow)


def _query_url(names: Iterable[str]) -> str:
    """A sanitized evidence URL for /files/doc with the given query parameter names, as a scan writes it."""
    return sanitize_url(TARGET + "/files/doc?" + "&".join(f"{name}=1" for name in names))


HUNDRED = [f"p{index}" for index in range(100)]
UNKEYED = {"assume_same_target": True, "assume_same_identities": True, "assume_same_configuration": True}


class RedactedScopeComparisonTests(unittest.TestCase):
    """Items 1 and 2: what redaction hides is not shown to be unchanged."""

    def setUp(self) -> None:
        self.context = _context()

    def assert_not_shown_same(self, left: str, right: str, reason: str = "scope_unknown") -> None:
        for before, after, expected in (("CONFIRMED", "SECURE", "resolved"), ("CONFIRMED", "CONFIRMED", "persisting")):
            with self.subTest(left=left, right=right, before=before, after=after):
                issue = _issue(_report(self.context, before, left), _report(self.context, after, right))
                self.assertNotEqual(issue["status"], expected)
                self.assertEqual(issue["status"], "not_comparable")
                self.assertIn(reason, issue["reasons"])

    def test_literal_between_two_markers_that_differs_is_not_the_same_resource(self) -> None:
        self.assert_not_shown_same(TARGET + "/files/%5BREDACTED%5D-1001-%5BREDACTED%5D",
                                   TARGET + "/files/%5BREDACTED%5D-2002-%5BREDACTED%5D")
        self.assert_not_shown_same(TARGET + "/files/[REDACTED]a[REDACTED]b[REDACTED]",
                                   TARGET + "/files/[REDACTED]a[REDACTED]c[REDACTED]")
        self.assert_not_shown_same(TARGET + "/files/[REDACTED]-1001-[EMAIL%20REDACTED]",
                                   TARGET + "/files/[REDACTED]-2002-[EMAIL%20REDACTED]")
        # The same literal with another kind of marker around it is not shown the same either.
        self.assert_not_shown_same(TARGET + "/files/[REDACTED]-1001-[EMAIL%20REDACTED]",
                                   TARGET + "/files/[REDACTED]-1001-[REDACTED]")
        # A literal that cannot line up at the start or the end is a proven change.
        self.assert_not_shown_same(TARGET + "/files/a-[REDACTED]-x", TARGET + "/files/b-[REDACTED]-x",
                                   reason="resources_changed")

    def test_identical_redacted_text_stays_comparable_on_keyed_fingerprints_only(self) -> None:
        same = TARGET + "/files/%5BREDACTED%5D-1001-%5BREDACTED%5D"
        issue = _issue(_report(self.context, "CONFIRMED", same), _report(self.context, "SECURE", same))
        self.assertEqual((issue["status"], issue.get("reasons")), ("resolved", None))
        unkeyed = _issue(_report(None, "CONFIRMED", same), _report(None, "SECURE", same), **UNKEYED)
        self.assertEqual(unkeyed["status"], "not_comparable")
        self.assertIn("scope_unknown", unkeyed["reasons"])

    def test_query_parameters_cut_off_by_the_evidence_limit_are_not_shown_unchanged(self) -> None:
        tenant_a = _query_url([*HUNDRED, "tenant"])
        tenant_b = _query_url([*HUNDRED, "other"])
        # The evidence limit keeps the first 100 parameters: both scans write the same text.
        self.assertEqual(tenant_a, tenant_b)
        self.assertIn("_truncated_params", tenant_a)
        self.assert_not_shown_same(tenant_a, tenant_b)
        # One scan cut parameters off, the other sent no more than the kept ones: a proven change.
        self.assert_not_shown_same(tenant_a, _query_url(HUNDRED), reason="resources_changed")
        self.assert_not_shown_same(_query_url(HUNDRED[:99]), tenant_a, reason="resources_changed")
        # A kept parameter that differs is a change whatever was cut off.
        self.assert_not_shown_same(tenant_a, _query_url(["q", *HUNDRED[1:], "tenant"]), reason="resources_changed")
        # Both cut off, or one cut off and the other longer than the kept part: unknown.
        self.assert_not_shown_same(_query_url([*HUNDRED, "a", "b"]), tenant_a)
        self.assert_not_shown_same(TARGET + "/files/doc?a=%5BREDACTED%5D&_truncated_params=%5BREDACTED%5D",
                                   TARGET + "/files/doc?a=%5BREDACTED%5D&b=%5BREDACTED%5D")

    def test_unaffected_comparisons_keep_their_result(self) -> None:
        cases = [
            # One side redacted, the other matching around the marker: the PR #102 rule on keyed fingerprints.
            (TARGET + "/files/[REDACTED]-1001", TARGET + "/files/segsecret-0001-1001", "resolved", None),
            (TARGET + "/files/[REDACTED]-1001", TARGET + "/files/[REDACTED]-2002", "not_comparable",
             "resources_changed"),
            (TARGET + "/files/doc-1", TARGET + "/files/doc-1", "resolved", None),
            (TARGET + "/files/doc-1", TARGET + "/files/doc-2", "not_comparable", "resources_changed"),
            (_query_url(HUNDRED), _query_url(HUNDRED), "resolved", None),
            (_query_url(HUNDRED), _query_url(HUNDRED[1:] + ["x"]), "not_comparable", "resources_changed"),
        ]
        for left, right, status, reason in cases:
            with self.subTest(left=left, right=right):
                issue = _issue(_report(self.context, "CONFIRMED", left), _report(self.context, "SECURE", right))
                self.assertEqual(issue["status"], status)
                if reason:
                    self.assertIn(reason, issue["reasons"])


class GateUsesTheDiffResourceRuleTests(unittest.TestCase):
    """Item 3: a declaration change the comparison cannot rule out never passes the gate."""

    def setUp(self) -> None:
        self.context = _context()

    def gate_result(self, left: str, right: str, context: Optional[Dict[str, Any]] = None, *,
                    allow: bool = False, **assumptions: bool) -> Tuple[str, List[str]]:
        ctx = self.context if context is None else context
        if assumptions:
            ctx = None
        decided = _gate(_report(ctx, "SECURE", left), _report(ctx, "PUBLIC", right), allow=allow, **assumptions)
        [part] = decided["conditions"]
        return decided["result"], [item["reason"] for item in part["unverified"] + part["regressions"]]

    def test_accepted_access_with_cut_off_query_parameters_is_not_verified(self) -> None:
        url = _query_url([*HUNDRED, "tenant"])
        self.assertEqual(self.gate_result(url, url), ("unverified", ["accepted_after_declaration_change"]))

    def test_accepted_access_with_redacted_resources_on_stated_assumptions_is_not_verified(self) -> None:
        url = TARGET + "/files/%5BREDACTED%5D"
        result = self.gate_result(url, url, allow=True, **UNKEYED)
        self.assertEqual(result, ("unverified", ["accepted_after_declaration_change"]))
        # Unredacted, identical request URLs on the same assumptions still pass, as before.
        plain = TARGET + "/files/doc-1"
        self.assertEqual(self.gate_result(plain, plain, allow=True, **UNKEYED), ("passed", []))

    def test_gate_never_passes_what_diff_cannot_show_unchanged(self) -> None:
        pairs = [
            (TARGET + "/files/%5BREDACTED%5D-1001-%5BREDACTED%5D", TARGET + "/files/%5BREDACTED%5D-2002-%5BREDACTED%5D"),
            (TARGET + "/files/[REDACTED]-1001-[EMAIL%20REDACTED]", TARGET + "/files/[REDACTED]-1001-[REDACTED]"),
            (_query_url([*HUNDRED, "tenant"]), _query_url([*HUNDRED, "other"])),
            (_query_url([*HUNDRED, "tenant"]), _query_url(HUNDRED)),
            (TARGET + "/files/doc-1", TARGET + "/files/doc-2"),
            (TARGET + "/files/[REDACTED]-1001", TARGET + "/files/[REDACTED]-2002"),
            (TARGET + "/files/doc-1", TARGET + "/files/doc-1"),
            (TARGET + "/files/%5BREDACTED%5D-1001-%5BREDACTED%5D", TARGET + "/files/%5BREDACTED%5D-1001-%5BREDACTED%5D"),
        ]
        for keyed in (True, False):
            for left, right in pairs:
                with self.subTest(keyed=keyed, left=left, right=right):
                    ctx = self.context if keyed else None
                    flags = {} if keyed else UNKEYED
                    issue = _issue(_report(ctx, "CONFIRMED", left), _report(ctx, "SECURE", right), **flags)
                    scope = {"resources_changed", "scope_unknown"} & set(issue.get("reasons", ()))
                    result, _ = self.gate_result(left, right, allow=not keyed, **flags)
                    if scope:
                        self.assertEqual(result, "unverified")
                    else:
                        self.assertEqual(result, "passed")

    def test_the_gate_is_not_relaxed_where_only_redaction_differs(self) -> None:
        # diff matches one redacted side against the other on keyed fingerprints; the gate keeps its
        # stricter rule for accepted access and does not pass a resource it cannot read in both reports.
        left, right = TARGET + "/files/[REDACTED]-1001", TARGET + "/files/segsecret-0001-1001"
        self.assertEqual(self.gate_result(left, right), ("unverified", ["accepted_after_declaration_change"]))


class ShortSecretOperationKeyTests(unittest.TestCase):
    """Item 6: a short configured value only redacts a whole path segment or a whole operationId."""

    def test_operation_templates(self) -> None:
        cases = [
            ("GET /users/{id}/status", ("us",), "GET /users/{id}/status"),
            ("GET /users/{id}/status", ("Bearer us",), "GET /users/{id}/status"),
            ("GET /regions/us/items", ("us",), "GET /regions/[REDACTED]/items"),
            ("GET /regions/{us}/items", ("us",), "GET /regions/{[REDACTED]}/items"),
            ("GET /api/x-LONGSECRET-9/items", ("LONGSECRET-9",), "GET /api/x-[REDACTED]/items"),
            ("GET /api/{x-LONGSECRET-9}", ("LONGSECRET-9",), "GET /api/{x-[REDACTED]}"),
            ("GET /orders/{id}", ("us", "id"), "GET /orders/{[REDACTED]}"),
            ("POST /us", ("us",), "POST /[REDACTED]"),
        ]
        for operation, secrets, expected in cases:
            with self.subTest(operation=operation, secrets=secrets):
                self.assertEqual(sanitize_operation_key(operation, secrets), expected)

    def test_operation_ids(self) -> None:
        cases = [
            ("getUserStatus", ("us",), "getUserStatus"),
            ("us", ("us",), "[REDACTED]"),
            ("readLONGSECRET-9", ("LONGSECRET-9",), "read[REDACTED]"),
            ("getUserStatus", (), "getUserStatus"),
        ]
        for value, secrets, expected in cases:
            with self.subTest(value=value, secrets=secrets):
                self.assertEqual(evidence.sanitize_operation_id(value, secrets), expected)

    def test_sarif_endpoint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gt-sarif-") as folder:
            output = Path(folder) / "r.sarif"
            SarifReportGenerator.generate(
                results=[{"endpoint": "GET /users/{id}/status", "check": "BOLA", "verdict": "CONFIRMED",
                          "evidence": {}},
                         {"endpoint": "GET /regions/us/items", "check": "BOLA", "verdict": "CONFIRMED",
                          "evidence": {}}],
                target_url=TARGET, output_path=str(output), secret_values=("us", "Bearer LONGSECRET-9"))
            sarif = json.loads(output.read_text(encoding="utf-8"))
        endpoints = [item["properties"].get("endpoint") for item in sarif["runs"][0]["results"]]
        self.assertEqual(endpoints, ["GET /users/{id}/status", "GET /regions/[REDACTED]/items"])


def _auditor(folder: Path, bopla: bool = False) -> APISentinelAuditor:
    spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearer": []}],
            "paths": {"/users/{id}": {"get": {"operationId": "getUser", "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}}}}}}
    path = folder / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    bopla_config = {"GET /users/{id}": {
        "policy_id": "p", "context_id": "c", "resource_binding": {"id": "1001"},
        "fields": [{"rule_id": "r", "path": "email", "baseline_representation": "full_private_value",
                    "value_is_resource_specific": True,
                    "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}} if bopla else None
    return APISentinelAuditor(str(path), TARGET, request_delay=0, max_workers=1, bopla_config=bopla_config,
                              identities_config={"owner": {"id": "1001", "token": "Bearer OWNER-oid-0001"},
                                                 "visitor": {"id": "1002", "token": "Bearer VISITOR-oid-0002"},
                                                 "anonymous": {},
                                                 "roles": {"ops": {"role": "ops", "token": "Bearer ROLE-oid-3",
                                                                   "headers": {"X-Region": "us"}}}})


class OperationIdTypeTests(unittest.TestCase):
    """Item 7: the operationId keeps its JSON type; only text is sanitized."""

    def test_record_keeps_type_and_value(self) -> None:
        cases: List[Tuple[Dict[str, Any], Any]] = [
            ({"operation_id": None}, None),
            ({"operation_id": 7}, 7),
            ({"operation_id": 2.5}, 2.5),
            ({"operation_id": True}, True),
            ({"operation_id": "getUserStatus"}, "getUserStatus"),
            ({"operation_id": "us"}, "[REDACTED]"),
            ({}, ""),
        ]
        for bopla in (False, True):
            with tempfile.TemporaryDirectory(prefix="gt-opid-") as folder:
                auditor = _auditor(Path(folder), bopla=bopla)
                for extra, expected in cases:
                    with self.subTest(bopla=bopla, operation_id=extra.get("operation_id", "<missing>")):
                        ep = {"method": "GET", "path": "/users/{id}", **extra}
                        auditor._record_result(ep, "BOLA", Verdict.SECURE, "denied",
                                               evidence={"requests_attempted": 1})
                        recorded = auditor.results[-1]
                        self.assertIn("operation_id", recorded)
                        self.assertEqual(recorded["operation_id"], expected)
                        self.assertIs(type(recorded["operation_id"]), type(expected))
                        self.assertEqual(recorded["endpoint"], "GET /users/{id}")


class _Api(BaseHTTPRequestHandler):
    """Loopback API: every authenticated caller reads every user and document."""

    fixed = False
    owners = {"Bearer OWNER-short-0001", "Bearer OWNER-doc-0001"}
    visitors = {"Bearer VISITOR-short-0002", "Bearer VISITOR-doc-0002"}
    others = {"Bearer ADMIN-short-0003"}

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        auth = self.headers.get("Authorization") or ""
        resource = self.path.split("?")[0].rstrip("/").split("/")
        if auth not in self.owners | self.visitors | self.others:
            code, doc = 401, {"error": "unauthorized"}
        elif type(self).fixed and auth in self.visitors and resource[-1] not in ("1002", "doc-2002"):
            code, doc = 403, {"error": "forbidden"}
        else:
            name = resource[-1] if resource[-1] != "status" else resource[-2]
            code, doc = 200, {"id": name, "email": f"{name}@example.test", "state": "active"}
        data = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _LoopbackScans(unittest.TestCase):
    def setUp(self) -> None:
        _Api.fixed = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.target = f"http://127.0.0.1:{self.server.server_address[1]}"
        temp = tempfile.TemporaryDirectory(prefix="gt-hardening-")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)

    def scan(self, name: str, spec: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, str]:
        spec_path, config_path = self.folder / f"{name}.spec.json", self.folder / f"{name}.config.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        out = {kind: str(self.folder / f"{name}.{kind}") for kind in ("html", "json", "sarif")}
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"GRANTTRACE_COMPARISON_KEY": KEY}), \
                patch("urllib.request.getproxies", return_value={}), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = api_sentinel.main(["--spec", str(spec_path), "--config", str(config_path), "--target", self.target,
                                      "--delay", "0", "--output", out["html"], "--export-json", out["json"],
                                      "--export-sarif", out["sarif"]])
        self.assertIn(code, (0, 1), stdout.getvalue()[-2000:] + stderr.getvalue()[-2000:])
        out.update(stdout=stdout.getvalue(), stderr=stderr.getvalue())
        return out


STATUS_SPEC = {
    "openapi": "3.0.3", "info": {"title": "status", "version": "1"},
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearer": []}],
    "paths": {"/users/{id}/status": {"get": {"operationId": "getUserStatus", "parameters": [
        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "OK"}}}}}}


def _status_config(bopla: bool) -> Dict[str, Any]:
    config: Dict[str, Any] = {
        "identities": {
            "owner": {"id": "1001", "token": "Bearer OWNER-short-0001"},
            "visitor": {"id": "1002", "token": "Bearer VISITOR-short-0002"},
            "anonymous": {"id": None, "token": None},
            "roles": {"admin": {"role": "administrator", "token": "Bearer ADMIN-short-0003",
                                "headers": {"X-Region": "us"}}}},
        "bola": {"GET /users/{id}/status": {"private_data_paths": ["email"]}}}
    if bopla:
        config["bopla"] = {"GET /users/{id}/status": {
            "policy_id": "status-fields", "context_id": "owner-status", "resource_binding": {"id": "1001"},
            "fields": [{"rule_id": "email-owner-only", "path": "email",
                        "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                        "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}}
    return config


class ShortSecretEndToEndTests(_LoopbackScans):
    """Item 6 end to end: a two-letter role header value leaves every output's operation intact."""

    def test_outputs_keep_the_operation_and_its_id(self) -> None:
        for bopla in (False, True):
            with self.subTest(bopla=bopla):
                out = self.scan(f"short{int(bopla)}", STATUS_SPEC, _status_config(bopla))
                report = json.loads(Path(out["json"]).read_text(encoding="utf-8"))
                records = report["results"] + report["findings"]
                self.assertTrue(report["results"])
                self.assertEqual({item["endpoint"] for item in records}, {"GET /users/{id}/status"})
                self.assertEqual({item["operation_id"] for item in report["results"]}, {"getUserStatus"})
                self.assertEqual(sorted(report["comparison_context"]["operations"]), ["GET /users/{id}/status"])
                sarif = json.loads(Path(out["sarif"]).read_text(encoding="utf-8"))
                sarif_endpoints = {item["properties"].get("endpoint") for item in sarif["runs"][0]["results"]}
                self.assertEqual(sarif_endpoints, {"GET /users/{id}/status"})
                self.assertEqual({item["message"]["text"] for item in sarif["runs"][0]["results"]},
                                 {"Confirmed broken object level authorization at GET /users/{id}/status."})
                texts = {kind: Path(out[kind]).read_text(encoding="utf-8") for kind in ("html", "json", "sarif")}
                texts.update(stdout=out["stdout"], stderr=out["stderr"])
                for kind, text in texts.items():
                    for secret in ("OWNER-short-0001", "VISITOR-short-0002", "ADMIN-short-0003"):
                        self.assertNotIn(secret, text, kind)
                for kind in ("sarif", "stdout", "stderr"):
                    self.assertNotIn("GET /[REDACTED]ers", texts[kind], kind)
                self.assertIn("<code>GET /users/{id}/status</code>", texts["html"])
                self.assertNotIn("<code>GET /[REDACTED]", texts["html"])
                self.assertNotIn("getUserStat[REDACTED]", texts["html"] + texts["json"])
                # Evidence text stays redacted as before: the value is still replaced wherever it occurs there.
                urls = [item["evidence"]["target_url"] for item in report["results"]
                        if isinstance(item["evidence"].get("target_url"), str)]
                self.assertTrue(all("[REDACTED]" in url for url in urls), urls)


class ResourceIdentifierParameterTests(unittest.TestCase):
    """Item 8: resource identifiers are resource values; declared and credential-like names stay credentials."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="gt-resid-")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)

    def context(self, name: str, value: str, *, schemes: Optional[Dict[str, Any]] = None,
                auth_header: Optional[str] = None) -> Dict[str, Any]:
        """The comparison context of a scan, built as the CLI builds it from the auditor."""
        security = {"bearer": {"type": "http", "scheme": "bearer"}, **(schemes or {})}
        spec = {"openapi": "3.0.3", "info": {"title": "d", "version": "1"},
                "components": {"securitySchemes": security}, "security": [{"bearer": []}],
                "paths": {"/docs/{doc}": {"get": {"operationId": "getDoc", "parameters": [
                    {"name": "doc", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "OK"}}}}}}
        path = self.folder / "spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        identities: Dict[str, Any] = {"owner": {"id": "1", "token": "Bearer OWNER-T1"},
                                      "visitor": {"id": "2", "token": "Bearer VIS-V1"}, "anonymous": {}}
        if auth_header:
            for who, header_value in (("owner", "HDR-OWNER-0001"), ("visitor", "HDR-VISITOR-0002")):
                identities[who]["headers"] = {auth_header: header_value}
                identities[who]["auth_header_names"] = [auth_header]
        auditor = APISentinelAuditor(
            str(path), TARGET, request_delay=0, max_workers=1, identities_config=identities,
            parameter_values={"GET /docs/{doc}": {"owner": {name: value}, "visitor": {name: "doc-2002"}}})
        return build_comparison_context(
            key=KEY, target=TARGET, identities=auditor.identities, endpoints=auditor.parser.get_endpoints(),
            security_schemes=specification_security_schemes(auditor.parser.raw_spec),
            parameter_values=auditor.parameter_values, secret_values=auditor.config_secret_values())

    def classify(self, name: str, **declared: Any) -> str:
        before, after = self.context(name, "doc-1111", **declared), self.context(name, "doc-3333", **declared)
        credentials = before["credentials"] != after["credentials"]
        resources = (before["operations"]["GET /docs/{doc}"]["resources"]
                     != after["operations"]["GET /docs/{doc}"]["resources"])
        self.assertNotEqual(credentials, resources, name)
        return "credential" if credentials else "resource"

    def test_names(self) -> None:
        for name in ("session_id", "sessionId", "ticket_id", "token_id", "api_key_id", "secret_uuid", "uid"):
            with self.subTest(name=name):
                self.assertEqual(self.classify(name), "resource")
        for name in ("sid", "SID", "JSESSIONID", "session", "page_token", "ticket", "auth", "api_key",
                     "access_token", "password", "client_secret"):
            with self.subTest(name=name):
                self.assertEqual(self.classify(name), "credential")

    def test_declared_names_stay_credentials(self) -> None:
        for location in ("query", "header", "cookie"):
            with self.subTest(location=location):
                schemes = {"key": {"type": "apiKey", "in": location, "name": "session_id"}}
                self.assertEqual(self.classify("session_id", schemes=schemes), "credential")
        self.assertEqual(self.classify("ticket-id", auth_header="Ticket-Id"), "credential")
        self.assertEqual(self.classify("ticket_id", auth_header="Other-Key"), "resource")

    def test_auditor_secret_sets(self) -> None:
        def build(folder: Path, declare: bool) -> APISentinelAuditor:
            schemes: Dict[str, Any] = {"bearer": {"type": "http", "scheme": "bearer"}}
            if declare:
                schemes["sessionKey"] = {"type": "apiKey", "in": "query", "name": "session_id"}
            spec = {"openapi": "3.0.3", "info": {"title": "d", "version": "1"},
                    "components": {"securitySchemes": schemes}, "security": [{"bearer": []}],
                    "paths": {"/docs/{session_id}": {"get": {"operationId": "getDoc", "parameters": [
                        {"name": "session_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "OK"}}}}}}
            path = folder / f"spec{int(declare)}.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            return APISentinelAuditor(
                str(path), TARGET, request_delay=0, max_workers=1,
                identities_config={"owner": {"id": "1", "token": "Bearer OWNER-T1"},
                                   "visitor": {"id": "2", "token": "Bearer VIS-V1"}, "anonymous": {}},
                parameter_values={"GET /docs/{session_id}": {"owner": {"session_id": "doc-1111"},
                                                             "visitor": {"session_id": "doc-2002"}}})
        with tempfile.TemporaryDirectory(prefix="gt-resid-") as folder:
            plain = build(Path(folder), declare=False)
            self.assertNotIn("doc-1111", plain.config_secret_values())
            # Output redaction stays as conservative as before: the value is still never printed.
            self.assertIn("doc-1111", plain.secret_values())
            declared = build(Path(folder), declare=True)
            self.assertIn("doc-1111", declared.config_secret_values())
            self.assertIn("doc-1111", declared.secret_values())


DOCS_SPEC = {
    "openapi": "3.0.3", "info": {"title": "docs", "version": "1"},
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearer": []}],
    "paths": {"/users/{id}": {"get": {"operationId": "getUser", "parameters": [
        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "OK"}}}},
        "/docs/{session_id}": {"get": {"operationId": "getDoc", "parameters": [
            {"name": "session_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "responses": {"200": {"description": "OK"}}}}}}


def _docs_config(doc: str) -> Dict[str, Any]:
    return {"identities": {"owner": {"id": "1001", "token": "Bearer OWNER-doc-0001"},
                           "visitor": {"id": "1002", "token": "Bearer VISITOR-doc-0002"},
                           "anonymous": {"id": None, "token": None}},
            "parameter_values": {"GET /docs/{session_id}": {"owner": {"session_id": doc},
                                                             "visitor": {"session_id": "doc-2002"}}},
            "bola": {"GET /users/{id}": {"private_data_paths": ["email"]},
                     "GET /docs/{session_id}": {"private_data_paths": ["email"]}}}


class ResourceIdentifierEndToEndTests(_LoopbackScans):
    def test_another_document_is_a_resource_change_not_a_credential_change(self) -> None:
        baseline = self.scan("base", DOCS_SPEC, _docs_config("doc-1111"))
        _Api.fixed = True
        current = self.scan("cur", DOCS_SPEC, _docs_config("doc-3333"))
        comparison = compare_reports(load_report(baseline["json"]), load_report(current["json"]))
        comparability = comparison["comparability"]
        self.assertEqual(comparability["blocking"], [])
        self.assertNotIn("credentials_changed", [change.get("cause") for change in comparability["changes"]])
        changes = {item["operation"]: item["reasons"] for item in comparability["operation_changes"]}
        self.assertIn("resources_changed", changes.get("GET /docs/{session_id}", []))
        self.assertNotIn("GET /users/{id}", changes)
        statuses = {issue["operation"]: issue["status"] for issue in comparison["issues"]}
        self.assertEqual(statuses["GET /users/{id}"], "resolved")
        self.assertEqual(statuses["GET /docs/{session_id}"], "not_comparable")
        for out in (baseline, current):
            for kind in ("html", "json", "sarif"):
                text = Path(out[kind]).read_text(encoding="utf-8")
                for value in ("doc-1111", "doc-3333", "OWNER-doc-0001", "VISITOR-doc-0002"):
                    self.assertNotIn(value, text, kind)


if __name__ == "__main__":
    unittest.main()
