"""P0-01: a safe OpenAPI path template must never certify the concrete request built from it.

v2.7.1 checked the concrete GET/HEAD path only when no documented template
matched it. A request that matched a safe template (``GET /reports/{kind}``)
skipped the concrete check, so a value filled from enum/example/default/const,
``parameter_values`` or identity configuration could produce
``GET /reports/delete`` and reach the server, while the same path written
literally was refused.

Every scenario drives the real auditor, transport or CLI against a loopback
server that records each request that actually arrives. The server's oracle is
independent of ``core.scan_safety``: it decodes and splits the received target
itself and flags a request whose path segment starts with an action word that
the v2.7.1 read-only vocabulary already refuses in a literal GET path. Nothing
here contacts a host other than 127.0.0.1.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import tempfile
import threading
import unittest
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch
from urllib.parse import quote, unquote, urlsplit

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.models import HTTPResult
from core.parameters import ParameterSerializationError
from core.transport import HttpTransport

# ---------------------------------------------------------------------------
# Independent loopback oracle
# ---------------------------------------------------------------------------

# Action words the scenarios use. Each one is refused by the v2.7.1 GET/HEAD
# vocabulary when it starts a literal path segment; the oracle does not import it.
ORACLE_ACTIONS = frozenset({
    "delete", "create", "cancel", "reset", "terminate", "submit", "revoke",
    "remove", "transfer", "publish", "execute",
})


def oracle_is_side_effect(target: str) -> bool:
    """Whether a received request target names a scenario action, as a lenient router may decode it."""
    path = urlsplit(target).path
    for _ in range(8):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    for piece in re.split(r"[/;\\]", path):
        words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", piece).lower()
        tokens = [token for token in re.split(r"[^a-z0-9]+", words) if token]
        if tokens and tokens[0] in ORACLE_ACTIONS:
            return True
    return False


class LoopbackServer:
    """Records every request that reaches 127.0.0.1 and answers with an ordinary JSON object."""

    def __init__(self) -> None:
        self.records: List[Tuple[str, str]] = []
        self.lock = threading.Lock()
        self.limited: Dict[str, int] = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def reply(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                with owner.lock:
                    owner.records.append((self.command, self.path))
                    remaining_limits = owner.limited.get(urlsplit(self.path).path, 0)
                    if remaining_limits:
                        owner.limited[urlsplit(self.path).path] = remaining_limits - 1
                if remaining_limits:
                    self.send_response(429)
                    self.send_header("Retry-After", "0")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if urlsplit(self.path).path.endswith("/redirect-elsewhere"):
                    self.send_response(302)
                    self.send_header("Location", urlsplit(self.path).path.rsplit("/", 1)[0] + "/delete")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps({"id": "1001", "owner": "alice", "title": "Quarterly report",
                                   "private_note": "owner-only-note"}).encode("utf-8")
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
            self.records.clear()
            self.limited.clear()

    def snapshot(self) -> List[Tuple[str, str]]:
        with self.lock:
            return list(self.records)

    def side_effect_hits(self) -> List[Tuple[str, str]]:
        return [record for record in self.snapshot() if oracle_is_side_effect(record[1])]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Specification and scenario helpers
# ---------------------------------------------------------------------------

def path_param(name: str, schema: Optional[Dict[str, Any]] = None, **extra: Any) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {"name": name, "in": "path", "required": True,
                                "schema": schema if schema is not None else {"type": "string"}}
    metadata.update(extra)
    return metadata


def get_operation(parameters: Tuple[Dict[str, Any], ...], operation_id: str = "getRecordView") -> Dict[str, Any]:
    return {"get": {"operationId": operation_id, "summary": "Read one record view",
                    "security": [{"bearer": []}], "parameters": list(parameters),
                    "responses": {"200": {"description": "The record"}}}}


def write_spec(folder: Path, paths: Dict[str, Any], name: str = "openapi.json") -> Path:
    spec = {"openapi": "3.0.3", "info": {"title": "P0-01 regression", "version": "1.0.0"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "paths": paths}
    target = folder / name
    target.write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
    return target


def identities(owner_parameters: Optional[Dict[str, Any]] = None,
               visitor_parameters: Optional[Dict[str, Any]] = None,
               owner_id: str = "1001", visitor_id: str = "1002") -> Dict[str, Any]:
    return {
        "owner": {"id": owner_id, "token": "Bearer P0-01-OWNER-TOKEN", "parameters": owner_parameters or {}},
        "visitor": {"id": visitor_id, "token": "Bearer P0-01-VISITOR-TOKEN",
                    "parameters": visitor_parameters or {}},
        "anonymous": {"id": None, "token": None, "parameters": {}},
    }


@dataclass(frozen=True)
class Scenario:
    sid: str
    category: str
    title: str
    path: str
    parameters: Tuple[Dict[str, Any], ...]
    blocked: bool
    prefix: str = ""
    parameter_values: Optional[Dict[str, Any]] = None
    identities: Dict[str, Any] = field(default_factory=identities)
    # True when v2.7.1 already refuses the same concrete path written literally.
    literal_refused_by_v271: bool = True

    @property
    def operation_key(self) -> str:
        return "GET " + self.path


KIND = "/reports/{kind}"


def kind(schema: Optional[Dict[str, Any]] = None, **extra: Any) -> Tuple[Dict[str, Any], ...]:
    return (path_param("kind", schema, **extra),)


def value(text: str) -> Dict[str, Any]:
    return {"kind": text}


BLOCKED_SCENARIOS: Tuple[Scenario, ...] = (
    # Parameter value sources
    Scenario("S01", "source", "schema enum selects an action word", KIND,
             kind({"type": "string", "enum": ["delete", "summary"]}), True),
    Scenario("S02", "source", "parameter example", KIND, kind(example="cancel"), True),
    Scenario("S03", "source", "parameter examples map", KIND,
             kind(examples={"first": {"value": "reset"}}), True),
    Scenario("S04", "source", "schema example", KIND, kind({"type": "string", "example": "terminate"}), True),
    Scenario("S05", "source", "schema default", KIND, kind({"type": "string", "default": "submit"}), True),
    Scenario("S06", "source", "schema const", KIND, kind({"type": "string", "const": "revoke"}), True),
    Scenario("S07", "source", "parameter_values flat value", KIND, kind(), True,
             parameter_values=value("delete")),
    Scenario("S08", "source", "parameter_values common value", KIND, kind(), True,
             parameter_values={"common": value("remove")}),
    Scenario("S09", "source", "parameter_values owner-scoped value", KIND, kind(), True,
             parameter_values={"owner": value("delete"), "visitor": value("summary")}),
    Scenario("S10", "source", "parameter_values visitor-scoped value", KIND, kind(), True,
             parameter_values={"owner": value("summary"), "visitor": value("delete")}),
    Scenario("S11", "source", "identity parameters", KIND, kind(), True,
             identities=identities(value("transfer"), value("summary"))),
    Scenario("S12", "source", "identity id for a resource identifier", "/accounts/{account_id}",
             (path_param("account_id"),), True, identities=identities(owner_id="delete")),
    # Template shapes
    Scenario("T01", "template", "multi-level template, action in the last level",
             "/orgs/{org}/projects/{project}/{view}",
             (path_param("org", example="acme"), path_param("project", example="p-7"),
              path_param("view", {"type": "string", "enum": ["remove"]})), True),
    Scenario("T02", "template", "adjacent placeholders", "/files/{folder}/{name}",
             (path_param("folder", example="shared"), path_param("name", example="create_report")), True),
    Scenario("T03", "template", "placeholder inside a segment", "/exports/{name}.json",
             (path_param("name", example="delete"),), True),
    Scenario("T04", "template", "identity-bound multi-level template", "/tenants/{tenant}/records/{record_id}/{view}",
             (path_param("tenant", example="acme"), path_param("record_id"),
              path_param("view", example="publish")), True),
    # URL encoding and normalization
    Scenario("U01", "encoding", "upper-case value", KIND, kind(example="DELETE"), True),
    Scenario("U02", "encoding", "camelCase value", KIND, kind(example="deleteAll"), True),
    Scenario("U03", "encoding", "hyphenated value", KIND, kind(example="delete-all"), True),
    Scenario("U04", "encoding", "trailing space value", KIND, kind(example="delete "), True),
    Scenario("U05", "encoding", "value with an interior encoded slash", KIND, kind(example="monthly/delete"), True),
    Scenario("U06", "encoding", "value with a literal percent escape (nested escape)", KIND,
             kind(example="%64elete"), True),
    Scenario("U07", "encoding", "dot-segment value", KIND, kind(example="../delete"), True),
    Scenario("U08", "encoding", "encoded semicolon before an action piece", KIND,
             kind(example="summary;delete"), True, literal_refused_by_v271=False),
    # Target base URL with a path prefix
    Scenario("B01", "prefix", "target prefix /api/v1", KIND, kind({"type": "string", "enum": ["delete"]}), True,
             prefix="/api/v1"),
    Scenario("B02", "prefix", "root-level template under a prefix", "/{kind}", kind(example="delete"), True,
             prefix="/api"),
    Scenario("B03", "prefix", "specification path repeats the prefix", "/api/{kind}", kind(example="delete"), True,
             prefix="/api"),
    Scenario("B04", "prefix", "deep prefix with default value", KIND, kind({"type": "string", "default": "cancel"}),
             True, prefix="/gateway/tenant-a/api/v2"),
)

POLYSEMOUS_VALUES = (
    "created", "updated_at", "deleted-items", "startup", "enabled-features", "payments", "savings",
    "cancellations", "scheduled", "publisher", "running", "refunds", "confirmations", "accepted",
    "history", "report.v1", "a/b", "汉 字", "100% complete", "item;id=normal", "export", "preview",
)

ALLOWED_SCENARIOS: Tuple[Scenario, ...] = (
    Scenario("N01", "negative", "numeric identity resource ids", "/items/{item_id}", (path_param("item_id"),), False),
    Scenario("N02", "negative", "UUID resource ids from parameter_values", "/documents/{doc_uuid}",
             (path_param("doc_uuid", {"type": "string", "format": "uuid"}),), False,
             parameter_values={"owner": {"doc_uuid": "550e8400-e29b-41d4-a716-446655440000"},
                               "visitor": {"doc_uuid": "7d444840-9dc0-11d1-b245-5ffdce74fad2"}}),
    Scenario("N03", "negative", "enum whose first member is a read view", KIND,
             kind({"type": "string", "enum": ["summary", "delete"]}), False),
    Scenario("N04", "negative", "prefix containing an action-like word", KIND, kind(example="summary"), False,
             prefix="/upload-gateway/api"),
    Scenario("N05", "negative", "polysemous literal template segments", "/reports/{report_id}/created-by",
             (path_param("report_id"),), False),
    Scenario("N06", "negative", "multi-level benign template", "/orgs/{org}/projects/{project}/{view}",
             (path_param("org", example="acme"), path_param("project", example="p-7"),
              path_param("view", {"type": "string", "enum": ["history"]})), False, prefix="/api/v1"),
) + tuple(
    Scenario(f"N10-{index:02d}", "negative", f"polysemous value {text!r}", KIND, kind(), False,
             parameter_values=value(text))
    for index, text in enumerate(POLYSEMOUS_VALUES, start=1)
)


class LoopbackTestCase(unittest.TestCase):
    server: LoopbackServer

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = LoopbackServer()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.close()

    def setUp(self) -> None:
        self.server.clear()
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-p0-01-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def scenario_auditor(self, scenario: Scenario, **options: Any) -> Tuple[APISentinelAuditor, Dict[str, Any]]:
        spec = write_spec(self.folder, {scenario.path: get_operation(scenario.parameters)}, f"{scenario.sid}.json")
        auditor = APISentinelAuditor(
            str(spec), self.server.origin + scenario.prefix, request_delay=0, max_workers=1,
            identities_config=scenario.identities,
            parameter_values={scenario.operation_key: scenario.parameter_values} if scenario.parameter_values else None,
            **options,
        )
        endpoint = next(item for item in auditor.parser.get_endpoints() if item["path"] == scenario.path)
        return auditor, endpoint


# ---------------------------------------------------------------------------
# Python API: BOLA object checks built from safe templates
# ---------------------------------------------------------------------------

class TemplateShadowingApiTests(LoopbackTestCase):
    def test_unsafe_concrete_values_never_reach_the_server(self) -> None:
        for scenario in BLOCKED_SCENARIOS:
            with self.subTest(scenario=scenario.sid, title=scenario.title):
                self.server.clear()
                auditor, endpoint = self.scenario_auditor(scenario)
                auditor.audit_endpoint_bola(endpoint)
                self.assertEqual(self.server.side_effect_hits(), [], "a state-changing request arrived")
                self.assertEqual(self.server.snapshot(), [], "the unsafe comparison must send nothing")
                self.assertEqual(auditor.stats["http_requests_sent"], 0)
                self.assertEqual(auditor.stats["transport_attempts"], 0)
                self.assertEqual(auditor.findings, [])
                self.assertEqual(len(auditor.results), 1)
                result = auditor.results[0]
                self.assertEqual(result["verdict"], "SKIPPED")
                self.assertNotIn(result["verdict"], {"SECURE", "CONFIRMED"})
                self.assertEqual(result["evidence"]["reason_category"], "safety_policy")
                self.assertIn(result["evidence"]["safety_signal"], {"path", "path_ambiguity"})
                self.assertEqual(result["evidence"]["requests_attempted"], 0)
                self.assertIn("no request was sent", result["reason"])

    def test_both_identity_urls_are_refused_before_transport(self) -> None:
        for scenario in BLOCKED_SCENARIOS:
            with self.subTest(scenario=scenario.sid):
                auditor, endpoint = self.scenario_auditor(scenario)
                owner_url = auditor._build_url(endpoint, "owner")
                visitor_url = auditor._build_url(endpoint, "visitor")
                unsafe = [url for url in (owner_url, visitor_url)
                          if oracle_is_side_effect(urlsplit(url).path[len(scenario.prefix):])]
                self.assertTrue(unsafe, "scenario must build at least one unsafe concrete URL")
                for url in unsafe:
                    for method in ("GET", "HEAD"):
                        self.assertIsNotNone(auditor._read_request_risk(method, url), (method, url))
                        self.assertIsNotNone(auditor._request_risk(method, url), (method, url))
                        result = auditor._http_request(method, url, identity_name="owner")
                        self.assertEqual(result.status, 0)
                        self.assertIn("no request was sent", result.error or "")
                self.assertEqual(self.server.snapshot(), [])

    def test_explicit_and_parameterized_paths_get_the_same_decision(self) -> None:
        bare_spec = write_spec(self.folder, {"/health": get_operation((), "getHealth")}, "bare.json")
        for scenario in BLOCKED_SCENARIOS:
            if not scenario.literal_refused_by_v271:
                continue
            with self.subTest(scenario=scenario.sid):
                auditor, endpoint = self.scenario_auditor(scenario)
                target = self.server.origin + scenario.prefix
                bare = APISentinelAuditor(str(bare_spec), target, request_delay=0)
                for identity in ("owner", "visitor"):
                    url = auditor._build_url(endpoint, identity)
                    relative = urlsplit(url).path[len(urlsplit(target).path):]
                    if not oracle_is_side_effect(relative):
                        continue
                    literal_url = target + quote(unquote(relative), safe="/;")
                    explicit = bare._read_request_risk("GET", literal_url)
                    parameterized = auditor._read_request_risk("GET", url)
                    self.assertIsNotNone(explicit, "precondition: v2.7.1 refuses the literal path")
                    self.assertIsNotNone(parameterized, "a safe template certified an unsafe value")
                    self.assertEqual(parameterized["safety_signal"] == "path_ambiguity",
                                     explicit["safety_signal"] == "path_ambiguity"
                                     or parameterized["safety_signal"] == "path_ambiguity")
        self.assertEqual(self.server.snapshot(), [])

    def test_legitimate_parameterized_reads_still_execute(self) -> None:
        for scenario in ALLOWED_SCENARIOS:
            with self.subTest(scenario=scenario.sid, title=scenario.title):
                self.server.clear()
                auditor, endpoint = self.scenario_auditor(scenario)
                owner_url = auditor._build_url(endpoint, "owner")
                self.assertIsNone(auditor._read_request_risk("GET", owner_url), owner_url)
                auditor.audit_endpoint_bola(endpoint)
                arrivals = self.server.snapshot()
                self.assertGreaterEqual(len(arrivals), 3, "Owner, cross-Visitor and Anonymous reads must arrive")
                self.assertEqual(self.server.side_effect_hits(), [])
                self.assertTrue(all(method == "GET" for method, _ in arrivals))
                result = auditor.results[0]
                self.assertNotEqual(result["evidence"].get("reason_category"), "safety_policy")
                self.assertGreater(result["evidence"]["requests_attempted"], 0)

    def test_head_requests_follow_the_get_decision(self) -> None:
        unsafe, _ = self.scenario_auditor(BLOCKED_SCENARIOS[0])
        url = unsafe._build_url(unsafe.parser.get_endpoints()[0], "owner")
        self.assertEqual(unsafe._http_request("HEAD", url, identity_name="owner").status, 0)
        safe, endpoint = self.scenario_auditor(ALLOWED_SCENARIOS[0])
        self.assertEqual(safe._http_request("HEAD", safe._build_url(endpoint, "owner"), identity_name="owner").status,
                         200)
        self.assertEqual(self.server.snapshot(), [("HEAD", "/items/1001")])

    def test_safe_template_cannot_shadow_an_explicitly_unsafe_documented_route(self) -> None:
        # Both a safe template and an unsafe literal match /reports/delete; the
        # unsafe decision must win whatever order the specification lists them.
        for order in (("/reports/{kind}", "/reports/delete"), ("/reports/delete", "/reports/{kind}")):
            with self.subTest(order=order):
                paths = {}
                for path in order:
                    paths[path] = (get_operation(kind(), "getReport") if "{" in path
                                   else get_operation((), "deleteReport"))
                spec = write_spec(self.folder, paths, "order.json")
                auditor = APISentinelAuditor(str(spec), self.server.origin, request_delay=0)
                risk = auditor._read_request_risk("GET", self.server.origin + "/reports/delete")
                self.assertIsNotNone(risk)
        self.assertEqual(self.server.snapshot(), [])

    def test_unparseable_request_url_is_refused_without_raising(self) -> None:
        auditor, _ = self.scenario_auditor(ALLOWED_SCENARIOS[0])
        for url in ("http://[::1/reports/delete", "http://127.0.0.1:99999999/reports/delete"):
            with self.subTest(url=url):
                self.assertIsNotNone(auditor._read_request_risk("GET", url))
                result = auditor._http_request("GET", url, identity_name="owner")
                self.assertEqual(result.status, 0)
        self.assertEqual(self.server.snapshot(), [])


# ---------------------------------------------------------------------------
# Other auditor flows that read with a concrete URL
# ---------------------------------------------------------------------------

class _StateAuthorityAuditor(APISentinelAuditor):
    """Test double: claims independent write-state authority so preflight reaches the readback."""

    def _authoritative_patch_state(self, ep: Dict[str, Any], mutation_url: str,
                                   readback: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return {"id": "1002", "role": "user"}


class OtherFlowTests(LoopbackTestCase):
    def test_full_run_skips_only_the_unsafe_operation(self) -> None:
        spec = write_spec(self.folder, {
            KIND: get_operation(kind({"type": "string", "enum": ["delete"]}), "getReport"),
            "/items/{item_id}": get_operation((path_param("item_id"),), "getItem"),
        })
        auditor = APISentinelAuditor(str(spec), self.server.origin, request_delay=0, max_workers=2,
                                     identities_config=identities())
        with contextlib.redirect_stdout(io.StringIO()):
            auditor.run()
        self.assertEqual(self.server.side_effect_hits(), [])
        self.assertTrue(any(path.startswith("/items/") for _, path in self.server.snapshot()))
        by_endpoint = {item["endpoint"]: item for item in auditor.results if item["check"] == "BOLA"}
        unsafe = by_endpoint["GET " + KIND]
        self.assertEqual(unsafe["verdict"], "SKIPPED")
        self.assertEqual(unsafe["evidence"]["reason_category"], "safety_policy")
        self.assertNotEqual(by_endpoint["GET /items/{item_id}"]["verdict"], "SKIPPED")

    def test_bopla_property_check_refuses_unsafe_concrete_get(self) -> None:
        scenario = BLOCKED_SCENARIOS[0]
        policy = {"policy_id": "report-fields-v1", "context_id": "selected-owner-report",
                  "resource_binding": {"id": "1001"},
                  "fields": [{"rule_id": "owner-note", "path": "private_note",
                              "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                              "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}
        auditor, endpoint = self.scenario_auditor(scenario, bopla_config={scenario.operation_key: policy})
        auditor.audit_endpoint_bola(endpoint)
        self.assertEqual(self.server.snapshot(), [])
        self.assertEqual(auditor.findings, [])
        bopla = [item for item in auditor.results if item["check"] == "BOPLA"]
        self.assertTrue(bopla)
        self.assertTrue(all(item["verdict"] == "SKIPPED" for item in bopla))
        self.assertTrue(all(item["evidence"]["reason_category"] == "safety_policy" for item in bopla))

    def test_patch_readback_with_unsafe_concrete_value_sends_nothing(self) -> None:
        for source, readback_values, parameters in (
            ("readback parameter_values", {"kind": "delete"}, kind()),
            ("readback template example", None, kind(example="delete")),
        ):
            with self.subTest(source=source):
                self.server.clear()
                spec = write_spec(self.folder, {
                    KIND: get_operation(parameters, "getReport"),
                    "/settings/{id}": {"patch": {
                        "operationId": "updateSettings", "security": [{"bearer": []}],
                        "parameters": [path_param("id")],
                        "requestBody": {"content": {"application/json": {"schema": {
                            "type": "object", "properties": {"role": {
                                "type": "string", "readOnly": True, "enum": ["user", "admin"]}}}}}},
                        "responses": {"200": {"description": "ok"}}}},
                }, "readback.json")
                mapping: Dict[str, Any] = {"method": "GET", "path": KIND, "field_map": {"role": "role"},
                                           "consistency": "strong"}
                if readback_values is not None:
                    mapping["parameter_values"] = readback_values
                auditor = _StateAuthorityAuditor(
                    str(spec), self.server.origin, request_delay=0, identities_config=identities(),
                    allow_write_tests=True, write_allowlist=["PATCH /settings/{id}"],
                    readback_config={"PATCH /settings/{id}": mapping})
                endpoints = auditor.parser.get_endpoints()
                patch_endpoint = next(item for item in endpoints if item["method"] == "PATCH")
                auditor.audit_endpoint_mass_assignment(patch_endpoint, endpoints)
                self.assertEqual(self.server.snapshot(), [], "neither the readback GET nor the PATCH may be sent")
                with self.assertRaises(ParameterSerializationError):
                    auditor._readback_result(patch_endpoint, mapping, "visitor")
                self.assertEqual(self.server.snapshot(), [], "a direct readback must not be sent either")
                result = auditor.results[0]
                self.assertEqual(result["verdict"], "SKIPPED")
                self.assertEqual(result["evidence"]["reason_category"], "safety_policy")
                self.assertEqual(result["evidence"]["requests_attempted"], 0)
                operation = next(item for item in auditor.build_plan()["operations"]
                                 if item["check"] == "MASS_ASSIGNMENT")
                self.assertFalse(operation["writes_enabled"])
                self.assertTrue(operation["safety_blocked"])

    def test_plan_marks_unsafe_parameterized_operation_as_blocked(self) -> None:
        for scenario in BLOCKED_SCENARIOS:
            with self.subTest(scenario=scenario.sid):
                auditor, _ = self.scenario_auditor(scenario)
                plan = auditor.build_plan()
                entry = next(item for item in plan["operations"] if item["endpoint"] == scenario.operation_key)
                self.assertTrue(entry.get("safety_blocked"), entry)
                self.assertEqual(entry["reason_category"], "safety_policy")
                self.assertEqual(plan["requests_sent"], 0)
        for scenario in ALLOWED_SCENARIOS:
            with self.subTest(scenario=scenario.sid):
                auditor, _ = self.scenario_auditor(scenario)
                entry = next(item for item in auditor.build_plan()["operations"]
                             if item["endpoint"] == scenario.operation_key)
                self.assertFalse(entry.get("safety_blocked", False), entry)
        self.assertEqual(self.server.snapshot(), [])

    def test_read_only_post_controls(self) -> None:
        spec = write_spec(self.folder, {
            "/documents/search": {"post": {"operationId": "searchDocuments", "security": [{"bearer": []}],
                                           "responses": {"200": {"description": "ok"}}}},
            "/indexes/{index}/search": {"post": {"operationId": "searchIndex", "security": [{"bearer": []}],
                                                 "parameters": [path_param("index")],
                                                 "responses": {"200": {"description": "ok"}}}},
        })
        body_policy = {"read_only": True, "identity_bodies": {"owner": {"id": "1001"}, "visitor_self": {"id": "1002"}}}
        for index, blocked in (("products", False), ("delete", True)):
            with self.subTest(index=index):
                self.server.clear()
                auditor = APISentinelAuditor(
                    str(spec), self.server.origin, request_delay=0, identities_config=identities(),
                    parameter_values={"POST /indexes/{index}/search": {"index": index}},
                    bola_config={"POST /documents/search": body_policy, "POST /indexes/{index}/search": body_policy})
                for endpoint in auditor.parser.get_endpoints():
                    auditor.audit_endpoint_bola(endpoint)
                posted = {path for method, path in self.server.snapshot() if method == "POST"}
                self.assertIn("/documents/search", posted)
                self.assertEqual("/indexes/" + index + "/search" in posted, not blocked)
                self.assertEqual(self.server.side_effect_hits(), [])


# ---------------------------------------------------------------------------
# Transport layer and alternative entry points
# ---------------------------------------------------------------------------

class TransportEntryPointTests(LoopbackTestCase):
    def unsafe_auditor(self) -> Tuple[APISentinelAuditor, str]:
        auditor, endpoint = self.scenario_auditor(BLOCKED_SCENARIOS[0])
        return auditor, auditor._build_url(endpoint, "owner")

    def test_auditor_transport_send_refuses_unsafe_concrete_get(self) -> None:
        auditor, url = self.unsafe_auditor()
        events: List[str] = []
        result = auditor._transport.send("GET", url, {"authorization": "Bearer P0-01-OWNER-TOKEN"},
                                         on_attempt=lambda: events.append("attempt"))
        self.assertEqual(result.status, 0)
        self.assertEqual(events, [], "a refused request is not an attempt")
        self.assertEqual(self.server.snapshot(), [])

    def test_send_http_request_cannot_bypass_the_read_check(self) -> None:
        auditor, url = self.unsafe_auditor()
        result = auditor._send_http_request("GET", url, None, "owner", "application/json", None)
        self.assertEqual(result.status, 0)
        self.assertEqual(auditor.stats["transport_attempts"], 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_subclass_overriding_http_request_cannot_bypass_the_read_check(self) -> None:
        class Shortcut(APISentinelAuditor):
            def _http_request(self, method: str, url: str, data: Optional[Any] = None,
                              identity_name: str = "anonymous", content_type: str = "application/json",
                              headers: Optional[Dict[str, str]] = None) -> HTTPResult:
                return self._send_http_request(method, url, data, identity_name, content_type, headers)

        scenario = BLOCKED_SCENARIOS[0]
        spec = write_spec(self.folder, {scenario.path: get_operation(scenario.parameters)}, "shortcut.json")
        auditor = Shortcut(str(spec), self.server.origin, request_delay=0, identities_config=identities())
        endpoint = auditor.parser.get_endpoints()[0]
        self.assertEqual(auditor._http_request("GET", auditor._build_url(endpoint, "owner")).status, 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_standalone_transport_applies_the_concrete_read_policy(self) -> None:
        transport = HttpTransport(request_delay=0.0, request_timeout=3.0, max_response_bytes=4096,
                                  insecure_ssl=False)
        origin = self.server.origin
        for method, path in (("GET", "/reports/delete"), ("HEAD", "/reports/create_report"),
                             ("GET", "/reports/monthly%2Fdelete"), ("GET", "/reports/%2564elete"),
                             ("POST", "/documents/delete/lookup")):
            with self.subTest(method=method, path=path):
                self.assertEqual(transport.send(method, origin + path, {}, data={} if method == "POST" else None).status,
                                 0)
        self.assertEqual(self.server.snapshot(), [])
        for method, path, data in (("GET", "/reports/summary", None), ("GET", "/reports/deleted-items", None),
                                   ("POST", "/documents/search", {"id": "1001"}),
                                   ("PATCH", "/settings/1002", {"role": "user"})):
            with self.subTest(method=method, path=path):
                self.assertEqual(transport.send(method, origin + path, {}, data=data).status, 200)
        self.assertEqual(self.server.side_effect_hits(), [])

    def test_transport_guard_failure_fails_closed(self) -> None:
        auditor, endpoint = self.scenario_auditor(ALLOWED_SCENARIOS[0])
        url = auditor._build_url(endpoint, "owner")
        with patch.object(auditor, "_read_safety_snapshot", side_effect=RuntimeError("cache unavailable")):
            result = auditor._transport.send("GET", url, {})
        self.assertEqual(result.status, 0)
        self.assertEqual(self.server.snapshot(), [])

    def test_redirect_to_an_action_path_is_returned_not_followed(self) -> None:
        spec = write_spec(self.folder, {"/reports/{kind}/redirect-elsewhere": get_operation(kind(), "getReportLink")})
        auditor = APISentinelAuditor(str(spec), self.server.origin, request_delay=0, identities_config=identities(),
                                     parameter_values={"GET /reports/{kind}/redirect-elsewhere": value("summary")})
        auditor.audit_endpoint_bola(auditor.parser.get_endpoints()[0])
        self.assertTrue(self.server.snapshot())
        self.assertTrue(all(path == "/reports/summary/redirect-elsewhere" for _, path in self.server.snapshot()))
        self.assertEqual(self.server.side_effect_hits(), [])

    def test_rate_limit_retry_keeps_working_for_safe_reads(self) -> None:
        auditor, endpoint = self.scenario_auditor(ALLOWED_SCENARIOS[0])
        url = auditor._build_url(endpoint, "owner")
        with self.server.lock:
            self.server.limited[urlsplit(url).path] = 1
        result = auditor._http_request("GET", url, identity_name="owner")
        self.assertEqual(result.status, 200)
        self.assertEqual(auditor.stats["rate_limit_retries"], 1)
        self.assertEqual(self.server.snapshot(), [("GET", "/items/1001"), ("GET", "/items/1001")])


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

class CommandLineTests(LoopbackTestCase):
    def write_cli_inputs(self, prefix: str = "") -> Tuple[Path, Path]:
        spec = write_spec(self.folder, {
            KIND: get_operation(kind(), "getReport"),
            "/exports/{name}.json": get_operation((path_param("name", example="delete"),), "getExport"),
            "/items/{item_id}": get_operation((path_param("item_id"),), "getItem"),
        })
        config = self.folder / "config.json"
        config.write_text(json.dumps({
            "identities": identities(),
            "parameter_values": {"GET /reports/{kind}": {"owner": {"kind": "delete"}, "visitor": {"kind": "summary"}}},
        }), encoding="utf-8")
        return spec, config

    def test_cli_scan_reports_unsafe_operations_as_safety_skips(self) -> None:
        for prefix in ("", "/api/v1"):
            with self.subTest(prefix=prefix):
                self.server.clear()
                spec, config = self.write_cli_inputs(prefix)
                report = self.folder / f"report{len(prefix)}.json"
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = main(["--spec", str(spec), "--target", self.server.origin + prefix,
                                 "--config", str(config), "--delay", "0", "--workers", "1",
                                 "--output", str(self.folder / "report.html"), "--export-json", str(report)])
                self.assertEqual(code, 0)
                self.assertEqual(self.server.side_effect_hits(), [])
                arrived = {path for _, path in self.server.snapshot()}
                self.assertEqual(arrived, {prefix + "/items/1001", prefix + "/items/1002"})
                payload = json.loads(report.read_text(encoding="utf-8"))
                results = {item["endpoint"]: item for item in payload["results"] if item["check"] == "BOLA"}
                for key in ("GET /reports/{kind}", "GET /exports/{name}.json"):
                    self.assertEqual(results[key]["verdict"], "SKIPPED")
                    self.assertEqual(results[key]["evidence"]["reason_category"], "safety_policy")
                    self.assertEqual(results[key]["evidence"]["requests_attempted"], 0)
                self.assertNotEqual(results["GET /items/{item_id}"]["verdict"], "SKIPPED")
                self.assertFalse(any(item["endpoint"] != "GET /items/{item_id}" for item in payload["findings"]))
                self.assertEqual(payload["stats"]["http_requests_sent"], len(self.server.snapshot()))

    def test_cli_dry_run_plans_the_refusal_without_network(self) -> None:
        spec, config = self.write_cli_inputs()
        plan_path = self.folder / "plan.json"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                patch("socket.create_connection", side_effect=AssertionError("network")) as connection:
            code = main(["--spec", str(spec), "--target", self.server.origin, "--config", str(config),
                         "--dry-run", "--export-json", str(plan_path)])
        self.assertEqual(code, 0)
        connection.assert_not_called()
        plan = {item["endpoint"]: item for item in json.loads(plan_path.read_text(encoding="utf-8"))["operations"]}
        for key in ("GET /reports/{kind}", "GET /exports/{name}.json"):
            self.assertTrue(plan[key].get("safety_blocked"), plan[key])
            self.assertEqual(plan[key]["reason_category"], "safety_policy")
        self.assertFalse(plan["GET /items/{item_id}"].get("safety_blocked", False))
        self.assertEqual(self.server.snapshot(), [])


class OracleSelfTests(unittest.TestCase):
    def test_oracle_flags_scenario_actions_and_not_controls(self) -> None:
        for target in ("/reports/delete", "/api/v1/reports/DELETE", "/reports/monthly%2Fdelete",
                       "/reports/%2564elete", "/reports/deleteAll", "/reports/summary%3Bdelete",
                       "/files/shared/create_report", "/exports/delete.json"):
            self.assertTrue(oracle_is_side_effect(target), target)
        for text in POLYSEMOUS_VALUES:
            self.assertFalse(oracle_is_side_effect("/reports/" + quote(text, safe="")), text)
        self.assertFalse(oracle_is_side_effect("/upload-gateway/api/reports/summary"))


if __name__ == "__main__":
    unittest.main()
