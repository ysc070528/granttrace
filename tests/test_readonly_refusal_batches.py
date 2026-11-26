"""IND-01: "a refused request never yields SECURE, PUBLIC or AUTHORIZED", per observation batch.

One batch of Owner / Visitor / Anonymous observations is shared by several records: BOLA,
BROKEN_AUTH and BFLA (``_record_expanded_read_checks``), BOPLA_EXPOSURE, the BOPLA property
records, and the RBAC role records, which reuse the batch's Anonymous observation. The record
layer applied a policy refusal only to the first record written after it; every later record of
the same batch lost the structured refusal, and a refused observation read as a transport failure.

Contract pinned here:

* A record that depends on a refused observation carries ``safety_refusals`` (how many of the
  observations it depends on were refused), ``policy_layer``, ``safety_signal`` and
  ``refused_observations``, and is never SECURE, PUBLIC or AUTHORIZED.
* A record of the same batch that does not depend on the refused observation keeps the verdict
  its own, sent observations support, and says that its shared batch had a refusal
  (``shared_observation_refused`` and ``refused_shared_observations``).
* A record that does not name its observations is decided on every refusal of its batch
  (fail-closed), so a detector added later is constrained as well.
* A batch ends at the next request after a record, or when a new check starts: a refusal never
  reaches a record of another batch, another endpoint or another identity.

Network checks use a loopback server that records every request it parses. Nothing here contacts
a host other than 127.0.0.1.
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
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.authorization import AuthorizationEvidence
from core.models import HTTPResult, Verdict

CONCLUSIVE_NEGATIVE = {"SECURE", "PUBLIC", "AUTHORIZED"}
OVERRIDE = {"X-HTTP-Method-Override": "DELETE"}  # refused by the transport for that identity only
OVERRIDE_SIGNAL = ("method_override_header", "transport_request")
OWNER_DOCUMENT = {"id": "1001", "title": "Owner document", "secret": "s-1001", "private_note": "OWNER-NOTE-1001",
                  "items": [{"id": "1001", "secret": "s-1001"}]}
VISITOR_DOCUMENT = {"id": "1002", "title": "Visitor document", "secret": "s-1002", "private_note": "VISITOR-NOTE-1002",
                    "items": [{"id": "1002", "secret": "s-1002"}]}


class _Recorder:
    """127.0.0.1 server: no credential 401, a credential containing DENIED 403, otherwise JSON data."""

    def __init__(self) -> None:
        self.requests: List[Tuple[str, str, str]] = []
        self.lock = threading.Lock()
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                auth = self.headers.get("Authorization") or ""
                with recorder.lock:
                    recorder.requests.append((self.command, self.path, auth))
                if not auth:
                    status, document = 401, {"error": "Unauthorized"}
                elif "DENIED" in auth:
                    status, document = 403, {"error": "Forbidden"}
                else:
                    status, document = 200, VISITOR_DOCUMENT if self.path.endswith("/1002") else OWNER_DOCUMENT
                payload = json.dumps(document).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.httpd.server_port}"

    def clear(self) -> None:
        with self.lock:
            self.requests.clear()

    def snapshot(self) -> List[Tuple[str, str, str]]:
        with self.lock:
            return list(self.requests)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def _operation(operation_id: str, *, object_id: bool = False) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"operationId": operation_id, "security": [{"bearer": []}],
                                 "responses": {"200": {"description": "ok"}}}
    if object_id:
        operation["parameters"] = [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]
    return {"get": operation}


ROLE_POLICY = {"required_role": "administrator", "private_data_paths": ["secret"]}
IDENTITIES: Dict[str, Any] = {
    "owner": {"id": "1001", "token": "Bearer BATCH-OWNER", "parameters": {"id": "1001"}},
    "visitor": {"id": "1002", "token": "Bearer DENIED-BATCH-VISITOR", "parameters": {"id": "1002"}},
    "anonymous": {"id": None, "token": None, "parameters": {}},
    "roles": {"admin": {"token": "Bearer BATCH-ADMIN", "role": "administrator"},
              "viewer": {"token": "Bearer DENIED-BATCH-VIEWER", "role": "viewer"},
              "guest": {"token": "Bearer DENIED-BATCH-GUEST", "role": "guest"}},
}
COLLECTION = "GET /admin/settings"
OBJECT = "GET /admin/users/{id}"
BOPLA_ENDPOINT = "GET /documents/{id}"
BOPLA_POLICY = {"policy_id": "batch-document-fields", "context_id": "batch-owner-document",
                "resource_binding": {"id": "1001"},
                "fields": [{"rule_id": "owner-note", "path": "private_note",
                            "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                            "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}

# Which named observations each record's decision consumes (core/auditor.py).
SHARED_BATCH = frozenset({"owner", "visitor_cross", "anonymous"})
OBJECT_BATCH = SHARED_BATCH | {"visitor_self"}
DEPENDS_ON = {
    ("BOLA", "collection"): SHARED_BATCH,
    ("BOLA", "object"): OBJECT_BATCH,
    ("BROKEN_AUTH", None): frozenset({"owner", "anonymous"}),
    ("BFLA", None): SHARED_BATCH,
    ("BOPLA_EXPOSURE", None): frozenset({"owner", "visitor_cross", "visitor_self"}),
    ("BOPLA", "visitor"): frozenset({"owner", "visitor_cross", "visitor_self"}),
    ("BOPLA", "anonymous"): frozenset({"owner", "anonymous"}),
    ("RBAC", None): frozenset({"privileged_role", "role", "anonymous"}),
}
# The observation names an identity's requests produce in a shared batch.
IDENTITY_OBSERVATIONS = {"owner": {"owner"}, "visitor": {"visitor_cross", "visitor_self"}, "anonymous": {"anonymous"}}


class _BatchCase(unittest.TestCase):
    server: _Recorder

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _Recorder()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.close()

    def setUp(self) -> None:
        self.server.clear()
        folder = tempfile.TemporaryDirectory(prefix="granttrace-refusal-batches-")
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def auditor(self, paths: Dict[str, Any], *, bola: Optional[Dict[str, Any]] = None,
                bopla: Optional[Dict[str, Any]] = None, identities: Optional[Dict[str, Any]] = None,
                cls: type = APISentinelAuditor) -> APISentinelAuditor:
        spec = {"openapi": "3.0.3", "info": {"title": "refusal batches", "version": "1"},
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                "paths": paths}
        target = self.folder / f"spec{len(list(self.folder.iterdir()))}.json"
        target.write_text(json.dumps(spec), encoding="utf-8")
        with patch("urllib.request.getproxies", return_value={}):
            return cls(str(target), self.server.origin, request_delay=0, max_workers=1,
                       identities_config=copy.deepcopy(identities or IDENTITIES),
                       bola_config=copy.deepcopy(bola or {}), bopla_config=copy.deepcopy(bopla or {}))

    def scan(self, auditor: APISentinelAuditor, *, refuse: Iterable[str] = (),
             refuse_roles: Iterable[str] = ()) -> List[Dict[str, Any]]:
        # Only the named identities' requests carry an override header, so only they are refused.
        for name in refuse:
            auditor.identities[name]["headers"] = dict(OVERRIDE)
        for name in refuse_roles:
            auditor.identities["roles"][name]["headers"] = dict(OVERRIDE)
        with redirect_stdout(io.StringIO()), patch("urllib.request.getproxies", return_value={}):
            auditor.run()
        return auditor.results

    @staticmethod
    def key(record: Dict[str, Any]) -> Tuple[Any, ...]:
        evidence = record["evidence"]
        decision = evidence.get("decision_evidence") or {}
        return (record["endpoint"], record["check"], evidence.get("rbac_role"), decision.get("subject_identity"),
                decision.get("field_path"))

    @staticmethod
    def depends_on(record: Dict[str, Any]) -> FrozenSet[str]:
        check = record["check"]
        if check == "BOLA":
            return DEPENDS_ON[("BOLA", "object" if "{id}" in record["endpoint"] else "collection")]
        if check == "BOPLA":
            return DEPENDS_ON[("BOPLA", record["evidence"]["decision_evidence"]["subject_identity"])]
        return DEPENDS_ON[(check, None)]

    def assert_refusal_fields(self, record: Dict[str, Any], names: Iterable[str]) -> None:
        evidence = record["evidence"]
        names = sorted(names)
        self.assertNotIn(record["verdict"], CONCLUSIVE_NEGATIVE, record)
        self.assertEqual(evidence.get("safety_refusals"), len(names), record)
        self.assertEqual((evidence.get("safety_signal"), evidence.get("policy_layer")), OVERRIDE_SIGNAL, record)
        self.assertEqual(sorted(evidence.get("refused_observations") or []), names, record)

    def assert_no_refusal_fields(self, record: Dict[str, Any]) -> None:
        for field in ("safety_refusals", "refused_observations", "shared_observation_refused",
                      "refused_shared_observations"):
            self.assertNotIn(field, record["evidence"], record)

    def assert_batch_contract(self, control: List[Dict[str, Any]], refused: List[Dict[str, Any]],
                              refused_names: Iterable[str]) -> None:
        """Every record of a shared batch: dependent ones refuse, independent ones keep their verdict."""
        expected = {self.key(record): record for record in control}
        refused_names = set(refused_names)
        self.assertTrue(refused)
        for record in refused:
            with self.subTest(record=self.key(record)):
                batch = OBJECT_BATCH if "{id}" in record["endpoint"] else SHARED_BATCH
                in_batch = refused_names & batch
                dependent = self.depends_on(record) & in_batch
                if dependent:
                    self.assert_refusal_fields(record, dependent)
                    continue
                # Decided only on observations that were sent: the same decision as without a refusal.
                self.assertNotIn("safety_refusals", record["evidence"], record)
                self.assertNotIn("refused_observations", record["evidence"], record)
                self.assertIn(self.key(record), expected, record)
                self.assertEqual(record["verdict"], expected[self.key(record)]["verdict"], record)
                if in_batch:
                    self.assertIs(record["evidence"].get("shared_observation_refused"), True, record)
                    self.assertEqual(sorted(record["evidence"].get("refused_shared_observations") or []),
                                     sorted(in_batch), record)
                else:
                    self.assert_no_refusal_fields(record)


# ---------------------------------------------------------------------------
# Record layer: one batch, several records
# ---------------------------------------------------------------------------

REFUSAL = {"safety_reason": "Read-only safety policy blocked a request (batch test); no request was sent",
           "safety_signal": "path", "policy_layer": "transport_request"}


def _refused() -> HTTPResult:
    return HTTPResult(status=0, body="", error=REFUSAL["safety_reason"], refusal=dict(REFUSAL))


def _response(status: int, document: Dict[str, Any]) -> HTTPResult:
    return HTTPResult(status=status, body=json.dumps(document), headers={"Content-Type": "application/json"})


def _decision(verdict: Verdict) -> Any:
    def evaluate(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {"verdict": verdict, "reason": f"forced {verdict.value} decision", "evidence": {}}
    return evaluate


class RecordLayerBatchTests(_BatchCase):
    """The invariant itself, with detectors forced to conclude: only the record layer stands guard."""

    PATHS = {"/admin/settings": _operation("getSettings"), "/reports/{kind}": {"get": {
        "operationId": "readReport", "security": [{"bearer": []}],
        "parameters": [{"name": "kind", "in": "path", "required": True, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "ok"}}}}}

    def endpoint(self, auditor: APISentinelAuditor, path: str = "/admin/settings") -> Dict[str, Any]:
        return next(ep for ep in auditor.parser.get_endpoints() if ep["path"] == path)

    def test_every_record_of_a_batch_keeps_a_refusal_it_cannot_attribute(self) -> None:
        # A detector that does not name its observations: each of its records decides on every refusal
        # of the batch (fail-closed), not only the first one written after it.
        auditor = self.auditor(self.PATHS)
        endpoint = self.endpoint(auditor)
        auditor._request_accounting.attempts = 0
        auditor._note_policy_refusal(REFUSAL)
        for check, verdict in (("BOLA", Verdict.SECURE), ("BROKEN_AUTH", Verdict.SECURE),
                               ("BFLA", Verdict.AUTHORIZED), ("BOPLA_EXPOSURE", Verdict.PUBLIC)):
            with self.subTest(check=check):
                record = auditor._record_result(endpoint, check, verdict, "detector decision", {})
                self.assertEqual(record["verdict"], "ERROR")
                self.assertEqual(record["evidence"]["safety_refusals"], 1)
                self.assertEqual(record["evidence"]["policy_layer"], "transport_request")
                self.assertEqual(record["evidence"]["safety_signal"], "path")
                self.assertIn("refused", record["reason"])
        self.assertEqual(self.server.snapshot(), [])

    def expanded(self, refused: Iterable[str], *, collection: bool,
                 forced: Tuple[Verdict, Verdict, Verdict] = (Verdict.SECURE, Verdict.SECURE, Verdict.AUTHORIZED),
                 ) -> Dict[str, Dict[str, Any]]:
        auditor = self.auditor(self.PATHS, bola={COLLECTION: ROLE_POLICY})
        endpoint = self.endpoint(auditor)
        observations = {"owner": _response(200, OWNER_DOCUMENT), "visitor_cross": _response(403, {"error": "no"}),
                        "anonymous": _response(401, {"error": "no"})}
        auditor._request_accounting.attempts = 0
        for name in refused:
            observations[name] = _refused()
            auditor._note_policy_refusal(REFUSAL)  # what _http_request does for a refused observation
        evidence = {"target_url": self.server.origin + "/admin/settings", "requests_attempted": 3}
        with patch.object(AuthorizationEvidence, "evaluate_collection", _decision(forced[0])), \
                patch.object(AuthorizationEvidence, "evaluate_auth", _decision(forced[1])), \
                patch.object(AuthorizationEvidence, "evaluate_bfla", _decision(forced[2])):
            auditor._record_expanded_read_checks(endpoint, ROLE_POLICY, observations["owner"],
                                                 observations["visitor_cross"], observations["anonymous"],
                                                 evidence, collection=collection)
        records = {record["check"]: record for record in auditor.results}
        self.assertEqual(sorted(records), sorted(["BROKEN_AUTH", "BFLA"] + (["BOLA"] if collection else [])))
        return records

    def test_each_identity_refused_in_a_shared_batch(self) -> None:
        forced = {"BOLA": "SECURE", "BROKEN_AUTH": "SECURE", "BFLA": "AUTHORIZED"}
        depends = {"BOLA": SHARED_BATCH, "BROKEN_AUTH": {"owner", "anonymous"}, "BFLA": SHARED_BATCH}
        for collection in (True, False):
            for refused in ("owner", "visitor_cross", "anonymous"):
                with self.subTest(collection=collection, refused=refused):
                    for check, record in self.expanded([refused], collection=collection).items():
                        evidence = record["evidence"]
                        if refused in depends[check]:
                            self.assertEqual(record["verdict"], "ERROR", record)
                            self.assertEqual(evidence["safety_refusals"], 1, record)
                            self.assertEqual(evidence["policy_layer"], "transport_request", record)
                            self.assertEqual(evidence["safety_signal"], "path", record)
                            self.assertEqual(evidence["refused_observations"], [refused], record)
                            self.assertNotIn("refused_shared_observations", evidence, record)
                        else:
                            self.assertEqual(record["verdict"], forced[check], record)
                            self.assertNotIn("safety_refusals", evidence, record)
                            self.assertIs(evidence["shared_observation_refused"], True, record)
                            self.assertEqual(evidence["refused_shared_observations"], [refused], record)

    def test_several_refused_observations_are_counted_per_record(self) -> None:
        records = self.expanded(["visitor_cross", "anonymous"], collection=True)
        self.assertEqual(records["BOLA"]["evidence"]["safety_refusals"], 2)
        self.assertEqual(sorted(records["BOLA"]["evidence"]["refused_observations"]), ["anonymous", "visitor_cross"])
        self.assertEqual(records["BFLA"]["evidence"]["safety_refusals"], 2)
        broken_auth = records["BROKEN_AUTH"]["evidence"]
        self.assertEqual(broken_auth["safety_refusals"], 1)
        self.assertEqual(broken_auth["refused_observations"], ["anonymous"])
        self.assertEqual(broken_auth["refused_shared_observations"], ["visitor_cross"])
        for record in records.values():
            self.assertEqual(record["verdict"], "ERROR")

    def test_a_batch_without_a_refusal_keeps_every_verdict(self) -> None:
        for collection in (True, False):
            with self.subTest(collection=collection):
                records = self.expanded([], collection=collection,
                                        forced=(Verdict.PUBLIC, Verdict.SECURE, Verdict.AUTHORIZED))
                expected = {"BOLA": "PUBLIC", "BROKEN_AUTH": "SECURE", "BFLA": "AUTHORIZED"}
                for check, record in records.items():
                    self.assertEqual(record["verdict"], expected[check])
                    self.assert_no_refusal_fields(record)

    def test_a_new_request_starts_a_new_batch(self) -> None:
        auditor = self.auditor(self.PATHS)
        endpoint = self.endpoint(auditor, "/reports/{kind}")
        refused = auditor._http_request("GET", self.server.origin + "/reports/withdraw", identity_name="owner")
        self.assertIsNotNone(refused.refusal)
        self.assertEqual(auditor._record_result(endpoint, "BOLA", Verdict.SECURE, "refused batch", {})["verdict"],
                         "ERROR")
        sent = auditor._http_request("GET", self.server.origin + "/reports/summary", identity_name="owner")
        self.assertEqual(sent.status, 200)
        later = auditor._record_result(endpoint, "BROKEN_AUTH", Verdict.SECURE, "a later batch", {})
        self.assertEqual(later["verdict"], "SECURE")
        self.assert_no_refusal_fields(later)
        self.assertEqual([path for _, path, _ in self.server.snapshot()], ["/reports/summary"])

    def test_a_new_check_starts_a_new_batch(self) -> None:
        auditor = self.auditor(self.PATHS)
        endpoint = self.endpoint(auditor, "/reports/{kind}")
        auditor._http_request("GET", self.server.origin + "/reports/withdraw", identity_name="owner")
        auditor._record_result(endpoint, "BOLA", Verdict.SECURE, "refused batch", {})
        auditor._begin_check_accounting()  # what every check task does before it starts
        later = auditor._record_result(endpoint, "BOLA", Verdict.SECURE, "a later, independent check", {})
        self.assertEqual(later["verdict"], "SECURE")
        self.assertNotIn("safety_refusals", later["evidence"])
        self.assertEqual(self.server.snapshot(), [])


# ---------------------------------------------------------------------------
# Scans: Owner / Visitor / Anonymous / roles refused x collection / object, over loopback
# ---------------------------------------------------------------------------

class SharedBatchScanTests(_BatchCase):
    PATHS = {"/admin/settings": _operation("getSettings"),
             "/admin/users/{id}": _operation("getUser", object_id=True)}
    BOLA = {COLLECTION: ROLE_POLICY, OBJECT: ROLE_POLICY}

    def run_scan(self, **refusals: Iterable[str]) -> List[Dict[str, Any]]:
        return self.scan(self.auditor(self.PATHS, bola=self.BOLA), **refusals)

    def test_control_scan_has_no_refusal_and_conclusive_negatives(self) -> None:
        control = self.run_scan()
        for record in control:
            self.assert_no_refusal_fields(record)
        verdicts = {(record["endpoint"], record["check"], record["evidence"].get("rbac_role")): record["verdict"]
                    for record in control}
        # The independent records below are compared against these conclusive negatives.
        self.assertEqual(verdicts[(COLLECTION, "BOLA", None)], "SECURE")
        self.assertEqual(verdicts[(COLLECTION, "BROKEN_AUTH", None)], "SECURE")
        self.assertEqual(verdicts[(COLLECTION, "RBAC", "viewer")], "SECURE")
        self.assertEqual(verdicts[(OBJECT, "BROKEN_AUTH", None)], "SECURE")

    def test_each_identity_refused_in_collection_and_object_batches(self) -> None:
        control = self.run_scan()
        for identity in ("owner", "visitor", "anonymous"):
            with self.subTest(refused=identity):
                self.server.clear()
                refused = self.run_scan(refuse=[identity])
                self.assert_batch_contract(control, refused, IDENTITY_OBSERVATIONS[identity])
                if identity != "anonymous":
                    # The refused identity's requests never reached the target.
                    sent = {auth for _, _, auth in self.server.snapshot()}
                    self.assertNotIn(IDENTITIES[identity]["token"], sent)

    def test_the_rbac_records_depend_on_the_shared_anonymous_observation(self) -> None:
        refused = self.run_scan(refuse=["anonymous"])
        rbac = [record for record in refused if record["check"] == "RBAC" and record["endpoint"] == COLLECTION]
        self.assertEqual(len(rbac), 2)  # viewer and guest; the admin role is the privileged baseline
        for record in rbac:
            self.assert_refusal_fields(record, ["anonymous"])

    def test_two_refused_identities_are_counted_once_each(self) -> None:
        control = self.run_scan()
        refused = self.run_scan(refuse=["visitor", "anonymous"])
        self.assert_batch_contract(control, refused, {"visitor_cross", "visitor_self", "anonymous"})
        records = {(record["endpoint"], record["check"], record["evidence"].get("rbac_role")): record
                   for record in refused}
        self.assertEqual(records[(COLLECTION, "BOLA", None)]["evidence"]["safety_refusals"], 2)
        self.assertEqual(records[(COLLECTION, "BROKEN_AUTH", None)]["evidence"]["safety_refusals"], 1)
        self.assertEqual(records[(OBJECT, "BOLA", None)]["evidence"]["safety_refusals"], 3)

    def test_a_refused_role_probe_stays_with_its_own_record(self) -> None:
        control = self.run_scan()
        expected = {self.key(record): record["verdict"] for record in control}
        for role, name in (("admin", "privileged_role"), ("viewer", "role")):
            with self.subTest(refused_role=role):
                refused = self.run_scan(refuse_roles=[role])
                for record in refused:
                    with self.subTest(record=self.key(record)):
                        role_record = record["check"] == "RBAC" and (role == "admin"
                                                                     or record["evidence"].get("rbac_role") == role)
                        if role_record:
                            self.assert_refusal_fields(record, [name])
                        else:
                            # Other roles' records and the shared batch never carry this role's refusal.
                            self.assert_no_refusal_fields(record)
                            self.assertEqual(record["verdict"], expected[self.key(record)])


class PropertyBatchScanTests(_BatchCase):
    """BOPLA records and the sensitive-exposure record reuse the object and collection batches."""

    PATHS = {"/admin/settings": _operation("getSettings"),
             "/documents/{id}": _operation("getDocument", object_id=True)}
    IDENTITIES = {
        "owner": {"id": "1001", "token": "Bearer PROPERTY-OWNER", "parameters": {"id": "1001"}},
        "visitor": {"id": "1002", "token": "Bearer PROPERTY-VISITOR", "parameters": {"id": "1002"}},
        "anonymous": {"id": None, "token": None, "parameters": {}},
    }
    BOLA = {COLLECTION: dict(ROLE_POLICY, detect_sensitive_exposure=True),
            BOPLA_ENDPOINT: {"expected_visitor_access": "deny"}}

    def run_scan(self, **refusals: Iterable[str]) -> List[Dict[str, Any]]:
        auditor = self.auditor(self.PATHS, bola=self.BOLA, bopla={BOPLA_ENDPOINT: BOPLA_POLICY},
                               identities=self.IDENTITIES)
        return self.scan(auditor, **refusals)

    def test_property_records_follow_their_own_observations(self) -> None:
        control = self.run_scan()
        checks = {record["check"] for record in control}
        self.assertTrue({"BOPLA", "BOPLA_EXPOSURE", "BOLA", "BROKEN_AUTH"} <= checks, checks)
        for record in control:
            self.assert_no_refusal_fields(record)
        for identity in ("owner", "visitor", "anonymous"):
            with self.subTest(refused=identity):
                refused = self.run_scan(refuse=[identity])
                self.assertIn("BOPLA", {record["check"] for record in refused})
                self.assert_batch_contract(control, refused, IDENTITY_OBSERVATIONS[identity])

    def test_a_refused_anonymous_observation_keeps_the_sent_visitor_property_decision(self) -> None:
        refused = self.run_scan(refuse=["anonymous"])
        bopla = {record["evidence"]["decision_evidence"]["subject_identity"]: record
                 for record in refused if record["check"] == "BOPLA"}
        self.assertEqual(bopla["visitor"]["verdict"], "CONFIRMED")
        self.assertEqual(bopla["visitor"]["evidence"]["refused_shared_observations"], ["anonymous"])
        self.assert_refusal_fields(bopla["anonymous"], ["anonymous"])


class BatchIsolationTests(_BatchCase):
    """A refusal never reaches another endpoint's batch, in a scan or in direct library calls."""

    PATHS = {"/admin/settings": _operation("getSettings"), "/reports": _operation("listReports")}

    class _RefuseAnonymousSettings(APISentinelAuditor):
        """The transport refuses only Anonymous on /admin/settings (a per-endpoint, per-identity refusal)."""

        def _send_http_request(self, method: str, url: str, data: Any, identity_name: str,
                               content_type: str, headers: Optional[Dict[str, str]]) -> HTTPResult:
            if identity_name == "anonymous" and url.endswith("/admin/settings"):
                return _refused()
            return super()._send_http_request(method, url, data, identity_name, content_type, headers)

    def bola(self) -> Dict[str, Any]:
        return {COLLECTION: ROLE_POLICY, "GET /reports": {"private_data_paths": ["secret"]}}

    def test_other_endpoints_stay_clean_in_a_scan(self) -> None:
        control = self.scan(self.auditor(self.PATHS, bola=self.bola()))
        refused = self.scan(self.auditor(self.PATHS, bola=self.bola(), cls=self._RefuseAnonymousSettings))
        expected = {self.key(record): record["verdict"] for record in control}
        reports = [record for record in refused if record["endpoint"] == "GET /reports"]
        self.assertTrue(reports)
        for record in reports:
            self.assert_no_refusal_fields(record)
            self.assertEqual(record["verdict"], expected[self.key(record)])
        settings = [record for record in refused if record["endpoint"] == COLLECTION]
        self.assertTrue(settings)
        for record in settings:
            self.assertEqual(record["evidence"]["refused_observations"], ["anonymous"])

    def test_other_endpoints_stay_clean_in_direct_calls(self) -> None:
        auditor = self.auditor(self.PATHS, bola=self.bola(), cls=self._RefuseAnonymousSettings)
        endpoints = {ep["path"]: ep for ep in auditor.parser.get_endpoints()}
        with redirect_stdout(io.StringIO()):
            auditor.audit_endpoint_bola(endpoints["/admin/settings"])
            first = len(auditor.results)
            auditor.audit_endpoint_bola(endpoints["/reports"])
        self.assertTrue(any("safety_refusals" in record["evidence"] for record in auditor.results[:first]))
        for record in auditor.results[first:]:
            self.assert_no_refusal_fields(record)


if __name__ == "__main__":
    unittest.main()
