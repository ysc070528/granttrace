"""PUT replacement and recovery proofs against an independently observed store.

Only the fixture-specific subclass can inspect this disposable backing store.
The ordinary auditor, including a loopback HTTP target, has no such authority.
"""

import contextlib
import copy
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.transactions import get_path, prepare_patch


class ReplacementServer:
    def __init__(self, mode="honest", method="PUT", field="role", content_type="application/json"):
        self.mode = mode
        self.method = method
        self.field = field
        self.original = {
            "id": "disposable-a", "role": "user", "nullable": None,
            "profile": {"role": "user", "display": "Keep this display"},
            "entries": [{"id": "entry-a", "is_admin": False, "note": "first"},
                        {"id": "entry-b", "is_admin": False, "note": "second"}],
            "unmodeled": {"owner_note": "Preserve fields omitted from the request schema"},
        }
        self.states = {path: copy.deepcopy(self.original) for path in ("/a", "/b")}
        self.lock = threading.RLock()
        self.writes = []
        self.reads = []
        self.authority_reads = []
        self.wait_restore = False
        self.restore_entered = threading.Event()
        self.release_restore = threading.Event()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, value):
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                with fixture.lock:
                    state = copy.deepcopy(fixture.states[self.path])
                    count = sum(write["path"] == self.path for write in fixture.writes)
                    if self.path == "/a" and (
                        (fixture.mode == "opaque_after" and count == 1)
                        or (fixture.mode == "opaque_restore" and count >= 2)
                        or (fixture.mode == "initial_mismatch" and count == 0)
                    ):
                        state = copy.deepcopy(fixture.original)
                    fixture.reads.append({"path": self.path, "body": copy.deepcopy(state)})
                self.respond(state)

            def write(self, method):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                restoring = get_path(body, fixture.field) == get_path(fixture.original, fixture.field)
                if fixture.wait_restore and restoring:
                    fixture.restore_entered.set()
                    if not fixture.release_restore.wait(5):
                        raise RuntimeError("Test did not release restoration")
                with fixture.lock:
                    before = copy.deepcopy(fixture.states[self.path])
                    applied = not (
                        fixture.mode == "mutation_ack_only"
                        or (restoring and fixture.mode in {"restore_ack_only", "opaque_restore"})
                    )
                    if applied:
                        if method == "PUT":
                            # A replacement removes every omitted top-level field.
                            fixture.states[self.path] = copy.deepcopy(body)
                        else:
                            fixture.states[self.path].update(copy.deepcopy(body))
                    fixture.writes.append({"method": method, "path": self.path,
                        "payload": body, "applied": applied, "restoring": restoring,
                        "before": before, "after": copy.deepcopy(fixture.states[self.path])})
                self.respond({"ack": True})

            def do_PUT(self):
                self.write("PUT")

            def do_PATCH(self):
                self.write("PATCH")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.target = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.directory = tempfile.TemporaryDirectory(prefix="granttrace-put-state-")
        if field == "profile.role":
            properties = {"profile": {"type": "object", "properties": {
                "role": {"type": "string", "enum": ["user", "admin"], "readOnly": True}}}}
        elif field == "entries[0].is_admin":
            properties = {"entries": {"type": "array", "items": {"type": "object", "properties": {
                "is_admin": {"type": "boolean", "readOnly": True}}}}}
        else:
            properties = {"role": {"type": "string", "enum": ["user", "admin"], "readOnly": True}}
        operation = {"requestBody": {"content": {content_type: {"schema": {
            "type": "object", "properties": properties}}}}, "responses": {}}
        self.spec = Path(self.directory.name) / "spec.json"
        self.spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {
            path: {"get": {"responses": {}}, method.lower(): operation} for path in self.states
        }}))
        self.readbacks = {method + " " + path: {
            "path": path, "field_map": {field: field}, "consistency": "strong",
            "readback_attempts": 1, "readback_delay": 0,
        } for path in self.states}

    def auditor(self, authority=True, writes=True, listed=True):
        fixture = self

        class StoreAuditor(APISentinelAuditor):
            def _authoritative_patch_state(self, ep, mutation_url, readback):
                selected = urlsplit(mutation_url)
                if (self.target_base_url.rstrip("/") != fixture.target
                        or selected.netloc != urlsplit(fixture.target).netloc
                        or not fixture.thread.is_alive()):
                    return None
                with fixture.lock:
                    if fixture.mode == "authority_lost_after" and fixture.writes:
                        return None
                    state = copy.deepcopy(fixture.states[selected.path])
                    fixture.authority_reads.append({"path": selected.path, "state": state})
                    return state

        cls = StoreAuditor if authority else APISentinelAuditor
        with patch("urllib.request.getproxies", return_value={}):
            return cls(str(self.spec), self.target, request_delay=0,
                allow_write_tests=writes, write_allowlist=list(self.readbacks) if listed else [],
                readback_config=copy.deepcopy(self.readbacks))

    def scan(self, auditor, path="/a"):
        endpoints = auditor.parser.get_endpoints()
        endpoint = next(ep for ep in endpoints if ep["method"] == self.method and ep["path"] == path)
        with contextlib.redirect_stdout(io.StringIO()):
            auditor.audit_endpoint_mass_assignment(endpoint, endpoints)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.release_restore.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.directory.cleanup()


class PutSnapshotTests(unittest.TestCase):
    def test_full_replacement_preserves_nested_arrays_null_and_unmodeled_fields(self):
        before = {"role": "user", "nested": {"keep": "original"},
                  "entries": [{"is_admin": False, "note": "first"}, {"is_admin": False}], "nullable": None}
        case = {"field_path": "entries[0].is_admin", "value": True,
                "payload": {"entries": [{"is_admin": True, "note": "generated-placeholder"}]}}
        snapshot = prepare_patch(before, case, {"field_map": {case["field_path"]: case["field_path"]}}, "PUT")
        expected = copy.deepcopy(before)
        expected["entries"][0]["is_admin"] = True
        self.assertEqual(expected, snapshot.mutation)
        self.assertEqual(before, snapshot.restore)
        snapshot.mutation["nested"]["keep"] = "changed"
        self.assertEqual("original", before["nested"]["keep"])
        self.assertEqual("original", snapshot.restore["nested"]["keep"])

    def test_ambiguous_or_partial_replacement_mappings_are_rejected(self):
        before = {"role": "user", "other": "user"}
        case = {"field_path": "role", "value": "admin"}
        for extra in ({"snapshot_path": "data"}, {"ignore_readback_paths": ["other"]},
                      {"ignore_readback_paths": "other"}, {"baseline_payload": {"other": "generated"}},
                      {"snapshot_field_map": {"role": "other"}},
                      {"field_map": {"role": "role", "unselected": "other"}},
                      {"field_map": {"role": "other"}}):
            with self.subTest(extra=extra), self.assertRaises((ValueError, KeyError)):
                prepare_patch(before, case, {"field_map": {"role": "role"}, **extra}, "PUT")

    def test_put_and_patch_keep_distinct_request_semantics(self):
        before = {"role": "user", "business": {"note": "keep"}}
        case = {"field_path": "role", "value": "admin"}
        mapping = {"field_map": {"role": "role"}}
        patch_snapshot = prepare_patch(before, case, mapping)
        put_snapshot = prepare_patch(before, case, mapping, "PUT")
        self.assertEqual({"role": "admin"}, patch_snapshot.mutation)
        self.assertEqual({"role": "user"}, patch_snapshot.restore)
        self.assertEqual({**before, "role": "admin"}, put_snapshot.mutation)
        self.assertEqual(before, put_snapshot.restore)


class PutStateSafetyTests(unittest.TestCase):
    def test_fixture_put_really_replaces_omitted_fields(self):
        with ReplacementServer() as api:
            auditor = api.auditor()
            response = auditor._http_request("PUT", api.target + "/a", data={"role": "admin"},
                                             identity_name="visitor")
            self.assertEqual(200, response.status)
            self.assertEqual({"role": "admin"}, api.states["/a"])
            self.assertNotIn("unmodeled", api.writes[0]["after"])

    def test_complete_replacement_and_restore_preserve_every_business_field(self):
        for field in ("role", "profile.role", "entries[0].is_admin"):
            with self.subTest(field=field), ReplacementServer(field=field) as api:
                auditor = api.auditor()
                api.scan(auditor)
                self.assertEqual("CONFIRMED", auditor.results[0]["verdict"])
                self.assertTrue(auditor.results[0]["evidence"]["rollback_verified"])
                self.assertEqual(2, len(api.writes))
                self.assertEqual(["PUT", "PUT"], [write["method"] for write in api.writes])
                self.assertEqual(api.original, api.states["/a"])
                self.assertEqual(api.original, api.writes[1]["payload"])
                for write in api.writes:
                    self.assertEqual(api.original.keys(), write["payload"].keys())
                    self.assertEqual(api.original["unmodeled"], write["payload"]["unmodeled"])
                self.assertIsNone(auditor._writes_halted_reason)

    def test_generic_http_has_zero_puts_even_with_allowlist_and_strong_readback(self):
        for mode in ("honest", "opaque_after", "opaque_restore"):
            with self.subTest(mode=mode), ReplacementServer(mode) as api:
                auditor = api.auditor(authority=False)
                plan = auditor.build_plan()
                self.assertTrue(all(not item["writes_enabled"] for item in plan["operations"]
                                    if item["check"] == "MASS_ASSIGNMENT"))
                api.scan(auditor)
                api.scan(auditor, "/b")
                self.assertEqual([], api.writes)
                self.assertEqual([], api.reads)
                self.assertEqual(api.original, api.states["/a"])
                self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
                self.assertFalse(auditor.results[0]["evidence"]["rollback_verified"])

    def test_opaque_write_observation_cannot_skip_real_restoration(self):
        with ReplacementServer("opaque_after") as api:
            auditor = api.auditor()
            api.scan(auditor)
            self.assertEqual(2, len(api.writes))
            self.assertEqual("admin", api.writes[0]["after"]["role"])
            self.assertEqual(api.original, api.states["/a"])
            self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
            self.assertTrue(auditor.results[0]["evidence"]["recovery_sent"])
            self.assertTrue(auditor.results[0]["evidence"]["rollback_verified"])

    def test_acknowledged_noop_restore_never_certifies_recovery_or_allows_later_put(self):
        for mode in ("restore_ack_only", "opaque_restore"):
            with self.subTest(mode=mode), ReplacementServer(mode) as api:
                auditor = api.auditor()
                api.scan(auditor)
                api.scan(auditor, "/b")
                self.assertEqual("admin", api.states["/a"]["role"])
                self.assertEqual([True, False], [write["applied"] for write in api.writes])
                self.assertFalse(auditor.results[0]["evidence"]["rollback_verified"])
                self.assertTrue(auditor._writes_halted_reason)
                self.assertEqual("SKIPPED", auditor.results[-1]["verdict"])
                self.assertEqual(api.original, api.states["/b"])

    def test_lost_authority_after_write_retains_halt_even_when_actual_restore_succeeds(self):
        with ReplacementServer("authority_lost_after") as api:
            auditor = api.auditor()
            api.scan(auditor)
            api.scan(auditor, "/b")
            self.assertEqual(api.original, api.states["/a"])
            self.assertEqual(2, len(api.writes))
            self.assertFalse(auditor.results[0]["evidence"]["rollback_verified"])
            self.assertTrue(auditor._writes_halted_reason)
            self.assertEqual("SKIPPED", auditor.results[-1]["verdict"])

    def test_initial_state_disagreement_and_authority_lost_before_transport_send_zero_put(self):
        with ReplacementServer("initial_mismatch") as api:
            api.states["/a"]["role"] = "actual-other-value"
            auditor = api.auditor()
            api.scan(auditor)
            self.assertEqual([], api.writes)
            self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
        with ReplacementServer() as api:
            auditor = api.auditor()

            def prepare_then_lose_authority(*args, **kwargs):
                snapshot = prepare_patch(*args, **kwargs)
                auditor._authoritative_patch_state = lambda *unused: None
                return snapshot

            with patch("core.auditor.prepare_patch", side_effect=prepare_then_lose_authority):
                api.scan(auditor)
            self.assertEqual([], api.writes)
            self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])

    def test_mutation_ack_without_persistence_is_not_a_vulnerability(self):
        with ReplacementServer("mutation_ack_only") as api:
            auditor = api.auditor()
            api.scan(auditor)
            self.assertEqual(api.original, api.states["/a"])
            self.assertEqual("SECURE", auditor.results[0]["verdict"])
            self.assertFalse(auditor.findings)
            self.assertTrue(auditor.results[0]["evidence"]["rollback_verified"])

    def test_put_write_gates_and_unsupported_media_cannot_be_bypassed(self):
        for writes, listed in ((False, True), (True, False)):
            with self.subTest(writes=writes, listed=listed), ReplacementServer() as api:
                auditor = api.auditor(writes=writes, listed=listed)
                api.scan(auditor)
                self.assertEqual([], api.writes)
        with ReplacementServer(content_type="application/merge-patch+json") as api:
            auditor = api.auditor()
            api.scan(auditor)
            self.assertEqual([], api.writes)
            self.assertEqual("SKIPPED", auditor.results[0]["verdict"])

    def test_ambiguous_or_ignored_state_never_reaches_put_transport(self):
        for extra in ({"snapshot_path": "profile"}, {"ignore_readback_paths": ["unmodeled"]},
                      {"snapshot_field_map": {"role": "profile.role"}},
                      {"field_map": {"role": "profile.role"}},
                      {"baseline_payload": {"role": "generated-placeholder"}}):
            with self.subTest(extra=extra), ReplacementServer() as api:
                auditor = api.auditor()
                auditor.readback_config["PUT /a"].update(extra)
                api.scan(auditor)
                self.assertEqual([], api.writes)
                self.assertEqual(api.original, api.states["/a"])
                self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
                self.assertIsNot(True, auditor.results[0]["evidence"].get("rollback_verified"))

    def test_patch_retains_partial_mutation_and_container_restore(self):
        with ReplacementServer(method="PATCH", field="profile.role") as api:
            auditor = api.auditor()
            api.scan(auditor)
            self.assertEqual("CONFIRMED", auditor.results[0]["verdict"])
            self.assertEqual(api.original, api.states["/a"])
            self.assertEqual(["PATCH", "PATCH"], [write["method"] for write in api.writes])
            self.assertEqual({"profile"}, set(api.writes[0]["payload"]))
            self.assertEqual("Keep this display", api.writes[0]["payload"]["profile"]["display"])

    def test_waiting_other_resource_observes_failed_put_restoration_before_writing(self):
        with ReplacementServer("opaque_restore") as api:
            api.wait_restore = True
            auditor = api.auditor()
            gate = auditor._write_lock
            waiting = threading.Event()
            errors = []

            class ObservedGate:
                def __enter__(self):
                    if threading.current_thread().name == "put-waiter":
                        if gate.acquire(blocking=False):
                            gate.release()
                            raise AssertionError("First PUT transaction did not hold the write gate")
                        waiting.set()
                    gate.acquire()
                    return self

                def __exit__(self, *args):
                    gate.release()

            auditor._write_lock = ObservedGate()

            def scan(path):
                try:
                    api.scan(auditor, path)
                except BaseException as exc:
                    errors.append(repr(exc))

            first = threading.Thread(target=scan, args=("/a",))
            second = threading.Thread(target=scan, args=("/b",), name="put-waiter")
            first.start()
            self.assertTrue(api.restore_entered.wait(3))
            second.start()
            self.assertTrue(waiting.wait(3))
            api.release_restore.set()
            first.join(4)
            second.join(4)
            self.assertFalse(first.is_alive() or second.is_alive())
            self.assertEqual([], errors)
            self.assertEqual(["/a", "/a"], [write["path"] for write in api.writes])
            self.assertFalse(auditor.results[0]["evidence"]["rollback_verified"])
            self.assertTrue(auditor._writes_halted_reason)
            self.assertEqual("SKIPPED", auditor.results[-1]["verdict"])


if __name__ == "__main__":
    unittest.main()
