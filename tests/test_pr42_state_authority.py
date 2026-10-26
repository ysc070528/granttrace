"""Fresh independent state machines for the two unmarked-cache counterexamples.

The backing store and write-side audit trail are separate from GET responses.
No verdict from the original fixed scenario runner defines these test truths.
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

OBSERVATIONS = []


class StateServer:
    def __init__(self):
        self.original = {"id": "disposable-a", "role": "user", "details": {"note": "keep"}}
        self.states = {path: copy.deepcopy(self.original) for path in ("/a", "/b")}
        self.lock = threading.RLock()
        self.writes = []
        self.reads = []
        self.authority_reads = []
        self.snapshots = []
        self.restore_entered = threading.Event()
        self.release_restore = threading.Event()
        self.wait_restore = False
        self.lose_authority = False
        self.server = None
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, value):
                data = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                with fixture.lock:
                    value = fixture.representation(self.path)
                    fixture.reads.append({"path": self.path, "body": copy.deepcopy(value)})
                self.respond(value)

            def do_PATCH(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if fixture.wait_restore and body.get("role") == "user":
                    fixture.restore_entered.set()
                    if not fixture.release_restore.wait(5):
                        raise RuntimeError("Test failed to release recovery")
                with fixture.lock:
                    before = copy.deepcopy(fixture.states[self.path])
                    applied = fixture.apply(self.path, body)
                    fixture.writes.append({"path": self.path, "payload": body, "applied": applied,
                                           "before": before, "after": copy.deepcopy(fixture.states[self.path])})
                self.respond({"ack": True})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.target = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.directory = tempfile.TemporaryDirectory(prefix="granttrace-state-proof-")
        operation = {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"role": {"type": "string", "enum": ["user", "admin"]}}
        }}}}, "responses": {}}
        self.spec = Path(self.directory.name) / "spec.json"
        self.spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {
            path: {"get": {"responses": {}}, "patch": operation} for path in self.states
        }}))
        self.readbacks = {"PATCH " + path: {"path": path, "field_map": {"role": "role"},
            "consistency": "strong", "readback_attempts": 1, "readback_delay": 0} for path in self.states}

    def representation(self, path):
        return copy.deepcopy(self.states[path])

    def apply(self, path, body):
        self.states[path].update(copy.deepcopy(body))
        return True

    def auditor(self, authority=False):
        fixture = self

        class StateAuditor(APISentinelAuditor):
            def _authoritative_patch_state(self, ep, mutation_url, readback):
                if self.target_base_url.rstrip("/") != fixture.target:
                    return None
                path = urlsplit(mutation_url).path
                with fixture.lock:
                    state = copy.deepcopy(fixture.states[path])
                    fixture.authority_reads.append({"path": path, "state": state})
                    if fixture.lose_authority and fixture.writes:
                        return None
                    if not fixture.writes:
                        fixture.snapshots.append(state)
                    return state

        cls = StateAuditor if authority else APISentinelAuditor
        with patch("urllib.request.getproxies", return_value={}):
            return cls(str(self.spec), self.target, request_delay=0, allow_write_tests=True,
                       write_allowlist=list(self.readbacks), readback_config=self.readbacks)

    def scan(self, auditor, path="/a"):
        endpoints = auditor.parser.get_endpoints()
        ep = next(e for e in endpoints if e["method"] == "PATCH" and e["path"] == path)
        with contextlib.redirect_stdout(io.StringIO()):
            auditor.audit_endpoint_mass_assignment(ep, endpoints)

    def observe(self, auditor, label):
        result = {"case": type(self).__name__, "label": label, "actual_state": copy.deepcopy(self.states),
                  "initial_resource": self.original, "initial_snapshots": self.snapshots,
                  "patch_count": len(self.writes), "restore_count": sum(w["payload"]["role"] == "user" for w in self.writes),
                  "writes": copy.deepcopy(self.writes), "get_claims": copy.deepcopy(self.reads),
                  "authority_observations": copy.deepcopy(self.authority_reads),
                  "halted": bool(auditor._writes_halted_reason), "halt_reason": auditor._writes_halted_reason,
                  "results": copy.deepcopy(auditor.results)}
        OBSERVATIONS.append(result)
        return result

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.release_restore.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.directory.cleanup()


class CachedAfterServer(StateServer):
    """Mutation persists, but GET claims the old complete resource without markers."""
    def representation(self, path):
        if path == "/a" and len(self.writes) == 1:
            return copy.deepcopy(self.original)
        return super().representation(path)


class NoopRestoreServer(StateServer):
    """Restore is acknowledged without application; GET falsely claims restoration."""
    def apply(self, path, body):
        if path == "/a" and body["role"] == "user":
            return False
        return super().apply(path, body)

    def representation(self, path):
        if path == "/a" and len(self.writes) >= 2:
            return copy.deepcopy(self.original)
        return super().representation(path)


class StateAuthorityTests(unittest.TestCase):
    def test_original_unmarked_cache_servers_are_blocked_before_any_patch(self):
        for cls in (CachedAfterServer, NoopRestoreServer):
            with self.subTest(server=cls.__name__), cls() as api:
                auditor = api.auditor()
                plan = auditor.build_plan()
                self.assertTrue(all(not p["writes_enabled"] for p in plan["operations"] if p["check"] == "MASS_ASSIGNMENT"))
                self.assertEqual([], api.reads)
                api.scan(auditor)
                api.scan(auditor, "/b")
                self.assertEqual([], api.writes)
                self.assertEqual(api.original, api.states["/a"])
                self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
                self.assertFalse(auditor.results[0]["evidence"].get("rollback_verified"))
                self.assertFalse(auditor.findings)
                api.observe(auditor, "generic HTTP: blocked")

    def test_authoritative_comparison_exposes_stale_after_and_restores_actual_state(self):
        with CachedAfterServer() as api:
            auditor = api.auditor(authority=True)
            api.scan(auditor)
            self.assertEqual(2, len(api.writes))
            self.assertEqual("admin", api.writes[0]["after"]["role"])
            self.assertEqual(api.original, api.states["/a"])
            self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
            self.assertTrue(auditor.results[0]["evidence"]["rollback_verified"])
            self.assertFalse(auditor.findings)
            api.observe(auditor, "actual store checked: stale after rejected, real restore verified")

    def test_authoritative_comparison_exposes_noop_restore_and_halts_other_resource(self):
        with NoopRestoreServer() as api:
            auditor = api.auditor(authority=True)
            api.scan(auditor)
            api.scan(auditor, "/b")
            self.assertEqual("admin", api.states["/a"]["role"])
            self.assertFalse(api.writes[1]["applied"])
            self.assertEqual(2, len(api.writes))
            self.assertFalse(auditor.results[0]["evidence"]["rollback_verified"])
            self.assertTrue(auditor._writes_halted_reason)
            self.assertEqual("SKIPPED", auditor.results[-1]["verdict"])
            self.assertTrue(any(r["check"] == "ROLLBACK" and r["verdict"] == "ERROR" for r in auditor.results))
            api.observe(auditor, "actual store checked: lying restore rejected")

    def test_initial_200_must_agree_with_actual_store_before_patch(self):
        with CachedAfterServer() as api:
            api.representation = lambda path: copy.deepcopy(api.original)
            api.states["/a"]["role"] = "actual-different-value"
            auditor = api.auditor(authority=True)
            api.scan(auditor)
            self.assertEqual([], api.writes)
            self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
            api.observe(auditor, "initial snapshot disagrees with store")

    def test_authority_lost_during_snapshot_preparation_prevents_patch(self):
        with StateServer() as api:
            auditor = api.auditor(authority=True)
            from core.transactions import prepare_patch

            def prepare_then_lose_authority(*args):
                snapshot = prepare_patch(*args)
                auditor._authoritative_patch_state = lambda *unused: None
                return snapshot

            with patch("core.auditor.prepare_patch", side_effect=prepare_then_lose_authority):
                api.scan(auditor)
            self.assertEqual([], api.writes)
            self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
            self.assertFalse(auditor.findings)
            api.observe(auditor, "authority lost before transport: zero PATCH")

    def test_loss_of_authority_after_commit_never_certifies_recovery(self):
        with StateServer() as api:
            api.lose_authority = True
            auditor = api.auditor(authority=True)
            api.scan(auditor)
            api.scan(auditor, "/b")
            self.assertEqual(api.original, api.states["/a"])
            self.assertEqual(2, len(api.writes))
            self.assertFalse(auditor.results[0]["evidence"]["rollback_verified"])
            self.assertTrue(auditor._writes_halted_reason)
            self.assertEqual("SKIPPED", auditor.results[-1]["verdict"])
            api.observe(auditor, "actual restore happened, proof unavailable: retain halt")

    def test_waiting_other_resource_cannot_write_after_opaque_restore_failure(self):
        with NoopRestoreServer() as api:
            api.wait_restore = True
            auditor = api.auditor(authority=True)
            errors = []
            waiting = threading.Event()
            write_gate = auditor._write_lock

            class ObservedGate:
                def __enter__(self):
                    if threading.current_thread().name == "authority-waiter":
                        # Signal only after observing that the first transaction
                        # really owns the gate, rather than just starting a thread.
                        if write_gate.acquire(blocking=False):
                            write_gate.release()
                            raise AssertionError("First transaction did not hold the write gate")
                        waiting.set()
                    write_gate.acquire()
                    return self

                def __exit__(self, *args):
                    write_gate.release()

            auditor._write_lock = ObservedGate()

            def scan(path):
                try:
                    api.scan(auditor, path)
                except BaseException as exc:
                    errors.append(repr(exc))

            first = threading.Thread(target=scan, args=("/a",))
            second = threading.Thread(target=scan, args=("/b",), name="authority-waiter")
            first.start()
            self.assertTrue(api.restore_entered.wait(3))
            second.start()
            self.assertTrue(waiting.wait(3))
            api.release_restore.set()
            first.join(4)
            second.join(4)
            self.assertFalse(first.is_alive() or second.is_alive())
            self.assertEqual([], errors)
            self.assertEqual(["/a", "/a"], [w["path"] for w in api.writes])
            self.assertTrue(auditor._writes_halted_reason)
            self.assertEqual("SKIPPED", auditor.results[-1]["verdict"])
            api.observe(auditor, "concurrent waiter blocked")

    def test_honest_state_and_restore_remain_confirmed_only_with_authority(self):
        with StateServer() as api:
            auditor = api.auditor(authority=True)
            api.scan(auditor)
            self.assertEqual("CONFIRMED", auditor.results[0]["verdict"])
            self.assertTrue(auditor.results[0]["evidence"]["rollback_verified"])
            self.assertEqual(api.original, api.states["/a"])
            self.assertEqual([True, True], [w["applied"] for w in api.writes])
            self.assertIsNone(auditor._writes_halted_reason)
            api.observe(auditor, "honest independent store control")


if __name__ == "__main__":
    unittest.main()
