"""Independent HTTP counterexamples for PR #42; no fixed-scenario imports."""

import contextlib
import copy
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.diff import ResponseDiffEngine
from core.parser import OpenAPIParser
from core.models import HTTPResult


OBSERVATIONS = []


class AdversarialAPI:
    """Observe actual state separately from what the GET handler claims."""

    def __init__(self, mode="honest", *, nested=False, writes=True, listed=True, authority=True):
        self.mode = mode
        self.original = {"id": "account-7", "role": "user", "profile": {
            "server_marker": False, "display": "Original display"}, "counter": 0,
            "records": [{"ref": "a", "note": "first"}, {"ref": "b", "note": "second"}]}
        self.states = {path: copy.deepcopy(self.original) for path in ("/profile", "/other")}
        self.calls = []
        self.patch_counts = {path: 0 for path in self.states}
        self.contender = threading.Event()
        self.first_finished = threading.Event()
        self.first_mutation = threading.Event()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, status, data, headers=None):
                body = b"" if status == 204 else json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if fixture.mode in {"public", "shared"}:
                    fixture.calls.append({"method": "GET", "path": self.path})
                    identity = self.headers.get("Authorization")
                    if fixture.mode == "shared" and identity is None:
                        self.respond(401, {"error": "Unauthorized"})
                        return
                    record_id = "1001" if fixture.mode == "public" else self.path.rsplit("/", 1)[-1]
                    self.respond(200, {"id": record_id, "note": "Record " + record_id})
                    return
                count = fixture.patch_counts[self.path]
                if self.path == "/profile" and count == 1:
                    fixture.first_mutation.set()
                state = copy.deepcopy(fixture.states[self.path])
                headers = {}
                if self.path == "/profile":
                    if fixture.mode == "partial_after_echo" and count == 1:
                        state = {"role": "admin"}
                    elif fixture.mode in {"partial_nested_after", "partial_array_after"} and count == 1:
                        state = copy.deepcopy(fixture.original)
                        state["role"] = "admin"
                        if fixture.mode == "partial_nested_after":
                            state["profile"].pop("display")
                        else:
                            state["records"] = state["records"][:1]
                    elif fixture.mode in {"cached_after", "opaque_cached_after"} and count == 1:
                        state = copy.deepcopy(fixture.original)
                        if fixture.mode == "cached_after":
                            headers["Age"] = "120"
                    elif fixture.mode in {"cached_restore", "opaque_cached_restore"} and count >= 2:
                        state = copy.deepcopy(fixture.original)
                        if fixture.mode == "cached_restore":
                            headers["Age"] = "120"
                    elif fixture.mode == "cached_before" and count == 0:
                        headers["Warning"] = '110 fixture "Response is stale"'
                    elif fixture.mode == "missing_before_field" and count == 0:
                        state.pop("role")
                fixture.calls.append({"method": "GET", "path": self.path, "body": state, "headers": headers})
                self.respond(200, state, headers)

            def do_PATCH(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fixture.patch_counts[self.path] += 1
                count = fixture.patch_counts[self.path]
                fixture.calls.append({"method": "PATCH", "path": self.path, "body": payload})
                if fixture.mode == "nested_denied":
                    self.respond(403, {"error": "Forbidden"})
                    return
                if self.path == "/profile" and count >= 2:
                    if fixture.mode in {"restore_failure", "concurrent_failure"}:
                        if fixture.mode == "concurrent_failure":
                            fixture.contender.wait(2)
                        self.respond(500, {"error": "Restore failed"})
                        return
                    if fixture.mode in {"restore_ack_only", "cached_restore", "opaque_cached_restore"}:
                        self.respond(200, {"ok": True})
                        return
                if fixture.mode not in {"no_persistence", "partial_after_echo", "partial_nested_after", "partial_array_after"}:
                    fixture.states[self.path].update(copy.deepcopy(payload))
                if fixture.mode == "unrelated_side_effect" and count == 1:
                    fixture.states[self.path]["counter"] += 1
                self.respond(204 if fixture.mode == "ack_204" else 200, {"ok": True})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.directory = tempfile.TemporaryDirectory(prefix="granttrace-independent-")
        child = ({"profile": {"type": "object", "properties": {
            "server_marker": {"type": "boolean", "readOnly": True}, "display": {"type": "string"}
        }}} if nested else {"role": {"type": "string", "enum": ["user", "admin"], "readOnly": True}})
        operation = {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": child
        }}}}, "responses": {"200": {"description": "Update"}}}
        spec = {"openapi": "3.0.3", "paths": {
            "/profile": {"get": {"responses": {}}, "patch": operation},
            "/other": {"get": {"responses": {}}, "patch": copy.deepcopy(operation)},
        }}
        if mode in {"public", "shared"}:
            spec = {"openapi": "3.0.3", "paths": {"/items/{id}": {"get": {
                "security": [] if mode == "public" else [{"bearer": []}],
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Item"}}
            }}}}
        source = Path(self.directory.name) / "api.json"
        source.write_text(json.dumps(spec))
        field = "profile.server_marker" if nested else "role"
        mappings = {"PATCH " + path: {"method": "GET", "path": path,
                    "field_map": {field: field}, "consistency": "strong",
                    "readback_attempts": 1, "readback_delay": 0} for path in self.states}
        with patch("urllib.request.getproxies", return_value={}):
            self.auditor = APISentinelAuditor(
                str(source), f"http://127.0.0.1:{self.server.server_port}", request_delay=0,
                allow_write_tests=writes, write_allowlist=list(mappings) if listed else [],
                readback_config=mappings,
                bola_config={"GET /items/{id}": {"expected_visitor_access": "allow"}} if mode == "shared" else {},
            )
        if authority:
            # Observe the fixture's actual backing state, never its GET claims.
            from urllib.parse import urlsplit
            self.auditor._authoritative_patch_state = lambda ep, url, readback: copy.deepcopy(
                self.states[urlsplit(url).path])
        self.endpoints = self.auditor.parser.get_endpoints()

    def __enter__(self):
        self.thread.start()
        return self

    def scan(self, path="/profile"):
        endpoint = next(ep for ep in self.endpoints if ep["method"] == "PATCH" and ep["path"] == path)
        self.auditor.audit_endpoint_mass_assignment(endpoint, self.endpoints)

    def observe(self):
        result = {
            "case": self.mode, "state": copy.deepcopy(self.states),
            "patch_counts": dict(self.patch_counts),
            "requests": copy.deepcopy(self.calls),
            "initial_snapshot": copy.deepcopy(self.original),
            "halted": bool(self.auditor._writes_halted_reason),
            "verdicts": [{"endpoint": r["endpoint"], "check": r["check"], "verdict": r["verdict"],
                          "rollback_verified": r["evidence"].get("rollback_verified"),
                          "recovery_sent": r["evidence"].get("recovery_sent")} for r in self.auditor.results],
        }
        OBSERVATIONS.append(result)
        return result

    def __exit__(self, *args):
        self.observe()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.directory.cleanup()


class IndependentStateTests(unittest.TestCase):
    def test_known_cached_write_observation_is_not_trusted(self):
        with AdversarialAPI("cached_after") as api:
            api.scan()
            self.assertEqual(api.original, api.states["/profile"])
            self.assertNotIn(api.auditor.results[0]["verdict"], {"SECURE", "CONFIRMED"})

    def test_known_cached_restore_is_not_verified(self):
        with AdversarialAPI("cached_restore") as api:
            api.scan()
            self.assertFalse(api.auditor.results[0]["evidence"]["rollback_verified"])
            self.assertTrue(api.auditor._writes_halted_reason)
            api.scan("/other")
            self.assertEqual(0, api.patch_counts["/other"])

    def test_known_stale_initial_snapshot_sends_zero_patches(self):
        with AdversarialAPI("cached_before") as api:
            api.scan()
            self.assertEqual(0, api.patch_counts["/profile"])

    def test_partial_200_echo_cannot_confirm_persistence(self):
        with AdversarialAPI("partial_after_echo") as api:
            api.scan()
            self.assertEqual("user", api.states["/profile"]["role"])
            self.assertNotEqual("CONFIRMED", api.auditor.results[0]["verdict"])
            self.assertTrue(api.auditor.results[0]["evidence"]["rollback_verified"])

    def test_missing_configured_snapshot_field_prevents_writes(self):
        with AdversarialAPI("missing_before_field") as api:
            api.scan()
            self.assertEqual(0, api.patch_counts["/profile"])

    def test_nested_or_array_omissions_cannot_confirm_persistence(self):
        for mode in ("partial_nested_after", "partial_array_after"):
            with self.subTest(mode=mode), AdversarialAPI(mode) as api:
                api.scan()
                self.assertEqual("INCONCLUSIVE", api.auditor.results[0]["verdict"])
                self.assertEqual(api.original, api.states["/profile"])

    def test_failed_or_noop_restore_halts_all_later_writes(self):
        for mode in ("restore_failure", "restore_ack_only", "unrelated_side_effect"):
            with self.subTest(mode=mode), AdversarialAPI(mode) as api:
                api.scan()
                self.assertFalse(api.auditor.results[0]["evidence"]["rollback_verified"])
                self.assertTrue(api.auditor._writes_halted_reason)
                api.scan("/other")
                self.assertEqual(0, api.patch_counts["/other"])
                self.assertEqual("SKIPPED", api.auditor.results[-1]["verdict"])

    def test_successful_ack_requires_actual_readback_persistence(self):
        with AdversarialAPI("no_persistence") as api:
            api.scan()
            self.assertEqual("SECURE", api.auditor.results[0]["verdict"])
            self.assertEqual(api.original, api.states["/profile"])

    def test_204_ack_still_confirms_and_restores(self):
        with AdversarialAPI("ack_204") as api:
            api.scan()
            self.assertEqual("CONFIRMED", api.auditor.results[0]["verdict"])
            self.assertTrue(api.auditor.results[0]["evidence"]["rollback_verified"])
            self.assertEqual(api.original, api.states["/profile"])

    def test_nested_readonly_protection_and_injection_preserve_mutable_siblings(self):
        for mode, expected in (("nested_denied", "SECURE"), ("nested_injected", "CONFIRMED")):
            with self.subTest(mode=mode), AdversarialAPI(mode, nested=True) as api:
                api.scan()
                self.assertEqual(expected, api.auditor.results[0]["verdict"])
                self.assertEqual(api.original, api.states["/profile"])
                for call in api.calls:
                    if call["method"] == "PATCH":
                        self.assertEqual("Original display", call["body"]["profile"]["display"])

    def test_readonly_candidates_never_bypass_write_gates(self):
        for writes, listed in ((False, True), (True, False)):
            with self.subTest(writes=writes, listed=listed), AdversarialAPI(nested=True, writes=writes, listed=listed) as api:
                api.scan()
                self.assertEqual(0, api.patch_counts["/profile"])

    def test_unselected_readonly_field_is_never_written(self):
        with AdversarialAPI(nested=True) as api:
            api.auditor.readback_config["PATCH /profile"]["field_map"] = {"profile.display": "profile.display"}
            api.scan()
            self.assertEqual(0, api.patch_counts["/profile"])

    def test_keyboard_interrupt_after_commit_still_restores(self):
        with AdversarialAPI() as api:
            original = api.auditor._write_request
            first = True

            def interrupted(*args, **kwargs):
                nonlocal first
                result = original(*args, **kwargs)
                if first:
                    first = False
                    raise KeyboardInterrupt("synthetic interrupted caller")
                return result

            with patch.object(api.auditor, "_write_request", side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    api.scan()
            self.assertEqual(api.original, api.states["/profile"])
            self.assertIsNone(api.auditor._writes_halted_reason)

    def test_exit_during_restore_retains_write_halt(self):
        with AdversarialAPI() as api:
            original = api.auditor._write_request
            first = True

            def interrupted(*args, **kwargs):
                nonlocal first
                if not first:
                    raise SystemExit("synthetic interrupted restoration")
                first = False
                return original(*args, **kwargs)

            with patch.object(api.auditor, "_write_request", side_effect=interrupted):
                with self.assertRaises(SystemExit):
                    api.scan()
            self.assertTrue(api.auditor._writes_halted_reason)
            api.scan("/other")
            self.assertEqual(0, api.patch_counts["/other"])

    def test_waiting_concurrent_call_rechecks_halt_before_writing(self):
        with AdversarialAPI("concurrent_failure") as api:
            real_lock = api.auditor._resource_lock
            errors = []

            class WaitingLock:
                def __enter__(self):
                    api.contender.set()
                    if not api.first_finished.wait(3):
                        raise AssertionError("First scan never finished")
                    return self

                def __exit__(self, *args):
                    pass

            def controlled_lock(key):
                return WaitingLock() if threading.current_thread().name == "contender" else real_lock(key)

            def scan_first():
                try:
                    api.scan()
                except BaseException as exc:
                    errors.append(repr(exc))
                finally:
                    api.first_finished.set()

            def scan_next():
                try:
                    api.scan("/other")
                except BaseException as exc:
                    errors.append(repr(exc))

            with patch.object(api.auditor, "_resource_lock", side_effect=controlled_lock):
                first = threading.Thread(target=scan_first, name="first")
                contender = threading.Thread(target=scan_next, name="contender")
                first.start()
                self.assertTrue(api.first_mutation.wait(3), "First transaction never started")
                contender.start()
                first.join(timeout=4)
                contender.join(timeout=4)
                self.assertFalse(first.is_alive() or contender.is_alive())
            self.assertEqual([], errors)
            self.assertEqual(0, api.patch_counts["/other"])
            self.assertEqual("SKIPPED", api.auditor.results[-1]["verdict"])


class IndependentInterpretationTests(unittest.TestCase):
    owner = (200, '{"id":"account-7","secret_note":"Owner note"}')
    own = (200, '{"id":"account-8","secret_note":"Visitor note"}')

    def test_request_echo_errors_do_not_become_confirmed_access(self):
        for status in (400, 404, 500):
            for body in ({"request_id": "account-7"}, {"params": {"id": "account-7"}}, {"id": "account-7"}):
                with self.subTest(status=status, body=body):
                    result = ResponseDiffEngine.evaluate_bola(self.owner, (status, json.dumps(body)),
                        (401, '{"error":"Unauthorized"}'), visitor_self=self.own, resource_id_paths=["id"])
                    self.assertNotEqual("BOLA_CONFIRMED", result["verdict"])
                    self.assertEqual([], result["evidence"]["confirmation_signals"])

    def test_declared_public_resource_is_not_bola(self):
        result = ResponseDiffEngine.evaluate_bola(self.owner, self.owner, self.owner, expected_public=True)
        self.assertEqual("PUBLIC_ENDPOINT", result["verdict"])

    def test_real_http_public_and_shared_resources_are_not_confirmed_as_bola(self):
        for mode, verdict in (("public", "PUBLIC"), ("shared", "AUTHORIZED")):
            with self.subTest(mode=mode), AdversarialAPI(mode) as api:
                with contextlib.redirect_stdout(io.StringIO()):
                    api.auditor.run()
                self.assertEqual(verdict, api.auditor.results[0]["verdict"])
                self.assertFalse(api.auditor.findings)

    def test_swagger_uses_declared_media_with_parameters_and_case(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "spec.json"
            source.write_text(json.dumps({"swagger": "2.0", "paths": {"/profile": {"patch": {
                "consumes": ["application/xml", "Application/JSON ; charset=utf-8"],
                "parameters": [{"name": "body", "in": "body", "schema": {"type": "object"}}]
            }}}}))
            endpoint = OpenAPIParser(str(source)).get_endpoints()[0]
            self.assertEqual("Application/JSON ; charset=utf-8", endpoint["request_content_type"])

    def test_cached_state_headers_are_rejected_case_insensitively(self):
        for headers in ({"AGE": "2"}, {"Age": "invalid"}, {"Warning": '110 cache "Response is stale"'}):
            with self.subTest(headers=headers):
                self.assertIsNone(APISentinelAuditor._json_object(HTTPResult(200, '{"role":"user"}', headers=headers)))


if __name__ == "__main__":
    with contextlib.redirect_stdout(io.StringIO()):
        unittest.main()
