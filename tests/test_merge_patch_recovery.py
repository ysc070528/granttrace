"""Active probes must be restorable under the server's actual PATCH semantics."""

import copy
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator


class MergePatchRecoveryTests(unittest.TestCase):
    def scan(self, original, field_schema, content_type="application/merge-patch+json"):
        state = copy.deepcopy(original)
        requests = []

        def merge_patch(target, changes):
            # RFC 7396 section 2: recurse into objects, delete null members,
            # and replace scalar/array values. An empty object is not a reset.
            if isinstance(changes, dict):
                target = copy.deepcopy(target) if isinstance(target, dict) else {}
                for name in changes:
                    if changes[name] is None:
                        if name in target:
                            del target[name]
                    else:
                        target[name] = merge_patch(target.get(name), changes[name])
                return target
            return copy.deepcopy(changes)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, value):
                body = json.dumps(value).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                requests.append(("GET", None, None))
                self.respond(state)

            def do_PATCH(self):
                changes = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                media = self.headers["Content-Type"]
                requests.append(("PATCH", media, changes))
                if media == "application/merge-patch+json":
                    updated = merge_patch(state, changes)
                    state.clear()
                    state.update(updated)
                else:
                    state.update(changes)
                self.respond({"ok": True})

        spec = {
            "openapi": "3.0.3", "info": {"title": "Synthetic recovery test", "version": "1"},
            "paths": {"/profile": {
                "get": {"responses": {"200": {"description": "Profile"}}},
                "patch": {
                    "requestBody": {"content": {content_type: {"schema": {
                        "type": "object", "properties": {"permissions": field_schema},
                    }}}},
                    "responses": {"200": {"description": "Updated"}},
                },
            }},
        }
        identities = {
            "owner": {"id": "1", "token": "Bearer SYNTHETIC_OWNER"},
            "visitor": {"id": "2", "token": "Bearer SYNTHETIC_VISITOR"},
            "anonymous": {},
        }
        readback = {
            "method": "GET", "path": "/profile", "field_map": {"permissions": "permissions"},
            "consistency": "strong", "readback_attempts": 1, "readback_delay": 0,
        }
        config = {"identities": identities, "write_allowlist": ["PATCH /profile"],
                  "readbacks": {"PATCH /profile": readback}}
        self.assertTrue(ConfigValidator.validate(config, spec).is_valid)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="granttrace-merge-patch-") as directory:
                spec_path = Path(directory) / "spec.json"
                spec_path.write_text(json.dumps(spec), encoding="utf-8")
                # Keep this loopback fixture independent of machine proxy settings.
                with patch("urllib.request.getproxies", return_value={}):
                    auditor = APISentinelAuditor(
                        str(spec_path), f"http://127.0.0.1:{server.server_port}", request_delay=0,
                        identities_config=identities, allow_write_tests=True,
                        write_allowlist=config["write_allowlist"], readback_config=config["readbacks"],
                    )
                endpoints = auditor.parser.get_endpoints()
                endpoint = next(item for item in endpoints if item["method"] == "PATCH")
                auditor.audit_endpoint_mass_assignment(endpoint, endpoints)
                return auditor, state, requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def assert_rejected_without_patch(self, original, field_schema, reason):
        auditor, state, requests = self.scan(original, field_schema)
        self.assertEqual(state, original)
        self.assertEqual(requests, [("GET", None, None)])
        self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")
        self.assertIn(reason, auditor.results[0]["reason"])
        self.assertFalse(auditor.findings)
        self.assertIsNone(auditor._writes_halted_reason)

    def test_added_object_privilege_member_is_rejected_before_patch(self):
        self.assert_rejected_without_patch(
            {"permissions": {}},
            {"type": "object", "readOnly": True, "example": {"admin": True},
             "properties": {"admin": {"type": "boolean"}}},
            "cannot be reversed",
        )

    def test_nested_added_members_are_rejected_before_patch(self):
        self.assert_rejected_without_patch(
            {"permissions": {"scope": {"reader": True}}},
            {"type": "object", "readOnly": True, "example": {"scope": {"admin": True}},
             "properties": {"scope": {"type": "object", "properties": {
                 "admin": {"type": "boolean"}, "reader": {"type": "boolean"},
             }}}},
            "cannot be reversed",
        )

    def test_present_null_object_member_remains_rejected(self):
        self.assert_rejected_without_patch(
            {"permissions": {"admin": False, "note": None}},
            {"type": "object", "readOnly": True, "example": {"admin": True},
             "properties": {"admin": {"type": "boolean"},
                            "note": {"type": "string", "nullable": True}}},
            "cannot restore present null object members",
        )

    def test_existing_object_member_probe_still_confirms_and_restores(self):
        original = {"permissions": {"admin": False}}
        auditor, state, requests = self.scan(
            original,
            {"type": "object", "readOnly": True, "example": {"admin": True},
             "properties": {"admin": {"type": "boolean"}}},
        )
        self.assertEqual(state, original)
        self.assertEqual([request[0] for request in requests], ["GET", "PATCH", "GET", "PATCH", "GET"])
        self.assertEqual(auditor.results[0]["verdict"], "CONFIRMED")
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])
        self.assertIsNone(auditor._writes_halted_reason)

    def test_scalar_probe_still_confirms_and_restores(self):
        original = {"permissions": "user"}
        auditor, state, requests = self.scan(
            original, {"type": "string", "readOnly": True, "enum": ["user", "admin"]},
        )
        self.assertEqual(state, original)
        self.assertEqual(len([request for request in requests if request[0] == "PATCH"]), 2)
        self.assertEqual(auditor.results[0]["verdict"], "CONFIRMED")
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])

    def test_complete_array_with_nulls_still_restores(self):
        original = {"permissions": [{"admin": False, "note": None}]}
        auditor, state, requests = self.scan(
            original,
            {"type": "array", "readOnly": True, "items": {
                "type": "object", "example": {"admin": True}, "properties": {
                    "admin": {"type": "boolean"}, "note": {"type": "string", "nullable": True},
                },
            }},
        )
        self.assertEqual(state, original)
        self.assertEqual(len([request for request in requests if request[0] == "PATCH"]), 2)
        self.assertEqual(auditor.results[0]["verdict"], "CONFIRMED")
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])

    def test_application_json_object_replacement_is_not_restricted(self):
        original = {"permissions": {}}
        auditor, state, requests = self.scan(
            original,
            {"type": "object", "readOnly": True, "example": {"admin": True},
             "properties": {"admin": {"type": "boolean"}}},
            content_type="application/json",
        )
        self.assertEqual(state, original)
        self.assertEqual(len([request for request in requests if request[0] == "PATCH"]), 2)
        self.assertEqual(auditor.results[0]["verdict"], "CONFIRMED")
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])


if __name__ == "__main__":
    unittest.main()
