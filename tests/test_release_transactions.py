"""Release regressions: reject unverifiable readbacks before any PATCH."""

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.models import HTTPResult, strict_json_loads
from core.transactions import prepare_patch

ROOT = Path(__file__).resolve().parents[1]


class StrictReadbackTests(unittest.TestCase):
    def make_auditor(self):
        endpoint = {
            "method": "PATCH", "path": "/users/{user_id}", "parameters": [],
            "request_schema": {
                "type": "object",
                "properties": {"role": {"type": "string", "readOnly": True,
                                        "enum": ["user", "admin"]}},
            },
            "request_content_type": "application/json",
        }
        mapping = {"method": "GET", "path": endpoint["path"], "field_map": {"role": "role"},
                   "consistency": "strong", "readback_attempts": 1, "readback_delay": 0}
        auditor = APISentinelAuditor(
            str(ROOT / "openapi.json"), "http://127.0.0.1:8080", request_delay=0,
            allow_write_tests=True, write_allowlist=["PATCH " + endpoint["path"]],
            readback_config={"PATCH " + endpoint["path"]: mapping},
        )
        return auditor, endpoint

    def test_valid_finite_numbers_and_literal_strings_are_preserved(self):
        body = '{"number":1.25,"large":1e300,"bool":true,"text":"NaN Infinity"}'
        self.assertEqual(strict_json_loads(body), json.loads(body))

    def test_nonfinite_readback_never_sends_a_write(self):
        for literal in ("NaN", "Infinity", "-Infinity", "1e400", "-1e400"):
            with self.subTest(literal=literal):
                auditor, endpoint = self.make_auditor()
                requests = []

                def respond(method, url, data=None, **kwargs):
                    requests.append(method)
                    self.assertEqual(method, "GET", "Invalid snapshots must never reach PATCH")
                    return HTTPResult(200, '{"role":"user","telemetry":' + literal + '}')

                with patch.object(auditor, "_http_request", side_effect=respond):
                    auditor.audit_endpoint_mass_assignment(endpoint, [endpoint])
                self.assertEqual(requests, ["GET"])
                self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")
                self.assertFalse(auditor.findings)
                self.assertIsNone(auditor._writes_halted_reason)

    def test_nested_nonfinite_value_invalidates_the_entire_readback(self):
        response = HTTPResult(200, '{"role":"user","metadata":{"samples":[1,NaN]}}')
        self.assertIsNone(APISentinelAuditor._json_object(response))

    def test_direct_snapshot_cannot_hide_nonfinite_value_as_volatile(self):
        case = {"field_path": "role", "value": "admin", "payload": {"role": "admin"}}
        mapping = {"field_map": {"role": "role"}, "ignore_readback_paths": ["telemetry"]}
        for number in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(number=repr(number)), self.assertRaises(ValueError):
                prepare_patch({"role": "user", "telemetry": number}, case, mapping)

    def test_original_snapshot_must_match_before_transport(self):
        auditor, endpoint = self.make_auditor()
        before = {"role": "user"}
        snapshot = prepare_patch(before, {"field_path": "role", "value": "admin",
                                         "payload": {"role": "admin"}},
                                 {"field_map": {"role": "role"}})
        snapshot.document["role"] = "different"
        with patch.object(auditor, "_readback_result", return_value=("readback", HTTPResult(200, json.dumps(before)))), \
                patch("core.auditor.prepare_patch", return_value=snapshot), \
                patch.object(auditor, "_http_request") as transport:
            auditor.audit_endpoint_mass_assignment(endpoint, [endpoint])
        transport.assert_not_called()
        self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")

    def test_invalid_postwrite_readback_still_restores_state(self):
        auditor, endpoint = self.make_auditor()
        state = {"role": "user"}
        original = copy.deepcopy(state)
        writes = []
        read_count = 0

        def respond(method, url, data=None, **kwargs):
            nonlocal read_count
            if method == "PATCH":
                writes.append(copy.deepcopy(data))
                state.update(data)
                return HTTPResult(200, '{"ok":true}')
            read_count += 1
            if read_count == 2:
                return HTTPResult(200, '{"role":"admin","telemetry":Infinity}')
            return HTTPResult(200, json.dumps(state))

        with patch.object(auditor, "_http_request", side_effect=respond):
            auditor.audit_endpoint_mass_assignment(endpoint, [endpoint])
        self.assertEqual(writes, [{"role": "admin"}, {"role": "user"}])
        self.assertEqual(state, original)
        self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")
        self.assertIsNone(auditor._writes_halted_reason)

    def test_valid_snapshot_still_confirms_and_restores(self):
        auditor, endpoint = self.make_auditor()
        state = {"role": "user", "telemetry": 1.25}
        original = copy.deepcopy(state)
        writes = []

        def respond(method, url, data=None, **kwargs):
            if method == "PATCH":
                writes.append(copy.deepcopy(data))
                state.update(data)
                return HTTPResult(200, '{"ok":true}')
            return HTTPResult(200, json.dumps(state))

        with patch.object(auditor, "_http_request", side_effect=respond):
            auditor.audit_endpoint_mass_assignment(endpoint, [endpoint])
        self.assertEqual(len(writes), 2)
        self.assertEqual(state, original)
        self.assertEqual(auditor.results[0]["verdict"], "CONFIRMED")
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])


if __name__ == "__main__":
    unittest.main()
