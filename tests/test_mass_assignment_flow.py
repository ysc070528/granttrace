"""Control flow of a mass-assignment check across its fields.

_audit_endpoint_mass_assignment was split into preflight, per-field and
summary steps; a per-field step either stops the whole check after recording
a final result or moves on to the next field. These tests drive each such
branch without a network: the fixture supplies authoritative state the way
the bundled demo does, and the readback and write transaction are replaced.
"""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.models import HTTPResult
from core.parameters import ParameterSerializationError

PATH = "/api/v1/records/rec-1"
STATE = {"id": "rec-1", "title": "original", "role": "reader", "is_admin": False}
SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "flow", "version": "1"},
    "paths": {
        PATH: {
            "get": {"responses": {"200": {"description": "OK"}}},
            "patch": {
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "role": {"type": "string", "readOnly": True},
                        "is_admin": {"type": "boolean", "readOnly": True},
                    },
                }}}},
                "responses": {"200": {"description": "Updated"}},
            },
        }
    },
}
IDENTITIES = {
    "owner": {"id": "1001", "token": "Bearer OWNER", "parameters": {}},
    "visitor": {"id": "1002", "token": "Bearer VISITOR", "parameters": {}},
    "anonymous": {"id": None, "token": None, "parameters": {}},
}


class _StateAuditor(APISentinelAuditor):
    """Authoritative state from a dictionary, as the demo reads its database."""

    state: Dict[str, Any] = {}

    def _authoritative_patch_state(self, ep, mutation_url, readback):  # noqa: ANN001
        return copy.deepcopy(self.state)


def _ok(document: Dict[str, Any], status: int = 200) -> HTTPResult:
    return HTTPResult(status=status, body=json.dumps(document))


class MassAssignmentFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        spec_path = Path(directory.name) / "spec.json"
        spec_path.write_text(json.dumps(SPEC), encoding="utf-8")
        self.auditor = _StateAuditor(
            str(spec_path), "https://api.example.test", request_delay=0, identities_config=IDENTITIES,
            allow_write_tests=True, write_allowlist=["PATCH " + PATH],
            readback_config={"PATCH " + PATH: {
                "method": "GET", "path": PATH, "field_map": {"role": "role", "is_admin": "is_admin"},
                "consistency": "strong",
            }},
        )
        self.auditor.state = copy.deepcopy(STATE)
        self.endpoints = self.auditor.parser.get_endpoints()
        self.ep = next(ep for ep in self.endpoints if ep["method"].upper() == "PATCH")
        self.transactions: List[Dict[str, Any]] = []

    def scan(self, readback: Any, after: Optional[Dict[str, Any]] = None,
             mutation: Optional[HTTPResult] = None) -> List[Dict[str, Any]]:
        def execute(ep, mutation_url, readback_mapping, snapshot):  # noqa: ANN001
            self.transactions.append({"field": snapshot.read_path})
            after_document = copy.deepcopy(STATE) if after is None else after
            return {
                "mutation": mutation or _ok(STATE), "after_http": _ok(after_document), "after": after_document,
                "rollback": _ok(STATE), "restored": _ok(STATE), "rollback_verified": True,
                "recovery_sent": False, "failure": None,
            }

        with patch.object(self.auditor, "_readback_result", **readback), \
                patch.object(self.auditor, "_execute_patch_case", side_effect=execute), \
                patch.object(self.auditor, "_http_request", side_effect=AssertionError("network")):
            self.auditor.audit_endpoint_mass_assignment(self.ep, self.endpoints)
        return [r for r in self.auditor.results if r["check"] == "MASS_ASSIGNMENT"]

    def readback_ok(self) -> Dict[str, Any]:
        return {"return_value": ("https://api.example.test" + PATH, _ok(STATE))}

    def test_unchanged_state_for_every_field_is_secure(self) -> None:
        results = self.scan(self.readback_ok())
        self.assertEqual([r["verdict"] for r in results], ["SECURE"])
        self.assertEqual(len(self.transactions), 2)
        self.assertEqual(sorted(results[0]["evidence"]["safe_fields"]), ["is_admin", "role"])

    def test_read_before_write_failure_stops_the_check(self) -> None:
        results = self.scan({"return_value": ("u", HTTPResult(status=0, body="", error="boom"))})
        self.assertEqual([(r["verdict"], r["reason"]) for r in results],
                         [("ERROR", "Read-before-write failed: boom")])
        self.assertEqual(self.transactions, [])

    def test_readback_that_cannot_be_built_stops_the_check(self) -> None:
        results = self.scan({"side_effect": ParameterSerializationError("bad readback parameter")})
        self.assertEqual([(r["verdict"], r["reason"]) for r in results],
                         [("INCONCLUSIVE", "bad readback parameter")])
        self.assertEqual(self.transactions, [])

    def test_unexpected_change_moves_on_to_the_next_field(self) -> None:
        changed = dict(STATE, title="changed elsewhere")
        results = self.scan(self.readback_ok(), after=changed)
        self.assertEqual(len(self.transactions), 2, "both fields were tested")
        self.assertEqual([r["verdict"] for r in results], ["INCONCLUSIVE"])
        self.assertEqual(results[0]["reason"].count("unexpected state change; original snapshot restored"), 2)

    def test_rejected_mutation_moves_on_and_stays_inconclusive(self) -> None:
        rejected = HTTPResult(status=422, body=json.dumps({"error": "field is read-only"}))
        results = self.scan(self.readback_ok(), mutation=rejected)
        self.assertEqual(len(self.transactions), 2)
        self.assertEqual([r["verdict"] for r in results], ["INCONCLUSIVE"])
        self.assertEqual(results[0]["reason"].count("mutation was rejected or returned a business error"), 2)

    def test_persisted_field_confirms_and_stops(self) -> None:
        escalated = dict(STATE)
        results_before = len(self.auditor.results)

        def persisted_after(ep, mutation_url, readback_mapping, snapshot):  # noqa: ANN001
            document = dict(escalated)
            document[snapshot.read_path[-1] if isinstance(snapshot.read_path, (list, tuple)) else snapshot.read_path] = snapshot.target
            self.transactions.append({"field": snapshot.read_path})
            return {"mutation": _ok(document), "after_http": _ok(document), "after": document,
                    "rollback": _ok(STATE), "restored": _ok(STATE), "rollback_verified": True,
                    "recovery_sent": False, "failure": None}

        with patch.object(self.auditor, "_readback_result", **self.readback_ok()), \
                patch.object(self.auditor, "_execute_patch_case", side_effect=persisted_after), \
                patch.object(self.auditor, "_http_request", side_effect=AssertionError("network")):
            self.auditor.audit_endpoint_mass_assignment(self.ep, self.endpoints)
        results = [r for r in self.auditor.results[results_before:] if r["check"] == "MASS_ASSIGNMENT"]
        self.assertEqual([r["verdict"] for r in results], ["CONFIRMED"])
        self.assertEqual(len(self.transactions), 1, "the first persisted field ends the check")
        self.assertEqual(self.auditor.stats["mass_assignment_confirmed"], 1)


if __name__ == "__main__":
    unittest.main()
