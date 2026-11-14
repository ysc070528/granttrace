"""Offline comparison of two GrantTrace JSON reports (`granttrace diff`).

The suite is organised around one invariant: a finding is reported as new,
persisting or resolved only when both reports are shown to cover the same
target, test identities, specification, policy and resources, or the caller
states the missing part as an explicit assumption. Everything else is not
comparable.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
import random
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from unittest.mock import patch

import api_sentinel
from core import demo, report_diff
from core.report_diff import (
    ComparisonKeyError, ReportError, build_comparison_context, compare_reports, comparison_key_from_environment,
    finding_id, specification_security_schemes, validate_report,
)

ROOT = Path(__file__).resolve().parents[1]
OP = "GET /api/items/{id}"
OTHER = "GET /api/orders/{id}"
THIRD = "GET /api/notes/{id}"
PATCH_OP = "PATCH /api/users/{id}/settings"
KEY = "unit-test-comparison-key-0123456789"
OTHER_KEY = "another-comparison-key-9876543210zyx"
TARGET = "http://127.0.0.1:8000"
NEGATIVE = ("SECURE", "PUBLIC", "AUTHORIZED")
UNVERIFIED = ("SKIPPED", "INCONCLUSIVE", "ERROR", "SUSPICIOUS", "NOT-A-VERDICT")
CONCLUSIONS = ("new", "persisting", "resolved")


def result(check: str, endpoint: str, verdict: str, **evidence: Any) -> Dict[str, Any]:
    return {"endpoint": endpoint, "operation_id": "op", "check": check, "verdict": verdict,
            "reason": "synthetic", "evidence": evidence}


def bola(verdict: str, endpoint: str = OP, path: str = "/api/items/1") -> Dict[str, Any]:
    return result("BOLA", endpoint, verdict, target_url=TARGET + path, visitor_self_url=TARGET + "/api/items/2")


def report(results: List[Any], *, version: str = "2.8.0", target: Any = TARGET,
           context: Optional[Dict[str, Any]] = None, stats: Optional[Dict[str, Any]] = None,
           generated_at: str = "2026-11-13T00:00:00Z") -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "tool_version": version, "report_schema_version": 2, "generated_at": generated_at,
        "elapsed_seconds": 1.0, "target": target, "stats": stats or {}, "results": results, "findings": [],
    }
    if context is not None:
        data["comparison_context"] = context
    return data


def endpoint(operation: str, **extra: Any) -> Dict[str, Any]:
    method, path = operation.split(" ")
    return dict({"method": method, "path": path, "operation_id": "op", "parameters": [],
                 "security": [{"bearer": []}], "security_declared": True}, **extra)


def identities(owner_id: Optional[str] = "1001", visitor_id: Optional[str] = "1002",
               visitor_token: str = "Bearer VISITOR-VALUE", **more: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"owner": {"id": owner_id, "token": "Bearer OWNER-VALUE"},
                            "visitor": {"id": visitor_id, "token": visitor_token}, "anonymous": {}}
    for name, extra in more.items():
        if name == "roles":
            data["roles"] = extra
        else:
            data[name].update(extra)
    return data


def context(*, target: str = TARGET, key: str = KEY, operations: Sequence[str] = (OP, OTHER, THIRD, PATCH_OP),
            endpoints: Optional[List[Dict[str, Any]]] = None, who: Optional[Dict[str, Any]] = None,
            **sections: Any) -> Dict[str, Any]:
    """A keyed context for a scan of `operations` with identities that declare account ids."""
    who = who if who is not None else identities()
    secrets = [str(value.get("token")) for value in who.values() if isinstance(value, dict) and value.get("token")]
    secrets.extend(sections.pop("more_secrets", ()))
    return build_comparison_context(
        key=key, target=target, identities=who,
        endpoints=endpoints if endpoints is not None else [endpoint(operation) for operation in operations],
        secret_values=secrets, **sections)


def keyed(results: List[Any], **options: Any) -> Dict[str, Any]:
    """A report from a keyed scan; context options go to `context`, the rest to `report`."""
    report_options = {name: options.pop(name) for name in ("version", "stats", "generated_at") if name in options}
    return report(results, target=options.get("target", TARGET), context=context(**options), **report_options)


def by_id(comparison: Dict[str, Any]) -> Dict[Tuple[str, str, Optional[str]], Dict[str, Any]]:
    return {(issue["check"], issue["operation"], issue.get("subject")): issue for issue in comparison["issues"]}


def only(comparison: Dict[str, Any]) -> Dict[str, Any]:
    assert len(comparison["issues"]) == 1, comparison["issues"]
    return comparison["issues"][0]


class FindingIdentityTests(unittest.TestCase):
    def test_finding_id_depends_only_on_check_operation_and_subject(self):
        self.assertEqual(finding_id("BOLA", OP), finding_id("BOLA", OP, None))
        self.assertRegex(finding_id("BOLA", OP), r"^gtf_[0-9a-f]{16}$")
        identifiers = {finding_id("BOLA", OP), finding_id("BFLA", OP), finding_id("BOLA", OTHER),
                       finding_id("RBAC", OP, "role:auditor"), finding_id("RBAC", OP, "role:viewer")}
        self.assertEqual(len(identifiers), 5)

    def test_identifiers_ignore_target_port_time_key_and_evidence(self):
        first = keyed([bola("CONFIRMED")], target="http://127.0.0.1:40001", generated_at="2026-11-13T00:00:00Z")
        second = keyed([bola("CONFIRMED")], target="http://127.0.0.1:50002", key=OTHER_KEY,
                       generated_at="2026-11-20T09:30:00Z")
        second["results"][0]["evidence"]["request_id"] = "random-7f3a"
        # The identifier is the same wherever and whenever the finding was seen; comparability is separate.
        blocked = compare_reports(first, second)
        assumed = compare_reports(first, second, assume_same_target=True, assume_same_identities=True)
        self.assertEqual((only(blocked)["status"], only(assumed)["status"]), ("not_comparable", "persisting"))
        for comparison in (blocked, assumed):
            self.assertEqual(only(comparison)["finding_id"], finding_id("BOLA", OP))


class StatusMatrixTests(unittest.TestCase):
    """Every transition of one finding between two reports with a verified, unchanged context.

    A verdict list holds the verdicts of all records for the finding; [] means
    the operation was scanned without this check, None that it is absent.
    """

    MATRIX: List[Tuple[Optional[List[str]], Optional[List[str]], Optional[str], Optional[str]]] = (
        [(["CONFIRMED"], ["CONFIRMED"], "persisting", None)]
        + [(["CONFIRMED"], [verdict], "resolved", None) for verdict in NEGATIVE]
        + [(["CONFIRMED"], [verdict], "not_comparable", "current_unverified") for verdict in UNVERIFIED]
        + [([verdict], ["CONFIRMED"], "new", None) for verdict in NEGATIVE]
        + [([verdict], ["CONFIRMED"], "not_comparable", "baseline_unverified") for verdict in UNVERIFIED]
        + [
            # Contradicting records for one finding: CONFIRMED wins, and one unverified record spoils a fix.
            (["CONFIRMED"], ["SECURE", "CONFIRMED"], "persisting", None),
            (["CONFIRMED"], ["SECURE", "SKIPPED"], "not_comparable", "current_unverified"),
            (["CONFIRMED"], ["SECURE", "PUBLIC"], "resolved", None),
            (["SECURE", "CONFIRMED"], ["SECURE"], "resolved", None),
            (["SECURE", "INCONCLUSIVE"], ["CONFIRMED"], "not_comparable", "baseline_unverified"),
            (["SECURE", "CONFIRMED"], ["CONFIRMED"], "persisting", None),
            # Missing records and operations.
            (["CONFIRMED"], [], "not_comparable", "missing_in_current"),
            (["CONFIRMED"], None, "not_comparable", "operation_not_in_current"),
            ([], ["CONFIRMED"], "not_comparable", "not_checked_in_baseline"),
            (None, ["CONFIRMED"], "not_comparable", "operation_not_in_baseline"),
            # No confirmed finding on either side: nothing to classify.
            (["SECURE"], ["SECURE"], None, None),
            (["SKIPPED"], ["SECURE"], None, None),
            (["SECURE"], ["INCONCLUSIVE"], None, None),
            ([], [], None, None),
        ])

    @staticmethod
    def records(verdicts: Optional[List[str]]) -> List[Dict[str, Any]]:
        if verdicts is None:
            return [bola("SECURE", OTHER)]
        return [bola(verdict) for verdict in verdicts] + [
            result("BFLA", OP, "SECURE", target_url=TARGET + "/api/items/1"), bola("SECURE", OTHER)]

    def compare(self, before: Optional[List[str]], after: Optional[List[str]], *,
                baseline: Optional[Dict[str, Any]] = None, current: Optional[Dict[str, Any]] = None,
                **assumptions: bool) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        old = keyed(self.records(before), **(baseline or {}))
        new = keyed(self.records(after), **(current or {}))
        comparison = compare_reports(old, new, **assumptions)
        return comparison, by_id(comparison).get(("BOLA", OP, None))

    def test_every_transition_with_a_verified_context(self):
        for before, after, status, reason in self.MATRIX:
            with self.subTest(before=before, after=after):
                comparison, issue = self.compare(before, after)
                if status is None:
                    self.assertIsNone(issue)
                    continue
                assert issue is not None
                self.assertEqual(issue["status"], status)
                self.assertEqual(issue.get("reasons"), [reason] if reason else None)
                # A verdict this version does not know is reported as UNKNOWN, never copied.
                for name, verdicts in (("baseline_verdicts", before), ("current_verdicts", after)):
                    self.assertEqual(issue[name], sorted({verdict if verdict != "NOT-A-VERDICT" else "UNKNOWN"
                                                          for verdict in verdicts or []}))
                self.assertNotIn("assumptions", issue)
                self.assertTrue(comparison["comparability"]["fully_comparable"])
                self.assertEqual(comparison["comparability"]["basis"], "declared")
                self.assertEqual(comparison["summary"][status], 1)

    def test_summary_separates_first_detections_from_new_findings(self):
        for before, after in ((["SKIPPED"], ["CONFIRMED"]), ([], ["CONFIRMED"]), (None, ["CONFIRMED"])):
            with self.subTest(before=before):
                comparison, _ = self.compare(before, after)
                self.assertEqual(comparison["summary"]["new"], 0)
                self.assertEqual(comparison["summary"]["current_confirmed_not_comparable"], 1)
        comparison, _ = self.compare(["SECURE"], ["CONFIRMED"])
        self.assertEqual((comparison["summary"]["new"], comparison["summary"]["current_confirmed_not_comparable"]),
                         (1, 0))

    # Each entry makes the two reports incomparable for OP: (name, baseline options, current options, reason).
    BLOCKERS: List[Tuple[str, Dict[str, Any], Dict[str, Any], str]] = [
        ("another port", {}, {"target": "http://127.0.0.1:8001"}, "target_changed"),
        ("another host", {"target": "https://staging.example"}, {"target": "https://production.example"},
         "target_changed"),
        ("another scheme", {"target": "http://api.example"}, {"target": "https://api.example"}, "target_changed"),
        ("another base path", {"target": "https://api.example/v1"}, {"target": "https://api.example/v2"},
         "target_changed"),
        ("unreadable target", {"target": "[BOPLA TARGET OMITTED]"}, {"target": "[BOPLA TARGET OMITTED]"},
         "target_unknown"),
        ("visitor account id", {}, {"who": identities(visitor_id="2002")}, "identities_changed"),
        ("owner account id", {}, {"who": identities(owner_id="9")}, "identities_changed"),
        ("visitor header", {}, {"who": identities(visitor={"headers": {"X-Tenant": "other"}})}, "identities_changed"),
        ("visitor parameters", {}, {"who": identities(visitor={"parameters": {"tenant": "b"}})}, "identities_changed"),
        ("anonymous parameters", {}, {"who": identities(anonymous={"parameters": {"tenant": "b"}})},
         "identities_changed"),
        ("role added", {}, {"who": identities(roles={"auditor": {"id": "7", "token": "Bearer R"}})},
         "identities_changed"),
        ("credential of another account", {}, {"who": identities(visitor_token="Bearer SOMEONE-ELSE")},
         "identities_unverified"),
        ("no account ids", {"who": identities(None, None)}, {"who": identities(None, None)}, "identities_unverified"),
        ("visitor without account id", {"who": identities(visitor_id=None)}, {"who": identities(visitor_id=None)},
         "identities_unverified"),
        ("different keys", {}, {"key": OTHER_KEY}, "identities_unverified"),
        ("specification", {}, {"endpoints": [endpoint(OP, security=[], security_declared=True), endpoint(OTHER)]},
         "spec_changed"),
        ("new required parameter", {}, {"endpoints": [
            endpoint(OP, parameters=[{"name": "edge", "in": "query", "required": True}]), endpoint(OTHER)]},
         "spec_changed"),
        ("security schemes", {"security_schemes": {"bearer": {"type": "http"}}},
         {"security_schemes": {"bearer": {"type": "apiKey", "name": "X-Key", "in": "header"}}}, "spec_changed"),
        ("policy", {"bola_config": {OP: {"resource_id_paths": ["id"]}}},
         {"bola_config": {OP: {"resource_id_paths": ["id"], "not_found_is_denial": True}}}, "policy_changed"),
        ("policy added", {}, {"bola_config": {OP: {"expected_visitor_access": "allow"}}}, "policy_changed"),
        ("resources", {"parameter_values": {OP: {"owner": {"id": 1}}}},
         {"parameter_values": {OP: {"owner": {"id": 7}}}}, "resources_changed"),
        ("operation missing from a context", {}, {"operations": (OTHER,)}, "context_incomplete"),
        ("declared credential headers", {}, {"who": identities(visitor={"auth_header_names": ["X-Session"]})},
         "identities_changed"),
        ("role removed", {"who": identities(roles={"auditor": {"id": "7", "token": "Bearer R"}})}, {},
         "identities_changed"),
        ("write allowlist", {}, {"write_allowlist": [OP]}, "policy_changed"),
        ("readback", {"readback_config": {OP: {"method": "GET", "path": "/a"}}},
         {"readback_config": {OP: {"method": "GET", "path": "/b"}}}, "policy_changed"),
        ("field policy", {"bopla_config": {OP: {"fields": [{"rule_id": "a"}]}}},
         {"bopla_config": {OP: {"fields": [{"rule_id": "b"}]}}}, "policy_changed"),
        ("one target unreadable", {"target": "not-a-url"}, {}, "target_unknown"),
        ("other target unreadable", {}, {"target": "not-a-url"}, "target_unknown"),
    ]
    CONCLUSIVE_ROWS = [(["CONFIRMED"], ["CONFIRMED"], "persisting"), (["CONFIRMED"], ["SECURE"], "resolved"),
                       (["SECURE"], ["CONFIRMED"], "new")]

    def test_every_blocker_turns_every_conclusion_into_not_comparable(self):
        for name, baseline, current, reason in self.BLOCKERS:
            for before, after, status in self.CONCLUSIVE_ROWS:
                with self.subTest(blocker=name, would_be=status):
                    comparison, issue = self.compare(before, after, baseline=baseline, current=current)
                    assert issue is not None
                    self.assertEqual(issue["status"], "not_comparable")
                    self.assertIn(reason, issue["reasons"])
                    self.assertFalse(comparison["comparability"]["fully_comparable"])
                    self.assertEqual([comparison["summary"][key] for key in CONCLUSIONS], [0, 0, 0])

    def test_no_context_in_either_report_is_not_comparable(self):
        for before, after, _ in self.CONCLUSIVE_ROWS:
            for old_keyed, new_keyed in ((False, False), (True, False), (False, True)):
                with self.subTest(before=before, old_keyed=old_keyed, new_keyed=new_keyed):
                    old = (keyed if old_keyed else report)(self.records(before))
                    new = (keyed if new_keyed else report)(self.records(after))
                    comparison = compare_reports(old, new)
                    issue = by_id(comparison)[("BOLA", OP, None)]
                    self.assertEqual((issue["status"], issue["reasons"]), ("not_comparable", ["identities_unverified"]))
                    self.assertEqual(comparison["comparability"]["basis"], "evidence")

    def test_assumptions_restore_conclusions_and_are_recorded_on_every_finding(self):
        cases = [
            ("another port", {}, {"target": "http://127.0.0.1:8001"}, {"assume_same_target": True}, ["same_target"]),
            ("unreadable target", {"target": "x"}, {"target": "x"}, {"assume_same_target": True}, ["same_target"]),
            ("credential changed", {}, {"who": identities(visitor_token="Bearer ROTATED")},
             {"assume_same_identities": True}, ["same_identities"]),
            ("no account ids", {"who": identities(None, None)}, {"who": identities(None, None)},
             {"assume_same_identities": True}, ["same_identities"]),
            ("different keys and ports", {}, {"key": OTHER_KEY, "target": "http://127.0.0.1:8001"},
             {"assume_same_target": True, "assume_same_identities": True}, ["same_target", "same_identities"]),
        ]
        for name, baseline, current, flags, expected in cases:
            for before, after, status in self.CONCLUSIVE_ROWS:
                with self.subTest(case=name, status=status):
                    comparison, issue = self.compare(before, after, baseline=baseline, current=current, **flags)
                    assert issue is not None
                    self.assertEqual(issue["status"], status)
                    self.assertEqual(issue["assumptions"], expected)
                    self.assertEqual(comparison["comparability"]["assumptions"], expected)
                    self.assertFalse(comparison["comparability"]["fully_comparable"])
                    self.assertEqual(comparison["summary"]["relying_on_assumptions"], 1)

    def test_assumptions_never_override_a_detected_change(self):
        both = {"assume_same_target": True, "assume_same_identities": True}
        for name, baseline, current, reason in self.BLOCKERS:
            if reason in ("target_changed", "target_unknown", "identities_unverified"):
                continue
            with self.subTest(blocker=name):
                comparison, issue = self.compare(["CONFIRMED"], ["SECURE"], baseline=baseline, current=current,
                                                 **both)
                assert issue is not None
                self.assertEqual(issue["status"], "not_comparable")
                self.assertIn(reason, issue["reasons"])
                self.assertNotIn("assumptions", issue)

    def test_an_assumption_covers_only_its_own_condition(self):
        # The target assumption does not vouch for the accounts, and the other way round.
        comparison, issue = self.compare(["CONFIRMED"], ["SECURE"], current={"key": OTHER_KEY},
                                         assume_same_target=True)
        assert issue is not None
        self.assertEqual((issue["status"], issue["reasons"]), ("not_comparable", ["identities_unverified"]))
        self.assertEqual(comparison["comparability"]["assumptions"], [])
        comparison, issue = self.compare(["CONFIRMED"], ["SECURE"], current={"target": "http://127.0.0.1:8001"},
                                         assume_same_identities=True)
        assert issue is not None
        self.assertEqual((issue["status"], issue["reasons"]), ("not_comparable", ["target_changed"]))
        # An assumption that is not needed is not recorded.
        comparison, issue = self.compare(["CONFIRMED"], ["SECURE"], assume_same_target=True,
                                         assume_same_identities=True)
        assert issue is not None
        self.assertEqual((issue["status"], comparison["comparability"]["assumptions"]), ("resolved", []))
        self.assertTrue(comparison["comparability"]["fully_comparable"])


class SubjectTests(unittest.TestCase):
    """Checks with several results per operation are matched per subject, never across subjects."""

    @staticmethod
    def bopla(verdict: str, rule: Any, identity: Any = "visitor") -> Dict[str, Any]:
        return result("BOPLA", OP, verdict, decision_evidence={"rule_id": rule, "subject_identity": identity})

    @staticmethod
    def rbac(verdict: str, role: Any) -> Dict[str, Any]:
        return result("RBAC", OP, verdict, target_url=TARGET + "/api/items/1", rbac_role=role, role="user",
                      required_role="admin")

    @staticmethod
    def mass(verdict: str, **evidence: Any) -> Dict[str, Any]:
        return result("MASS_ASSIGNMENT", PATCH_OP, verdict, target_url=TARGET + "/api/users/1/settings", **evidence)

    def test_bopla_and_rbac_findings_are_tracked_per_subject(self):
        baseline = keyed([self.bopla("CONFIRMED", "salary"), self.bopla("SECURE", "phone"),
                          self.bopla("CONFIRMED", "salary", "anonymous"),
                          self.rbac("CONFIRMED", "viewer"), self.rbac("SECURE", "auditor")])
        current = keyed([self.bopla("SECURE", "salary"), self.bopla("CONFIRMED", "phone"),
                         self.bopla("CONFIRMED", "salary", "anonymous"),
                         self.rbac("SECURE", "viewer"), self.rbac("CONFIRMED", "auditor")])
        issues = by_id(compare_reports(baseline, current))
        self.assertEqual(issues[("BOPLA", OP, "field:salary|identity:visitor")]["status"], "resolved")
        self.assertEqual(issues[("BOPLA", OP, "field:salary|identity:anonymous")]["status"], "persisting")
        self.assertEqual(issues[("BOPLA", OP, "field:phone|identity:visitor")]["status"], "new")
        self.assertEqual(issues[("RBAC", OP, "role:viewer")]["status"], "resolved")
        self.assertEqual(issues[("RBAC", OP, "role:auditor")]["status"], "new")
        # A role name is whatever the configuration calls it.
        named = compare_reports(keyed([self.rbac("CONFIRMED", "read only \u5ba1\u8ba1")]),
                                keyed([self.rbac("SECURE", "read only \u5ba1\u8ba1")]))
        self.assertEqual((only(named)["subject"], only(named)["status"]), ("role:read only \u5ba1\u8ba1", "resolved"))

    def test_a_field_rule_without_an_id_is_known_by_its_path(self):
        def by_path(verdict: str, path: str) -> Dict[str, Any]:
            return result("BOPLA", OP, verdict, decision_evidence={"field_path": path, "subject_identity": "visitor"})

        comparison = compare_reports(keyed([by_path("CONFIRMED", "owner.note"), by_path("CONFIRMED", "owner.phone")]),
                                     keyed([by_path("SECURE", "owner.note"), by_path("CONFIRMED", "owner.phone")]))
        self.assertEqual({issue["subject"]: issue["status"] for issue in comparison["issues"]}, {
            "field:owner.note|identity:visitor": "resolved", "field:owner.phone|identity:visitor": "persisting"})
        # A rule id wins over the path when both are present.
        both = result("BOPLA", OP, "CONFIRMED", decision_evidence={
            "rule_id": "note", "field_path": "owner.note", "subject_identity": "visitor"})
        self.assertEqual(only(compare_reports(keyed([both]), keyed([both])))["subject"], "field:note|identity:visitor")

    def test_a_fix_for_one_subject_never_resolves_another(self):
        # One rule or role fixed, another one no longer checked: the latter is missing, not resolved.
        bopla = compare_reports(keyed([self.bopla("CONFIRMED", "salary"), self.bopla("CONFIRMED", "phone")]),
                                keyed([self.bopla("SECURE", "salary")]))
        self.assertEqual(by_id(bopla)[("BOPLA", OP, "field:phone|identity:visitor")]["reasons"],
                         ["missing_in_current"])
        rbac = compare_reports(keyed([self.rbac("CONFIRMED", "viewer")]), keyed([self.rbac("SECURE", "auditor")]))
        self.assertEqual(by_id(rbac)[("RBAC", OP, "role:viewer")]["reasons"], ["missing_in_current"])

    def test_mass_assignment_is_resolved_only_for_a_verified_safe_field(self):
        confirmed = keyed([self.mass("CONFIRMED", field="role")])
        cases = {
            "role verified safe": (["role"], "SECURE", "resolved", None),
            "another field verified, role not tested": (["nickname"], "SECURE", "not_comparable",
                                                        ["missing_in_current"]),
            "role safe but the check is inconclusive for another field": (["role"], "INCONCLUSIVE",
                                                                          "not_comparable", ["current_unverified"]),
            "nothing verified": ([], "INCONCLUSIVE", "not_comparable", ["current_unverified"]),
            "skipped": (None, "SKIPPED", "not_comparable", ["current_unverified"]),
        }
        for name, (safe, verdict, status, reasons) in cases.items():
            with self.subTest(name):
                evidence = {} if safe is None else {"safe_fields": safe}
                issue = only(compare_reports(confirmed, keyed([self.mass(verdict, **evidence)])))
                self.assertEqual((issue["subject"], issue["status"], issue.get("reasons")),
                                 ("field:role", status, reasons))
        # Another field is confirmed now; the earlier one was not tested again.
        moved = by_id(compare_reports(confirmed, keyed([self.mass("CONFIRMED", field="is_admin")])))
        self.assertEqual(moved[("MASS_ASSIGNMENT", PATCH_OP, "field:role")]["reasons"], ["missing_in_current"])
        self.assertEqual(moved[("MASS_ASSIGNMENT", PATCH_OP, "field:is_admin")]["reasons"],
                         ["not_checked_in_baseline"])

    def test_a_conclusive_record_without_a_readable_subject_matches_nothing(self):
        long_a, long_b = "a" * 600, "b" * 600
        cases = {
            "mass assignment field too long": (self.mass("CONFIRMED", field=long_a),
                                               self.mass("SECURE", safe_fields=["nickname"])),
            "mass assignment field not text": (self.mass("CONFIRMED", field=["role"]),
                                               self.mass("SECURE", safe_fields=["role"])),
            "mass assignment confirmed without a field": (self.mass("CONFIRMED"),
                                                          self.mass("SECURE", safe_fields=["role"])),
            "bopla rules too long": (self.bopla("CONFIRMED", long_a), self.bopla("SECURE", long_b)),
            "bopla rule missing": (self.bopla("CONFIRMED", None), self.bopla("SECURE", None)),
            "bopla identity missing": (self.bopla("CONFIRMED", "salary", None), self.bopla("SECURE", "salary", None)),
            "bopla identity with separator": (self.bopla("CONFIRMED", "a", "visitor|identity:anonymous"),
                                              self.bopla("SECURE", "a|identity:visitor", "anonymous")),
            "bopla rule with control character": (self.bopla("CONFIRMED", "sal\x1bary"),
                                                  self.bopla("SECURE", "sal\x1bary")),
            "rbac role missing": (result("RBAC", OP, "CONFIRMED", role="viewer"),
                                  result("RBAC", OP, "SECURE", role="auditor")),
            "rbac role not a name": (self.rbac("CONFIRMED", "viewer‮"), self.rbac("SECURE", "viewer‮")),
        }
        for name, (before, after) in cases.items():
            for old, new in ((before, after), (after, before)):
                with self.subTest(name, confirmed_in="baseline" if old is before else "current"):
                    comparison = compare_reports(keyed([old]), keyed([new]))
                    for issue in comparison["issues"]:
                        self.assertEqual(issue["status"], "not_comparable")
                    self.assertTrue(any("subject_unknown" in issue["reasons"] for issue in comparison["issues"]))

    def test_a_rule_name_cannot_impersonate_another_rule_and_identity(self):
        # "field:a|identity:visitor|identity:anonymous" is one rule name plus the anonymous identity only.
        first = self.bopla("CONFIRMED", "a|identity:visitor", "anonymous")
        other = self.bopla("SECURE", "a", "visitor")
        issues = by_id(compare_reports(keyed([first]), keyed([other])))
        self.assertEqual(issues[("BOPLA", OP, "field:a|identity:visitor|identity:anonymous")]["reasons"],
                         ["missing_in_current"])

    def test_an_unreadable_record_that_may_be_confirmed_blocks_every_conclusion(self):
        hidden = [dict(bola("CONFIRMED"), endpoint="GET  /api/items/{id}"), dict(bola("CONFIRMED"), check="bad check"),
                  dict(bola("CONFIRMED"), endpoint="GET /" + "x" * 600), dict(bola("NOT-A-VERDICT"), endpoint=7),
                  "junk", None, 5, dict(bola("CONFIRMED"), endpoint="GET /a/\x1b[2K")]
        for record in hidden:
            for where in ("baseline", "current"):
                with self.subTest(record=str(record)[:40], where=where):
                    old = [bola("CONFIRMED"), bola("SECURE", OTHER)] + ([record] if where == "baseline" else [])
                    new = [bola("SECURE"), bola("CONFIRMED", OTHER)] + ([record] if where == "current" else [])
                    comparison = compare_reports(keyed(old), keyed(new))
                    self.assertEqual(comparison["comparability"]["blocking"], ["unreadable_results"])
                    for issue in comparison["issues"]:
                        self.assertEqual((issue["status"], issue["reasons"][0]),
                                         ("not_comparable", "unreadable_results"))

    def test_a_contradicting_record_for_the_same_operation_is_never_dropped(self):
        # Surrounding whitespace does not make it another operation: the finding persists.
        for spelling in (OP + " ", " " + OP, OP):
            with self.subTest(spelling=spelling):
                comparison = compare_reports(keyed([bola("CONFIRMED")]),
                                             keyed([bola("SECURE"), dict(bola("CONFIRMED"), endpoint=spelling)]))
                self.assertEqual((only(comparison)["status"], only(comparison)["current_verdicts"]),
                                 ("persisting", ["CONFIRMED", "SECURE"]))

    def test_an_unreadable_record_that_is_not_a_finding_is_noted_only(self):
        # An unresolved path-item reference is reported as "UNKNOWN /path" with an INCONCLUSIVE verdict.
        unresolved = result("BOLA", "UNKNOWN /api/broken", "INCONCLUSIVE")
        comparison = compare_reports(keyed([bola("CONFIRMED"), unresolved]), keyed([bola("SECURE"), unresolved]))
        self.assertEqual(only(comparison)["status"], "resolved")
        self.assertEqual(comparison["comparability"]["notes"], ["unreadable_results_ignored"])
        self.assertEqual(comparison["comparability"]["blocking"], [])
        self.assertFalse(comparison["comparability"]["fully_comparable"])


class ComparabilityTests(unittest.TestCase):
    def test_fully_comparable_needs_a_verified_unchanged_context(self):
        comparison = compare_reports(keyed([bola("CONFIRMED")]), keyed([bola("SECURE")]))
        self.assertEqual(comparison["comparability"], {
            "basis": "declared", "fully_comparable": True, "blocking": [], "assumptions": [],
            "operation_changes": [], "changes": [], "notes": [],
            "not_verified": ["report_integrity", "server_side_test_data"]})
        self.assertEqual((comparison["baseline"]["context"], comparison["current"]["context"]), ("keyed", "keyed"))

    def test_per_operation_changes_affect_only_that_operation(self):
        before = {"bola_config": {OP: {"resource_id_paths": ["id"]}},
                  "parameter_values": {OTHER: {"owner": {"id": 1}, "visitor": {"id": 2}}}}
        after = {"bola_config": {OP: {"resource_id_paths": ["id"], "not_found_is_denial": True}},
                 "parameter_values": {OTHER: {"owner": {"id": 7}, "visitor": {"id": 2}}},
                 "endpoints": [endpoint(OP), endpoint(OTHER), endpoint(THIRD),
                               endpoint(PATCH_OP, security=[], security_declared=True)]}
        records = [bola("CONFIRMED"), bola("CONFIRMED", OTHER), bola("CONFIRMED", THIRD),
                   result("BFLA", PATCH_OP, "CONFIRMED", target_url=TARGET + "/api/users/1/settings")]
        fixed = [dict(record, verdict="SECURE") for record in records]
        comparison = compare_reports(keyed(records, **before), keyed(fixed, **after))
        issues = by_id(comparison)
        self.assertEqual(issues[("BOLA", OP, None)]["reasons"], ["policy_changed"])
        self.assertEqual(issues[("BOLA", OTHER, None)]["reasons"], ["resources_changed"])
        self.assertEqual(issues[("BFLA", PATCH_OP, None)]["reasons"], ["spec_changed"])
        self.assertEqual(issues[("BOLA", THIRD, None)]["status"], "resolved")
        # One unaffected operation must not make the whole comparison look verified.
        self.assertFalse(comparison["comparability"]["fully_comparable"])
        self.assertEqual(comparison["comparability"]["blocking"], [])
        self.assertEqual(comparison["comparability"]["operation_changes"], [
            {"operation": OP, "reasons": ["policy_changed"]},
            {"operation": OTHER, "reasons": ["resources_changed"]},
            {"operation": PATCH_OP, "reasons": ["spec_changed"]}])

    def test_the_evidence_is_checked_even_when_the_fingerprints_agree(self):
        # Equal contexts, yet the requests went to another resource: a fingerprint does not outrank the evidence.
        moved = compare_reports(keyed([bola("CONFIRMED", path="/api/items/1")]),
                                keyed([bola("SECURE", path="/api/items/999")]))
        self.assertEqual((only(moved)["status"], only(moved)["reasons"]), ("not_comparable", ["resources_changed"]))
        self.assertFalse(moved["comparability"]["fully_comparable"])
        query = compare_reports(keyed([bola("CONFIRMED", path="/api/items/1")]),
                                keyed([bola("SECURE", path="/api/items/1?edge=eu")]))
        self.assertEqual(only(query)["reasons"], ["resources_changed"])

        def judged(verdict: str, **decision: Any) -> Dict[str, Any]:
            return dict(bola(verdict), evidence=dict(bola(verdict)["evidence"], decision_evidence=decision))
        for name, old, new in (("requires_auth", {"requires_auth": True}, {"requires_auth": False}),
                               ("expected_public", {"expected_public": False}, {"expected_public": True}),
                               ("expected_visitor_access", {"expected_visitor_access": "deny"},
                                {"expected_visitor_access": "allow"})):
            with self.subTest(name):
                policy = compare_reports(keyed([judged("CONFIRMED", **old)]), keyed([judged("SECURE", **new)]))
                self.assertEqual(only(policy)["reasons"], ["policy_changed"])

    def test_reports_without_context_are_compared_by_evidence_only_under_assumptions(self):
        flags = {"assume_same_identities": True}
        same = compare_reports(report([bola("CONFIRMED")]), report([bola("SECURE")]), **flags)
        self.assertEqual((only(same)["status"], only(same)["assumptions"]), ("resolved", ["same_identities"]))
        self.assertEqual((same["comparability"]["basis"], same["comparability"]["fully_comparable"]),
                         ("evidence", False))
        moved = compare_reports(report([bola("CONFIRMED", path="/api/items/1")]),
                                report([bola("SECURE", path="/api/items/9")]), **flags)
        self.assertEqual(only(moved)["reasons"], ["resources_changed"])
        unknown = compare_reports(report([result("BOLA", OP, "CONFIRMED")]), report([result("BOLA", OP, "SECURE")]),
                                  **flags)
        self.assertEqual(only(unknown)["reasons"], ["scope_unknown"])
        for target in ("[BOPLA TARGET OMITTED]", "", "not-a-url", "http://", "ftp://host/", None, 7):
            with self.subTest(target=target):
                hidden = compare_reports(report([bola("CONFIRMED")], target=target),
                                         report([bola("SECURE")], target=target), **flags)
                self.assertEqual(only(hidden)["reasons"], ["target_unknown"])

    def test_default_ports_are_the_only_port_equivalence(self):
        flags = {"assume_same_identities": True}
        for implicit, explicit in (("http://api.example", "http://api.example:80"),
                                   ("https://api.example/", "https://api.example:443"),
                                   ("https://API.example/v1/", "https://api.example:443/v1")):
            with self.subTest(implicit=implicit):
                same = compare_reports(report([bola("CONFIRMED")], target=implicit),
                                       report([bola("SECURE")], target=explicit), **flags)
                self.assertEqual(only(same)["status"], "resolved")
                keyed_same = compare_reports(keyed([bola("CONFIRMED")], target=implicit),
                                             keyed([bola("SECURE")], target=explicit))
                self.assertEqual(only(keyed_same)["status"], "resolved")
        other = compare_reports(report([bola("CONFIRMED")], target="http://127.0.0.1:8001"),
                                report([bola("SECURE")], target="http://127.0.0.1:8002"), **flags)
        self.assertEqual(only(other)["reasons"], ["target_changed"])

    def test_rotated_credentials_are_not_another_identity_but_need_the_stated_assumption(self):
        rotated = identities(visitor_token="Bearer ROTATED-B")
        self.assertEqual(context(who=rotated)["identities"], context()["identities"])
        self.assertNotEqual(context(who=rotated)["credentials"], context()["credentials"])
        # A rotated credential and another account's credential look the same from outside.
        comparison = compare_reports(keyed([bola("CONFIRMED")]), keyed([bola("SECURE")], who=rotated))
        self.assertEqual((only(comparison)["status"], only(comparison)["reasons"]),
                         ("not_comparable", ["identities_unverified"]))
        self.assertIn({"kind": "identities", "state": "unverified", "cause": "credentials_changed",
                       "identities": [], "blocking": True}, comparison["comparability"]["changes"])
        stated = compare_reports(keyed([bola("CONFIRMED")]), keyed([bola("SECURE")], who=rotated),
                                 assume_same_identities=True)
        self.assertEqual((only(stated)["status"], only(stated)["assumptions"]), ("resolved", ["same_identities"]))
        # Credentials inside headers and parameters are masked in the identity fingerprint as well.
        contexts = [context(who=identities(visitor={"headers": {"Authorization": token, "X-Tenant": "a"},
                                                    "parameters": {"session": token}}, visitor_token=token))
                    for token in ("Bearer X1", "Bearer Y2")]
        self.assertEqual(contexts[0]["identities"], contexts[1]["identities"])
        self.assertNotEqual(contexts[0]["credentials"], contexts[1]["credentials"])

    def test_identity_changes_name_the_identity_and_the_cause(self):
        def changes(current: Dict[str, Any], baseline: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
            comparison = compare_reports(keyed([bola("CONFIRMED")], who=baseline or identities()),
                                         keyed([bola("SECURE")], who=current))
            return [change for change in comparison["comparability"]["changes"] if change["kind"] == "identities"]

        self.assertEqual(changes(identities(visitor_id="2002")), [
            {"kind": "identities", "state": "changed", "identities": ["visitor"], "blocking": True}])
        self.assertEqual(changes(identities(anonymous={"parameters": {"tenant": "b"}})), [
            {"kind": "identities", "state": "changed", "identities": ["anonymous"], "blocking": True}])
        with_role = identities(roles={"auditor": {"id": "7", "role": "auditor", "token": "Bearer R"}})
        self.assertEqual(changes(identities(), with_role)[0]["identities"], ["role:auditor"])
        for name, role in (("role value", {"id": "7", "role": "admin", "token": "Bearer R"}),
                           ("role body", {"id": "7", "role": "auditor", "token": "Bearer R", "body": {"q": 1}}),
                           ("role parameters", {"id": "7", "role": "auditor", "token": "Bearer R",
                                                "parameters": {"tenant": "b"}})):
            with self.subTest(name):
                self.assertEqual(changes(identities(roles={"auditor": role}), with_role)[0]["identities"],
                                 ["role:auditor"])
        no_role_id = identities(roles={"auditor": {"role": "auditor", "token": "Bearer R"}})
        self.assertEqual(changes(no_role_id, no_role_id), [
            {"kind": "identities", "state": "unverified", "cause": "no_account_id", "identities": ["role:auditor"],
             "blocking": True}])
        self.assertEqual(changes(identities(None, None), identities(None, None))[0]["identities"],
                         ["owner", "visitor"])

    def test_target_and_identity_states_are_recorded_as_changes(self):
        def changes(kind: str, old: Dict[str, Any], new: Dict[str, Any], **flags: bool) -> List[Dict[str, Any]]:
            comparison = compare_reports(old, new, **flags)
            return [change for change in comparison["comparability"]["changes"] if change["kind"] == kind]

        here, there = keyed([bola("CONFIRMED")]), keyed([bola("SECURE")], target="http://127.0.0.1:8001")
        hidden = keyed([bola("SECURE")], target="not-a-url")
        self.assertEqual(changes("target", here, there), [{"kind": "target", "state": "changed", "blocking": True}])
        self.assertEqual(changes("target", here, there, assume_same_target=True),
                         [{"kind": "target", "state": "changed", "acknowledged": True, "blocking": False}])
        self.assertEqual(changes("target", here, hidden), [{"kind": "target", "state": "unknown", "blocking": True}])
        self.assertEqual(changes("target", hidden, here, assume_same_target=True),
                         [{"kind": "target", "state": "unknown", "acknowledged": True, "blocking": False}])
        self.assertEqual(changes("target", here, keyed([bola("SECURE")])), [])
        plain_old, plain_new = report([bola("CONFIRMED")]), report([bola("SECURE")])
        self.assertEqual(changes("identities", plain_old, plain_new), [
            {"kind": "identities", "state": "unverified", "cause": "no_keyed_context", "identities": [],
             "blocking": True}])
        self.assertEqual(changes("identities", plain_old, plain_new, assume_same_identities=True), [
            {"kind": "identities", "state": "unverified", "cause": "no_keyed_context", "identities": [],
             "acknowledged": True, "blocking": False}])
        self.assertEqual(changes("target", report([bola("CONFIRMED")], target=7), plain_new),
                         [{"kind": "target", "state": "unknown", "blocking": True}])

    def test_roles_with_account_ids_are_verified_like_owner_and_visitor(self):
        def who(auditor_token: str = "Bearer R") -> Dict[str, Any]:
            return identities(roles={"auditor": {"id": "7", "role": "auditor", "token": auditor_token},
                                     "viewer": {"id": 8, "headers": {"X-Api-Key": "viewer-key"}}})

        same = compare_reports(keyed([bola("CONFIRMED")], who=who()), keyed([bola("SECURE")], who=who()))
        self.assertEqual((only(same)["status"], same["comparability"]["fully_comparable"]), ("resolved", True))
        self.assertEqual(context(who=who())["account_ids"], ["owner", "role:auditor", "role:viewer", "visitor"])
        # A role's credential is a credential like any other.
        rotated = compare_reports(keyed([bola("CONFIRMED")], who=who()), keyed([bola("SECURE")], who=who("Bearer R2")))
        self.assertEqual(only(rotated)["reasons"], ["identities_unverified"])
        self.assertEqual(context(who=who())["identities"], context(who=who("Bearer R2"))["identities"])

    def test_every_part_of_the_evidence_scope_is_compared(self):
        def record(verdict: str, **evidence: Any) -> Dict[str, Any]:
            scope = {"target_url": TARGET + "/a/1?x=1", "visitor_self_url": TARGET + "/a/2",
                     "readback_url": TARGET + "/a/1/profile", "role": "user", "required_role": "admin"}
            return result("BFLA", OP, verdict, **dict(scope, **evidence))

        cases = {
            "nothing": ({}, None),
            # The evidence URL's host is not the scope; the target is compared on its own.
            "host of the evidence url": ({"target_url": "https://elsewhere.example/a/1?x=1"}, None),
            "query value": ({"target_url": TARGET + "/a/1?x=2"}, "resources_changed"),
            "query removed": ({"target_url": TARGET + "/a/1"}, "resources_changed"),
            "path": ({"target_url": TARGET + "/a/9?x=1"}, "resources_changed"),
            "visitor resource": ({"visitor_self_url": TARGET + "/a/3"}, "resources_changed"),
            "readback resource": ({"readback_url": TARGET + "/a/9/profile"}, "resources_changed"),
            "role": ({"role": "support"}, "policy_changed"),
            "required role": ({"required_role": "owner"}, "policy_changed"),
        }
        for name, (changed, reason) in cases.items():
            for flags, make in (({}, keyed), ({"assume_same_identities": True}, report)):
                with self.subTest(name, keyed=make is keyed):
                    issue = only(compare_reports(make([record("CONFIRMED")]), make([record("SECURE", **changed)]),
                                                 **flags))
                    self.assertEqual((issue["status"], issue.get("reasons")),
                                     ("not_comparable", [reason]) if reason else ("resolved", None))

    def test_one_sided_evidence_does_not_outrank_agreeing_fingerprints(self):
        # A report made with a field policy carries no request paths; the fingerprints still cover them.
        with_paths, without = [bola("CONFIRMED")], [result("BOLA", OP, "SECURE")]
        self.assertEqual(only(compare_reports(keyed(with_paths), keyed(without)))["status"], "resolved")
        unkeyed = compare_reports(report(with_paths), report(without), assume_same_identities=True)
        self.assertEqual(only(unkeyed)["reasons"], ["scope_unknown"])

    def test_the_comparison_names_versions_times_counts_and_order(self):
        skipped = result("BFLA", PATCH_OP, "SKIPPED", target_url=TARGET + "/u")
        baseline = keyed([bola("CONFIRMED"), bola("CONFIRMED", OTHER), bola("SECURE", THIRD),
                          dict(skipped, verdict="CONFIRMED")], generated_at="2026-11-13T00:00:00Z")
        current = keyed([bola("SECURE"), bola("CONFIRMED", OTHER), bola("CONFIRMED", THIRD), skipped,
                         result("BFLA", OP, "SECURE"), result("BFLA", OTHER, "SECURE"),
                         result("BFLA", THIRD, "SECURE")], generated_at="2026-11-20T09:30:00Z")
        comparison = compare_reports(baseline, current)
        self.assertEqual(set(comparison), {"comparison_schema_version", "tool_version", "baseline", "current",
                                           "comparability", "summary", "issues", "coverage"})
        self.assertEqual((comparison["comparison_schema_version"], comparison["tool_version"]),
                         (1, api_sentinel.__version__))
        self.assertEqual(comparison["baseline"], {"tool_version": "2.8.0", "generated_at": "2026-11-13T00:00:00Z",
                                                  "context": "keyed"})
        self.assertEqual(comparison["current"], {"tool_version": "2.8.0", "generated_at": "2026-11-20T09:30:00Z",
                                                 "context": "keyed"})
        self.assertEqual(comparison["summary"], {
            "new": 1, "not_comparable": 1, "persisting": 1, "resolved": 1, "current_confirmed_not_comparable": 0,
            "relying_on_assumptions": 0, "baseline_confirmed": 3, "current_confirmed": 2})
        # New findings first, then what could not be compared, then persisting and resolved ones.
        self.assertEqual([(issue["status"], issue["operation"]) for issue in comparison["issues"]],
                         [("new", THIRD), ("not_comparable", PATCH_OP), ("persisting", OTHER), ("resolved", OP)])
        self.assertEqual(comparison["issues"][3], {
            "finding_id": finding_id("BOLA", OP), "check": "BOLA", "operation": OP, "cwe": "CWE-639",
            "status": "resolved", "baseline_verdicts": ["CONFIRMED"], "current_verdicts": ["SECURE"]})

    def test_each_check_carries_its_weakness_identifier(self):
        evidence: Dict[str, Dict[str, Any]] = {
            "BOLA": {}, "BROKEN_AUTH": {}, "BFLA": {}, "BOPLA_EXPOSURE": {}, "CUSTOM_CHECK": {},
            "RBAC": {"rbac_role": "viewer"}, "MASS_ASSIGNMENT": {"field": "role"},
            "BOPLA": {"decision_evidence": {"rule_id": "note", "subject_identity": "visitor"}}}
        records = [result(check, OP, "CONFIRMED", target_url=TARGET + "/a", **extra)
                   for check, extra in evidence.items()]
        comparison = compare_reports(keyed(records), keyed(records))
        self.assertEqual({issue["check"]: issue.get("cwe") for issue in comparison["issues"]}, {
            "BOLA": "CWE-639", "BROKEN_AUTH": "CWE-306", "BFLA": "CWE-285", "RBAC": "CWE-285", "BOPLA": "CWE-200",
            "BOPLA_EXPOSURE": "CWE-200", "MASS_ASSIGNMENT": "CWE-915", "CUSTOM_CHECK": None})
        self.assertEqual({issue["status"] for issue in comparison["issues"]}, {"persisting"})

    def test_subject_and_operation_length_limits(self):
        def mass(verdict: str, field: str) -> Dict[str, Any]:
            return result("MASS_ASSIGNMENT", PATCH_OP, verdict, field=field, target_url=TARGET + "/u")

        for length, status in ((512, "persisting"), (513, "not_comparable")):
            with self.subTest(subject_length=length):
                records = [mass("CONFIRMED", "f" * length)]
                self.assertEqual(only(compare_reports(keyed(records), keyed(records)))["status"], status)
        for length, blocking in ((512, []), (513, ["unreadable_results"])):
            with self.subTest(operation_length=length):
                operation = "GET /" + "x" * (length - 5)
                records = [bola("CONFIRMED", operation)]
                comparison = compare_reports(keyed(records, operations=(operation,)),
                                             keyed(records, operations=(operation,)))
                self.assertEqual(comparison["comparability"]["blocking"], blocking)

    def test_unreadable_records_are_counted(self):
        junk = result("BOLA", "UNKNOWN /api/broken", "INCONCLUSIVE")
        comparison = compare_reports(keyed([bola("SECURE"), junk, junk]), keyed([bola("SECURE"), junk]))
        self.assertIn({"kind": "unreadable_results", "baseline": 2, "current": 1, "blocking": False},
                      comparison["comparability"]["changes"])
        hidden = compare_reports(keyed([bola("SECURE")]), keyed([bola("SECURE"), "junk"]))
        self.assertIn({"kind": "unreadable_results", "baseline": 0, "current": 1, "blocking": True},
                      hidden["comparability"]["changes"])

    def test_tool_version_and_operation_changes_are_reported_without_blocking(self):
        comparison = compare_reports(keyed([bola("CONFIRMED")], version="2.7.1"),
                                     keyed([bola("CONFIRMED"), bola("SECURE", OTHER)], version="2.8.0"))
        kinds = {change["kind"]: change for change in comparison["comparability"]["changes"]}
        self.assertEqual(kinds["tool_version"], {"kind": "tool_version", "baseline": "2.7.1", "current": "2.8.0",
                                                 "blocking": False})
        self.assertEqual(kinds["operations_added"]["count"], 1)
        self.assertEqual(only(comparison)["status"], "persisting")
        # Another detector version may judge the same evidence differently.
        self.assertFalse(comparison["comparability"]["fully_comparable"])
        unknown = compare_reports(keyed([bola("CONFIRMED")], version="?"), keyed([bola("SECURE")], version="?"))
        self.assertFalse(unknown["comparability"]["fully_comparable"])
        self.assertIsNone(unknown["baseline"]["tool_version"])

    def test_coverage_loss_is_reported_separately(self):
        comparison = compare_reports(
            keyed([bola("SECURE"), bola("SECURE", OTHER)], stats={"conclusive_coverage_pct": 100.0}),
            keyed([bola("SECURE"), bola("SKIPPED", OTHER)], stats={"conclusive_coverage_pct": 50.0}))
        coverage = comparison["coverage"]
        self.assertTrue(coverage["decreased"])
        self.assertEqual([item["operation"] for item in coverage["conclusive_lost"]], [OTHER])
        self.assertEqual(comparison["issues"], [])
        self.assertIn({"kind": "coverage_decreased", "blocking": False}, comparison["comparability"]["changes"])
        self.assertEqual(coverage["conclusive_lost"], [{
            "finding_id": finding_id("BOLA", OTHER), "check": "BOLA", "operation": OTHER, "cwe": "CWE-639",
            "baseline_verdicts": ["SECURE"], "current_verdicts": ["SKIPPED"]}])
        self.assertEqual(coverage["conclusive_gained"], [])

    def test_coverage_is_judged_by_percentage_and_by_checks_lost_or_gained(self):
        def coverage(old: Optional[float], new: Optional[float], before: str = "SECURE",
                     after: str = "SECURE") -> Dict[str, Any]:
            stats = [{} if value is None else {"conclusive_coverage_pct": value} for value in (old, new)]
            comparison = compare_reports(keyed([bola(before)], stats=stats[0]), keyed([bola(after)], stats=stats[1]))
            noted = {"kind": "coverage_decreased", "blocking": False} in comparison["comparability"]["changes"]
            self.assertEqual(comparison["coverage"]["decreased"], noted)
            return comparison["coverage"]

        for old, new, decreased in ((80.0, 60.0, True), (60.0, 80.0, False), (70.0, 70.0, False), (None, 50.0, False),
                                    (50.0, None, False), (None, None, False), (5, 0, True), (0, 0, False)):
            with self.subTest(old=old, new=new):
                self.assertEqual(coverage(old, new)["decreased"], decreased)
        # A value of zero is a value.
        self.assertEqual(coverage(0, 0)["baseline"], {"conclusive_coverage_pct": 0})
        gained = coverage(50.0, 100.0, "SKIPPED", "SECURE")
        self.assertEqual((gained["decreased"], gained["conclusive_lost"]), (False, []))
        self.assertEqual(gained["conclusive_gained"], [{
            "finding_id": finding_id("BOLA", OP), "check": "BOLA", "operation": OP, "cwe": "CWE-639",
            "baseline_verdicts": ["SKIPPED"], "current_verdicts": ["SECURE"]}])
        # A lost check counts even when the percentage went up.
        self.assertTrue(coverage(50.0, 100.0, "SECURE", "ERROR")["decreased"])
        # Lost and gained checks are listed by operation, then check, then subject.
        checks = ("BROKEN_AUTH", "BOLA", "BFLA", "RBAC")
        listed = compare_reports(
            keyed([result(check, operation, "SECURE", rbac_role="viewer") for operation in (OTHER, OP)
                   for check in checks]),
            keyed([result(check, operation, "SKIPPED", rbac_role="viewer") for check in checks
                   for operation in (OP, OTHER)]))
        self.assertEqual([(item["operation"], item["check"]) for item in listed["coverage"]["conclusive_lost"]],
                         [(operation, check) for operation in (OP, OTHER) for check in sorted(checks)])
        moved = compare_reports(keyed([bola("SECURE"), bola("SECURE", OTHER)]),
                                keyed([bola("SECURE"), bola("SECURE", THIRD), bola("SECURE", PATCH_OP)]))
        self.assertEqual((moved["coverage"]["operations_added"], moved["coverage"]["operations_removed"]), (2, 1))
        self.assertIn({"kind": "operations_added", "count": 2, "blocking": False}, moved["comparability"]["changes"])
        self.assertIn({"kind": "operations_removed", "count": 1, "blocking": False}, moved["comparability"]["changes"])


class ContextTests(unittest.TestCase):
    """What a context contains, and what `diff` accepts as one."""

    def test_context_holds_fingerprints_only(self):
        marker = "Bearer CONTEXT-CANARY-7"
        built = build_comparison_context(
            key=KEY, target="https://context-target-canary.internal:8443/base",
            identities={"owner": {"id": "owner-account-canary", "token": marker,
                                  "headers": {"X-Api-Key": "CONTEXT-KEY-8", "X-Tenant": "tenant-canary"},
                                  "parameters": {"session": marker}},
                        "visitor": {"id": "2", "token": "Bearer B"}, "anonymous": {},
                        "roles": {"auditor": {"id": "7", "token": "Bearer R"}, "bad name!": {"token": "x"}}},
            endpoints=[endpoint(OP, description="spec-text-canary")],
            security_schemes={"bearer": {"type": "http", "description": "scheme-canary"}},
            bola_config={OP: {"body": {"auth": marker, "note": "policy-canary"}}},
            parameter_values={OP: {"owner": {"id": "resource-canary"}}},
            secret_values=(marker, "CONTEXT-KEY-8", "Bearer B"))
        text = json.dumps(built)
        for value in (marker, "CANARY", "canary", "CONTEXT-KEY-8", KEY, "8443", "Bearer", "bad name"):
            self.assertNotIn(value, text)
        self.assertEqual(set(built), {"version", "algorithm", "key_id", "target", "identities", "account_ids",
                                      "credentials", "operations"})
        self.assertEqual(built["account_ids"], ["owner", "role:auditor", "visitor"])
        self.assertEqual(len(built["identities"]["roles"]), 2)
        self.assertEqual([name[:5] for name in sorted(built["identities"]["roles"]) if name != "auditor"], ["role-"])
        fingerprints = ([built["key_id"], built["target"], built["credentials"]]
                        + [built["identities"][name] for name in ("owner", "visitor", "anonymous")]
                        + list(built["identities"]["roles"].values())
                        + [value for item in built["operations"].values() for value in item.values()])
        for value in fingerprints:
            self.assertRegex(value, r"^[0-9a-f]{16}$")
        self.assertEqual(report_diff._context({"comparison_context": built}), built)

    def test_fingerprints_depend_on_a_stretched_key(self):
        first, second = context(), context(key=OTHER_KEY)
        self.assertEqual(first["algorithm"], "pbkdf2-sha256-200000/hmac-sha256")
        for name in ("key_id", "target", "credentials"):
            self.assertNotEqual(first[name], second[name])
        self.assertNotEqual(first["identities"]["owner"], second["identities"]["owner"])
        # Neither a plain hash nor an HMAC under the key as typed reproduces a fingerprint.
        material = json.dumps(["http", "127.0.0.1", 8000, ""], separators=(",", ":"))
        for version in ("v1", "v2"):
            message = f"granttrace/target/{version}\0{material}".encode()
            self.assertNotEqual(first["target"], hashlib.sha256(message).hexdigest()[:16])
            self.assertNotEqual(first["target"], hmac.new(KEY.encode(), message, hashlib.sha256).hexdigest()[:16])
        comparison = compare_reports(keyed([bola("CONFIRMED")]), keyed([bola("SECURE")], key=OTHER_KEY))
        self.assertEqual(comparison["comparability"]["basis"], "evidence")
        self.assertEqual(comparison["comparability"]["notes"], ["comparison_keys_differ"])

    def test_fingerprints_match_an_independent_computation(self):
        built = context()
        derived = hashlib.pbkdf2_hmac("sha256", KEY.encode(), b"granttrace/comparison-key/v2", 200_000)

        def expected(kind: str, value: Any) -> str:
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
            return hmac.new(derived, f"granttrace/{kind}/v2\0{canonical}".encode(), hashlib.sha256).hexdigest()[:16]

        self.assertEqual(built["version"], 2)
        self.assertEqual(built["key_id"], expected("comparison-key-id", None))
        self.assertEqual(built["target"], expected("target", ["http", "127.0.0.1", 8000, ""]))
        self.assertEqual(built["identities"]["owner"], expected("identity", {
            "id": "1001", "role": None, "parameters": {}, "headers": {}, "auth_header_names": [], "body": None}))
        self.assertEqual(built["identities"]["anonymous"], expected("identity", {
            "id": None, "role": None, "parameters": {}, "headers": {}, "auth_header_names": [], "body": None}))
        self.assertEqual(built["operations"][OP]["resources"], expected("resources", None))
        self.assertEqual(built["operations"][OP]["policy"], expected("policy", {
            "bola": None, "bopla": None, "readback": None, "write_allowlisted": False}))
        self.assertEqual(context(write_allowlist=[OP])["operations"][OP]["policy"], expected("policy", {
            "bola": None, "bopla": None, "readback": None, "write_allowlisted": True}))
        self.assertEqual(report_diff.MAX_REPORT_BYTES, 64 * 1024 * 1024)

    def test_key_length_and_variety_limits(self):
        accepted = ["abcdefgh" * 4, "abcdefgh" * 4 + "x"]
        refused = [("abcdefgh" * 4)[:31], "abcdefg" * 5, "abcdefg" * 4 + "aaaa"]
        for value in accepted:
            self.assertEqual(comparison_key_from_environment({"GRANTTRACE_COMPARISON_KEY": value}), value)
        for value in refused:
            with self.subTest(length=len(value), distinct=len(set(value))), self.assertRaises(ComparisonKeyError):
                comparison_key_from_environment({"GRANTTRACE_COMPARISON_KEY": value})

    def test_values_are_normalised_and_credentials_masked_before_fingerprinting(self):
        masked = report_diff._mask(
            {"none": None, "flag": True, "count": 1, "ratio": 1.5, "nan": float("nan"), "raw": b"x", 3: ("a", 2),
             "values": ["tok-secret", "has tok-secret inside", "abc", "xabcx", "", "xwxyzx"]},
            ("tok-secret", "abc", "wxyz"))
        self.assertEqual(masked, {
            "none": None, "flag": True, "count": 1, "ratio": 1.5, "nan": "nan", "raw": "b'x'", "3": ["a", 2],
            # A short secret is only masked as a whole value: it would otherwise hide unrelated text.
            "values": ["[REDACTED]", "[REDACTED]", "[REDACTED]", "xabcx", "", "[REDACTED]"]})
        # Values that are not text, and an empty one, are never treated as secrets.
        plain = build_comparison_context(key=KEY, target=TARGET, identities=identities(), endpoints=[endpoint(OP)],
                                         secret_values=(None, "", 5, "Bearer OWNER-VALUE"))  # type: ignore[arg-type]
        self.assertEqual(plain, context(operations=(OP,)))
        # Text outside ASCII is fingerprinted like any other.
        named = context(who=identities(owner_id="\u7528\u6237\u4e00"),
                        parameter_values={OP: {"owner": {"id": "\u8d44\u6e90"}}})
        for value in (named["identities"]["owner"], named["operations"][OP]["resources"], named["credentials"]):
            self.assertRegex(value, r"^[0-9a-f]{16}$")
        self.assertNotEqual(named["identities"]["owner"], context()["identities"]["owner"])

    def test_the_credentials_fingerprint_changes_with_credentials_only(self):
        def built(api_key: str = "KEY-ONE-1234", **sections: Any) -> Dict[str, Any]:
            sections.setdefault("parameter_values", {OP: {"visitor": {"api_key": api_key, "id": 2}}})
            return context(more_secrets=[api_key], **sections)

        base = built()
        # A credential kept in parameter_values: masked where it is declared, visible only here.
        rotated = built("KEY-TWO-5678")
        self.assertEqual((rotated["identities"], rotated["operations"]), (base["identities"], base["operations"]))
        self.assertNotEqual(rotated["credentials"], base["credentials"])
        comparison = compare_reports(report([bola("CONFIRMED")], context=base),
                                     report([bola("SECURE")], context=rotated))
        self.assertEqual(only(comparison)["reasons"], ["identities_unverified"])
        self.assertEqual([change["cause"] for change in comparison["comparability"]["changes"]],
                         ["credentials_changed"])
        # Declared changes are not credential changes: they stay with their own operation.
        for name, changed in (("policy", built(bola_config={OP: {"not_found_is_denial": True}})),
                              ("resources", built(parameter_values={OP: {"visitor": {"api_key": "KEY-ONE-1234",
                                                                                     "id": 3}}})),
                              ("specification", built(endpoints=[endpoint(OP, summary="edited"), endpoint(OTHER)])),
                              ("target", built(target="http://127.0.0.1:9"))):
            with self.subTest(name):
                self.assertEqual(changed["credentials"], base["credentials"])
        for name, who in (("token", identities(visitor_token="Bearer NEXT")),
                          ("header", identities(visitor={"headers": {"X-Api-Key": "next"}})),
                          ("role token", identities(roles={"auditor": {"id": "7", "token": "Bearer R"}}))):
            with self.subTest(name):
                self.assertNotEqual(built(who=who)["credentials"], base["credentials"])
        # A credential kept in an identity's parameters or in a role's request body.
        for name, place in (("identity parameter", lambda value: identities(visitor={"parameters": {"sid": value}})),
                            ("role body", lambda value: identities(roles={"auditor": {"id": "7", "body": {
                                "session": value}}}))):
            with self.subTest(name):
                first, second = (context(who=place(value), more_secrets=[value])
                                 for value in ("SESSION-ONE-1", "SESSION-TWO-2"))
                self.assertEqual(first["identities"], second["identities"])
                self.assertNotEqual(first["credentials"], second["credentials"])

    def test_weak_or_short_keys_are_refused_without_echoing_them(self):
        weak = ["short-key", "a" * 64, "ab" * 32, "0123456" * 8, "password12345678", "x" * 31 + "y"]
        for value in weak:
            with self.subTest(key=value):
                with self.assertRaises(ComparisonKeyError) as raised:
                    comparison_key_from_environment({"GRANTTRACE_COMPARISON_KEY": value})
                self.assertIn("GRANTTRACE_COMPARISON_KEY", str(raised.exception))
                self.assertNotIn(value, str(raised.exception))
                with self.assertRaises(ComparisonKeyError):
                    build_comparison_context(key=value, target=TARGET, identities=identities())
        self.assertIsNone(comparison_key_from_environment({}))
        self.assertIsNone(comparison_key_from_environment({"GRANTTRACE_COMPARISON_KEY": ""}))
        self.assertEqual(comparison_key_from_environment({"GRANTTRACE_COMPARISON_KEY": KEY}), KEY)

    def test_a_malformed_or_truncated_context_is_never_used(self):
        good = context()
        operation = dict(good["operations"][OP])

        def edited(**changes: Any) -> Dict[str, Any]:
            return dict(copy.deepcopy(good), **changes)

        malformed: Dict[str, Any] = {
            "identities emptied": edited(identities={}),
            "identity missing": edited(identities={name: value for name, value in good["identities"].items()
                                                   if name != "anonymous"}),
            "identity fingerprint not text": edited(identities=dict(good["identities"], owner=1)),
            "identity fingerprint boolean": edited(identities=dict(good["identities"], visitor=True)),
            "unexpected identity": edited(identities=dict(good["identities"], admin="0" * 16)),
            "roles not an object": edited(identities=dict(good["identities"], roles=[])),
            "role name with markup": edited(identities=dict(good["identities"], roles={"a\x1b[2K": "0" * 16})),
            "target a list": edited(target=[]),
            "target too short": edited(target="abc"),
            "credentials a number": edited(credentials=5),
            "account ids missing": {name: value for name, value in good.items() if name != "account_ids"},
            "account ids not a list": edited(account_ids="owner"),
            "account id unknown": edited(account_ids=["owner", "visitor", "anonymous"]),
            "operations emptied to a list": edited(operations=[]),
            "operation not an object": edited(operations={OP: "junk"}),
            "operation fingerprint missing": edited(operations={OP: {"policy": operation["policy"]}}),
            "operation fingerprint extra": edited(operations={OP: dict(operation, more="0" * 16)}),
            "operation key not canonical": edited(operations={"get /api/items/{id}": operation}),
            "operation fingerprint upper case": edited(operations={OP: dict(operation, policy="A" * 16)}),
            "version as text": edited(version="2"),
            "version boolean": edited(version=True),
            "previous version": edited(version=1, algorithm="hmac-sha256"),
            "other algorithm": edited(algorithm="hmac-sha256"),
            "key id not hexadecimal": edited(key_id="Z" * 16),
            "key id missing": {name: value for name, value in good.items() if name != "key_id"},
            "not an object": ["version", 2],
        }
        for name, broken in malformed.items():
            with self.subTest(name):
                self.assertIsNone(report_diff._context({"comparison_context": broken}))
                # The same malformed context in both reports must not pass as "nothing changed".
                comparison = compare_reports(report([bola("CONFIRMED")], context=broken),
                                             report([bola("SECURE")], context=broken))
                self.assertEqual((only(comparison)["status"], only(comparison)["reasons"]),
                                 ("not_comparable", ["identities_unverified"]))
                self.assertEqual(comparison["comparability"]["basis"], "evidence")
                self.assertEqual(comparison["comparability"]["notes"], ["comparison_context_invalid"])
                self.assertEqual(comparison["baseline"]["context"], "invalid")
                self.assertFalse(comparison["comparability"]["fully_comparable"])

    def test_missing_fingerprints_in_a_well_formed_context_are_not_comparable(self):
        good = context()
        for name, broken, reason in (
                ("identity fingerprint null", dict(good, identities=dict(good["identities"], owner=None)),
                 "identities_unverified"),
                ("target null", dict(good, target=None), "target_unknown"),
                ("credentials null", dict(good, credentials=None), "identities_unverified"),
                ("operation fingerprint null", dict(good, operations={OP: dict(good["operations"][OP], policy=None)}),
                 "context_incomplete"),
                ("operations empty", dict(good, operations={}), "context_incomplete")):
            with self.subTest(name):
                comparison = compare_reports(report([bola("CONFIRMED")], context=broken),
                                             report([bola("SECURE")], context=broken))
                self.assertEqual(only(comparison)["status"], "not_comparable")
                self.assertIn(reason, only(comparison)["reasons"])
                self.assertFalse(comparison["comparability"]["fully_comparable"])

    def test_security_schemes_are_read_from_both_specification_dialects(self):
        self.assertEqual(specification_security_schemes({"components": {"securitySchemes": {"a": 1}}}),
                         {"components": {"a": 1}, "definitions": None})
        self.assertEqual(specification_security_schemes({"securityDefinitions": {"b": 2}}),
                         {"components": None, "definitions": {"b": 2}})
        self.assertIsNone(specification_security_schemes(None))

    def test_values_that_cannot_be_serialised_do_not_break_a_scan(self):
        nested: Any = []
        for _ in range(5000):
            nested = [nested]
        built = build_comparison_context(
            key=KEY, target=TARGET, identities=identities(),
            endpoints=[endpoint(OP, parameters=[{"example": float("nan"), "raw": b"bytes", "set": {1, 2}}]),
                       endpoint(OTHER, request_schema=nested)],
            parameter_values={THIRD: {"owner": {"id": float("inf")}}})
        self.assertRegex(built["operations"][OP]["definition"], r"^[0-9a-f]{16}$")
        self.assertRegex(built["operations"][THIRD]["resources"], r"^[0-9a-f]{16}$")
        self.assertEqual(set(built["operations"][OTHER].values()), {None})
        self.assertIsNotNone(report_diff._context({"comparison_context": built}))


class RandomizedInvariantTests(unittest.TestCase):
    """Seeded random scenarios, checked against rules written independently of the implementation."""

    CHECKS = ("BOLA", "BFLA", "BROKEN_AUTH")
    OPERATIONS = (OP, OTHER, THIRD)
    VERDICTS = ("CONFIRMED", "CONFIRMED", "SECURE", "PUBLIC", "AUTHORIZED", "SKIPPED", "INCONCLUSIVE", "ERROR",
                "SUSPICIOUS")

    def scenario(self, rng: random.Random) -> Dict[str, Any]:
        choice = rng.random
        return {
            "keyed": (choice() < 0.8, choice() < 0.8), "same_key": choice() < 0.85, "same_target": choice() < 0.75,
            "identity_changed": choice() < 0.15, "credential_changed": choice() < 0.2, "ids": choice() < 0.85,
            "changed": {operation: rng.choice(("spec", "policy", "resources")) for operation in self.OPERATIONS
                        if choice() < 0.15},
            "moved": {operation for operation in self.OPERATIONS if choice() < 0.1},
            "flags": {"assume_same_target": choice() < 0.4, "assume_same_identities": choice() < 0.4},
            "verdicts": [{(check, operation): [rng.choice(self.VERDICTS) for _ in range(rng.choice((1, 1, 2)))]
                          for check in self.CHECKS for operation in self.OPERATIONS if choice() < 0.7}
                         for _ in range(2)],
        }

    def build(self, scenario: Dict[str, Any], side: int) -> Dict[str, Any]:
        current = side == 1
        records = [result(check, operation, verdict, target_url=TARGET + (
                       "/moved" if current and operation in scenario["moved"] else "/same"))
                   for (check, operation), verdicts in scenario["verdicts"][side].items() for verdict in verdicts]
        target = TARGET if scenario["same_target"] or not current else "http://127.0.0.1:9000"
        if not scenario["keyed"][side]:
            return report(records, target=target)
        changed = scenario["changed"] if current else {}
        who = identities("1001" if scenario["ids"] else None,
                         ("1002" if scenario["ids"] else None) if not (current and scenario["identity_changed"])
                         else "3003",
                         visitor_token="Bearer NEXT" if current and scenario["credential_changed"]
                         else "Bearer VISITOR-VALUE")
        return report(records, target=target, context=context(
            target=target, key=KEY if scenario["same_key"] or not current else OTHER_KEY, who=who,
            endpoints=[endpoint(operation, summary="edited" if changed.get(operation) == "spec" else "")
                       for operation in self.OPERATIONS],
            bola_config={operation: {"not_found_is_denial": True} for operation in self.OPERATIONS
                         if changed.get(operation) == "policy"},
            parameter_values={operation: {"owner": {"id": 5}} for operation in self.OPERATIONS
                              if changed.get(operation) == "resources"}))

    @staticmethod
    def expected(scenario: Dict[str, Any], key: Tuple[str, str]) -> Optional[str]:
        """The status the documented rules give, or None when there is no confirmed finding."""
        before: Optional[Set[str]] = set(scenario["verdicts"][0][key]) if key in scenario["verdicts"][0] else None
        after: Optional[Set[str]] = set(scenario["verdicts"][1][key]) if key in scenario["verdicts"][1] else None
        if "CONFIRMED" not in (before or set()) | (after or set()):
            return None
        negative = set(NEGATIVE)
        candidate: Optional[str]
        if after is not None and "CONFIRMED" in after:
            candidate = ("persisting" if before is not None and "CONFIRMED" in before
                         else "new" if before is not None and before <= negative else None)
        else:
            candidate = "resolved" if after is not None and after <= negative else None
        if candidate is None:
            return "not_comparable"
        declared = all(scenario["keyed"]) and scenario["same_key"]
        flags = scenario["flags"]
        target_ok = scenario["same_target"] or flags["assume_same_target"]
        if declared:
            verified = scenario["ids"] and not scenario["credential_changed"]
            identities_ok = not scenario["identity_changed"] and (verified or flags["assume_same_identities"])
            operation_ok = key[1] not in scenario["changed"]
        else:
            identities_ok = flags["assume_same_identities"]
            operation_ok = True
        comparable = target_ok and identities_ok and operation_ok and key[1] not in scenario["moved"]
        return candidate if comparable else "not_comparable"

    def test_classification_matches_the_documented_rules(self):
        rng = random.Random(20261114)
        seen: Set[str] = set()
        fully = 0
        for index in range(400):
            scenario = self.scenario(rng)
            baseline, current = self.build(scenario, 0), self.build(scenario, 1)
            comparison = compare_reports(baseline, current, **scenario["flags"])
            actual = {(issue["check"], issue["operation"]): issue for issue in comparison["issues"]}
            keys = set(scenario["verdicts"][0]) | set(scenario["verdicts"][1])
            for key in sorted(keys):
                expected = self.expected(scenario, key)
                with self.subTest(index=index, key=key):
                    self.assertEqual(actual[key]["status"] if key in actual else None, expected, scenario)
                if expected:
                    seen.add(expected)
            comparability = comparison["comparability"]
            with self.subTest(index=index, invariant="structure"):
                # A blocking condition leaves no conclusion; a conclusion under an assumption says so.
                if comparability["blocking"]:
                    self.assertEqual({issue["status"] for issue in comparison["issues"]} - {"not_comparable"}, set())
                for issue in comparison["issues"]:
                    self.assertEqual(issue["status"] == "not_comparable", bool(issue.get("reasons")))
                    if issue["status"] != "not_comparable":
                        self.assertEqual(issue.get("assumptions", []), comparability["assumptions"])
                    else:
                        self.assertNotIn("assumptions", issue)
                if comparability["fully_comparable"]:
                    fully += 1
                    self.assertTrue(all(scenario["keyed"]) and scenario["same_key"] and scenario["same_target"]
                                    and scenario["ids"] and not scenario["identity_changed"]
                                    and not scenario["credential_changed"])
                    self.assertEqual((comparability["blocking"], comparability["assumptions"],
                                      comparability["operation_changes"]), ([], [], []))
                self.assertEqual(sum(comparison["summary"][name] for name in report_diff.STATUS_ORDER),
                                 len(comparison["issues"]))
                # Record order never matters.
                shuffled = copy.deepcopy(current)
                rng.shuffle(shuffled["results"])
                self.assertEqual(json.dumps(comparison, sort_keys=True),
                                 json.dumps(compare_reports(baseline, shuffled, **scenario["flags"]), sort_keys=True))
            with self.subTest(index=index, invariant="symmetry"):
                # Swapping the reports swaps new and resolved and nothing else.
                mirror = {"new": "resolved", "resolved": "new", "persisting": "persisting",
                          "not_comparable": "not_comparable"}
                swapped = compare_reports(current, baseline, **scenario["flags"])
                self.assertEqual({(issue["check"], issue["operation"]): issue["status"] for issue in swapped["issues"]},
                                 {key: mirror[issue["status"]] for key, issue in actual.items()})
                self.assertEqual(swapped["comparability"]["fully_comparable"], comparability["fully_comparable"])
            with self.subTest(index=index, invariant="self comparison"):
                # A report compared with itself has neither new nor resolved findings.
                for side in (baseline, current):
                    itself = compare_reports(side, side, **scenario["flags"])
                    self.assertEqual((itself["summary"]["new"], itself["summary"]["resolved"]), (0, 0))
                    self.assertEqual(itself["comparability"]["operation_changes"], [])
                    self.assertEqual(itself["coverage"]["decreased"], False)
        self.assertEqual(seen, {"new", "persisting", "resolved", "not_comparable"})
        self.assertGreater(fully, 10)

    def test_arbitrary_documents_never_crash_the_comparison(self):
        rng = random.Random(96)
        atoms: List[Any] = [None, True, False, 0, 1, -1, 2, 1.5, 10 ** 30, "", "x", OP, "CONFIRMED", "SECURE", "BOLA",
                            "RBAC", "BOPLA", "MASS_ASSIGNMENT", "http://h:1/p", "\ud800", "\x1b[2K", "‮",
                            "a" * 700, "0" * 16, 2, "2.8.0"]
        names = ["tool_version", "report_schema_version", "results", "target", "stats", "comparison_context",
                 "endpoint", "check", "verdict", "evidence", "field", "safe_fields", "decision_evidence", "rule_id",
                 "subject_identity", "rbac_role", "target_url", "version", "algorithm", "key_id", "identities",
                 "account_ids", "operations", "credentials", "owner", "visitor", "anonymous", "roles",
                 "generated_at", "conclusive_coverage_pct", OP]

        def value(depth: int) -> Any:
            roll = rng.random()
            if depth > 4 or roll < 0.35:
                return rng.choice(atoms)
            if roll < 0.6:
                return [value(depth + 1) for _ in range(rng.randrange(4))]
            return {rng.choice(names): value(depth + 1) for _ in range(rng.randrange(6))}

        evidence_names = ["field", "safe_fields", "decision_evidence", "rbac_role", "target_url", "visitor_self_url",
                          "readback_url", "role", "required_role"]

        def record() -> Any:
            # A result whose parts are each either plausible or arbitrary, down to the evidence.
            evidence = {name: value(2) for name in rng.sample(evidence_names, rng.randrange(len(evidence_names)))}
            if rng.random() < 0.5:
                evidence["decision_evidence"] = {"rule_id": value(3), "subject_identity": value(3),
                                                 "requires_auth": value(3), "field_path": value(3)}
            return {"endpoint": rng.choice([OP, OTHER, PATCH_OP, value(3)]),
                    "check": rng.choice(["BOLA", "RBAC", "BOPLA", "MASS_ASSIGNMENT", value(3)]),
                    "verdict": rng.choice([*self.VERDICTS, value(3)]),
                    "evidence": rng.choice([evidence, evidence, value(1)])}

        def document() -> Any:
            base = report([bola(rng.choice(self.VERDICTS)) for _ in range(rng.randrange(3))]
                          + [record() for _ in range(rng.randrange(5))],
                          context=context() if rng.random() < 0.5 else None)
            for _ in range(rng.randrange(1, 6)):
                holder: Any = base
                for _ in range(rng.randrange(5)):
                    children = [item for item in (holder.values() if isinstance(holder, dict) else holder)
                                if isinstance(item, (dict, list)) and item]
                    if not children:
                        break
                    holder = rng.choice(children)
                if isinstance(holder, dict):
                    holder[rng.choice(names)] = value(0)
                elif holder:
                    holder[rng.randrange(len(holder))] = value(0)
            return base

        outcomes: Set[int] = set()
        with tempfile.TemporaryDirectory(prefix="granttrace-diff-fuzz-") as folder:
            paths = [Path(folder, name) for name in ("a.json", "b.json", "out.json")]
            failure = AssertionError("network opened")
            for index in range(500):
                for path in paths[:2]:
                    path.write_text(json.dumps(document()), encoding="utf-8")
                with self.subTest(index=index):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                            patch("socket.socket", side_effect=failure), \
                            patch("socket.create_connection", side_effect=failure):
                        code = api_sentinel.main(["diff", str(paths[0]), str(paths[1]), "--assume-same-target",
                                                  "--assume-same-identities", "--export-json", str(paths[2])])
                    outcomes.add(code)
                    self.assertIn(code, (0, 2), stderr.getvalue())
                    self.assertNotIn("Traceback", stderr.getvalue())
                    printed = stdout.getvalue() + (paths[2].read_text(encoding="utf-8") if code == 0 else "")
                    for line in printed.replace(str(paths[2]), "").splitlines():
                        self.assertTrue(line.isascii() and line.isprintable(), repr(line))
        self.assertEqual(outcomes, {0, 2})


class PrivacyAndHostileInputTests(unittest.TestCase):
    MARKERS = ("CANARY-BODY-VALUE", "CANARY-REASON-VALUE", "canary-host.internal", "CANARY-HEADER-VALUE",
               "CANARY-PATH-VALUE", "CANARY-COOKIE-VALUE", "CANARY-VERSION-VALUE", "CANARY-TIME-VALUE",
               "CANARY-STAT-VALUE", "CANARY-FINDING-VALUE")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-diff-hostile-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def write(self, name: str, data: Any) -> Path:
        path = self.folder / name
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return path

    def call(self, arguments: Sequence[str]) -> Tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        failure = AssertionError("network opened")
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                patch("socket.socket", side_effect=failure), patch("socket.create_connection", side_effect=failure):
            code = api_sentinel.main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def leaky_reports(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        def leaky(verdict: str) -> Dict[str, Any]:
            record = bola(verdict, path="/api/items/CANARY-PATH-VALUE")
            record["reason"] = "CANARY-REASON-VALUE"
            record["evidence"]["owner"] = {
                "status": 200, "body": '{"ssn": "CANARY-BODY-VALUE"}',
                "headers": {"Authorization": "Bearer CANARY-HEADER-VALUE", "Set-Cookie": "sid=CANARY-COOKIE-VALUE"}}
            return record
        reports = []
        for port, other in ((1, "SECURE"), (2, "CONFIRMED")):
            data = report([leaky("CONFIRMED"), bola(other, OTHER)], target=f"http://canary-host.internal:{port}",
                          version="Bearer CANARY-VERSION-VALUE", generated_at="Cookie: sid=CANARY-TIME-VALUE",
                          stats={"conclusive_coverage_pct": "CANARY-STAT-VALUE", "confirmed": 1})
            data["findings"] = [{"details": "CANARY-FINDING-VALUE", "evidence": {"body": "CANARY-BODY-VALUE"}}]
            reports.append(data)
        return reports[0], reports[1]

    def test_output_contains_no_evidence_credentials_or_free_text_from_the_reports(self):
        baseline, current = self.leaky_reports()
        for flags in ([], ["--assume-same-target", "--assume-same-identities"]):
            with self.subTest(flags=flags):
                code, stdout, stderr = self.call(["diff", str(self.write("a.json", baseline)),
                                                  str(self.write("b.json", current)), *flags,
                                                  "--export-json", str(self.folder / "out.json")])
                self.assertEqual(code, 0, stderr)
                exported = (self.folder / "out.json").read_text(encoding="utf-8")
                for marker in self.MARKERS:
                    self.assertNotIn(marker, stdout + stderr)
                    self.assertNotIn(marker, exported)
                written = json.loads(exported)
                self.assertEqual((written["baseline"]["tool_version"], written["baseline"]["generated_at"]),
                                 (None, None))
                self.assertEqual(written["coverage"]["baseline"], {"confirmed": 1})

    def test_terminal_and_json_output_cannot_be_forged_by_report_content(self):
        hostile_operation = "GET /a/\x1b[2K‮evil"
        records = [
            result("RBAC", OP, "CONFIRMED", rbac_role="viewer‮\x1b[31m", target_url=TARGET + "/a"),
            result("BOLA", hostile_operation, "SECURE", target_url=TARGET + "/a"),
            result("MASS_ASSIGNMENT", PATCH_OP, "CONFIRMED", field="name\r\nRESOLVED  forged-line",
                   target_url=TARGET + "/u"),
            result("MASS_ASSIGNMENT", PATCH_OP, "CONFIRMED", field="rôle 角色", target_url=TARGET + "/u"),
            result("BOPLA", OP, "CONFIRMED",
                   decision_evidence={"rule_id": "note​⁦", "subject_identity": "visitor"}),
            bola("CONFIRMED", OTHER),
        ]
        baseline = self.write("a.json", report(records, version="2.8.0\x1b[2J", generated_at="2026\r\nforged"))
        current = self.write("b.json", report(records))
        code, stdout, stderr = self.call(["diff", str(baseline), str(current), "--assume-same-identities",
                                          "--export-json", str(self.folder / "out.json")])
        self.assertEqual(code, 0, stderr)
        exported = (self.folder / "out.json").read_text(encoding="utf-8")
        for text in (stdout.replace(str(self.folder), ""), exported):
            self.assertTrue(text.isascii())
            self.assertFalse([character for character in text if character != "\n" and not character.isprintable()])
        self.assertNotIn("forged", stdout + exported)
        self.assertEqual(len([line for line in stdout.splitlines() if "RESOLVED" in line]), 0)
        # A legitimate non-ASCII field name survives as an escape in both outputs.
        self.assertIn("field:r\\u00f4le \\u89d2\\u8272", stdout)
        self.assertIn("field:rôle 角色",
                      [issue.get("subject") for issue in json.loads(exported)["issues"]])
        self.assertEqual(json.loads(exported)["summary"]["persisting"], 2)

    def test_lone_surrogates_and_nul_do_not_break_the_export(self):
        baseline = self.write("a.json", '{"tool_version": "\\ud800", "report_schema_version": 2, "target": "\\u0000",'
                                        ' "results": [{"endpoint": "GET /a/\\udfff", "check": "BOLA",'
                                        ' "verdict": "CONFIRMED", "evidence": {"field": "\\ud800"}},'
                                        ' {"endpoint": "PATCH /u", "check": "MASS_ASSIGNMENT", "verdict": "CONFIRMED",'
                                        ' "evidence": {"field": "\\ud800"}}]}')
        code, stdout, stderr = self.call(["diff", str(baseline), str(baseline), "--assume-same-target",
                                          "--assume-same-identities", "--export-json", str(self.folder / "o.json")])
        self.assertEqual(code, 0, stderr)
        written = json.loads((self.folder / "o.json").read_text(encoding="utf-8"))
        self.assertEqual(written["comparability"]["blocking"], ["unreadable_results"])
        self.assertEqual(only(written)["reasons"], ["unreadable_results", "subject_unknown"])

    def test_invalid_inputs_exit_two_without_echoing_contents(self):
        valid = self.write("valid.json", report([]))
        results = json.dumps([bola("CONFIRMED")])
        cases = {
            "missing": str(self.folder / "missing.json"),
            "directory": str(self.folder),
            "not json": str(self.write("bad.json", "{not json CANARY-INPUT")),
            "nan": str(self.write("nan.json", '{"report_schema_version": 2, "x": NaN}')),
            "infinite number": str(self.write("inf.json", '{"report_schema_version": 2, "x": 1e999}')),
            "huge integer": str(self.write("int.json", '{"report_schema_version": %s}' % ("9" * 5000))),
            "deep nesting": str(self.write("deep.json", "[" * 100_000 + "]" * 100_000)),
            # Another parser may keep the first "results"; the report must not mean two things.
            "duplicate key": str(self.write("dup.json", '{"tool_version": "2.8.0", "report_schema_version": 2,'
                                                        ' "results": %s, "results": []}' % results)),
            "nested duplicate key": str(self.write("dup2.json", json.dumps(report([])).replace(
                '"stats": {}', '"stats": {"confirmed": 1, "confirmed": 0}'))),
            "dry run": str(self.write("plan.json", {"mode": "DRY_RUN", "operations": []})),
            "sarif": str(self.write("out.sarif", {"version": "2.1.0", "runs": []})),
            "schema": str(self.write("v3.json", dict(report([]), report_schema_version=3))),
            "bool schema": str(self.write("bool.json", dict(report([]), report_schema_version=True))),
            "float schema": str(self.write("float.json", dict(report([]), report_schema_version=2.0))),
            "no results": str(self.write("none.json", {"tool_version": "2.8.0", "report_schema_version": 2})),
            "no version": str(self.write("nov.json", {"results": [], "report_schema_version": 2})),
            "list root": str(self.write("list.json", [])),
            "empty": str(self.write("empty.json", "")),
        }
        for name, path in cases.items():
            for position in ("baseline", "current"):
                with self.subTest(name, position=position):
                    arguments = [path, str(valid)] if position == "baseline" else [str(valid), path]
                    code, stdout, stderr = self.call(["diff", *arguments, "--export-json",
                                                      str(self.folder / "never.json")])
                    self.assertEqual(code, 2)
                    self.assertIn(f"[ERROR] {position} report:", stderr)
                    self.assertNotIn("CANARY-INPUT", stdout + stderr)
                    self.assertNotIn("Traceback", stderr)
                    self.assertEqual(stdout, "")
                    self.assertFalse((self.folder / "never.json").exists())
        binary = self.folder / "binary.json"
        binary.write_bytes(b"\xff\xfe{")
        self.assertIn("not valid UTF-8", self.call(["diff", str(valid), str(binary)])[2])
        # Non-standard numbers are refused wherever they are, not only at the top of an invalid document.
        text = json.dumps(report([bola("CONFIRMED")], stats={"confirmed": 1}))
        for name, number in (("nan", "NaN"), ("infinity", "Infinity"), ("negative infinity", "-Infinity"),
                             ("overflow", "1e999")):
            with self.subTest(name):
                code, _, stderr = self.call(["diff", str(valid), str(self.write("number.json", text.replace(
                    '"confirmed": 1', f'"confirmed": {number}')))])
                self.assertEqual((code, "not valid JSON" in stderr), (2, True))

    def test_error_messages_say_what_is_wrong_with_the_input(self):
        valid = self.write("valid.json", report([bola("CONFIRMED")]))
        plan = {"mode": "DRY_RUN", "operations": [], "results": []}
        cases = {
            "dry-run plan": (plan, "this is a --dry-run plan"),
            "plan without a mode": ({"operations": [], "requests_sent": 0}, "this is a --dry-run plan"),
            "sarif": ({"version": "2.1.0", "runs": []}, "this is a SARIF file"),
            "schema": (dict(report([]), report_schema_version=1), "unsupported report_schema_version"),
            "results": (dict(report([]), results={}), "report has no results list"),
            "tool version": (dict(report([]), tool_version=2), "report has no tool_version"),
            "root": ([report([])], "report root must be a JSON object"),
        }
        for name, (data, message) in cases.items():
            with self.subTest(name):
                code, _, stderr = self.call(["diff", str(valid), str(self.write("other.json", data))])
                self.assertEqual(code, 2)
                self.assertTrue(stderr.startswith("[ERROR] current report: ") and message in stderr, stderr)
        # A real report is not mistaken for a plan or a SARIF file because of an extra key.
        extra = dict(report([bola("CONFIRMED")]), operations=[], runs=[])
        self.assertEqual(self.call(["diff", str(valid), str(self.write("extra.json", extra))])[0], 0)
        missing = self.call(["diff", str(valid), str(self.folder / "missing.json")])
        self.assertIn("report file does not exist or is not a regular file", missing[2])
        with patch.object(Path, "open", side_effect=PermissionError("CANARY-PATH-DETAIL")):
            code, _, stderr = self.call(["diff", str(valid), str(valid)])
        self.assertEqual((code, stderr.strip()), (2, "[ERROR] baseline report: cannot read report (PermissionError)"))
        with patch("core.report_diff._strict_json", side_effect=MemoryError):
            code, _, stderr = self.call(["diff", str(valid), str(valid)])
        self.assertEqual((code, stderr.strip()), (2, "[ERROR] baseline report: report is too large to process"))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are a POSIX feature")
    def test_a_named_pipe_is_refused_without_waiting_for_a_writer(self):
        valid = self.write("valid.json", report([]))
        pipe = self.folder / "pipe.json"
        os.mkfifo(pipe)
        outcome: List[Any] = []
        worker = threading.Thread(target=lambda: outcome.append(self.call(["diff", str(valid), str(pipe)])),
                                  daemon=True)
        worker.start()
        worker.join(10)
        if worker.is_alive():
            with open(pipe, "w", encoding="utf-8"):  # release a reader that should never have opened it
                pass
            worker.join(10)
            self.fail("the comparison waited on a named pipe")
        self.assertEqual((outcome[0][0], "not a regular file" in outcome[0][2]), (2, True))
        with_bom = self.folder / "bom.json"
        with_bom.write_bytes(b"\xef\xbb\xbf" + json.dumps(report([])).encode())
        self.assertEqual(self.call(["diff", str(valid), str(with_bom)])[0], 0)

    def test_the_size_limit_holds_even_if_the_file_grows_after_the_check(self):
        valid = self.write("valid.json", report([bola("CONFIRMED")]))
        size = valid.stat().st_size
        with patch("core.report_diff.MAX_REPORT_BYTES", size - 1):
            self.assertIn("larger than", self.call(["diff", str(valid), str(valid)])[2])
        with patch("core.report_diff.MAX_REPORT_BYTES", size):
            self.assertEqual(self.call(["diff", str(valid), str(valid)])[0], 0)
        # The reader itself never takes more than the limit: it does not rely on a size reported earlier.
        requested: List[int] = []

        class Growing(io.BytesIO):
            def read(self, size: Optional[int] = -1) -> bytes:
                requested.append(-1 if size is None else size)
                return b"x" * 1000 if size is None or size < 0 else b"x" * size

        with patch("core.report_diff.MAX_REPORT_BYTES", 10), patch.object(Path, "open", return_value=Growing()):
            with self.assertRaises(ReportError) as raised:
                report_diff.load_report(str(valid))
        self.assertEqual((requested, "larger than" in str(raised.exception)), ([11], True))
        with patch.object(Path, "open", return_value=Growing()):
            with self.assertRaises(ReportError) as raised:
                report_diff.load_report(str(valid))
        self.assertEqual((requested[1], str(raised.exception)), (64 * 1024 * 1024 + 1, "report is larger than 64 MiB"))

    def test_statistics_are_passed_through_by_name(self):
        stats = {"total_endpoints": 12, "coverage_pct": 91.5, "conclusive_coverage_pct": 75.0, "conclusive_count": 9,
                 "inconclusive_count": 2, "skipped_count": 1, "error_count": 0, "confirmed": 3,
                 "bola_confirmed": 2, "requests_sent": 40}
        comparison = compare_reports(keyed([bola("SECURE")], stats=stats), keyed([bola("SECURE")], stats={}))
        self.assertEqual(comparison["coverage"]["baseline"], {
            name: value for name, value in stats.items() if name not in ("bola_confirmed", "requests_sent")})
        self.assertEqual(comparison["coverage"]["current"], {})

    def test_out_of_range_statistics_are_left_out(self):
        stats = {"conclusive_coverage_pct": int("9" * 400), "coverage_pct": -5, "confirmed": True,
                 "total_endpoints": 12, "skipped_count": 1e300, "error_count": "3"}
        comparison = compare_reports(keyed([bola("SECURE")], stats=stats), keyed([bola("SECURE")], stats=stats))
        self.assertEqual(comparison["coverage"]["baseline"], {"total_endpoints": 12})

    def test_output_cannot_overwrite_or_alias_an_input(self):
        old = self.write("old.json", report([]))
        new = self.write("new.json", report([]))
        before = old.read_bytes()
        (self.folder / "sub").mkdir()
        aliases = {"same path": old, "relative alias": self.folder / "sub" / ".." / "old.json"}
        try:
            (self.folder / "link.json").symlink_to(old)
            aliases["symbolic link"] = self.folder / "link.json"
        except OSError:
            pass  # symbolic links need a privilege on some Windows systems
        try:
            os.link(old, self.folder / "hard.json")
            aliases["hard link"] = self.folder / "hard.json"
        except OSError:
            pass
        for name, target in aliases.items():
            with self.subTest(name):
                code, _, stderr = self.call(["diff", str(old), str(new), "--export-json", str(target)])
                self.assertEqual(code, 2)
                self.assertIn("must not overwrite an input report", stderr)
                self.assertEqual(old.read_bytes(), before)
        code, _, stderr = self.call(["diff", str(old), str(new), "--export-json", str(self.folder / "sub")])
        self.assertEqual((code, "cannot write comparison JSON" in stderr), (2, True))
        for bad in ("", "   ", "out\x00.json", "out\n.json", "out\x1f.json", "out\x7f.json"):
            with self.subTest(path=bad):
                code, _, stderr = self.call(["diff", str(old), str(new), "--export-json", bad])
                self.assertEqual((code, "--export-json requires" in stderr), (2, True))

    def test_the_comparison_file_is_written_where_asked(self):
        old = self.write("old.json", keyed([bola("CONFIRMED")]))
        new = self.write("new.json", keyed([bola("SECURE")]))
        # Spaces, non-ASCII names and directories that do not exist yet are all fine.
        for target in (self.folder / "my reports" / "deeper level" / "comparison \u5bf9\u6bd4.json",
                       self.folder / "again.json", self.folder / "again.json"):
            with self.subTest(target=target.name):
                code, stdout, stderr = self.call(["diff", str(old), str(new), "--export-json", str(target)])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(stdout.splitlines()[-1], f"[OK] Comparison JSON: {target.resolve()}")
                text = target.read_text(encoding="utf-8")
                self.assertTrue(text.endswith("}\n") and text.startswith("{\n  \"comparison_schema_version\": 1,"))
                self.assertEqual(json.loads(text)["summary"]["resolved"], 1)
        code, stdout, _ = self.call(["diff", str(old), str(new)])
        self.assertEqual((code, "[OK]" in stdout), (0, False))

    def test_validate_report_accepts_a_real_v271_report(self):
        validate_report(json.loads((ROOT / "examples" / "sample_result.json").read_text(encoding="utf-8")))
        with self.assertRaises(ReportError):
            validate_report({"report_schema_version": 2, "results": []})


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-diff-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def write(self, name: str, data: Any) -> Path:
        path = self.folder / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def call(self, arguments: Sequence[str]) -> Tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        failure = AssertionError("network opened")
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                patch("socket.socket", side_effect=failure), patch("socket.create_connection", side_effect=failure):
            code = api_sentinel.main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_diff_writes_json_and_a_readable_summary_offline(self):
        old = self.write("old.json", keyed([bola("CONFIRMED"), bola("SECURE", OTHER)]))
        new = self.write("new.json", keyed([bola("SECURE"), bola("CONFIRMED", OTHER)]))
        output = self.folder / "nested" / "diff.json"
        code, stdout, stderr = self.call(["diff", str(old), str(new), "--export-json", str(output)])
        self.assertEqual(code, 0, stderr)
        self.assertIn("Comparability: declared configuration unchanged (keyed fingerprints in both reports)", stdout)
        self.assertIn("Confirmed findings: 1 new, 0 persisting, 1 resolved, 0 not comparable", stdout)
        self.assertIn("Reports are not authenticated", stdout)
        written = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(written["comparison_schema_version"], 1)
        self.assertEqual((written["summary"]["new"], written["summary"]["resolved"]), (1, 1))
        self.assertTrue(written["comparability"]["fully_comparable"])

    def test_the_exit_code_is_zero_whatever_the_comparison_finds(self):
        cases = {
            "new finding": (keyed([bola("SECURE")]), keyed([bola("CONFIRMED")]), []),
            "not comparable": (report([bola("SECURE")]), report([bola("CONFIRMED")]), []),
            "other target": (keyed([bola("CONFIRMED")]), keyed([bola("CONFIRMED")], target="http://127.0.0.1:9"),
                             []),
            "assumed": (report([bola("CONFIRMED")]), report([bola("SECURE")], target="http://127.0.0.1:9"),
                        ["--assume-same-target", "--assume-same-identities"]),
        }
        for name, (old, new, flags) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.call(["diff", str(self.write("o.json", old)), str(self.write("n.json", new)),
                                            *flags])[0], 0)

    def test_blocked_comparisons_explain_the_way_out(self):
        old = self.write("old.json", report([bola("CONFIRMED")]))
        new = self.write("new.json", report([bola("SECURE")], target="http://127.0.0.1:9999"))
        code, stdout, _ = self.call(["diff", str(old), str(new)])
        self.assertEqual(code, 0)
        self.assertIn("NOT comparable for any finding (target_changed, identities_unverified)", stdout)
        self.assertIn("--assume-same-target", stdout)
        self.assertIn("--assume-same-identities", stdout)
        self.assertIn("GRANTTRACE_COMPARISON_KEY", stdout)
        self.assertIn("0 new, 0 persisting, 0 resolved, 1 not comparable", stdout)
        code, stdout, _ = self.call(["diff", str(old), str(new), "--assume-same-target", "--assume-same-identities"])
        self.assertEqual(code, 0)
        self.assertIn("Comparability: limited (assumed by the caller: same_target; assumed by the caller: "
                      "same_identities)", stdout)
        self.assertIn("[assumed: same_target, same_identities]", stdout)
        self.assertIn("Conclusions that rely on assumptions stated by the caller, not on verification: 1.", stdout)

    def test_assumptions_must_be_spelled_out(self):
        old = self.write("old.json", report([bola("CONFIRMED")]))
        for abbreviated in ("--assume", "--assume-same", "--assume-same-t", "--assume-same-id", "--export"):
            with self.subTest(abbreviated):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as exited:
                    api_sentinel.main(["diff", str(old), str(old), abbreviated])
                self.assertEqual(exited.exception.code, 2)

    def test_help_lists_the_diff_command_and_its_assumptions(self):
        text = api_sentinel.build_argument_parser().format_help()
        self.assertIn("granttrace diff BASELINE.json CURRENT.json", text)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as exited:
            api_sentinel.main(["diff", "--help"])
        self.assertEqual(exited.exception.code, 0)
        for expected in ("never count", "--assume-same-target", "--assume-same-identities",
                         "GRANTTRACE_COMPARISON_KEY", "--export-json PATH", "BASELINE.json CURRENT.json"):
            self.assertIn(expected, " ".join(stdout.getvalue().split()))


class SummaryTests(unittest.TestCase):
    """The terminal summary, line by line."""

    ALL = (OP, OTHER, THIRD, PATCH_OP, "GET /api/removed", "GET /api/added", "GET /api/kept")
    CLOSING = ("Reports are not authenticated, and test data on the server may differ between the scans; "
               "resolved means no longer reproduced with this configuration.")

    def test_a_comparison_with_every_kind_of_line(self):
        unresolved = result("BOLA", "UNKNOWN /api/broken", "INCONCLUSIVE")
        old = keyed([bola("CONFIRMED"), bola("CONFIRMED", OTHER), bola("CONFIRMED", THIRD), bola("SECURE", PATCH_OP),
                     bola("SECURE", "GET /api/removed"), bola("SECURE", "GET /api/kept"), unresolved],
                    version="2.7.1", stats={"conclusive_coverage_pct": 100.0}, operations=self.ALL,
                    bola_config={OP: {"resource_id_paths": ["id"]}})
        new = keyed([bola("SECURE"), bola("SECURE", OTHER), bola("CONFIRMED", THIRD), bola("CONFIRMED", PATCH_OP),
                     bola("CONFIRMED", "GET /api/added"), bola("SKIPPED", "GET /api/kept"), unresolved],
                    version="2.8.0", stats={"conclusive_coverage_pct": 80.0}, generated_at="2026-11-20T09:30:00Z",
                    operations=self.ALL, target="http://127.0.0.1:8001",
                    bola_config={OP: {"resource_id_paths": ["id"], "not_found_is_denial": True}})
        self.assertEqual(report_diff.summary_lines(compare_reports(old, new, assume_same_target=True)), [
            "GrantTrace report comparison",
            "Baseline: GrantTrace 2.7.1, generated 2026-11-13T00:00:00Z",
            "Current:  GrantTrace 2.8.0, generated 2026-11-20T09:30:00Z",
            "Comparability: limited (assumed by the caller: same_target; 1 operation(s) changed or unverifiable; "
            "different or unknown tool versions; unreadable results)",
            "  note: tool versions: 2.7.1 and 2.8.0",
            "  operation GET /api/items/{id}: policy_changed",
            "  note: some result records could not be read and were ignored",
            "Conclusive coverage: 100.0% -> 80.0% (DECREASED; 2 conclusive check(s) lost)",
            "Operations: 1 added, 1 removed",
            "Confirmed findings: 1 new, 1 persisting, 1 resolved, 2 not comparable",
            f"  NEW             {finding_id('BOLA', PATCH_OP)} BOLA {PATCH_OP} [assumed: same_target]",
            f"  NOT COMPARABLE  {finding_id('BOLA', 'GET /api/added')} BOLA GET /api/added "
            "(operation_not_in_baseline)",
            f"  NOT COMPARABLE  {finding_id('BOLA', OP)} BOLA {OP} (policy_changed)",
            f"  PERSISTING      {finding_id('BOLA', THIRD)} BOLA {THIRD} [assumed: same_target]",
            f"  RESOLVED        {finding_id('BOLA', OTHER)} BOLA {OTHER} [assumed: same_target]",
            "Not comparable findings are neither proven new nor fixed; see the reason codes.",
            "Confirmed in the current scan without comparable baseline evidence: 1.",
            "Conclusions that rely on assumptions stated by the caller, not on verification: 3.",
            self.CLOSING])

    def test_a_blocked_comparison_names_every_reason_and_the_way_out(self):
        hidden = dict(bola("CONFIRMED"), check="bad check")
        old = report([bola("CONFIRMED")], target="[BOPLA TARGET OMITTED]", context=dict(context(), version=1),
                     version="?", generated_at="yesterday")
        new = report([bola("SECURE"), hidden], target="[BOPLA TARGET OMITTED]")
        self.assertEqual(report_diff.summary_lines(compare_reports(old, new)), [
            "GrantTrace report comparison",
            "Baseline: GrantTrace unknown version, generated unknown",
            "Current:  GrantTrace 2.8.0, generated 2026-11-13T00:00:00Z",
            "Comparability: NOT comparable for any finding (target_unknown, identities_unverified, "
            "unreadable_results)",
            "  a target cannot be read. Set the comparison key for both scans, or state the same deployment with "
            "--assume-same-target",
            "  a result record that may be a confirmed finding could not be read",
            "  note: tool versions: unknown and 2.8.0",
            "  test accounts not verified: both scans need the same GRANTTRACE_COMPARISON_KEY; state the same "
            "accounts with --assume-same-identities only if you know it",
            "  note: a comparison context is malformed or from an unsupported version and was not used",
            "Conclusive coverage: not recorded",
            "Confirmed findings: 0 new, 0 persisting, 0 resolved, 1 not comparable",
            f"  NOT COMPARABLE  {finding_id('BOLA', OP)} BOLA {OP} (target_unknown, identities_unverified, "
            "unreadable_results)",
            "Not comparable findings are neither proven new nor fixed; see the reason codes.",
            self.CLOSING])

    def test_coverage_and_operation_lines(self):
        def lines(old_stats: Dict[str, Any], new_stats: Dict[str, Any], extra: Sequence[str] = ()) -> List[str]:
            comparison = compare_reports(keyed([bola("SECURE")], stats=old_stats, operations=self.ALL),
                                         keyed([bola("SECURE")] + [bola("SECURE", name) for name in extra],
                                               stats=new_stats, operations=self.ALL))
            return [line for line in report_diff.summary_lines(comparison) if line.startswith(("Conclusive", "Oper"))]

        both = {"conclusive_coverage_pct": 75.0}
        self.assertEqual(lines(both, {"conclusive_coverage_pct": 80.0}), ["Conclusive coverage: 75.0% -> 80.0%"])
        self.assertEqual(lines(both, {"conclusive_coverage_pct": 70.0}),
                         ["Conclusive coverage: 75.0% -> 70.0% (DECREASED; 0 conclusive check(s) lost)"])
        for old_stats, new_stats in ((both, {}), ({}, both), ({}, {})):
            self.assertEqual(lines(old_stats, new_stats), ["Conclusive coverage: not recorded"])
        self.assertEqual(lines({}, {}, ["GET /api/added"]),
                         ["Conclusive coverage: not recorded", "Operations: 1 added, 0 removed"])

    def test_identity_and_target_lines(self):
        def lines(new: Dict[str, Any], old: Optional[Dict[str, Any]] = None, **flags: bool) -> List[str]:
            comparison = compare_reports(old or keyed([bola("CONFIRMED")]), new, **flags)
            return [line for line in report_diff.summary_lines(comparison) if line.startswith(("Compar", "  "))][:-1]

        self.assertEqual(lines(keyed([bola("SECURE")], who=identities(
            visitor_id="2002", roles={"auditor": {"id": "7", "token": "Bearer R"}}))), [
            "Comparability: NOT comparable for any finding (identities_changed)",
            "  the declared test identities differ; these scans are not comparable",
            "  identities changed: visitor, role:auditor"])
        anonymous = identities(None, "1002")
        self.assertEqual(lines(keyed([bola("SECURE")], who=anonymous), keyed([bola("CONFIRMED")], who=anonymous)), [
            "Comparability: NOT comparable for any finding (identities_unverified)",
            "  test accounts not verified: identities without an account id: owner; state the same accounts with "
            "--assume-same-identities only if you know it"])
        self.assertEqual(lines(keyed([bola("SECURE")], who=anonymous), keyed([bola("CONFIRMED")], who=anonymous),
                               assume_same_identities=True), [
            "Comparability: limited (assumed by the caller: same_identities)",
            "  test accounts not verified: identities without an account id: owner (assumed the same by "
            "--assume-same-identities)"])
        self.assertEqual(lines(keyed([bola("SECURE")], who=identities(visitor_token="Bearer ROTATED"))), [
            "Comparability: NOT comparable for any finding (identities_unverified)",
            "  test accounts not verified: a credential differs between the scans (a rotation and another "
            "account's credential look the same); state the same accounts with --assume-same-identities only if "
            "you know it"])
        self.assertEqual(lines(keyed([bola("SECURE")], key=OTHER_KEY))[2],
                         "  note: the reports were made with different comparison keys; keyed fingerprints were "
                         "not used")
        self.assertEqual(lines(keyed([bola("SECURE")], target="http://127.0.0.1:8001")), [
            "Comparability: NOT comparable for any finding (target_changed)",
            "  the targets differ (scheme, host, port or base path). If both scans tested the same deployment, "
            "state it with --assume-same-target"])
        self.assertEqual(lines(keyed([bola("SECURE")])), [
            "Comparability: declared configuration unchanged (keyed fingerprints in both reports)"])


class _OrdersApi(BaseHTTPRequestHandler):
    """A is user 1 in organisation 1 and owns order 11; B (user 2, organisation 1) and C (user 3,
    organisation 2) share order 22. In mode `intra_org` anyone in the owner's organisation can read
    an order: the vulnerability. Requests through the "eu" edge are always checked properly."""

    mode = "intra_org"
    users = {"Bearer owner-test": (1, 1), "Bearer visitor-test": (2, 1), "Bearer visitor-rotated": (2, 1),
             "Bearer other-account": (3, 2)}
    orders = {11: {"id": 11, "organisation": 1, "members": [1], "address": "1 Owner Street"},
              22: {"id": 22, "organisation": 9, "members": [2, 3], "address": "2 Shared Avenue"}}

    def log_message(self, *args: Any) -> None:
        pass

    def reply(self, status: int, body: Any) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path, _, query = self.path.partition("?")
        user = self.users.get(self.headers.get("Authorization", ""))
        if user is None:
            return self.reply(401, {"error": "authentication required"})
        order = self.orders.get(int(path.rstrip("/").split("/")[-1]))
        if order is None:
            return self.reply(404, {"error": "not found"})
        strict = self.headers.get("X-Edge-Region") == "eu" or "edge=eu" in query
        allowed = user[0] in order["members"] or (
            type(self).mode == "intra_org" and not strict and user[1] == order["organisation"])
        return self.reply(200, order) if allowed else self.reply(403, {"error": "forbidden"})


class _DocumentsApi(BaseHTTPRequestHandler):
    """One shared document whose private note leaks to the Visitor unless `leaking` is false."""

    leaking = True
    OWNER_NOTE = "owner-note-unique-5521"

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        authorization = self.headers.get("Authorization", "")
        identity = "owner" if "ALICE" in authorization else "visitor" if "BOB" in authorization else "anonymous"
        if self.path.endswith("/1001"):
            if identity == "owner" or (identity == "visitor" and type(self).leaking):
                status, body = 200, {"id": "1001", "title": "Shared", "private_note": self.OWNER_NOTE}
            elif identity == "visitor":
                status, body = 403, {"error": "forbidden"}
            else:
                status, body = 401, {"error": "authentication required"}
        elif self.path.endswith("/1002") and identity == "visitor":
            status, body = 200, {"id": "1002", "title": "Visitor document", "private_note": "visitor-note-8812"}
        else:
            status, body = 404, {"error": "not found"}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class EndToEndTests(unittest.TestCase):
    """Real scans of a local API and the built-in demo, compared with `granttrace diff`."""

    ORDER = "GET /orders/{orderId}"
    DOCUMENT = "GET /documents/{id}"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-diff-e2e-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def run_cli(self, arguments: Sequence[Any], key: Optional[str] = None) -> Tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"GRANTTRACE_COMPARISON_KEY": key} if key is not None else {}), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            if key is None:
                os.environ.pop("GRANTTRACE_COMPARISON_KEY", None)
            code = api_sentinel.main([str(item) for item in arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def scan(self, name: str, handler: type, spec: Dict[str, Any], config: Dict[str, Any], *, port: int = 0,
             key: Optional[str] = KEY) -> Tuple[Path, int]:
        server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        folder = self.folder / name
        folder.mkdir()
        (folder / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
        (folder / "config.json").write_text(json.dumps(config), encoding="utf-8")
        try:
            code, stdout, stderr = self.run_cli(
                ["--spec", folder / "spec.json", "--config", folder / "config.json", "--target",
                 f"http://127.0.0.1:{server.server_port}", "--delay", "0", "-o", folder / "report.html",
                 "--export-json", folder / "report.json"], key)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(code, 0, stdout + stderr)
        return folder / "report.json", server.server_port

    def diff(self, old: Path, new: Path, *options: str) -> Dict[str, Any]:
        output = self.folder / "comparison.json"
        code, stdout, stderr = self.run_cli(["diff", old, new, *options, "--export-json", output])
        self.assertEqual(code, 0, stdout + stderr)
        return json.loads(output.read_text(encoding="utf-8"))

    def finding(self, comparison: Dict[str, Any], check: str = "BOLA", subject: Optional[str] = None) -> Dict[str, Any]:
        issues = [issue for issue in comparison["issues"]
                  if issue["check"] == check and issue.get("subject") == subject]
        self.assertEqual(len(issues), 1, comparison["issues"])
        return issues[0]

    # --- an orders API with an intra-organisation BOLA ---------------------------------------------

    @staticmethod
    def orders_spec(edge: bool = False) -> Dict[str, Any]:
        parameters: List[Dict[str, Any]] = [{"name": "orderId", "in": "path", "required": True,
                                             "schema": {"type": "integer"}}]
        if edge:
            parameters.append({"name": "edge", "in": "query", "required": True,
                               "schema": {"type": "string", "enum": ["eu"]}})
        return {"openapi": "3.0.3", "info": {"title": "orders", "version": "1"},
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                "security": [{"bearer": []}],
                "paths": {"/orders/{orderId}": {"get": {"operationId": "getOrder", "parameters": parameters,
                                                        "responses": {"200": {"description": "ok"}}}}}}

    @staticmethod
    def orders_config(visitor_token: str = "Bearer visitor-test", ids: bool = True,
                      visitor_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        owner: Dict[str, Any] = {"token": "Bearer owner-test"}
        visitor: Dict[str, Any] = {"token": visitor_token}
        if ids:
            owner["id"], visitor["id"] = "1", "2"
        if visitor_headers:
            visitor["headers"] = visitor_headers
        return {"identities": {"owner": owner, "visitor": visitor, "anonymous": {}},
                "parameter_values": {"GET /orders/{orderId}": {"owner": {"orderId": 11}, "visitor": {"orderId": 22}}}}

    def orders(self, name: str, mode: str, **options: Any) -> Tuple[Path, int]:
        _OrdersApi.mode = mode
        spec = self.orders_spec(options.pop("edge", False))
        scan_options = {name: options.pop(name) for name in ("port", "key") if name in options}
        return self.scan(name, _OrdersApi, spec, self.orders_config(**options), **scan_options)

    def test_real_scans_classify_new_persisting_and_resolved(self):
        vulnerable, port = self.orders("one", "intra_org")
        fixed, _ = self.orders("two", "fixed", port=port)
        again, _ = self.orders("three", "intra_org", port=port)
        text = vulnerable.read_text(encoding="utf-8")
        context_text = json.dumps(json.loads(text)["comparison_context"])
        for value in ("owner-test", "visitor-test", KEY, str(port), "127.0.0.1"):
            self.assertNotIn(value, context_text)
        self.assertNotIn(KEY, text)
        for old, new, status in ((vulnerable, fixed, "resolved"), (fixed, again, "new"),
                                 (vulnerable, again, "persisting")):
            with self.subTest(status):
                comparison = self.diff(old, new)
                self.assertEqual(comparison["comparability"]["basis"], "declared")
                self.assertTrue(comparison["comparability"]["fully_comparable"])
                issue = self.finding(comparison)
                self.assertEqual((issue["status"], issue["finding_id"]), (status, finding_id("BOLA", self.ORDER)))
                self.assertNotIn("assumptions", issue)

    def test_a_vulnerability_that_is_still_there_is_never_reported_as_resolved(self):
        """The API stays vulnerable in every second scan; only the way it is scanned changes."""
        baseline, port = self.orders("baseline", "intra_org")
        self.assertEqual(json.loads(baseline.read_text(encoding="utf-8"))["stats"]["bola_confirmed"], 1)
        cases = {
            # The specification gained a required parameter that selects a properly checked edge.
            "specification edited": ({"edge": True}, ["resources_changed", "spec_changed"]),
            # The visitor sends a non-credential header that selects that edge.
            "identity header added": ({"visitor_headers": {"X-Edge-Region": "eu"}}, ["identities_changed"]),
            # The visitor's credential now belongs to an account outside the owner's organisation.
            "credential of another account": ({"visitor_token": "Bearer other-account"}, ["identities_unverified"]),
        }
        for name, (options, reasons) in cases.items():
            with self.subTest(name):
                current, _ = self.orders(name.replace(" ", "-"), "intra_org", port=port, **options)
                report_data = json.loads(current.read_text(encoding="utf-8"))
                self.assertEqual([item["verdict"] for item in report_data["results"]], ["SECURE"])
                comparison = self.diff(baseline, current)
                issue = self.finding(comparison)
                self.assertEqual((issue["status"], issue["reasons"]), ("not_comparable", reasons))
                self.assertFalse(comparison["comparability"]["fully_comparable"])
                self.assertEqual(comparison["summary"]["resolved"], 0)
        # Without a key, or without account ids, the same swap of accounts cannot be told from a fix.
        for name, options in (("no key", {"key": None}), ("no account ids", {"ids": False})):
            with self.subTest(name):
                first, first_port = self.orders(name.replace(" ", "-") + "-a", "intra_org", **options)
                second, _ = self.orders(name.replace(" ", "-") + "-b", "intra_org", port=first_port,
                                        visitor_token="Bearer other-account", **options)
                comparison = self.diff(first, second)
                issue = self.finding(comparison)
                self.assertEqual((issue["status"], issue["reasons"]), ("not_comparable", ["identities_unverified"]))
                self.assertEqual(issue["current_verdicts"], ["SECURE"])

    def test_a_rotated_credential_needs_the_stated_assumption(self):
        vulnerable, port = self.orders("before", "intra_org")
        fixed, _ = self.orders("after", "fixed", port=port, visitor_token="Bearer visitor-rotated")
        issue = self.finding(self.diff(vulnerable, fixed))
        self.assertEqual((issue["status"], issue["reasons"]), ("not_comparable", ["identities_unverified"]))
        stated = self.diff(vulnerable, fixed, "--assume-same-identities")
        self.assertEqual((self.finding(stated)["status"], self.finding(stated)["assumptions"]),
                         ("resolved", ["same_identities"]))
        self.assertFalse(stated["comparability"]["fully_comparable"])
        # The flag does not cover a changed specification or declared identity.
        edited, _ = self.orders("edited", "intra_org", port=port, edge=True)
        self.assertEqual(self.finding(self.diff(vulnerable, edited, "--assume-same-identities",
                                                "--assume-same-target"))["status"], "not_comparable")

    def test_two_services_on_one_host_are_another_target(self):
        vulnerable, first_port = self.orders("vulnerable-service", "intra_org")
        fixed, second_port = self.orders("fixed-service", "fixed")
        self.assertNotEqual(first_port, second_port)
        issue = self.finding(self.diff(vulnerable, fixed))
        self.assertEqual((issue["status"], issue["reasons"]), ("not_comparable", ["target_changed"]))
        acknowledged = self.diff(vulnerable, fixed, "--assume-same-target")
        self.assertEqual((self.finding(acknowledged)["status"], self.finding(acknowledged)["assumptions"]),
                         ("resolved", ["same_target"]))
        self.assertEqual(acknowledged["comparability"]["assumptions"], ["same_target"])
        self.assertFalse(acknowledged["comparability"]["fully_comparable"])

    # --- a documents API scanned with a BOPLA policy: the report omits its target -------------------

    def documents(self, name: str, leaking: bool, **options: Any) -> Tuple[Path, int]:
        _DocumentsApi.leaking = leaking
        spec = {"openapi": "3.0.3", "info": {"title": "documents", "version": "1"},
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                "paths": {"/documents/{id}": {"get": {
                    "security": [{"bearer": []}],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "document"}}}}}}
        config = {
            "identities": {"owner": {"id": "1001", "token": "Bearer ALICE_OWNER_TOKEN", "parameters": {"id": "1001"}},
                           "visitor": {"id": "1002", "token": "Bearer BOB_VISITOR_TOKEN",
                                       "parameters": {"id": "1002"}},
                           "anonymous": {"id": None, "token": None, "parameters": {}}},
            "bola": {self.DOCUMENT: {"expected_visitor_access": "allow"}},
            "bopla": {self.DOCUMENT: {
                "policy_id": "document-fields-v1", "context_id": "selected-owner-document",
                "resource_binding": {"id": "1001"},
                "fields": [{"rule_id": "owner-note", "path": "private_note",
                            "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                            "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}}}
        return self.scan(name, _DocumentsApi, spec, config, **options)

    def test_bopla_reports_omit_the_target_and_compare_only_with_a_key(self):
        subject = "field:owner-note|identity:visitor"
        leaking, port = self.documents("leaking", True, key=None)
        fixed, _ = self.documents("fixed", False, key=None, port=port)
        for path in (leaking, fixed):
            text = path.read_text(encoding="utf-8")
            self.assertIn("[BOPLA TARGET OMITTED]", text)
            self.assertNotIn("127.0.0.1", text)
            self.assertNotIn("comparison_context", text)
        issue = self.finding(self.diff(leaking, fixed), "BOPLA", subject)
        self.assertEqual((issue["status"], issue["baseline_verdicts"], issue["current_verdicts"]),
                         ("not_comparable", ["CONFIRMED"], ["SECURE"]))
        self.assertEqual(issue["reasons"][:2], ["target_unknown", "identities_unverified"])
        # With a key the target is compared by its fingerprint and still never written.
        keyed_leaking, keyed_port = self.documents("keyed-leaking", True)
        elsewhere, _ = self.documents("keyed-elsewhere", False)
        same, _ = self.documents("keyed-same", False, port=keyed_port)
        for path in (keyed_leaking, elsewhere, same):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("127.0.0.1", text)
            self.assertNotIn(KEY, text)
        moved = self.finding(self.diff(keyed_leaking, elsewhere), "BOPLA", subject)
        self.assertEqual((moved["status"], moved["reasons"]), ("not_comparable", ["target_changed"]))
        comparison = self.diff(keyed_leaking, same)
        self.assertEqual(self.finding(comparison, "BOPLA", subject)["status"], "resolved")
        self.assertEqual(comparison["comparability"]["basis"], "declared")

    # --- the built-in demo, an earlier release and the key itself -----------------------------------

    def test_demo_runs_and_a_v271_report_need_explicit_assumptions(self):
        runs = []
        for name in ("first", "second"):
            with patch.dict(os.environ, {"GRANTTRACE_COMPARISON_KEY": KEY}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(demo.run_demo(output_dir=str(self.folder / name)), 0)
            runs.append(next((self.folder / name).rglob("granttrace_report.json")))
        # Each demo run listens on a new ephemeral port, so the targets differ.
        plain = self.diff(runs[0], runs[1])
        self.assertEqual(plain["comparability"]["blocking"], ["target_changed"])
        self.assertEqual([plain["summary"][name] for name in CONCLUSIONS], [0, 0, 0])
        comparison = self.diff(runs[0], runs[1], "--assume-same-target")
        self.assertEqual(comparison["summary"]["persisting"], 2)
        self.assertEqual((comparison["comparability"]["basis"], comparison["comparability"]["assumptions"]),
                         ("declared", ["same_target"]))
        self.assertFalse(comparison["comparability"]["fully_comparable"])
        # A report from 2.7.1 has no context: nothing is concluded without both assumptions.
        sample = ROOT / "examples" / "sample_result.json"
        for flags in ([], ["--assume-same-target"], ["--assume-same-identities"]):
            with self.subTest(flags=flags):
                legacy = self.diff(sample, runs[1], *flags)
                self.assertEqual(legacy["comparability"]["basis"], "evidence")
                self.assertEqual([legacy["summary"][name] for name in CONCLUSIONS], [0, 0, 0])
        legacy = self.diff(sample, runs[1], "--assume-same-target", "--assume-same-identities")
        self.assertEqual(legacy["summary"]["persisting"], 2)
        self.assertEqual(legacy["summary"]["relying_on_assumptions"], 2)
        self.assertEqual((legacy["baseline"]["tool_version"], legacy["baseline"]["context"]), ("2.7.1", "absent"))
        self.assertEqual({issue["finding_id"] for issue in legacy["issues"]},
                         {issue["finding_id"] for issue in comparison["issues"]})
        # Without a key the demo report is exactly what it was: no context at all.
        with patch.dict(os.environ), contextlib.redirect_stdout(io.StringIO()):
            os.environ.pop("GRANTTRACE_COMPARISON_KEY", None)
            self.assertEqual(demo.run_demo(output_dir=str(self.folder / "plain")), 0)
        plain_report = json.loads(next((self.folder / "plain").rglob("granttrace_report.json")).read_text("utf-8"))
        self.assertNotIn("comparison_context", plain_report)

    def test_an_unusable_comparison_key_stops_a_scan_before_any_request(self):
        failure = AssertionError("network opened")
        for weak in ("short-key", "a" * 40):
            with self.subTest(key=weak):
                demo_errors = io.StringIO()
                with patch("socket.socket", side_effect=failure), \
                        patch("socket.create_connection", side_effect=failure):
                    code, stdout, stderr = self.run_cli(
                        ["--spec", ROOT / "openapi.json", "--config", ROOT / "config.example.json",
                         "--target", "http://127.0.0.1:9", "-o", self.folder / "r.html"], key=weak)
                    with patch.dict(os.environ, {"GRANTTRACE_COMPARISON_KEY": weak}), \
                            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(demo_errors):
                        demo_code = demo.run_demo(output_dir=str(self.folder / "demo"))
                self.assertEqual((code, demo_code), (2, 2))
                self.assertIn("GRANTTRACE_COMPARISON_KEY", stderr)
                self.assertNotIn(weak, stdout + stderr + demo_errors.getvalue())
                self.assertFalse((self.folder / "r.html").exists())
                self.assertFalse((self.folder / "demo").exists())
        # The key is not needed, and not read, for an offline plan.
        code, _, stderr = self.run_cli(["--spec", ROOT / "openapi.json", "--config", ROOT / "config.example.json",
                                        "--dry-run"], key="short-key")
        self.assertEqual(code, 0, stderr)


if __name__ == "__main__":
    unittest.main()
