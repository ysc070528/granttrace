"""Offline comparison of two GrantTrace JSON reports (`granttrace diff`)."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import random
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from unittest.mock import patch

import api_sentinel
from core import demo
from core.report_diff import ReportError, build_comparison_context, compare_reports, finding_id, validate_report

ROOT = Path(__file__).resolve().parents[1]
OP = "GET /api/items/{id}"
OTHER = "GET /api/orders/{id}"
KEY = "unit-test-comparison-key-0123456789"
TARGET = "http://127.0.0.1:8000"


def result(check: str, endpoint: str, verdict: str, **evidence: Any) -> Dict[str, Any]:
    return {"endpoint": endpoint, "operation_id": "op", "check": check, "verdict": verdict,
            "reason": "synthetic", "evidence": evidence}


def bola(verdict: str, endpoint: str = OP, path: str = "/api/items/1") -> Dict[str, Any]:
    return result("BOLA", endpoint, verdict, target_url="http://127.0.0.1:8000" + path,
                  visitor_self_url="http://127.0.0.1:8000/api/items/2")


def report(results: List[Dict[str, Any]], *, version: str = "2.8.0", target: str = "http://127.0.0.1:8000",
           context: Optional[Dict[str, Any]] = None, stats: Optional[Dict[str, Any]] = None,
           generated_at: str = "2026-11-13T00:00:00Z") -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "tool_version": version, "report_schema_version": 2, "generated_at": generated_at,
        "elapsed_seconds": 1.0, "target": target, "stats": stats or {}, "results": results, "findings": [],
    }
    if context is not None:
        data["comparison_context"] = context
    return data


def context(owner_id: str = "1001", visitor_id: str = "1002", target: str = TARGET, key: str = KEY,
            **sections: Any) -> Dict[str, Any]:
    return build_comparison_context(
        key=key, target=target,
        identities={"owner": {"id": owner_id, "token": "Bearer OWNER-VALUE"},
                    "visitor": {"id": visitor_id, "token": "Bearer VISITOR-VALUE"}, "anonymous": {}},
        secret_values=("Bearer OWNER-VALUE", "Bearer VISITOR-VALUE"), **sections)


def by_id(comparison: Dict[str, Any]) -> Dict[Tuple[str, str, Optional[str]], Dict[str, Any]]:
    return {(issue["check"], issue["operation"], issue.get("subject")): issue for issue in comparison["issues"]}


class FindingIdentityTests(unittest.TestCase):
    def test_finding_id_depends_only_on_check_operation_and_subject(self):
        self.assertEqual(finding_id("BOLA", OP), finding_id("BOLA", OP, None))
        self.assertRegex(finding_id("BOLA", OP), r"^gtf_[0-9a-f]{16}$")
        identifiers = {finding_id("BOLA", OP), finding_id("BFLA", OP), finding_id("BOLA", OTHER),
                       finding_id("RBAC", OP, "role:auditor"), finding_id("RBAC", OP, "role:viewer")}
        self.assertEqual(len(identifiers), 5)

    def test_identifiers_ignore_target_port_time_resource_and_evidence(self):
        first = report([bola("CONFIRMED", path="/api/items/1")], target="http://127.0.0.1:40001",
                       generated_at="2026-11-13T00:00:00Z")
        second = report([bola("CONFIRMED", path="/api/items/1")], target="http://127.0.0.1:50002",
                        generated_at="2026-11-20T09:30:00Z")
        second["results"][0]["evidence"]["request_id"] = "random-7f3a"
        # The port decides comparability (see ReviewRegressionTests), never the identifier.
        for comparison, status in ((compare_reports(first, second), "not_comparable"),
                                   (compare_reports(first, second, assume_same_target=True), "persisting")):
            self.assertEqual([issue["status"] for issue in comparison["issues"]], [status])
            self.assertEqual(comparison["issues"][0]["finding_id"], finding_id("BOLA", OP))


class ClassificationTests(unittest.TestCase):
    def test_new_persisting_and_resolved(self):
        baseline = report([bola("SECURE"), bola("CONFIRMED", OTHER, "/api/orders/1"),
                           result("BFLA", OP, "CONFIRMED", target_url="http://127.0.0.1:8000/api/items/1")])
        current = report([bola("CONFIRMED"), bola("CONFIRMED", OTHER, "/api/orders/1"),
                          result("BFLA", OP, "SECURE", target_url="http://127.0.0.1:8000/api/items/1")])
        comparison = compare_reports(baseline, current)
        issues = by_id(comparison)
        self.assertEqual(issues[("BOLA", OP, None)]["status"], "new")
        self.assertEqual(issues[("BOLA", OTHER, None)]["status"], "persisting")
        self.assertEqual(issues[("BFLA", OP, None)]["status"], "resolved")
        self.assertEqual(comparison["summary"], {"new": 1, "not_comparable": 0, "persisting": 1, "resolved": 1,
                                                 "current_confirmed_not_comparable": 0,
                                                 "baseline_confirmed": 2, "current_confirmed": 2})
        # Without keyed contexts the test accounts are unverified: usable, but not fully comparable.
        self.assertEqual(comparison["comparability"]["basis"], "evidence")
        self.assertFalse(comparison["comparability"]["fully_comparable"])
        self.assertEqual(issues[("BOLA", OP, None)]["cwe"], "CWE-639")
        keyed = compare_reports(dict(baseline, comparison_context=context()), dict(current, comparison_context=context()))
        self.assertEqual(keyed["comparability"]["basis"], "declared")
        self.assertTrue(keyed["comparability"]["fully_comparable"])
        self.assertEqual(by_id(keyed)[("BOLA", OP, None)]["status"], "new")

    def test_skipped_inconclusive_error_or_suspicious_never_count_as_fixed(self):
        for verdict in ("SKIPPED", "INCONCLUSIVE", "ERROR", "SUSPICIOUS", "NOT-A-VERDICT"):
            with self.subTest(verdict=verdict):
                comparison = compare_reports(report([bola("CONFIRMED")]), report([bola(verdict)]))
                issue = comparison["issues"][0]
                self.assertEqual(issue["status"], "not_comparable")
                self.assertEqual(issue["reasons"], ["current_unverified"])
                self.assertEqual(comparison["summary"]["resolved"], 0)

    def test_missing_current_results_are_not_comparable(self):
        removed = compare_reports(report([bola("CONFIRMED")]), report([bola("SECURE", OTHER, "/api/orders/1")]))
        self.assertEqual(removed["issues"][0]["reasons"], ["operation_not_in_current"])
        other_check = compare_reports(report([bola("CONFIRMED")]),
                                      report([result("BFLA", OP, "SECURE", target_url="http://h/api/items/1")]))
        self.assertEqual(other_check["issues"][0]["reasons"], ["missing_in_current"])
        for comparison in (removed, other_check):
            self.assertEqual(comparison["issues"][0]["status"], "not_comparable")

    def test_unverified_or_unchecked_baseline_is_not_new(self):
        unverified = compare_reports(report([bola("SKIPPED")]), report([bola("CONFIRMED")]))
        self.assertEqual((unverified["issues"][0]["status"], unverified["issues"][0]["reasons"]),
                         ("not_comparable", ["baseline_unverified"]))
        unchecked = compare_reports(report([result("BFLA", OP, "SECURE")]), report([bola("CONFIRMED")]))
        self.assertEqual((unchecked["issues"][0]["status"], unchecked["issues"][0]["reasons"]),
                         ("not_comparable", ["not_checked_in_baseline"]))
        added = compare_reports(report([bola("SECURE", OTHER)]), report([bola("SECURE", OTHER), bola("CONFIRMED")]))
        self.assertEqual((added["issues"][0]["status"], added["issues"][0]["reasons"]),
                         ("not_comparable", ["operation_not_in_baseline"]))
        for comparison in (unverified, unchecked, added):
            self.assertEqual(comparison["summary"]["new"], 0)
            self.assertEqual(comparison["summary"]["current_confirmed_not_comparable"], 1)

    def test_bopla_and_rbac_findings_are_tracked_per_subject(self):
        def bopla(verdict: str, rule: str, identity: str = "visitor") -> Dict[str, Any]:
            return result("BOPLA", OP, verdict, target_url="http://h/api/items/1",
                          decision_evidence={"rule_id": rule, "subject_identity": identity})

        def rbac(verdict: str, role: str) -> Dict[str, Any]:
            return result("RBAC", OP, verdict, target_url="http://h/api/items/1", rbac_role=role,
                          role=role, required_role="admin")

        baseline = report([bopla("CONFIRMED", "salary"), bopla("SECURE", "phone"), rbac("CONFIRMED", "viewer"),
                           rbac("SECURE", "auditor")])
        current = report([bopla("SECURE", "salary"), bopla("CONFIRMED", "phone"), rbac("SECURE", "viewer"),
                          rbac("CONFIRMED", "auditor")])
        issues = by_id(compare_reports(baseline, current))
        self.assertEqual(issues[("BOPLA", OP, "field:salary|identity:visitor")]["status"], "resolved")
        self.assertEqual(issues[("BOPLA", OP, "field:phone|identity:visitor")]["status"], "new")
        self.assertEqual(issues[("RBAC", OP, "role:viewer")]["status"], "resolved")
        self.assertEqual(issues[("RBAC", OP, "role:auditor")]["status"], "new")

    def test_mass_assignment_is_resolved_only_for_a_verified_safe_field(self):
        patch_op = "PATCH /api/users/{id}/settings"
        confirmed = report([result("MASS_ASSIGNMENT", patch_op, "CONFIRMED", field="role",
                                   target_url="http://h/api/users/1/settings")])
        cases = {
            "role verified safe": (["role"], "SECURE", "resolved", None),
            "role not tested": (["nickname"], "SECURE", "not_comparable", ["missing_in_current"]),
            "check inconclusive": ([], "INCONCLUSIVE", "not_comparable", ["current_unverified"]),
        }
        for name, (safe, verdict, status, reasons) in cases.items():
            with self.subTest(name):
                current = report([result("MASS_ASSIGNMENT", patch_op, verdict, safe_fields=safe,
                                         target_url="http://h/api/users/1/settings")])
                issue = compare_reports(confirmed, current)["issues"][0]
                self.assertEqual((issue["subject"], issue["status"], issue.get("reasons")),
                                 ("field:role", status, reasons))


class ComparabilityTests(unittest.TestCase):
    def test_changed_test_accounts_make_every_finding_not_comparable(self):
        comparison = compare_reports(report([bola("CONFIRMED"), bola("CONFIRMED", OTHER)], context=context()),
                                     report([bola("SECURE"), bola("CONFIRMED", OTHER)],
                                            context=context(visitor_id="2002")))
        self.assertFalse(comparison["comparability"]["fully_comparable"])
        self.assertIn({"kind": "identities", "identities": ["visitor"], "blocking": True},
                      comparison["comparability"]["changes"])
        for issue in comparison["issues"]:
            self.assertEqual(issue["status"], "not_comparable")
            self.assertIn("identities_changed", issue["reasons"])

    def test_rotated_credentials_alone_keep_reports_comparable(self):
        rotated = build_comparison_context(
            key=KEY, target=TARGET,
            identities={"owner": {"id": "1001", "token": "Bearer ROTATED-A"},
                        "visitor": {"id": "1002", "token": "Bearer ROTATED-B"}, "anonymous": {}},
            secret_values=("Bearer ROTATED-A", "Bearer ROTATED-B"))
        self.assertEqual(rotated["identities"], context()["identities"])
        # Credentials are not fingerprinted at all, even when they are not known as secrets.
        unmasked = [build_comparison_context(key=KEY, target=TARGET, identities={
            "owner": {"id": "1001", "token": token, "headers": {"Authorization": token}},
            "visitor": {"id": "1002", "token": token}, "anonymous": {}}) for token in ("Bearer X1", "Bearer Y2")]
        self.assertEqual(unmasked[0]["identities"], unmasked[1]["identities"])
        comparison = compare_reports(report([bola("CONFIRMED")], context=context()),
                                     report([bola("SECURE")], context=rotated))
        self.assertEqual(comparison["issues"][0]["status"], "resolved")

    def test_policy_or_resource_changes_affect_only_that_operation(self):
        before = context(bola_config={OP: {"resource_id_paths": ["id"]}},
                         parameter_values={OTHER: {"owner": {"id": 1}, "visitor": {"id": 2}}})
        after = context(bola_config={OP: {"resource_id_paths": ["id"], "not_found_is_denial": True}},
                        parameter_values={OTHER: {"owner": {"id": 7}, "visitor": {"id": 2}}})
        third = "GET /api/notes/{id}"
        comparison = compare_reports(
            report([bola("CONFIRMED"), bola("CONFIRMED", OTHER), bola("CONFIRMED", third)], context=before),
            report([bola("SECURE"), bola("SECURE", OTHER), bola("SECURE", third)], context=after))
        issues = by_id(comparison)
        self.assertEqual(issues[("BOLA", OP, None)]["reasons"], ["policy_changed"])
        self.assertEqual(issues[("BOLA", OTHER, None)]["reasons"], ["resources_changed"])
        self.assertEqual(issues[("BOLA", third, None)]["status"], "resolved")
        # One unaffected operation must not make the whole comparison look verified.
        self.assertFalse(comparison["comparability"]["fully_comparable"])
        self.assertEqual(comparison["comparability"]["operation_changes"],
                         [{"operation": OP, "reasons": ["policy_changed"]},
                          {"operation": OTHER, "reasons": ["resources_changed"]}])
        self.assertEqual(comparison["comparability"]["blocking"], [])

    def test_a_different_host_scheme_or_base_path_blocks(self):
        for before, after in (("https://staging.example", "https://production.example"),
                              ("http://api.example", "https://api.example"),
                              ("https://api.example/v1", "https://api.example/v2")):
            with self.subTest(before=before, after=after):
                plain = compare_reports(report([bola("CONFIRMED")], target=before),
                                        report([bola("SECURE")], target=after))
                self.assertEqual(plain["issues"][0]["reasons"], ["target_changed"])
                self.assertFalse(plain["comparability"]["fully_comparable"])
                keyed = compare_reports(report([bola("CONFIRMED")], target=before, context=context(target=before)),
                                        report([bola("SECURE")], target=after, context=context(target=after)))
                self.assertEqual(keyed["comparability"]["basis"], "declared")
                self.assertEqual(keyed["issues"][0]["reasons"], ["target_changed"])

    def test_reports_without_context_fall_back_to_evidence_paths(self):
        comparison = compare_reports(report([bola("CONFIRMED", path="/api/items/1")]),
                                     report([bola("SECURE", path="/api/items/9")], context=context()))
        self.assertEqual(comparison["comparability"]["basis"], "evidence")
        self.assertIn("identities_unverified", comparison["comparability"]["notes"])
        self.assertEqual(comparison["issues"][0]["reasons"], ["resources_changed"])
        unknown = compare_reports(report([result("BOLA", OP, "CONFIRMED")]), report([result("BOLA", OP, "SECURE")]))
        self.assertEqual(unknown["issues"][0]["reasons"], ["scope_unknown"])

    def test_tool_version_and_operation_changes_are_reported_without_blocking(self):
        comparison = compare_reports(report([bola("CONFIRMED")], version="2.7.1", context=context()),
                                     report([bola("CONFIRMED"), bola("SECURE", OTHER)], version="2.8.0",
                                            context=context()))
        kinds = {change["kind"]: change for change in comparison["comparability"]["changes"]}
        self.assertFalse(kinds["tool_version"]["blocking"])
        self.assertEqual(kinds["operations_added"]["count"], 1)
        self.assertTrue(comparison["comparability"]["fully_comparable"])

    def test_coverage_loss_is_reported_separately(self):
        comparison = compare_reports(
            report([bola("SECURE"), bola("SECURE", OTHER)], stats={"conclusive_coverage_pct": 100.0}),
            report([bola("SECURE"), bola("SKIPPED", OTHER)], stats={"conclusive_coverage_pct": 50.0}))
        coverage = comparison["coverage"]
        self.assertTrue(coverage["decreased"])
        self.assertEqual([item["operation"] for item in coverage["conclusive_lost"]], [OTHER])
        self.assertEqual(comparison["issues"], [])
        self.assertIn({"kind": "coverage_decreased", "blocking": False}, comparison["comparability"]["changes"])

    def test_unconfigured_operation_uses_the_default_fingerprint(self):
        self.assertEqual(context()["operations"], {})
        self.assertEqual(set(context()["unconfigured_operation"]), {"policy", "resources"})
        # Adding a policy to a previously unconfigured operation is a policy change for that operation.
        comparison = compare_reports(report([bola("CONFIRMED")], context=context()),
                                     report([bola("SECURE")], context=context(bola_config={OP: {"x": 1}})))
        self.assertEqual(comparison["issues"][0]["reasons"], ["policy_changed"])


class PrivacyAndDeterminismTests(unittest.TestCase):
    MARKERS = ("CANARY-BODY-VALUE", "CANARY-REASON-VALUE", "canary-host.internal", "CANARY-HEADER-VALUE",
               "CANARY-PATH-VALUE")

    def reports(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        def leaky(verdict: str) -> Dict[str, Any]:
            record = bola(verdict, path="/api/items/CANARY-PATH-VALUE")
            record["reason"] = "CANARY-REASON-VALUE"
            record["evidence"]["owner"] = {"status": 200, "body": '{"ssn": "CANARY-BODY-VALUE"}',
                                           "headers": {"Authorization": "CANARY-HEADER-VALUE"}}
            return record
        return (report([leaky("CONFIRMED"), bola("SECURE", OTHER)], target="http://canary-host.internal:1"),
                report([leaky("CONFIRMED"), bola("CONFIRMED", OTHER)], target="http://canary-host.internal:2"))

    def test_comparison_output_contains_no_report_evidence_or_free_text(self):
        comparison = compare_reports(*self.reports())
        text = json.dumps(comparison)
        for marker in self.MARKERS:
            self.assertNotIn(marker, text)

    def test_context_never_contains_credentials(self):
        marker = "Bearer CONTEXT-CANARY-7"
        built = build_comparison_context(
            key=KEY, target="https://context-target-canary.internal:8443/base",
            identities={"owner": {"id": "1", "token": marker, "headers": {"X-Api-Key": "CONTEXT-KEY-8"},
                                  "parameters": {"session": marker}},
                        "visitor": {"id": "2", "token": "Bearer B"}, "anonymous": {}},
            bola_config={OP: {"body": {"auth": marker}}},
            secret_values=(marker, "CONTEXT-KEY-8", "Bearer B"))
        text = json.dumps(built)
        for value in (marker, "CONTEXT-CANARY-7", "CONTEXT-KEY-8", KEY, "context-target-canary", "8443"):
            self.assertNotIn(value, text)
        self.assertRegex(built["identities"]["owner"], r"^[0-9a-f]{16}$")
        self.assertRegex(built["target"], r"^[0-9a-f]{16}$")

    def test_result_order_does_not_change_the_output(self):
        baseline, current = self.reports()
        shuffled = copy.deepcopy(current)
        random.Random(7).shuffle(shuffled["results"])
        self.assertEqual(json.dumps(compare_reports(baseline, current), sort_keys=True),
                         json.dumps(compare_reports(baseline, shuffled), sort_keys=True))


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-diff-")
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

    def test_diff_writes_json_and_a_readable_summary_offline(self):
        old = self.write("old.json", report([bola("CONFIRMED"), bola("SECURE", OTHER)]))
        new = self.write("new.json", report([bola("SECURE"), bola("CONFIRMED", OTHER)]))
        output = self.folder / "nested" / "diff.json"
        code, stdout, stderr = self.call(["diff", str(old), str(new), "--export-json", str(output)])
        self.assertEqual(code, 0, stderr)
        self.assertIn("Confirmed findings: 1 new, 0 persisting, 1 resolved, 0 not comparable", stdout)
        self.assertIn("RESOLVED", stdout)
        written = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(written["comparison_schema_version"], 1)
        self.assertEqual(written["summary"]["new"], 1)

    def test_findings_do_not_change_the_exit_code(self):
        old = self.write("old.json", report([bola("SECURE")]))
        new = self.write("new.json", report([bola("CONFIRMED")]))
        self.assertEqual(self.call(["diff", str(old), str(new)])[0], 0)
        moved = self.write("moved.json", report([bola("CONFIRMED")], target="http://127.0.0.1:9999"))
        code, stdout, _ = self.call(["diff", str(old), str(moved)])
        self.assertEqual(code, 0)
        self.assertIn("NOT comparable for any finding (target_changed)", stdout)
        code, stdout, _ = self.call(["diff", str(old), str(moved), "--assume-same-target"])
        self.assertEqual(code, 0)
        self.assertIn("same target assumed by --assume-same-target", stdout)
        self.assertIn("1 new", stdout)

    def test_invalid_inputs_exit_two_without_echoing_contents(self):
        valid = self.write("valid.json", report([]))
        cases = {
            "missing": str(self.folder / "missing.json"),
            "not json": str(self.write("bad.json", "{not json CANARY-INPUT")),
            "nan": str(self.write("nan.json", '{"report_schema_version": 2, "x": NaN}')),
            "dry run": str(self.write("plan.json", {"mode": "DRY_RUN", "operations": []})),
            "sarif": str(self.write("out.sarif", {"version": "2.1.0", "runs": []})),
            "schema": str(self.write("v3.json", dict(report([]), report_schema_version=3))),
            "bool schema": str(self.write("bool.json", dict(report([]), report_schema_version=True))),
            "list root": str(self.write("list.json", [])),
        }
        for name, path in cases.items():
            with self.subTest(name):
                code, stdout, stderr = self.call(["diff", path, str(valid)])
                self.assertEqual(code, 2)
                self.assertIn("[ERROR] baseline report:", stderr)
                self.assertNotIn("CANARY-INPUT", stdout + stderr)
        binary = self.folder / "binary.json"
        binary.write_bytes(b"\xff\xfe{")
        self.assertIn("not valid UTF-8", self.call(["diff", str(valid), str(binary)])[2])
        with patch("core.report_diff.MAX_REPORT_BYTES", 10):
            self.assertIn("larger than", self.call(["diff", str(valid), str(valid)])[2])

    def test_output_cannot_overwrite_an_input(self):
        old = self.write("old.json", report([]))
        new = self.write("new.json", report([]))
        before = old.read_bytes()
        code, _, stderr = self.call(["diff", str(old), str(new), "--export-json", str(old)])
        self.assertEqual(code, 2)
        self.assertIn("must not overwrite an input report", stderr)
        self.assertEqual(old.read_bytes(), before)

    def test_unreadable_result_records_are_ignored_and_noted(self):
        old = self.write("old.json", report([bola("CONFIRMED"), "junk", {"check": "bad check", "endpoint": OP}]))
        new = self.write("new.json", report([bola("CONFIRMED"), {"check": "BOLA", "endpoint": "not an op"}]))
        code, stdout, _ = self.call(["diff", str(old), str(new)])
        self.assertEqual(code, 0)
        self.assertIn("could not be read", stdout)

    def test_validate_report_accepts_a_real_v271_report(self):
        validate_report(json.loads((ROOT / "examples" / "sample_result.json").read_text(encoding="utf-8")))
        with self.assertRaises(ReportError):
            validate_report({"report_schema_version": 2, "results": []})

    def test_help_lists_the_diff_command(self):
        text = api_sentinel.build_argument_parser().format_help()
        self.assertIn("granttrace diff BASELINE.json CURRENT.json", text)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as exited:
            api_sentinel.main(["diff", "--help"])
        self.assertEqual(exited.exception.code, 0)
        self.assertIn("never count", stdout.getvalue())


class _OrdersApi(BaseHTTPRequestHandler):
    """Two users, two orders; `vulnerable` toggles the owner check on GET /orders/{id}."""

    vulnerable = True
    tokens = {"Bearer owner-test": 1, "Bearer visitor-test": 2}
    orders = {11: {"id": 11, "owner_id": 1, "total": 99.5, "address": "1 Owner Street"},
              22: {"id": 22, "owner_id": 2, "total": 5.0, "address": "2 Visitor Avenue"}}

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
        user = self.tokens.get(self.headers.get("Authorization"))
        if user is None:
            return self.reply(401, {"error": "authentication required"})
        order = self.orders.get(int(self.path.rstrip("/").split("/")[-1]))
        if order is None:
            return self.reply(404, {"error": "not found"})
        if not type(self).vulnerable and order["owner_id"] != user:
            return self.reply(403, {"error": "forbidden"})
        return self.reply(200, order)


class EndToEndTests(unittest.TestCase):
    """Real scans and the built-in demo, compared with `granttrace diff`."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-diff-e2e-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.spec = self.folder / "spec.json"
        self.spec.write_text(json.dumps({
            "openapi": "3.0.3", "info": {"title": "orders", "version": "1"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearer": []}],
            "paths": {"/orders/{orderId}": {"get": {
                "operationId": "getOrder",
                "parameters": [{"name": "orderId", "in": "path", "required": True, "schema": {"type": "integer"}}],
                "responses": {"200": {"description": "ok"}, "401": {"description": "no"},
                              "403": {"description": "no"}, "404": {"description": "no"}}}}},
        }), encoding="utf-8")
        self.config = self.folder / "config.json"
        self.config.write_text(json.dumps({
            "identities": {"owner": {"id": "1", "token": "Bearer owner-test"},
                           "visitor": {"id": "2", "token": "Bearer visitor-test"}, "anonymous": {}},
            "parameter_values": {"GET /orders/{orderId}": {"owner": {"orderId": 11}, "visitor": {"orderId": 22}}},
        }), encoding="utf-8")

    def scan(self, name: str, vulnerable: bool, port: int = 0) -> Tuple[Path, int]:
        _OrdersApi.vulnerable = vulnerable
        server = ThreadingHTTPServer(("127.0.0.1", port), _OrdersApi)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        exported = self.folder / f"{name}.json"
        try:
            with patch.dict(os.environ, {"GRANTTRACE_COMPARISON_KEY": KEY}), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = api_sentinel.main(["--spec", str(self.spec), "--config", str(self.config), "--target",
                                          f"http://127.0.0.1:{server.server_port}", "--delay", "0",
                                          "-o", str(self.folder / f"{name}.html"), "--export-json", str(exported)])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(code, 0)
        return exported, server.server_port

    def diff(self, old: Path, new: Path, *options: str) -> Dict[str, Any]:
        output = self.folder / "comparison.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(api_sentinel.main(["diff", str(old), str(new), *options,
                                                "--export-json", str(output)]), 0)
        return json.loads(output.read_text(encoding="utf-8"))

    def test_real_scans_classify_new_persisting_and_resolved(self):
        vulnerable, port = self.scan("one", True)
        fixed, _ = self.scan("two", False, port)
        again, _ = self.scan("three", True, port)
        context_text = json.dumps(json.loads(vulnerable.read_text(encoding="utf-8"))["comparison_context"])
        for value in ("owner-test", "visitor-test", KEY, str(port)):
            self.assertNotIn(value, context_text)
        cases = ((vulnerable, fixed, "resolved"), (fixed, again, "new"), (vulnerable, again, "persisting"))
        for old, new, status in cases:
            with self.subTest(status):
                comparison = self.diff(old, new)
                self.assertEqual(comparison["comparability"]["basis"], "declared")
                self.assertTrue(comparison["comparability"]["fully_comparable"])
                bola_issues = [issue for issue in comparison["issues"] if issue["check"] == "BOLA"]
                self.assertEqual([issue["status"] for issue in bola_issues], [status])
                self.assertEqual(bola_issues[0]["finding_id"], finding_id("BOLA", "GET /orders/{orderId}"))

    def test_demo_runs_and_a_v271_report_need_an_explicit_same_target_assumption(self):
        runs = []
        for name in ("first", "second"):
            with patch.dict(os.environ, {"GRANTTRACE_COMPARISON_KEY": KEY}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(demo.run_demo(output_dir=str(self.folder / name)), 0)
            runs.append(next((self.folder / name).rglob("granttrace_report.json")))
        # Each demo run listens on a new ephemeral port, so the targets differ.
        plain = self.diff(runs[0], runs[1])
        self.assertEqual(plain["comparability"]["blocking"], ["target_changed"])
        self.assertEqual(plain["summary"]["persisting"], 0)
        comparison = self.diff(runs[0], runs[1], "--assume-same-target")
        self.assertEqual(comparison["summary"]["persisting"], 2)
        self.assertEqual(comparison["comparability"]["basis"], "declared")
        self.assertEqual(comparison["comparability"]["assumptions"], ["same_target"])
        self.assertFalse(comparison["comparability"]["fully_comparable"])
        legacy = self.diff(ROOT / "examples" / "sample_result.json", runs[1], "--assume-same-target")
        self.assertEqual(legacy["comparability"]["basis"], "evidence")
        self.assertEqual(legacy["summary"]["persisting"], 2)
        self.assertEqual({issue["finding_id"] for issue in legacy["issues"]},
                         {issue["finding_id"] for issue in comparison["issues"]})


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


class ReviewRegressionTests(unittest.TestCase):
    """Counterexamples from the review of the first version of `granttrace diff`."""

    KEY = "review-comparison-key-0123456789"
    BOPLA_OP = "GET /documents/{id}"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-diff-review-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    # --- helpers -----------------------------------------------------------

    def serve(self, handler: type, port: int = 0) -> ThreadingHTTPServer:
        server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def run_cli(self, arguments: Sequence[str], key: Optional[str] = None) -> Tuple[int, str, str]:
        environment = {"GRANTTRACE_COMPARISON_KEY": key} if key is not None else {}
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, environment), contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            if key is None:
                os.environ.pop("GRANTTRACE_COMPARISON_KEY", None)
            code = api_sentinel.main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def bopla_scan(self, name: str, leaking: bool, port: int = 0, key: Optional[str] = None) -> Tuple[Path, int]:
        spec, config = self.folder / "documents.json", self.folder / "documents-config.json"
        spec.write_text(json.dumps({
            "openapi": "3.0.3", "info": {"title": "documents", "version": "1"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "paths": {"/documents/{id}": {"get": {
                "security": [{"bearer": []}],
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "document"}}}}}}), encoding="utf-8")
        config.write_text(json.dumps({
            "identities": {"owner": {"id": "1001", "token": "Bearer ALICE_OWNER_TOKEN", "parameters": {"id": "1001"}},
                           "visitor": {"id": "1002", "token": "Bearer BOB_VISITOR_TOKEN",
                                       "parameters": {"id": "1002"}},
                           "anonymous": {"id": None, "token": None, "parameters": {}}},
            "bola": {self.BOPLA_OP: {"expected_visitor_access": "allow"}},
            "bopla": {self.BOPLA_OP: {
                "policy_id": "document-fields-v1", "context_id": "selected-owner-document",
                "resource_binding": {"id": "1001"},
                "fields": [{"rule_id": "owner-note", "path": "private_note",
                            "baseline_representation": "full_private_value", "value_is_resource_specific": True,
                            "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"}}]}},
        }), encoding="utf-8")
        _DocumentsApi.leaking = leaking
        server = self.serve(_DocumentsApi, port)
        exported = self.folder / f"{name}.json"
        code, stdout, stderr = self.run_cli(
            ["--spec", str(spec), "--config", str(config), "--target", f"http://127.0.0.1:{server.server_port}",
             "--delay", "0", "-o", str(self.folder / f"{name}.html"), "--export-json", str(exported)], key)
        server.shutdown()
        server.server_close()
        self.assertEqual(code, 0, stdout + stderr)
        return exported, server.server_port

    def diff(self, old: Path, new: Path, *options: str) -> Dict[str, Any]:
        output = self.folder / "comparison.json"
        code, stdout, stderr = self.run_cli(["diff", str(old), str(new), *options, "--export-json", str(output)])
        self.assertEqual(code, 0, stdout + stderr)
        return json.loads(output.read_text(encoding="utf-8"))

    def bopla_visitor_issue(self, comparison: Dict[str, Any]) -> Dict[str, Any]:
        issues = [issue for issue in comparison["issues"]
                  if issue["check"] == "BOPLA" and issue.get("subject") == "field:owner-note|identity:visitor"]
        self.assertEqual(len(issues), 1, comparison["issues"])
        return issues[0]

    # --- P0: an unidentifiable target never yields a scope-dependent conclusion

    def test_omitted_targets_are_not_comparable(self):
        omitted = "[BOPLA TARGET OMITTED]"
        def bopla(verdict: str) -> Dict[str, Any]:
            return result("BOPLA", self.BOPLA_OP, verdict,
                          decision_evidence={"rule_id": "owner-note", "subject_identity": "visitor"})
        for before, after in (("CONFIRMED", "SECURE"), ("CONFIRMED", "CONFIRMED"), ("SECURE", "CONFIRMED")):
            with self.subTest(before=before, after=after):
                comparison = compare_reports(report([bopla(before)], target=omitted),
                                             report([bopla(after)], target=omitted))
                issue = comparison["issues"][0]
                self.assertEqual(issue["status"], "not_comparable")
                self.assertIn("target_unknown", issue["reasons"])
                self.assertFalse(comparison["comparability"]["fully_comparable"])
        # Identical resource paths in the evidence do not make an unreadable target comparable.
        for target in (omitted, "", "not-a-url", "http://"):
            with self.subTest(target=target):
                comparison = compare_reports(report([bola("CONFIRMED")], target=target),
                                             report([bola("SECURE")], target=target))
                self.assertEqual(comparison["issues"][0]["status"], "not_comparable")
                self.assertIn("target_unknown", comparison["issues"][0]["reasons"])

    def test_real_bopla_scans_of_different_targets_are_never_resolved(self):
        leaking, leaking_port = self.bopla_scan("leaking", True)
        fixed, fixed_port = self.bopla_scan("fixed", False)
        self.assertNotEqual(leaking_port, fixed_port)
        for path in (leaking, fixed):
            text = path.read_text(encoding="utf-8")
            self.assertIn("[BOPLA TARGET OMITTED]", text)
            self.assertNotIn("127.0.0.1", text)
        issue = self.bopla_visitor_issue(self.diff(leaking, fixed))
        self.assertEqual((issue["status"], issue["baseline_verdicts"], issue["current_verdicts"]),
                         ("not_comparable", ["CONFIRMED"], ["SECURE"]))
        self.assertIn("target_unknown", issue["reasons"])

    def test_keyed_bopla_scans_compare_targets_without_writing_them(self):
        leaking, port = self.bopla_scan("leaking", True, key=self.KEY)
        elsewhere, other_port = self.bopla_scan("elsewhere", False, key=self.KEY)
        same, same_port = self.bopla_scan("same", False, port=port, key=self.KEY)
        self.assertEqual(same_port, port)
        for path in (leaking, elsewhere, same):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("127.0.0.1", text)
            self.assertNotIn(self.KEY, text)
        moved = self.bopla_visitor_issue(self.diff(leaking, elsewhere))
        self.assertEqual(moved["status"], "not_comparable")
        self.assertIn("target_changed", moved["reasons"])
        fixed = self.diff(leaking, same)
        self.assertEqual(fixed["comparability"]["basis"], "declared")
        self.assertEqual(self.bopla_visitor_issue(fixed)["status"], "resolved")

    # --- P0: the port is part of the target

    def test_same_host_on_another_port_is_another_target(self):
        vulnerable = report([bola("CONFIRMED")], target="http://127.0.0.1:8001")
        secure = report([bola("SECURE")], target="http://127.0.0.1:8002")
        comparison = compare_reports(vulnerable, secure)
        self.assertEqual(comparison["issues"][0]["status"], "not_comparable")
        self.assertIn("target_changed", comparison["issues"][0]["reasons"])
        for implicit, explicit in (("http://api.example", "http://api.example:80"),
                                   ("https://api.example/", "https://api.example:443")):
            with self.subTest(implicit=implicit):
                same = compare_reports(report([bola("CONFIRMED")], target=implicit),
                                       report([bola("SECURE")], target=explicit))
                self.assertEqual(same["issues"][0]["status"], "resolved")

    def orders_scan(self, name: str, vulnerable: bool, port: int = 0, key: Optional[str] = None) -> Path:
        spec, config = self.folder / "orders.json", self.folder / "orders-config.json"
        spec.write_text(json.dumps({
            "openapi": "3.0.3", "info": {"title": "orders", "version": "1"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearer": []}],
            "paths": {"/orders/{orderId}": {"get": {
                "parameters": [{"name": "orderId", "in": "path", "required": True, "schema": {"type": "integer"}}],
                "responses": {"200": {"description": "ok"}}}}}}), encoding="utf-8")
        config.write_text(json.dumps({
            "identities": {"owner": {"id": "1", "token": "Bearer owner-test"},
                           "visitor": {"id": "2", "token": "Bearer visitor-test"}, "anonymous": {}},
            "parameter_values": {"GET /orders/{orderId}": {"owner": {"orderId": 11}, "visitor": {"orderId": 22}}},
        }), encoding="utf-8")
        _OrdersApi.vulnerable = vulnerable
        server = self.serve(_OrdersApi, port)
        exported = self.folder / f"{name}.json"
        code, stdout, stderr = self.run_cli(
            ["--spec", str(spec), "--config", str(config), "--target", f"http://127.0.0.1:{server.server_port}",
             "--delay", "0", "-o", str(self.folder / f"{name}.html"), "--export-json", str(exported)], key)
        server.shutdown()
        server.server_close()
        self.assertEqual(code, 0, stdout + stderr)
        return exported

    def test_real_scans_of_two_services_on_one_host_are_never_resolved(self):
        # Two services on one host: the vulnerable one and a fixed one on another port.
        vulnerable = self.orders_scan("vulnerable-service", True)
        fixed = self.orders_scan("fixed-service", False)
        comparison = self.diff(vulnerable, fixed)
        issue = [item for item in comparison["issues"] if item["check"] == "BOLA"][0]
        self.assertEqual(issue["status"], "not_comparable")
        self.assertIn("target_changed", issue["reasons"])
        acknowledged = self.diff(vulnerable, fixed, "--assume-same-target")
        self.assertEqual([item["status"] for item in acknowledged["issues"] if item["check"] == "BOLA"],
                         ["resolved"])
        self.assertEqual(acknowledged["comparability"]["assumptions"], ["same_target"])
        self.assertFalse(acknowledged["comparability"]["fully_comparable"])

    # --- P0: first detection of an operation is not a proven regression

    def test_finding_on_an_operation_absent_from_the_baseline_is_not_new(self):
        comparison = compare_reports(report([bola("SECURE", OTHER)]),
                                     report([bola("SECURE", OTHER), bola("CONFIRMED")]))
        issue = comparison["issues"][0]
        self.assertEqual((issue["status"], issue["reasons"]), ("not_comparable", ["operation_not_in_baseline"]))
        self.assertEqual(comparison["summary"]["new"], 0)
        self.assertEqual(comparison["summary"]["current_confirmed_not_comparable"], 1)

    # --- P1: no enumerable fingerprints by default; keyed fingerprints otherwise

    def test_reports_carry_no_fingerprints_without_a_comparison_key(self):
        exported, _ = self.bopla_scan("plain", True)
        self.assertNotIn("comparison_context", json.loads(exported.read_text(encoding="utf-8")))

    def test_keyed_fingerprints_are_not_plain_hashes_and_depend_on_the_key(self):
        exported, _ = self.bopla_scan("keyed", True, key=self.KEY)
        other, _ = self.bopla_scan("other-key", True, key="another-comparison-key-987654")
        first = json.loads(exported.read_text(encoding="utf-8"))["comparison_context"]
        second = json.loads(other.read_text(encoding="utf-8"))["comparison_context"]
        self.assertEqual(first["algorithm"], "hmac-sha256")
        self.assertNotEqual(first["key_id"], second["key_id"])
        self.assertNotEqual(first["identities"]["owner"], second["identities"]["owner"])
        material = json.dumps({"id": "1001", "parameters": {"id": "1001"}, "role": None},
                              sort_keys=True, separators=(",", ":"))
        unkeyed = hashlib.sha256(f"granttrace/identity/v1\0{material}".encode()).hexdigest()[:16]
        self.assertNotEqual(first["identities"]["owner"], unkeyed)
        comparison = self.diff(exported, other)
        self.assertEqual(comparison["comparability"]["basis"], "evidence")
        self.assertIn("comparison_keys_differ", comparison["comparability"]["notes"])

    def test_short_comparison_key_is_rejected_before_any_request(self):
        failure = AssertionError("network opened")
        with patch("socket.socket", side_effect=failure), patch("socket.create_connection", side_effect=failure):
            code, stdout, stderr = self.run_cli(
                ["--spec", str(ROOT / "openapi.json"), "--config", str(ROOT / "config.example.json"),
                 "--target", "http://127.0.0.1:9", "-o", str(self.folder / "r.html")], key="short-key")
        self.assertEqual(code, 2)
        self.assertIn("GRANTTRACE_COMPARISON_KEY", stderr)
        self.assertNotIn("short-key", stdout + stderr)
        self.assertFalse((self.folder / "r.html").exists())

    # --- fully_comparable must not hide operation-level changes

    def test_operation_level_policy_change_is_not_fully_comparable(self):
        before = build_comparison_context(key=self.KEY, target="http://127.0.0.1:8000",
                                          identities={"owner": {"id": "1"}, "visitor": {"id": "2"}},
                                          bola_config={OP: {"resource_id_paths": ["id"]}})
        after = build_comparison_context(key=self.KEY, target="http://127.0.0.1:8000",
                                         identities={"owner": {"id": "1"}, "visitor": {"id": "2"}},
                                         bola_config={OP: {"resource_id_paths": ["id"], "not_found_is_denial": True}})
        comparison = compare_reports(report([bola("CONFIRMED"), bola("CONFIRMED", OTHER)], context=before),
                                     report([bola("SECURE"), bola("SECURE", OTHER)], context=after))
        self.assertFalse(comparison["comparability"]["fully_comparable"])
        self.assertEqual(comparison["comparability"]["operation_changes"],
                         [{"operation": OP, "reasons": ["policy_changed"]}])
        self.assertEqual(by_id(comparison)[("BOLA", OTHER, None)]["status"], "resolved")


if __name__ == "__main__":
    unittest.main()
