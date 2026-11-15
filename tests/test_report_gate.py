"""The optional CI security gate of `granttrace diff` (--fail-on-*).

The suite is organised around one invariant: the gate only passes (exit 0) when
every enabled condition is shown to hold. A result that is not comparable, lacks
evidence or rests on an assumption the caller did not allow in the gate never
counts as a pass, and a verified regression is never reported as merely
unverified.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import re
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from unittest.mock import patch

import api_sentinel
import test_report_diff as diff_tests
from core import report_gate
from core.report_diff import compare_reports, finding_id, result_states, summary_lines
from core.report_gate import CONDITIONS, evaluate_gate
from test_report_diff import (
    KEY, NEGATIVE, OP, OTHER, OTHER_KEY, THIRD, UNKEYED, UNVERIFIED, bola, endpoint, keyed, report, result,
)

ROOT = Path(__file__).resolve().parents[1]
ALL = CONDITIONS


def gate(baseline: Dict[str, Any], current: Dict[str, Any], *conditions: str, allow: bool = False,
         **assumptions: bool) -> Dict[str, Any]:
    comparison = compare_reports(baseline, current, **assumptions)
    return evaluate_gate(comparison, result_states(baseline), result_states(current),
                         conditions=conditions or ALL, allow_assumptions=allow)


def part(result: Dict[str, Any], condition: str) -> Dict[str, Any]:
    return next(item for item in result["conditions"] if item["condition"] == condition)


def reasons(result: Dict[str, Any], condition: str, kind: str) -> List[str]:
    return [item["reason"] for item in part(result, condition)[kind]]


def outcome(result: Dict[str, Any]) -> Dict[str, str]:
    return {item["condition"]: item["result"] for item in result["conditions"]}


def anchor(verdict: str = "SECURE") -> Dict[str, Any]:
    """A conclusive result on another operation, so that the current report is not empty of conclusions."""
    return result("BROKEN_AUTH", THIRD, verdict)


class ConditionTests(unittest.TestCase):
    def test_a_new_confirmed_finding_fails_with_exit_1(self):
        decided = gate(keyed([bola("SECURE")]), keyed([bola("CONFIRMED")]))
        self.assertEqual((decided["result"], decided["exit_code"], decided["verified"]), ("failed", 1, True))
        self.assertEqual(outcome(decided), {"new": "failed", "coverage_decrease": "passed",
                                            "not_comparable": "passed"})
        regression = part(decided, "new")["regressions"][0]
        self.assertEqual((regression["reason"], regression["finding_id"], regression["baseline_verdicts"],
                          regression["current_verdicts"]),
                         ("new_finding", finding_id("BOLA", OP), ["SECURE"], ["CONFIRMED"]))

    def test_persisting_and_resolved_findings_pass_every_condition(self):
        for before, after in (("CONFIRMED", "CONFIRMED"), ("CONFIRMED", "SECURE"), ("SECURE", "SECURE"),
                              ("PUBLIC", "SECURE"), ("CONFIRMED", "AUTHORIZED")):
            with self.subTest(before=before, after=after):
                decided = gate(keyed([bola(before)]), keyed([bola(after)]))
                self.assertEqual((decided["result"], decided["exit_code"], decided["verified"]), ("passed", 0, True))
                self.assertEqual(decided["prerequisites"], [])

    def test_a_confirmed_finding_without_comparable_baseline_evidence_is_not_verified(self):
        cases = {
            # First detection on an operation, check or subject the baseline did not cover.
            "operation_not_in_baseline": (keyed([anchor()]), keyed([anchor(), bola("CONFIRMED")])),
            "not_checked_in_baseline": (keyed([result("BFLA", OP, "SECURE"), anchor()]),
                                        keyed([result("BFLA", OP, "SECURE"), bola("CONFIRMED"), anchor()])),
            "baseline_unverified": (keyed([bola("INCONCLUSIVE"), anchor()]), keyed([bola("CONFIRMED"), anchor()])),
            # A confirmed verdict that no request supports, on either side.
            "current_unverified": (keyed([bola("SECURE"), anchor()]),
                                   keyed([result("BOLA", OP, "CONFIRMED", requests_attempted=0), anchor()])),
            "spec_changed": (keyed([bola("SECURE"), anchor()]),
                             keyed([bola("CONFIRMED"), anchor()],
                                   endpoints=[endpoint(OP, summary="edited"), endpoint(OTHER), endpoint(THIRD)])),
            "resources_changed": (keyed([bola("SECURE"), anchor()]),
                                  keyed([bola("CONFIRMED", path="/api/items/9"), anchor()])),
        }
        for reason, (baseline, current) in cases.items():
            with self.subTest(reason=reason):
                decided = gate(baseline, current, "new")
                self.assertEqual((decided["result"], decided["exit_code"]), ("unverified", 3))
                item = part(decided, "new")["unverified"][0]
                self.assertEqual(item["reason"], "confirmed_not_comparable")
                self.assertIn(reason, item["comparison_reasons"])
                self.assertEqual(part(decided, "new")["regressions"], [])

    def test_a_check_verified_safe_that_is_no_longer_conclusive_is_not_verified(self):
        baseline = keyed([bola("SECURE"), result("BOLA", OTHER, "SECURE"), anchor()])
        for verdict in UNVERIFIED:
            with self.subTest(verdict=verdict):
                current = keyed([bola(verdict), result("BOLA", OTHER, "SECURE"), anchor()])
                decided = gate(baseline, current)
                self.assertEqual(reasons(decided, "new", "unverified"), ["no_longer_verified"])
                # The same evidence is a verified coverage regression, which decides the exit code.
                self.assertEqual(reasons(decided, "coverage_decrease", "regressions"), ["conclusive_check_lost"])
                self.assertEqual((decided["result"], decided["exit_code"]), ("failed", 1))
                only_new = gate(baseline, current, "new")
                self.assertEqual((only_new["result"], only_new["exit_code"]), ("unverified", 3))
        # A conclusive verdict without a request, a missing check and a removed operation prove nothing either.
        for name, current in (
                ("no request", keyed([result("BOLA", OP, "SECURE", requests_attempted=0),
                                      result("BOLA", OTHER, "SECURE"), anchor()])),
                ("missing check", keyed([result("BFLA", OP, "SECURE"), result("BOLA", OTHER, "SECURE"), anchor()])),
                ("removed operation", keyed([result("BOLA", OTHER, "SECURE"), anchor()]))):
            with self.subTest(case=name):
                decided = gate(baseline, current, "new")
                self.assertEqual(reasons(decided, "new", "unverified"), ["no_longer_verified"])
                self.assertEqual(decided["exit_code"], 3)

    def test_access_accepted_after_its_declaration_changed_is_not_verified(self):
        # The change under test also changed what the check is judged by: the specification no longer
        # requires authentication, or the policy now allows the Visitor.
        spec = [endpoint(OP, security=[]), endpoint(OTHER), endpoint(THIRD)]
        baseline = keyed([result("BROKEN_AUTH", OP, "SECURE"), anchor()])
        for verdict in ("PUBLIC", "AUTHORIZED"):
            with self.subTest(verdict=verdict):
                current = keyed([result("BROKEN_AUTH", OP, verdict), anchor()], endpoints=spec)
                decided = gate(baseline, current, "new")
                self.assertEqual(reasons(decided, "new", "unverified"), ["accepted_after_declaration_change"])
                self.assertEqual(decided["exit_code"], 3)
                # Without a declaration change the same verdict is the scanner's verified conclusion.
                unchanged = gate(baseline, keyed([result("BROKEN_AUTH", OP, verdict), anchor()]), "new")
                self.assertEqual((unchanged["result"], unchanged["exit_code"]), ("passed", 0))
        # A change in the evidence of what was expected is a policy change as well.
        policy = gate(keyed([result("BOLA", OP, "SECURE", decision_evidence={"expected_visitor_access": "deny"}),
                             anchor()]),
                      keyed([result("BOLA", OP, "AUTHORIZED", decision_evidence={"expected_visitor_access": "allow"}),
                             anchor()]), "new")
        self.assertEqual(reasons(policy, "new", "unverified"), ["accepted_after_declaration_change"])
        # An unchanged acceptance, or a denial after a declaration change, is not a weakening.
        for before, after in (("PUBLIC", "PUBLIC"), ("AUTHORIZED", "SECURE"), ("SECURE", "SECURE")):
            with self.subTest(before=before, after=after):
                decided = gate(keyed([result("BROKEN_AUTH", OP, before), anchor()]),
                               keyed([result("BROKEN_AUTH", OP, after), anchor()], endpoints=spec), "new")
                self.assertEqual(decided["exit_code"], 0)

    def test_without_fingerprints_the_evidence_decides_whether_a_declaration_changed(self):
        # Reports compared on stated assumptions: only the evidence can show what changed, and evidence
        # without request URLs cannot show that nothing did.
        def check(verdict: str, path: Optional[str]) -> Dict[str, Any]:
            evidence = {"target_url": "http://127.0.0.1:8000" + path} if path else {}
            return result("BROKEN_AUTH", OP, verdict, **evidence)
        cases = {"no request URLs": (None, None, 3), "same request": ("/api/items/1", "/api/items/1", 0),
                 "other request": ("/api/items/1", "/api/items/2", 3)}
        for name, (before, after, expected) in cases.items():
            with self.subTest(case=name):
                decided = gate(report([check("SECURE", before), anchor()]), report([check("PUBLIC", after), anchor()]),
                               "new", allow=True, **UNKEYED)
                self.assertEqual(decided["exit_code"], expected)
                if expected:
                    self.assertEqual(reasons(decided, "new", "unverified"), ["accepted_after_declaration_change"])

    def test_items_name_the_subject_of_a_check(self):
        role = "role:auditor"
        decided = gate(keyed([result("RBAC", OP, "SECURE", rbac_role="auditor"), anchor()]),
                       keyed([result("RBAC", OP, "ERROR", rbac_role="auditor"), anchor()]), "new")
        item = part(decided, "new")["unverified"][0]
        self.assertEqual((item["reason"], item["subject"], item["finding_id"]),
                         ("no_longer_verified", role, finding_id("RBAC", OP, role)))

    def test_coverage_decrease_fails_with_exit_1(self):
        stats = {"conclusive_coverage_pct": 80.0}
        decided = gate(keyed([bola("SECURE")], stats=stats),
                       keyed([bola("SECURE")], stats={"conclusive_coverage_pct": 60.0}), "coverage_decrease")
        self.assertEqual((decided["result"], decided["exit_code"]), ("failed", 1))
        self.assertEqual(part(decided, "coverage_decrease")["regressions"],
                         [{"reason": "coverage_pct_decreased", "baseline_pct": 80.0, "current_pct": 60.0}])
        gained = gate(keyed([bola("INCONCLUSIVE"), anchor()], stats={"conclusive_coverage_pct": 50.0}),
                      keyed([bola("SECURE"), anchor()], stats={"conclusive_coverage_pct": 100.0}), "coverage_decrease")
        self.assertEqual((gained["result"], gained["exit_code"]), ("passed", 0))

    def test_a_finding_that_is_not_comparable_is_reported_with_exit_3(self):
        baseline = keyed([bola("CONFIRMED"), anchor()])
        current = keyed([bola("INCONCLUSIVE"), anchor()])
        decided = gate(baseline, current)
        self.assertEqual(outcome(decided), {"new": "passed", "coverage_decrease": "failed",
                                            "not_comparable": "unverified"})
        self.assertEqual(part(decided, "not_comparable")["unverified"][0]["comparison_reasons"],
                         ["current_unverified"])
        # A finding the current scan could not check again is not new; it is a coverage regression and not
        # comparable, which the other conditions catch.
        self.assertEqual(gate(baseline, current, "new")["exit_code"], 0)
        self.assertEqual(gate(baseline, current, "not_comparable")["exit_code"], 3)
        self.assertEqual(gate(baseline, current, "coverage_decrease")["exit_code"], 1)

    def test_a_verified_regression_outranks_what_could_not_be_verified(self):
        baseline = keyed([bola("SECURE"), result("BOLA", OTHER, "CONFIRMED"), anchor()])
        current = keyed([bola("CONFIRMED"), result("BOLA", OTHER, "ERROR"), anchor()])
        decided = gate(baseline, current, "new", "not_comparable")
        self.assertEqual(outcome(decided), {"new": "failed", "not_comparable": "unverified"})
        self.assertEqual((decided["result"], decided["exit_code"]), ("failed", 1))

    def test_conditions_are_reported_in_a_fixed_order_and_must_be_known(self):
        decided = gate(keyed([bola("SECURE")]), keyed([bola("SECURE")]), "not_comparable", "new")
        self.assertEqual([item["condition"] for item in decided["conditions"]], ["new", "not_comparable"])
        self.assertEqual([item["flag"] for item in decided["conditions"]],
                         ["--fail-on-new", "--fail-on-not-comparable"])
        for conditions in ((), ("everything",), ("new", "vulnerable")):
            with self.subTest(conditions=conditions), self.assertRaises(ValueError):
                comparison = compare_reports(keyed([bola("SECURE")]), keyed([bola("SECURE")]))
                evaluate_gate(comparison, {}, {}, conditions=conditions)


class PrerequisiteTests(unittest.TestCase):
    """What keeps every condition from passing, whatever it would conclude on its own."""

    def assert_never_passes(self, decided: Dict[str, Any], reason: str) -> None:
        self.assertIn(reason, [item["reason"] for item in decided["prerequisites"]])
        self.assertEqual((decided["result"], decided["exit_code"], decided["verified"]), ("unverified", 3, False))
        self.assertEqual(set(outcome(decided).values()), {"unverified"})
        self.assertTrue(all(not item["regressions"] for item in decided["conditions"]))

    def test_reports_that_are_not_comparable_never_pass(self):
        cases = {
            "unkeyed": (report([bola("SECURE")]), report([bola("SECURE")])),
            "different keys": (keyed([bola("SECURE")]), keyed([bola("SECURE")], key=OTHER_KEY)),
            "target changed": (keyed([bola("SECURE")]),
                               keyed([bola("SECURE")], target="http://127.0.0.1:9000")),
            "identities changed": (keyed([bola("SECURE")]),
                                   keyed([bola("SECURE")], who=diff_tests.identities(visitor_id="3003"))),
            "credentials changed": (keyed([bola("SECURE")]),
                                    keyed([bola("SECURE")], who=diff_tests.identities(visitor_token="Bearer NEW"))),
            "no account ids": (keyed([bola("SECURE")], who=diff_tests.identities(None, None)),
                               keyed([bola("SECURE")], who=diff_tests.identities(None, None))),
            "unreadable confirmed record": (keyed([bola("SECURE")]),
                                            keyed([bola("SECURE"), {"check": "BOLA", "verdict": "CONFIRMED"}])),
        }
        for name, (baseline, current) in cases.items():
            with self.subTest(case=name):
                self.assert_never_passes(gate(baseline, current), "comparison_blocked")

    def test_a_blocked_comparison_turns_a_coverage_decrease_into_not_verified(self):
        decided = gate(report([bola("SECURE"), anchor()]), report([bola("ERROR"), anchor()]), "coverage_decrease")
        self.assert_never_passes(decided, "comparison_blocked")
        self.assertEqual(reasons(decided, "coverage_decrease", "unverified"), ["conclusive_check_lost"])

    def test_assumptions_never_pass_unless_the_gate_allows_them(self):
        baseline, current = report([bola("CONFIRMED"), anchor()]), report([bola("CONFIRMED"), anchor()])
        self.assertEqual(only_status(baseline, current), "persisting")
        refused = gate(baseline, current, **UNKEYED)
        self.assert_never_passes(refused, "assumptions_not_allowed")
        self.assertEqual(refused["prerequisites"],
                         [{"reason": "assumptions_not_allowed", "assumptions": ["same_identities",
                                                                                "same_configuration"]}])
        self.assertEqual(part(refused, "new")["unverified"][0]["comparison_reasons"], ["assumptions_not_allowed"])
        allowed = gate(baseline, current, allow=True, **UNKEYED)
        self.assertEqual((allowed["result"], allowed["exit_code"], allowed["verified"]), ("passed", 0, False))
        self.assertEqual(allowed["relies_on_assumptions"], ["same_identities", "same_configuration"])

    def test_a_regression_that_rests_on_an_assumption_is_a_regression_only_when_allowed(self):
        baseline, current = report([bola("SECURE"), anchor()]), report([bola("CONFIRMED"), anchor()])
        refused = gate(baseline, current, "new", **UNKEYED)
        self.assertEqual((refused["result"], refused["exit_code"]), ("unverified", 3))
        self.assertEqual(reasons(refused, "new", "unverified"), ["confirmed_not_comparable"])
        allowed = gate(baseline, current, "new", allow=True, **UNKEYED)
        self.assertEqual((allowed["result"], allowed["exit_code"], allowed["verified"]), ("failed", 1, False))
        self.assertEqual(part(allowed, "new")["regressions"][0]["assumptions"],
                         ["same_identities", "same_configuration"])

    def test_an_assumption_never_covers_a_detected_change(self):
        # Every assumption and the allowance together still leave a changed identity blocking.
        current = keyed([bola("SECURE")], who=diff_tests.identities(visitor_id="3003"))
        decided = gate(keyed([bola("SECURE")]), current, allow=True, assume_same_target=True,
                       assume_same_identities=True, assume_same_configuration=True)
        self.assert_never_passes(decided, "comparison_blocked")

    def test_a_current_report_without_any_conclusive_result_never_passes(self):
        cases = {
            "target unreachable": (keyed([bola("SECURE")]), keyed([bola("ERROR")])),
            "everything skipped": (keyed([bola("CONFIRMED")]), keyed([bola("SKIPPED")])),
            "no requests": (keyed([bola("SECURE")]), keyed([result("BOLA", OP, "SECURE", requests_attempted=0)])),
            "two empty reports": (keyed([]), keyed([])),
            "empty baseline and current": (keyed([bola("INCONCLUSIVE")]), keyed([bola("INCONCLUSIVE")])),
        }
        for name, (baseline, current) in cases.items():
            with self.subTest(case=name):
                self.assert_never_passes(gate(baseline, current), "no_conclusive_results")


def only_status(baseline: Dict[str, Any], current: Dict[str, Any]) -> str:
    return diff_tests.only(compare_reports(baseline, current, **UNKEYED))["status"]


class RandomizedGateTests(unittest.TestCase):
    """Seeded random report pairs, checked against the gate rules derived from the raw records."""

    SEEDS = 600
    DECLARED_ACCEPTANCE = {"PUBLIC", "AUTHORIZED"}

    @staticmethod
    def states(scenario: Dict[str, Any], side: int) -> Dict[Tuple[str, str], Tuple[Set[str], bool]]:
        """Per check and operation: the verdicts and whether they are conclusive, from the scenario itself."""
        found = {}
        for key, verdicts in scenario["verdicts"][side].items():
            values = set(verdicts)
            unobserved = key in scenario["unobserved"][side]
            found[key] = (values, bool(values) and values <= set(NEGATIVE) | {"CONFIRMED"} and not unobserved)
        return found

    def expected(self, scenario: Dict[str, Any], comparison: Dict[str, Any], conditions: Sequence[str],
                 allow: bool) -> Dict[str, Dict[str, List[Tuple[str, str]]]]:
        """Regressions and unverified items per condition, as (reason, finding id), by the documented rules."""
        before, after = self.states(scenario, 0), self.states(scenario, 1)
        comparability = comparison["comparability"]
        met = (not comparability["blocking"] and (allow or not comparability["assumptions"])
               and any(conclusive for _, conclusive in after.values()))
        changed = {item["operation"] for item in comparability["operation_changes"]}

        def status(issue: Dict[str, Any]) -> str:
            return ("not_comparable" if issue.get("assumptions") and not allow else issue["status"])

        def ident(key: Tuple[str, str]) -> str:
            return finding_id(key[0], key[1])

        expected: Dict[str, Dict[str, List[Tuple[str, str]]]] = {}
        for condition in conditions:
            regressions: List[Tuple[str, str]] = []
            unverified: List[Tuple[str, str]] = []
            if condition == "new":
                for issue in comparison["issues"]:
                    if status(issue) == "new":
                        regressions.append(("new_finding", issue["finding_id"]))
                    elif "CONFIRMED" in issue["current_verdicts"] and status(issue) != "persisting":
                        unverified.append(("confirmed_not_comparable", issue["finding_id"]))
                for key, (verdicts, conclusive) in before.items():
                    if not conclusive or "CONFIRMED" in verdicts:
                        continue
                    now, now_conclusive = after.get(key, (set(), False))
                    if not now_conclusive:
                        unverified.append(("no_longer_verified", ident(key)))
                    elif ("CONFIRMED" not in now and (key[1] in changed or key[1] in scenario["moved"])
                          and (now & self.DECLARED_ACCEPTANCE) - verdicts):
                        unverified.append(("accepted_after_declaration_change", ident(key)))
            elif condition == "coverage_decrease":
                for key, (_, conclusive) in before.items():
                    if conclusive and not after.get(key, (set(), False))[1]:
                        regressions.append(("conclusive_check_lost", ident(key)))
                old = scenario["pct"][0]
                new = scenario["pct"][1]
                if old is not None and new is not None and new < old:
                    regressions.append(("coverage_pct_decreased", ""))
            else:
                unverified += [("finding_not_comparable", issue["finding_id"]) for issue in comparison["issues"]
                               if status(issue) == "not_comparable"]
            if not met:
                unverified, regressions = regressions + unverified, []
            expected[condition] = {"regressions": sorted(regressions), "unverified": sorted(unverified)}
        return expected

    def test_random_report_pairs_follow_the_gate_rules(self):
        generator = diff_tests.RandomizedInvariantTests()
        counts: Dict[str, int] = {"passed": 0, "failed": 0, "unverified": 0}
        for seed in range(self.SEEDS):
            rng = random.Random(f"gate-{seed}")
            scenario = generator.scenario(rng)
            scenario["pct"] = [rng.choice((None, 50.0, 75.0, 100.0)) for _ in range(2)]
            if rng.random() < 0.4:
                # Comparable scans of an unchanged deployment, with a few verdicts changed.
                scenario.update(keyed=(True, True), same_key=True, same_target=True, identity_changed=False,
                                credential_changed=False, ids=True, changed={}, moved=set(),
                                unobserved=[set(), set()])
                scenario["verdicts"][1] = {key: list(verdicts) if rng.random() < 0.9
                                           else [rng.choice(generator.VERDICTS)]
                                           for key, verdicts in scenario["verdicts"][0].items()}
                scenario["pct"][1] = scenario["pct"][0]
            baseline, current = generator.build(scenario, 0), generator.build(scenario, 1)
            for side, data in enumerate((baseline, current)):
                if scenario["pct"][side] is not None:
                    data["stats"] = {"conclusive_coverage_pct": scenario["pct"][side]}
            conditions = [condition for condition in ALL if rng.random() < 0.6] or ["new"]
            allow = rng.random() < 0.5
            comparison = compare_reports(baseline, current, **scenario["flags"])
            decided = evaluate_gate(comparison, result_states(baseline), result_states(current),
                                    conditions=conditions, allow_assumptions=allow)
            with self.subTest(seed=seed):
                expected = self.expected(scenario, comparison, conditions, allow)
                actual = {item["condition"]: {kind: sorted((entry["reason"], entry.get("finding_id", ""))
                                                           for entry in item[kind])
                                              for kind in ("regressions", "unverified")}
                          for item in decided["conditions"]}
                self.assertEqual(actual, expected)
                failed = any(item["regressions"] for item in expected.values())
                unverified = any(item["unverified"] for item in expected.values())
                met = (not comparison["comparability"]["blocking"]
                       and (allow or not comparison["comparability"]["assumptions"])
                       and any(state.conclusive for state in result_states(current).values()))
                result_name = "failed" if failed else "unverified" if unverified or not met else "passed"
                self.assertEqual(decided["result"], result_name)
                self.assertEqual(decided["exit_code"], {"failed": 1, "unverified": 3, "passed": 0}[result_name])
                # The fail-closed invariant, stated directly.
                if decided["result"] == "passed":
                    self.assertEqual(comparison["comparability"]["blocking"], [])
                    self.assertTrue(allow or not comparison["comparability"]["assumptions"])
                    if "new" in conditions:
                        self.assertTrue(all(issue["status"] == "persisting" for issue in comparison["issues"]
                                            if "CONFIRMED" in issue["current_verdicts"]))
                    if "coverage_decrease" in conditions:
                        self.assertFalse(comparison["coverage"]["decreased"])
                    if "not_comparable" in conditions:
                        self.assertEqual(comparison["summary"]["not_comparable"], 0)
                    self.assertEqual(decided["verified"], not comparison["comparability"]["assumptions"])
                counts[decided["result"]] += 1
        # The scenarios reach every outcome.
        self.assertTrue(all(count > 20 for count in counts.values()), counts)


# ---------------------------------------------------------------------------
# Command line


def write(folder: Path, name: str, data: Dict[str, Any]) -> Path:
    path = folder / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def run_diff(arguments: Iterable[Any], environment: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    variables = {"GITHUB_STEP_SUMMARY": ""}
    variables.update(environment or {})
    with patch.dict(os.environ, variables), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = api_sentinel.main(["diff", *[str(item) for item in arguments]])
        except SystemExit as exc:  # argparse errors
            code = int(exc.code or 0)
    return code, stdout.getvalue(), stderr.getvalue()


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-gate-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def pair(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> Tuple[Path, Path]:
        return write(self.folder, "baseline.json", baseline), write(self.folder, "current.json", current)

    def test_without_gate_options_the_output_and_exit_code_are_unchanged(self):
        cases = [
            (keyed([bola("SECURE")]), keyed([bola("CONFIRMED")]), ()),
            (report([bola("CONFIRMED")]), report([bola("SECURE")]), ()),
            (report([bola("CONFIRMED")]), report([bola("SECURE")]), diff_tests.UNKEYED_FLAGS),
            (keyed([bola("CONFIRMED"), anchor()]), keyed([bola("ERROR")]), ()),
        ]
        for index, (baseline, current, flags) in enumerate(cases):
            with self.subTest(case=index):
                old, new = self.pair(baseline, current)
                output = self.folder / "comparison.json"
                code, stdout, stderr = run_diff([old, new, *flags, "--export-json", output])
                comparison = compare_reports(baseline, current, **({} if not flags else UNKEYED))
                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")
                self.assertEqual(stdout, "\n".join(summary_lines(comparison) + [f"[OK] Comparison JSON: {output}"])
                                 + "\n")
                self.assertEqual(output.read_text(encoding="utf-8"),
                                 json.dumps(comparison, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
                self.assertNotIn("gate", json.loads(output.read_text(encoding="utf-8")))

    def test_exit_codes(self):
        cases = {
            0: (keyed([bola("CONFIRMED")]), keyed([bola("CONFIRMED")])),
            1: (keyed([bola("SECURE")]), keyed([bola("CONFIRMED")])),
            3: (report([bola("SECURE")]), report([bola("CONFIRMED")])),
        }
        for expected, (baseline, current) in cases.items():
            with self.subTest(expected=expected):
                old, new = self.pair(baseline, current)
                output = self.folder / "comparison.json"
                code, stdout, _ = run_diff([old, new, "--fail-on-new", "--export-json", output])
                self.assertEqual(code, expected)
                gate_json = json.loads(output.read_text(encoding="utf-8"))["gate"]
                self.assertEqual(gate_json["exit_code"], expected)
                self.assertIn(f"(exit {expected})", stdout)
                self.assertIn(report_gate.EXIT_CODES_LINE, stdout)
                # Without a gate option the same comparison exits 0.
                self.assertEqual(run_diff([old, new])[0], 0)

    def test_invalid_input_and_options_exit_2(self):
        old, new = self.pair(keyed([bola("SECURE")]), keyed([bola("CONFIRMED")]))
        plan = write(self.folder, "plan.json", {"mode": "DRY_RUN", "report_schema_version": 2, "operations": []})
        cases = {
            "allowance without a condition": ([old, new, "--gate-allow-assumptions"], "needs at least one --fail-on"),
            "plan instead of a report": ([old, plan, "--fail-on-new"], "dry-run"),
            "missing report": ([old, self.folder / "missing.json", "--fail-on-new"], "does not exist"),
            "abbreviated option": ([old, new, "--fail-on-n"], "unrecognized"),
            "abbreviated allowance": ([old, new, "--fail-on-new", "--gate-allow"], "unrecognized"),
        }
        for name, (arguments, message) in cases.items():
            with self.subTest(case=name):
                code, stdout, stderr = run_diff(arguments)
                self.assertEqual(code, 2)
                self.assertIn(message, stderr)
                self.assertNotIn("Security gate", stdout)

    def test_help_lists_the_gate_and_its_exit_codes(self):
        code, stdout, _ = run_diff(["--help"])
        self.assertEqual(code, 0)
        for text in ("--fail-on-new", "--fail-on-coverage-decrease", "--fail-on-not-comparable",
                     "--gate-allow-assumptions", "--github-actions", "3 when the gate could not be verified"):
            self.assertIn(text, " ".join(stdout.split()))

    def test_terminal_output_names_the_conditions_and_what_kept_the_gate_from_passing(self):
        old, new = self.pair(report([bola("SECURE"), anchor()]), report([bola("CONFIRMED"), anchor()]))
        code, stdout, _ = run_diff([old, new, "--fail-on-new", "--fail-on-coverage-decrease", *diff_tests.UNKEYED_FLAGS])
        self.assertEqual(code, 3)
        self.assertIn("Security gate (--fail-on-new, --fail-on-coverage-decrease): NOT VERIFIED (exit 3)", stdout)
        self.assertIn("cannot pass: the comparison relies on assumptions (same_identities, same_configuration); "
                      "add --gate-allow-assumptions only if they may decide the gate", stdout)
        self.assertIn("UNVERIFIED  [new] " + finding_id("BOLA", OP), stdout)
        self.assertIn("does not show that the API is secure", stdout)
        code, stdout, _ = run_diff([old, new, "--fail-on-new", "--gate-allow-assumptions", *diff_tests.UNKEYED_FLAGS])
        self.assertEqual(code, 1)
        self.assertIn("REGRESSION  [new] " + finding_id("BOLA", OP), stdout)
        self.assertIn("This result relies on assumptions stated by the caller, not on verification: "
                      "same_identities, same_configuration.", stdout)

    def test_terminal_output_is_bounded(self):
        many = [result("BOLA", f"GET /api/item{index}/{{id}}", "SECURE") for index in range(80)]
        old, new = self.pair(keyed(many), keyed([anchor()]))
        code, stdout, _ = run_diff([old, new, "--fail-on-new"])
        self.assertEqual(code, 3)
        self.assertEqual(stdout.count("UNVERIFIED  [new]"), 50)
        self.assertIn("... 30 more; see --export-json", stdout)


# ---------------------------------------------------------------------------
# GitHub Actions


RUNNER_COMMANDS = {"set-output", "save-state", "add-mask", "add-path", "set-env", "add-matcher", "remove-matcher",
                   "debug", "warning", "error", "notice", "group", "endgroup", "echo", "stop-commands",
                   "internal-set-repo-path"}


def _unescape(value: str) -> str:
    return value.replace("%0D", "\r").replace("%0A", "\n").replace("%3A", ":").replace("%2C", ",").replace("%25", "%")


def runner_commands(log: str) -> List[Tuple[str, str]]:
    """The workflow commands the GitHub Actions runner would run for these log lines, as (command, data).

    Follows the runner: a `::command::data` line after leading whitespace, the
    legacy `##[command]data` anywhere in a line, and `::stop-commands::TOKEN`
    until `::TOKEN::`.
    """
    executed: List[Tuple[str, str]] = []
    token: Optional[str] = None
    for line in log.splitlines():
        registered = RUNNER_COMMANDS | ({token} if token else set())
        command: Optional[Tuple[str, str]] = None
        trimmed = line.lstrip()
        if trimmed.startswith("::") and trimmed.find("::", 2) > 0:
            end = trimmed.find("::", 2)
            name = trimmed[2:end].split(" ", 1)[0]
            if name in registered:
                command = (name, _unescape(trimmed[end + 2:]))
        if command is None and "##[" in line:
            start = line.index("##[")
            close = line.find("]", start)
            if close > 0:
                name = line[start + 3:close].split(" ", 1)[0]
                if name in registered:
                    command = (name, line[close + 1:])
        if command is None:
            continue
        if token is not None:
            if command[0].lower() == token.lower():
                executed.append(("resume", ""))
                token = None
            continue
        if command[0] == "stop-commands":
            token = command[1]
        executed.append(command)
    return executed


HOSTILE = (
    "##[set-output name=gate;]passed",
    "##[add-mask]x ##[stop-commands]y",
    "::set-output name=gate::passed",
    "%0A::error::forged %25",
    "<img src=x onerror=alert(1)> **bold** `code` | cell | [link](https://evil.example) www.evil.example",
    "a@evil.example &#60; \\ _x_",
)


class GitHubActionsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-gate-gh-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.summary = self.folder / "step-summary.md"

    def run_github(self, baseline: Dict[str, Any], current: Dict[str, Any], *options: str,
                   summary: Optional[str] = None) -> Tuple[int, str, str]:
        old, new = write(self.folder, "baseline.json", baseline), write(self.folder, "current.json", current)
        return run_diff([old, new, "--github-actions", *options],
                        {"GITHUB_STEP_SUMMARY": str(self.summary) if summary is None else summary})

    def hostile_pair(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        def rbac(verdict: str, role: str) -> Dict[str, Any]:
            return result("RBAC", OP, verdict, rbac_role=role)
        baseline = keyed([rbac("SECURE", role) for role in HOSTILE] + [anchor()])
        current = keyed([rbac("CONFIRMED", role) for role in HOSTILE] + [anchor()])
        return baseline, current

    def test_report_text_never_runs_as_a_workflow_command(self):
        baseline, current = self.hostile_pair()
        code, stdout, stderr = self.run_github(baseline, current, "--fail-on-new", "--fail-on-not-comparable")
        self.assertEqual(code, 1)
        executed = runner_commands(stdout + "\n" + stderr)
        self.assertEqual(executed[0][0], "stop-commands")
        self.assertEqual(executed[1], ("resume", ""))
        names = [name for name, _ in executed[2:]]
        self.assertEqual(names, ["error"] * len(HOSTILE) + ["error"])
        for _, data in executed[2:]:
            self.assertNotIn("\n", data)
            self.assertNotIn("\r", data)
        self.assertIn("passed", " ".join(data for _, data in executed))  # the hostile text is shown, inert
        # The token is unpredictable: two runs use different tokens.
        again = runner_commands(self.run_github(baseline, current, "--fail-on-new")[1])
        self.assertNotEqual(executed[0][1], again[0][1])
        self.assertRegex(executed[0][1], r"^granttrace-[0-9a-f]{32}$")

    def test_the_default_output_is_not_protected_and_github_mode_is(self):
        # Documented limitation of the unchanged default output: report text reaches the log as it is.
        baseline, current = self.hostile_pair()
        old, new = write(self.folder, "baseline.json", baseline), write(self.folder, "current.json", current)
        _, plain, _ = run_diff([old, new])
        self.assertIn("set-output", [name for name, _ in runner_commands(plain)])
        _, protected, _ = run_diff([old, new, "--github-actions"])
        self.assertEqual([name for name, _ in runner_commands(protected)], ["stop-commands", "resume"])

    def test_annotations_are_escaped_and_capped(self):
        roles = [f"role{index}%0A::warning::x" for index in range(30)]
        baseline = keyed([result("RBAC", OP, "SECURE", rbac_role=role) for role in roles] + [anchor()])
        current = keyed([result("RBAC", OP, "CONFIRMED", rbac_role=role) for role in roles] + [anchor()])
        code, stdout, _ = self.run_github(baseline, current, "--fail-on-new")
        self.assertEqual(code, 1)
        annotations = [line for line in stdout.splitlines() if line.startswith("::error ")]
        self.assertEqual(len(annotations), 10)
        self.assertIn("%250A::warning::x", annotations[0])
        self.assertIn("21 more item(s) in the log and the step summary", annotations[-1])

    def test_annotation_levels_follow_the_result(self):
        cases = {
            "notice": (keyed([bola("CONFIRMED")]), keyed([bola("CONFIRMED")]), ()),
            "warning": (report([bola("CONFIRMED"), anchor()]), report([bola("CONFIRMED"), anchor()]),
                        ("--gate-allow-assumptions", *diff_tests.UNKEYED_FLAGS)),
            "error": (report([bola("SECURE")]), report([bola("CONFIRMED")]), ()),
        }
        for level, (baseline, current, options) in cases.items():
            with self.subTest(level=level):
                code, stdout, _ = self.run_github(baseline, current, "--fail-on-new", *options)
                final = [line for line in stdout.splitlines() if line.startswith("::")][-1]
                self.assertTrue(final.startswith(f"::{level} title=GrantTrace security gate::"), final)
                self.assertEqual(code, {"notice": 0, "warning": 0, "error": 3}[level])
        self.assertIn("relying on assumptions", self.run_github(*cases["warning"][:2], "--fail-on-new",
                                                                  *cases["warning"][2])[1])

    def test_step_summary_cannot_carry_markup_from_a_report(self):
        baseline, current = self.hostile_pair()
        self.summary.write_text("earlier step\n", encoding="utf-8")
        code, _, _ = self.run_github(baseline, current, "--fail-on-new")
        self.assertEqual(code, 1)
        text = self.summary.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("earlier step\n## GrantTrace security gate: FAILED (exit 1)\n"), text[:80])
        self.assertTrue(text.isascii())
        rows = [line for line in text.splitlines() if line.startswith("| REGRESSION")]
        self.assertEqual(len(rows), len(HOSTILE))
        self.assertTrue(all(row.count("|") == 8 for row in rows), rows)
        body = "\n".join(line for line in text.splitlines() if not line.startswith("## "))
        for forbidden in ("<", ">", "[", "](", "`", "**", "www.", "https:", "@", "::", "##", "\\"):
            self.assertNotIn(forbidden, body, forbidden)
        self.assertIn("does not show that the API is secure", text)

    def test_step_summary_without_a_gate_lists_the_comparison(self):
        code, stdout, _ = self.run_github(keyed([bola("SECURE")]), keyed([bola("CONFIRMED")]))
        self.assertEqual(code, 0)
        text = self.summary.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("## GrantTrace report comparison\n"))
        self.assertIn(f"| new | {finding_id('BOLA', OP)} | BOLA | GET /api/items/{{id}} | - | - |", text)
        self.assertEqual([name for name, _ in runner_commands(stdout)], ["stop-commands", "resume"])

    def test_step_summary_lists_a_coverage_percentage_and_shortens_long_text(self):
        long_role = "r" * 300
        baseline = keyed([result("RBAC", OP, "SECURE", rbac_role=long_role), anchor()],
                         stats={"conclusive_coverage_pct": 100.0})
        current = keyed([result("RBAC", OP, "CONFIRMED", rbac_role=long_role), anchor()],
                        stats={"conclusive_coverage_pct": 50.0})
        code, _, _ = self.run_github(baseline, current, "--fail-on-new", "--fail-on-coverage-decrease")
        self.assertEqual(code, 1)
        text = self.summary.read_text(encoding="utf-8")
        self.assertIn("- Conclusive coverage: 100.0% -> 50.0% (decreased)", text)
        self.assertIn("| REGRESSION | coverage_decrease | coverage_pct_decreased | - | - | "
                      "conclusive coverage 100.0% -> 50.0% | - |", text)
        self.assertIn("| role&#58;" + "r" * 115 + "&#46;&#46;&#46; |", text)
        self.assertNotIn("r" * 121, text)

    def test_step_summary_is_bounded(self):
        many = [result("BOLA", f"GET /api/item{index}/{{id}}", "SECURE") for index in range(150)]
        code, _, _ = self.run_github(keyed(many), keyed([anchor()]), "--fail-on-new")
        self.assertEqual(code, 3)
        text = self.summary.read_text(encoding="utf-8")
        self.assertEqual(text.count("| NOT VERIFIED | new |"), 100)
        self.assertIn("50 more row(s) are in the comparison JSON", text)

    def test_missing_unwritable_or_aliased_step_summary(self):
        pair = (keyed([bola("CONFIRMED")]), keyed([bola("CONFIRMED")]))
        code, _, stderr = self.run_github(*pair, "--fail-on-new", summary="")
        self.assertEqual(code, 0)
        self.assertIn("GITHUB_STEP_SUMMARY is not set", stderr)
        code, stdout, stderr = self.run_github(*pair, "--fail-on-new", summary=str(self.folder))
        self.assertEqual(code, 2)
        self.assertIn("cannot write the GitHub step summary", stderr)
        # The gate itself passed, but an output failed: the step must not read as a pass.
        self.assertEqual(runner_commands(stdout)[-1], ("error", "An output could not be written (exit 2); see the "
                                                                "log."))
        self.assertNotIn("notice", [name for name, _ in runner_commands(stdout)])
        code, _, stderr = self.run_github(*pair, "--fail-on-new", summary=str(self.folder / "current.json"))
        self.assertEqual(code, 2)
        self.assertIn("GITHUB_STEP_SUMMARY must not overwrite an input report", stderr)
        code, _, stderr = self.run_github(*pair, "--fail-on-new", "--export-json", str(self.summary))
        self.assertEqual(code, 2)
        self.assertIn("--export-json must not be the GitHub step summary file", stderr)

    def test_an_input_error_is_annotated(self):
        old = write(self.folder, "baseline.json", keyed([bola("SECURE")]))
        code, stdout, stderr = run_diff([old, self.folder / "missing.json", "--fail-on-new", "--github-actions"])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", stderr)
        self.assertEqual(runner_commands(stdout), [("error", "The comparison could not be completed (exit 2); "
                                                            "see the log.")])


# ---------------------------------------------------------------------------
# Real scans


class EndToEndTests(unittest.TestCase):
    """Real scans of a local API, compared and gated through the command line."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-gate-e2e-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.addCleanup(setattr, diff_tests._OrdersApi, "mode", diff_tests._OrdersApi.mode)
        self.port = 0

    def scan(self, name: str, mode: Optional[str], key: Optional[str] = KEY, **config: Any) -> Path:
        """Scan the orders API in `mode` on one fixed port; mode None scans with nothing listening."""
        folder = self.folder / name
        folder.mkdir()
        spec = diff_tests.EndToEndTests.orders_spec()
        configuration = diff_tests.EndToEndTests.orders_config()
        configuration.update(config)
        (folder / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
        (folder / "config.json").write_text(json.dumps(configuration), encoding="utf-8")
        server = None
        if mode is not None:
            diff_tests._OrdersApi.mode = mode
            server = ThreadingHTTPServer(("127.0.0.1", self.port), diff_tests._OrdersApi)
            self.port = server.server_port
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
        elif not self.port:
            raise AssertionError("scan a running service first")
        stdout, stderr = io.StringIO(), io.StringIO()
        environment = {"GRANTTRACE_COMPARISON_KEY": key} if key else {}
        try:
            with patch.dict(os.environ, environment), contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                if not key:
                    os.environ.pop("GRANTTRACE_COMPARISON_KEY", None)
                code = api_sentinel.main(["--spec", str(folder / "spec.json"), "--config", str(folder / "config.json"),
                                          "--target", f"http://127.0.0.1:{self.port}", "--delay", "0",
                                          "-o", str(folder / "report.html"),
                                          "--export-json", str(folder / "report.json")])
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
        self.assertEqual(code, 0, stdout.getvalue() + stderr.getvalue())
        return folder / "report.json"

    def gate(self, old: Path, new: Path, *options: str) -> Tuple[int, Dict[str, Any], str]:
        output = self.folder / "comparison.json"
        code, stdout, stderr = run_diff([old, new, *options, "--export-json", output])
        self.assertIn(code, (0, 1, 3), stdout + stderr)
        return code, json.loads(output.read_text(encoding="utf-8"))["gate"], stdout

    def test_a_regression_a_fix_and_an_unchanged_finding(self):
        secure = self.scan("secure", "members")
        vulnerable = self.scan("vulnerable", "intra_org")
        again = self.scan("vulnerable-again", "intra_org")
        fixed = self.scan("fixed", "members")
        everything = ("--fail-on-new", "--fail-on-coverage-decrease", "--fail-on-not-comparable")
        code, decided, stdout = self.gate(secure, vulnerable, *everything)
        self.assertEqual((code, decided["result"], decided["verified"]), (1, "failed", True))
        self.assertEqual([item["reason"] for item in part(decided, "new")["regressions"]], ["new_finding"])
        self.assertIn("REGRESSION  [new]", stdout)
        for name, (old, new) in {"persisting": (vulnerable, again), "resolved": (again, fixed),
                                 "unchanged": (secure, fixed)}.items():
            with self.subTest(case=name):
                code, decided, _ = self.gate(old, new, *everything)
                self.assertEqual((code, decided["result"], decided["verified"]), (0, "passed", True))

    def test_an_unreachable_target_never_passes(self):
        secure = self.scan("secure", "members")
        down = self.scan("down", None)
        for option in ("--fail-on-new", "--fail-on-coverage-decrease", "--fail-on-not-comparable"):
            with self.subTest(option=option):
                code, decided, _ = self.gate(secure, down, option)
                self.assertNotEqual(code, 0)
                self.assertIn("no_conclusive_results", [item["reason"] for item in decided["prerequisites"]])

    def test_a_policy_that_now_allows_the_visitor_does_not_pass_as_no_regression(self):
        secure = self.scan("secure", "members")
        # The vulnerability returns, and the same change declares that the Visitor may read the order.
        allowed = self.scan("allowed", "intra_org",
                            bola={"GET /orders/{orderId}": {"expected_visitor_access": "allow"}})
        code, decided, _ = self.gate(secure, allowed, "--fail-on-new")
        states = result_states(json.loads(allowed.read_text(encoding="utf-8")))
        self.assertIn("AUTHORIZED", states[("BOLA", "GET /orders/{orderId}", None)].verdicts)
        self.assertEqual((code, decided["result"]), (3, "unverified"))
        self.assertEqual([item["reason"] for item in part(decided, "new")["unverified"]],
                         ["accepted_after_declaration_change"])

    def test_scans_without_a_comparison_key_need_assumptions_and_the_allowance(self):
        secure = self.scan("secure", "members", key=None)
        vulnerable = self.scan("vulnerable", "intra_org", key=None)
        code, decided, _ = self.gate(secure, vulnerable, "--fail-on-new")
        self.assertEqual((code, decided["prerequisites"][0]["reason"]), (3, "comparison_blocked"))
        code, decided, _ = self.gate(secure, vulnerable, "--fail-on-new", *diff_tests.UNKEYED_FLAGS)
        self.assertEqual((code, decided["prerequisites"][0]["reason"]), (3, "assumptions_not_allowed"))
        code, decided, _ = self.gate(secure, vulnerable, "--fail-on-new", "--gate-allow-assumptions",
                                     *diff_tests.UNKEYED_FLAGS)
        self.assertEqual((code, decided["result"], decided["verified"]), (1, "failed", False))


class ExampleWorkflowTests(unittest.TestCase):
    """The GitHub Actions example keeps the safety properties the documentation relies on."""

    PATH = ROOT / "examples" / "github-actions" / "granttrace-security-gate.yml"

    def test_example_workflow(self):
        import yaml

        text = self.PATH.read_text(encoding="utf-8")
        workflow = yaml.safe_load(text)
        triggers = workflow.get("on", workflow.get(True))
        self.assertEqual(set(triggers), {"pull_request"})
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("pull_request_target", code)
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        (job,) = workflow["jobs"].values()
        self.assertNotIn("GRANTTRACE_COMPARISON_KEY", json.dumps(job.get("env", {})))
        steps = job["steps"]
        for step in steps:
            if step.get("uses", "").startswith("actions/checkout@"):
                self.assertIs(step["with"]["persist-credentials"], False)
            # Expressions from the event never reach a shell script directly.
            self.assertNotIn("${{ github.event", step.get("run", ""))
            if "GRANTTRACE_COMPARISON_KEY" in json.dumps(step.get("env", {})):
                self.assertIn("granttrace --spec", step["run"])
                self.assertNotIn("start", step["name"].lower())
        gate_step = next(step for step in steps if "granttrace diff" in step.get("run", ""))
        for option in ("--fail-on-new", "--fail-on-coverage-decrease", "--github-actions", "--export-json"):
            self.assertIn(option, gate_step["run"])
        for option in ("--gate-allow-assumptions", "--assume-", "continue-on-error"):
            self.assertNotIn(option, json.dumps(gate_step))
        # Both scans read the configuration from the base branch.
        scans = [step["run"] for step in steps if "granttrace --spec" in step.get("run", "")]
        self.assertEqual(len(scans), 2)
        self.assertTrue(all("--config base/" in scan for scan in scans), scans)
        # Only the comparison, which holds no evidence, is uploaded.
        uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual([step["with"]["path"] for step in uploads], ["${{ runner.temp }}/comparison.json"])

    def test_the_example_uses_the_action_versions_of_this_repository(self):
        ours = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        for action in re.findall(r"uses: (actions/[a-z-]+@v[0-9]+)", self.PATH.read_text(encoding="utf-8")):
            self.assertIn(action, ours)


if __name__ == "__main__":
    unittest.main()
