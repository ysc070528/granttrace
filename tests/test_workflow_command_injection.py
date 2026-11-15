"""Report text in `granttrace diff` output never runs as a GitHub Actions workflow command.

The GitHub Actions runner reads every line a step writes, on stdout and stderr,
and runs `::command::` at the start of a line and the legacy `##[command]`
anywhere in a line. Subjects in a report (RBAC role names, BOPLA rule IDs,
mass-assignment field names) are free text from a configuration or an OpenAPI
document. Before this fix, a subject such as `##[set-output name=gate;]passed`
printed by the default output set a step output, forged an annotation or stopped
command processing. `tests/github_runner.py` models the runner's parser.

The terminal output now escapes these markers in any mode (`##[` is printed as
`##\\u005b`, a leading `:` of `::` as `\\u003a`); JSON, step summaries and
annotations are unchanged, and ordinary text is printed as before.
"""

from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import test_report_diff as diff_tests
from core import report_diff, report_gate
from core.report_diff import compare_reports, result_states, summary_lines
from github_runner import DOTNET_WHITESPACE, Command, runner_commands
from test_report_diff import OP, THIRD, keyed, result
from test_report_gate import run_diff, write

GATE_TITLE = "GrantTrace security gate"
PAYLOADS = (
    # Plain printable text: set a step output, forge an annotation inline, stop command processing,
    # mask log text, open a log group, and the v2 form inside a line.
    "##[set-output name=gate;]passed",
    "harmless text ##[error title=GrantTrace security gate]Gate passed (exit 0)",
    "##[stop-commands]halt",
    "##[add-mask]Security gate",
    "x ##[group]collapsed ##[warning]w",
    "###[save-state name=s;]v",
    "::set-output name=gate::passed",
    # The same with ANSI escapes, CR LF, bidirectional and zero-width controls, full-width and
    # look-alike characters.
    "\x1b[31m##[set-output name=gate;]passed\x1b[0m",
    "role\r\n::set-output name=gate::passed\r\n##[error]forged",
    "\u202e##[set-output name=gate;]passed\u2028::error::x",
    "#\u200b#[set-output name=gate;]passed",
    "#\ufe0f#[set-output name=gate;]passed",
    "\uff03\uff03\uff3bset-output name=gate;\uff3dpassed",
)
CHANNELS = ("RBAC", "BOPLA", "MASS_ASSIGNMENT")
MODES = {
    "default": (),
    "gate": ("--fail-on-new", "--fail-on-coverage-decrease", "--fail-on-not-comparable"),
    "github-actions": ("--github-actions",),
    "gate and github-actions": ("--fail-on-new", "--fail-on-coverage-decrease", "--fail-on-not-comparable",
                                "--github-actions"),
}


def subject_record(check: str, verdict: str, text: str) -> Dict[str, Any]:
    if check == "RBAC":
        return result("RBAC", OP, verdict, rbac_role=text)
    if check == "BOPLA":
        return result("BOPLA", OP, verdict, decision_evidence={"rule_id": text, "subject_identity": "visitor"})
    return result("MASS_ASSIGNMENT", OP, verdict, field=text)


def hostile_pair(check: str, payloads: Sequence[str] = PAYLOADS) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    anchor = result("BROKEN_AUTH", THIRD, "SECURE")
    return (keyed([subject_record(check, "SECURE", text) for text in payloads] + [anchor]),
            keyed([subject_record(check, "CONFIRMED", text) for text in payloads] + [anchor]))


def only_our_commands(test: unittest.TestCase, executed: List[Command], github: bool) -> None:
    """Without --github-actions nothing may run; with it, only its stop/resume pair and gate annotations."""
    if not github:
        test.assertEqual(executed, [])
        return
    test.assertEqual([command.name for command in executed[:2]], ["stop-commands", "resume"])
    for command in executed[2:]:
        test.assertIn(command.name, ("error", "warning", "notice"))
        test.assertEqual(command.properties, {"title": GATE_TITLE})
        test.assertTrue(command.line.startswith(f"::{command.name} title={GATE_TITLE}::"), command.line)


class SafeLogLineTests(unittest.TestCase):
    def test_markers_are_escaped_wherever_the_runner_reads_them(self):
        cases = {
            "##[set-output name=gate;]passed": "##\\u005bset-output name=gate;]passed",
            "role:x ##[error]forged": "role:x ##\\u005berror]forged",
            "###[a] ##[##[b]": "###\\u005ba] ##\\u005b##\\u005bb]",
            "::set-output name=gate::passed": "\\u003a:set-output name=gate::passed",
            "  \t::error::x": "  \t\\u003a:error::x",
            "\u3000\u2028::warning::x": "\u3000\u2028\\u003a:warning::x",
            "text ::set-output name=a::b": "text ::set-output name=a::b",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(report_diff.safe_log_line(line), expected)
                self.assertEqual(runner_commands(report_diff.safe_log_line(line)), [])

    def test_every_whitespace_the_runner_trims_counts_before_a_leading_marker(self):
        for character in sorted(DOTNET_WHITESPACE - {"\r", "\n"}):
            with self.subTest(character=hex(ord(character))):
                line = character * 2 + "::set-output name=gate::passed"
                self.assertEqual(len(runner_commands(line)), 1)
                self.assertEqual(runner_commands(report_diff.safe_log_line(line)), [])
        # A line break starts a new line for the runner.
        for separator in ("\r\n", "\n", "\r"):
            with self.subTest(separator=repr(separator)):
                text = "first" + separator + " ::set-output name=gate::passed"
                self.assertEqual(runner_commands(report_diff.safe_log_line(text)), [])

    def test_ordinary_text_is_unchanged(self):
        for line in ("GrantTrace report comparison", "  NEW             gtf_0123456789abcdef BOLA GET /a/{id} [role:a#b]",
                     "  operation GET /a::b: spec_changed", "Comparability: limited (assumed by the caller: x)",
                     "[OK] Comparison JSON: C:\\Users\\测试\\comparison.json", "# heading", "#[x]", "[##]", "",
                     "\\u005b already escaped", ": one colon", "a::b"):
            with self.subTest(line=line):
                self.assertEqual(report_diff.safe_log_line(line), line)

    def test_random_text_never_runs_and_escaping_is_idempotent(self):
        rng = random.Random("safe-log-line")
        alphabet = ["#", "#", "[", "]", ":", ":", " ", "\t", "\u3000", "\\", "u", "0", "5", "b", "a", "=", ";", ",",
                    "set-output", "error", "stop-commands", "add-mask", "name"]
        for _ in range(20000):
            line = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
            safe = report_diff.safe_log_line(line)
            self.assertEqual(runner_commands(safe), [], (line, safe))
            self.assertEqual(report_diff.safe_log_line(safe), safe, line)
            if "##[" not in line and not line.lstrip().startswith("::"):
                self.assertEqual(safe, line)


class DiffOutputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-injection-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def run_mode(self, baseline: Dict[str, Any], current: Dict[str, Any], options: Sequence[str]
                 ) -> Tuple[int, str, str, Dict[str, Any]]:
        old, new = write(self.folder, "baseline.json", baseline), write(self.folder, "current.json", current)
        output = self.folder / "comparison.json"
        code, stdout, stderr = run_diff([old, new, *options, "--export-json", output],
                                        {"GITHUB_STEP_SUMMARY": str(self.folder / "summary.md")})
        text = output.read_text(encoding="utf-8")
        written = json.loads(text)
        # The file is exactly what json.dumps writes for these values: nothing in it is escaped for a log.
        self.assertEqual(text, json.dumps(written, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
        return code, stdout, stderr, written

    def test_report_text_never_runs_as_a_workflow_command_in_any_mode(self):
        for check in CHANNELS:
            baseline, current = hostile_pair(check)
            comparison = compare_reports(baseline, current)
            for mode, options in MODES.items():
                with self.subTest(check=check, mode=mode):
                    code, stdout, stderr, written = self.run_mode(baseline, current, options)
                    only_our_commands(self, runner_commands(stdout + "\n" + stderr), "--github-actions" in options)
                    # Exit codes and the machine-readable comparison are those of the unescaped report.
                    gate = written.pop("gate", None)
                    self.assertEqual(written, json.loads(json.dumps(comparison)))
                    self.assertEqual(code, gate["exit_code"] if gate else 0)
                    # The text stays visible, escaped, in the log.
                    self.assertIn("##\\u005bset-output name=gate;]passed", stdout)
                    self.assertIn(":set-output name=gate::passed", stdout)

    def test_json_keeps_the_subjects_exactly(self):
        baseline, current = hostile_pair("RBAC", PAYLOADS[:7])
        _, _, _, written = self.run_mode(baseline, current, MODES["gate"])
        subjects = sorted(issue["subject"] for issue in written["issues"])
        self.assertEqual(subjects, sorted("role:" + text for text in PAYLOADS[:7]))
        self.assertEqual(sorted(item["subject"] for item in written["gate"]["conditions"][0]["regressions"]),
                         subjects)

    def test_step_summary_and_annotations_are_unchanged_by_the_escaping(self):
        baseline, current = hostile_pair("RBAC", PAYLOADS[:2])
        code, stdout, _, written = self.run_mode(baseline, current, MODES["gate and github-actions"])
        comparison = dict(written)
        gate = comparison["gate"]
        expected_summary = report_gate.github_step_summary(comparison, gate)
        self.assertEqual((self.folder / "summary.md").read_text(encoding="utf-8"), expected_summary)
        annotations = [line for line in stdout.splitlines() if line.startswith("::error ")]
        self.assertEqual(annotations, report_gate.github_annotations(gate))
        self.assertEqual(code, 1)


class ErrorPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-injection-errors-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.baseline = write(self.folder, "baseline.json", keyed([diff_tests.bola("SECURE")]))
        self.current = write(self.folder, "current.json", keyed([diff_tests.bola("SECURE")]))

    def assert_inert(self, arguments: Sequence[Any], expected_code: int, environment: Any = None) -> Tuple[str, str]:
        for github in (False, True):
            with self.subTest(arguments=[str(item)[-40:] for item in arguments], github=github):
                code, stdout, stderr = run_diff([*arguments, *(["--github-actions"] if github else [])],
                                                environment)
                self.assertEqual(code, expected_code, stdout + stderr)
                executed = runner_commands(stdout + "\n" + stderr)
                if github and expected_code == 2:
                    # Only the fixed annotation that the comparison or an output failed.
                    self.assertTrue(all(command.name in ("stop-commands", "resume", "error") for command in executed))
                    self.assertTrue(all(command.properties in ({}, {"title": GATE_TITLE}) for command in executed))
                else:
                    only_our_commands(self, executed, github)
        return stdout, stderr

    def test_reports_that_cannot_be_used(self):
        payload = PAYLOADS[0]
        files = {
            "invalid JSON": '{"tool_version": "' + payload + '", ',
            "repeated key": '{"a": 1, "a": "' + payload + '"}',
            "plan": json.dumps({"mode": "DRY_RUN", "operations": [payload]}),
            "SARIF": json.dumps({"runs": [{"tool": payload}]}),
            "schema": json.dumps({"report_schema_version": payload, "results": [], "tool_version": "2.8.0"}),
            "no results": json.dumps({"report_schema_version": 2, "results": payload, "tool_version": "2.8.0"}),
        }
        for name, text in files.items():
            path = self.folder / f"{name}.json"
            path.write_text(text, encoding="utf-8")
            self.assert_inert([self.baseline, path, "--fail-on-new"], 2)

    def test_an_output_path_with_markers_is_printed_inert_and_written_where_asked(self):
        output = self.folder / "x ##[set-output name=gate;]passed.json"
        stdout, _ = self.assert_inert([self.baseline, self.current, "--export-json", output], 0)
        self.assertTrue(output.is_file())
        self.assertIn("##\\u005bset-output name=gate;]passed.json", stdout)

    def test_failures_after_the_comparison(self):
        self.assert_inert([self.baseline, self.current, "--fail-on-new", "--export-json", self.folder], 2)
        self.assert_inert([self.baseline, self.current, "--gate-allow-assumptions"], 2)

    def test_hostile_reports_never_escape_as_an_unhandled_error(self):
        """An unhandled exception would print its message unescaped; random hostile reports never raise one."""
        rng = random.Random("hostile-reports")
        strings = list(PAYLOADS) + ["", "GET /a/{id}", "BOLA", "CONFIRMED", "SECURE", "2.8.0", "\x00", "[" * 50]

        def value(depth: int) -> Any:
            kind = rng.random()
            if depth > 3 or kind < 0.45:
                return rng.choice(strings + [0, 1, -1, 2.5, True, None])
            if kind < 0.7:
                return [value(depth + 1) for _ in range(rng.randint(0, 4))]
            return {rng.choice(strings + ["evidence", "verdict", "check", "endpoint", "rbac_role", "field",
                                          "decision_evidence", "rule_id", "subject_identity", "requests_attempted"]):
                    value(depth + 1) for _ in range(rng.randint(0, 5))}

        def record() -> Any:
            if rng.random() < 0.2:
                return value(1)
            data = {"endpoint": rng.choice([OP, "GET /a::b", rng.choice(strings)]),
                    "check": rng.choice(["BOLA", "RBAC", "BOPLA", "MASS_ASSIGNMENT", rng.choice(strings)]),
                    "verdict": rng.choice(["CONFIRMED", "SECURE", "PUBLIC", "ERROR", rng.choice(strings)]),
                    "evidence": value(1)}
            if rng.random() < 0.7 and isinstance(data["evidence"], dict):
                data["evidence"].update({"rbac_role": rng.choice(strings), "field": rng.choice(strings),
                                         "requests_attempted": rng.choice([0, 1, 3, "3"])})
            return data

        modes = list(MODES.values())
        for seed in range(250):
            reports = []
            for side in range(2):
                data: Dict[str, Any] = {"tool_version": rng.choice(["2.8.0", "2.5.2", rng.choice(strings)]),
                                        "report_schema_version": 2, "target": rng.choice(strings),
                                        "generated_at": rng.choice(strings), "stats": value(1),
                                        "results": [record() for _ in range(rng.randint(0, 8))]}
                if rng.random() < 0.3:
                    data["comparison_context"] = value(1)
                reports.append(write(self.folder, f"hostile-{side}.json", data))
            options = rng.choice(modes)
            with self.subTest(seed=seed, options=options):
                code, stdout, stderr = run_diff([*reports, *options],
                                                {"GITHUB_STEP_SUMMARY": str(self.folder / "summary.md")})
                self.assertIn(code, (0, 1, 2, 3))
                only_our_commands(self, runner_commands(stdout + "\n" + stderr), "--github-actions" in options)


class CompatibilityTests(unittest.TestCase):
    """Ordinary reports print, write and exit exactly as the unescaped renderers produce them."""

    def test_ordinary_reports_are_printed_unchanged_in_every_mode(self):
        generator = diff_tests.RandomizedInvariantTests()
        with tempfile.TemporaryDirectory(prefix="granttrace-injection-compat-") as temporary:
            folder = Path(temporary)
            for seed in range(60):
                rng = random.Random(f"compat-{seed}")
                scenario = generator.scenario(rng)
                baseline, current = generator.build(scenario, 0), generator.build(scenario, 1)
                old, new = write(folder, "baseline.json", baseline), write(folder, "current.json", current)
                flags = [flag for flag, name in (("--assume-same-target", "assume_same_target"),
                                                 ("--assume-same-identities", "assume_same_identities"),
                                                 ("--assume-same-configuration", "assume_same_configuration"))
                         if scenario["flags"][name]]
                for mode, options in MODES.items():
                    if "--github-actions" in options:
                        continue  # stop-commands tokens are random; the GitHub tests cover these modes
                    with self.subTest(seed=seed, mode=mode):
                        output = folder / "comparison.json"
                        code, stdout, stderr = run_diff([old, new, *flags, *options, "--export-json", output])
                        comparison = compare_reports(baseline, current, **scenario["flags"])
                        lines = summary_lines(comparison)
                        expected_code = 0
                        if options:
                            gate = report_gate.evaluate_gate(
                                comparison, result_states(baseline), result_states(current),
                                conditions=report_gate.CONDITIONS)
                            comparison["gate"] = gate
                            lines += report_gate.gate_lines(gate)
                            expected_code = gate["exit_code"]
                        self.assertEqual(stdout, "\n".join(lines + [f"[OK] Comparison JSON: {output.resolve()}"])
                                         + "\n")
                        self.assertEqual(stderr, "")
                        self.assertEqual(code, expected_code)
                        self.assertEqual(output.read_text(encoding="utf-8"),
                                         json.dumps(comparison, indent=2, ensure_ascii=True, allow_nan=False) + "\n")


if __name__ == "__main__":
    unittest.main()
