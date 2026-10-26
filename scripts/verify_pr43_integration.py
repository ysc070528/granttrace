"""Independently verify PR #43's preserved gates and disposable PUT state machines.

The direct backing-store observer belongs only to the imported local fixture.
It is not an external API adapter, configuration option, or production recovery
guarantee. No external target is contacted by this verification.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import copy
import hashlib
import importlib
import io
import json
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
PR42_HEAD = "7f25de9df81798bd9f8d20ab15c45b87eb9c8dc2"

# Computed from the fixed PR #42 source, rather than from a candidate tree.
# These permit the same checks in fetch-depth: 1 CI without fetching ancestors.
PR42_METHOD_SHA256 = {
    "_authoritative_patch_state": "c46d07d893d3337f7fcd0f0fc08a71918323b5389c9f0e4b533cbbe8f38e729f",
    "_has_patch_state_authority": "5a886b40ce3d65b95c7565a45c78cd40b0e4f5246b1b953de71f9382cc3e6e77",
    "_verified_patch_document": "9a0ca50b06ad5cc5d0ed75c530637394c937f44ac2352c1ae810c2d8ec30dc31",
    "_json_object": "e31258231a5f1a7072f43ad3ea8d80e758f1d578e6d5bb5cc0e45a139efdd49f",
    "_rollback_and_verify": "549d9f3610e2284ea2a22c22fcecd85eec1077b8980dd1656afcb1cb25b30c88",
    "_execute_patch_case": "4667426e66c6b2613e0ed5c85f85c4a7e401dcffa1d07b01016932f527ecc24f",
    "audit_endpoint_mass_assignment": "cb1ebfb8244e27155faccb2c0ce0d90783f80c1396878fdbce305c0fa920f5da",
}
PR42_FILE_SHA256 = {
    "tests/test_pr42_adversarial.py": "95431f6f4ca7cf0747ffa790c898f8d7433290ebac3b594d2d0d58b2a9e0bf6f",
    "tests/test_pr42_state_authority.py": "bfb09046d8619755ee3e672d64032c6d23f2ae6b1ade9fa4c94bb2ffade55658",
    "scripts/verify_pr42_adversarial.py": "c17c2893c72471f896f5183c8c80b32ab3aa81fe4331426b0b71a499d8712da8",
}


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalized_file_hash(path: Path) -> str:
    return sha256(path.read_bytes().replace(b"\r\n", b"\n"))


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *arguments], stderr=subprocess.DEVNULL)


def source_metadata() -> dict:
    digest = hashlib.sha256()
    for source in sorted((ROOT / "core").rglob("*.py")) + [ROOT / "api_sentinel.py"]:
        digest.update(source.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(source.read_bytes())
    selected_tests = sorted(set((ROOT / "tests").glob("test_pr43*.py"))
                            | set((ROOT / "tests").glob("test_expanded_detection.py")))
    return {
        "source_commit": git("rev-parse", "HEAD").decode().strip(),
        "source_tree_dirty": bool(git("status", "--porcelain").strip()),
        "runtime_source_sha256": digest.hexdigest(),
        "test_source_sha256": {path.name: normalized_file_hash(path) for path in selected_tests},
        "verification_script_sha256": normalized_file_hash(Path(__file__)),
    }


def auditor_methods(source: str) -> dict:
    """Use AST boundaries, retaining exact source text except newline/indentation."""
    source = source.replace("\r\n", "\n")
    lines = source.splitlines(keepends=True)
    cls = next(node for node in ast.parse(source).body
               if isinstance(node, ast.ClassDef) and node.name == "APISentinelAuditor")
    methods = {}
    for node in cls.body:
        if not isinstance(node, ast.FunctionDef) or node.name not in PR42_METHOD_SHA256:
            continue
        start = min([node.lineno] + [decorator.lineno for decorator in node.decorator_list])
        normalized = textwrap.dedent("".join(lines[start - 1:node.end_lineno])).strip() + "\n"
        methods[node.name] = {"source_sha256": sha256(normalized.encode()),
                              "ast_structure": ast.dump(node, include_attributes=False)}
    return methods


def preservation_checks() -> dict:
    current = auditor_methods((ROOT / "core/auditor.py").read_text(encoding="utf-8"))
    try:
        baseline = auditor_methods(git("show", PR42_HEAD + ":core/auditor.py").decode())
    except subprocess.CalledProcessError:
        baseline = None
    methods = {}
    for name, expected in PR42_METHOD_SHA256.items():
        observed = current.get(name, {})
        source_equal = observed.get("source_sha256") == expected
        # When the historical object is absent, exact source identity to the
        # independently pinned SHA also establishes identical parsed structure.
        ast_equal = (observed.get("ast_structure") == baseline.get(name, {}).get("ast_structure")
                     if baseline is not None else source_equal and bool(observed))
        constant_valid = baseline is None or baseline.get(name, {}).get("source_sha256") == expected
        methods[name] = {"expected_source_sha256": expected,
                         "observed_source_sha256": observed.get("source_sha256"),
                         "normalized_source_equal": source_equal,
                         "ast_equal": ast_equal, "baseline_constant_valid": constant_valid,
                         "passed": source_equal and ast_equal and constant_valid}
    files = {}
    for name, expected in PR42_FILE_SHA256.items():
        observed = normalized_file_hash(ROOT / name) if (ROOT / name).is_file() else None
        files[name] = {"expected_normalized_sha256": expected,
                       "observed_normalized_sha256": observed, "passed": expected == observed}
    return {"baseline_commit": PR42_HEAD,
            "baseline_source": "git object and pinned hashes" if baseline is not None else "pinned PR42 source hashes",
            "normalization": "CRLF to LF; AST-selected methods also dedented and outer whitespace stripped",
            "methods": methods, "legacy_counterexample_files": files,
            "passed": all(item["passed"] for item in [*methods.values(), *files.values()])}


def test_id(test) -> str:
    # A failed subtest may embed response bodies in its display label. Record
    # only the parent test name, never parameter reprs or credential-like data.
    return getattr(test, "test_case", test).id()


def run_tests() -> dict:
    suite = unittest.TestSuite()
    for pattern in ("test_pr43*.py", "test_expanded*.py"):
        suite.addTests(unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern=pattern))
    names = []

    class RecordingResult(unittest.TextTestResult):
        def startTest(self, test):
            names.append(test_id(test))
            super().startTest(test)

    stream = io.StringIO()
    # Test output can contain deliberately sensitive fixtures. Keep only names,
    # counts and digest-addressed diagnostics in this artifact and stdout.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        result = unittest.TextTestRunner(stream=stream, resultclass=RecordingResult, verbosity=2).run(suite)
    diagnostics = [{"test": test_id(test), "kind": kind, "traceback_sha256": sha256(trace.encode())}
                   for kind, entries in (("failure", result.failures), ("error", result.errors))
                   for test, trace in entries]
    return {"test_names": names, "tests_run": result.testsRun,
            "failures": len(result.failures), "errors": len(result.errors),
            "skipped": len(result.skipped), "diagnostics": diagnostics,
            "runner_output_sha256": sha256(stream.getvalue().encode()), "passed": result.wasSuccessful()}


def observe_put_case(fixture_class, mode: str, authority: bool) -> dict:
    """Record actual state independently of HTTP claims and reported verdicts."""
    assertions = []

    def check(name, condition):
        assertions.append({"name": name, "passed": bool(condition)})

    with fixture_class(mode) as api:
        auditor = api.auditor(authority=authority)
        initial = copy.deepcopy(api.states)
        plan = auditor.build_plan()
        api.scan(auditor)
        first = copy.deepcopy(auditor.results[0])
        after_first = copy.deepcopy(api.states)
        halted_after_first = bool(auditor._writes_halted_reason)
        api.scan(auditor, "/b")
        journal = copy.deepcopy(api.writes)
        b_writes = [write for write in journal if write["path"] == "/b"]
        rollback_verified = first["evidence"].get("rollback_verified")
        recovery_sent = first["evidence"].get("recovery_sent")
        if not authority:
            check("generic_http_plan_blocks_every_write", all(
                not item["writes_enabled"] for item in plan["operations"]
                if item["check"] == "MASS_ASSIGNMENT"))
            check("generic_http_sends_no_put_or_recovery", not journal)
            check("generic_http_sends_no_readback", not api.reads)
            check("generic_http_does_not_claim_recovery", rollback_verified is False)
            check("generic_http_is_inconclusive", first["verdict"] == "INCONCLUSIVE")
            check("generic_http_actual_resources_unchanged", api.states == initial)
        else:
            check("actual_store_observed_independently", bool(api.authority_reads))
            check("a_mutation_really_applied", any(
                write["path"] == "/a" and not write["restoring"] and write["applied"]
                and write["before"] != write["after"] for write in journal))
            check("put_payloads_retain_the_complete_replacement_document", all(
                set(write["payload"]) == set(api.original) for write in journal))
            if mode in ("honest", "opaque_after"):
                check("actual_a_resource_fully_restored", after_first["/a"] == initial["/a"])
                check("all_successful_actual_resources_fully_restored", api.states == initial)
                check("real_recovery_was_sent", recovery_sent is True)
                check("restore_journal_records_complete_original_payload", any(
                    write["path"] == "/a" and write["restoring"] and write["payload"] == api.original
                    for write in journal))
                check("verified_recovery_matches_actual_state", rollback_verified is True)
                check("successful_recovery_does_not_leave_halt", not halted_after_first)
                check("all_actual_restores_apply", all(write["applied"] for write in journal if write["restoring"]))
                check("verdict_uses_valid_persistence_evidence", first["verdict"] == (
                    "CONFIRMED" if mode == "honest" else "INCONCLUSIVE"))
            else:
                check("unverified_recovery_retains_false_flag", rollback_verified is False)
                check("unverified_recovery_retains_global_halt", halted_after_first and bool(auditor._writes_halted_reason))
                check("later_b_has_no_put", not b_writes)
                check("later_b_actual_resource_unchanged", api.states["/b"] == initial["/b"])
                check("later_b_reports_skipped", auditor.results[-1]["verdict"] == "SKIPPED")
                if mode == "authority_lost_after":
                    check("actual_restore_without_proof_is_not_certified", after_first["/a"] == initial["/a"])
                else:
                    check("noop_restore_leaves_actual_mutated_resource", after_first["/a"] != initial["/a"])
                    check("restore_ack_is_independently_shown_to_be_noop", any(
                        write["path"] == "/a" and write["restoring"] and not write["applied"] for write in journal))
        check("no_false_recovery_claim", rollback_verified is not True or after_first["/a"] == initial["/a"])
        return {
            "case": mode if authority else "generic_http_" + mode,
            "observer": "fixture-owned direct backing-store observer" if authority else "ordinary auditor; no state authority",
            "initial_actual_state": initial, "actual_state_after_a": after_first,
            "final_actual_state": copy.deepcopy(api.states), "write_journal": journal,
            "http_get_claims": copy.deepcopy(api.reads), "authority_observations": copy.deepcopy(api.authority_reads),
            "first_verdict": first["verdict"], "rollback_verified": rollback_verified,
            "recovery_sent": recovery_sent, "halted_after_a": halted_after_first,
            "halted_final": bool(auditor._writes_halted_reason), "later_b_write_count": len(b_writes),
            "later_b_verdict": auditor.results[-1]["verdict"], "assertions": assertions,
            "passed": all(item["passed"] for item in assertions),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/pr43-integration.json")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    before = source_metadata()
    preservation = preservation_checks()
    tests = run_tests()
    fixture_class = importlib.import_module("test_pr43_put_safety").ReplacementServer
    scenarios = []
    for mode, authority in [
        ("honest", True), ("opaque_after", True), ("opaque_restore", True),
        ("restore_ack_only", True), ("authority_lost_after", True),
        ("honest", False), ("opaque_after", False), ("opaque_restore", False),
    ]:
        try:
            scenarios.append(observe_put_case(fixture_class, mode, authority))
        except Exception as exc:
            # Do not serialize exception messages, which can contain request data.
            scenarios.append({"case": mode, "authority": authority, "passed": False,
                              "error_type": type(exc).__name__, "error_sha256": sha256(str(exc).encode())})
    after = source_metadata()
    stable = all(before[key] == after[key] for key in (
        "source_commit", "runtime_source_sha256", "test_source_sha256", "verification_script_sha256"))
    passed = preservation["passed"] and tests["passed"] and stable and all(item["passed"] for item in scenarios)
    output = {
        "scope": "Independent local disposable loopback acceptance; no external API adapter or production recovery guarantee",
        "fixture_dependency": "tests/test_pr43_put_safety.py:ReplacementServer; actual store and write journal are separate from GET responses",
        **before, "source_unchanged_during_verification": stable,
        "pr42_preservation": preservation, "selected_tests": tests,
        "independent_put_observations": scenarios, "passed": passed,
        "merge_decision": "PASS WITH CONDITIONS" if passed else "BLOCK",
        "conditions": ["Re-run against a clean final HEAD and inspect CI for that exact SHA",
                       "External PATCH/PUT remain blocked without authoritative actual-state verification",
                       "Local fixtures do not establish an external recovery protocol"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": passed, "source_commit": before["source_commit"],
                      "source_tree_dirty": before["source_tree_dirty"], "tests_run": tests["tests_run"],
                      "failures": tests["failures"], "errors": tests["errors"],
                      "failed_scenarios": [item["case"] for item in scenarios if not item["passed"]]}, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
