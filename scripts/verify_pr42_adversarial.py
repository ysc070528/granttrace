"""Run PR #42's independent counterexamples against a selected source tree."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/pr42-adversarial.json")
    args = parser.parse_args()
    sys.path.insert(0, str(args.source_root.resolve()))
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_pr42*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    module = sys.modules["test_pr42_adversarial"]
    observations = list(module.OBSERVATIONS) + list(sys.modules["test_pr42_state_authority"].OBSERVATIONS)
    limitations = []
    # Keep both original unmarked-cache probes. Test the generic HTTP entry,
    # where no state authority exists: safety requires zero PATCH, not detecting
    # an information-theoretically unobservable cache implementation.
    for mode in ("opaque_cached_after", "opaque_cached_restore"):
        with module.AdversarialAPI(mode, authority=False) as api:
            api.scan()
            api.scan("/other")
            reported = api.auditor.results[0]["evidence"].get("rollback_verified")
            blocked = api.patch_counts["/profile"] == 0 and api.patch_counts["/other"] == 0
            restored = api.states["/profile"] == api.original
            limitations.append({"case": mode, "resource_restored": restored,
                "reported_rollback_verified": reported, "verdict": api.auditor.results[0]["verdict"],
                "initial_snapshot": api.original, "actual_state": api.states,
                "requests": api.calls, "halted": bool(api.auditor._writes_halted_reason),
                "patch_counts": dict(api.patch_counts), "blocked_before_write": blocked,
                "solved": blocked and restored and reported is not True,
                "mechanism": "fail-closed before mutation; no generic cache detection claimed"})
    output = {"scope": "Independent loopback counterexamples, not the original fixed scenario suite",
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "regression_passed": result.wasSuccessful(),
              "unresolved_contract_probe_count": sum(not item["solved"] for item in limitations),
              "merge_decision": "PASS WITH CONDITIONS" if result.wasSuccessful() and all(item["solved"] for item in limitations) else "BLOCK",
              "diagnostics": [{"test": str(test), "traceback": trace} for test, trace in result.failures + result.errors],
              "observations": observations, "unsupported_contract_probes": limitations,
              "test_source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in sorted((ROOT / "tests").glob("test_pr42*.py"))}}
    output["source_commit"] = subprocess.check_output(
        ["git", "-C", str(args.source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    output["source_tree_dirty"] = bool(subprocess.check_output(
        ["git", "-C", str(args.source_root), "status", "--porcelain"], text=True
    ).strip())
    source_hash = hashlib.sha256()
    for source in sorted((args.source_root / "core").rglob("*.py")) + [args.source_root / "api_sentinel.py"]:
        source_hash.update(source.relative_to(args.source_root).as_posix().encode() + b"\0")
        source_hash.update(source.read_bytes())
    output["runtime_source_sha256"] = source_hash.hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # Exit 3 still means regressions passed but unsafe original probes remain. It must
    # not be interpreted as an unconditional safety acceptance.
    return 1 if not result.wasSuccessful() else 3 if output["unresolved_contract_probe_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
