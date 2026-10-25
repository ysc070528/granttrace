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
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_pr42_adversarial.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    module = sys.modules["test_pr42_adversarial"]
    observations = list(module.OBSERVATIONS)
    limitations = []
    # Deliberately violate the operator's strong-read contract without an
    # observable cache marker. These are reported as unsafe limitations, never
    # included in the passing regression count or claimed as solved.
    for mode in ("opaque_cached_after", "opaque_cached_restore"):
        with module.AdversarialAPI(mode) as api:
            api.scan()
            limitations.append({"case": mode, "contract_violated": "configured strong readback serves unmarked old state",
                "resource_restored": api.states["/profile"] == api.original,
                "reported_rollback_verified": api.auditor.results[0]["evidence"].get("rollback_verified"),
                "verdict": api.auditor.results[0]["verdict"],
                "solved": False})
    output = {"scope": "Independent loopback counterexamples, not the original fixed scenario suite",
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "regression_passed": result.wasSuccessful(),
              "unresolved_contract_probe_count": sum(not item["resource_restored"] and item["reported_rollback_verified"] is True
                                                     for item in limitations),
              "merge_decision": "PASS WITH CONDITIONS" if result.wasSuccessful() else "BLOCK",
              "diagnostics": [{"test": str(test), "traceback": trace} for test, trace in result.failures + result.errors],
              "observations": observations, "unsupported_contract_probes": limitations,
              "test_source_sha256": hashlib.sha256((ROOT / "tests/test_pr42_adversarial.py").read_bytes()).hexdigest()}
    output["source_commit"] = subprocess.check_output(
        ["git", "-C", str(args.source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    source_hash = hashlib.sha256()
    for source in sorted((args.source_root / "core").rglob("*.py")) + [args.source_root / "api_sentinel.py"]:
        source_hash.update(source.relative_to(args.source_root).as_posix().encode() + b"\0")
        source_hash.update(source.read_bytes())
    output["runtime_source_sha256"] = source_hash.hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # Exit 3 means regressions passed but unsafe contract probes remain. It must
    # not be interpreted as an unconditional safety acceptance.
    return 1 if not result.wasSuccessful() else 3 if output["unresolved_contract_probe_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
