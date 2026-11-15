"""Verify the optional security gate of `granttrace diff` on real scans of the bundled mock.

Every scan is a read-only scan of the local mock API on one loopback port. The
baseline either has the mock's deliberate profile BOLA fixed or not, so each
case is a real regression, fix or unchanged result rather than an edited
report. The gate must exit 0 only when every enabled condition is shown to
hold, 1 for a regression and 3 when it cannot verify; it never passes on
insufficient evidence, an unreachable target or unstated assumptions.

The reports of the verified pass are kept in dist/ci-gate/ so that CI can run
the gate on them once more with --github-actions.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api_sentinel import main as cli_main  # noqa: E402
from mock_server.server import TargetMockHandler  # noqa: E402

PROFILE = "GET /api/users/{user_id}/profile"
ALL = ("--fail-on-new", "--fail-on-coverage-decrease", "--fail-on-not-comparable")


class GateMockHandler(TargetMockHandler):
    """The bundled mock. With `profile_fixed` its deliberate profile BOLA is fixed; with `profile_broken`
    the profile endpoint fails with HTTP 500, so no check on it can reach a conclusion."""

    profile_fixed = False
    profile_broken = False

    def reply(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        match = re.fullmatch(r"/api/users/([^/?]+)/profile", self.path)
        user = {"Bearer TOKEN_ALICE_OWNER_1001": "1001",
                "Bearer TOKEN_BOB_VISITOR_1002": "1002"}.get(self.headers.get("Authorization", ""))
        if match and type(self).profile_broken:
            return self.reply(500, {"error": "Internal Server Error"})
        if match and type(self).profile_fixed and user and match.group(1) != user:
            return self.reply(403, {"error": "Forbidden", "code": 403})
        return super().do_GET()


def require(condition, message):
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def call(arguments, environment):
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch_environment(environment), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli_main([str(item) for item in arguments])
    return code, stdout.getvalue(), stderr.getvalue()


@contextlib.contextmanager
def patch_environment(values):
    saved = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class Lab:
    def __init__(self, folder):
        self.folder = folder
        self.key = secrets.token_hex(32)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), GateMockHandler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.running = True

    def stop(self):
        if self.running:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join()
            self.running = False

    def scan(self, name, fixed, keyed=True, broken=False):
        GateMockHandler.profile_fixed, GateMockHandler.profile_broken = fixed, broken
        GateMockHandler.reset_database()
        path = self.folder / f"{name}.json"
        code, stdout, stderr = call(
            ["--spec", ROOT / "openapi.json", "--config", ROOT / "config.example.json",
             "--target", f"http://127.0.0.1:{self.port}", "--delay", "0", "--timeout", "2",
             "-o", self.folder / f"{name}.html", "--export-json", path],
            {"GRANTTRACE_COMPARISON_KEY": self.key if keyed else None})
        require(code == 0 and path.exists(), f"scan {name} failed ({code}): {stdout[-400:]} {stderr[-400:]}")
        return path

    def gate(self, baseline, current, expected, *options, summary=""):
        output = self.folder / "gate.json"
        code, stdout, stderr = call(["diff", baseline, current, *options, "--export-json", output],
                                    {"GITHUB_STEP_SUMMARY": summary})
        require(code == expected, f"gate {options} exited {code}, expected {expected}:\n{stdout}\n{stderr}")
        return json.loads(output.read_text(encoding="utf-8"))["gate"], stdout


def reasons(gate, condition, kind):
    part = next(item for item in gate["conditions"] if item["condition"] == condition)
    return sorted({item["reason"] for item in part[kind]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "ci-gate.json")
    arguments = parser.parse_args()
    kept = ROOT / "dist" / "ci-gate"
    cases = {}
    with tempfile.TemporaryDirectory(prefix="granttrace-ci-gate-") as temporary:
        folder = Path(temporary)
        lab = Lab(folder)
        try:
            fixed = lab.scan("fixed", True)
            fixed_again = lab.scan("fixed-again", True)
            vulnerable = lab.scan("vulnerable", False)
            vulnerable_again = lab.scan("vulnerable-again", False)
            # The profile endpoint fails: the scan runs, but its checks there cannot reach a conclusion.
            degraded = lab.scan("degraded", True, broken=True)
            fixed_unkeyed = lab.scan("fixed-unkeyed", True, False)
            vulnerable_unkeyed = lab.scan("vulnerable-unkeyed", False, False)
            lab.stop()
            unreachable = lab.scan("unreachable", True)
        finally:
            lab.stop()

        gate, _ = lab.gate(fixed, fixed_again, 0, *ALL)
        require(gate["result"] == "passed" and gate["verified"] is True, "an unchanged deployment did not pass")
        cases["unchanged_passes_verified"] = 0

        gate, _ = lab.gate(fixed, vulnerable, 1, *ALL)
        regression = [(item["check"], item["operation"]) for item in
                      next(part for part in gate["conditions"] if part["condition"] == "new")["regressions"]]
        require(regression == [("BOLA", PROFILE)], f"the reintroduced BOLA was not the regression: {regression}")
        cases["regression_exit_code"] = 1

        gate, _ = lab.gate(vulnerable, vulnerable_again, 0, *ALL)
        require(gate["verified"] is True, "a persisting finding was not a verified pass")
        cases["persisting_finding_passes_new"] = 0
        gate, _ = lab.gate(vulnerable, fixed, 0, *ALL)
        cases["fix_passes"] = 0

        gate, _ = lab.gate(fixed, degraded, 3, "--fail-on-new")
        require("no_longer_verified" in reasons(gate, "new", "unverified"),
                "checks that could no longer conclude passed the new-findings condition")
        gate, _ = lab.gate(fixed, degraded, 1, "--fail-on-coverage-decrease")
        require(reasons(gate, "coverage_decrease", "regressions")[0] == "conclusive_check_lost",
                "lost conclusions were not a coverage regression")
        cases["insufficient_evidence_new_exit_code"] = 3
        cases["insufficient_evidence_coverage_exit_code"] = 1

        for option in ALL:
            gate, _ = lab.gate(fixed, unreachable, 3, option)
            require({"reason": "no_conclusive_results"} in gate["prerequisites"],
                    f"an unreachable target was not refused by {option}")
        cases["unreachable_target_exit_code"] = 3

        unkeyed = (fixed_unkeyed, vulnerable_unkeyed)
        gate, _ = lab.gate(*unkeyed, 3, "--fail-on-new")
        require(gate["prerequisites"][0]["reason"] == "comparison_blocked", "unverifiable scans were compared")
        gate, _ = lab.gate(*unkeyed, 3, "--fail-on-new", "--assume-same-identities", "--assume-same-configuration")
        require(gate["prerequisites"][0]["reason"] == "assumptions_not_allowed", "assumptions decided the gate")
        gate, _ = lab.gate(*unkeyed, 1, "--fail-on-new", "--assume-same-identities", "--assume-same-configuration",
                           "--gate-allow-assumptions")
        require(gate["verified"] is False and gate["relies_on_assumptions"] == ["same_identities",
                                                                                 "same_configuration"],
                "a regression found on assumptions was not labelled as such")
        cases["unkeyed_exit_codes"] = {"no_assumptions": 3, "assumptions_not_allowed": 3, "allowed": 1}

        summary = folder / "step-summary.md"
        gate, printed = lab.gate(fixed, fixed_again, 0, *ALL, "--github-actions", summary=str(summary))
        lines = printed.splitlines()
        token = lines[0].removeprefix("::stop-commands::")
        require(re.fullmatch(r"granttrace-[0-9a-f]{32}", token) is not None and f"::{token}::" in lines,
                "report text was not kept from running as workflow commands")
        require(lines[-1].startswith("::notice title=GrantTrace security gate::Gate passed (exit 0)"),
                "the verified pass was not annotated")
        text = summary.read_text(encoding="utf-8")
        require(text.startswith("## GrantTrace security gate: PASSED (exit 0)") and text.isascii(),
                "the step summary is wrong")
        cases["github_actions_output"] = "stop-commands, notice annotation, step summary"

        if kept.exists():
            shutil.rmtree(kept)
        kept.mkdir(parents=True)
        shutil.copyfile(fixed, kept / "baseline.json")
        shutil.copyfile(fixed_again, kept / "current.json")

    result = {"scans": "read-only scans of the bundled mock on one loopback port, keyed with a random key",
              "cases": cases, "kept_reports": str(kept.relative_to(ROOT))}
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
