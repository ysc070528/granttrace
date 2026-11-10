"""End-to-end output snapshots: the safety net for behavior-preserving refactors.

Each test scans the bundled mock target through the CLI and compares the JSON
report, the HTML report and the console output with committed snapshots in
tests/snapshots/, after replacing run-specific values: generation time, elapsed
seconds, the loopback port, temporary paths and the version string. Trailing
whitespace in HTML lines is dropped so the snapshot passes `git diff --check`.

A refactor must leave every snapshot unchanged. A deliberate output change
regenerates them, and the snapshot diff is reviewed with the change:

    GRANTTRACE_UPDATE_SNAPSHOTS=1 python -m pytest tests/test_output_snapshot.py
"""

from __future__ import annotations

import contextlib
import difflib
import io
import json
import os
import re
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

from api_sentinel import main
from core import __version__
from mock_server.server import TargetMockHandler

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"
UPDATE = os.environ.get("GRANTTRACE_UPDATE_SNAPSHOTS") == "1"
VERSION = re.compile(rf"(?<![\d.]){re.escape(__version__)}(?![\d.])")


def _scan(*, write_tests: bool, workers: int) -> Dict[str, Any]:
    """Run one CLI scan of a fresh mock target and return its raw outputs."""
    TargetMockHandler.reset_database()
    server = ThreadingHTTPServer(("127.0.0.1", 0), TargetMockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="granttrace-snapshot-") as directory:
            json_path = Path(directory) / "report.json"
            html_path = Path(directory) / "report.html"
            target = f"http://127.0.0.1:{server.server_port}"
            argv = [
                "--spec", str(ROOT / "openapi.json"),
                "--target", target,
                "--config", str(ROOT / "config.example.json"),
                "--delay", "0",
                "--workers", str(workers),
                "--export-json", str(json_path),
                "-o", str(html_path),
            ]
            if write_tests:
                argv.append("--allow-write-tests")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = main(argv)
            raw = {
                "json": json_path.read_text(encoding="utf-8"),
                "html": html_path.read_text(encoding="utf-8"),
                "console": (f"exit code: {exit_code}\n--- stdout ---\n{stdout.getvalue()}"
                            f"--- stderr ---\n{stderr.getvalue()}"),
            }
            replacements = [(target, "http://127.0.0.1:<port>")]
            for path in {os.path.realpath(directory), directory}:
                replacements.append((path, "<tmp>"))
            return {name: _replace(text, replacements) for name, text in raw.items()}
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _replace(text: str, replacements: List[tuple]) -> str:
    for old, new in replacements:
        text = text.replace(old, new)
    text = text.replace("<tmp>\\", "<tmp>/")
    return VERSION.sub("<version>", text)


def _normalise_json(text: str, *, sort_results: bool = False) -> str:
    report = json.loads(text)
    report["generated_at"] = "<generated_at>"
    report["elapsed_seconds"] = "<elapsed_seconds>"
    if sort_results:
        for key in ("results", "findings"):
            report[key] = sorted(report[key], key=lambda item: json.dumps(item, sort_keys=True))
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def _normalise_html(text: str) -> str:
    text = re.sub(r"生成时间：[^<]*", "生成时间：<generated_at>", text)
    return "\n".join(line.rstrip() for line in text.splitlines()) + "\n"


def _snapshot_outputs(raw: Dict[str, str]) -> Dict[str, str]:
    return {
        "json": _normalise_json(raw["json"]),
        "html": _normalise_html(raw["html"]),
        "txt": raw["console"],
    }


class OutputSnapshotTests(unittest.TestCase):
    maxDiff = None

    def assert_matches_snapshot(self, name: str, suffix: str, actual: str) -> None:
        path = SNAPSHOTS / f"{name}.{suffix}"
        if UPDATE:
            SNAPSHOTS.mkdir(exist_ok=True)
            path.write_text(actual, encoding="utf-8", newline="\n")
        self.assertTrue(path.is_file(), f"missing snapshot {path.name}; see the module docstring")
        expected = path.read_text(encoding="utf-8")
        if actual != expected:
            diff = "".join(difflib.unified_diff(
                expected.splitlines(keepends=True), actual.splitlines(keepends=True),
                fromfile=f"snapshots/{path.name}", tofile="this run", n=2,
            ))
            self.fail(f"output differs from snapshots/{path.name}:\n{diff[:6000]}")

    def check_scan(self, name: str, *, write_tests: bool) -> None:
        outputs = _snapshot_outputs(_scan(write_tests=write_tests, workers=1))
        for suffix, actual in outputs.items():
            with self.subTest(snapshot=f"{name}.{suffix}"):
                self.assert_matches_snapshot(name, suffix, actual)

    def test_read_only_scan(self) -> None:
        self.check_scan("mock_read_only", write_tests=False)

    def test_write_tests_requested_scan(self) -> None:
        # External PATCH tests stay blocked without authoritative state, so this
        # snapshot records that the request is refused before any write.
        self.check_scan("mock_write_tests_requested", write_tests=True)

    def test_parallel_scan_differs_only_in_result_order(self) -> None:
        if UPDATE:
            self.skipTest("snapshots are written by the single-worker scans")
        raw = _scan(write_tests=False, workers=4)
        expected = (SNAPSHOTS / "mock_read_only.json").read_text(encoding="utf-8")
        self.assertEqual(
            _normalise_json(raw["json"], sort_results=True),
            _normalise_json(expected, sort_results=True),
        )
        self.assertEqual(raw["console"], (SNAPSHOTS / "mock_read_only.txt").read_text(encoding="utf-8"))

    def test_normalisation_keeps_verdicts_and_reasons(self) -> None:
        # The replacements must never hide what a refactor could change.
        if UPDATE:
            self.skipTest("snapshots are being rewritten")
        report = json.loads((SNAPSHOTS / "mock_read_only.json").read_text(encoding="utf-8"))
        self.assertEqual(report["generated_at"], "<generated_at>")
        self.assertTrue(report["results"])
        for result in report["results"]:
            self.assertTrue(result["verdict"])
            self.assertTrue(result["reason"])
            self.assertNotIn("<", result["reason"])


if __name__ == "__main__":
    unittest.main()
