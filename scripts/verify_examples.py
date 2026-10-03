"""Validate real JSON/YAML CLI scans and complete mock state restoration."""

from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml
from core import __version__
from api_sentinel import main as cli_main
from mock_server.server import TargetMockHandler


@contextlib.contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-examples", action="store_true")
    args = parser.parse_args()
    output = ROOT / "dist" / "mock-validation"
    output.mkdir(parents=True, exist_ok=True)
    TargetMockHandler.reset_database()
    server = ThreadingHTTPServer(("127.0.0.1", 0), TargetMockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    results = []
    try:
        with tempfile.TemporaryDirectory() as directory:
            yaml_spec = Path(directory) / "openapi.yaml"
            yaml_spec.write_text(
                yaml.safe_dump(
                    json.loads((ROOT / "openapi.json").read_text(encoding="utf-8")),
                    allow_unicode=True,
                ),
                encoding="utf-8",
            )
            for name, spec, active in (
                ("readonly", ROOT / "openapi.json", False),
                ("active-json", ROOT / "openapi.json", True),
                ("active-yaml", yaml_spec, True),
            ):
                before = copy.deepcopy(TargetMockHandler.DATABASE)
                html = output / (name + ".html")
                report = output / (name + ".json")
                run_directory = Path(directory) / name
                run_directory.mkdir()
                default_html = run_directory / "granttrace_report.html"
                command = [
                    "--spec", str(spec),
                    "--target", f"http://127.0.0.1:{server.server_port}",
                    "--config", str(ROOT / "config.example.json"),
                    "--delay", "0",
                    "--export-json", str(report),
                ]
                if active:
                    command += [
                        "--allow-write-tests", "--fail-on-vuln", "--fail-on-error",
                        "--fail-on-suspicious", "--min-coverage", "100",
                    ]
                with working_directory(run_directory), contextlib.redirect_stdout(io.StringIO()):
                    exit_code = cli_main(command)
                if not default_html.is_file():
                    raise RuntimeError("A scan without -o did not create granttrace_report.html")
                html_text = default_html.read_text(encoding="utf-8")
                if f">v{__version__}</span>" not in html_text:
                    raise RuntimeError("Generated HTML report does not declare the runtime version")
                shutil.copyfile(default_html, html)
                data = json.loads(report.read_text(encoding="utf-8"))
                stats = data["stats"]
                status_counts = Counter(item["verdict"] for item in data["results"])
                expected_counts = Counter({"CONFIRMED": 2, "PUBLIC": 1, "SECURE": 2} if active else {
                    "CONFIRMED": 1, "PUBLIC": 1, "SECURE": 1, "SKIPPED": 2,
                })
                expected_stats = {
                    "total_endpoints": 5,
                    "total_checks": 5,
                    "audited_count": 5 if active else 3,
                    "conclusive_count": 5 if active else 3,
                    "confirmed": 2 if active else 1,
                    "bola_confirmed": 1,
                    "mass_assignment_confirmed": 1 if active else 0,
                    "public_endpoints": 1,
                    "authorized_endpoints": 0,
                    "secure_endpoints": 2 if active else 1,
                    "skipped_count": 0 if active else 2,
                    "suspicious_count": 0,
                    "error_count": 0,
                    "inconclusive_count": 0,
                    "coverage_pct": 100.0 if active else 60.0,
                    "conclusive_coverage_pct": 100.0 if active else 60.0,
                }
                restored = before == TargetMockHandler.DATABASE
                if (
                    exit_code != (1 if active else 0)
                    or status_counts != expected_counts
                    or any(stats.get(key) != value for key, value in expected_stats.items())
                    or data["tool_version"] != __version__
                    or not restored
                ):
                    raise RuntimeError(
                        f"Unexpected {name} results: {stats}; restoration={restored}; exit={exit_code}"
                    )
                if active and not next(
                    item for item in data["findings"] if item["cwe"] == "CWE-915"
                )["evidence"]["rollback_verified"]:
                    raise RuntimeError("Mass-assignment rollback was not independently verified")
                results.append({
                    "mode": name,
                    "exit_code": exit_code,
                    "confirmed": stats["confirmed"],
                    "status_counts": dict(sorted(status_counts.items())),
                    "conclusive_coverage_pct": stats["conclusive_coverage_pct"],
                    "default_report": default_html.name,
                    "default_report_created_without_output_option": True,
                    "tool_version": data["tool_version"],
                    "full_database_restored": restored,
                })
                if args.update_examples and name == "active-json":
                    (ROOT / "examples" / "sample_report.html").write_text(
                        html.read_text(encoding="utf-8"), encoding="utf-8",
                    )
                    (ROOT / "examples" / "sample_result.json").write_text(
                        report.read_text(encoding="utf-8"), encoding="utf-8",
                    )
            active_json = json.loads((output / "active-json.json").read_text(encoding="utf-8"))
            active_yaml = json.loads((output / "active-yaml.json").read_text(encoding="utf-8"))
            if active_json["stats"] != active_yaml["stats"]:
                raise RuntimeError("Active JSON/YAML aggregate results differ")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        TargetMockHandler.reset_database()
    (output / "verification.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
