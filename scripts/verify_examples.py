"""Validate real JSON/YAML CLI scans and complete mock state restoration."""

from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml
from api_sentinel import main as cli_main
from mock_server.server import TargetMockHandler


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
                command = [
                    "--spec", str(spec),
                    "--target", f"http://127.0.0.1:{server.server_port}",
                    "--config", str(ROOT / "config.example.json"),
                    "--delay", "0",
                    "--output", str(html),
                    "--export-json", str(report),
                ]
                if active:
                    command += [
                        "--allow-write-tests", "--fail-on-vuln", "--fail-on-error",
                        "--fail-on-suspicious", "--min-coverage", "100",
                    ]
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = cli_main(command)
                data = json.loads(report.read_text(encoding="utf-8"))
                stats = data["stats"]
                restored = before == TargetMockHandler.DATABASE
                if (
                    exit_code != (1 if active else 0)
                    or stats["confirmed"] != (2 if active else 1)
                    or not restored
                    or stats["error_count"]
                    or stats["inconclusive_count"]
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
                    "conclusive_coverage_pct": stats["conclusive_coverage_pct"],
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
