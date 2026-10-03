"""Build and install a GrantTrace wheel, then run its CLI outside the source tree."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import venv
from http.server import ThreadingHTTPServer
from pathlib import Path
from email.parser import Parser
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import __version__
from mock_server.server import TargetMockHandler


def run(command, cwd, env):
    result = subprocess.run(
        [str(value) for value in command],
        cwd=str(cwd),
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
    )
    if result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {command}\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheelhouse", type=Path,
        help="Install dependencies offline from this pre-populated wheel directory",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "install-verification.json")
    args = parser.parse_args()
    manifest = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_section = re.search(r"(?ms)^\[project\]\s*\n(.*?)(?=^\[|\Z)", manifest)
    declared_version = (
        re.search(r'^version\s*=\s*"([^"]+)"\s*$', project_section[1], re.MULTILINE)
        if project_section is not None else None
    )
    if declared_version is None or declared_version[1] != __version__:
        raise RuntimeError("pyproject.toml and core.__version__ must agree before building")
    wheel_dir = ROOT / "dist" / "wheel-validation"
    env = dict(os.environ)
    # Neither the installed CLI nor import validation may use the source checkout.
    env.pop("PYTHONPATH", None)
    env["PYTHONUTF8"] = "1"
    # Select only the wheel from this build. Older files in dist cannot affect validation.
    with tempfile.TemporaryDirectory(prefix="granttrace-build-") as build_directory:
        built_dir = Path(build_directory)
        run(
            [sys.executable, "-m", "pip", "wheel", "--no-cache-dir", "--no-build-isolation",
             "--no-deps", ROOT, "--wheel-dir", built_dir],
            ROOT, env,
        )
        wheels = list(built_dir.glob("granttrace-*.whl"))
        if len(wheels) != 1:
            raise RuntimeError("Expected exactly one GrantTrace wheel from the current build")
        with ZipFile(wheels[0]) as archive:
            metadata_files = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(metadata_files) != 1:
                raise RuntimeError("Built wheel does not contain exactly one distribution metadata file")
            wheel_metadata = Parser().parsestr(archive.read(metadata_files[0]).decode("utf-8"))
        if wheel_metadata["Name"] != "granttrace" or wheel_metadata["Version"] != __version__:
            raise RuntimeError("Built wheel metadata disagrees with the GrantTrace release version")
        if wheels[0].name.split("-")[1] != __version__:
            raise RuntimeError("Built wheel filename disagrees with its version metadata")
        wheel_dir.mkdir(parents=True, exist_ok=True)
        wheel = wheel_dir / wheels[0].name
        shutil.copyfile(wheels[0], wheel)
    with tempfile.TemporaryDirectory(prefix="granttrace-installed-") as temporary:
        outside = Path(temporary)
        environment = outside / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        binaries = environment / ("Scripts" if os.name == "nt" else "bin")
        interpreter = binaries / ("python.exe" if os.name == "nt" else "python")
        cli = binaries / ("granttrace.exe" if os.name == "nt" else "granttrace")
        command = [interpreter, "-m", "pip", "install", "--no-cache-dir"]
        if args.wheelhouse:
            command.extend(["--no-index", "--find-links", args.wheelhouse.resolve()])
        run(command + [wheel], outside, env)
        installed = json.loads(run(
            [interpreter, "-c", (
                "import inspect,json,pathlib,sys,api_sentinel,core,yaml; from importlib.metadata import version; "
                "from core.reporter import SecurityReportGenerator; "
                "p=pathlib.Path(api_sentinel.__file__).resolve(); "
                "assert pathlib.Path(sys.prefix).resolve() in p.parents; "
                "assert pathlib.Path(sys.prefix).resolve() in pathlib.Path(core.__file__).resolve().parents; "
                "assert version('granttrace') == core.__version__ == sys.argv[1]; "
                "assert api_sentinel.build_argument_parser().parse_args([]).output == 'granttrace_report.html'; "
                "assert inspect.signature(SecurityReportGenerator.generate).parameters['output_path'].default == 'granttrace_report.html'; "
                "print(json.dumps({'metadata_version':version('granttrace'), "
                "'runtime_version':core.__version__, 'import_path':str(p), 'pyyaml_version':yaml.__version__}))"
            ), __version__],
            outside, env,
        ))
        spec = ROOT / "openapi.json"
        config = ROOT / "config.example.json"
        version = run([cli, "--version"], outside, env)
        if version != f"GrantTrace {__version__}":
            raise RuntimeError("Installed CLI version disagrees with wheel, runtime, and project metadata")
        run([cli, "--spec", spec, "--config", config, "--validate-config"], outside, env)
        # Exercise the installed scanner and its default output outside the checkout.
        TargetMockHandler.reset_database()
        before = copy.deepcopy(TargetMockHandler.DATABASE)
        server = ThreadingHTTPServer(("127.0.0.1", 0), TargetMockHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            scan_file = outside / "installed-result.json"
            run(
                [cli, "--spec", spec, "--config", config,
                 "--target", f"http://127.0.0.1:{server.server_port}",
                 "--delay", "0", "--export-json", scan_file],
                outside, env,
            )
            report_file = outside / "granttrace_report.html"
            if not report_file.is_file() or f">v{__version__}</span>" not in report_file.read_text(encoding="utf-8"):
                raise RuntimeError("Installed scan did not generate a default HTML report with the release version")
            scan = json.loads(scan_file.read_text(encoding="utf-8"))
            if (scan["tool_version"] != __version__ or scan["stats"]["confirmed"] != 1
                    or scan["stats"]["skipped_count"] != 2
                    or scan["stats"]["conclusive_coverage_pct"] != 60.0
                    or before != TargetMockHandler.DATABASE):
                raise RuntimeError("Installed default scan did not match the read-only example")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            TargetMockHandler.reset_database()
        plan_file = outside / "plan.json"
        run(
            [cli, "--spec", spec, "--config", config, "--dry-run", "--export-json", plan_file],
            outside, env,
        )
        plan = json.loads(plan_file.read_text(encoding="utf-8"))
        if plan["requests_sent"] != 0 or any(op["writes_enabled"] for op in plan["operations"]):
            raise RuntimeError("Installed default plan was not read-only and offline")
        yaml_file = outside / "openapi.yaml"
        # Conversion is performed in the new environment, verifying its declared dependency.
        run(
            [interpreter, "-c", (
                "import json,sys,yaml; from pathlib import Path; "
                "Path(sys.argv[2]).write_text(yaml.safe_dump("
                "json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')), "
                "allow_unicode=True, sort_keys=False), encoding='utf-8')"
            ), spec, yaml_file],
            outside, env,
        )
        run([cli, "--spec", yaml_file, "--config", config, "--validate-config"], outside, env)
        yaml_plan = outside / "yaml-plan.json"
        run(
            [cli, "--spec", yaml_file, "--config", config, "--dry-run", "--export-json", yaml_plan],
            outside, env,
        )
        yaml_operations = json.loads(yaml_plan.read_text(encoding="utf-8"))["operations"]
        if sorted(yaml_operations, key=lambda op: op["endpoint"]) != sorted(
            plan["operations"], key=lambda op: op["endpoint"]
        ):
            raise RuntimeError("Installed JSON/YAML plans differ")
        draft = outside / "config.local.json"
        run([cli, "--spec", yaml_file, "--init-config", draft], outside, env)
        blocked = subprocess.run(
            [str(cli), "--spec", str(yaml_file), "--config", str(draft), "--dry-run"],
            cwd=outside, env=env, capture_output=True,
        )
        if blocked.returncode != 2:
            raise RuntimeError("Installed CLI did not block an incomplete draft")
        result = {
            "wheel": wheel.name,
            "python": sys.version.split()[0],
            "version": version,
            "project_version": declared_version[1],
            "wheel_metadata_version": wheel_metadata["Version"],
            "installed_metadata_version": installed["metadata_version"],
            "installed_runtime_version": installed["runtime_version"],
            "version_consistency": True,
            "fresh_build_directory": True,
            "installed_import_checked": True,
            "installed_default_report": report_file.name,
            "installed_cli_and_reporter_defaults_checked": True,
            "installed_readonly_scan": "passed",
            "installed_html_json_versions_checked": True,
            "declared_pyyaml_dependency_installed": True,
            "config_validation": "passed",
            "json_yaml_plan_equivalence": True,
            "offline_plan_requests_sent": plan["requests_sent"],
            "draft_created_and_blocked": True,
            "run_outside_source_tree": True,
            "dependency_install_mode": (
                "offline wheelhouse" if args.wheelhouse else "pip dependency resolution"
            ),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
