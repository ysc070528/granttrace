"""Build and install a GrantTrace wheel, then run its CLI outside the source tree."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
    wheel_dir = ROOT / "dist" / "wheel-validation"
    wheel_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    # Neither the installed CLI nor import validation may use the source checkout.
    env.pop("PYTHONPATH", None)
    env["PYTHONUTF8"] = "1"
    run(
        [sys.executable, "-m", "pip", "wheel", "--no-cache-dir", "--no-build-isolation",
         "--no-deps", ROOT, "--wheel-dir", wheel_dir],
        ROOT, env,
    )
    wheels = list(wheel_dir.glob("granttrace-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("Expected exactly one current GrantTrace wheel in dist/wheel-validation")
    wheel = wheels[0]
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
        run(
            [interpreter, "-c", (
                "import pathlib,sys,api_sentinel,yaml; from importlib.metadata import version; "
                "p=pathlib.Path(api_sentinel.__file__).resolve(); "
                "assert pathlib.Path(sys.prefix).resolve() in p.parents; "
                "print(version('granttrace')); print(p); print(yaml.__version__)"
            )],
            outside, env,
        )
        spec = ROOT / "openapi.json"
        config = ROOT / "config.example.json"
        version = run([cli, "--version"], outside, env)
        run([cli, "--spec", spec, "--config", config, "--validate-config"], outside, env)
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
            "installed_import_checked": True,
            "declared_pyyaml_dependency_installed": True,
            "config_validation": "passed",
            "json_yaml_plan_equivalence": True,
            "requests_sent": plan["requests_sent"],
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
