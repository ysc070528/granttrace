"""Validate the real Windows ZIP without exposing Python or the checkout to it."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from zipfile import ZipFile


VERSION = "2.5.1"
PACKAGE = f"GrantTrace-v{VERSION}-Windows-x64"
ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def isolated_environment():
    environment = dict(os.environ)
    for key in tuple(environment):
        if key.upper().startswith("PYTHON") or key.upper() in {
            "VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_DEFAULT_ENV",
        }:
            environment.pop(key)
    windows = Path(os.environ["SystemRoot"])
    environment["PATH"] = os.pathsep.join((str(windows / "System32"), str(windows)))
    environment.update(
        GRANTTRACE_DEMO_NO_OPEN="1",
        HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1", NO_PROXY="",
        http_proxy="http://127.0.0.1:1", https_proxy="http://127.0.0.1:1", no_proxy="",
    )
    return environment


def run(command, directory, environment, expected_returncode=0):
    result = subprocess.run(
        [str(item) for item in command], cwd=directory, env=environment,
        input="\n", text=True, encoding="utf-8",
        capture_output=True, timeout=120,
    )
    require(result.returncode == expected_returncode,
            f"Unexpected exit {result.returncode}: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def extract_package(archive_path, destination):
    with ZipFile(archive_path) as archive:
        seen = set()
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            require(
                bool(path.parts) and path.parts[0] == PACKAGE and not path.is_absolute()
                and ".." not in path.parts and "\\" not in entry.filename
                and not any(":" in part for part in path.parts)
                and not stat.S_ISLNK(entry.external_attr >> 16),
                f"Unsafe or unexpected ZIP entry: {entry.filename}",
            )
            normalized = str(path).casefold()
            require(normalized not in seen, f"Duplicate ZIP entry: {entry.filename}")
            seen.add(normalized)
        archive.extractall(destination)
    package = destination / PACKAGE
    for name in ("granttrace.exe", "Start-Demo.bat", "README.txt", "LICENSE"):
        require((package / name).is_file(), f"Portable ZIP is missing {name}")
    return package


def package_processes(package):
    """Find surviving process images inside this extracted package, without killing any."""
    class ProcessEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for name in ("Process32FirstW", "Process32NextW"):
        function = getattr(kernel, name)
        function.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry))
        function.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    )
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    require(snapshot != ctypes.c_void_p(-1).value, "Could not enumerate Windows processes")
    remaining = []
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        found = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        require(bool(found), "Could not read Windows process snapshot")
        while found:
            process = kernel.OpenProcess(0x1000, False, entry.th32ProcessID)
            if process:
                try:
                    buffer = ctypes.create_unicode_buffer(32768)
                    size = wintypes.DWORD(len(buffer))
                    if kernel.QueryFullProcessImageNameW(process, 0, buffer, ctypes.byref(size)):
                        image_path = Path(buffer.value).resolve()
                        if image_path.is_relative_to(package.resolve()):
                            remaining.append({"pid": entry.th32ProcessID, "image": str(image_path)})
                finally:
                    kernel.CloseHandle(process)
            found = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return remaining


def verify_report(directory, read_only, output):
    reports = list(directory.rglob("granttrace_report.json"))
    require(len(reports) == 1, f"Expected exactly one demo JSON in {directory}; found {len(reports)}")
    report_path = reports[0]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    html_path = report_path.with_suffix(".html")
    require(html_path.is_file(), "Demo HTML report is missing")
    require(f">v{VERSION}</span>" in html_path.read_text(encoding="utf-8"), "Demo HTML version is wrong")
    require(report["tool_version"] == VERSION and report["report_schema_version"] == 2, "Wrong JSON version")
    expected_stats = {
        "bola_confirmed": 1, "mass_assignment_confirmed": 0 if read_only else 1,
        "error_count": 0, "inconclusive_count": 0, "suspicious_count": 0,
    }
    require(all(report["stats"][key] == value for key, value in expected_stats.items()), "Unexpected demo stats")
    verification = report["demo"]
    require(verification["read_only"] is read_only, "Wrong demo mode")
    for key in ("database_restored", "server_stopped", "target_bound_to_loopback"):
        require(verification[key] is True, f"Demo verification failed: {key}")
    require(verification["user_agents"] == [f"GrantTrace/{VERSION}"], "Wrong HTTP User-Agent")
    require(
        verification["request_methods"] == (["GET"] if read_only else ["GET", "PATCH"]),
        "Demo sent unexpected HTTP methods",
    )
    require(
        verification["rollback_verified"] is (None if read_only else True),
        "Demo rollback evidence is wrong",
    )
    if not read_only:
        evidence = next(item for item in report["findings"] if item["cwe"] == "CWE-915")["evidence"]
        require(
            evidence["rollback_verified"] is True and evidence["recovery_sent"] is True
            and evidence["readback_url"] != evidence["target_url"]
            and evidence["readback_consistency"] == "strong"
            and evidence["after"]["status"] == 200 and evidence["restored"]["status"] == 200,
            "Active demo did not retain independent persistence and rollback evidence",
        )
    require("Demo completed successfully." in output, "Demo success message is missing")
    require(
        str(html_path.resolve()) in output and str(report_path.resolve()) in output,
        "Demo output did not preserve its complete report paths",
    )
    target = urlsplit(report["target"])
    require(target.scheme == "http" and target.hostname == "127.0.0.1" and target.port, "Unexpected demo target")
    try:
        connection = socket.create_connection((target.hostname, target.port), timeout=1)
    except OSError:
        pass
    else:
        connection.close()
        raise RuntimeError("Demo left its loopback server listening")
    return {
        "stats": expected_stats, "demo": verification, "html_report_generated": True,
        "json_report_generated": True, "report_paths_preserved_in_console_output": True,
        "loopback_port_closed_independently": True,
    }


def verify_yaml_plan(executable, directory, environment):
    specification = directory / "portable.yaml"
    specification.write_text(
        "openapi: 3.0.3\ninfo:\n  title: Portable smoke\n  version: '1'\n"
        "paths:\n  /ping:\n    get:\n      security: []\n      responses:\n"
        "        '200':\n          description: Public response\n", encoding="utf-8",
    )
    configuration = directory / "portable-config.json"
    configuration.write_text(json.dumps({
        "identities": {
            "owner": {"id": "1", "token": "Bearer portable-smoke-owner"},
            "visitor": {"id": "2", "token": "Bearer portable-smoke-visitor"},
            "anonymous": {"id": None, "token": None},
        },
        "write_allowlist": [], "bola": {"GET /ping": {"expected_public": True}},
    }), encoding="utf-8")
    plan_path = directory / "portable-plan.json"
    run([
        executable, "--spec", specification, "--config", configuration,
        "--dry-run", "--export-json", plan_path,
    ], directory, environment)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    require(
        plan["requests_sent"] == 0 and len(plan["operations"]) == 1
        and not any(item["writes_enabled"] for item in plan["operations"]),
        "Packaged YAML plan did not stay offline and read-only",
    )
    return {"yaml_loaded": True, "requests_sent": 0, "writes_enabled": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", type=Path, required=True, help="The already-built Windows portable ZIP")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "windows-portable-verification.json")
    arguments = parser.parse_args()
    require(os.name == "nt" and platform.machine().lower() in {"amd64", "x86_64"}, "Use Windows x64")
    archive_path = arguments.zip.resolve()
    environment = isolated_environment()
    cmd = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
    started = time.monotonic()
    results = []
    with tempfile.TemporaryDirectory(prefix="granttrace-portable-") as temporary:
        outside = Path(temporary).resolve()
        require(not outside.is_relative_to(ROOT), "Portable verification must run outside the source checkout")
        for label, suffix in (
            ("spaces", Path("Test User") / "Desktop" / "GrantTrace v2.5.1"),
            ("chinese_and_spaces", Path("安全工具") / "GrantTrace 测试"),
        ):
            destination = outside / suffix
            destination.mkdir(parents=True)
            package = extract_package(archive_path, destination)
            executable = package / "granttrace.exe"
            working = outside / (label + "-empty-cwd")
            working.mkdir()
            version = run([executable, "--version"], working, environment).strip()
            require(version == f"GrantTrace {VERSION}", "Packaged CLI changed the existing --version output")
            help_output = run([executable, "--help"], working, environment)
            require(all(value in help_output for value in ("--spec", "--version", "granttrace demo")), "CLI help is wrong")
            active = run([executable, "demo"], working, environment)
            active_result = verify_report(working / "granttrace-demo", False, active)
            readonly = run([executable, "demo", "--read-only", "--output-dir", "readonly"], working, environment)
            readonly_result = verify_report(working / "readonly", True, readonly)
            yaml_result = verify_yaml_plan(executable, working, environment)
            launcher = run([cmd, "/d", "/c", "call", package / "Start-Demo.bat"], working, environment)
            launcher_result = verify_report(package / "granttrace-demo", False, launcher)
            remaining = package_processes(package)
            require(not remaining, f"Portable package left background processes: {remaining}")
            results.append({
                "path_test": label, "extraction_path": str(package), "working_directory": str(working),
                "version_output": version, "help_exit_code": 0,
                "active_demo": active_result, "readonly_demo": readonly_result, "yaml_plan": yaml_result,
                "start_demo_bat": launcher_result, "package_processes_remaining": remaining,
            })
        missing = outside / "missing exe 错误路径"
        missing.mkdir()
        shutil.copyfile(package / "Start-Demo.bat", missing / "Start-Demo.bat")
        failure_output = run([cmd, "/d", "/c", "call", missing / "Start-Demo.bat"], outside, environment, 2)
        require(
            "[错误]" in failure_output and "granttrace.exe" in failure_output and "按任意键" in failure_output,
            "Missing-exe launcher failure did not explain the error and retain its pause prompt",
        )
    result = {
        "version": VERSION, "zip": archive_path.name,
        "zip_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "source_checkout_not_on_child_path": True, "python_not_on_child_path": True,
        "existing_python_environment_variables_cleared": True,
        "outside_source_checkout": True, "environment_proxy_bypassed": True,
        "launcher_pause_acknowledged_via_stdin": True, "launcher_browser_open_suppressed_for_smoke": True,
        "missing_exe_launcher_returns_error": True,
        "process_check_scope": "Accessible Windows process images under each extracted package directory",
        "path_tests": results, "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Windows portable verified: {archive_path.name}\nEvidence: {arguments.output.resolve()}")


if __name__ == "__main__":
    main()
