"""Build the v2.5.1 Windows x64 folder bundle and ZIP; never publish it."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.5.1"
PACKAGE_NAME = f"GrantTrace-v{VERSION}-Windows-x64"


def check_build_environment() -> None:
    if sys.platform != "win32" or sysconfig.get_platform() != "win-amd64":
        raise RuntimeError("Build with standard Windows x64 CPython, not MinGW or another OS")
    if sys.version_info[:3] != (3, 14, 5):
        raise RuntimeError("Use the documented build interpreter: CPython 3.14.5 x64")
    sys.path.insert(0, str(ROOT))
    from core import __version__

    if __version__ != VERSION or importlib.metadata.version("granttrace") != VERSION:
        raise RuntimeError("Source and installed GrantTrace must both be version 2.5.1")
    if importlib.metadata.version("pyinstaller") != "6.22.3":
        raise RuntimeError("Install packaging/windows/requirements-build.txt before building")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check_x64_executable(executable: Path) -> None:
    with executable.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise RuntimeError("Bundle is missing a Windows executable")
        stream.seek(0x3C)
        pe_offset = struct.unpack("<I", stream.read(4))[0]
        stream.seek(pe_offset)
        if stream.read(4) != b"PE\0\0" or struct.unpack("<H", stream.read(2))[0] != 0x8664:
            raise RuntimeError("granttrace.exe is not an AMD64 Windows executable")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    check_build_environment()
    destination = args.output_dir.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    work_parent = (ROOT / "build" / "windows-portable").resolve()
    if not work_parent.is_relative_to(ROOT):
        raise RuntimeError("Build directory must stay inside the source checkout")
    work_parent.mkdir(parents=True, exist_ok=True)
    archive_path = destination / f"{PACKAGE_NAME}.zip"
    with tempfile.TemporaryDirectory(prefix="bundle-", dir=work_parent) as temporary:
        work = Path(temporary)
        subprocess.run([
            sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--console",
            "--noupx", "--python-option", "X utf8", "--name", "granttrace",
            "--contents-directory", "_internal",
            "--distpath", str(work / "dist"), "--workpath", str(work / "work"),
            "--specpath", str(work), "--paths", str(ROOT),
            "--hidden-import", "core.demo_assets", "--collect-data", "core.demo_assets",
            "--copy-metadata", "granttrace", "--copy-metadata", "PyYAML",
            str(ROOT / "api_sentinel.py"),
        ], cwd=ROOT, env=dict(os.environ, PYINSTALLER_CONFIG_DIR=str(work / "cache")), check=True)
        bundle = work / "dist" / "granttrace"
        executable = bundle / "granttrace.exe"
        check_x64_executable(executable)
        for name in ("Start-Demo.bat", "README.txt"):
            # Produce Windows text consistently even when checkout uses LF.
            text = (ROOT / "packaging" / "windows" / name).read_text(encoding="utf-8")
            (bundle / name).write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
        shutil.copyfile(ROOT / "LICENSE", bundle / "LICENSE")
        licenses = bundle / "LICENSES"
        licenses.mkdir()
        shutil.copyfile(Path(sys.base_prefix) / "LICENSE.txt", licenses / "Python.txt")
        distribution = importlib.metadata.distribution("pyinstaller")
        for path in distribution.files or ():
            if str(path).endswith("licenses/COPYING.txt"):
                shutil.copyfile(distribution.locate_file(path), licenses / "PyInstaller.txt")
                break
        if not (licenses / "PyInstaller.txt").is_file():
            raise RuntimeError("PyInstaller license is missing from the build environment")
        resources = bundle / "_internal" / "core" / "demo_assets"
        for name in ("openapi.json", "demo-config.json", "mock-data.json"):
            if (resources / name).read_bytes() != (ROOT / "core" / "demo_assets" / name).read_bytes():
                raise RuntimeError(f"Bundled demo resource differs from source: {name}")
        # Select this new bundle only, never unrelated wheels, secrets, or old release assets.
        new_archive = work / archive_path.name
        with ZipFile(new_archive, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(bundle.rglob("*")):
                if path.is_symlink():
                    raise RuntimeError(f"Unexpected symlink in bundle: {path.name}")
                if path.is_file():
                    archive.write(path, Path(PACKAGE_NAME) / path.relative_to(bundle))
        shutil.copyfile(new_archive, archive_path)
        digest = sha256(archive_path)
        (destination / "SHA256SUMS.txt").write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True).strip())
        evidence = {
            "version": VERSION, "source_commit": commit, "source_tree_dirty": dirty,
            "platform": platform.platform(),
            "python": platform.python_version(), "pyinstaller": importlib.metadata.version("pyinstaller"),
            "pyinstaller_hooks": importlib.metadata.version("pyinstaller-hooks-contrib"),
            "pyyaml": importlib.metadata.version("PyYAML"), "mode": "onedir", "upx": False,
            "exe_size_bytes": executable.stat().st_size, "exe_sha256": sha256(executable),
            "zip_name": archive_path.name, "zip_size_bytes": archive_path.stat().st_size,
            "zip_sha256": digest,
        }
        (destination / "windows-portable-build.json").write_text(
            json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    print(f"ZIP: {archive_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
