"""Read GrantTrace's release version from the source tree without importing it.

``pyproject.toml`` (distribution metadata) and ``core/__init__.py`` (runtime
``__version__``) are the two declarations the release workflow checks against
the tag. Everything derived from them, such as the Windows portable package
name, the workflow artifact name and the packaged README banner, reads the
version here instead of repeating a literal, so a version bump cannot leave a
stale copy behind. Run as a script, it prints the verified version.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
# Packaging text files carry this marker; the Windows build replaces it.
VERSION_PLACEHOLDER = "@GRANTTRACE_VERSION@"
_RELEASE_VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")


def runtime_version(root: Path = ROOT) -> str:
    """The literal ``__version__`` assigned in ``core/__init__.py``."""
    tree = ast.parse((root / "core" / "__init__.py").read_text(encoding="utf-8"))
    values = [
        node.value.value for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
        and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
    ]
    if len(values) != 1:
        raise RuntimeError("core/__init__.py must assign __version__ exactly once to a string literal")
    return values[0]


def project_version(root: Path = ROOT) -> str:
    """The static ``[project] version`` in ``pyproject.toml``."""
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.9/3.10: read the one key we need.
        table = re.search(r"(?ms)^\[project\]\s*$(.*?)(?=^\[)", text + "\n[")
        match = re.search(r'(?m)^version\s*=\s*"([^"\n]*)"\s*$', table.group(1) if table else "")
        if not match:
            raise RuntimeError("pyproject.toml must declare a static [project] version") from None
        return match.group(1)
    version = tomllib.loads(text).get("project", {}).get("version")
    if not isinstance(version, str):
        raise RuntimeError("pyproject.toml must declare a static [project] version")
    return version


def source_version(root: Path = ROOT) -> str:
    """Return the release version after checking both declarations agree."""
    project, runtime = project_version(root), runtime_version(root)
    if project != runtime:
        raise RuntimeError(
            f"Version drift: pyproject.toml declares {project!r} but core/__init__.py declares {runtime!r}")
    if not _RELEASE_VERSION.fullmatch(project):
        raise RuntimeError(f"Release version must be MAJOR.MINOR.PATCH, not {project!r}")
    return project


def windows_package_name(version: str) -> str:
    return f"GrantTrace-v{version}-Windows-x64"


def render_versioned_text(text: str, version: str, name: str = "text") -> str:
    """Fill the version marker; refuse a file that lost it or kept a copy."""
    if VERSION_PLACEHOLDER not in text:
        raise RuntimeError(f"{name} must contain {VERSION_PLACEHOLDER} instead of a literal version")
    rendered = text.replace(VERSION_PLACEHOLDER, version)
    if "@GRANTTRACE_" in rendered:
        raise RuntimeError(f"{name} contains an unknown @GRANTTRACE_ marker")
    return rendered


if __name__ == "__main__":
    try:
        print(source_version())
    except (OSError, RuntimeError, SyntaxError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
