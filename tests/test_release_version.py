"""The release version has one source, and nothing derived from it drifts.

``pyproject.toml`` and ``core/__init__.py`` are the two declarations the
release workflow checks against the tag. The Windows portable build, its
verifier, its workflow and the packaged README/launcher derive the version
from them. A hard-coded copy once broke the Windows build after a version bump.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import core


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_script(name: str):
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(f"_granttrace_script_{name}", SCRIPTS / f"{name}.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPTS))


source_version = _load_script("source_version")
# Any MAJOR.MINOR.PATCH directly after a GrantTrace product label.
LITERAL_PRODUCT_VERSION = re.compile(r"GrantTrace[ -]v?\d+\.\d+\.\d+")


def _source_tree(root: Path, project: str, runtime: str) -> Path:
    (root / "core").mkdir()
    (root / "pyproject.toml").write_text(
        f'[build-system]\nrequires = ["setuptools"]\n\n[project]\nname = "granttrace"\nversion = "{project}"\n'
        '\n[tool.other]\nversion = "9.9.9"\n', encoding="utf-8")
    (root / "core" / "__init__.py").write_text(f'"""Core."""\n\n__version__ = "{runtime}"\n', encoding="utf-8")
    return root


class SourceVersionTests(unittest.TestCase):
    def test_project_metadata_and_runtime_declare_the_same_version(self):
        self.assertEqual(source_version.project_version(ROOT), core.__version__)
        self.assertEqual(source_version.runtime_version(ROOT), core.__version__)
        self.assertEqual(source_version.source_version(ROOT), core.__version__)

    def test_drift_between_declarations_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = _source_tree(Path(folder), "2.7.0", "2.6.0")
            with self.assertRaisesRegex(RuntimeError, r"drift.*'2\.7\.0'.*'2\.6\.0'"):
                source_version.source_version(root)

    def test_only_release_versions_are_accepted(self):
        for version in ("2.7.0.dev1", "2.7", "v2.7.0", "02.7.0", ""):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as folder:
                root = _source_tree(Path(folder), version, version)
                with self.assertRaises(RuntimeError):
                    source_version.source_version(root)

    def test_runtime_version_must_be_one_literal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = _source_tree(Path(folder), "2.7.0", "2.7.0")
            (root / "core" / "__init__.py").write_text('__version__ = "2.7.0"\n__version__ = "2.8.0"\n',
                                                        encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exactly once"):
                source_version.runtime_version(root)
            (root / "core" / "__init__.py").write_text("__version__ = VERSION\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exactly once"):
                source_version.runtime_version(root)

    def test_project_version_without_tomllib_reads_only_the_project_table(self):
        with tempfile.TemporaryDirectory() as folder:
            root = _source_tree(Path(folder), "2.7.0", "2.7.0")
            with mock.patch.dict(sys.modules, {"tomllib": None}):
                self.assertEqual(source_version.project_version(root), "2.7.0")
            (root / "pyproject.toml").write_text('[project]\nname = "granttrace"\ndynamic = ["version"]\n',
                                                 encoding="utf-8")
            with mock.patch.dict(sys.modules, {"tomllib": None}), self.assertRaises(RuntimeError):
                source_version.project_version(root)

    def test_versioned_text_requires_the_marker(self):
        marker = source_version.VERSION_PLACEHOLDER
        self.assertEqual(source_version.render_versioned_text(f"GrantTrace v{marker}\n", "2.7.0"),
                         "GrantTrace v2.7.0\n")
        with self.assertRaisesRegex(RuntimeError, "instead of a literal version"):
            source_version.render_versioned_text("GrantTrace v2.6.0\n", "2.7.0", "README.txt")
        with self.assertRaisesRegex(RuntimeError, "unknown"):
            source_version.render_versioned_text(f"{marker} @GRANTTRACE_DATE@", "2.7.0")


class WindowsPortableVersionTests(unittest.TestCase):
    def test_packaged_text_files_carry_the_marker_not_a_version(self):
        for name in ("README.txt", "Start-Demo.bat"):
            with self.subTest(file=name):
                text = (ROOT / "packaging" / "windows" / name).read_text(encoding="utf-8")
                self.assertIn(f"GrantTrace v{source_version.VERSION_PLACEHOLDER}", text)
                self.assertIsNone(LITERAL_PRODUCT_VERSION.search(text))
                rendered = source_version.render_versioned_text(text, core.__version__, name)
                self.assertIn(f"GrantTrace v{core.__version__}", rendered)

    def test_build_and_verify_scripts_derive_the_version(self):
        for name in ("build_windows_portable.py", "verify_windows_portable.py"):
            with self.subTest(script=name):
                text = (SCRIPTS / name).read_text(encoding="utf-8")
                self.assertIn("VERSION = source_version(ROOT)", text)
                self.assertIsNone(re.search(r"""VERSION\s*=\s*["']""", text))
                self.assertIsNone(LITERAL_PRODUCT_VERSION.search(text))
                self.assertNotIn(f'"{core.__version__}"', text)

    def test_build_script_names_the_package_after_the_source_version(self):
        build = _load_script("build_windows_portable")
        self.assertEqual(build.VERSION, core.__version__)
        self.assertEqual(build.PACKAGE_NAME, f"GrantTrace-v{core.__version__}-Windows-x64")

    def test_workflow_uses_the_resolved_version_everywhere(self):
        text = (ROOT / ".github" / "workflows" / "windows-package.yml").read_text(encoding="utf-8")
        self.assertIn("python scripts/source_version.py", text)
        self.assertIsNone(LITERAL_PRODUCT_VERSION.search(text))
        # The verified ZIP, the uploaded file and the artifact name all follow the source.
        self.assertEqual(text.count("GrantTrace-v${{ steps.version.outputs.version }}-Windows-x64"), 3)


if __name__ == "__main__":
    unittest.main()
