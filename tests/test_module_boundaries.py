"""Production modules use each other's public names only.

Modules reached into each other's private members (CLI and demo read
``auditor._secret_values``; authorization and BOPLA called underscored helpers
of ResponseDiffEngine and AuthorizationEvidence; parameters and configuration
validation called SmartDataGenerator internals). Those members are public now.
This test keeps it that way, so a refactor can move private code freely.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path
from typing import List, Set

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = sorted((ROOT / "core").glob("*.py")) + [ROOT / "api_sentinel.py"]
# Local names that hold another module's object rather than an imported name.
FOREIGN_INSTANCES = {"auditor"}


def _imported_core_names(tree: ast.Module) -> Set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("core"):
            names.update(alias.asname or alias.name for alias in node.names)
    return names


def private_accesses(source: str, label: str) -> List[str]:
    tree = ast.parse(source)
    foreign = _imported_core_names(tree) | FOREIGN_INSTANCES
    found = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id in foreign
                and node.attr.startswith("_") and not node.attr.startswith("__")):
            found.append((node.lineno, f"{label}:{node.lineno}: {node.value.id}.{node.attr}"))
    return [text for _, text in sorted(found)]


class ModuleBoundaryTests(unittest.TestCase):
    def test_no_module_uses_another_modules_private_members(self) -> None:
        found = [item for path in PRODUCTION
                 for item in private_accesses(path.read_text(encoding="utf-8"),
                                              path.relative_to(ROOT).as_posix())]
        self.assertEqual(found, [])

    def test_detects_a_private_access(self) -> None:
        source = ("from core.diff import ResponseDiffEngine\n"
                  "ResponseDiffEngine._assess_response(200, '{}')\n"
                  "auditor._secret_values\n"
                  "self._own_member, ResponseDiffEngine.__name__\n")
        self.assertEqual(private_accesses(source, "probe.py"), [
            "probe.py:2: ResponseDiffEngine._assess_response",
            "probe.py:3: auditor._secret_values",
        ])

    def test_public_replacements_exist(self) -> None:
        from core.auditor import APISentinelAuditor
        from core.authorization import AuthorizationEvidence
        from core.diff import ResponseDiffEngine
        from core.generator import SmartDataGenerator

        for owner, names in (
            (ResponseDiffEngine, ("assess_response", "assessment_evidence", "normalise_key",
                                  "is_request_metadata_key", "denial_body_is_clean")),
            (AuthorizationEvidence, ("assess", "valid", "private_values", "clean_denial")),
            (SmartDataGenerator, ("parameter_schema", "is_resource_identifier")),
            (APISentinelAuditor, ("secret_values", "identity_headers")),
        ):
            for name in names:
                with self.subTest(owner=owner.__name__, name=name):
                    self.assertTrue(callable(getattr(owner, name)))
                    self.assertFalse(hasattr(owner, "_" + name))


if __name__ == "__main__":
    unittest.main()
