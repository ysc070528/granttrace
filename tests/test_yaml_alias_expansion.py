"""YAML anchors/aliases must not expand a small document exponentially.

Aliases share one parsed node between many references. PyYAML expands merge
keys while constructing objects, and the schema resolver walks every
reference separately, so a document of a few hundred bytes could stall the
parser for minutes. Both local specification files and remote ``$ref``
documents are covered.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import time
import unittest
from pathlib import Path

from api_sentinel import main
from core.parser import OpenAPIParser
from core.remote_refs import RemoteRefFetcher, RemoteRefResolutionError
from core.yaml_safety import (
    MAX_ALIAS_EXPANSION_NODES,
    MAX_ALIAS_EXPANSION_RATIO,
    YAMLAliasExpansionError,
    check_alias_expansion,
    safe_load_yaml,
)


def schema_alias_bomb(levels: int) -> str:
    """About 1 KB at six levels; each level references the previous one ten times."""
    lines = ["openapi: 3.0.3", "info: {title: t, version: '1'}", "components:", "  schemas:",
             "    L0: &l0 {type: object, properties: {a: {type: string}}}"]
    for level in range(1, levels + 1):
        refs = ", ".join(f"p{index}: *l{level - 1}" for index in range(10))
        lines.append(f"    L{level}: &l{level} {{type: object, properties: {{{refs}}}}}")
    lines += ["paths:", "  /x:", "    patch:", "      requestBody:", "        content:",
              "          application/json:", f"            schema: *l{levels}",
              "      responses: {'200': {description: ok}}"]
    return "\n".join(lines) + "\n"


def merge_key_bomb(levels: int) -> str:
    """PyYAML flattens merge keys during construction: about 10x work per level."""
    lines = ["openapi: 3.0.3", "info: {title: t, version: '1'}", "paths: {}", "x-m0: &m0 {k0: v}"]
    for level in range(1, levels + 1):
        merged = ", ".join(f"*m{level - 1}" for _ in range(10))
        lines.append(f"x-m{level}: &m{level} {{<<: [{merged}], k{level}: v}}")
    return "\n".join(lines) + "\n"


ORDINARY_ANCHORS = """\
openapi: 3.0.3
info: {title: anchors, version: '1'}
x-id-parameter: &id-parameter
  name: id
  in: path
  required: true
  schema: {type: string}
x-base-record: &base-record
  type: object
  properties:
    id: {type: string}
paths:
  /users/{id}:
    get:
      parameters: [*id-parameter]
      responses: {'200': {description: ok}}
  /orders/{id}:
    get:
      parameters: [*id-parameter]
      responses: {'200': {description: ok}}
    patch:
      parameters: [*id-parameter]
      requestBody:
        content:
          application/json:
            schema:
              <<: *base-record
              required: [id]
      responses: {'200': {description: ok}}
"""


class LocalSpecificationTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def write(self, text: str, name: str = "openapi.yaml") -> str:
        path = self.directory / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def assert_rejected_quickly(self, text: str, pattern: str) -> None:
        path = self.write(text)
        started = time.perf_counter()
        with self.assertRaisesRegex(YAMLAliasExpansionError, pattern):
            OpenAPIParser(path).get_endpoints()
        self.assertLess(time.perf_counter() - started, 2.0)

    def test_schema_alias_bomb_is_rejected_before_resolution(self) -> None:
        text = schema_alias_bomb(6)
        self.assertLess(len(text), 1200)  # Previously about 13 s of schema resolution.
        self.assert_rejected_quickly(text, "expand")

    def test_merge_key_bomb_is_rejected_before_construction(self) -> None:
        # Eight levels would spend minutes inside yaml.safe_load itself.
        self.assert_rejected_quickly(merge_key_bomb(8), "expand")

    def test_recursive_alias_is_rejected(self) -> None:
        text = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths: {}\nx-loop: &loop [*loop]\n"
        self.assert_rejected_quickly(text, "[Rr]ecursive")

    def test_referenced_yaml_file_is_checked_too(self) -> None:
        self.write(schema_alias_bomb(6).replace("paths:", "x-unused-paths:"), "models.yaml")
        root = self.write(
            "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    patch:\n"
            "      requestBody:\n        content:\n          application/json:\n"
            "            schema: {$ref: 'models.yaml#/components/schemas/L6'}\n"
            "      responses: {'200': {description: ok}}\n"
        )
        started = time.perf_counter()
        with self.assertRaises(ValueError):
            OpenAPIParser(root).get_endpoints()
        self.assertLess(time.perf_counter() - started, 2.0)

    def test_ordinary_anchors_and_merge_keys_still_work(self) -> None:
        endpoints = {f"{ep['method']} {ep['path']}": ep for ep in OpenAPIParser(self.write(ORDINARY_ANCHORS)).get_endpoints()}
        self.assertEqual(set(endpoints), {"GET /users/{id}", "GET /orders/{id}", "PATCH /orders/{id}"})
        for endpoint in endpoints.values():
            self.assertEqual(endpoint["parameters"][0]["name"], "id")
            self.assertEqual(endpoint["parameters"][0]["in"], "path")
        schema = endpoints["PATCH /orders/{id}"]["request_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema["required"], ["id"])
        self.assertIn("id", schema["properties"])

    def test_cli_rejects_bomb_without_sending_requests(self) -> None:
        path = self.write(schema_alias_bomb(6))
        stderr = io.StringIO()
        started = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            code = main(["--spec", path, "--dry-run"])
        self.assertEqual(code, 2)
        self.assertIn("alias", stderr.getvalue())
        self.assertLess(time.perf_counter() - started, 2.0)


class ExpansionRuleTests(unittest.TestCase):
    @staticmethod
    def node(text: str):
        import yaml

        return yaml.compose(text, Loader=yaml.SafeLoader)

    def test_documents_without_aliases_are_never_limited(self) -> None:
        # Expansion counts only nodes that aliases add, not document size.
        text = "[" + ", ".join(str(index) for index in range(500)) + "]"
        check_alias_expansion(self.node(text), limit=0, ratio=0)

    def test_only_alias_added_nodes_count_against_the_limit(self) -> None:
        text = "base: &b [1, 2, 3, 4]\nuses: [*b, *b, *b]"  # Each alias adds 5 nodes: 15 in total.
        check_alias_expansion(self.node(text), limit=15, ratio=0)
        with self.assertRaises(YAMLAliasExpansionError):
            check_alias_expansion(self.node(text), limit=14, ratio=0)

    def test_allowance_scales_with_the_documents_own_size(self) -> None:
        text = "base: &b [1, 2, 3, 4]\nuses: [*b, *b, *b]"  # 9 own nodes, 15 added by aliases.
        check_alias_expansion(self.node(text), limit=0, ratio=2)  # Allows 18.
        with self.assertRaises(YAMLAliasExpansionError):
            check_alias_expansion(self.node(text), limit=0, ratio=1)  # Allows 9.

    def test_tool_generated_reuse_fits_the_ratio_allowance(self) -> None:
        import yaml

        # yaml.safe_dump emits an alias for every repeated Python object, e.g.
        # one shared response schema across many operations.
        shared = {"type": "object", "properties": {f"f{index}": {"type": "string"} for index in range(20)}}
        spec = {"openapi": "3.0.3", "info": {"title": "generated", "version": "1"}, "paths": {
            f"/r{index}": {"get": {"responses": {"200": {"description": "ok", "content": {
                "application/json": {"schema": shared}}}}}} for index in range(300)}}
        node = self.node(yaml.safe_dump(spec))
        # Far more alias-added nodes than a small fixed floor allows ...
        with self.assertRaises(YAMLAliasExpansionError):
            check_alias_expansion(node, limit=1_000, ratio=0)
        # ... yet proportional to the document, so the default ratio accepts it.
        check_alias_expansion(node, limit=1_000)

    def test_default_limit_and_loader_behaviour(self) -> None:
        self.assertEqual(MAX_ALIAS_EXPANSION_NODES, 250_000)
        self.assertEqual(MAX_ALIAS_EXPANSION_RATIO, 10)
        self.assertIsNone(safe_load_yaml(""))
        self.assertEqual(safe_load_yaml("a: &x [1]\nb: *x"), {"a": [1], "b": [1]})
        with self.assertRaises(YAMLAliasExpansionError):
            safe_load_yaml(merge_key_bomb(8))


class RemoteDocumentTests(unittest.TestCase):
    def test_remote_yaml_alias_bomb_fails_closed(self) -> None:
        started = time.perf_counter()
        with self.assertRaisesRegex(RemoteRefResolutionError, "expand"):
            RemoteRefFetcher._parse_schema_content(merge_key_bomb(8), "https://schemas.example.com/models.yaml")
        self.assertLess(time.perf_counter() - started, 2.0)

    def test_remote_yaml_with_ordinary_anchors_still_parses(self) -> None:
        document = RemoteRefFetcher._parse_schema_content(ORDINARY_ANCHORS, "https://schemas.example.com/api.yaml")
        self.assertEqual(document["paths"]["/users/{id}"]["get"]["parameters"][0]["name"], "id")


if __name__ == "__main__":
    unittest.main()
