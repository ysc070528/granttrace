"""Offline configuration drafts remain blocked until reviewed and completed."""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.config_scaffold import DRAFT_KEY, INPUT_PREFIX, build_config_scaffold, config_needs_input
from core.config_validator import ConfigValidator


class ConfigScaffoldTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.spec = self.folder / "api.json"
        self.output = self.folder / "config.json"
        self.checklist = self.folder / "config.checklist.json"
        self.spec_data = {
            "openapi": "3.0.3",
            "components": {
                "securitySchemes": {"access": {"type": "apiKey", "in": "header", "name": "X-Access"}},
                "parameters": {"id": {"name": "id", "in": "path", "required": True,
                                      "schema": {"type": "integer", "example": 987654321}}},
            },
            "paths": {
                "/items/{id}": {
                    "parameters": [{"$ref": "#/components/parameters/id"}],
                    "get": {"parameters": [
                        {"name": "labels", "in": "query", "required": True,
                         "style": "form", "explode": False, "schema": {"type": "array", "items": {"type": "string"}}},
                        {"name": "view", "in": "query", "schema": {"type": "string", "default": "secret-default"}},
                    ]},
                    "patch": {"requestBody": {"content": {"application/json": {"schema": {
                        "type": "object", "properties": {"role": {"type": "string"}},
                    }}}}},
                    "delete": {},
                },
                "/shared": {"get": {"parameters": [{"name": "X-Account", "in": "header", "required": True,
                                                        "schema": {"type": "string"}}]}},
            },
        }
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")

    def call_cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("socket.socket", side_effect=AssertionError("Network socket opened")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("Network request sent")), \
             patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor constructed")), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def init_args(self, spec=None):
        return ["--spec", str(spec or self.spec), "--init-config", str(self.output)]

    def test_generates_no_requests_and_keeps_write_scope_empty(self):
        code, out, error = self.call_cli(self.init_args())
        self.assertEqual(code, 0, error)
        self.assertIn("Needs user input", out)
        draft = json.loads(self.output.read_text(encoding="utf-8"))
        checklist = json.loads(self.checklist.read_text(encoding="utf-8"))
        self.assertEqual(draft[DRAFT_KEY]["status"], "needs_user_input")
        self.assertEqual(draft["write_allowlist"], [])
        self.assertEqual(draft["bola"], {})
        self.assertEqual(draft["identities"]["owner"]["token"], None)
        self.assertEqual(draft["identities"]["anonymous"]["headers"], {})
        self.assertTrue(config_needs_input(draft))
        self.assertFalse(ConfigValidator.validate(draft, self.spec_data).is_valid)
        self.assertTrue(checklist["offline"])
        self.assertEqual(checklist["status"], "needs_user_input")
        self.assertIn("X-Access", json.dumps(checklist))

    def test_required_resources_and_resolved_metadata_are_listed_without_example_ids(self):
        draft, checklist = build_config_scaffold(str(self.spec))
        values = draft["parameter_values"]["GET /items/{id}"]
        for identity in ("owner", "visitor"):
            self.assertEqual(set(values[identity]), {"id", "labels"})
            self.assertTrue(values[identity]["id"].startswith(INPUT_PREFIX))
        self.assertNotIn("secret-default", json.dumps((draft, checklist)))
        self.assertNotIn("987654321", json.dumps((draft, checklist)))
        operation = next(item for item in checklist["operations"] if item["operation"] == "GET /items/{id}")
        labels = next(p for p in operation["parameters"] if p["name"] == "labels")
        self.assertEqual(labels["style"], "form")
        self.assertFalse(labels["explode"])
        self.assertEqual(labels["type"], "array")

    def test_patch_readback_candidates_require_manual_verification(self):
        draft, checklist = build_config_scaffold(str(self.spec))
        mapping = draft["readbacks"]["PATCH /items/{id}"]
        self.assertTrue(mapping["path"].startswith(INPUT_PREFIX))
        self.assertTrue(mapping["consistency"].startswith(INPUT_PREFIX))
        self.assertEqual(mapping["field_map"], {})
        operation = next(item for item in checklist["operations"] if item["operation"] == "PATCH /items/{id}")
        self.assertEqual(operation["readback_review"]["candidate_get_paths"], ["/items/{id}"])
        self.assertEqual(operation["readback_review"]["candidate_written_fields"], ["role"])
        self.assertTrue(any("strong consistency" in text for text in checklist["limitations"]))

    def test_unsupported_parameters_and_methods_are_explicit(self):
        draft, checklist = build_config_scaffold(str(self.spec))
        header_operation = next(item for item in checklist["operations"] if item["operation"] == "GET /shared")
        header = header_operation["parameters"][0]
        self.assertIn("unsupported", header["needs_review"])
        self.assertFalse(header["included_in_config"])
        delete_operation = next(item for item in checklist["operations"] if item["operation"].startswith("DELETE"))
        self.assertFalse(delete_operation["scan_supported"])
        self.assertNotIn("DELETE /items/{id}", draft["parameter_values"])

    def test_marker_blocks_validation_dry_run_and_scan_before_auditor_creation(self):
        self.assertEqual(self.call_cli(self.init_args())[0], 0)
        for mode in (["--validate-config"], ["--dry-run"], []):
            with self.subTest(mode=mode):
                code, _, error = self.call_cli([*mode, "--config", str(self.output), "--spec", str(self.spec)])
                self.assertEqual(code, 2)
                self.assertIn("draft needs user input", error)

    def test_unresolved_parameter_still_blocks_when_marker_is_removed_and_auth_is_filled(self):
        draft, _ = build_config_scaffold(str(self.spec))
        del draft[DRAFT_KEY]
        draft["readbacks"] = {}
        for identity in ("owner", "visitor"):
            draft["identities"][identity].update({"id": identity, "token": "Bearer " + identity + "-key"})
        self.output.write_text(json.dumps(draft), encoding="utf-8")
        for mode in (["--validate-config"], ["--dry-run"], []):
            code, _, error = self.call_cli([*mode, "--config", str(self.output), "--spec", str(self.spec)])
            self.assertEqual(code, 2)
            self.assertIn("draft needs user input", error)
            self.assertNotIn("owner-key", error)

    def test_existing_config_or_checklist_is_never_overwritten(self):
        for destination in (self.output, self.checklist):
            with self.subTest(destination=destination):
                destination.write_text("original", encoding="utf-8")
                code, _, error = self.call_cli(self.init_args())
                self.assertEqual(code, 2)
                self.assertIn("Refusing to overwrite", error)
                self.assertEqual(destination.read_text(encoding="utf-8"), "original")
                peer = self.checklist if destination == self.output else self.output
                self.assertFalse(peer.exists())
                destination.unlink()

    def test_invalid_spec_creates_no_output(self):
        for spec_text in ("[]", "{bad", json.dumps({"openapi": "3.0.3", "paths": {
            "/items": {"get": {"parameters": [{"$ref": "https://example.invalid/params.json"}]}}
        }})):
            with self.subTest(spec_text=spec_text):
                self.spec.write_text(spec_text, encoding="utf-8")
                self.assertEqual(self.call_cli(self.init_args())[0], 2)
                self.assertFalse(self.output.exists())
                self.assertFalse(self.checklist.exists())

    def test_conflicting_modes_are_rejected_without_creating_files(self):
        for extra in (["--dry-run"], ["--validate-config"], ["--allow-write-tests"],
                      ["--write-endpoint", "PATCH /items/{id}"], ["--config", "existing.json"]):
            with self.subTest(extra=extra):
                code, _, error = self.call_cli([*self.init_args(), *extra])
                self.assertEqual(code, 2)
                self.assertIn("cannot be combined", error)
                self.assertFalse(self.output.exists())

    def test_missing_template_parameter_is_an_explicit_input(self):
        self.spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {"/lost/{resource}": {"get": {}}}}),
                             encoding="utf-8")
        draft, checklist = build_config_scaffold(str(self.spec))
        self.assertIn("resource", draft["parameter_values"]["GET /lost/{resource}"]["owner"])
        self.assertIn("Missing OpenAPI", checklist["operations"][0]["parameters"][0]["needs_review"])

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML is optional")
    def test_yaml_and_json_produce_equivalent_scaffolds(self):
        import yaml
        yaml_spec = self.folder / "api.yaml"
        yaml_spec.write_text(yaml.safe_dump(self.spec_data, sort_keys=False), encoding="utf-8")
        self.assertEqual(build_config_scaffold(str(self.spec)), build_config_scaffold(str(yaml_spec)))
        code, _, error = self.call_cli(self.init_args(yaml_spec))
        self.assertEqual(code, 0, error)

    def test_placeholder_detection_handles_deep_mappings_without_recursion(self):
        config = {}
        cursor = config
        for _ in range(2000):
            cursor["nested"] = {}
            cursor = cursor["nested"]
        cursor["resource"] = INPUT_PREFIX + "resource"
        self.assertTrue(config_needs_input(config))
        self.assertFalse(config_needs_input({"identities": {"owner": {"token": "Bearer owner"}}}))


if __name__ == "__main__":
    unittest.main()
