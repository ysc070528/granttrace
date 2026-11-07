"""Offline release regressions for configuration and specification preflight."""

from __future__ import annotations

import builtins
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.generator import SmartDataGenerator
from core.models import HTTPResult


ROOT = Path(__file__).resolve().parents[1]


def readback(**overrides):
    mapping = {"method": "GET", "path": "/items/{id}", "field_map": {"role": "role"}}
    mapping.update(overrides)
    return {"readbacks": {"PATCH /items/{id}": mapping}}


class ReadbackParameterTests(unittest.TestCase):
    def test_mapping_scalar_and_null_parameters_are_rejected(self):
        for value in ({"id": {"in": "path"}}, 42, None, "id"):
            with self.subTest(value=value):
                result = ConfigValidator.validate(readback(parameters=value))
                self.assertFalse(result.is_valid)
                self.assertIn("readbacks.PATCH /items/{id}.parameters", [e.path for e in result.errors])

    def test_parameter_elements_require_name_supported_location_and_schema(self):
        for parameter in ("id", None, {}, {"name": "", "in": "path", "schema": {}},
                          {"name": "id", "in": "header", "schema": {}},
                          {"name": "id", "in": "query", "schema": "string"},
                          {"name": "id\x00", "in": "path", "schema": {}}):
            with self.subTest(parameter=parameter):
                result = ConfigValidator.validate(readback(parameters=[parameter]))
                self.assertFalse(result.is_valid)
                self.assertTrue(any(".parameters[0]" in e.path for e in result.errors))

    def test_duplicate_parameter_pairs_are_rejected(self):
        parameter = {"name": "id", "in": "path", "schema": {"type": "integer"}}
        result = ConfigValidator.validate(readback(parameters=[parameter, parameter]))
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Duplicate readback parameter" in e.message for e in result.errors))

    def test_parameter_values_require_object_and_clean_names(self):
        for value in (42, ["id"], None, "id", {"": "1"}, {"id\n": "1"}):
            with self.subTest(value=value):
                result = ConfigValidator.validate(readback(parameter_values=value))
                self.assertFalse(result.is_valid)
                self.assertTrue(any(".parameter_values" in e.path for e in result.errors))

    def test_valid_parameter_metadata_builds_the_expected_readback_url(self):
        config = readback(
            parameters=[
                {"name": "id", "in": "path", "required": True,
                 "description": "Test resource", "schema": {"type": "integer"}},
                {"name": "view", "in": "query", "deprecated": False,
                 "schema": {"type": "string", "default": "full"}},
            ],
            parameter_values={"id": "7", "view": "summary"},
        )
        self.assertTrue(ConfigValidator.validate(config).is_valid)
        auditor = APISentinelAuditor(str(ROOT / "openapi.json"), "https://example.invalid")
        mapping = config["readbacks"]["PATCH /items/{id}"]
        with patch.object(auditor, "_http_request", return_value=HTTPResult(200, '{}')):
            url, _ = auditor._readback_result(
                {"method": "PATCH", "path": "/items/{id}"}, mapping, "visitor"
            )
        self.assertEqual(url, "https://example.invalid/items/7?view=summary")

    def test_ide_schema_rejects_the_same_unsupported_parameter_shapes(self):
        schema = json.loads((ROOT / "config.schema.json").read_text(encoding="utf-8"))
        parameter_schema = schema["definitions"]["readback_entry"]["properties"]["parameters"]
        for invalid in ({"id": {"in": "path"}}, ["id"], [{}],
                        [{"name": "id", "in": "header", "schema": {}}]):
            with self.subTest(invalid=invalid):
                self.assertFalse(SmartDataGenerator.validate_schema_value(invalid, parameter_schema))
        self.assertTrue(SmartDataGenerator.validate_schema_value(
            [{"name": "id", "in": "path", "schema": {}, "description": "Resource"}],
            parameter_schema,
        ))


class SpecAwarePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.config = self.folder / "config.json"
        self.config.write_text(json.dumps({"identities": {
            "owner": {"headers": {"X-Access": "owner-key"}},
            "visitor": {"headers": {"X-Access": "visitor-key"}},
            "anonymous": {},
        }}), encoding="utf-8")
        self.spec_data = {"openapi": "3.0.3", "paths": {}, "components": {
            "securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-Access"}}
        }}
        self.spec = self.folder / "openapi.json"
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")

    def call_cli(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("socket.socket", side_effect=AssertionError("Network socket opened")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("Network request sent")), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def modes(self, spec=None):
        common = ["--config", str(self.config), "--spec", str(spec or self.spec)]
        return [["--validate-config", *common], ["--dry-run", *common]]

    def test_json_api_key_headers_are_accepted_in_both_modes(self):
        for args in self.modes():
            with self.subTest(args=args):
                code, _, error = self.call_cli(args)
                self.assertEqual(code, 0, error)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML is optional")
    def test_yaml_api_key_headers_are_accepted_in_both_modes(self):
        import yaml
        yaml_spec = self.folder / "openapi.yaml"
        yaml_spec.write_text(yaml.safe_dump(self.spec_data), encoding="utf-8")
        for args in self.modes(yaml_spec):
            with self.subTest(args=args):
                code, _, error = self.call_cli(args)
                self.assertEqual(code, 0, error)

    def test_explicit_missing_spec_returns_error_in_both_modes(self):
        for args in self.modes(self.folder / "missing.json"):
            with self.subTest(args=args):
                code, _, error = self.call_cli(args)
                self.assertEqual(code, 2)
                self.assertIn("Cannot load specification", error)

    def test_explicit_empty_spec_does_not_fall_back_to_default(self):
        for mode in ("--validate-config", "--dry-run"):
            with self.subTest(mode=mode):
                code, _, error = self.call_cli([mode, "--config", str(self.config), "--spec", ""])
                self.assertEqual(code, 2)
                self.assertIn("Cannot load specification", error)

    def test_malformed_spec_returns_error_in_both_modes(self):
        for filename, contents in (("bad.json", "{ invalid"), ("bad.yaml", "openapi: ["),
                                   ("list.json", "[]")):
            spec = self.folder / filename
            spec.write_text(contents, encoding="utf-8")
            for args in self.modes(spec):
                with self.subTest(args=args):
                    code, _, error = self.call_cli(args)
                    self.assertEqual(code, 2)
                    self.assertIn("Cannot load specification", error)

    def test_missing_yaml_dependency_returns_clean_error_in_both_modes(self):
        spec = self.folder / "openapi.yaml"
        spec.write_text("openapi: 3.0.3\npaths: {}\n", encoding="utf-8")
        original_import = builtins.__import__

        def without_yaml(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("PyYAML intentionally unavailable")
            return original_import(name, *args, **kwargs)

        for args in self.modes(spec):
            with self.subTest(args=args), patch("builtins.__import__", side_effect=without_yaml):
                code, _, error = self.call_cli(args)
                self.assertEqual(code, 2)
                self.assertIn("PyYAML", error)

    def test_config_only_validation_works_without_default_spec(self):
        self.config.write_text("{}", encoding="utf-8")
        original_cwd = Path.cwd()
        try:
            os.chdir(self.folder)
            self.spec.unlink()
            code, _, error = self.call_cli(["--validate-config", "--config", str(self.config)])
        finally:
            os.chdir(original_cwd)
        self.assertEqual(code, 0, error)

    def test_malformed_config_is_rejected_before_loading_explicit_spec(self):
        self.config.write_text("{ invalid", encoding="utf-8")
        with patch("api_sentinel.OpenAPIParser", side_effect=AssertionError("Spec loaded first")):
            for args in self.modes(self.folder / "missing.json"):
                with self.subTest(args=args):
                    code, _, error = self.call_cli(args)
                    self.assertEqual(code, 2)
                    self.assertIn("configuration", error.lower())

    def test_malformed_authentication_definitions_return_validation_error(self):
        self.spec_data["components"] = ["invalid"]
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")
        for args in self.modes():
            with self.subTest(args=args):
                code, _, error = self.call_cli(args)
                self.assertEqual(code, 2)
                self.assertIn("Invalid specification authentication definitions", error)

    def test_readback_parameter_errors_are_rejected_before_auditor_creation(self):
        for overrides in ({"parameters": {"id": {"in": "path"}}}, {"parameters": ["id"]},
                          {"parameter_values": 42}):
            self.config.write_text(json.dumps(readback(**overrides)), encoding="utf-8")
            with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
                for args in self.modes():
                    with self.subTest(overrides=overrides, args=args):
                        code, _, error = self.call_cli(args)
                        self.assertEqual(code, 2)
                        self.assertIn("Configuration validation failed", error)

    def test_cli_write_selection_requires_its_own_readback(self):
        self.config.write_text(json.dumps({"write_allowlist": []}), encoding="utf-8")
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
            code, _, error = self.call_cli([
                "--dry-run", "--config", str(self.config), "--spec", str(self.spec),
                "--write-endpoint", "PATCH /selected",
            ])
        self.assertEqual(code, 2)
        self.assertIn("PATCH /selected", error)
        self.assertIn("missing an independent GET readback", error)


if __name__ == "__main__":
    unittest.main()
