"""Offline operation and explicit-parameter checks against the selected contract."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.config_validator import ConfigValidator


class SpecConfigCrossCheckTests(unittest.TestCase):
    def setUp(self):
        self.spec = {
            "openapi": "3.0.3",
            "paths": {
                "/items/{id}": {
                    "parameters": [{"$ref": "#/components/parameters/item_id"}],
                    "get": {"responses": {"200": {"description": "Item"}}},
                    "patch": {"responses": {"200": {"description": "Updated"}}},
                },
                "/status/{id}": {
                    "get": {
                        "parameters": [{"$ref": "#/components/parameters/item_id"}],
                        "responses": {"200": {"description": "Readback"}},
                    },
                },
                "/search": {
                    "get": {
                        "parameters": [
                            {"name": "view", "in": "query", "schema": {"type": "string", "enum": ["summary"]}},
                            {"name": "ids", "in": "query", "schema": {
                                "type": "array", "items": {"type": "integer", "minimum": 1}, "minItems": 1,
                            }},
                        ],
                        "responses": {"200": {"description": "Results"}},
                    },
                },
            },
            "components": {"parameters": {"item_id": {
                "name": "id", "in": "path", "required": True,
                "schema": {"type": "integer", "minimum": 1, "maximum": 9},
            }}},
        }

    @staticmethod
    def readback(path="/status/{id}", **overrides):
        return {"method": "GET", "path": path, "field_map": {"role": "role"},
                "consistency": "strong", **overrides}

    def test_unknown_operations_fail_in_each_configuration_section(self):
        configs = (
            {"write_allowlist": ["PATCH /missing"], "readbacks": {
                "PATCH /missing": self.readback(),
            }},
            {"bola": {"GET /missing": {"expected_visitor_access": "allow"}}},
            {"parameter_values": {"GET /missing": {"id": 1}}},
            {"readbacks": {"PATCH /missing": self.readback()}},
        )
        for config in configs:
            with self.subTest(config=config):
                result = ConfigValidator.validate(config, self.spec)
                self.assertFalse(result.is_valid)
                self.assertTrue(any("not declared in the selected specification" in issue.message
                                    for issue in result.errors))

    def test_config_only_validation_does_not_claim_unknown_operations_are_checked(self):
        result = ConfigValidator.validate({"bola": {"GET /missing": {"expected_public": True}}})
        self.assertTrue(result.is_valid)

    def test_internal_parameter_reference_accepts_native_value_and_rejects_type_and_bounds(self):
        for value, expected in ((1, True), (9, True), ("1", False), (True, False), (0, False), (10, False)):
            with self.subTest(value=value):
                result = ConfigValidator.validate({"parameter_values": {"GET /items/{id}": {"id": value}}}, self.spec)
                self.assertEqual(result.is_valid, expected)
                if not expected:
                    self.assertIn("parameter_values.GET /items/{id}.id", [issue.path for issue in result.errors])

    def test_explicit_query_enum_and_array_items_are_checked(self):
        for values, expected in (({"view": "summary", "ids": [1, 2]}, True),
                                 ({"view": "detail"}, False), ({"ids": [0]}, False), ({"ids": []}, False)):
            with self.subTest(values=values):
                result = ConfigValidator.validate({"parameter_values": {"GET /search": values}}, self.spec)
                self.assertEqual(result.is_valid, expected)

    def test_boolean_parameter_schema_cannot_be_silently_replaced_by_empty_constraints(self):
        spec = copy.deepcopy(self.spec)
        for schema, expected in ((False, False), (True, True)):
            with self.subTest(schema=schema):
                spec["paths"]["/search"]["get"]["parameters"] = [{
                    "name": "view", "in": "query", "schema": schema,
                }]
                result = ConfigValidator.validate({"parameter_values": {"GET /search": {"view": "summary"}}}, spec)
                self.assertEqual(result.is_valid, expected)

    def test_effective_overrides_follow_runtime_precedence(self):
        config = {"parameter_values": {"GET /items/{id}": {
            "common": {"id": "invalid-unused-value"}, "id": 3,
        }}}
        self.assertTrue(ConfigValidator.validate(config, self.spec).is_valid)
        config["identities"] = {
            "owner": {"token": "Bearer owner-fixture", "parameters": {"id": 0}},
            "visitor": {"token": "Bearer visitor-fixture", "parameters": {"id": 2}},
            "anonymous": {},
        }
        result = ConfigValidator.validate(config, self.spec)
        self.assertFalse(result.is_valid)
        self.assertIn("identities.owner.parameters.id", [issue.path for issue in result.errors])

    def test_role_values_can_replace_unused_common_value_for_both_resource_selectors(self):
        config = {"parameter_values": {"GET /items/{id}": {
            "common": {"id": "invalid-unused-value"}, "owner": {"id": 1}, "visitor": {"id": 2},
        }}}
        self.assertTrue(ConfigValidator.validate(config, self.spec).is_valid)

    def test_parameter_required_readonly_property_is_not_exempted_as_request_body(self):
        spec = copy.deepcopy(self.spec)
        spec["paths"]["/search"]["get"]["parameters"] = [{
            "name": "filter", "in": "query", "schema": {
                "type": "object", "required": ["tenant"],
                "properties": {"tenant": {"type": "string", "readOnly": True}},
            },
        }]
        result = ConfigValidator.validate({"parameter_values": {"GET /search": {"filter": {}}}}, spec)
        self.assertFalse(result.is_valid)

    def test_independent_undocumented_readback_remains_supported_with_explicit_warning(self):
        result = ConfigValidator.validate({
            "write_allowlist": ["PATCH /items/{id}"],
            "readbacks": {"PATCH /items/{id}": self.readback("/independent/{id}")},
        }, self.spec)
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("Independent GET readback is not declared", result.warnings[0].message)
        self.assertIn("Confirm this readback path", result.warnings[0].suggestion)

    def test_documented_readback_and_explicit_readback_metadata_check_values(self):
        for path in ("/status/{id}", "/independent/{id}"):
            with self.subTest(path=path):
                mapping = self.readback(path, parameter_values={"id": "private-invalid-parameter"})
                if path.startswith("/independent"):
                    mapping["parameters"] = [{
                        "name": "id", "in": "path", "required": True, "schema": {"type": "integer"},
                    }]
                result = ConfigValidator.validate({"readbacks": {"PATCH /items/{id}": mapping}}, self.spec)
                self.assertFalse(result.is_valid)
                issue = next(issue for issue in result.errors if "parameter_values.id" in issue.path)
                self.assertNotIn("private-invalid-parameter", issue.format())

    def test_config_only_can_check_explicit_readback_metadata_without_a_specification(self):
        mapping = self.readback(parameters=[{
            "name": "id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1},
        }], parameter_values={"id": "1"})
        config = {"readbacks": {"PATCH /items/{id}": mapping}}
        self.assertFalse(ConfigValidator.validate(config).is_valid)
        mapping["parameter_values"]["id"] = 1
        self.assertTrue(ConfigValidator.validate(config).is_valid)

    def test_swagger_primitive_parameter_constraints_are_checked(self):
        spec = {"swagger": "2.0", "paths": {"/items/{id}": {"get": {
            "parameters": [{"name": "id", "in": "path", "required": True,
                            "type": "integer", "minimum": 1, "enum": [1, 2]}],
            "responses": {"200": {"description": "Item"}},
        }}}}
        for value, expected in ((1, True), (3, False), ("1", False)):
            with self.subTest(value=value):
                result = ConfigValidator.validate({"parameter_values": {"GET /items/{id}": {"id": value}}}, spec)
                self.assertEqual(result.is_valid, expected)

    def test_source_path_resolves_relative_parameter_references(self):
        spec = copy.deepcopy(self.spec)
        spec["paths"]["/items/{id}"]["parameters"] = [{"$ref": "parameters.json#/item_id"}]
        config = {"parameter_values": {"GET /items/{id}": {"id": 1}}}
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "openapi.json"
            source.write_text(json.dumps(spec), encoding="utf-8")
            (Path(directory) / "parameters.json").write_text(
                json.dumps(spec["components"]["parameters"]), encoding="utf-8",
            )
            self.assertTrue(ConfigValidator.validate(config, spec, spec_path=str(source)).is_valid)
            without_source = ConfigValidator.validate(config, spec)
            self.assertFalse(without_source.is_valid)
            self.assertIn("original spec_path", without_source.errors[0].suggestion)

    def test_cli_rejects_missing_policy_and_invalid_parameter_before_any_network(self):
        with tempfile.TemporaryDirectory() as directory:
            source, configuration = Path(directory) / "openapi.json", Path(directory) / "config.json"
            source.write_text(json.dumps(self.spec), encoding="utf-8")
            for config in ({"bola": {"GET /missing": {"expected_public": True}}},
                           {"parameter_values": {"GET /items/{id}": {"id": 0}}}):
                configuration.write_text(json.dumps(config), encoding="utf-8")
                for mode in ("--validate-config", "--dry-run"):
                    with self.subTest(config=config, mode=mode), \
                         patch("socket.socket", side_effect=AssertionError("Network socket opened")), \
                         patch("urllib.request.urlopen", side_effect=AssertionError("Network request sent")), \
                         redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertEqual(main([mode, "--spec", str(source), "--config", str(configuration)]), 2)


if __name__ == "__main__":
    unittest.main()
