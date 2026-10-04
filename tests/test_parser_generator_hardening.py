# -*- coding: utf-8 -*-
"""Focused contracts for parser/generator hardening.

These tests intentionally avoid network access and exercise only deterministic
specification parsing and payload generation.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from core.generator import SmartDataGenerator
from core.parser import OpenAPIParser


class ParserHardeningTests(unittest.TestCase):
    def _write_json(self, path: Path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_external_refs_recursive_compositions_and_parameter_override(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            models = {
                "Base": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string", "minLength": 3},
                        "metadata": {"$ref": "#/Metadata"},
                    },
                },
                "Metadata": {
                    "type": "object",
                    "properties": {"verified": {"type": "boolean"}},
                },
                "Tag": {
                    "oneOf": [
                        {"type": "string", "minLength": 2},
                        {"type": "integer", "minimum": 1},
                    ]
                },
                "Update": {
                    "allOf": [
                        {"$ref": "#/Base"},
                        {
                            "type": "object",
                            "properties": {
                                "account": {
                                    "type": "object",
                                    "properties": {
                                        "role": {
                                            "type": "string",
                                            "enum": ["member", "admin"],
                                        }
                                    },
                                },
                                "tags": {
                                    "type": "array",
                                    "items": {"$ref": "#/Tag"},
                                },
                            },
                        },
                    ]
                },
            }
            spec = {
                "openapi": "3.0.3",
                "paths": {
                    "/users/{user_id}": {
                        "parameters": [
                            {
                                "name": "user_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                            },
                            {
                                "name": "page",
                                "in": "query",
                                "schema": {"type": "integer", "default": 1},
                            },
                        ],
                        "patch": {
                            "parameters": [
                                {
                                    "name": "page",
                                    "in": "query",
                                    "schema": {"type": "integer", "default": 2},
                                }
                            ],
                            "requestBody": {
                                "content": {
                                    "application/vnd.sentinel+json": {
                                        "schema": {"$ref": "models/models.json#/Update"}
                                    }
                                }
                            },
                            "responses": {"200": {"description": "ok"}},
                        },
                    }
                },
            }
            self._write_json(root / "models" / "models.json", models)
            self._write_json(root / "openapi.json", spec)

            parser = OpenAPIParser(str(root / "openapi.json"))
            initial_sources = parser.source_files
            self.assertEqual((root / "openapi.json",), initial_sources)
            endpoint = parser.get_endpoints()[0]
            self.assertEqual(
                {root / "openapi.json", root / "models" / "models.json"},
                set(parser.source_files),
            )
            self.assertIsInstance(parser.source_files, tuple)
            self.assertEqual((root / "openapi.json",), initial_sources)
            with self.assertRaises(AttributeError):
                parser.source_files = ()

            self.assertEqual(endpoint["request_content_type"], "application/vnd.sentinel+json")
            params = {(item["name"], item["in"]): item for item in endpoint["parameters"]}
            self.assertEqual(params[("page", "query")]["schema"]["default"], 2)
            schema = endpoint["request_schema"]
            self.assertIn("name", schema["properties"])
            self.assertIn("account", schema["properties"])
            self.assertEqual(
                schema["properties"]["metadata"]["properties"]["verified"]["type"],
                "boolean",
            )
            self.assertEqual(
                schema["properties"]["tags"]["items"]["oneOf"][1]["type"],
                "integer",
            )

    def test_external_ref_cannot_escape_spec_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            spec_dir = root / "contract"
            self._write_json(root / "secret.json", {"Body": {"type": "object"}})
            self._write_json(
                spec_dir / "openapi.json",
                {
                    "openapi": "3.0.3",
                    "paths": {
                        "/unsafe": {
                            "post": {
                                "requestBody": {
                                    "content": {
                                        "application/json": {
                                            "schema": {"$ref": "../secret.json#/Body"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            )
            parser = OpenAPIParser(str(spec_dir / "openapi.json"))
            with self.assertRaisesRegex(ValueError, "escapes the specification directory"):
                parser.get_endpoints()

    def test_yaml_has_optional_dependency_with_clear_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_path = Path(temp_dir) / "openapi.yaml"
            spec_path.write_text(
                "openapi: 3.0.3\ninfo:\n  title: Test\n  version: 1.0.0\npaths: {}\n",
                encoding="utf-8",
            )
            if importlib.util.find_spec("yaml") is None:
                with self.assertRaisesRegex(RuntimeError, "PyYAML"):
                    OpenAPIParser(str(spec_path))
            else:
                parser = OpenAPIParser(str(spec_path))
                self.assertEqual(parser.version, "OpenAPI 3.0.3")


class GeneratorHardeningTests(unittest.TestCase):
    def test_candidate_id_only_applies_to_resource_identifiers(self):
        user_id = {
            "name": "user_id",
            "in": "path",
            "schema": {"type": "integer", "minimum": 1},
        }
        page = {
            "name": "page",
            "in": "query",
            "schema": {"type": "integer", "minimum": 1, "default": 3},
        }
        constrained_uuid = {
            "name": "documentUuid",
            "in": "path",
            "schema": {
                "type": "string",
                "format": "uuid",
                "example": "550e8400-e29b-41d4-a716-446655440000",
            },
        }

        self.assertEqual(SmartDataGenerator.generate_value_for_param(user_id, "1001"), "1001")
        self.assertEqual(SmartDataGenerator.generate_value_for_param(page, "1001"), "3")
        self.assertEqual(
            SmartDataGenerator.generate_value_for_param(constrained_uuid, "1001"),
            "550e8400-e29b-41d4-a716-446655440000",
        )

    def test_schema_samples_respect_documented_values_and_constraints(self):
        schema = {
            "type": "object",
            "required": ["code", "count", "kind"],
            "properties": {
                "code": {"type": "string", "pattern": "^[A-Z]{3}[0-9]{2}$"},
                "count": {
                    "type": "integer",
                    "minimum": 5,
                    "exclusiveMinimum": True,
                    "multipleOf": 2,
                },
                "kind": {"type": "string", "enum": ["safe", "admin"]},
                "optional": {"type": "string", "default": "kept"},
            },
        }

        baseline = SmartDataGenerator.build_baseline_body(schema)
        self.assertEqual(set(baseline), {"code", "count", "kind"})
        self.assertRegex(baseline["code"], r"^[A-Z]{3}[0-9]{2}$")
        self.assertGreater(baseline["count"], 5)
        self.assertEqual(baseline["count"] % 2, 0)
        self.assertEqual(baseline["kind"], "safe")

        full_sample = SmartDataGenerator.generate_schema_sample(schema)
        self.assertEqual(full_sample["optional"], "kept")

    def test_nested_mass_assignment_cases_change_one_field_at_a_time(self):
        schema = {
            "type": "object",
            "required": ["display_name"],
            "properties": {
                "display_name": {"type": "string", "example": "Alice"},
                "account": {
                    "type": "object",
                    "properties": {
                        "role": {
                            "type": "string",
                            "enum": ["member", "admin"],
                        },
                        "is_admin": {"type": "boolean"},
                    },
                },
            },
        }

        cases = SmartDataGenerator.build_mass_assignment_cases(schema)

        self.assertEqual([case["field_path"] for case in cases], ["account.role", "account.is_admin"])
        self.assertEqual(cases[0]["payload"]["display_name"], "Alice")
        self.assertEqual(cases[0]["payload"]["account"], {"role": "admin"})
        self.assertEqual(cases[1]["payload"]["account"], {"is_admin": True})
        self.assertEqual(cases[0]["mutation"], {"account": {"role": "admin"}})

        combined = SmartDataGenerator.build_mass_assignment_payload(schema)
        self.assertEqual(combined["account"], {"role": "admin", "is_admin": True})


if __name__ == "__main__":
    unittest.main()
