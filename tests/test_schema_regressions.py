"""Regression cases for the v2.1 review's schema and reference failures."""

import json
import tempfile
import unittest
from pathlib import Path

from core.generator import SchemaGenerationError, SmartDataGenerator as Generator
from core.parser import OpenAPIParser


class SchemaRegressionTests(unittest.TestCase):
    def test_readonly_privilege_is_probe_candidate_but_never_normal_baseline(self):
        schema = {
            "type": "object",
            "required": ["name", "isAdmin"],
            "example": {"name": "Original", "isAdmin": True},
            "properties": {
                "name": {"type": "string"},
                "status": {"type": "string", "enum": ["active", "disabled"]},
                "isAdmin": {"type": "boolean", "readOnly": True},
            },
        }
        baseline = Generator.build_baseline_body(schema)
        self.assertEqual(baseline, {"name": "Original"})
        self.assertNotIn("isAdmin", Generator.generate_schema_sample(schema))
        cases = {case["field_path"]: case for case in Generator.build_mass_assignment_cases(schema)}
        self.assertIn("status", cases)
        self.assertIs(cases["isAdmin"]["payload"]["isAdmin"], True)
        self.assertTrue(Generator.validate_schema_value(baseline, schema))
        self.assertFalse(Generator.validate_schema_value(baseline, schema, request=False))

    def test_readonly_nested_permissions_remain_discoverable(self):
        schema = {"type": "object", "properties": {
            "account": {"type": "object", "readOnly": True,
                        "properties": {"isAdmin": {"type": "boolean", "readOnly": True}}}
        }}
        self.assertEqual(Generator.generate_schema_sample(schema), {})
        self.assertEqual(Generator.build_mass_assignment_cases(schema)[0]["field_path"], "account.isAdmin")

    def test_narrow_exclusive_numeric_range_uses_an_interior_value(self):
        for schema in (
            {"type": "number", "minimum": 0, "maximum": .05, "exclusiveMaximum": True},
            {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": .05},
        ):
            value = Generator.build_baseline_body(schema)
            self.assertGreaterEqual(value, 0)
            self.assertLess(value, .05)
            self.assertTrue(Generator.validate_schema_value(value, schema))

    def test_allof_numeric_constraints_are_an_intersection(self):
        schema = {"type": "integer", "allOf": [{"minimum": 2}, {"minimum": 10, "maximum": 12}]}
        value = Generator.build_baseline_body(schema)
        self.assertGreaterEqual(value, 10)
        self.assertLessEqual(value, 12)
        self.assertFalse(Generator.validate_schema_value(2, schema))

    def test_allof_multipleof_and_integer_number_type_intersections(self):
        schema = {"allOf": [
            {"type": "number", "minimum": 1, "multipleOf": 1.5},
            {"type": "integer", "multipleOf": 2, "maximum": 7},
        ]}
        self.assertEqual(Generator.build_baseline_body(schema), 6)

    def test_allof_property_constraints_are_not_overwritten(self):
        schema = {"allOf": [
            {"type": "object", "required": ["name"], "properties": {"name": {"type": "string", "minLength": 3}}},
            {"properties": {"name": {"pattern": "^[A-Z]{3}$"}}},
        ]}
        value = Generator.build_baseline_body(schema)
        self.assertEqual(value, {"name": "AAA"})
        self.assertFalse(Generator.validate_schema_value({"name": "ab"}, schema))

    def test_invalid_object_example_is_not_treated_as_a_valid_baseline(self):
        schema = {"type": "object", "required": ["name"], "example": {},
                  "properties": {"name": {"type": "string", "minLength": 3}}}
        self.assertFalse(Generator.validate_schema_value({}, schema))
        value = Generator.build_baseline_body(schema)
        self.assertIn("name", value)
        self.assertTrue(Generator.validate_schema_value(value, schema))

    def test_nested_example_validation_checks_types_required_and_unknown_fields(self):
        schema = {"type": "object", "required": ["account"], "properties": {
            "account": {"type": "object", "required": ["age"], "additionalProperties": False,
                        "properties": {"age": {"type": "integer", "minimum": 18}}}
        }}
        for invalid in ({"account": {}}, {"account": {"age": "adult"}},
                        {"account": {"age": 18, "extra": True}}):
            self.assertFalse(Generator.validate_schema_value(invalid, schema))
        self.assertTrue(Generator.validate_schema_value({"account": {"age": 18}}, schema))

    def test_const_enum_and_json_boolean_are_strictly_validated(self):
        self.assertFalse(Generator.validate_schema_value(True, {"enum": [1]}))
        self.assertFalse(Generator.validate_schema_value({"x": True}, {"const": {"x": 1}}))
        self.assertFalse(Generator.validate_schema_value(2, {"const": 1}))
        self.assertTrue(Generator.validate_schema_value(None, {"type": "null"}))

    def test_unsatisfiable_or_unsupported_generation_is_explicit(self):
        schemas = [
            {"type": "number", "minimum": 2, "maximum": 1},
            {"type": "integer", "minimum": 0, "maximum": 1, "exclusiveMinimum": True, "exclusiveMaximum": True},
            {"allOf": [{"type": "integer"}, {"type": "string"}]},
            {"allOf": [{"enum": [1]}, {"enum": [2]}]},
            {"type": "object", "required": ["missing"], "additionalProperties": False},
            {"type": "string", "pattern": "^(foo|bar)$"},
            {"$ref": "#/unresolved"},
            {"type": "object", "unevaluatedProperties": False},
            False,
        ]
        for schema in schemas:
            with self.subTest(schema=schema), self.assertRaises(SchemaGenerationError):
                Generator.build_baseline_body(schema)

    def test_alternative_branches_are_validated_against_the_entire_schema(self):
        schema = {"type": "integer", "minimum": 5,
                  "anyOf": [{"maximum": 2}, {"minimum": 8}]}
        self.assertGreaterEqual(Generator.build_baseline_body(schema), 8)
        with self.assertRaises(SchemaGenerationError):
            Generator.build_baseline_body({"oneOf": [{"type": "string"}, {"type": "string"}]})

    def test_array_items_unique_and_contains_are_recursively_validated(self):
        schema = {"type": "array", "minItems": 2, "uniqueItems": True,
                  "items": {"type": "integer"}, "contains": {"minimum": 5}}
        self.assertTrue(Generator.validate_schema_value([1, 5], schema))
        for invalid in ([1, 1], [1, "5"], [1, 2]):
            self.assertFalse(Generator.validate_schema_value(invalid, schema))


class ReferenceRegressionTests(unittest.TestCase):
    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def endpoint_spec(self, schema, version="3.1.0"):
        return {"openapi": version, "paths": {"/update": {"patch": {"requestBody": {
            "content": {"application/json": {"schema": schema}}
        }}}}}

    def test_external_schema_and_local_sibling_keep_their_own_ref_origins(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.write(root / "models" / "base.json", {
                "Base": {"type": "object", "required": ["name"], "properties": {"name": {"$ref": "#/Name"}}},
                "Name": {"type": "string", "minLength": 3},
            })
            spec = self.endpoint_spec({"$ref": "models/base.json#/Base", "properties": {
                "role": {"$ref": "#/components/schemas/LocalRole"}
            }})
            spec["components"] = {"schemas": {"LocalRole": {"type": "string", "enum": ["member", "admin"]}}}
            self.write(root / "openapi.json", spec)
            schema = OpenAPIParser(str(root / "openapi.json")).get_endpoints()[0]["request_schema"]
            self.assertEqual(set(schema["properties"]), {"name", "role"})
            self.assertEqual(schema["properties"]["name"]["minLength"], 3)
            self.assertEqual(schema["properties"]["role"]["enum"], ["member", "admin"])
            self.assertTrue(Generator.validate_schema_value(Generator.build_baseline_body(schema), schema))

    def test_alias_schema_siblings_keep_their_document_context(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.write(root / "base.json", {"Base": {"type": "object", "properties": {"name": {"type": "string"}}}})
            self.write(root / "models" / "alias.json", {"Alias": {
                "$ref": "../base.json#/Base", "properties": {"role": {"$ref": "#/LocalRole"}}
            }, "LocalRole": {"type": "string", "enum": ["admin"]}})
            self.write(root / "openapi.json", self.endpoint_spec({"$ref": "models/alias.json#/Alias"}))
            schema = OpenAPIParser(str(root / "openapi.json")).get_endpoints()[0]["request_schema"]
            self.assertEqual(set(schema["properties"]), {"name", "role"})
            self.assertEqual(schema["properties"]["role"]["enum"], ["admin"])

    def test_oas30_schema_siblings_require_explicit_allof(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            spec = self.endpoint_spec({"$ref": "#/Base", "properties": {"role": {"type": "string"}}}, "3.0.3")
            spec["Base"] = {"type": "object", "properties": {"name": {"type": "string"}}}
            self.write(root / "openapi.json", spec)
            with self.assertRaisesRegex(ValueError, "use allOf"):
                OpenAPIParser(str(root / "openapi.json")).get_endpoints()

    def test_missing_ref_and_invalid_array_pointer_raise_instead_of_empty_schema(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "openapi.json"
            self.write(path, {"openapi": "3.1.0", "paths": {}, "schemas": [{}]})
            parser = OpenAPIParser(str(path))
            for ref in ("#/missing", "#/schemas/-1", "#/schemas/01"):
                with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "Unresolved"):
                    parser.resolve_ref(ref)

    def test_pointer_uri_decoding_happens_only_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "openapi.json"
            self.write(path, {"openapi": "3.1.0", "paths": {}, "%2F": {"type": "integer"}, "/": {"type": "string"}})
            parser = OpenAPIParser(str(path))
            self.assertEqual(parser.resolve_ref("#/%252F")["type"], "integer")
            self.assertEqual(parser.resolve_ref("#/~1")["type"], "string")

    def test_security_declared_distinguishes_absence_from_explicit_public(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "openapi.json"
            self.write(path, {"openapi": "3.1.0", "paths": {"/implicit": {"get": {}}, "/public": {"get": {"security": []}}}})
            implicit, public = OpenAPIParser(str(path)).get_endpoints()
            self.assertFalse(implicit["security_declared"])
            self.assertTrue(public["security_declared"])
            self.assertEqual(public["security"], [])
            self.write(path, {"openapi": "3.1.0", "security": [{"bearer": []}], "paths": {"/private": {"get": {}}}})
            private = OpenAPIParser(str(path)).get_endpoints()[0]
            self.assertTrue(private["security_declared"])
            self.assertEqual(private["security"], [{"bearer": []}])


if __name__ == "__main__":
    unittest.main()
