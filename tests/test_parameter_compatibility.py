"""Canonical legacy scalar strings retain native wire and identity semantics."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.generator import SmartDataGenerator
from core.models import HTTPResult
from core.parameters import (
    ParameterSerializationError,
    normalize_parameter_value,
    serialize_path_parameter,
    serialize_query_parameter,
)


ROOT = Path(__file__).resolve().parents[1]


def parameter(kind, location="query", **constraints):
    return {"name": "value", "in": location, "schema": {"type": kind, **constraints}}


class CanonicalScalarCompatibilityTests(unittest.TestCase):
    def assert_same_wire(self, schema_type, text, native, **constraints):
        for location, serializer in (("path", serialize_path_parameter), ("query", serialize_query_parameter)):
            metadata = parameter(schema_type, location, **constraints)
            with self.subTest(location=location, text=text):
                normalized = normalize_parameter_value(metadata, text)
                self.assertEqual(type(native), type(normalized))
                self.assertEqual(native, normalized)
                self.assertTrue(SmartDataGenerator.validate_schema_value(
                    normalized, metadata["schema"], request=False))
                self.assertEqual(serializer(metadata, native), serializer(metadata, text))

    def test_canonical_integers_and_nullable_integer_strings(self):
        for text, native in (("0", 0), ("1001", 1001), ("-1001", -1001)):
            self.assert_same_wire("integer", text, native)
            self.assert_same_wire(["integer", "null"], text, native)
        self.assert_same_wire("integer", "1001", 1001, minimum=1, maximum=2000, enum=[1001])

    def test_noncanonical_or_wrong_native_integers_are_rejected(self):
        invalid = ("01", "+1", "-0", " 1001", "1001 ", "", "1001x", "1.0",
                   "1e3", "\u0661\u0660\u0660\u0661", "\uff11\uff10\uff10\uff11", 1.5, True, False)
        for value in invalid:
            for location, serializer in (("path", serialize_path_parameter), ("query", serialize_query_parameter)):
                with self.subTest(value=value, location=location), self.assertRaises(ParameterSerializationError):
                    serializer(parameter("integer", location), value)

    def test_canonical_numbers_preserve_native_wire(self):
        for text, native in (("1", 1), ("1.0", 1.0), ("1.5", 1.5), ("-0.0", -0.0),
                             ("1e+20", 1e20), ("1e-07", 1e-7)):
            self.assert_same_wire("number", text, native)
            self.assert_same_wire(["null", "number"], text, native)

    def test_noncanonical_precision_losing_and_nonfinite_numbers_are_rejected(self):
        invalid = ("NaN", "Infinity", "-Infinity", "1e400", "01", "+1", "-0", "1.00",
                   "1e20", "1E+20", "1e+020", "1e-7", " 1.5", "1.5 ", "",
                   "0.10000000000000001", "9007199254740993.0", "\uff11.\uff15",
                   float("nan"), float("inf"), True)
        for value in invalid:
            for location, serializer in (("path", serialize_path_parameter), ("query", serialize_query_parameter)):
                with self.subTest(value=value, location=location), self.assertRaises(ParameterSerializationError):
                    serializer(parameter("number", location), value)

    def test_exact_lowercase_boolean_strings_preserve_native_wire(self):
        for text, native in (("true", True), ("false", False)):
            self.assert_same_wire("boolean", text, native)
            self.assert_same_wire(["boolean", "null"], text, native)
        for value in ("TRUE", "False", "1", "0", " true", "false ", "", 1, 0):
            with self.subTest(value=value), self.assertRaises(ParameterSerializationError):
                serialize_query_parameter(parameter("boolean"), value)

    def test_normalization_still_enforces_full_schema_constraints(self):
        cases = (
            (parameter("integer", minimum=1), "-1"),
            (parameter("integer", enum=[2]), "1"),
            (parameter("number", maximum=1), "1.5"),
            (parameter("number", multipleOf=1), "1.5"),
            (parameter("boolean", enum=[False]), "true"),
            (parameter("boolean", enum=[1]), "true"),
        )
        for metadata, value in cases:
            with self.subTest(metadata=metadata), self.assertRaises(ParameterSerializationError):
                serialize_query_parameter(metadata, value)

    def test_strings_unions_and_containers_are_not_guessed_or_recursively_coerced(self):
        for kind, value in (("string", "01"), (["integer", "string"], "1001"),
                            (["integer", "number"], "1001"), ("array", "[1,2]"),
                            ("object", '{"active":true}'), ("array", [1, "2"]),
                            ("object", {"active": "true"})):
            self.assertIs(value, normalize_parameter_value(parameter(kind), value))
        self.assertEqual([("value", "01")], serialize_query_parameter(parameter("string"), "01"))
        self.assertEqual([("value", "1001")], serialize_query_parameter(parameter(["integer", "string"]), "1001"))
        invalid = (
            (parameter(["integer", "number"]), "1001"),
            (parameter("array", items={"type": "integer"}), [1, "2"]),
            (parameter("object", properties={"active": {"type": "boolean"}}), {"active": "true"}),
            (parameter("array"), "[1,2]"),
            (parameter("object"), '{"active":true}'),
        )
        for metadata, value in invalid:
            with self.subTest(metadata=metadata), self.assertRaises(ParameterSerializationError):
                serialize_query_parameter(metadata, value)

    def test_swagger2_and_path_styles_keep_identical_wire(self):
        for kind, text, native in (("integer", "1001", 1001), ("number", "1.5", 1.5),
                                   ("boolean", "false", False)):
            for location, serializer in (("path", serialize_path_parameter), ("query", serialize_query_parameter)):
                metadata = {"name": "value", "in": location, "type": kind}
                self.assertEqual(serializer(metadata, native, swagger2=True),
                                 serializer(metadata, text, swagger2=True))
            for style in ("simple", "label", "matrix"):
                metadata = {**parameter(kind, "path"), "style": style}
                self.assertEqual(serialize_path_parameter(metadata, native),
                                 serialize_path_parameter(metadata, text))

    def test_rejection_diagnostics_do_not_include_values(self):
        secret = "SYNTHETIC_PRIVATE_PARAMETER"
        for kind in ("integer", "number", "boolean"):
            with self.subTest(kind=kind), self.assertRaises(ParameterSerializationError) as caught:
                normalize_parameter_value(parameter(kind), secret)
            self.assertNotIn(secret, str(caught.exception))
            self.assertIn("no request was sent", str(caught.exception))


class RuntimeIdentityCompatibilityTests(unittest.TestCase):
    endpoint = {"method": "GET", "path": "/items/{user_id}", "parameters": [
        {"name": "user_id", "in": "path", "schema": {"type": "integer", "minimum": 1}},
        {"name": "active", "in": "query", "schema": {"type": "boolean"}},
    ]}

    def run_audit(self, string_values):
        identities = {
            "owner": {"id": "1001", "token": "Bearer SYNTHETIC_OWNER",
                      "parameters": {"user_id": "1001" if string_values else 1001}},
            "visitor": {"id": "1002", "token": "Bearer SYNTHETIC_VISITOR",
                        "parameters": {"user_id": "1002" if string_values else 1002}},
            "anonymous": {"id": None, "token": None},
        }
        auditor = APISentinelAuditor(str(ROOT / "openapi.json"), "http://127.0.0.1:8080",
            request_delay=0, identities_config=identities,
            parameter_values={"GET /items/{user_id}": {"common": {"active": "false" if string_values else False}}})

        def result(method, url, data=None, identity_name="owner", **kwargs):
            if identity_name == "anonymous":
                return HTTPResult(401, json.dumps({"error": "Forbidden"}))
            return HTTPResult(200, json.dumps({"business_value": "visitor" if "/1002?" in url else "owner"}))

        with patch.object(auditor, "_http_request", side_effect=result) as http:
            auditor.audit_endpoint_bola(self.endpoint)
        return auditor, [(call.args[1], call.kwargs["identity_name"]) for call in http.call_args_list]

    def test_legacy_and_native_values_use_same_four_requests_and_resource_identities(self):
        legacy, legacy_calls = self.run_audit(True)
        native, native_calls = self.run_audit(False)
        self.assertEqual(native_calls, legacy_calls)
        self.assertEqual([
            ("http://127.0.0.1:8080/items/1001?active=false", "owner"),
            ("http://127.0.0.1:8080/items/1001?active=false", "visitor"),
            ("http://127.0.0.1:8080/items/1001?active=false", "anonymous"),
            ("http://127.0.0.1:8080/items/1002?active=false", "visitor"),
        ], legacy_calls)
        self.assertEqual("CONFIRMED", legacy.results[0]["verdict"])
        self.assertEqual(native.results[0]["verdict"], legacy.results[0]["verdict"])

    def test_ambiguous_legacy_override_stops_before_any_request(self):
        auditor = APISentinelAuditor(str(ROOT / "openapi.json"), "http://127.0.0.1:8080",
            request_delay=0, identities_config={
                "owner": {"id": "1001", "token": "Bearer SYNTHETIC_OWNER", "parameters": {"user_id": "01001"}},
                "visitor": {"id": "1002", "token": "Bearer SYNTHETIC_VISITOR", "parameters": {"user_id": "1002"}},
                "anonymous": {"id": None, "token": None},
            }, parameter_values={"GET /items/{user_id}": {"common": {"active": "false"}}})
        with patch.object(auditor, "_http_request") as http:
            auditor.audit_endpoint_bola(self.endpoint)
        http.assert_not_called()
        self.assertEqual("INCONCLUSIVE", auditor.results[0]["verdict"])
