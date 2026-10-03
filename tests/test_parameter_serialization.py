"""Wire-level regressions for parameter contracts and failed-closed requests."""

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from core.auditor import APISentinelAuditor
from core.generator import SmartDataGenerator
from core.parameters import ParameterSerializationError, serialize_path_parameter, serialize_query_parameter
from core.parser import OpenAPIParser


ROOT = Path(__file__).resolve().parents[1]


def metadata(location="query", kind="array", **settings):
    return {"name": "ids", "in": location, "schema": {"type": kind}, **settings}


class ParameterSerializationTests(unittest.TestCase):
    def test_oas3_arrays_keep_structure_and_boolean_case(self):
        self.assertEqual(serialize_query_parameter(metadata(), [10, 20]), [("ids", "10"), ("ids", "20")])
        self.assertEqual(serialize_query_parameter(metadata(explode=False), [10, 20]), [("ids", "10,20")])
        self.assertEqual(serialize_query_parameter(metadata(kind="boolean"), True), [("ids", "true")])
        self.assertEqual(serialize_path_parameter(metadata("path", "boolean"), False), "false")

    def test_data_is_encoded_before_delimiters_and_exactly_once(self):
        pairs = serialize_query_parameter(metadata(explode=False), ["a,b", "c&x=y", "a+b", "100%", "汉 字", "a/b?#"])
        self.assertEqual(pairs, [("ids", "a%2Cb,c%26x%3Dy,a%2Bb,100%25,%E6%B1%89%20%E5%AD%97,a%2Fb%3F%23")])
        self.assertEqual(serialize_path_parameter(metadata("path", "string"), "a/b?x=#"), "a%2Fb%3Fx%3D%23")
        self.assertEqual(serialize_path_parameter(metadata("path", "string"), "%2F"), "%252F")
        self.assertEqual(serialize_path_parameter(metadata("path", "string"), ".."), "%2E%2E")
        with self.assertRaises(ParameterSerializationError):
            serialize_path_parameter(metadata("path", "string"), "")

    def test_all_path_styles_and_explode_follow_oas3_examples(self):
        examples = [
            ("simple", False, [10, 20], "10,20"),
            ("simple", True, [10, 20], "10,20"),
            ("label", False, [10, 20], ".10,20"),
            ("label", True, [10, 20], ".10.20"),
            ("matrix", False, [10, 20], ";ids=10,20"),
            ("matrix", True, [10, 20], ";ids=10;ids=20"),
            ("simple", False, {"R": 100, "G": 200}, "R,100,G,200"),
            ("simple", True, {"R": 100, "G": 200}, "R=100,G=200"),
            ("label", False, {"R": 100, "G": 200}, ".R,100,G,200"),
            ("label", True, {"R": 100, "G": 200}, ".R=100.G=200"),
            ("matrix", False, {"R": 100, "G": 200}, ";ids=R,100,G,200"),
            ("matrix", True, {"R": 100, "G": 200}, ";R=100;G=200"),
        ]
        for style, explode, value, expected in examples:
            with self.subTest(style=style, explode=explode, value=value):
                kind = "object" if isinstance(value, dict) else "array"
                self.assertEqual(serialize_path_parameter(metadata("path", kind, style=style, explode=explode), value), expected)

    def test_query_objects_and_delimited_styles(self):
        value = {"R": 100, "G": False}
        self.assertEqual(serialize_query_parameter(metadata(kind="object"), value), [("R", "100"), ("G", "false")])
        self.assertEqual(serialize_query_parameter(metadata(kind="object", explode=False), value), [("ids", "R,100,G,false")])
        self.assertEqual(serialize_query_parameter(metadata(kind="object", style="deepObject", explode=True), value), [("ids%5BR%5D", "100"), ("ids%5BG%5D", "false")])
        for style, delimiter in (("spaceDelimited", "%20"), ("pipeDelimited", "%7C")):
            with self.subTest(style=style):
                self.assertEqual(serialize_query_parameter(metadata(style=style), [10, 20]), [("ids", "10" + delimiter + "20")])
                self.assertEqual(serialize_query_parameter(metadata(kind="object", style=style), value), [("ids", delimiter.join(("R", "100", "G", "false")))])

    def test_swagger2_collection_formats_and_csv_default(self):
        for collection, expected in ((None, "10,20"), ("csv", "10,20"), ("ssv", "10%2020"), ("tsv", "10%0920"), ("pipes", "10%7C20")):
            with self.subTest(collection=collection):
                parameter = {"name": "ids", "in": "query", "type": "array", "items": {"type": "integer"}}
                if collection:
                    parameter["collectionFormat"] = collection
                self.assertEqual(serialize_query_parameter(parameter, [10, 20], swagger2=True), [("ids", expected)])
                parameter["in"] = "path"
                self.assertEqual(serialize_path_parameter(parameter, [10, 20], swagger2=True), expected)
        self.assertEqual(serialize_query_parameter({"name": "ids", "in": "query", "type": "array", "collectionFormat": "multi"}, [10, 20], swagger2=True), [("ids", "10"), ("ids", "20")])

    def test_unsupported_and_ambiguous_inputs_have_no_value_in_diagnostic(self):
        secret = "PRIVATE_PARAMETER_VALUE"
        cases = [
            (metadata(kind="object", style="deepObject"), {"x": secret}, False),
            (metadata(kind="object", style="deepObject", explode=True), {"x": {"nested": secret}}, False),
            (metadata(kind="object", style="deepObject", explode=True), {"x[]": secret}, False),
            (metadata(allowReserved=True), [secret], False),
            (metadata(style="unknown"), [secret], False),
            (metadata(style="pipeDelimited", explode=True), [secret], False),
            (metadata(style="spaceDelimited"), ["two words"], False),
            (metadata(style="pipeDelimited"), ["two|words"], False),
            (metadata(kind="object"), {"x": [secret]}, False),
            (metadata(content={"application/json": {}}), [secret], False),
            (metadata(), "[10,20]", False),
            (metadata(), [], False),
            (metadata(kind="boolean"), None, False),
            (metadata(kind="number"), float("nan"), False),
            (metadata(kind="number"), float("inf"), False),
            (metadata("header"), [secret], False),
            (metadata("cookie"), [secret], False),
            (metadata(collectionFormat="json"), [secret], True),
            (metadata(kind="object"), {"x": secret}, True),
        ]
        for parameter, value, swagger2 in cases:
            with self.subTest(parameter=parameter, value=value):
                with self.assertRaises(ParameterSerializationError) as caught:
                    serialize_query_parameter(parameter, value, swagger2=swagger2)
                self.assertNotIn(secret, str(caught.exception))
                self.assertIn("no request was sent", str(caught.exception))
        with self.assertRaises(ParameterSerializationError):
            serialize_path_parameter({"name": "ids", "in": "path", "type": "array", "collectionFormat": "multi"}, [10, 20], swagger2=True)

    def test_generated_documented_values_keep_types(self):
        parameter = metadata()
        parameter["schema"]["items"] = {"type": "integer"}
        parameter["schema"]["default"] = [10, 20]
        self.assertEqual(SmartDataGenerator.generate_raw_value_for_param(parameter), [10, 20])
        self.assertEqual(SmartDataGenerator.generate_value_for_param(parameter), "10,20")
        parameter = metadata(kind="boolean")
        parameter["example"] = False
        self.assertIs(SmartDataGenerator.generate_raw_value_for_param(parameter), False)

    def test_parser_preserves_serialization_metadata_from_reference_override(self):
        with tempfile.TemporaryDirectory() as directory:
            spec = {"openapi": "3.0.3", "components": {"parameters": {"Ids": metadata(style="form", explode=True)}}, "paths": {"/items": {"parameters": [{"$ref": "#/components/parameters/Ids"}], "get": {"parameters": [metadata(style="pipeDelimited", explode=False, description="preserved", example=[10, 20])], "responses": {"200": {"description": "ok"}}}}}}
            spec_path = Path(directory) / "openapi.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            endpoint = OpenAPIParser(str(spec_path)).get_endpoints()[0]
            self.assertEqual(endpoint["spec_version"], "3.0.3")
            self.assertEqual(endpoint["parameters"], spec["paths"]["/items"]["get"]["parameters"])


class WireParameterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                cls.requests.append((self.path, dict(self.headers)))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"id":"1001","result":true}')

            def log_message(self, *_):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.requests.clear()

    def make_auditor(self, **kwargs):
        return APISentinelAuditor(str(ROOT / "openapi.json"), self.target, request_delay=0, **kwargs)

    def test_actual_url_keeps_native_arrays_booleans_and_reserved_values(self):
        auditor = self.make_auditor(parameter_values={"GET /items/{key}": {"common": {"key": "a/b", "ids": [10, 20], "active": True, "search": "A+B&x=汉 字"}}})
        endpoint = {"method": "GET", "path": "/items/{key}", "parameters": [{"name": "key", "in": "path", "schema": {"type": "string"}}, metadata(), {"name": "active", "in": "query", "schema": {"type": "boolean"}}, {"name": "search", "in": "query", "schema": {"type": "string"}}]}
        url = auditor._build_url(endpoint, "owner")
        self.assertEqual(auditor._http_request("GET", url, identity_name="owner").status, 200)
        request_path, headers = self.requests[0]
        self.assertEqual(request_path, "/items/a%2Fb?ids=10&ids=20&active=true&search=A%2BB%26x%3D%E6%B1%89%20%E5%AD%97")
        self.assertEqual(parse_qs(urlsplit(request_path).query), {"ids": ["10", "20"], "active": ["true"], "search": ["A+B&x=汉 字"]})
        self.assertEqual(headers["Authorization"], "Bearer TOKEN_ALICE_OWNER_1001")

    def test_swagger2_actual_multi_and_pipe_encoded_urls(self):
        auditor = self.make_auditor()
        endpoint = {"method": "GET", "path": "/items", "spec_version": "2.0", "parameters": [{"name": "ids", "in": "query", "type": "array", "items": {"type": "integer"}, "collectionFormat": "multi"}, {"name": "flags", "in": "query", "type": "array", "items": {"type": "boolean"}, "collectionFormat": "pipes"}]}
        url = auditor._build_url(endpoint, "owner", {"ids": [10, 20], "flags": [True, False]})
        self.assertEqual(auditor._http_request("GET", url).status, 200)
        self.assertEqual(self.requests[0][0], "/items?ids=10&ids=20&flags=true%7Cfalse")

    def test_readback_uses_declared_get_metadata_and_shared_serializer(self):
        with tempfile.TemporaryDirectory() as directory:
            read_parameters = [metadata(style="pipeDelimited", explode=False), {"name": "active", "in": "query", "schema": {"type": "boolean", "default": True}}]
            spec = {"openapi": "3.0.3", "paths": {"/items": {"get": {"parameters": read_parameters}}}}
            spec_path = Path(directory) / "openapi.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            auditor = APISentinelAuditor(str(spec_path), self.target, request_delay=0)
            mutation = {"method": "PATCH", "path": "/settings", "parameters": [], "operation_id": "patch_settings"}
            url, result = auditor._readback_result(mutation, {"path": "/items", "parameter_values": {"ids": [10, 20]}}, "visitor")
            self.assertEqual(result.status, 200)
            self.assertTrue(url.endswith("/items?ids=10%7C20&active=true"))
            self.assertEqual(self.requests[0][0], "/items?ids=10%7C20&active=true")
            self.assertEqual(self.requests[0][1]["Authorization"], "Bearer TOKEN_BOB_VISITOR_1002")

    def test_incomplete_or_unsupported_contracts_send_zero_requests(self):
        for parameter, value in ((metadata("header"), [10, 20]), (metadata("cookie"), [10, 20]), (metadata(style="deepObject"), [10, 20]), (metadata(allowReserved=True), [10, 20]), (metadata(), "[10,20]")):
            with self.subTest(parameter=parameter):
                auditor = self.make_auditor(parameter_values={"GET /items/{user_id}": {"common": {"ids": value}}})
                endpoint = {"method": "GET", "path": "/items/{user_id}", "parameters": [parameter]}
                auditor.audit_endpoint_bola(endpoint)
                self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")
                self.assertIn("no request was sent", auditor.results[0]["reason"])
                self.assertEqual(self.requests, [])

    def test_auth_headers_are_owned_by_requester_never_resource_parameters(self):
        identities = {"owner": {"id": "1001", "headers": {"X-Api-Key": "OWNER_KEY"}}, "visitor": {"id": "1002", "headers": {"X-Api-Key": "VISITOR_KEY"}}, "anonymous": {"id": None, "headers": {}}}
        auditor = self.make_auditor(identities_config=identities)
        endpoint = {"method": "GET", "path": "/items/{user_id}", "parameters": [{"name": "X-Api-Key", "in": "header", "schema": {"type": "string"}}, {"name": "Authorization", "in": "header", "schema": {"type": "string"}}]}
        auditor.audit_endpoint_bola(endpoint)
        self.assertEqual(len(self.requests), 4)
        self.assertEqual([headers.get("X-Api-Key") for _, headers in self.requests], ["OWNER_KEY", "VISITOR_KEY", None, "VISITOR_KEY"])

    def test_colliding_exploded_objects_fail_before_request(self):
        auditor = self.make_auditor()
        endpoint = {"method": "GET", "path": "/items", "parameters": [{"name": "filter", "in": "query", "schema": {"type": "object"}}, {"name": "user_id", "in": "query", "schema": {"type": "integer"}}]}
        with self.assertRaises(ParameterSerializationError):
            auditor._build_url(endpoint, "owner", {"filter": {"user_id": "1002"}, "user_id": "1001"})
        self.assertEqual(self.requests, [])

    def test_unsupported_readback_contract_prevents_patch(self):
        auditor = self.make_auditor(allow_write_tests=True, write_allowlist=["PATCH /items/{user_id}"], readback_config={"PATCH /items/{user_id}": {"path": "/items/{user_id}", "parameters": [metadata(allowReserved=True)], "parameter_values": {"ids": [10, 20]}, "field_map": {"role": "role"}}})
        endpoint = {"method": "PATCH", "path": "/items/{user_id}", "parameters": [], "request_content_type": "application/json", "request_schema": {"type": "object", "properties": {"role": {"type": "string", "readOnly": True}}}}
        with patch.object(auditor, "_http_request") as transport:
            auditor.audit_endpoint_mass_assignment(endpoint, [endpoint])
        transport.assert_not_called()
        self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")
        self.assertEqual(self.requests, [])
