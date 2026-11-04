"""Comprehensive tests for Header and Cookie parameter serialization.

Verifies:
1. Header primitive, array, and object support with simple style.
2. Explode settings (explode=false, explode=true) for headers.
3. Cookie primitive support with form style.
4. Cookie array rejection across explode=false and explode=true (0 wire requests).
5. Cookie object rejection across explode=false and explode=true (0 wire requests).
6. OpenAPI 3.x vs Swagger 2.0 rules (Swagger 2 collectionFormat=csv, non-csv rejection, object rejection).
7. Empty arrays, empty objects, and nested containers rejection.
8. CRLF, null byte, and control character injection prevention.
9. Header/Cookie identity conflicts with Authorization and session credentials.
10. Owner, Visitor, and Anonymous authentication isolation.
11. Parameter missing and schema type mismatches.
12. Delimiter ambiguity (comma conflict in items/keys prevention).
13. Transport header conflicts prevention (Host, Content-Length, etc.).
14. Illegal parameter zero request verification across all failure modes.
15. Illegal/unsupported cookies never produce CONFIRMED or SECURE results.
16. Sensitive object property redaction in HTML, JSON, and SARIF reports.
17. OpenAPI 3.2 style: cookie boundary tests (fail-closed, 0 requests).
18. Non-GET write operations (PATCH/PUT) safety boundary tests (fail-closed, 0 requests).
19. GET independent readback integration with Header array and object wire delivery.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.auditor import APISentinelAuditor
from core.models import Verdict
from core.parameters import (
    ParameterSerializationError,
    serialize_cookie_parameter,
    serialize_header_parameter,
)
from core.reporter import SecurityReportGenerator
from core.sarif import SarifReportGenerator


class ArrayObjectRecordingHandler(BaseHTTPRequestHandler):
    """Local disposable HTTP handler recording received wire headers."""

    requests: List[Tuple[str, str, Dict[str, str]]] = []
    lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        with self.lock:
            headers_dict = {k: v for k, v in self.headers.items()}
            self.requests.append((self.command, self.path, headers_dict))

        auth = self.headers.get("Authorization", "")
        if self.path.startswith("/api/echo/"):
            doc_id = self.path.split("?")[0].split("/")[-1]
            body_dict = {
                "id": doc_id,
                "title": "Echo Response",
                "echo_auth": auth,
                "echo_cookie": self.headers.get("Cookie", ""),
                "echo_header": self.headers.get("X-Array-Header", ""),
                "echo_context": self.headers.get("X-Context", ""),
            }
            body = json.dumps(body_dict).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/readback/"):
            doc_id = self.path.split("?")[0].split("/")[-1]
            tags = self.headers.get("X-Readback-Tags", "")
            ctx = self.headers.get("X-Readback-Context", "")
            body_dict = {
                "id": doc_id,
                "title": f"Document {doc_id}",
                "readback_tags": tags,
                "readback_context": ctx,
                "readback_auth": auth,
            }
            body = json.dumps(body_dict).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/documents/"):
            doc_id = self.path.split("?")[0].split("/")[-1]
            if "Bearer OWNER_TOKEN" in auth:
                body = json.dumps({"id": doc_id, "title": "Owner Doc", "owner": "1001"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif "Bearer VISITOR_TOKEN" in auth:
                if doc_id == "doc-owner":
                    # BOLA trigger
                    body = json.dumps({"id": doc_id, "title": "Owner Doc", "owner": "1001"}).encode("utf-8")
                    self.send_response(200)
                else:
                    body = json.dumps({"id": doc_id, "title": "Visitor Doc", "owner": "1002"}).encode("utf-8")
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                body = json.dumps({"error": "Unauthorized"}).encode("utf-8")
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        else:
            body = json.dumps({"status": "ok"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_PATCH(self) -> None:  # noqa: N802
        with self.lock:
            headers_dict = {k: v for k, v in self.headers.items()}
            self.requests.append((self.command, self.path, headers_dict))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_PUT(self) -> None:  # noqa: N802
        with self.lock:
            headers_dict = {k: v for k, v in self.headers.items()}
            self.requests.append((self.command, self.path, headers_dict))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


class HeaderCookieArrayObjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ArrayObjectRecordingHandler.requests = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ArrayObjectRecordingHandler)
        cls.host, cls.port = cls.server.server_address
        cls.target_url = f"http://{cls.host}:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    def setUp(self) -> None:
        with ArrayObjectRecordingHandler.lock:
            ArrayObjectRecordingHandler.requests.clear()

    def _make_spec(
        self,
        parameters: List[Dict[str, Any]],
        path: str = "/api/documents/{doc_id}",
        version: str = "3.0.3",
    ) -> Dict[str, Any]:
        if version.startswith("2."):
            return {
                "swagger": "2.0",
                "info": {"title": "Test Swagger 2", "version": "1.0.0"},
                "paths": {
                    path: {
                        "get": {
                            "operationId": "getDocument",
                            "parameters": [
                                {"name": "doc_id", "in": "path", "required": True, "type": "string"},
                                *parameters,
                            ],
                            "responses": {"200": {"description": "OK"}},
                            "security": [{"BearerAuth": []}],
                        }
                    }
                },
                "securityDefinitions": {
                    "BearerAuth": {"type": "apiKey", "name": "Authorization", "in": "header"}
                },
            }
        return {
            "openapi": version,
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                path: {
                    "get": {
                        "operationId": "getDocument",
                        "parameters": [
                            {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
                            *parameters,
                        ],
                        "responses": {"200": {"description": "OK"}},
                        "security": [{"BearerAuth": []}],
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "BearerAuth": {"type": "http", "scheme": "bearer"}
                }
            },
        }

    def _make_config(
        self,
        parameter_values: Optional[Dict[str, Any]] = None,
        extra_identities: Optional[Dict[str, Any]] = None,
        path: str = "/api/documents/{doc_id}",
    ) -> Dict[str, Any]:
        identities: Dict[str, Any] = {
            "owner": {
                "id": "1001",
                "token": "Bearer OWNER_TOKEN",
                "parameters": {"doc_id": "doc-owner"},
            },
            "visitor": {
                "id": "1002",
                "token": "Bearer VISITOR_TOKEN",
                "parameters": {"doc_id": "doc-visitor"},
            },
            "anonymous": {"id": None, "token": None, "parameters": {}},
        }
        if extra_identities:
            for role, data in extra_identities.items():
                identities[role].update(data)
        return {
            "identities": identities,
            "parameter_values": parameter_values or {},
            "bola": {
                f"GET {path}": {
                    "expected_visitor_access": "deny",
                    "resource_id_paths": ["id"],
                }
            },
        }

    def _run_audit(
        self,
        spec: Dict[str, Any],
        config: Dict[str, Any],
    ) -> APISentinelAuditor:
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_file = Path(temp_dir) / "spec.json"
            spec_file.write_text(json.dumps(spec), encoding="utf-8")

            auditor = APISentinelAuditor(
                spec_path=str(spec_file),
                target_base_url=self.target_url,
                identities_config=config.get("identities"),
                parameter_values=config.get("parameter_values"),
                bola_config=config.get("bola"),
                allow_http=True,
                request_delay=0,
            )
            auditor.run()
            return auditor

    # -------------------------------------------------------------------------
    # 1. Header primitive / array / object serialization
    # -------------------------------------------------------------------------

    def test_header_primitive_serialization(self) -> None:
        meta = {"name": "X-Simple-Header", "in": "header", "schema": {"type": "string"}}
        name, val = serialize_header_parameter(meta, "hello-world")
        self.assertEqual(name, "X-Simple-Header")
        self.assertEqual(val, "hello-world")

    def test_header_array_explode_false_wire_delivery(self) -> None:
        """Header array with explode=false serializes as comma-separated values."""
        spec = self._make_spec([
            {"name": "X-Roles", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Roles": ["admin", "auditor", "reader"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 4)

        for _, _, headers in ArrayObjectRecordingHandler.requests:
            self.assertEqual(headers.get("X-Roles"), "admin,auditor,reader")

    def test_header_array_explode_true_wire_delivery(self) -> None:
        """OAS 3 simple style header array with explode=true also serializes as comma-separated values."""
        spec = self._make_spec([
            {"name": "X-Roles", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": True}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Roles": ["sec", "ops"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)

        for _, _, headers in ArrayObjectRecordingHandler.requests:
            self.assertEqual(headers.get("X-Roles"), "sec,ops")

    def test_header_object_explode_false_wire_delivery(self) -> None:
        """Header object with explode=false serializes as k1,v1,k2,v2."""
        spec = self._make_spec([
            {"name": "X-Context", "in": "header", "schema": {"type": "object"}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Context": {"tenant": "acme", "env": "prod"}}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)

        for _, _, headers in ArrayObjectRecordingHandler.requests:
            self.assertEqual(headers.get("X-Context"), "tenant,acme,env,prod")

    def test_header_object_explode_true_wire_delivery(self) -> None:
        """Header object with explode=true serializes as k1=v1,k2=v2."""
        spec = self._make_spec([
            {"name": "X-Context", "in": "header", "schema": {"type": "object"}, "explode": True}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Context": {"tenant": "acme", "env": "prod"}}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)

        for _, _, headers in ArrayObjectRecordingHandler.requests:
            self.assertEqual(headers.get("X-Context"), "tenant=acme,env=prod")

    def test_serialize_cookie_parameter_direct_unit(self) -> None:
        """serialize_cookie_parameter directly raises ParameterSerializationError on array or object."""
        meta_arr = {"name": "c_arr", "in": "cookie", "schema": {"type": "array", "items": {"type": "string"}}}
        with self.assertRaises(ParameterSerializationError) as ctx:
            serialize_cookie_parameter(meta_arr, ["v1", "v2"])
        self.assertIn("Cookie array parameter serialization is unsupported under RFC 6265", str(ctx.exception))

        meta_obj = {"name": "c_obj", "in": "cookie", "schema": {"type": "object"}}
        with self.assertRaises(ParameterSerializationError) as ctx:
            serialize_cookie_parameter(meta_obj, {"k": "v"})
        self.assertIn("Cookie object parameter serialization is unsupported under RFC 6265", str(ctx.exception))

        # Scalar cookie returns tuple
        meta_str = {"name": "c_str", "in": "cookie", "schema": {"type": "string"}}
        name, val = serialize_cookie_parameter(meta_str, "valid_val")
        self.assertEqual(name, "c_str")
        self.assertEqual(val, "valid_val")

    # -------------------------------------------------------------------------
    # 2. Cookie parameter rules (Scalar supported, Array/Object rejected under RFC 6265)
    # -------------------------------------------------------------------------

    def test_cookie_primitive_wire_delivery(self) -> None:
        """Scalar cookie parameter is delivered in the HTTP Cookie header."""
        spec = self._make_spec([
            {"name": "client_id", "in": "cookie", "schema": {"type": "string"}}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"client_id": "cid-999"}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)

        for _, _, headers in ArrayObjectRecordingHandler.requests:
            cookie_header = headers.get("Cookie", "")
            self.assertIn("client_id=cid-999", cookie_header)

    def test_cookie_array_explode_false_rejected_zero_requests(self) -> None:
        """Cookie array parameter with explode=false is rejected under RFC 6265 with zero requests sent."""
        spec = self._make_spec([
            {"name": "features", "in": "cookie", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"features": ["beta", "darkmode"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Cookie array parameter serialization is unsupported under RFC 6265", auditor.results[0]["reason"])
        self.assertIn("no request was sent", auditor.results[0]["reason"])

    def test_cookie_array_explode_true_rejected_zero_requests(self) -> None:
        """Cookie array parameter with explode=true is rejected under RFC 6265 with zero requests sent."""
        spec = self._make_spec([
            {"name": "features", "in": "cookie", "schema": {"type": "array", "items": {"type": "string"}}, "explode": True}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"features": ["beta", "darkmode"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Cookie array parameter serialization is unsupported under RFC 6265", auditor.results[0]["reason"])
        self.assertIn("no request was sent", auditor.results[0]["reason"])

    def test_cookie_object_explode_false_rejected_zero_requests(self) -> None:
        """Cookie object parameter with explode=false is rejected under RFC 6265 with zero requests sent."""
        spec = self._make_spec([
            {"name": "prefs", "in": "cookie", "schema": {"type": "object"}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"prefs": {"theme": "dark", "lang": "en"}}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Cookie object parameter serialization is unsupported under RFC 6265", auditor.results[0]["reason"])
        self.assertIn("no request was sent", auditor.results[0]["reason"])

    def test_cookie_object_explode_true_rejected_zero_requests(self) -> None:
        """Cookie object parameter with explode=true is rejected under RFC 6265 with zero requests sent."""
        spec = self._make_spec([
            {"name": "prefs", "in": "cookie", "schema": {"type": "object"}, "explode": True}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"prefs": {"theme": "dark"}}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Cookie object parameter serialization is unsupported under RFC 6265", auditor.results[0]["reason"])
        self.assertIn("no request was sent", auditor.results[0]["reason"])

    def test_illegal_cookie_never_produces_confirmed_or_secure(self) -> None:
        """Illegal cookie configurations fail-closed and must never produce CONFIRMED or SECURE."""
        bad_specs = [
            ("array_explode_false", [{"name": "c_arr", "in": "cookie", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}], {"c_arr": ["a", "b"]}),
            ("array_explode_true", [{"name": "c_arr", "in": "cookie", "schema": {"type": "array", "items": {"type": "string"}}, "explode": True}], {"c_arr": ["a", "b"]}),
            ("object_explode_false", [{"name": "c_obj", "in": "cookie", "schema": {"type": "object"}, "explode": False}], {"c_obj": {"k": "v"}}),
            ("object_explode_true", [{"name": "c_obj", "in": "cookie", "schema": {"type": "object"}, "explode": True}], {"c_obj": {"k": "v"}}),
        ]
        for name, params, values in bad_specs:
            with self.subTest(scenario=name):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                spec = self._make_spec(params)
                config = self._make_config(parameter_values={"GET /api/documents/{doc_id}": {"common": values}})
                auditor = self._run_audit(spec, config)
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                self.assertNotEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)
                self.assertNotEqual(auditor.results[0]["verdict"], Verdict.SECURE)
                self.assertEqual(auditor.stats["confirmed"], 0)
                self.assertEqual(auditor.stats["secure_endpoints"], 0)
                self.assertEqual(auditor.stats["http_requests_sent"], 0)

    def test_cookie_style_cookie_rejected_zero_requests(self) -> None:
        """OpenAPI 3.2.0 style: cookie is explicitly unsupported and fails closed with zero requests."""
        cases = [
            ("scalar", {"name": "c_pref", "in": "cookie", "style": "cookie", "schema": {"type": "string"}}, "dark"),
            ("array", {"name": "c_tags", "in": "cookie", "style": "cookie", "schema": {"type": "array", "items": {"type": "string"}}}, ["a", "b"]),
            ("object", {"name": "c_ctx", "in": "cookie", "style": "cookie", "schema": {"type": "object"}}, {"k": "v"}),
        ]
        for kind, meta, val in cases:
            with self.subTest(kind=kind):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                # Explicitly use OpenAPI 3.2.0 document fixture
                spec = self._make_spec([meta], version="3.2.0")
                self.assertEqual(spec["openapi"], "3.2.0")
                config = self._make_config(parameter_values={"GET /api/documents/{doc_id}": {"common": {meta["name"]: val}}})
                auditor = self._run_audit(spec, config)
                # Verify parser successfully parsed OpenAPI 3.2.0 document (distinguishing parser from parameter serialization)
                self.assertEqual(auditor.parser.version, "OpenAPI 3.2.0")
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                self.assertIn("Unsupported parameter style for its location", auditor.results[0]["reason"])
                self.assertNotEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)
                self.assertNotEqual(auditor.results[0]["verdict"], Verdict.SECURE)
                self.assertEqual(auditor.stats["confirmed"], 0)
                self.assertEqual(auditor.stats["secure_endpoints"], 0)
                self.assertEqual(auditor.stats["http_requests_sent"], 0)

    # -------------------------------------------------------------------------
    # 3. OpenAPI vs Swagger 2.0 rules
    # -------------------------------------------------------------------------

    def test_swagger2_header_array_csv_wire_delivery(self) -> None:
        """Swagger 2 header array with collectionFormat=csv serializes correctly."""
        spec = self._make_spec(
            [{"name": "X-Tags", "in": "header", "type": "array", "collectionFormat": "csv",
              "items": {"type": "string"}}],
            version="2.0",
        )
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Tags": ["v1", "v2"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)

        for _, _, headers in ArrayObjectRecordingHandler.requests:
            self.assertEqual(headers.get("X-Tags"), "v1,v2")

    def test_swagger2_header_array_non_csv_rejected_zero_requests(self) -> None:
        """Swagger 2 header parameters only support collectionFormat=csv."""
        for fmt in ("pipes", "ssv", "tsv", "multi"):
            with self.subTest(collectionFormat=fmt):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                spec = self._make_spec(
                    [{"name": "X-Tags", "in": "header", "type": "array", "collectionFormat": fmt,
                      "items": {"type": "string"}}],
                    version="2.0",
                )
                config = self._make_config(
                    parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Tags": ["v1", "v2"]}}}
                )
                auditor = self._run_audit(spec, config)
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                self.assertIn("no request was sent", auditor.results[0]["reason"])

    def test_swagger2_header_object_rejected_zero_requests(self) -> None:
        """Swagger 2 does not support non-body object parameters."""
        spec = self._make_spec(
            [{"name": "X-Obj", "in": "header", "type": "object"}],
            version="2.0",
        )
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Obj": {"k": "v"}}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Swagger 2 non-body object", auditor.results[0]["reason"])

    def test_swagger2_cookie_rejected_zero_requests(self) -> None:
        """Swagger 2 has no cookie parameters."""
        spec = self._make_spec(
            [{"name": "session", "in": "cookie", "type": "string"}],
            version="2.0",
        )
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"session": "abc"}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Swagger 2 does not support cookie parameters", auditor.results[0]["reason"])

    # -------------------------------------------------------------------------
    # 4. Empty containers and nested containers
    # -------------------------------------------------------------------------

    def test_empty_array_and_object_rejected_zero_requests(self) -> None:
        for location in ("header", "cookie"):
            for val, kind in [([], "array"), ({}, "object")]:
                with self.subTest(location=location, kind=kind):
                    with ArrayObjectRecordingHandler.lock:
                        ArrayObjectRecordingHandler.requests.clear()
                    schema: Dict[str, Any] = {"type": kind}
                    if kind == "array":
                        schema["items"] = {"type": "string"}
                    spec = self._make_spec([
                        {"name": "param_test", "in": location, "schema": schema, "explode": False}
                    ])
                    config = self._make_config(
                        parameter_values={"GET /api/documents/{doc_id}": {"common": {"param_test": val}}}
                    )
                    auditor = self._run_audit(spec, config)
                    self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                    self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                    self.assertIn(f"Empty {kind} parameter serialization is unsupported", auditor.results[0]["reason"])

    def test_nested_containers_rejected_zero_requests(self) -> None:
        cases = [
            ("header", [["nested"]], "array"),
            ("header", {"outer": {"inner": "v"}}, "object"),
            ("cookie", [["nested"]], "array"),
            ("cookie", {"outer": {"inner": "v"}}, "object"),
        ]
        for location, val, kind in cases:
            with self.subTest(location=location, kind=kind):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                schema: Dict[str, Any] = {"type": kind}
                if kind == "array":
                    schema["items"] = {"type": "string"}
                spec = self._make_spec([
                    {"name": "nested_param", "in": location, "schema": schema, "explode": False}
                ])
                config = self._make_config(
                    parameter_values={"GET /api/documents/{doc_id}": {"common": {"nested_param": val}}}
                )
                auditor = self._run_audit(spec, config)
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                self.assertIn("nested values are unsupported", auditor.results[0]["reason"])

    # -------------------------------------------------------------------------
    # 5. CRLF and control character injection
    # -------------------------------------------------------------------------

    def test_crlf_and_control_injection_in_header_array_items_blocked(self) -> None:
        injections = [
            "valid\r\nInjected: true",
            "valid\nInjected: true",
            "valid\0injected",
            "valid\x1b[31minjected",
            "valid\x01control",
        ]
        for payload in injections:
            with self.subTest(payload=repr(payload)):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                spec = self._make_spec([
                    {"name": "X-Roles", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}
                ])
                config = self._make_config(
                    parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Roles": ["admin", payload]}}}
                )
                auditor = self._run_audit(spec, config)
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                self.assertIn("CRLF injection prevented", auditor.results[0]["reason"])

    def test_crlf_and_control_injection_in_header_object_blocked(self) -> None:
        injections = [
            ({"safe": "val\r\nInjected: true"}, "value"),
            ({"safe\r\nInjected: true": "val"}, "key"),
            ({"safe": "val\0null"}, "null byte"),
        ]
        for obj_val, desc in injections:
            with self.subTest(desc=desc):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                spec = self._make_spec([
                    {"name": "X-Context", "in": "header", "schema": {"type": "object"}, "explode": False}
                ])
                config = self._make_config(
                    parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Context": obj_val}}}
                )
                auditor = self._run_audit(spec, config)
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                self.assertIn("CRLF injection prevented", auditor.results[0]["reason"])

    def test_cookie_delimiter_and_whitespace_injection_blocked(self) -> None:
        """Scalar cookie parameters must reject semicolons, quotes, whitespace, commas, and delimiters."""
        bad_cookies = [
            "item; evil=1",
            "item with spaces",
            'item"quoted"',
            "item\\escaped",
            "item\r\ninjected",
            "item,with,comma",
        ]
        for bad_item in bad_cookies:
            with self.subTest(bad_item=bad_item):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                spec = self._make_spec([
                    {"name": "client_tag", "in": "cookie", "schema": {"type": "string"}}
                ])
                config = self._make_config(
                    parameter_values={"GET /api/documents/{doc_id}": {"common": {"client_tag": bad_item}}}
                )
                auditor = self._run_audit(spec, config)
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                self.assertIn("CRLF or delimiter injection prevented", auditor.results[0]["reason"])

    # -------------------------------------------------------------------------
    # 6. Delimiter ambiguity (comma conflict in items/keys)
    # -------------------------------------------------------------------------

    def test_delimiter_ambiguity_comma_in_header_array_item_blocked(self) -> None:
        spec = self._make_spec([
            {"name": "X-Roles", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Roles": ["admin,superuser", "reader"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("delimiter comma ','", auditor.results[0]["reason"])

    def test_delimiter_ambiguity_in_header_object_blocked(self) -> None:
        # Explode false: comma in key or value
        spec = self._make_spec([
            {"name": "X-Ctx", "in": "header", "schema": {"type": "object"}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Ctx": {"a,b": "c"}}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("delimiter comma ','", auditor.results[0]["reason"])

        # Explode true: equals in key or value
        with ArrayObjectRecordingHandler.lock:
            ArrayObjectRecordingHandler.requests.clear()
        spec_explode = self._make_spec([
            {"name": "X-Ctx", "in": "header", "schema": {"type": "object"}, "explode": True}
        ])
        config_explode = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Ctx": {"k=1": "v"}}}}
        )
        auditor_explode = self._run_audit(spec_explode, config_explode)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor_explode.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("delimiter", auditor_explode.results[0]["reason"])

    # -------------------------------------------------------------------------
    # 7. Identity conflicts & transport conflicts
    # -------------------------------------------------------------------------

    def test_header_array_collision_with_identity_header_blocked(self) -> None:
        spec = self._make_spec([
            {"name": "X-Custom-Auth", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Custom-Auth": ["token1", "token2"]}}},
            extra_identities={
                "owner": {"headers": {"X-Custom-Auth": "OWNER_AUTH"}},
                "visitor": {"headers": {"X-Custom-Auth": "VISITOR_AUTH"}},
            },
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("conflicts with identity header", auditor.results[0]["reason"])

    def test_cookie_collision_with_identity_cookie_blocked(self) -> None:
        """Business cookie parameter conflicting with identity cookie name is blocked before any request."""
        spec = self._make_spec([
            {"name": "session_id", "in": "cookie", "schema": {"type": "string"}}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"session_id": "malicious_sess"}}},
            extra_identities={
                "owner": {"headers": {"Cookie": "session_id=OWNER_COOKIE"}},
                "visitor": {"headers": {"Cookie": "session_id=VISITOR_COOKIE"}},
            },
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("conflicts with identity authentication cookie", auditor.results[0]["reason"])

    def test_transport_header_collision_with_array_blocked(self) -> None:
        for bad_header in ("Host", "Content-Length", "Transfer-Encoding", "Connection"):
            with self.subTest(header=bad_header):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                spec = self._make_spec([
                    {"name": bad_header, "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}
                ])
                config = self._make_config(
                    parameter_values={"GET /api/documents/{doc_id}": {"common": {bad_header: ["val1", "val2"]}}}
                )
                auditor = self._run_audit(spec, config)
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                self.assertIn("conflicts with transport-managed header", auditor.results[0]["reason"])

    # -------------------------------------------------------------------------
    # 8. Authentication isolation (Owner, Visitor, Anonymous)
    # -------------------------------------------------------------------------

    def test_identity_isolation_with_business_arrays_and_cookies(self) -> None:
        """Owner, Visitor, and Anonymous maintain their respective auth state while sharing business parameters."""
        spec = self._make_spec([
            {"name": "X-Audit-Tags", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False},
            {"name": "ui_theme", "in": "cookie", "schema": {"type": "string"}},
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {
                "common": {
                    "X-Audit-Tags": ["security", "audit"],
                    "ui_theme": "dark",
                }
            }},
            extra_identities={
                "owner": {"headers": {"Cookie": "user_id=1001"}},
                "visitor": {"headers": {"Cookie": "user_id=1002"}},
            },
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 4)

        # Confirm that each request preserves proper credentials
        auth_headers = [h.get("Authorization") for _, _, h in ArrayObjectRecordingHandler.requests]
        self.assertIn("Bearer OWNER_TOKEN", auth_headers)
        self.assertIn("Bearer VISITOR_TOKEN", auth_headers)
        self.assertIn(None, auth_headers)  # Anonymous request has no Authorization header

        # Confirm merged cookie: user_id auth cookie + business ui_theme cookie
        for _, _, h in ArrayObjectRecordingHandler.requests:
            cookie = h.get("Cookie", "")
            self.assertIn("ui_theme=dark", cookie)
            self.assertEqual(h.get("X-Audit-Tags"), "security,audit")
            if "Bearer OWNER_TOKEN" in str(h.get("Authorization")):
                self.assertIn("user_id=1001", cookie)
            elif "Bearer VISITOR_TOKEN" in str(h.get("Authorization")):
                self.assertIn("user_id=1002", cookie)

    # -------------------------------------------------------------------------
    # 9. Parameter missing and type mismatch
    # -------------------------------------------------------------------------

    def test_missing_required_array_parameter_sends_zero_requests(self) -> None:
        spec = self._make_spec([
            {"name": "X-Required-List", "in": "header", "required": True, "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}
        ])
        config = self._make_config()  # no parameter value supplied
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Missing required header parameter 'X-Required-List'", auditor.results[0]["reason"])

    def test_type_mismatch_array_expected_got_scalar_sends_zero_requests(self) -> None:
        spec = self._make_spec([
            {"name": "X-Roles", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Roles": "admin"}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Configured parameter value must retain its declared array/object structure", auditor.results[0]["reason"])

    def test_type_mismatch_object_expected_got_array_sends_zero_requests(self) -> None:
        spec = self._make_spec([
            {"name": "X-Context", "in": "header", "schema": {"type": "object"}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Context": ["item1", "item2"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Configured parameter value must retain its declared array/object structure", auditor.results[0]["reason"])

    # -------------------------------------------------------------------------
    # 10. Report redaction of sensitive values in array and object parameters
    # -------------------------------------------------------------------------

    def test_sensitive_array_and_object_values_redacted_in_reports(self) -> None:
        """Sensitive parameters configured as array or object must be redacted in HTML, JSON, and SARIF."""
        secret_token1 = "TOP_SECRET_ARRAY_TOKEN_ALPHA"
        secret_token2 = "TOP_SECRET_ARRAY_TOKEN_BETA"
        secret_obj_val = "TOP_SECRET_OBJECT_VAL"

        spec = self._make_spec([
            {"name": "X-Secret-Tokens", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False},
            {"name": "X-Secret-Obj", "in": "header", "schema": {"type": "object"}, "explode": True},
        ], path="/api/echo/{doc_id}")

        config = self._make_config(
            parameter_values={"GET /api/echo/{doc_id}": {
                "common": {
                    "X-Secret-Tokens": [secret_token1, secret_token2],
                    "X-Secret-Obj": {"api_key": secret_obj_val},
                }
            }},
            path="/api/echo/{doc_id}",
        )

        auditor = self._run_audit(spec, config)

        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = str(Path(temp_dir) / "report.html")
            json_path = str(Path(temp_dir) / "report.json")
            sarif_path = str(Path(temp_dir) / "report.sarif")

            findings = [r["finding"] for r in auditor.results if r.get("finding")]
            SecurityReportGenerator.generate(
                auditor.stats,
                findings,
                self.target_url,
                html_path,
                results=auditor.results,
                secret_values=auditor._secret_values,
            )
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({"results": auditor.results, "findings": auditor.findings}, f)

            SarifReportGenerator.generate(
                auditor.results,
                self.target_url,
                str(sarif_path),
                secret_values=auditor._secret_values,
            )

            html_text = Path(html_path).read_text(encoding="utf-8")
            json_text = Path(json_path).read_text(encoding="utf-8")
            sarif_text = Path(sarif_path).read_text(encoding="utf-8")

            for secret in (secret_token1, secret_token2, secret_obj_val):
                self.assertNotIn(secret, html_text, f"Secret {secret} leaked in HTML report")
                self.assertNotIn(secret, json_text, f"Secret {secret} leaked in JSON report")
                self.assertNotIn(secret, sarif_text, f"Secret {secret} leaked in SARIF report")

    # -------------------------------------------------------------------------
    # 11. Sensitive object field redaction (Section V)
    # -------------------------------------------------------------------------

    def test_sensitive_inner_object_field_redacted_without_over_redaction(self) -> None:
        """Ordinary outer header parameter with sensitive inner object property is redacted in all reports.

        Verifies:
        1. Inner sensitive property (access_token) is recognized and its value collected.
        2. Even if echoed by server in response body/headers, the secret value is not leaked.
        3. HTML, JSON, and SARIF reports all redact the secret value.
        4. Non-sensitive property names (tenant) and values (acme_corp) are NOT over-redacted.
        5. Existing Owner and Visitor authentication tokens remain properly redacted.
        """
        sensitive_val = "SECRET_INNER_TOKEN_XYZ_98765"
        ordinary_prop = "tenant"
        ordinary_val = "acme_tenant_corp"

        spec = self._make_spec([
            {"name": "X-Context", "in": "header", "schema": {"type": "object"}, "explode": True}
        ], path="/api/echo/{doc_id}")

        config = self._make_config(
            parameter_values={"GET /api/echo/{doc_id}": {
                "common": {
                    "X-Context": {ordinary_prop: ordinary_val, "access_token": sensitive_val}
                }
            }},
            path="/api/echo/{doc_id}",
        )

        auditor = self._run_audit(spec, config)

        # 1. Verify sensitive value is collected into auditor._secret_values
        self.assertIn(sensitive_val, auditor._secret_values)

        # 2. Verify non-sensitive property name and ordinary value are NOT in secrets (no over-redaction)
        self.assertNotIn(ordinary_prop, auditor._secret_values)
        self.assertNotIn(ordinary_val, auditor._secret_values)
        self.assertNotIn("access_token", auditor._secret_values)

        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = str(Path(temp_dir) / "report.html")
            json_path = str(Path(temp_dir) / "report.json")
            sarif_path = str(Path(temp_dir) / "report.sarif")

            findings = [r["finding"] for r in auditor.results if r.get("finding")]
            SecurityReportGenerator.generate(
                auditor.stats,
                findings,
                self.target_url,
                html_path,
                results=auditor.results,
                secret_values=auditor._secret_values,
            )
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({"results": auditor.results, "findings": auditor.findings}, f)

            SarifReportGenerator.generate(
                auditor.results,
                self.target_url,
                str(sarif_path),
                secret_values=auditor._secret_values,
            )

            html_text = Path(html_path).read_text(encoding="utf-8")
            json_text = Path(json_path).read_text(encoding="utf-8")
            sarif_text = Path(sarif_path).read_text(encoding="utf-8")

            # 3. HTML, JSON, and SARIF must NOT contain the sensitive value
            self.assertNotIn(sensitive_val, html_text, "Sensitive inner token leaked in HTML")
            self.assertNotIn(sensitive_val, json_text, "Sensitive inner token leaked in JSON")
            self.assertNotIn(sensitive_val, sarif_text, "Sensitive inner token leaked in SARIF")

            # 4. Ordinary values must be preserved in reports (no over-redaction)
            self.assertIn(ordinary_val, html_text, "Ordinary value incorrectly redacted in HTML")
            self.assertIn(ordinary_val, json_text, "Ordinary value incorrectly redacted in JSON")

            # 5. Existing auth credentials remain properly redacted
            for auth_token in ("OWNER_TOKEN", "VISITOR_TOKEN"):
                self.assertNotIn(auth_token, html_text)
                self.assertNotIn(auth_token, json_text)
                self.assertNotIn(auth_token, sarif_text)

    # -------------------------------------------------------------------------
    # 12. Non-GET write operations (PATCH/PUT) safety boundary tests
    # -------------------------------------------------------------------------

    def test_patch_and_put_with_unsupported_parameters_rejected_zero_requests(self) -> None:
        """PATCH and PUT operations declaring Header array/object or Cookie are rejected before transport."""
        cases = [
            ("PATCH", "header_array", {"name": "X-Roles", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}}, ["admin", "editor"]),
            ("PATCH", "header_object", {"name": "X-Ctx", "in": "header", "schema": {"type": "object"}}, {"k": "v"}),
            ("PATCH", "cookie", {"name": "sess", "in": "cookie", "schema": {"type": "string"}}, "token123"),
            ("PUT", "header_array", {"name": "X-Roles", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}}, ["admin", "editor"]),
            ("PUT", "header_object", {"name": "X-Ctx", "in": "header", "schema": {"type": "object"}}, {"k": "v"}),
            ("PUT", "cookie", {"name": "sess", "in": "cookie", "schema": {"type": "string"}}, "token123"),
        ]

        for method, desc, param, val in cases:
            with self.subTest(method=method, scenario=desc):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                endpoint = {
                    "method": method,
                    "path": "/api/documents/{doc_id}",
                    "parameters": [
                        {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
                        param,
                    ],
                    "request_content_type": "application/json",
                    "request_schema": {
                        "type": "object",
                        "properties": {"title": {"type": "string"}},
                    },
                }
                config = self._make_config(
                    parameter_values={f"{method} /api/documents/{{doc_id}}": {"common": {param["name"]: val}}}
                )
                with tempfile.TemporaryDirectory() as temp_dir:
                    spec_file = Path(temp_dir) / "spec.json"
                    spec = {
                        "openapi": "3.0.3",
                        "info": {"title": "Test Write", "version": "1.0.0"},
                        "paths": {"/api/documents/{doc_id}": {method.lower(): endpoint}},
                    }
                    spec_file.write_text(json.dumps(spec), encoding="utf-8")

                    auditor = APISentinelAuditor(
                        spec_path=str(spec_file),
                        target_base_url=self.target_url,
                        identities_config=config.get("identities"),
                        parameter_values=config.get("parameter_values"),
                        allow_write_tests=True,
                        write_allowlist=[f"{method} /api/documents/{{doc_id}}"],
                        readback_config={
                            f"{method} /api/documents/{{doc_id}}": {
                                "path": "/api/documents/{doc_id}",
                                "field_map": {"title": "title"},
                            }
                        },
                        allow_http=True,
                        request_delay=0,
                    )
                    auditor.audit_endpoint_mass_assignment(endpoint, [endpoint])
                    self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0, f"Expected 0 requests for {method} {desc}")
                    self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
                    self.assertIn("not supported for", auditor.results[0]["reason"])
                    self.assertEqual(auditor.stats["confirmed"], 0)
                    self.assertEqual(auditor.stats["secure_endpoints"], 0)

    # -------------------------------------------------------------------------
    # 13. GET independent readback integration with Header array and object
    # -------------------------------------------------------------------------

    def test_get_independent_readback_with_header_array_and_object_wire_delivery(self) -> None:
        """GET independent readback correctly serializes Header array and object with identity isolation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_file = Path(temp_dir) / "spec.json"
            spec = {
                "openapi": "3.0.3",
                "info": {"title": "Test Readback", "version": "1.0.0"},
                "paths": {
                    "/api/readback/{doc_id}": {
                        "get": {
                            "operationId": "readbackDoc",
                            "parameters": [
                                {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
                                {"name": "X-Readback-Tags", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False},
                                {"name": "X-Readback-Context", "in": "header", "schema": {"type": "object"}, "explode": True},
                            ],
                            "responses": {"200": {"description": "OK"}},
                        }
                    }
                },
            }
            spec_file.write_text(json.dumps(spec), encoding="utf-8")

            config = self._make_config()
            auditor = APISentinelAuditor(
                spec_path=str(spec_file),
                target_base_url=self.target_url,
                identities_config=config.get("identities"),
                allow_http=True,
                request_delay=0,
            )

            readback_mapping = {
                "path": "/api/readback/{doc_id}",
                "parameters": [
                    {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "X-Readback-Tags", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False},
                    {"name": "X-Readback-Context", "in": "header", "schema": {"type": "object"}, "explode": True},
                ],
                "parameter_values": {
                    "X-Readback-Tags": ["audit", "compliance"],
                    "X-Readback-Context": {"tenant": "acme", "env": "prod"},
                },
                "field_map": {"title": "title"},
            }

            dummy_ep = {"method": "GET", "path": "/api/items/{doc_id}"}

            # 1. Test Owner readback
            with ArrayObjectRecordingHandler.lock:
                ArrayObjectRecordingHandler.requests.clear()
            owner_url, owner_res = auditor._readback_result(dummy_ep, readback_mapping, "owner")
            self.assertEqual(owner_res.status, 200)
            self.assertTrue(owner_url.endswith("/api/readback/doc-owner"))
            self.assertEqual(len(ArrayObjectRecordingHandler.requests), 1)
            _, _, owner_headers = ArrayObjectRecordingHandler.requests[0]
            self.assertEqual(owner_headers.get("X-Readback-Tags"), "audit,compliance")
            self.assertEqual(owner_headers.get("X-Readback-Context"), "tenant=acme,env=prod")
            self.assertEqual(owner_headers.get("Authorization"), "Bearer OWNER_TOKEN")

            # 2. Test Visitor readback
            with ArrayObjectRecordingHandler.lock:
                ArrayObjectRecordingHandler.requests.clear()
            visitor_url, visitor_res = auditor._readback_result(dummy_ep, readback_mapping, "visitor")
            self.assertEqual(visitor_res.status, 200)
            self.assertTrue(visitor_url.endswith("/api/readback/doc-visitor"))
            self.assertEqual(len(ArrayObjectRecordingHandler.requests), 1)
            _, _, visitor_headers = ArrayObjectRecordingHandler.requests[0]
            self.assertEqual(visitor_headers.get("X-Readback-Tags"), "audit,compliance")
            self.assertEqual(visitor_headers.get("X-Readback-Context"), "tenant=acme,env=prod")
            self.assertEqual(visitor_headers.get("Authorization"), "Bearer VISITOR_TOKEN")

    def test_get_independent_readback_invalid_header_fails_closed_zero_requests(self) -> None:
        """Readback parameter serialization failure fails closed before request and never produces CONFIRMED."""
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_file = Path(temp_dir) / "spec.json"
            spec = {
                "openapi": "3.0.3",
                "info": {"title": "Test Readback", "version": "1.0.0"},
                "paths": {"/api/documents/{doc_id}": {"get": {"responses": {"200": {"description": "OK"}}}}},
            }
            spec_file.write_text(json.dumps(spec), encoding="utf-8")

            config = self._make_config()
            auditor = APISentinelAuditor(
                spec_path=str(spec_file),
                target_base_url=self.target_url,
                identities_config=config.get("identities"),
                allow_http=True,
                request_delay=0,
            )

            # Readback has a delimiter comma in array item
            invalid_readback = {
                "path": "/api/readback/{doc_id}",
                "parameters": [
                    {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "X-Tags", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}, "explode": False},
                ],
                "parameter_values": {"X-Tags": ["item,with,comma"]},
                "field_map": {"title": "title"},
            }

            with ArrayObjectRecordingHandler.lock:
                ArrayObjectRecordingHandler.requests.clear()

            dummy_ep = {"method": "GET", "path": "/api/documents/{doc_id}"}
            with self.assertRaises(ParameterSerializationError) as ctx:
                auditor._readback_result(dummy_ep, invalid_readback, "visitor")
            self.assertIn("delimiter comma ','", str(ctx.exception))
            self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)

    def test_patch_independent_get_readback_invalid_header_array_rejected_preflight_zero_requests(self) -> None:
        """PATCH operation with independent GET readback declaring Header array fails preflight on invalid delimiter comma with 0 requests."""
        patch_endpoint = {
            "operationId": "updateDocument",
            "parameters": [
                {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
            ],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"title": {"type": "string"}},
                        }
                    }
                },
            },
            "responses": {"200": {"description": "OK"}},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_file = Path(temp_dir) / "spec.json"
            spec = {
                "openapi": "3.0.3",
                "info": {"title": "Test Patch Readback Preflight", "version": "1.0.0"},
                "paths": {
                    "/api/documents/{doc_id}": {"patch": patch_endpoint},
                },
            }
            spec_file.write_text(json.dumps(spec), encoding="utf-8")

            config = self._make_config(
                parameter_values={
                    "PATCH /api/documents/{doc_id}": {"visitor": {"doc_id": "doc-visitor"}},
                }
            )

            # Readback declares Header array parameter, but value contains illegal delimiter comma ','
            readback_config = {
                "PATCH /api/documents/{doc_id}": {
                    "path": "/api/readback/{doc_id}",
                    "parameters": [
                        {"name": "doc_id", "in": "path", "required": True, "schema": {"type": "string"}},
                        {
                            "name": "X-Readback-Tags",
                            "in": "header",
                            "schema": {"type": "array", "items": {"type": "string"}},
                            "explode": False,
                        },
                    ],
                    "parameter_values": {
                        "doc_id": "doc-visitor",
                        "X-Readback-Tags": ["valid_prefix", "illegal,delimiter,item"],
                    },
                    "field_map": {"title": "title"},
                }
            }

            with ArrayObjectRecordingHandler.lock:
                ArrayObjectRecordingHandler.requests.clear()

            auditor = APISentinelAuditor(
                spec_path=str(spec_file),
                target_base_url=self.target_url,
                identities_config=config.get("identities"),
                parameter_values=config.get("parameter_values"),
                allow_write_tests=True,
                write_allowlist=["PATCH /api/documents/{doc_id}"],
                readback_config=readback_config,
                allow_http=True,
                request_delay=0,
            )

            # Execute full audit chain via auditor.run()
            auditor.run()

            # Verify 0 requests sent: both GET and PATCH request counts are 0
            self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0, "Expected 0 wire requests for preflight failure")
            self.assertEqual(auditor.stats["http_requests_sent"], 0)

            # Verify MASS_ASSIGNMENT result is INCONCLUSIVE
            mass_assignment_results = [r for r in auditor.results if r.get("check") == "MASS_ASSIGNMENT"]
            self.assertEqual(len(mass_assignment_results), 1)
            ma_result = mass_assignment_results[0]
            self.assertEqual(ma_result["verdict"], Verdict.INCONCLUSIVE)
            self.assertIn("delimiter comma ','", ma_result["reason"])
            self.assertEqual(ma_result["evidence"].get("requests_attempted"), 0)

            # Verify confirmed = 0 and secure_endpoints = 0
            self.assertEqual(auditor.stats["confirmed"], 0)
            self.assertEqual(auditor.stats["secure_endpoints"], 0)
            self.assertNotEqual(ma_result["verdict"], Verdict.CONFIRMED)
            self.assertNotEqual(ma_result["verdict"], Verdict.SECURE)


if __name__ == "__main__":
    unittest.main()
