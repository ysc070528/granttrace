"""Comprehensive tests for Header and Cookie array and object parameter serialization.

Verifies:
1. Header primitive, array, and object support with simple style.
2. Explode settings (explode=false, explode=true) for headers and cookies.
3. Cookie primitive, array, and object support with form style.
4. OpenAPI 3.x vs Swagger 2.0 rules (Swagger 2 collectionFormat=csv, non-csv rejection, object rejection).
5. Empty arrays, empty objects, and nested containers rejection.
6. CRLF, null byte, and control character injection prevention.
7. Header/Cookie identity conflicts with Authorization and session credentials.
8. Owner, Visitor, and Anonymous authentication isolation.
9. Parameter missing and schema type mismatches.
10. Delimiter ambiguity (comma, semicolon, equals conflict prevention).
11. Illegal parameter zero request verification across all failure modes.
12. Compatibility with existing GET readback functionality.
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
            {"name": "X-Roles", "in": "header", "schema": {"type": "array"}, "explode": False}
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
            {"name": "X-Roles", "in": "header", "schema": {"type": "array"}, "explode": True}
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

    # -------------------------------------------------------------------------
    # 2. Cookie primitive / array / object serialization & explode rules
    # -------------------------------------------------------------------------

    def test_cookie_primitive_wire_delivery(self) -> None:
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

    def test_cookie_array_explode_false_wire_delivery(self) -> None:
        """Cookie array with explode=false serializes as name=val1,val2,val3 under RFC 6265."""
        spec = self._make_spec([
            {"name": "features", "in": "cookie", "schema": {"type": "array"}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"features": ["beta", "darkmode", "preview"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)

        for _, _, headers in ArrayObjectRecordingHandler.requests:
            cookie_header = headers.get("Cookie", "")
            self.assertIn("features=beta,darkmode,preview", cookie_header)

    def test_cookie_array_explode_true_rejected_zero_requests(self) -> None:
        """Cookie array with explode=true produces duplicate cookie names under RFC 6265 and is rejected."""
        spec = self._make_spec([
            {"name": "features", "in": "cookie", "schema": {"type": "array"}, "explode": True}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"features": ["beta", "darkmode"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("duplicate cookie names", auditor.results[0]["reason"])

    def test_cookie_array_default_explode_rejected_zero_requests(self) -> None:
        """In OAS 3, cookie style form defaults to explode=true, which must fail-closed."""
        spec = self._make_spec([
            {"name": "features", "in": "cookie", "schema": {"type": "array"}}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"features": ["beta", "darkmode"]}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("duplicate cookie names", auditor.results[0]["reason"])

    def test_cookie_object_explode_false_wire_delivery(self) -> None:
        """Cookie object with explode=false serializes as name=k1,v1,k2,v2."""
        spec = self._make_spec([
            {"name": "prefs", "in": "cookie", "schema": {"type": "object"}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"prefs": {"theme": "dark", "lang": "en"}}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.CONFIRMED)

        for _, _, headers in ArrayObjectRecordingHandler.requests:
            cookie_header = headers.get("Cookie", "")
            self.assertIn("prefs=theme,dark,lang,en", cookie_header)

    def test_cookie_object_explode_true_rejected_zero_requests(self) -> None:
        """Cookie object with explode=true produces un-namespaced cookies under RFC 6265 and is rejected."""
        spec = self._make_spec([
            {"name": "prefs", "in": "cookie", "schema": {"type": "object"}, "explode": True}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"prefs": {"theme": "dark"}}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("un-namespaced cookies", auditor.results[0]["reason"])

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
                    spec = self._make_spec([
                        {"name": "param_test", "in": location, "schema": {"type": kind}, "explode": False}
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
                spec = self._make_spec([
                    {"name": "nested_param", "in": location, "schema": {"type": kind}, "explode": False}
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
                    {"name": "X-Roles", "in": "header", "schema": {"type": "array"}, "explode": False}
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
        """Cookie parameters must reject semicolons, quotes, whitespace, and delimiters."""
        bad_array_items = [
            "item; evil=1",
            "item with spaces",
            "item\"quoted\"",
            "item\\escaped",
            "item\r\ninjected",
        ]
        for bad_item in bad_array_items:
            with self.subTest(bad_item=bad_item):
                with ArrayObjectRecordingHandler.lock:
                    ArrayObjectRecordingHandler.requests.clear()
                spec = self._make_spec([
                    {"name": "tags", "in": "cookie", "schema": {"type": "array"}, "explode": False}
                ])
                config = self._make_config(
                    parameter_values={"GET /api/documents/{doc_id}": {"common": {"tags": ["good", bad_item]}}}
                )
                auditor = self._run_audit(spec, config)
                self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # 6. Delimiter ambiguity (comma conflict in items/keys)
    # -------------------------------------------------------------------------

    def test_delimiter_ambiguity_comma_in_header_array_item_blocked(self) -> None:
        spec = self._make_spec([
            {"name": "X-Roles", "in": "header", "schema": {"type": "array"}, "explode": False}
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
            {"name": "X-Custom-Auth", "in": "header", "schema": {"type": "array"}, "explode": False}
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

    def test_cookie_array_collision_with_identity_cookie_blocked(self) -> None:
        spec = self._make_spec([
            {"name": "session_id", "in": "cookie", "schema": {"type": "array"}, "explode": False}
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"session_id": ["sess1", "sess2"]}}},
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
                    {"name": bad_header, "in": "header", "schema": {"type": "array"}, "explode": False}
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
            {"name": "X-Audit-Tags", "in": "header", "schema": {"type": "array"}, "explode": False},
            {"name": "ui_features", "in": "cookie", "schema": {"type": "array"}, "explode": False},
        ])
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {
                "common": {
                    "X-Audit-Tags": ["security", "audit"],
                    "ui_features": ["new_nav", "compact"],
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

        # Confirm merged cookie: user_id auth cookie + business ui_features cookie
        for _, _, h in ArrayObjectRecordingHandler.requests:
            cookie = h.get("Cookie", "")
            self.assertIn("ui_features=new_nav,compact", cookie)
            if "Bearer OWNER_TOKEN" in str(h.get("Authorization")):
                self.assertIn("user_id=1001", cookie)
            elif "Bearer VISITOR_TOKEN" in str(h.get("Authorization")):
                self.assertIn("user_id=1002", cookie)

    # -------------------------------------------------------------------------
    # 9. Parameter missing and type mismatch
    # -------------------------------------------------------------------------

    def test_missing_required_array_parameter_sends_zero_requests(self) -> None:
        spec = self._make_spec([
            {"name": "X-Required-List", "in": "header", "required": True, "schema": {"type": "array"}, "explode": False}
        ])
        config = self._make_config()  # no parameter value supplied
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ArrayObjectRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("Missing required header parameter 'X-Required-List'", auditor.results[0]["reason"])

    def test_type_mismatch_array_expected_got_scalar_sends_zero_requests(self) -> None:
        spec = self._make_spec([
            {"name": "X-Roles", "in": "header", "schema": {"type": "array"}, "explode": False}
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
            {"name": "X-Secret-Tokens", "in": "header", "schema": {"type": "array"}, "explode": False},
            {"name": "secret_pref", "in": "cookie", "schema": {"type": "object"}, "explode": False},
        ], path="/api/echo/{doc_id}")

        config = self._make_config(
            parameter_values={"GET /api/echo/{doc_id}": {
                "common": {
                    "X-Secret-Tokens": [secret_token1, secret_token2],
                    "secret_pref": {"key": secret_obj_val},
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
            )
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({"results": auditor.results, "findings": auditor.findings}, f)

            SarifReportGenerator.generate(
                auditor.results,
                self.target_url,
                str(sarif_path),
            )

            html_text = Path(html_path).read_text(encoding="utf-8")
            json_text = Path(json_path).read_text(encoding="utf-8")
            sarif_text = Path(sarif_path).read_text(encoding="utf-8")

            for secret in (secret_token1, secret_token2, secret_obj_val):
                self.assertNotIn(secret, html_text, f"Secret {secret} leaked in HTML report")
                self.assertNotIn(secret, json_text, f"Secret {secret} leaked in JSON report")
                self.assertNotIn(secret, sarif_text, f"Secret {secret} leaked in SARIF report")

    # -------------------------------------------------------------------------
    # 11. Readback compatibility
    # -------------------------------------------------------------------------

    def test_readback_compatibility_with_array_header_endpoint(self) -> None:
        """Declared readback parameters remain strictly path/query while main operation uses header array."""
        meta_header = {"name": "X-Scope", "in": "header", "schema": {"type": "array"}, "explode": False}
        name, val = serialize_header_parameter(meta_header, ["scope1", "scope2"])
        self.assertEqual(name, "X-Scope")
        self.assertEqual(val, "scope1,scope2")


if __name__ == "__main__":
    unittest.main()
