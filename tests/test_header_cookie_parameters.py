"""Dedicated test suite for read-only GET header and cookie parameter support.

Validates wire-level delivery, authentication isolation, CRLF protection,
cookie collision prevention, safety blocking, and report redaction.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import Verdict
from core.parameters import (
    ParameterSerializationError,
    serialize_cookie_parameter,
    serialize_header_parameter,
)
from core.reporter import SecurityReportGenerator
from core.sarif import SarifReportGenerator


class ParameterRecordingHandler(BaseHTTPRequestHandler):
    """Disposable local HTTP server that captures received requests and headers."""

    requests: List[Tuple[str, str, Dict[str, str]]] = []
    lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        with self.lock:
            headers_dict = {k: v for k, v in self.headers.items()}
            self.requests.append((self.command, self.path, headers_dict))

        auth = self.headers.get("Authorization", "")
        if self.path.startswith("/api/documents/"):
            doc_id = self.path.split("?")[0].split("/")[-1]
            if "Bearer OWNER_TOKEN" in auth:
                body = json.dumps({"id": doc_id, "title": "Owner Confidential", "owner": "1001"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif "Bearer VISITOR_TOKEN" in auth:
                if doc_id == "doc-owner":
                    # Cross-tenant access leak for BOLA detection
                    body = json.dumps({"id": doc_id, "title": "Owner Confidential", "owner": "1001"}).encode("utf-8")
                    self.send_response(200)
                else:
                    # Visitor's own baseline
                    body = json.dumps({"id": doc_id, "title": "Visitor Document", "owner": "1002"}).encode("utf-8")
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                # Anonymous denied
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


class HeaderCookieParameterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ParameterRecordingHandler.requests = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ParameterRecordingHandler)
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
        with ParameterRecordingHandler.lock:
            ParameterRecordingHandler.requests.clear()

    def _make_spec(self, parameters: List[Dict[str, Any]], path: str = "/api/documents/{doc_id}") -> Dict[str, Any]:
        return {
            "openapi": "3.0.3",
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
                "GET /api/documents/{doc_id}": {
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
            with contextlib.redirect_stdout(io.StringIO()):
                auditor.run()
            return auditor

    def test_normal_header_parameter_wire_delivery(self) -> None:
        """Declared GET header parameter is correctly delivered on the wire."""
        params = [
            {"name": "X-Client-Version", "in": "header", "schema": {"type": "string"}},
            {"name": "X-Tenant-Key", "in": "header", "schema": {"type": "integer"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(
            parameter_values={
                "GET /api/documents/{doc_id}": {
                    "common": {
                        "X-Client-Version": "v2.5.3",
                        "X-Tenant-Key": 42,
                    }
                }
            }
        )
        auditor = self._run_audit(spec, config)
        self.assertGreater(len(ParameterRecordingHandler.requests), 0)
        # Check wire headers received by local test server
        for _, _, headers in ParameterRecordingHandler.requests:
            self.assertEqual(headers.get("X-Client-Version"), "v2.5.3")
            self.assertEqual(headers.get("X-Tenant-Key"), "42")
        # Ensure BOLA check was attempted and confirmed with wire evidence
        confirmed = [r for r in auditor.results if r["verdict"] == Verdict.CONFIRMED]
        self.assertEqual(len(confirmed), 1)

    def test_normal_cookie_parameter_wire_delivery(self) -> None:
        """Declared GET cookie parameter is delivered in the HTTP Cookie header."""
        params = [
            {"name": "tracking_id", "in": "cookie", "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(
            parameter_values={
                "GET /api/documents/{doc_id}": {
                    "common": {"tracking_id": "trk_xyz_987"}
                }
            }
        )
        self._run_audit(spec, config)
        self.assertGreater(len(ParameterRecordingHandler.requests), 0)
        for _, _, headers in ParameterRecordingHandler.requests:
            cookie_header = headers.get("Cookie", "")
            self.assertIn("tracking_id=trk_xyz_987", cookie_header)

    def test_missing_required_header_parameter_sends_zero_requests(self) -> None:
        """Missing required header parameter safely fails before transport."""
        params = [
            {"name": "X-Required-Context", "in": "header", "required": True, "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(parameter_values={})
        auditor = self._run_audit(spec, config)
        # Zero requests sent to server
        self.assertEqual(len(ParameterRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("no request was sent", auditor.results[0]["reason"])

    def test_missing_required_cookie_parameter_sends_zero_requests(self) -> None:
        """Missing required cookie parameter safely fails before transport."""
        params = [
            {"name": "required_sess", "in": "cookie", "required": True, "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(parameter_values={})
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ParameterRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("no request was sent", auditor.results[0]["reason"])

    def test_unsupported_serialization_formats(self) -> None:
        """Unsupported styles, complex objects, and Swagger 2 cookie fail-closed."""
        cases = [
            ({"name": "X-Matrix", "in": "header", "style": "matrix"}, "val", False),
            ({"name": "X-Form", "in": "header", "style": "form"}, "val", False),
            ({"name": "c_simple", "in": "cookie", "style": "simple"}, "val", False),
            ({"name": "X-Obj", "in": "header", "schema": {"type": "object"}}, {"k": "v"}, False),
            ({"name": "X-Arr", "in": "header", "schema": {"type": "array"}}, ["a", "b"], False),
            ({"name": "c_arr", "in": "cookie", "schema": {"type": "array"}}, ["a", "b"], False),
            ({"name": "c_obj", "in": "cookie", "schema": {"type": "object"}}, {"k": "v"}, False),
            ({"name": "c_sw2", "in": "cookie", "type": "string"}, "val", True),
        ]
        for meta, value, swagger2 in cases:
            with self.subTest(meta=meta):
                with self.assertRaises(ParameterSerializationError) as caught:
                    if meta.get("in") == "header":
                        serialize_header_parameter(meta, value, swagger2=swagger2)
                    else:
                        serialize_cookie_parameter(meta, value, swagger2=swagger2)
                self.assertIn("no request was sent", str(caught.exception))

    def test_crlf_and_invalid_header_injection_attempts(self) -> None:
        """Header and cookie values with line breaks or invalid characters are blocked."""
        malicious_headers = [
            ({"name": "X-Custom", "in": "header"}, "value\r\nInjected: evil"),
            ({"name": "X-Custom", "in": "header"}, "value\nInjected: evil"),
            ({"name": "X-Custom", "in": "header"}, "value\rInjected: evil"),
            ({"name": "X-Custom", "in": "header"}, "value\x00evil"),
            ({"name": "X-Custom\r\n", "in": "header"}, "value"),
            ({"name": "X Custom", "in": "header"}, "value"),
            ({"name": "X:Custom", "in": "header"}, "value"),
        ]
        for meta, val in malicious_headers:
            with self.subTest(meta=meta, val=val):
                with self.assertRaises(ParameterSerializationError):
                    serialize_header_parameter(meta, val)

        malicious_cookies = [
            ({"name": "sess", "in": "cookie"}, "val\r\nSet-Cookie: evil=1"),
            ({"name": "sess", "in": "cookie"}, "val\nevil"),
            ({"name": "sess", "in": "cookie"}, "val; injected=evil"),
            ({"name": "sess;evil", "in": "cookie"}, "val"),
            ({"name": "sess\r\n", "in": "cookie"}, "val"),
        ]
        for meta, val in malicious_cookies:
            with self.subTest(meta=meta, val=val):
                with self.assertRaises(ParameterSerializationError):
                    serialize_cookie_parameter(meta, val)

    def test_cookie_and_auth_credential_safe_merge_and_collision(self) -> None:
        """Business cookies safely merge with identity cookies, but collisions are blocked."""
        # 1. Safe merge
        params = [
            {"name": "theme", "in": "cookie", "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"theme": "dark"}}},
            extra_identities={
                "owner": {"headers": {"Cookie": "auth_token=AUTH_OWNER_1"}},
                "visitor": {"headers": {"Cookie": "auth_token=AUTH_VISITOR_2"}},
            },
        )
        self._run_audit(spec, config)
        self.assertGreater(len(ParameterRecordingHandler.requests), 0)
        for _, _, headers in ParameterRecordingHandler.requests:
            cookie_header = headers.get("Cookie", "")
            self.assertIn("theme=dark", cookie_header)
            if "Bearer OWNER_TOKEN" in headers.get("Authorization", ""):
                self.assertIn("auth_token=AUTH_OWNER_1", cookie_header)
            elif "Bearer VISITOR_TOKEN" in headers.get("Authorization", ""):
                self.assertIn("auth_token=AUTH_VISITOR_2", cookie_header)

        # 2. Collision with identity cookie: must be blocked before transport
        with ParameterRecordingHandler.lock:
            ParameterRecordingHandler.requests.clear()

        params_collision = [
            {"name": "auth_token", "in": "cookie", "schema": {"type": "string"}},
        ]
        spec_col = self._make_spec(params_collision)
        config_col = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"auth_token": "COLLISION_VALUE"}}},
            extra_identities={
                "owner": {"headers": {"Cookie": "auth_token=AUTH_OWNER_1"}},
                "visitor": {"headers": {"Cookie": "auth_token=AUTH_VISITOR_2"}},
            },
        )
        auditor = self._run_audit(spec_col, config_col)
        self.assertEqual(len(ParameterRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("conflicts with identity authentication cookie", auditor.results[0]["reason"])

    def test_header_collision_with_identity_header_blocked(self) -> None:
        """Business header cannot overwrite an identity header."""
        params = [
            {"name": "X-Custom-Auth", "in": "header", "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}": {"common": {"X-Custom-Auth": "OVERWRITE"}}},
            extra_identities={
                "owner": {"headers": {"X-Custom-Auth": "OWNER_AUTH"}},
                "visitor": {"headers": {"X-Custom-Auth": "VISITOR_AUTH"}},
            },
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ParameterRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("conflicts with identity header", auditor.results[0]["reason"])

    def test_identity_isolation_owner_visitor_anonymous(self) -> None:
        """Visitor cross request NEVER gets Owner credentials; Anonymous gets no credentials."""
        params = [
            {"name": "X-Tenant-Id", "in": "header", "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(
            parameter_values={
                "GET /api/documents/{doc_id}": {
                    "owner": {"X-Tenant-Id": "tenant-owner"},
                    "visitor": {"X-Tenant-Id": "tenant-visitor"},
                }
            }
        )
        self._run_audit(spec, config)
        self.assertGreater(len(ParameterRecordingHandler.requests), 0)

        owner_reqs = [h for _, _, h in ParameterRecordingHandler.requests if "Bearer OWNER_TOKEN" in h.get("Authorization", "")]
        visitor_reqs = [h for _, _, h in ParameterRecordingHandler.requests if "Bearer VISITOR_TOKEN" in h.get("Authorization", "")]
        anon_reqs = [h for _, _, h in ParameterRecordingHandler.requests if not h.get("Authorization")]

        self.assertGreater(len(owner_reqs), 0)
        self.assertGreater(len(visitor_reqs), 0)
        self.assertGreater(len(anon_reqs), 0)

        # In visitor requests: MUST NOT contain owner token
        for h in visitor_reqs:
            self.assertNotIn("OWNER_TOKEN", h.get("Authorization", ""))
        # In anonymous requests: MUST NOT contain any Authorization
        for h in anon_reqs:
            self.assertIsNone(h.get("Authorization"))

    def test_unconfigured_optional_parameters_backward_compatibility(self) -> None:
        """Optional parameters without configuration do not block scan or invent headers."""
        params = [
            {"name": "X-Optional-Header", "in": "header", "required": False, "schema": {"type": "string"}},
            {"name": "optional_cookie", "in": "cookie", "required": False, "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(parameter_values={})
        auditor = self._run_audit(spec, config)
        self.assertGreater(len(ParameterRecordingHandler.requests), 0)
        for _, _, headers in ParameterRecordingHandler.requests:
            self.assertNotIn("X-Optional-Header", headers)
            self.assertNotIn("optional_cookie", headers.get("Cookie", ""))
        confirmed = [r for r in auditor.results if r["verdict"] == Verdict.CONFIRMED]
        self.assertEqual(len(confirmed), 1)

    def test_read_only_get_safety_blocking(self) -> None:
        """Dangerous GET routes with header/cookie parameters remain safely blocked."""
        params = [
            {"name": "X-Client-Id", "in": "header", "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params, path="/api/documents/{doc_id}/delete")
        config = self._make_config(
            parameter_values={"GET /api/documents/{doc_id}/delete": {"common": {"X-Client-Id": "123"}}}
        )
        auditor = self._run_audit(spec, config)
        self.assertEqual(len(ParameterRecordingHandler.requests), 0)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.SKIPPED)

    def test_redaction_html_json_sarif_no_leakage(self) -> None:
        """HTML, JSON, and SARIF reports redact credentials, tokens, and private fields."""
        params = [
            {"name": "X-Custom-Id", "in": "header", "schema": {"type": "string"}},
            {"name": "user_cookie", "in": "cookie", "schema": {"type": "string"}},
        ]
        spec = self._make_spec(params)
        config = self._make_config(
            parameter_values={
                "GET /api/documents/{doc_id}": {
                    "common": {"X-Custom-Id": "cust-secret-42", "user_cookie": "sess-secret-99"}
                }
            }
        )
        auditor = self._run_audit(spec, config)

        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "report.json"
            html_path = Path(temp_dir) / "report.html"
            sarif_path = Path(temp_dir) / "report.sarif"

            json_data = {
                "report_schema_version": 2,
                "tool": "GrantTrace",
                "stats": auditor.stats,
                "results": auditor.results,
            }
            json_text = json.dumps(json_data, indent=2)
            json_path.write_text(json_text, encoding="utf-8")

            findings = [r["finding"] for r in auditor.results if r.get("finding")]
            SecurityReportGenerator.generate(
                auditor.stats,
                findings,
                self.target_url,
                str(html_path),
                results=auditor.results,
            )
            html_text = html_path.read_text(encoding="utf-8")

            SarifReportGenerator.generate(
                auditor.results,
                self.target_url,
                str(sarif_path),
            )
            sarif_text = sarif_path.read_text(encoding="utf-8")

            for text, name in [(json_text, "JSON"), (html_text, "HTML"), (sarif_text, "SARIF")]:
                # Credentials and auth tokens must NEVER appear in report output
                self.assertNotIn("OWNER_TOKEN", text, f"Found raw OWNER_TOKEN in {name}")
                self.assertNotIn("VISITOR_TOKEN", text, f"Found raw VISITOR_TOKEN in {name}")

    def test_config_validator_header_cookie_schema(self) -> None:
        """Config validator verifies header and cookie parameter values against schema."""
        raw_spec = {
            "openapi": "3.0.3",
            "paths": {
                "/api/items/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "schema": {"type": "string"}},
                            {"name": "X-Count", "in": "header", "schema": {"type": "integer"}},
                            {"name": "is_active", "in": "cookie", "schema": {"type": "boolean"}},
                        ],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }

        # Valid config: native types or canonical strings
        valid_cfg = {
            "parameter_values": {
                "GET /api/items/{id}": {
                    "common": {"X-Count": 10, "is_active": True}
                }
            }
        }
        res_valid = ConfigValidator.validate(valid_cfg, raw_spec=raw_spec)
        self.assertEqual(len(res_valid.errors), 0)

        # Invalid config: bad integer for X-Count
        invalid_cfg = {
            "parameter_values": {
                "GET /api/items/{id}": {
                    "common": {"X-Count": "not-an-integer", "is_active": True}
                }
            }
        }
        res_invalid = ConfigValidator.validate(invalid_cfg, raw_spec=raw_spec)
        self.assertFalse(res_invalid.is_valid)
        self.assertTrue(any("X-Count" in issue.path for issue in res_invalid.issues))


if __name__ == "__main__":
    unittest.main()
