# -*- coding: utf-8 -*-
"""Comprehensive regression and acceptance tests for expanded detection capabilities:
1. OWASP API2:2023 - Broken Authentication (CWE-306)
2. OWASP API5:2023 - Broken Function Level Authorization (BFLA, CWE-285)
3. Collection & Contextual Endpoints Data Isolation / BOLA (CWE-639)
4. Full-Snapshot PUT Mass Assignment & Reversible Rollback (CWE-915)
"""

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import Verdict
from core.sarif import SarifReportGenerator
from core.transactions import prepare_patch


class ExpandedMockHandler(BaseHTTPRequestHandler):
    DATABASE = {
        "admin_config": {"cluster_secret": "sec-999-alpha", "debug": True},
        "orders": {
            "1001": [{"id": "ord-1", "user_id": "1001", "item": "Laptop"}],
            "1002": [{"id": "ord-2", "user_id": "1002", "item": "Keyboard"}],
        },
        "records": {
            "rec-1": {"id": "rec-1", "title": "Report", "is_admin": False, "status": "active"},
        },
    }

    def _write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _get_user(self) -> str:
        auth = self.headers.get("Authorization", "")
        if "TOKEN_ALICE_OWNER_1001" in auth:
            return "1001"
        if "TOKEN_BOB_VISITOR_1002" in auth:
            return "1002"
        return ""

    def do_GET(self) -> None:
        user = self._get_user()

        # 1. Broken Auth endpoint: requires auth, but leaks data to anonymous
        if self.path == "/api/broken-auth-resource":
            self._write_json(200, {"sensitive_data": "secret-xyz", "status": "leaked"})
            return

        # 2. Secure Auth endpoint: requires auth, properly rejects anonymous
        if self.path == "/api/secure-auth-resource":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            self._write_json(200, {"sensitive_data": "authorized-only"})
            return

        # 3. BFLA Vulnerable Admin endpoint: visitor can read admin config
        if self.path == "/api/admin/system/metrics":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            # Flaw: does not check if user is admin, allows visitor
            self._write_json(200, self.DATABASE["admin_config"])
            return

        # 4. BFLA Secure Admin endpoint: visitor is rejected with 403
        if self.path == "/api/admin/secure-settings":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            if user != "1001":  # only owner is admin
                self._write_json(403, {"error": "Admin access required"})
                return
            self._write_json(200, self.DATABASE["admin_config"])
            return

        # 5. Collection BOLA: orders collection leaks owner's orders to visitor
        if self.path == "/api/v1/orders/leaky":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            # Flaw: returns all orders including Alice's order to anyone
            self._write_json(200, self.DATABASE["orders"]["1001"])
            return

        # 6. Collection Isolated: returns only user's own orders
        if self.path == "/api/v1/orders/isolated":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            self._write_json(200, self.DATABASE["orders"].get(user, []))
            return

        # 7. PUT readback endpoint
        if self.path == "/api/v1/records/rec-1":
            self._write_json(200, self.DATABASE["records"]["rec-1"])
            return

        self._write_json(404, {"error": "Not found"})

    def do_PUT(self) -> None:
        user = self._get_user()
        if not user:
            self._write_json(401, {"error": "Unauthorized"})
            return

        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

        if self.path == "/api/v1/records/rec-1":
            # Vulnerable to mass assignment: updates entire object with payload
            self.DATABASE["records"]["rec-1"].update(payload)
            self._write_json(200, self.DATABASE["records"]["rec-1"])
            return

        self._write_json(404, {"error": "Not found"})

    def log_message(self, format, *args):
        return


class ExpandedDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ExpandedMockHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_auditor(self, paths: dict, config: dict = None, allow_write_tests: bool = False):
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Expanded Test Spec", "version": "1.0"},
            "paths": paths,
        }
        spec_path = self.folder / "spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")

        default_config = {
            "identities": {
                "owner": {"id": "1001", "token": "Bearer TOKEN_ALICE_OWNER_1001", "parameters": {}},
                "visitor": {"id": "1002", "token": "Bearer TOKEN_BOB_VISITOR_1002", "parameters": {}},
                "anonymous": {"id": None, "token": None, "parameters": {}},
            },
            "write_allowlist": [],
            "readbacks": {},
        }
        if config:
            default_config.update(config)

        return APISentinelAuditor(
            spec_path=str(spec_path),
            target_base_url=self.target_url,
            request_delay=0,
            identities_config=default_config["identities"],
            write_allowlist=default_config.get("write_allowlist", []),
            readback_config=default_config.get("readbacks", {}),
            allow_write_tests=allow_write_tests,
        )

    def test_broken_authentication_confirmed_on_unauthenticated_leak(self):
        """When an endpoint declares security but returns 200 to anonymous, Broken Auth is confirmed."""
        paths = {
            "/api/broken-auth-resource": {
                "get": {
                    "summary": "Sensitive profile",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}},
                }
            }
        }
        auditor = self._make_auditor(paths)
        auditor.run()

        broken_auth_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-306"]
        self.assertEqual(len(broken_auth_findings), 1)
        self.assertEqual(broken_auth_findings[0]["severity"], "High")
        self.assertIn("returned HTTP 200 to anonymous request", broken_auth_findings[0]["details"])
        self.assertEqual(auditor.stats["broken_auth_confirmed"], 1)

    def test_broken_authentication_not_reported_when_properly_denied(self):
        """When an endpoint denies anonymous with 401, no Broken Auth is reported."""
        paths = {
            "/api/secure-auth-resource": {
                "get": {
                    "summary": "Secure profile",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}},
                }
            }
        }
        auditor = self._make_auditor(paths)
        auditor.run()

        broken_auth_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-306"]
        self.assertEqual(len(broken_auth_findings), 0)
        self.assertEqual(auditor.stats["broken_auth_confirmed"], 0)

    def test_bfla_confirmed_when_visitor_accesses_admin_endpoint(self):
        """When unprivileged visitor accesses an administrative endpoint, BFLA is confirmed."""
        paths = {
            "/api/admin/system/metrics": {
                "get": {
                    "summary": "Admin system metrics",
                    "tags": ["admin"],
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}},
                }
            }
        }
        auditor = self._make_auditor(paths)
        auditor.run()

        bfla_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-285"]
        self.assertEqual(len(bfla_findings), 1)
        self.assertEqual(bfla_findings[0]["severity"], "Critical")
        self.assertEqual(auditor.stats["bfla_confirmed"], 1)

    def test_bfla_secure_when_visitor_is_rejected(self):
        """When visitor receives 403 on administrative endpoint, BFLA is SECURE."""
        paths = {
            "/api/admin/secure-settings": {
                "get": {
                    "summary": "Admin secure settings",
                    "tags": ["admin"],
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}},
                }
            }
        }
        auditor = self._make_auditor(paths)
        auditor.run()

        bfla_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-285"]
        self.assertEqual(len(bfla_findings), 0)
        bfla_result = next(r for r in auditor.results if r["check"] == "BFLA")
        self.assertEqual(bfla_result["verdict"], "SECURE")

    def test_collection_endpoint_bola_detected_when_visitor_leaks_owner_id(self):
        """When a collection endpoint returns owner's private record to visitor, collection BOLA is confirmed."""
        paths = {
            "/api/v1/orders/leaky": {
                "get": {
                    "summary": "User orders collection",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}},
                }
            }
        }
        auditor = self._make_auditor(paths)
        auditor.run()

        bola_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-639"]
        self.assertEqual(len(bola_findings), 1)
        self.assertIn("contains owner's private identifier '1001'", bola_findings[0]["details"])

    def test_collection_endpoint_secure_when_isolated(self):
        """When a collection endpoint isolates user data, BOLA verdict is SECURE."""
        paths = {
            "/api/v1/orders/isolated": {
                "get": {
                    "summary": "User orders collection",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}},
                }
            }
        }
        auditor = self._make_auditor(paths)
        auditor.run()

        bola_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-639"]
        self.assertEqual(len(bola_findings), 0)
        bola_result = next(r for r in auditor.results if r["endpoint"] == "GET /api/v1/orders/isolated")
        self.assertEqual(bola_result["verdict"], "SECURE")

    def test_put_mass_assignment_confirmed_and_rolled_back(self):
        """Full-snapshot PUT mass assignment is audited, confirmed, and automatically rolled back."""
        paths = {
            "/api/v1/records/rec-1": {
                "put": {
                    "summary": "Update full record",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "is_admin": {"type": "boolean", "readOnly": True},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Updated"}},
                }
            }
        }
        config = {
            "write_allowlist": ["PUT /api/v1/records/rec-1"],
            "readbacks": {
                "PUT /api/v1/records/rec-1": {
                    "method": "GET",
                    "path": "/api/v1/records/rec-1",
                    "field_map": {"is_admin": "is_admin"},
                    "consistency": "strong",
                }
            },
        }
        auditor = self._make_auditor(paths, config=config, allow_write_tests=True)
        auditor.run()

        # Vulnerability should be confirmed
        mass_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-915"]
        self.assertEqual(len(mass_findings), 1)
        self.assertEqual(mass_findings[0]["endpoint"], "PUT /api/v1/records/rec-1")
        # Rollback should be verified
        self.assertTrue(mass_findings[0]["evidence"]["rollback_verified"])
        # Server database state should be restored to False
        self.assertFalse(ExpandedMockHandler.DATABASE["records"]["rec-1"]["is_admin"])

    def test_sarif_includes_broken_auth_and_bfla(self):
        """SARIF report correctly encodes GT-AUTH-001 and GT-BFLA-001 rules and findings."""
        sarif_file = self.folder / "report.sarif"
        results = [
            {"endpoint": "GET /api/broken-auth", "check": "BROKEN_AUTH", "verdict": "CONFIRMED"},
            {"endpoint": "GET /api/admin/metrics", "check": "BFLA", "verdict": "CONFIRMED"},
        ]
        SarifReportGenerator.generate(
            results=results,
            output_path=str(sarif_file),
            target_url="http://127.0.0.1:8080",
        )
        data = json.loads(sarif_file.read_text(encoding="utf-8"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        self.assertIn("GT-AUTH-001", rule_ids)
        self.assertIn("GT-BFLA-001", rule_ids)
        sarif_results = data["runs"][0]["results"]
        self.assertEqual(len(sarif_results), 2)
        sarif_rule_ids = {r["ruleId"] for r in sarif_results}
        self.assertEqual(sarif_rule_ids, {"GT-AUTH-001", "GT-BFLA-001"})

    def test_config_validator_accepts_put_operations(self):
        """ConfigValidator accepts PUT in write_allowlist and readbacks."""
        config = {
            "write_allowlist": ["PUT /api/v1/records/{id}", "PATCH /api/v1/records/{id}"],
            "readbacks": {
                "PUT /api/v1/records/{id}": {
                    "method": "GET",
                    "path": "/api/v1/records/{id}",
                    "field_map": {"role": "role"},
                },
                "PATCH /api/v1/records/{id}": {
                    "method": "GET",
                    "path": "/api/v1/records/{id}",
                    "field_map": {"role": "role"},
                },
            },
        }
        res = ConfigValidator.validate(config)
        self.assertTrue(res.is_valid, f"Validation errors: {[e.message for e in res.errors]}")


if __name__ == "__main__":
    unittest.main()
