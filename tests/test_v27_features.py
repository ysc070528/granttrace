"""Tests for v2.7.0 extended detection features:
1. Read-only POST BOLA auditing with explicit read_only policy
2. Heuristic BOPLA sensitive property exposure detection (OWASP API3)
3. Multi-role RBAC access matrix and privilege violation checks
"""

import json
import tempfile
import unittest
from pathlib import Path

from core.auditor import APISentinelAuditor
from core.models import HTTPResult, Verdict


class TestV27ExtendedFeatures(unittest.TestCase):

    def setUp(self):
        self.spec = {
            "openapi": "3.0.3",
            "info": {"title": "Test v2.7 API", "version": "1.0"},
            "paths": {
                "/api/documents/query": {
                    "post": {
                        "summary": "Query document by ID",
                        "security": [{"BearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"doc_id": {"type": "string"}},
                                    }
                                }
                            },
                        },
                        "responses": {
                            "200": {
                                "description": "Document details",
                                "content": {"application/json": {"schema": {"type": "object"}}},
                            }
                        },
                    }
                },
                "/api/user/profile": {
                    "get": {
                        "summary": "Get user profile",
                        "security": [{"BearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "Profile data",
                                "content": {"application/json": {"schema": {"type": "object"}}},
                            }
                        },
                    }
                },
                "/api/admin/settings": {
                    "get": {
                        "summary": "Admin settings",
                        "security": [{"BearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "Settings data",
                            }
                        },
                    }
                },
            },
        }
        self.temp_dir = tempfile.TemporaryDirectory()
        self.spec_file = Path(self.temp_dir.name) / "spec.json"
        self.spec_file.write_text(json.dumps(self.spec), encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_post_bola_without_readonly_is_skipped(self):
        """Unsafe POST operations without explicit read_only: true must be skipped."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "POST /api/documents/query": {
                "body": {"doc_id": "doc_123"}
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]
        self.assertEqual(ep["method"], "POST")

        auditor._audit_endpoint_bola(ep)

        # Verify it was skipped for safety
        self.assertEqual(len(auditor.results), 1)
        res = auditor.results[0]
        self.assertEqual(res["verdict"], Verdict.SKIPPED.value)
        self.assertIn("read_only: true", res["reason"])

    def test_post_bola_with_readonly_confirms_vulnerability(self):
        """POST with read_only: true and matching cross-identity access confirms BOLA."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "POST /api/documents/query": {
                "read_only": True,
                "body": {
                    "owner": {"doc_id": "doc_owner_1"},
                    "visitor": {"doc_id": "doc_owner_1"},
                    "visitor_self": {"doc_id": "doc_visitor_2"},
                },
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]
        self.assertEqual(ep["method"], "POST")

        # Mock HTTP responses: owner gets doc, visitor cross-gets the same doc (BOLA), anon denied, visitor self gets its own
        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name == "owner":
                return HTTPResult(status=200, body=json.dumps({"id": "doc_owner_1", "title": "Confidential Report"}))
            elif identity_name == "visitor":
                if data and data.get("doc_id") == "doc_visitor_2":
                    return HTTPResult(status=200, body=json.dumps({"id": "doc_visitor_2", "title": "Visitor Notes"}))
                # Cross-identity access leaks owner's doc
                return HTTPResult(status=200, body=json.dumps({"id": "doc_owner_1", "title": "Confidential Report"}))
            elif identity_name == "anonymous":
                return HTTPResult(status=401, body=json.dumps({"error": "Unauthorized"}))
            return HTTPResult(status=404, body="")

        auditor._http_request = mock_http

        auditor._audit_endpoint_bola(ep)

        # Confirm BOLA
        bola_results = [r for r in auditor.results if r["check"] == "BOLA"]
        self.assertTrue(len(bola_results) >= 1)
        self.assertEqual(bola_results[0]["verdict"], Verdict.CONFIRMED.value)
        self.assertTrue(any(f["type"].startswith("BOLA") for f in auditor.findings))

    def test_bopla_sensitive_property_exposure_detection(self):
        """Detects unmasked phone / secret fields returned to visitor as BOPLA exposure."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "GET /api/user/profile": {
                "expected_visitor_access": "deny", "detect_sensitive_exposure": True
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        # Mock responses where visitor receives owner's unmasked phone and salary
        owner_body = json.dumps({"user": "alice", "phone": "13800138000", "salary": 25000})
        visitor_body = json.dumps({"user": "alice", "phone": "13800138000", "salary": 25000})
        anon_body = json.dumps({"error": "Auth required"})

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name == "owner":
                return HTTPResult(status=200, body=owner_body)
            elif identity_name == "visitor":
                return HTTPResult(status=200, body=visitor_body)
            return HTTPResult(status=401, body=anon_body)

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        # Check for BOPLA_EXPOSURE result
        exposure_results = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertTrue(len(exposure_results) >= 1)
        self.assertEqual(exposure_results[0]["verdict"], Verdict.CONFIRMED.value)
        self.assertIn("phone", exposure_results[0]["reason"])

    def test_rbac_matrix_privilege_violation(self):
        """Verifies multi-role RBAC matrix execution and privilege violation detection."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "administrator": {"token": "Bearer admin_tok", "role": "administrator"},
                "auditor_role": {"token": "Bearer audit_tok", "role": "auditor"},
                "viewer_role": {"token": "Bearer viewer_tok", "role": "viewer"},
            },
        }
        bola = {
            "GET /api/admin/settings": {
                "required_role": "administrator",
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/admin/settings"][0]

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("owner", "administrator"):
                return HTTPResult(status=200, body=json.dumps({"setting": "secret_key_123"}))
            elif identity_name == "auditor_role":
                return HTTPResult(status=403, body=json.dumps({"error": "Forbidden"}))
            elif identity_name == "viewer_role":
                # VIOLATION: viewer improperly gets 200 OK!
                return HTTPResult(status=200, body=json.dumps({"setting": "secret_key_123"}))
            return HTTPResult(status=401, body=json.dumps({"error": "Unauthorized"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        # Verify RBAC matrix was generated
        self.assertTrue(hasattr(auditor, "rbac_matrix"))
        matrix = auditor.rbac_matrix.get("GET /api/admin/settings")
        self.assertIsNotNone(matrix)
        self.assertEqual(matrix["roles"]["administrator"]["access"], "ALLOWED")
        self.assertEqual(matrix["roles"]["auditor_role"]["access"], "DENIED")
        self.assertEqual(matrix["roles"]["viewer_role"]["access"], "VIOLATION")

        # Verify RBAC violation finding was registered
        rbac_findings = [f for f in auditor.findings if "RBAC" in f["type"]]
        self.assertTrue(len(rbac_findings) >= 1)


if __name__ == "__main__":
    unittest.main()
