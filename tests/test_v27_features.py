"""Comprehensive test suite for v2.7.0 extended detection features:
1. Heuristic BOPLA sensitive property exposure detection (OWASP API3:2023)
2. Multi-role RBAC access matrix and privilege violation checks (CWE-285)
3. Read-only POST BOLA auditing with explicit safety controls (CWE-639)
"""

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import HTTPResult, Verdict
from core.reporter import SecurityReportGenerator


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
                "/api/admin/post-action": {
                    "post": {
                        "summary": "Admin post action",
                        "security": [{"BearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "Action executed",
                            }
                        },
                    }
                },
                "/api/admin/audit-log/search": {
                    "post": {
                        "summary": "Search the admin audit log",
                        "security": [{"BearerAuth": []}],
                        "responses": {"200": {"description": "Matching audit entries"}},
                    }
                },
                "/api/users/{id}": {
                    "get": {
                        "summary": "Get a user",
                        "security": [{"BearerAuth": []}],
                        "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "User"}},
                    }
                },
            },
        }
        self.temp_dir = tempfile.TemporaryDirectory()
        self.spec_file = Path(self.temp_dir.name) / "spec.json"
        self.spec_file.write_text(json.dumps(self.spec), encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # BOPLA Detection Tests
    # -------------------------------------------------------------------------

    def test_bopla_same_path_leak(self):
        """Same unmasked sensitive values on an endpoint without an object selector -> SUSPICIOUS lead.

        Both identities called the same URL and got identical documents, so the
        data may be shared rather than the Owner's; confirmation needs an
        object-level decision and a Visitor own-resource baseline.
        """
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "GET /api/user/profile": {
                "expected_visitor_access": "deny",
                "detect_sensitive_exposure": True,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        owner_doc = {"user": "alice", "phone": "13800138000", "salary": 25000}
        visitor_doc = {"user": "alice", "phone": "13800138000", "salary": 25000}

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name == "owner":
                return HTTPResult(status=200, body=json.dumps(owner_doc))
            elif identity_name == "visitor":
                return HTTPResult(status=200, body=json.dumps(visitor_doc))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        exposure_results = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertEqual(len(exposure_results), 1)
        self.assertEqual(exposure_results[0]["verdict"], Verdict.SUSPICIOUS.value)
        self.assertIn("phone", exposure_results[0]["reason"])
        self.assertIn("confirmed_object_level_access", exposure_results[0]["evidence"]["missing_evidence"])
        self.assertFalse([f for f in auditor.findings if f.get("check") == "BOPLA_EXPOSURE"])

    def test_bopla_cross_field_same_value_not_flagged(self):
        """Identical value appearing under different field path must NOT be falsely flagged."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "GET /api/user/profile": {
                "expected_visitor_access": "deny",
                "detect_sensitive_exposure": True,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        # Owner has phone 13800138000. Visitor response does NOT have phone, but has non-sensitive 'ref_code' with same number
        owner_doc = {"user": "alice", "phone": "13800138000"}
        visitor_doc = {"user": "visitor", "ref_code": "13800138000"}

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name == "owner":
                return HTTPResult(status=200, body=json.dumps(owner_doc))
            elif identity_name == "visitor":
                return HTTPResult(status=200, body=json.dumps(visitor_doc))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        exposure_results = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertEqual(len(exposure_results), 0, "Cross-field identical value must not trigger BOPLA")

    def test_bopla_masked_field_not_flagged(self):
        """Masked values in visitor response (e.g. ***, [REDACTED], xxxx) must not trigger BOPLA."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "GET /api/user/profile": {
                "expected_visitor_access": "deny",
                "detect_sensitive_exposure": True,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        owner_doc = {"user": "alice", "phone": "13800138000", "salary": 25000}
        visitor_doc = {"user": "alice", "phone": "138****8000", "salary": "[REDACTED]"}

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name == "owner":
                return HTTPResult(status=200, body=json.dumps(owner_doc))
            elif identity_name == "visitor":
                return HTTPResult(status=200, body=json.dumps(visitor_doc))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        exposure_results = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertEqual(len(exposure_results), 0, "Masked values must not trigger BOPLA exposure")

    def test_bopla_expected_visitor_access_allow_not_flagged(self):
        """When policy declares expected_visitor_access: 'allow', visitor access is not an unauthorized violation."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "GET /api/user/profile": {
                "expected_visitor_access": "allow",
                "detect_sensitive_exposure": True,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        doc = {"user": "alice", "phone": "13800138000"}

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("owner", "visitor"):
                return HTTPResult(status=200, body=json.dumps(doc))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        exposure_results = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertEqual(len(exposure_results), 0, "Allowed visitor access must not be flagged as BOPLA violation")

    def test_bopla_nested_objects_and_arrays(self):
        """Sensitive properties inside nested objects and arrays are properly extracted and matched."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "GET /api/user/profile": {
                "expected_visitor_access": "deny",
                "detect_sensitive_exposure": True,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        owner_doc = {
            "organization": {
                "members": [
                    {"name": "Alice", "salary": 120000, "is_admin": True},
                    {"name": "Bob", "salary": 80000, "is_admin": False},
                ]
            }
        }

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("owner", "visitor"):
                return HTTPResult(status=200, body=json.dumps(owner_doc))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        exposure_results = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertEqual(len(exposure_results), 1)
        self.assertIn("organization.members[0].salary", exposure_results[0]["reason"])

    def test_bopla_sensitive_value_not_in_report(self):
        """Raw sensitive values (e.g. passwords, numbers) must NEVER appear in report evidence or text."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        secret_password = "supersecretpassword999"
        secret_phone = "13899998888"
        bola = {
            "GET /api/user/profile": {
                "expected_visitor_access": "deny",
                "detect_sensitive_exposure": True,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        doc = {"user": "alice", "phone": secret_phone, "password": secret_password}

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("owner", "visitor"):
                return HTTPResult(status=200, body=json.dumps(doc))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        # Check results and findings for raw secrets
        results_str = json.dumps(auditor.results)
        findings_str = json.dumps(auditor.findings)
        self.assertNotIn(secret_password, results_str)
        self.assertNotIn(secret_password, findings_str)
        self.assertNotIn(secret_phone, results_str)
        self.assertNotIn(secret_phone, findings_str)

    # -------------------------------------------------------------------------
    # RBAC Matrix Tests
    # -------------------------------------------------------------------------

    def test_rbac_low_privilege_accessing_admin_data(self):
        """Viewer role gaining access to admin data requiring administrator role is flagged as VIOLATION."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "admin": {"token": "Bearer admin_tok", "role": "administrator"},
                "auditor": {"token": "Bearer audit_tok", "role": "auditor"},
                "viewer": {"token": "Bearer viewer_tok", "role": "viewer"},
            },
        }
        bola = {
            "GET /api/admin/settings": {
                "required_role": "administrator",
                # The operator's assertion that this value is protected admin data.
                "private_data_paths": ["setting"],
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/admin/settings"][0]

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("owner", "admin"):
                return HTTPResult(status=200, body=json.dumps({"setting": "secret_key_123"}))
            elif identity_name == "auditor":
                return HTTPResult(status=403, body=json.dumps({"error": "Forbidden"}))
            elif identity_name == "viewer":
                # Improperly gets 200 with admin JSON data!
                return HTTPResult(status=200, body=json.dumps({"setting": "secret_key_123"}))
            return HTTPResult(status=401, body=json.dumps({"error": "Unauthorized"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        matrix = auditor.rbac_matrix.get("GET /api/admin/settings")
        self.assertIsNotNone(matrix)
        self.assertEqual(matrix["roles"]["admin"]["access"], "ALLOWED")
        self.assertEqual(matrix["roles"]["auditor"]["access"], "DENIED")
        self.assertEqual(matrix["roles"]["viewer"]["access"], "VIOLATION")
        violations = [r for r in auditor.results if r["check"] == "RBAC" and r["verdict"] == Verdict.CONFIRMED.value]
        self.assertEqual([r["evidence"]["rbac_role"] for r in violations], ["viewer"])

    def test_rbac_soft_denial_login_page_200(self):
        """HTTP 200 containing an HTML login page is UNREADABLE (no data), never a VIOLATION."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "admin": {"token": "Bearer admin_tok", "role": "administrator"},
                "viewer": {"token": "Bearer viewer_tok", "role": "viewer"},
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
            if identity_name in ("owner", "admin"):
                return HTTPResult(status=200, body=json.dumps({"setting": "admin_ok"}))
            elif identity_name == "viewer":
                # Returns HTTP 200 with HTML login redirect
                return HTTPResult(status=200, body="<html><body><h3>Please Sign In</h3></body></html>")
            return HTTPResult(status=401, body=json.dumps({"error": "Unauthorized"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        matrix = auditor.rbac_matrix.get("GET /api/admin/settings")
        self.assertIsNotNone(matrix)
        # An HTML page is not JSON data; it does not prove a denial either.
        self.assertEqual(matrix["roles"]["viewer"]["access"], "UNREADABLE")
        self.assertEqual(matrix["roles"]["viewer"]["verdict"], Verdict.INCONCLUSIVE.value)
        self.assertFalse(matrix["roles"]["viewer"]["violation"])

    def test_rbac_soft_denial_business_error_200(self):
        """HTTP 200 containing nested soft denial JSON error must be classified as DENIED."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "admin": {"token": "Bearer admin_tok", "role": "administrator"},
                "viewer": {"token": "Bearer viewer_tok", "role": "viewer"},
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
            if identity_name in ("owner", "admin"):
                return HTTPResult(status=200, body=json.dumps({"setting": "admin_ok"}))
            elif identity_name == "viewer":
                # HTTP 200 with nested authorization error
                return HTTPResult(status=200, body=json.dumps({"code": 403, "error": "Access denied for this resource"}))
            return HTTPResult(status=401, body=json.dumps({"error": "Unauthorized"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        matrix = auditor.rbac_matrix.get("GET /api/admin/settings")
        self.assertIsNotNone(matrix)
        self.assertEqual(matrix["roles"]["viewer"]["access"], "DENIED")
        self.assertFalse(matrix["roles"]["viewer"]["violation"])

    def test_rbac_http_204_empty_body(self):
        """HTTP 204 No Content does not prove protected data exposure."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "admin": {"token": "Bearer admin_tok", "role": "administrator"},
                "viewer": {"token": "Bearer viewer_tok", "role": "viewer"},
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
            if identity_name in ("owner", "admin"):
                return HTTPResult(status=200, body=json.dumps({"setting": "admin_ok"}))
            elif identity_name == "viewer":
                return HTTPResult(status=204, body="")
            return HTTPResult(status=401, body=json.dumps({"error": "Unauthorized"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        matrix = auditor.rbac_matrix.get("GET /api/admin/settings")
        self.assertIsNotNone(matrix)
        self.assertIn(matrix["roles"]["viewer"]["access"], ("EMPTY", "HTTP_204"))
        self.assertFalse(matrix["roles"]["viewer"]["violation"])

    def test_rbac_invalid_role_config_validation(self):
        """Config validator flags invalid role names, invalid keys, and non-dict entries."""
        invalid_config = {
            "identities": {
                "owner": {"token": "Bearer ok"},
                "visitor": {"token": "Bearer ok"},
                "anonymous": {},
                "roles": {
                    "invalid name with spaces!": {"token": "Bearer tok"},
                    "bad_role": "not_a_dict",
                    "unknown_fields": {"token": "Bearer tok", "unsupported_key": 123},
                },
            }
        }
        result = ConfigValidator.validate(invalid_config)
        self.assertFalse(result.is_valid)
        error_paths = [issue.path for issue in result.issues]
        self.assertTrue(any("invalid name with spaces!" in p for p in error_paths))
        self.assertTrue(any("bad_role" in p for p in error_paths))
        self.assertTrue(any("unknown_fields.unsupported_key" in p for p in error_paths))

    def test_rbac_illegal_header_control_characters(self):
        """CRLF or control characters in role headers must be caught and rejected by validator."""
        invalid_config = {
            "identities": {
                "owner": {"token": "Bearer ok"},
                "visitor": {"token": "Bearer ok"},
                "anonymous": {},
                "roles": {
                    "attacker": {
                        "headers": {"X-Injected\r\nHeader": "val\r\nInjected"}
                    }
                },
            }
        }
        result = ConfigValidator.validate(invalid_config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("control characters" in issue.message for issue in result.issues))

    def test_rbac_token_redaction(self):
        """Role tokens must be registered in auditor secrets and redacted from public reports."""
        secret_tok = "secret-super-privileged-token-777"
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "operator": {"token": f"Bearer {secret_tok}", "role": "operator"},
            },
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, request_delay=0
        )
        self.assertIn(secret_tok, auditor.secret_values())

        # Matrix record sanitization
        auditor.rbac_matrix = {
            "GET /api/test": {
                "roles": {
                    "operator": {"error": f"Connection failed to {secret_tok}", "access": "ERROR"}
                }
            }
        }
        sanitized = auditor.rbac_matrix_record()
        self.assertNotIn(secret_tok, json.dumps(sanitized))
        self.assertIn("[REDACTED]", json.dumps(sanitized))

    def test_rbac_json_html_matrix_consistency(self):
        """Both HTML matrix generator and JSON record produce matching roles and status badges."""
        rbac_matrix = {
            "GET /api/admin/settings": {
                "endpoint": "GET /api/admin/settings",
                "method": "GET",
                "roles": {
                    "admin": {"status": 200, "access": "ALLOWED", "role": "administrator", "violation": False},
                    "viewer": {"status": 403, "access": "DENIED", "role": "viewer", "violation": False},
                },
            }
        }
        html_out = SecurityReportGenerator._rbac_matrix_html(rbac_matrix)
        self.assertIn("GET /api/admin/settings", html_out)
        self.assertIn("ADMIN", html_out)
        self.assertIn("VIEWER", html_out)
        self.assertIn("ALLOWED", html_out)
        self.assertIn("DENIED", html_out)

    # -------------------------------------------------------------------------
    # POST BOLA Tests
    # -------------------------------------------------------------------------

    def test_post_bola_explicit_readonly_sends_request_body(self):
        """POST with read_only: true transmits POST method and the configured JSON request body."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "POST /api/documents/query": {
                "read_only": True,
                "body": {"doc_id": "doc_test_100"},
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]

        recorded_requests: List[Dict[str, Any]] = []

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            recorded_requests.append({"method": method, "url": url, "data": data, "identity": identity_name})
            if identity_name == "owner":
                return HTTPResult(status=200, body=json.dumps({"id": "doc_test_100", "owner": "alice"}))
            elif identity_name == "visitor":
                return HTTPResult(status=200, body=json.dumps({"id": "doc_test_100", "owner": "alice"}))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertTrue(len(recorded_requests) >= 2)
        for req in recorded_requests:
            self.assertEqual(req["method"], "POST", "Method must remain POST")
            self.assertEqual(req["data"], {"doc_id": "doc_test_100"})

    def test_post_bola_unconfigured_readonly_zero_requests(self):
        """POST without read_only: true sends exactly zero HTTP requests."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "POST /api/documents/query": {
                "body": {"doc_id": "doc_test_100"},
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]

        sent_count = 0

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            nonlocal sent_count
            sent_count += 1
            return HTTPResult(status=200, body="{}")

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertEqual(sent_count, 0, "Non-read-only POST must send zero requests")
        self.assertEqual(auditor.results[0]["verdict"], Verdict.SKIPPED.value)

    def test_post_bola_array_and_scalar_bodies(self):
        """POST BOLA supports array bodies and scalar string/int bodies."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        array_payload = [{"doc_id": "1"}, {"doc_id": "2"}]
        bola = {
            "POST /api/documents/query": {
                "read_only": True,
                "body": array_payload,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]

        recorded_data = []

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            recorded_data.append(data)
            return HTTPResult(status=200, body=json.dumps({"status": "ok"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertTrue(len(recorded_data) >= 1)
        self.assertEqual(recorded_data[0], array_payload)

    def test_post_bola_identity_bodies_isolation(self):
        """Distinct payloads for owner, visitor, and visitor_self are strictly respected."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "POST /api/documents/query": {
                "read_only": True,
                "identity_bodies": {
                    "owner": {"id": "owner_res"},
                    "visitor_self": {"id": "visitor_self_res"},
                },
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]

        requests_by_identity: Dict[str, List[Any]] = {}

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            requests_by_identity.setdefault(identity_name, []).append(data)
            if identity_name == "owner":
                return HTTPResult(status=200, body=json.dumps({"id": "owner_res", "val": 1}))
            elif identity_name == "visitor":
                if data and data.get("id") == "visitor_self_res":
                    return HTTPResult(status=200, body=json.dumps({"id": "visitor_self_res", "val": 2}))
                return HTTPResult(status=200, body=json.dumps({"id": "owner_res", "val": 1}))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertEqual(requests_by_identity["owner"], [{"id": "owner_res"}])
        # Cross request repeats the Owner body; the self baseline uses the Visitor's own.
        self.assertEqual(requests_by_identity["visitor"], [{"id": "owner_res"}, {"id": "visitor_self_res"}])
        self.assertEqual(requests_by_identity["anonymous"], [{"id": "owner_res"}])

    def test_post_bola_never_replaced_with_get(self):
        """Under no circumstances should a POST operation be sent as GET."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "POST /api/documents/query": {
                "read_only": True,
                "body": {"query": "all"},
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]

        methods_used = []

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            methods_used.append(method)
            return HTTPResult(status=200, body=json.dumps({"query": "ok"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertNotIn("GET", methods_used)
        self.assertTrue(all(m == "POST" for m in methods_used))

    def test_post_bola_missing_body_inconclusive_zero_requests(self):
        """Read-only POST without a body policy is marked INCONCLUSIVE with zero requests sent."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "POST /api/documents/query": {
                "read_only": True,
                # body is omitted
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]

        sent = 0

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            nonlocal sent
            sent += 1
            return HTTPResult(status=200, body="{}")

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertEqual(sent, 0)
        self.assertEqual(len(auditor.results), 1)
        self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE.value)
        self.assertIn("body", auditor.results[0]["reason"])

    def test_rbac_post_uses_role_request_body(self):
        """RBAC probes on POST endpoints send the correct role-specific request body."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "admin": {"token": "Bearer admin_tok", "role": "administrator", "body": {"role_cmd": "admin_exec"}},
                "viewer": {"token": "Bearer viewer_tok", "role": "viewer", "body": {"role_cmd": "viewer_exec"}},
            },
        }
        bola = {
            "POST /api/admin/audit-log/search": {
                "read_only": True,
                "body": {"default_cmd": "noop"},
                "required_role": "administrator",
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/admin/audit-log/search"][0]

        bodies_by_role: Dict[str, Any] = {}

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("admin", "viewer"):
                bodies_by_role[identity_name] = data
            if identity_name in ("owner", "admin"):
                return HTTPResult(status=200, body=json.dumps({"result": "admin_done"}))
            elif identity_name == "viewer":
                return HTTPResult(status=403, body=json.dumps({"error": "Forbidden"}))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertEqual(bodies_by_role.get("admin"), {"role_cmd": "admin_exec"})
        self.assertEqual(bodies_by_role.get("viewer"), {"role_cmd": "viewer_exec"})

    # -------------------------------------------------------------------------
    # Comprehensive v2.7.0 Edge Case & Verification Tests
    # -------------------------------------------------------------------------

    def test_bopla_cvv_3digit_and_expanded_sensitive_keys(self):
        """3-digit CVV, email_address, date_of_birth, and account_number are properly detected."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        bola = {
            "GET /api/user/profile": {
                "expected_visitor_access": "deny",
                "detect_sensitive_exposure": True,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        doc = {
            "cvv": "123",
            "email_address": "alice@company.org",
            "date_of_birth": "1992-05-18",
            "account_number": "6222020200001234",
        }

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("owner", "visitor"):
                return HTTPResult(status=200, body=json.dumps(doc))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        exposure_results = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertEqual(len(exposure_results), 1)
        # No object selector: a lead, not a confirmation (see test_bopla_same_path_leak).
        self.assertEqual(exposure_results[0]["verdict"], Verdict.SUSPICIOUS.value)
        paths = exposure_results[0]["evidence"]["exposed_sensitive_paths"]
        self.assertIn("cvv", paths)
        self.assertIn("email_address", paths)
        self.assertIn("date_of_birth", paths)
        self.assertIn("account_number", paths)

    def test_bopla_unspecified_visitor_access_yields_suspicious(self):
        """When expected_visitor_access is not explicitly 'deny', exposure is marked as SUSPICIOUS heuristic lead."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        # Notice: NO expected_visitor_access: "deny"
        bola = {
            "GET /api/user/profile": {
                "detect_sensitive_exposure": True,
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/user/profile"][0]

        doc = {"phone": "13800138000"}

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("owner", "visitor"):
                return HTTPResult(status=200, body=json.dumps(doc))
            return HTTPResult(status=401, body=json.dumps({"error": "Auth required"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        exposure_results = [r for r in auditor.results if r["check"] == "BOPLA_EXPOSURE"]
        self.assertEqual(len(exposure_results), 1)
        self.assertEqual(exposure_results[0]["verdict"], Verdict.SUSPICIOUS.value)
        # Should not create a CONFIRMED finding
        self.assertEqual(len(auditor.findings), 0)

    def test_bopla_retroactive_redaction_of_earlier_findings(self):
        """When a sensitive value is discovered, earlier recorded results and findings are retroactively scrubbed."""
        identities = {
            "owner": {"token": "Bearer owner_token"},
            "visitor": {"token": "Bearer visitor_token"},
            "anonymous": {},
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config={}, request_delay=0
        )
        # Manually seed an earlier result with an unredacted secret
        discovered_secret = "SECRET_LEAK_TOKEN_999888"
        fake_result = {
            "endpoint": "GET /api/earlier",
            "check": "BOLA",
            "verdict": "SECURE",
            "evidence": {"response_snippet": f"Found id with token {discovered_secret}"},
        }
        fake_finding = {
            "type": "Information Disclosure",
            "severity": "Low",
            "details": f"Earlier note mentioning {discovered_secret}",
            "evidence": {"raw_body": f"details={discovered_secret}"},
        }
        auditor.results.append(fake_result)
        auditor.findings.append(fake_finding)

        # Now publish the discovered secret
        auditor._publish_secret_values({discovered_secret})

        # Verify retroactive scrubbing took place immediately
        self.assertNotIn(discovered_secret, json.dumps(auditor.results))
        self.assertNotIn(discovered_secret, json.dumps(auditor.findings))
        self.assertIn("[REDACTED]", json.dumps(auditor.results))
        self.assertIn("[REDACTED]", json.dumps(auditor.findings))

    def test_rbac_zero_probes_when_no_required_role(self):
        """When required_role is not specified in bola policy, RBAC sends 0 probe requests."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "admin": {"token": "Bearer admin_tok", "role": "administrator"},
                "viewer": {"token": "Bearer viewer_tok", "role": "viewer"},
            },
        }
        # Endpoint policy has NO required_role
        bola = {
            "GET /api/admin/settings": {}
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/admin/settings"][0]

        requests_sent = []

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            requests_sent.append(identity_name)
            return HTTPResult(status=200, body=json.dumps({"ok": True}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        # Only standard owner, visitor, anonymous requests, zero role probes!
        self.assertNotIn("admin", requests_sent)
        self.assertNotIn("viewer", requests_sent)
        self.assertNotIn("GET /api/admin/settings", getattr(auditor, "rbac_matrix", {}))

    def test_rbac_missing_privileged_role_aborts_probes(self):
        """When required_role is not configured in identities.roles, records INCONCLUSIVE with 0 probes."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "auditor": {"token": "Bearer audit_tok", "role": "auditor"},
            },
        }
        bola = {
            "GET /api/admin/settings": {
                "required_role": "superadmin",  # Not in roles!
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/admin/settings"][0]

        role_probes = []

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name not in ("owner", "visitor", "anonymous"):
                role_probes.append(identity_name)
            return HTTPResult(status=200, body=json.dumps({"ok": True}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertEqual(len(role_probes), 0, "No role probes should be sent when required_role is missing")
        rbac_res = [r for r in auditor.results if r["check"] == "RBAC"]
        self.assertEqual(len(rbac_res), 1)
        self.assertEqual(rbac_res[0]["verdict"], Verdict.INCONCLUSIVE.value)

    def test_rbac_invalid_privileged_baseline_aborts_comparison(self):
        """When privileged baseline fails (e.g. 403 Forbidden), records INCONCLUSIVE and sends 0 comparison probes."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "admin": {"token": "Bearer admin_tok", "role": "administrator"},
                "viewer": {"token": "Bearer viewer_tok", "role": "viewer"},
                "guest": {"token": "Bearer guest_tok", "role": "guest"},
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

        comparison_probes = []

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name == "admin":
                # Privileged baseline fails!
                return HTTPResult(status=403, body=json.dumps({"error": "Admin account locked"}))
            elif identity_name in ("viewer", "guest"):
                comparison_probes.append(identity_name)
                return HTTPResult(status=200, body=json.dumps({"setting": "leak"}))
            return HTTPResult(status=401, body=json.dumps({"error": "Unauthorized"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        self.assertEqual(len(comparison_probes), 0, "No lower role comparison probes must be sent if privileged baseline fails")
        rbac_res = [r for r in auditor.results if r["check"] == "RBAC"]
        self.assertEqual(len(rbac_res), 1)
        self.assertEqual(rbac_res[0]["verdict"], Verdict.INCONCLUSIVE.value)

    def test_rbac_stats_accuracy_no_double_count(self):
        """When an RBAC violation is found, stats['confirmed'] increments by exactly 1, not 2."""
        identities = {
            "owner": {"token": "Bearer admin_tok"},
            "visitor": {"token": "Bearer viewer_tok"},
            "anonymous": {},
            "roles": {
                "admin": {"token": "Bearer admin_tok", "role": "administrator"},
                "viewer": {"token": "Bearer viewer_tok", "role": "viewer"},
            },
        }
        bola = {
            "GET /api/admin/settings": {
                "required_role": "administrator",
                "private_data_paths": ["admin_data"],
            }
        }
        auditor = APISentinelAuditor(
            str(self.spec_file), target_base_url="http://127.0.0.1:8080",
            identities_config=identities, bola_config=bola, request_delay=0
        )
        ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/admin/settings"][0]

        def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
            if identity_name in ("owner", "admin"):
                return HTTPResult(status=200, body=json.dumps({"admin_data": "secret"}))
            elif identity_name == "viewer":
                return HTTPResult(status=200, body=json.dumps({"admin_data": "secret"}))
            # A clean Anonymous denial isolates the function-level boundary (as for BFLA).
            return HTTPResult(status=401, body=json.dumps({"error": "Unauthorized"}))

        auditor._http_request = mock_http
        auditor._audit_endpoint_bola(ep)

        # Check confirmed count: should only have RBAC confirmed
        rbac_violations = [r for r in auditor.results if r["check"] == "RBAC" and r["verdict"] == Verdict.CONFIRMED.value]
        self.assertEqual(len(rbac_violations), 1)
        # Total confirmed results matches stats['confirmed'] without double-counting
        total_confirmed_results = len([r for r in auditor.results if r["verdict"] == Verdict.CONFIRMED.value])
        self.assertEqual(auditor.stats["confirmed"], total_confirmed_results)

    def test_post_bola_scalar_and_array_body_handling(self):
        """Read-only POST BOLA supports scalar, list, and dict bodies without error."""
        identities = {
            "owner": {"token": "Bearer owner_tok"},
            "visitor": {"token": "Bearer visitor_tok"},
            "anonymous": {},
        }
        for body_payload in ([1, 2, 3], "plain text query", 42, {"key": "val"}):
            with self.subTest(body=body_payload):
                bola = {
                    "POST /api/documents/query": {
                        "read_only": True,
                        "body": body_payload,
                    }
                }
                auditor = APISentinelAuditor(
                    str(self.spec_file), target_base_url="http://127.0.0.1:8080",
                    identities_config=identities, bola_config=bola, request_delay=0
                )
                ep = [e for e in auditor.parser.get_endpoints() if e["path"] == "/api/documents/query"][0]

                received_bodies = []

                def mock_http(method, url, data=None, identity_name="anonymous", headers=None, content_type="application/json"):
                    received_bodies.append(data)
                    return HTTPResult(status=200, body=json.dumps({"result": "ok"}))

                auditor._http_request = mock_http
                auditor._audit_endpoint_bola(ep)
                self.assertGreater(len(received_bodies), 0)
                self.assertEqual(received_bodies[0], body_payload)

    def test_schema_validation_v27_full_config(self):
        """config.schema.json validates a comprehensive v2.7.0 configuration."""
        schema = json.loads((Path(__file__).resolve().parents[1] / "config.schema.json").read_text(encoding="utf-8"))
        
        # Verify schema definitions exist
        self.assertIn("roles", schema["properties"]["identities"]["properties"])
        self.assertIn("role_identity", schema["definitions"])
        bola_props = schema["definitions"]["bola_entry"]["properties"]
        self.assertIn("read_only", bola_props)
        self.assertIn("body", bola_props)
        self.assertIn("detect_sensitive_exposure", bola_props)


if __name__ == "__main__":
    unittest.main()
