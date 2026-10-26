# -*- coding: utf-8 -*-
"""Scoped regression and acceptance tests for expanded detection capabilities:
1. OWASP API2:2023 - Broken Authentication (CWE-306)
2. OWASP API5:2023 - Broken Function Level Authorization (BFLA, CWE-285)
3. Collection & Contextual Endpoints Data Isolation / BOLA (CWE-639)
4. Full-Snapshot PUT Mass Assignment & Reversible Rollback (CWE-915)
"""

import copy
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.sarif import SarifReportGenerator


class ExpandedMockHandler(BaseHTTPRequestHandler):
    LOCK = threading.RLock()
    WRITES = []
    GET_REQUESTS = []
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
        path = urlsplit(self.path).path
        with self.LOCK:
            self.GET_REQUESTS.append(self.path)

        # 1. Broken Auth endpoint: requires auth, but leaks data to anonymous
        if path == "/api/broken-auth-resource":
            self._write_json(200, {"sensitive_data": "secret-xyz", "status": "leaked"})
            return

        # 2. Secure Auth endpoint: requires auth, properly rejects anonymous
        if path == "/api/secure-auth-resource":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            self._write_json(200, {"sensitive_data": "authorized-only"})
            return

        # 3. BFLA Vulnerable Admin endpoint: visitor can read admin config
        if path == "/api/admin/system/metrics":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            # Flaw: does not check if user is admin, allows visitor
            self._write_json(200, self.DATABASE["admin_config"])
            return

        # 4. BFLA Secure Admin endpoint: visitor is rejected with 403
        if path == "/api/admin/secure-settings":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            if user != "1001":  # only owner is admin
                self._write_json(403, {"error": "Forbidden"})
                return
            self._write_json(200, self.DATABASE["admin_config"])
            return

        # 5. Collection BOLA: orders collection leaks owner's orders to visitor
        if path == "/api/v1/orders/leaky":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            # Flaw: returns all orders including Alice's order to anyone
            self._write_json(200, self.DATABASE["orders"]["1001"])
            return

        # 6. Collection Isolated: returns only user's own orders
        if path == "/api/v1/orders/isolated":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
                return
            self._write_json(200, self.DATABASE["orders"].get(user, []))
            return

        if path == "/api/v1/orders/denied":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
            elif user != "1001":
                self._write_json(403, {"error": "Forbidden"})
            else:
                self._write_json(200, self.DATABASE["orders"][user])
            return

        if path == "/api/v1/orders/leaky-no-id":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
            else:
                # Genuine cross-tenant data disclosure without an Owner ID.
                self._write_json(200, [{"item": self.DATABASE["orders"]["1001"][0]["item"]}])
            return

        if path == "/api/v1/orders/no-owner-baseline":
            if not user:
                self._write_json(401, {"error": "Authentication required"})
            elif user == "1001":
                self._write_json(200, [])
            else:
                self._write_json(200, self.DATABASE["orders"][user])
            return

        # 7. PUT readback endpoint
        if path == "/api/admin/public-metrics" or path in {
            "/api/admin/public-records/rec-1", "/api/admin/public-records/rec-2",
        }:
            self._write_json(200, {"id": path.rsplit("/", 1)[-1], **self.DATABASE["admin_config"]})
            return

        if path == "/api/v1/records/rec-1":
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
            # PUT replaces the resource: omitted fields are really deleted.
            # A partial mutation/restore document would corrupt this fixture.
            with self.LOCK:
                self.DATABASE["records"]["rec-1"] = copy.deepcopy(payload)
                self.WRITES.append(copy.deepcopy(payload))
                result = copy.deepcopy(self.DATABASE["records"]["rec-1"])
            self._write_json(200, result)
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
        with ExpandedMockHandler.LOCK:
            ExpandedMockHandler.DATABASE["records"]["rec-1"] = {
                "id": "rec-1", "title": "Report", "is_admin": False, "status": "active",
            }
            ExpandedMockHandler.WRITES.clear()
            ExpandedMockHandler.GET_REQUESTS.clear()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_auditor(self, paths: dict, config: dict = None, allow_write_tests: bool = False,
                      *, authority: bool = False, spec_overrides: dict = None):
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Expanded Test Spec", "version": "1.0"},
            "paths": paths,
        }
        spec.update(spec_overrides or {})
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

        fixture_target = self.target_url

        class DisposableStoreAuditor(APISentinelAuditor):
            """Internal fixture only: bypass HTTP to inspect our own disposable store."""

            def _authoritative_patch_state(self, ep, mutation_url, readback):
                if self.target_base_url != fixture_target or urlsplit(mutation_url).path != "/api/v1/records/rec-1":
                    return None
                with ExpandedMockHandler.LOCK:
                    return copy.deepcopy(ExpandedMockHandler.DATABASE["records"]["rec-1"])

        cls = DisposableStoreAuditor if authority else APISentinelAuditor
        with patch("urllib.request.getproxies", return_value={}):
            return cls(
                spec_path=str(spec_path),
                target_base_url=self.target_url,
                request_delay=0,
                identities_config=default_config["identities"],
                write_allowlist=default_config.get("write_allowlist", []),
                readback_config=default_config.get("readbacks", {}),
                allow_write_tests=allow_write_tests,
                bola_config=default_config.get("bola", {}),
                parameter_values=default_config.get("parameter_values", {}),
            )

    @staticmethod
    def _private_policy(path: str, *private_paths: str, roles: bool = False):
        policy = {"private_data_paths": list(private_paths)}
        if roles:
            policy.update(required_role="administrator", owner_role="administrator", visitor_role="reader")
        return {"bola": {"GET " + path: policy}}

    def test_broken_authentication_confirmed_on_unauthenticated_leak(self):
        """An anonymous exact match of explicitly private Owner data confirms Broken Auth."""
        paths = {
            "/api/broken-auth-resource": {
                "get": {
                    "summary": "Sensitive profile",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}},
                }
            }
        }
        auditor = self._make_auditor(paths, self._private_policy("/api/broken-auth-resource", "sensitive_data"))
        auditor.run()

        broken_auth_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-306"]
        self.assertEqual(len(broken_auth_findings), 1)
        self.assertEqual(broken_auth_findings[0]["severity"], "High")
        self.assertIn("private", broken_auth_findings[0]["details"].lower())
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
        auditor = self._make_auditor(paths, self._private_policy("/api/secure-auth-resource", "sensitive_data"))
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
        auditor = self._make_auditor(paths, self._private_policy("/api/admin/system/metrics", "cluster_secret", roles=True))
        auditor.run()

        bfla_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-285"]
        self.assertEqual(len(bfla_findings), 1)
        # This read proves protected data exposure, not administrative code
        # execution or a privilege-changing operation. High is the scoped risk.
        self.assertEqual(bfla_findings[0]["severity"], "High")
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
        auditor = self._make_auditor(paths, self._private_policy("/api/admin/secure-settings", "cluster_secret", roles=True))
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
        auditor = self._make_auditor(paths, self._private_policy("/api/v1/orders/leaky", "[0].item"))
        auditor.run()

        bola_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-639"]
        self.assertEqual(len(bola_findings), 1)
        self.assertIn("private", bola_findings[0]["details"].lower())

    def test_collection_endpoint_different_private_values_do_not_prove_full_isolation(self):
        """The original different-200 fixture is retained, with a stricter evidence requirement."""
        paths = {
            "/api/v1/orders/isolated": {
                "get": {
                    "summary": "User orders collection",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}},
                }
            }
        }
        auditor = self._make_auditor(paths, self._private_policy("/api/v1/orders/isolated", "[0].item"))
        auditor.run()

        bola_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-639"]
        self.assertEqual(len(bola_findings), 0)
        bola_result = next(r for r in auditor.results if r["endpoint"] == "GET /api/v1/orders/isolated" and r["check"] == "BOLA")
        self.assertEqual(bola_result["verdict"], "INCONCLUSIVE")

    def test_collection_endpoint_secure_on_clean_denial_with_owner_baseline(self):
        path = "/api/v1/orders/denied"
        paths = {path: {"get": {"security": [{"bearerAuth": []}], "responses": {"200": {"description": "OK"}}}}}
        auditor = self._make_auditor(paths, self._private_policy(path, "[0].item"))
        auditor.run()
        result = next(r for r in auditor.results if r["check"] == "BOLA")
        self.assertEqual(result["verdict"], "SECURE")
        self.assertTrue(result["evidence"]["decision_evidence"]["owner_baseline_valid"])
        self.assertFalse(any(f.get("cwe") == "CWE-639" for f in auditor.findings))

    def test_collection_leak_without_owner_id_is_confirmed(self):
        path = "/api/v1/orders/leaky-no-id"
        paths = {path: {"get": {"security": [{"bearerAuth": []}], "responses": {"200": {"description": "OK"}}}}}
        auditor = self._make_auditor(paths, self._private_policy(path, "[0].item"))
        auditor.run()
        result = next(r for r in auditor.results if r["check"] == "BOLA")
        self.assertEqual(result["verdict"], "CONFIRMED")
        self.assertEqual(result["evidence"]["decision_evidence"]["matched_private_data_paths"], ["[0].item"])
        self.assertEqual(len([f for f in auditor.findings if f.get("cwe") == "CWE-639"]), 1)

    def test_collection_missing_owner_baseline_cannot_be_secure(self):
        path = "/api/v1/orders/no-owner-baseline"
        paths = {path: {"get": {"security": [{"bearerAuth": []}], "responses": {"200": {"description": "OK"}}}}}
        auditor = self._make_auditor(paths, self._private_policy(path, "[0].item"))
        auditor.run()
        result = next(r for r in auditor.results if r["check"] == "BOLA")
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertFalse(result["evidence"]["decision_evidence"]["owner_baseline_valid"])
        self.assertEqual(auditor.stats["conclusive_endpoints"], 0)

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
        original = copy.deepcopy(ExpandedMockHandler.DATABASE["records"]["rec-1"])
        auditor = self._make_auditor(paths, config=config, allow_write_tests=True, authority=True)
        auditor.run()

        # Vulnerability should be confirmed
        mass_findings = [f for f in auditor.findings if f.get("cwe") == "CWE-915"]
        self.assertEqual(len(mass_findings), 1)
        self.assertEqual(mass_findings[0]["endpoint"], "PUT /api/v1/records/rec-1")
        # Rollback should be verified
        self.assertTrue(mass_findings[0]["evidence"]["rollback_verified"])
        # Server database state should be restored to False
        self.assertFalse(ExpandedMockHandler.DATABASE["records"]["rec-1"]["is_admin"])
        self.assertEqual(ExpandedMockHandler.DATABASE["records"]["rec-1"], original)
        self.assertEqual(len(ExpandedMockHandler.WRITES), 2)
        mutation, restore = ExpandedMockHandler.WRITES
        self.assertTrue(mutation["is_admin"])
        self.assertEqual(restore, original)
        self.assertEqual({k: v for k, v in mutation.items() if k != "is_admin"},
                         {k: v for k, v in original.items() if k != "is_admin"})

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

    def test_openapi_global_security_and_operation_overrides(self):
        """Authentication requirements follow OAS inheritance and anonymous alternatives."""
        required = [{"bearerAuth": []}]
        cases = [
            ("global inherited", {"security": required}, {}, required, True),
            ("operation requires auth", {"security": []}, {"security": required}, required, True),
            ("operation public override", {"security": required}, {"security": []}, [], False),
            ("anonymous alternative", {"security": required}, {"security": [{}, *required]}, [{}, *required], False),
            ("global public", {"security": []}, {}, [], False),
            ("unspecified", {}, {}, [], False),
        ]
        for label, root_security, operation_security, effective_security, should_confirm in cases:
            with self.subTest(case=label):
                path = "/api/broken-auth-resource"
                paths = {path: {"get": {"responses": {"200": {"description": "OK"}}, **operation_security}}}
                auditor = self._make_auditor(
                    paths, self._private_policy(path, "sensitive_data"), spec_overrides=root_security,
                )
                endpoint = auditor.parser.get_endpoints()[0]
                self.assertEqual(endpoint["security"], effective_security)
                self.assertEqual(endpoint["security_declared"], bool(root_security or operation_security))
                auditor.run()
                auth_result = next(r for r in auditor.results if r["check"] == "BROKEN_AUTH")
                self.assertEqual(auth_result["verdict"] == "CONFIRMED", should_confirm)
                findings = [f for f in auditor.findings if f.get("cwe") == "CWE-306"]
                self.assertEqual(bool(findings), should_confirm)

    def test_multiple_checks_count_findings_separately_and_require_complete_endpoint_evidence(self):
        """One positive check cannot conceal another inconclusive check on its endpoint."""
        roles_path = "/api/admin/system/metrics"
        incomplete_path = "/api/secure-auth-resource"
        operation = {"security": [{"bearerAuth": []}], "responses": {"200": {"description": "OK"}}}
        auditor = self._make_auditor(
            {roles_path: {"get": operation}, incomplete_path: {"get": operation}},
            self._private_policy(roles_path, "cluster_secret", roles=True),
        )
        auditor.run()
        by_path = {path: [r for r in auditor.results if r["endpoint"] == "GET " + path]
                   for path in (roles_path, incomplete_path)}
        self.assertEqual({r["check"] for r in by_path[roles_path]}, {"BOLA", "BROKEN_AUTH", "BFLA"})
        self.assertEqual({r["check"] for r in by_path[incomplete_path]}, {"BOLA", "BROKEN_AUTH"})
        self.assertTrue(all(r["verdict"] in {"CONFIRMED", "SECURE"} for r in by_path[roles_path]))
        self.assertEqual(next(r["verdict"] for r in by_path[incomplete_path] if r["check"] == "BROKEN_AUTH"), "SECURE")
        self.assertEqual(next(r["verdict"] for r in by_path[incomplete_path] if r["check"] == "BOLA"), "INCONCLUSIVE")
        self.assertEqual(auditor.stats["total_endpoints"], len(by_path))
        self.assertEqual(auditor.stats["total_checks"], sum(map(len, by_path.values())))
        confirmed = [r for r in auditor.results if r["verdict"] == "CONFIRMED"]
        self.assertGreater(len(confirmed), 1)
        self.assertEqual(len({r["endpoint"] for r in confirmed}), 1)
        self.assertEqual(auditor.stats["confirmed"], len(confirmed))
        self.assertEqual(len(auditor.findings), len(confirmed))
        self.assertEqual(auditor.stats["attempted_endpoints"], len(by_path))
        self.assertEqual(auditor.stats["conclusive_endpoints"], 1)
        self.assertEqual(auditor.stats["coverage_pct"], 100.0)
        self.assertEqual(auditor.stats["conclusive_coverage_pct"], 100.0 / len(by_path))

    def test_public_or_optional_auth_cannot_be_reclassified_as_bfla_by_role_configuration(self):
        """A role assertion cannot override an explicitly public contract silently."""
        for path in ("/api/admin/public-metrics", "/api/admin/public-records/{record_id}"):
            for security in ([], [{}, {"bearerAuth": []}]):
                with self.subTest(path=path, security=security):
                    operation = {"security": security, "responses": {"200": {"description": "OK"}}}
                    if "{" in path:
                        operation["parameters"] = [{"name": "record_id", "in": "path", "required": True,
                                                    "schema": {"type": "string"}}]
                    config = self._private_policy(path, "cluster_secret", roles=True)
                    if "{" in path:
                        config["identities"] = {
                            "owner": {"id": "1001", "token": "Bearer TOKEN_ALICE_OWNER_1001",
                                      "parameters": {"record_id": "rec-1"}},
                            "visitor": {"id": "1002", "token": "Bearer TOKEN_BOB_VISITOR_1002",
                                        "parameters": {"record_id": "rec-2"}},
                            "anonymous": {"id": None, "token": None, "parameters": {}},
                        }
                    auditor = self._make_auditor({path: {"get": operation}}, config)
                    auditor.run()
                    result = next(r for r in auditor.results if r["check"] == "BFLA")
                    self.assertEqual(result["verdict"], "INCONCLUSIVE")
                    self.assertFalse(any(f.get("cwe") == "CWE-285" for f in auditor.findings))
                    self.assertFalse(any(f.get("cwe") == "CWE-306" for f in auditor.findings))

    def test_collection_with_pagination_query_uses_explicit_private_evidence(self):
        path = "/api/v1/orders/leaky"
        operation = {"security": [{"bearerAuth": []}], "responses": {"200": {"description": "OK"}},
                     "parameters": [{"name": "limit", "in": "query", "required": True,
                                     "schema": {"type": "integer"}}]}
        config = self._private_policy(path, "[0].item")
        config["parameter_values"] = {"GET " + path: {"limit": 2}}
        auditor = self._make_auditor({path: {"get": operation}}, config)
        auditor.run()
        result = next(r for r in auditor.results if r["check"] == "BOLA")
        self.assertEqual(result["verdict"], "CONFIRMED")
        self.assertIn("?limit=", result["evidence"]["target_url"])
        self.assertEqual(ExpandedMockHandler.GET_REQUESTS, [path + "?limit=2"] * 3)
        self.assertEqual(result["evidence"]["decision_evidence"]["matched_private_data_paths"], ["[0].item"])


if __name__ == "__main__":
    unittest.main()
