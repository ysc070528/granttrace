"""Regression tests for isolating comparison_context from live response secrets (P0-01)."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Sequence, Tuple
from unittest.mock import patch

from urllib.parse import parse_qs, unquote, urlsplit

import api_sentinel
from core import demo
from core.auditor import APISentinelAuditor
from core.evidence import sanitize_operation_key, sanitize_url
from core.parser import OpenAPIParser
from core.report_diff import (
    build_comparison_context,
    compare_reports,
    diff_main,
    load_report,
    specification_security_schemes,
)

ROOT = Path(__file__).resolve().parents[1]
TEST_COMPARISON_KEY = "9f8e7d6c5b4a39281706f5e4d3c2b1a0" * 2


class _StatefulProfileHandler(BaseHTTPRequestHandler):
    """Local mock API whose responses overlap configured IDs, policy IDs and spec prose."""

    phase = "vulnerable"
    owner_token = "Bearer TEST_CFG_OWNER_TOKEN_9001"
    visitor_token = "Bearer TEST_CFG_VISITOR_TOKEN_9002"

    def log_message(self, *args: Any) -> None:
        pass

    def _reply(self, status: int, payload: Dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        if not auth:
            self._reply(401, {"error": "authentication required"})
            return
        who = (
            "owner"
            if auth == self.owner_token
            else "visitor"
            if auth.startswith("Bearer TEST_CFG_VISITOR_TOKEN")
            else "unknown"
        )
        if who == "unknown":
            self._reply(401, {"error": "invalid credentials"})
            return

        if self.path == "/users/user-1001":
            if type(self).phase == "fixed":
                if who != "owner":
                    self._reply(403, {"error": "forbidden"})
                    return
                # Server also masks sensitive PIN in Owner view after remediation.
                self._reply(200, {
                    "id": "user-1001",
                    "pin": "****",
                    "ssn": "***-**-6789",
                    "email": "alice_masked@example.org",
                    "bio": "Alice account record",
                })
                return
            # Vulnerable phase: sensitive values deliberately equal or overlap
            # owner.id ("user-1001" / "1001"), OpenAPI summary ("profile-alpha"),
            # and leaked runtime strings that must be redacted in reports without
            # mutating configuration fingerprints.
            self._reply(200, {
                "id": "user-1001",
                "pin": "1001",
                "ssn": "901-23-4567",
                "email": "profile-alpha@corp.example",
                "secret": "user-1001",
                "echo_token": self.owner_token,
                "bio": "Alice account record",
            })
        elif self.path == "/users/user-1002":
            self._reply(200, {
                "id": "user-1002",
                "pin": "2002",
                "ssn": "802-34-5678",
                "email": "bob@corp.example",
                "secret": "visitor-runtime-secret-8899",
                "bio": "Bob account record",
            })
        elif self.path == "/documents/doc-1001":
            if type(self).phase == "fixed" and who != "owner":
                self._reply(403, {"error": "forbidden"})
                return
            self._reply(200, {
                "id": "doc-1001",
                "title": "Confidential",
                "private_code": "doc-1001",
            })
        elif self.path == "/documents/doc-1002":
            self._reply(200, {
                "id": "doc-1002",
                "title": "Visitor doc",
                "private_code": "visitor-doc-9999",
            })
        else:
            self._reply(404, {"error": "not found"})


class ComparisonContextSecretsIsolationTests(unittest.TestCase):
    """Verify P0-01: runtime HTTP responses never contaminate comparison_context."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="granttrace-p001-")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)

    def _run_cli(self, argv: Sequence[Any], key: str | None = TEST_COMPARISON_KEY) -> Tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        env_patch = {"GRANTTRACE_COMPARISON_KEY": key} if key is not None else {}
        with patch.dict(os.environ, env_patch, clear=False), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if key is None:
                os.environ.pop("GRANTTRACE_COMPARISON_KEY", None)
            rc = api_sentinel.main([str(item) for item in argv])
        return rc, out.getvalue(), err.getvalue()

    @staticmethod
    def _spec_users_only() -> Dict[str, Any]:
        return {
            "openapi": "3.0.3",
            "info": {"title": "Profile Service", "version": "1.0.0"},
            "paths": {
                "/users/{id}": {
                    "get": {
                        "operationId": "getUserProfile",
                        "summary": "Fetch profile-alpha record for user-1001",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
            "components": {
                "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
            },
        }

    @staticmethod
    def _config_users(visitor_token: str = _StatefulProfileHandler.visitor_token,
                      detect_exposure: bool = True) -> Dict[str, Any]:
        return {
            "identities": {
                "owner": {"id": "user-1001", "token": _StatefulProfileHandler.owner_token},
                "visitor": {"id": "user-1002", "token": visitor_token},
                "anonymous": {"id": None, "token": None},
            },
            "parameter_values": {
                "GET /users/{id}": {
                    "owner": {"id": "user-1001"},
                    "visitor": {"id": "user-1002"},
                }
            },
            "bola": {
                "GET /users/{id}": {
                    "expected_visitor_access": "deny",
                    "resource_id_paths": ["id"],
                    "detect_sensitive_exposure": detect_exposure,
                }
            },
        }

    def test_config_secret_values_snapshot_stays_immutable_across_runtime_discoveries(self) -> None:
        spec_path = self.folder / "spec.json"
        spec_path.write_text(json.dumps(self._spec_users_only()), encoding="utf-8")
        cfg = self._config_users(detect_exposure=True)

        _StatefulProfileHandler.phase = "vulnerable"
        server = ThreadingHTTPServer(("127.0.0.1", 0), _StatefulProfileHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            auditor = APISentinelAuditor(
                spec_path=str(spec_path),
                target_base_url=f"http://127.0.0.1:{server.server_port}",
                request_delay=0,
                identities_config=cfg["identities"],
                parameter_values=cfg["parameter_values"],
                bola_config=cfg["bola"],
            )
            before_config_secrets = auditor.config_secret_values()
            self.assertIsInstance(before_config_secrets, frozenset)
            self.assertIn("TEST_CFG_OWNER_TOKEN_9001", before_config_secrets)
            self.assertIn("TEST_CFG_VISITOR_TOKEN_9002", before_config_secrets)
            self.assertNotIn("1001", before_config_secrets)
            self.assertNotIn("user-1001", before_config_secrets)
            self.assertNotIn("901-23-4567", before_config_secrets)

            with contextlib.redirect_stdout(io.StringIO()):
                auditor.run()

            after_config_secrets = auditor.config_secret_values()
            runtime_secrets = auditor.secret_values()
            # Config snapshot never absorbs live HTTP response values.
            self.assertEqual(before_config_secrets, after_config_secrets)
            self.assertNotIn("1001", after_config_secrets)
            self.assertNotIn("user-1001", after_config_secrets)
            self.assertNotIn("901-23-4567", after_config_secrets)
            # Runtime redaction set still captures sensitive response values for output scrubbing.
            self.assertIn("1001", runtime_secrets)
            self.assertIn("user-1001", runtime_secrets)
            self.assertIn("901-23-4567", runtime_secrets)
            self.assertTrue(after_config_secrets.issubset(runtime_secrets))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_bola_and_sensitive_exposure_fix_is_resolved_with_identical_comparison_context(self) -> None:
        spec_path = self.folder / "spec.json"
        cfg_path = self.folder / "config.json"
        spec_path.write_text(json.dumps(self._spec_users_only()), encoding="utf-8")
        cfg_path.write_text(json.dumps(self._config_users(detect_exposure=False)), encoding="utf-8")

        server = ThreadingHTTPServer(("127.0.0.1", 0), _StatefulProfileHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            # Scan 1 (vulnerable) & Scan 2 (fixed 403) with detect_sensitive_exposure=True
            cfg_exp_path = self.folder / "config_exposure.json"
            cfg_exp_path.write_text(json.dumps(self._config_users(detect_exposure=True)), encoding="utf-8")

            _StatefulProfileHandler.phase = "vulnerable"
            base_json = self.folder / "base.json"
            base_html = self.folder / "base.html"
            base_sarif = self.folder / "base.sarif"
            rc1, out1, err1 = self._run_cli([
                "--spec", spec_path, "--config", cfg_exp_path, "--target", target,
                "--delay", "0", "-o", base_html, "--export-json", base_json, "--export-sarif", base_sarif,
            ])
            self.assertEqual(rc1, 0, out1 + err1)

            _StatefulProfileHandler.phase = "fixed"
            curr_json = self.folder / "curr.json"
            curr_html = self.folder / "curr.html"
            rc2, out2, err2 = self._run_cli([
                "--spec", spec_path, "--config", cfg_exp_path, "--target", target,
                "--delay", "0", "-o", curr_html, "--export-json", curr_json,
            ])
            self.assertEqual(rc2, 0, out2 + err2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        # Verify default token & runtime response secret redaction across HTML, JSON, and SARIF.
        for artifact in (base_html, base_json, base_sarif):
            content = artifact.read_text(encoding="utf-8")
            self.assertNotIn("TEST_CFG_OWNER_TOKEN_9001", content)
            self.assertNotIn("TEST_CFG_VISITOR_TOKEN_9002", content)
            self.assertNotIn("901-23-4567", content)
            self.assertNotIn(TEST_COMPARISON_KEY, content)

        rep1 = load_report(str(base_json))
        rep2 = load_report(str(curr_json))
        self.assertEqual(rep1["comparison_context"], rep2["comparison_context"])

        comp = compare_reports(rep1, rep2)
        self.assertTrue(comp["comparability"]["fully_comparable"])
        self.assertEqual(comp["comparability"]["blocking"], [])
        self.assertEqual(comp["comparability"]["operation_changes"], [])
        self.assertFalse(any(c.get("kind") == "identities" for c in comp["comparability"]["changes"]))

        bola_issue = next(item for item in comp["issues"] if item["check"] == "BOLA")
        self.assertEqual(bola_issue["status"], "resolved")
        self.assertEqual(bola_issue["baseline_verdicts"], ["CONFIRMED"])
        self.assertEqual(bola_issue["current_verdicts"], ["SECURE"])

        # Without comparison_context, a redacted request path fails closed with scope_unknown.
        unkeyed_rep1 = {k: v for k, v in rep1.items() if k != "comparison_context"}
        unkeyed_rep2 = {k: v for k, v in rep2.items() if k != "comparison_context"}
        unkeyed_comp = compare_reports(
            unkeyed_rep1, unkeyed_rep2,
            assume_same_target=True, assume_same_identities=True, assume_same_configuration=True,
        )
        unkeyed_bola = next(item for item in unkeyed_comp["issues"] if item["check"] == "BOLA")
        self.assertEqual(unkeyed_bola["status"], "not_comparable")
        self.assertIn("scope_unknown", unkeyed_bola["reasons"])

    def test_bopla_response_matching_resource_id_resolves_cleanly_on_403_and_passes_gate(self) -> None:
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Documents doc-1001 API", "version": "1.0.0"},
            "paths": {
                "/documents/{id}": {
                    "get": {
                        "operationId": "getDocument",
                        "summary": "Read document doc-1001",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        }
        config = {
            "identities": {
                "owner": {"id": "doc-1001", "token": _StatefulProfileHandler.owner_token},
                "visitor": {"id": "doc-1002", "token": _StatefulProfileHandler.visitor_token},
                "anonymous": {"id": None, "token": None},
            },
            "parameter_values": {
                "GET /documents/{id}": {"owner": {"id": "doc-1001"}, "visitor": {"id": "doc-1002"}}
            },
            "bola": {"GET /documents/{id}": {"expected_visitor_access": "deny", "resource_id_paths": ["id"]}},
            "bopla": {
                "GET /documents/{id}": {
                    "policy_id": "pol-doc",
                    "context_id": "ctx-doc",
                    "resource_binding": {"id": "doc-1001"},
                    "fields": [{
                        "rule_id": "code-rule",
                        "path": "private_code",
                        "baseline_representation": "full_private_value",
                        "value_is_resource_specific": True,
                        "access": {"owner": "allow", "visitor": "deny", "anonymous": "deny"},
                    }],
                }
            },
        }
        spec_path = self.folder / "doc_spec.json"
        cfg_path = self.folder / "doc_cfg.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        cfg_path.write_text(json.dumps(config), encoding="utf-8")

        server = ThreadingHTTPServer(("127.0.0.1", 0), _StatefulProfileHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            _StatefulProfileHandler.phase = "vulnerable"
            base_json = self.folder / "bopla_base.json"
            curr_json = self.folder / "bopla_curr.json"
            vuln_again_json = self.folder / "bopla_vuln_again.json"

            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_path, "--target", target,
                "--delay", "0", "-o", self.folder / "b1.html", "--export-json", base_json,
            ])[0], 0)

            _StatefulProfileHandler.phase = "fixed"
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_path, "--target", target,
                "--delay", "0", "-o", self.folder / "b2.html", "--export-json", curr_json,
            ])[0], 0)

            # Unfixed scan must remain persisting, never falsely cleared.
            _StatefulProfileHandler.phase = "vulnerable"
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_path, "--target", target,
                "--delay", "0", "-o", self.folder / "b3.html", "--export-json", vuln_again_json,
            ])[0], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        rep_base = load_report(str(base_json))
        rep_curr = load_report(str(curr_json))
        rep_again = load_report(str(vuln_again_json))

        self.assertEqual(rep_base["comparison_context"], rep_curr["comparison_context"])
        comp_fixed = compare_reports(rep_base, rep_curr)
        self.assertTrue(comp_fixed["comparability"]["fully_comparable"])
        self.assertEqual(comp_fixed["comparability"]["blocking"], [])
        self.assertEqual(comp_fixed["comparability"]["operation_changes"], [])
        self.assertEqual(comp_fixed["summary"]["resolved"], 2)
        self.assertEqual(comp_fixed["summary"]["not_comparable"], 0)

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            gate_rc = diff_main([
                str(base_json), str(curr_json),
                "--fail-on-new", "--fail-on-coverage-decrease", "--fail-on-not-comparable",
            ])
        self.assertEqual(gate_rc, 0)

        comp_persisting = compare_reports(rep_base, rep_again)
        self.assertEqual(comp_persisting["summary"]["persisting"], 2)
        self.assertEqual(comp_persisting["summary"]["resolved"], 0)

    def test_real_credential_rotation_still_detected_and_legacy_reports_still_load(self) -> None:
        spec_path = self.folder / "spec.json"
        cfg1_path = self.folder / "cfg1.json"
        cfg2_path = self.folder / "cfg2.json"
        spec_path.write_text(json.dumps(self._spec_users_only()), encoding="utf-8")
        cfg1_path.write_text(json.dumps(self._config_users(detect_exposure=False)), encoding="utf-8")
        cfg2_path.write_text(
            json.dumps(self._config_users(visitor_token="Bearer TEST_CFG_VISITOR_TOKEN_ROTATED", detect_exposure=False)),
            encoding="utf-8",
        )

        server = ThreadingHTTPServer(("127.0.0.1", 0), _StatefulProfileHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            _StatefulProfileHandler.phase = "vulnerable"
            r1 = self.folder / "rot1.json"
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg1_path, "--target", target,
                "--delay", "0", "-o", self.folder / "rot1.html", "--export-json", r1,
            ])[0], 0)
            _StatefulProfileHandler.phase = "fixed"
            r2 = self.folder / "rot2.json"
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg2_path, "--target", target,
                "--delay", "0", "-o", self.folder / "rot2.html", "--export-json", r2,
            ])[0], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        comp = compare_reports(load_report(str(r1)), load_report(str(r2)))
        self.assertEqual(comp["comparability"]["blocking"], ["identities_unverified"])
        self.assertEqual(comp["comparability"]["operation_changes"], [])
        self.assertEqual(comp["comparability"]["changes"][0]["cause"], "credentials_changed")

        # Historical v2.7.1 report compatibility and demo comparison_context stability.
        legacy = load_report(str(ROOT / "tests" / "data" / "report-2.7.1.json"))
        self.assertEqual(legacy["tool_version"], "2.7.1")
        with patch.dict(os.environ, {"GRANTTRACE_COMPARISON_KEY": TEST_COMPARISON_KEY}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(demo.run_demo(output_dir=str(self.folder / "demo_out")), 0)
        demo_report = load_report(str(next((self.folder / "demo_out").rglob("granttrace_report.json"))))
        legacy_comp = compare_reports(
            legacy, demo_report,
            assume_same_target=True, assume_same_identities=True, assume_same_configuration=True,
        )
        self.assertEqual(legacy_comp["summary"]["persisting"], 2)

    def test_parser_replacement_updates_config_secrets_without_absorbing_runtime_secrets(self) -> None:
        spec1 = self.folder / "spec1.json"
        spec2 = self.folder / "spec2.json"
        spec1.write_text(json.dumps(self._spec_users_only()), encoding="utf-8")
        spec_with_custom_header = self._spec_users_only()
        spec_with_custom_header["components"]["securitySchemes"]["customHdr"] = {
            "type": "apiKey", "in": "header", "name": "X-Custom-Session",
        }
        spec2.write_text(json.dumps(spec_with_custom_header), encoding="utf-8")

        identities = {
            "owner": {"id": "1", "token": "Bearer tok-a", "headers": {"X-Custom-Session": "CUSTOM_HDR_SECRET_A"}},
            "visitor": {"id": "2", "token": "Bearer tok-b", "headers": {"X-Custom-Session": "CUSTOM_HDR_SECRET_B"}},
            "anonymous": {"id": None, "token": None},
        }
        auditor = APISentinelAuditor(str(spec1), "http://127.0.0.1:9", identities_config=identities)
        auditor._publish_secret_values({"RUNTIME_LEAKED_VALUE_XYZ"})
        auditor.parser = OpenAPIParser(str(spec2))

        cfg_secrets = auditor.config_secret_values()
        self.assertIn("CUSTOM_HDR_SECRET_A", cfg_secrets)
        self.assertIn("CUSTOM_HDR_SECRET_B", cfg_secrets)
        self.assertNotIn("RUNTIME_LEAKED_VALUE_XYZ", cfg_secrets)
        self.assertIn("RUNTIME_LEAKED_VALUE_XYZ", auditor.secret_values())

    # ------------------------------------------------------------------
    # ADV-01: URL redaction vs concrete resource identity separation
    # ------------------------------------------------------------------

    def test_adv01_partial_path_redaction_never_masks_unredacted_or_sibling_resource_changes(self) -> None:
        ctx = build_comparison_context(
            key=TEST_COMPARISON_KEY,
            target="http://127.0.0.1:8000",
            identities={
                "owner": {"id": "1", "token": "Bearer segsecret"},
                "visitor": {"id": "2", "token": "Bearer vis"},
                "anonymous": {},
            },
            endpoints=[{"method": "GET", "path": "/segsecret/{id}"}],
            secret_values=("Bearer segsecret", "segsecret", "Bearer vis"),
        )
        safe_op = "GET /[REDACTED]/{id}"
        base: Dict[str, Any] = {
            "tool_version": "2.8.0",
            "report_schema_version": 2,
            "target": "http://127.0.0.1:8000",
            "comparison_context": ctx,
            "results": [{
                "endpoint": safe_op,
                "check": "BOLA",
                "verdict": "CONFIRMED",
                "reason": "vuln",
                "evidence": {
                    "requests_attempted": 4,
                    "target_url": "http://127.0.0.1:8000/%5BREDACTED%5D/order-AAA",
                    "visitor_self_url": "http://127.0.0.1:8000/%5BREDACTED%5D/order-BBB",
                },
            }],
        }
        curr_different_target: Dict[str, Any] = {
            "tool_version": "2.8.0",
            "report_schema_version": 2,
            "target": "http://127.0.0.1:8000",
            "comparison_context": ctx,
            "results": [{
                "endpoint": safe_op,
                "check": "BOLA",
                "verdict": "SECURE",
                "reason": "denied",
                "evidence": {
                    "requests_attempted": 4,
                    "target_url": "http://127.0.0.1:8000/%5BREDACTED%5D/order-ZZZ",
                    "visitor_self_url": "http://127.0.0.1:8000/%5BREDACTED%5D/order-BBB",
                },
            }],
        }
        comp_target = compare_reports(base, curr_different_target)
        self.assertEqual(comp_target["issues"][0]["status"], "not_comparable")
        self.assertIn("resources_changed", comp_target["issues"][0]["reasons"])

        curr_different_self = copy.deepcopy(curr_different_target)
        curr_different_self["results"][0]["evidence"]["target_url"] = "http://127.0.0.1:8000/%5BREDACTED%5D/order-AAA"
        curr_different_self["results"][0]["evidence"]["visitor_self_url"] = "http://127.0.0.1:8000/%5BREDACTED%5D/order-DIFF"
        comp_self = compare_reports(base, curr_different_self)
        self.assertEqual(comp_self["issues"][0]["status"], "not_comparable")
        self.assertIn("resources_changed", comp_self["issues"][0]["reasons"])

        # Adversarial pathological multi-marker path segment completes in linear time (no ReDoS).
        redos_left = copy.deepcopy(base)
        redos_right = copy.deepcopy(curr_different_target)
        redos_left["results"][0]["evidence"]["target_url"] = (
            "http://127.0.0.1:8000/" + "a[REDACTED]" * 25 + "z/order-AAA"
        )
        redos_right["results"][0]["evidence"]["target_url"] = (
            "http://127.0.0.1:8000/" + ("a" * 400) + "x/order-AAA"
        )
        comp_redos = compare_reports(redos_left, redos_right)
        self.assertEqual(comp_redos["issues"][0]["status"], "not_comparable")
        self.assertIn("resources_changed", comp_redos["issues"][0]["reasons"])

    def test_adv01_redacted_pii_and_secret_overlapping_resources_never_collide(self) -> None:
        # 1) Unkeyed reports with different emails that both sanitize to [EMAIL%20REDACTED]
        #    must preserve uncertainty (scope_unknown), never resolved.
        url_alice = sanitize_url("http://127.0.0.1:8000/users/alice@corp.example")
        url_bob = sanitize_url("http://127.0.0.1:8000/users/bob@corp.example")
        self.assertEqual(url_alice, url_bob)
        unkeyed_1 = {
            "tool_version": "2.8.0", "report_schema_version": 2, "target": "http://127.0.0.1:8000",
            "results": [{"endpoint": "GET /users/{email}", "check": "BOLA", "verdict": "CONFIRMED",
                         "reason": "v", "evidence": {"requests_attempted": 3, "target_url": url_alice}}],
        }
        unkeyed_2 = {
            "tool_version": "2.8.0", "report_schema_version": 2, "target": "http://127.0.0.1:8000",
            "results": [{"endpoint": "GET /users/{email}", "check": "BOLA", "verdict": "SECURE",
                         "reason": "s", "evidence": {"requests_attempted": 3, "target_url": url_bob}}],
        }
        comp_unkeyed = compare_reports(
            unkeyed_1, unkeyed_2,
            assume_same_target=True, assume_same_identities=True, assume_same_configuration=True,
        )
        self.assertEqual(comp_unkeyed["issues"][0]["status"], "not_comparable")
        self.assertIn("scope_unknown", comp_unkeyed["issues"][0]["reasons"])

        # 2) Keyed reports where two different resource IDs each overlap their scan's token
        #    must still produce distinct resource HMACs and report resources_changed.
        ctx_a = build_comparison_context(
            key=TEST_COMPARISON_KEY,
            target="http://127.0.0.1:8000",
            identities={"owner": {"id": "acct-1", "token": "Bearer order-secret-A"},
                        "visitor": {"id": "acct-2", "token": "Bearer vis"}, "anonymous": {}},
            endpoints=[{"method": "GET", "path": "/orders/{id}"}],
            parameter_values={"GET /orders/{id}": {"owner": {"id": "order-secret-A"}, "visitor": {"id": "v-1"}}},
            secret_values=("Bearer order-secret-A", "order-secret-A", "Bearer vis"),
        )
        ctx_b = build_comparison_context(
            key=TEST_COMPARISON_KEY,
            target="http://127.0.0.1:8000",
            identities={"owner": {"id": "acct-1", "token": "Bearer order-secret-B"},
                        "visitor": {"id": "acct-2", "token": "Bearer vis"}, "anonymous": {}},
            endpoints=[{"method": "GET", "path": "/orders/{id}"}],
            parameter_values={"GET /orders/{id}": {"owner": {"id": "order-secret-B"}, "visitor": {"id": "v-1"}}},
            secret_values=("Bearer order-secret-B", "order-secret-B", "Bearer vis"),
        )
        self.assertNotEqual(
            ctx_a["operations"]["GET /orders/{id}"]["resources"],
            ctx_b["operations"]["GET /orders/{id}"]["resources"],
        )
        rep_a = {
            "tool_version": "2.8.0", "report_schema_version": 2, "target": "http://127.0.0.1:8000",
            "comparison_context": ctx_a,
            "results": [{"endpoint": "GET /orders/{id}", "check": "BOLA", "verdict": "CONFIRMED",
                         "reason": "v", "evidence": {"requests_attempted": 4,
                                                     "target_url": "http://127.0.0.1:8000/orders/[REDACTED]"}}],
        }
        rep_b = {
            "tool_version": "2.8.0", "report_schema_version": 2, "target": "http://127.0.0.1:8000",
            "comparison_context": ctx_b,
            "results": [{"endpoint": "GET /orders/{id}", "check": "BOLA", "verdict": "SECURE",
                         "reason": "s", "evidence": {"requests_attempted": 4,
                                                     "target_url": "http://127.0.0.1:8000/orders/[REDACTED]"}}],
        }
        comp_overlap = compare_reports(rep_a, rep_b, assume_same_identities=True)
        self.assertEqual(comp_overlap["issues"][0]["status"], "not_comparable")
        self.assertIn("resources_changed", comp_overlap["issues"][0]["reasons"])

        # 3) Token overlapping resource ID during normal token rotation (same resource ID)
        #    must NOT trigger false resources_changed.
        ctx_rot = build_comparison_context(
            key=TEST_COMPARISON_KEY,
            target="http://127.0.0.1:8000",
            identities={"owner": {"id": "acct-1", "token": "Bearer rotated-fresh-token"},
                        "visitor": {"id": "acct-2", "token": "Bearer vis"}, "anonymous": {}},
            endpoints=[{"method": "GET", "path": "/orders/{id}"}],
            parameter_values={"GET /orders/{id}": {"owner": {"id": "order-secret-A"}, "visitor": {"id": "v-1"}}},
            secret_values=("Bearer rotated-fresh-token", "rotated-fresh-token", "Bearer vis"),
        )
        self.assertEqual(
            ctx_a["operations"]["GET /orders/{id}"]["resources"],
            ctx_rot["operations"]["GET /orders/{id}"]["resources"],
        )

    def test_adv01_live_query_path_deleted_resource_and_server_mutation_matrix(self) -> None:
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Orders Matrix API", "version": "1.0.0"},
            "paths": {
                "/orders/{order_id}": {
                    "get": {
                        "operationId": "getOrderById",
                        "parameters": [
                            {"name": "order_id", "in": "path", "required": True, "schema": {"type": "string"}},
                            {"name": "region", "in": "query", "required": False, "schema": {"type": "string"}},
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        }
        state = {"mode": "vulnerable"}

        class OrderHandler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                auth = self.headers.get("Authorization", "")
                if not auth:
                    self._send(401, {"error": "authentication required"})
                    return
                parts = urlsplit(self.path)
                path = unquote(parts.path)
                region = parse_qs(parts.query).get("region", ["us"])[0]
                is_owner = auth == "Bearer OWN_ORD_1"
                if path == "/orders/ord-202":
                    self._send(200, {"id": "ord-202", "owner_note": "bob-item", "region": region})
                    return
                if path == "/orders/ord-999":
                    self._send(403 if not is_owner else 200,
                               {"error": "forbidden"} if not is_owner else {"id": "ord-999", "owner_note": "other"})
                    return
                if path == "/orders/ord-101":
                    if state["mode"] == "deleted":
                        self._send(404, {"error": "not found"})
                        return
                    if state["mode"] == "fixed" and not is_owner:
                        self._send(403, {"error": "forbidden"})
                        return
                    if state["mode"] == "different_payload":
                        self._send(200, {"id": "ord-101", "owner_note": "mutated-server-record", "region": region})
                        return
                    self._send(200, {"id": "ord-101", "owner_note": "alice-secret-order", "region": region})
                    return
                self._send(404, {"error": "not found"})

            def _send(self, code: int, body: Dict[str, Any]) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        spec_path = self.folder / "ord_spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")

        def make_cfg(owner_order: str = "ord-101", region: str | None = "us") -> Path:
            owner_params: Dict[str, Any] = {"order_id": owner_order}
            visitor_params: Dict[str, Any] = {"order_id": "ord-202"}
            if region is not None:
                owner_params["region"] = region
                visitor_params["region"] = region
            cfg = {
                "identities": {
                    "owner": {"id": "ord-101", "token": "Bearer OWN_ORD_1"},
                    "visitor": {"id": "ord-202", "token": "Bearer VIS_ORD_2"},
                    "anonymous": {"id": None, "token": None},
                },
                "parameter_values": {"GET /orders/{order_id}": {"owner": owner_params, "visitor": visitor_params}},
                "bola": {"GET /orders/{order_id}": {"expected_visitor_access": "deny", "resource_id_paths": ["id"]}},
            }
            p = self.folder / f"cfg_{owner_order}_{region}.json"
            p.write_text(json.dumps(cfg), encoding="utf-8")
            return p

        server = ThreadingHTTPServer(("127.0.0.1", 0), OrderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            cfg_base = make_cfg("ord-101", "us")
            cfg_diff_path = make_cfg("ord-999", "us")
            cfg_diff_query = make_cfg("ord-101", "eu")
            cfg_no_query = make_cfg("ord-101", None)

            def scan(label: str, cfg_p: Path, mode_val: str) -> Dict[str, Any]:
                state["mode"] = mode_val
                out_j = self.folder / f"{label}.json"
                rc, out, err = self._run_cli([
                    "--spec", spec_path, "--config", cfg_p, "--target", target,
                    "--delay", "0", "-o", self.folder / f"{label}.html", "--export-json", out_j,
                ])
                self.assertEqual(rc, 0, out + err)
                return load_report(str(out_j))

            rep_vuln = scan("vuln", cfg_base, "vulnerable")
            rep_fixed = scan("fixed", cfg_base, "fixed")
            rep_deleted = scan("deleted", cfg_base, "deleted")
            rep_mutated = scan("mutated", cfg_base, "different_payload")
            rep_diff_path = scan("diff_path", cfg_diff_path, "fixed")
            rep_diff_query = scan("diff_query", cfg_diff_query, "fixed")
            rep_no_query = scan("no_query", cfg_no_query, "fixed")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        # Genuine remediation -> resolved
        self.assertEqual(compare_reports(rep_vuln, rep_fixed)["issues"][0]["status"], "resolved")
        # Server returns mutated data on same resource -> still persisting with identical context
        comp_mut = compare_reports(rep_vuln, rep_mutated)
        self.assertTrue(comp_mut["comparability"]["fully_comparable"])
        self.assertEqual(comp_mut["issues"][0]["status"], "persisting")
        # Resource deleted (404) -> INCONCLUSIVE -> not_comparable (current_unverified), NEVER resolved
        comp_del = compare_reports(rep_vuln, rep_deleted)
        self.assertEqual(comp_del["issues"][0]["status"], "not_comparable")
        self.assertEqual(comp_del["issues"][0]["reasons"], ["current_unverified"])
        # Path parameter changed -> resources_changed
        comp_path = compare_reports(rep_vuln, rep_diff_path)
        self.assertEqual(comp_path["issues"][0]["status"], "not_comparable")
        self.assertIn("resources_changed", comp_path["issues"][0]["reasons"])
        # Query parameter value changed -> resources_changed
        comp_qval = compare_reports(rep_vuln, rep_diff_query)
        self.assertEqual(comp_qval["issues"][0]["status"], "not_comparable")
        self.assertIn("resources_changed", comp_qval["issues"][0]["reasons"])
        # Query parameter removed -> resources_changed
        comp_qrem = compare_reports(rep_vuln, rep_no_query)
        self.assertEqual(comp_qrem["issues"][0]["status"], "not_comparable")
        self.assertIn("resources_changed", comp_qrem["issues"][0]["reasons"])

    # ------------------------------------------------------------------
    # ADV-02: Runtime secrets never pollute OpenAPI operation metadata
    # ------------------------------------------------------------------

    def test_adv02_runtime_and_static_secrets_overlapping_operation_templates(self) -> None:
        # 1) Runtime response values matching path word 'users' and operationId 'getUserProfile'
        #    must NEVER alter endpoint, operation_id, finding_id, SARIF, or comparison_context.
        spec_path = self.folder / "adv02_spec.json"
        spec_path.write_text(json.dumps(self._spec_users_only()), encoding="utf-8")

        phase = {"mode": "vuln"}

        class OverlapHandler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                auth = self.headers.get("Authorization", "")
                if not auth:
                    self._send(401, {"error": "unauthorized"})
                    return
                if self.path == "/users/user-1002":
                    self._send(200, {"id": "user-1002", "pin": "safe-pin"})
                    return
                if self.path == "/users/user-1001":
                    if phase["mode"] == "fixed" and auth != _StatefulProfileHandler.owner_token:
                        self._send(403, {"error": "forbidden"})
                        return
                    # Deliberately return 'users' and 'getUserProfile' inside sensitive fields!
                    self._send(200, {
                        "id": "user-1001",
                        "pin": "users",
                        "secret": "getUserProfile",
                        "password": "users",
                    })
                    return
                self._send(404, {"error": "not found"})

            def _send(self, code: int, obj: Dict[str, Any]) -> None:
                raw = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), OverlapHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            cfg_normal = self.folder / "cfg_normal.json"
            cfg_normal.write_text(json.dumps(self._config_users(detect_exposure=True)), encoding="utf-8")
            j1, s1 = self.folder / "adv02_1.json", self.folder / "adv02_1.sarif"
            j2 = self.folder / "adv02_2.json"

            phase["mode"] = "vuln"
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_normal, "--target", target,
                "--delay", "0", "-o", self.folder / "a1.html", "--export-json", j1, "--export-sarif", s1,
            ])[0], 0)
            phase["mode"] = "fixed"
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_normal, "--target", target,
                "--delay", "0", "-o", self.folder / "a2.html", "--export-json", j2,
            ])[0], 0)

            # 2) Static config token overlapping path word ('Bearer users') -> both endpoint
            #    and comparison_context['operations'] align on 'GET /[REDACTED]/{id}'.
            cfg_tok_overlap = self.folder / "cfg_tok_overlap.json"
            cfg_tok_overlap.write_text(
                json.dumps(self._config_users(visitor_token="Bearer users", detect_exposure=False)),
                encoding="utf-8",
            )
            jb1, jb2 = self.folder / "b2_1.json", self.folder / "b2_2.json"
            phase["mode"] = "vuln"
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_tok_overlap, "--target", target,
                "--delay", "0", "-o", self.folder / "b2_1.html", "--export-json", jb1,
            ])[0], 0)
            phase["mode"] = "fixed"
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_tok_overlap, "--target", target,
                "--delay", "0", "-o", self.folder / "b2_2.html", "--export-json", jb2,
            ])[0], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        rep1, rep2 = load_report(str(j1)), load_report(str(j2))
        for rec in rep1["results"]:
            self.assertEqual(rec["endpoint"], "GET /users/{id}")
            self.assertEqual(rec["operation_id"], "getUserProfile")
        sarif_doc = json.loads(s1.read_text(encoding="utf-8"))
        self.assertEqual(sarif_doc["runs"][0]["results"][0]["properties"]["endpoint"], "GET /users/{id}")
        comp = compare_reports(rep1, rep2)
        self.assertTrue(comp["comparability"]["fully_comparable"])
        bola_issue = next(i for i in comp["issues"] if i["check"] == "BOLA")
        self.assertEqual(bola_issue["status"], "resolved")

        rep_b1, rep_b2 = load_report(str(jb1)), load_report(str(jb2))
        self.assertEqual(list(rep_b1["comparison_context"]["operations"].keys()), ["GET /[REDACTED]/{id}"])
        self.assertEqual(rep_b1["results"][0]["endpoint"], "GET /[REDACTED]/{id}")
        comp_b = compare_reports(rep_b1, rep_b2)
        self.assertTrue(comp_b["comparability"]["fully_comparable"])
        self.assertEqual(comp_b["issues"][0]["status"], "resolved")

        # HTTP verbs and placeholders remain valid even if secrets match 'POST' or '{id}'.
        self.assertEqual(sanitize_operation_key("POST /items/{id}", ("POST", "{id}")), "POST /items/{[REDACTED]}")

    # ------------------------------------------------------------------
    # ADV-03: Nested body/header/cookie auth secrets vs business PII
    # ------------------------------------------------------------------

    def test_adv03_nested_auth_material_collection_and_business_pii_separation(self) -> None:
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Search API", "version": "1.0.0"},
            "paths": {
                "/orders/search": {
                    "post": {
                        "operationId": "searchOrders",
                        "summary": "Read-only search over orders",
                        "responses": {"200": {"description": "ok"}},
                        "security": [{"bearerAuth": []}],
                    }
                }
            },
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        }
        spec_path = self.folder / "post_spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")

        def make_setup(
            role_api_key: str = "ROLE_BODY_KEY_V1",
            bola_secret: str = "POST_BODY_SECRET_V1",
            filter_name: str = "AliceCorp",
            filter_email: str = "alice@corp.example",
        ) -> Tuple[APISentinelAuditor, Dict[str, Any]]:
            identities = {
                "owner": {
                    "id": "u-1",
                    "token": "Bearer OWN_POST_TOK",
                    "headers": {
                        "X-Custom-Gateway": "GW_AUTH_9911",
                        "Cookie": 'sid="SID_COOKIE_7788"; theme=dark',
                    },
                    "auth_header_names": ["X-Custom-Gateway"],
                    "parameters": {"nested": [{"session_token": "NESTED_PARAM_SES_1"}]},
                },
                "visitor": {
                    "id": "u-2",
                    "token": "Bearer VIS_POST_TOK",
                    "headers": {"X-Custom-Gateway": "GW_AUTH_9922"},
                    "auth_header_names": ["X-Custom-Gateway"],
                },
                "anonymous": {"id": None, "token": None},
                "roles": {
                    "auditor": {
                        "id": "r-1",
                        "role": "auditor",
                        "token": "Token DRF_ROLE_TOK_5566",
                        # Every identity sends the gateway credential that owner and visitor declare.
                        "headers": {"X-Custom-Gateway": "GW_AUTH_9933"},
                        "body": {
                            "auth": {"api_key": role_api_key},
                            "chain": [{"client_secret": "LIST_ROLE_SEC_44"}],
                        },
                    }
                },
            }
            bola_cfg = {
                "POST /orders/search": {
                    "read_only": True,
                    "expected_visitor_access": "deny",
                    "resource_id_paths": ["order_id"],
                    "identity_bodies": {
                        "owner": {
                            "order_id": "ord-1",
                            "credentials": [{"access_token": bola_secret}],
                            "filter": {"name": filter_name, "email": filter_email},
                        },
                        "visitor_self": {"order_id": "ord-2"},
                    },
                }
            }
            readback_cfg = {
                "PATCH /orders/{id}": {
                    "method": "GET",
                    "path": "/orders/{id}",
                    "field_map": {"tier": "tier"},
                    "baseline_payload": {"auth_meta": {"refresh_token": "RB_REFRESH_TOK_33"}},
                }
            }
            aud = APISentinelAuditor(
                str(spec_path),
                "http://127.0.0.1:8000",
                identities_config=identities,
                bola_config=bola_cfg,
                readback_config=readback_cfg,
            )
            ctx = build_comparison_context(
                key=TEST_COMPARISON_KEY,
                target="http://127.0.0.1:8000",
                identities=aud.identities,
                endpoints=aud.parser.get_endpoints(),
                security_schemes=specification_security_schemes(aud.parser.raw_spec),
                parameter_values=aud.parameter_values,
                bola_config=aud.bola_config,
                bopla_config=aud.bopla_config,
                readback_config=aud.readback_config,
                write_allowlist=aud.write_allowlist,
                secret_values=aud.config_secret_values(),
            )
            return aud, ctx

        aud_base, ctx_base = make_setup()
        cfg_secrets = aud_base.config_secret_values()
        out_secrets = aud_base.secret_values()

        # Auth credentials across headers, cookies, Token scheme, nested dicts and lists are in config_secret_values().
        for expected_auth in (
            "OWN_POST_TOK",
            "GW_AUTH_9911",
            "SID_COOKIE_7788",
            "NESTED_PARAM_SES_1",
            "DRF_ROLE_TOK_5566",
            "ROLE_BODY_KEY_V1",
            "LIST_ROLE_SEC_44",
            "POST_BODY_SECRET_V1",
            "RB_REFRESH_TOK_33",
        ):
            self.assertIn(expected_auth, cfg_secrets)
            self.assertIn(expected_auth, out_secrets)

        # Business PII ('name', 'email') is NOT treated as an authentication credential in config_secret_values(),
        # YET IS collected in secret_values() for report/CLI output redaction!
        self.assertNotIn("AliceCorp", cfg_secrets)
        self.assertNotIn("alice@corp.example", cfg_secrets)
        self.assertNotIn("ord-1", cfg_secrets)
        self.assertIn("AliceCorp", out_secrets)
        self.assertIn("alice@corp.example", out_secrets)

        # Rotating auth credentials inside role.body or bola.identity_bodies triggers credentials_changed ONLY.
        _, ctx_rot_role = make_setup(role_api_key="ROLE_BODY_KEY_V2")
        comp_role = compare_reports(
            {"tool_version": "2.8.0", "report_schema_version": 2, "target": "http://127.0.0.1:8000",
             "comparison_context": ctx_base, "results": []},
            {"tool_version": "2.8.0", "report_schema_version": 2, "target": "http://127.0.0.1:8000",
             "comparison_context": ctx_rot_role, "results": []},
        )
        self.assertEqual(comp_role["comparability"]["blocking"], ["identities_unverified"])
        self.assertEqual(comp_role["comparability"]["changes"][0]["cause"], "credentials_changed")

        _, ctx_rot_bola = make_setup(bola_secret="POST_BODY_SECRET_V2")
        self.assertEqual(ctx_base["operations"], ctx_rot_bola["operations"])
        self.assertNotEqual(ctx_base["credentials"], ctx_rot_bola["credentials"])

        # Changing business filter ('AliceCorp' -> 'BobCorp') in bola body MUST trigger policy_changed, NOT credentials_changed!
        _, ctx_diff_business = make_setup(filter_name="BobCorp", filter_email="bob@corp.example")
        self.assertEqual(ctx_base["credentials"], ctx_diff_business["credentials"])
        self.assertNotEqual(
            ctx_base["operations"]["POST /orders/search"]["policy"],
            ctx_diff_business["operations"]["POST /orders/search"]["policy"],
        )

    def test_pr99_and_pr100_safety_guards_remain_intact_alongside_p001_pipeline(self) -> None:
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "PR99-100 Guard Check", "version": "1.0.0"},
            "paths": {
                "/carts/lookup": {
                    "post": {
                        "operationId": "getOrCreateCart",
                        "responses": {"200": {"description": "ok"}},
                        "security": [{"bearerAuth": []}],
                    }
                },
                "/orders/query": {
                    "post": {
                        "operationId": "searchOrders",
                        "responses": {"200": {"description": "ok"}},
                        "security": [{"bearerAuth": []}],
                    }
                },
                "/orders/{id}": {
                    "delete": {
                        "operationId": "deleteOrder",
                        "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                        "responses": {"204": {"description": "deleted"}},
                    }
                },
            },
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        }
        spec_path = self.folder / "guard_spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")

        observed_methods: list[Tuple[str, str]] = []
        state = {"fixed": False}

        class GuardHandler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _handle_any(self, verb: str) -> None:
                observed_methods.append((verb, self.path))
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length).decode("utf-8") if length else "{}"
                payload = json.loads(raw_body or "{}")
                auth = self.headers.get("Authorization", "")
                if not auth:
                    self._reply_json(401, {"error": "unauthorized"})
                    return
                if payload.get("order_id") == "ord-vis":
                    self._reply_json(200, {"order_id": "ord-vis", "secret_echo": payload.get("api_key", "")})
                    return
                if state["fixed"] and auth != "Bearer GUARD_OWNER_TOK":
                    self._reply_json(403, {"error": "forbidden"})
                    return
                self._reply_json(200, {"order_id": "ord-own", "secret_echo": payload.get("api_key", "")})

            def do_POST(self) -> None:
                self._handle_any("POST")

            def do_DELETE(self) -> None:
                self._handle_any("DELETE")

            def _reply_json(self, code: int, obj: Dict[str, Any]) -> None:
                raw = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        # PR #100: Python API direct construction refuses method-override headers on identities.
        with self.assertRaises(ValueError):
            APISentinelAuditor(
                str(spec_path),
                "http://127.0.0.1:9",
                identities_config={
                    "owner": {"id": "1", "token": "Bearer A", "headers": {"X-HTTP-Method-Override": "DELETE"}},
                    "visitor": {"id": "2", "token": "Bearer B"},
                    "anonymous": {},
                },
            )

        cfg = {
            "identities": {
                "owner": {"id": "1", "token": "Bearer GUARD_OWNER_TOK"},
                "visitor": {"id": "2", "token": "Bearer GUARD_VISITOR_TOK"},
                "anonymous": {"id": None, "token": None},
            },
            "bola": {
                "POST /carts/lookup": {
                    "read_only": True,
                    "body": {"cart_id": "c-1"},
                },
                "POST /orders/query": {
                    "read_only": True,
                    "expected_visitor_access": "deny",
                    "resource_id_paths": ["order_id"],
                    "identity_bodies": {
                        "owner": {"order_id": "ord-own", "api_key": "BODY_CRED_ECHO_77"},
                        "visitor_self": {"order_id": "ord-vis", "api_key": "BODY_CRED_ECHO_88"},
                    },
                },
            },
        }
        cfg_path = self.folder / "guard_cfg.json"
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

        server = ThreadingHTTPServer(("127.0.0.1", 0), GuardHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            j1, h1 = self.folder / "g1.json", self.folder / "g1.html"
            j2, h2 = self.folder / "g2.json", self.folder / "g2.html"
            state["fixed"] = False
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_path, "--target", target,
                "--delay", "0", "-o", h1, "--export-json", j1,
            ])[0], 0)
            state["fixed"] = True
            self.assertEqual(self._run_cli([
                "--spec", spec_path, "--config", cfg_path, "--target", target,
                "--delay", "0", "-o", h2, "--export-json", j2,
            ])[0], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        # PR #99 blocked getOrCreateCart and DELETE was never sent; only POST /orders/query reached the server.
        self.assertTrue(all(verb == "POST" and path == "/orders/query" for verb, path in observed_methods))
        for artifact in (j1, h1):
            txt = artifact.read_text(encoding="utf-8")
            self.assertNotIn("BODY_CRED_ECHO_77", txt)
            self.assertNotIn("GUARD_OWNER_TOK", txt)
        r1, r2 = load_report(str(j1)), load_report(str(j2))
        comp = compare_reports(r1, r2)
        self.assertTrue(comp["comparability"]["fully_comparable"])
        self.assertEqual(comp["issues"][0]["status"], "resolved")


if __name__ == "__main__":
    unittest.main()
