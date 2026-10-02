# -*- coding: utf-8 -*-
"""Comprehensive regression test suite for API-Sentinel v2.3.0 hardening.

Verifies:
1. Normal CLI entry point main() executes full ConfigValidator semantic validation
   offline and exits 2 before creating Auditor or starting scan.
2. Lowercase readback method is rejected at normal scan entry point.
3. Session/Credential/custom auth header identification is 100% consistent
   between ConfigValidator and Auditor.
4. Operation keys strictly reject non-canonical formatting (spaces), and no discrepancy
   exists between Validator check and Auditor runtime lookup.
5. ignore_readback_paths full collision check (parent, child, exact) across both written
   and readback paths in both ConfigValidator and prepare_patch.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import parse_operation_key
from core.transactions import paths_collide, prepare_patch

ROOT = Path(__file__).resolve().parent.parent


class NormalCliConfigValidationTests(unittest.TestCase):
    """Verify normal main() rejects invalid configuration with exit code 2."""

    def test_main_rejects_missing_field_map(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump({
                "readbacks": {
                    "PATCH /api/users/{id}": {
                        "method": "GET",
                        "path": "/api/users/{id}",
                    }
                }
            }, f)
            cfg_path = f.name

        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = main(["--spec", str(ROOT / "openapi.json"), "--config", cfg_path, "--dry-run"])
            self.assertEqual(code, 2)
        finally:
            Path(cfg_path).unlink(missing_ok=True)

    def test_main_rejects_lowercase_readback_method(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump({
                "readbacks": {
                    "PATCH /api/users/{id}": {
                        "method": "get",
                        "path": "/api/users/{id}",
                        "field_map": {"status": "status"},
                    }
                }
            }, f)
            cfg_path = f.name

        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = main(["--spec", str(ROOT / "openapi.json"), "--config", cfg_path, "--dry-run"])
            self.assertEqual(code, 2)
        finally:
            Path(cfg_path).unlink(missing_ok=True)

    def test_main_rejects_unknown_top_level_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump({
                "unknown_section": True,
            }, f)
            cfg_path = f.name

        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = main(["--spec", str(ROOT / "openapi.json"), "--config", cfg_path, "--dry-run"])
            self.assertEqual(code, 2)
        finally:
            Path(cfg_path).unlink(missing_ok=True)

    def test_main_never_makes_network_calls_on_invalid_config(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump({"readbacks": "not-a-dict"}, f)
            cfg_path = f.name

        try:
            with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network forbidden")):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = main(["--spec", str(ROOT / "openapi.json"), "--config", cfg_path])
                self.assertEqual(code, 2)
        finally:
            Path(cfg_path).unlink(missing_ok=True)

    def test_main_rejects_invalid_cli_write_endpoint(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main([
                "--spec", str(ROOT / "openapi.json"),
                "--dry-run",
                "--write-endpoint", "patch /api/users/{id}"  # lowercase method
            ])
        self.assertEqual(code, 2)


class AuthHeaderConsistencyTests(unittest.TestCase):
    """Verify ConfigValidator and Auditor reach identical conclusions on auth headers."""

    def setUp(self):
        self.auditor = APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url="http://127.0.0.1:8080",
        )

    def test_session_headers_recognized_consistently(self):
        test_headers = [
            "session", "Session", "SESSION",
            "X-Session-ID", "x-session-id",
            "session_token", "app-session-key",
        ]
        for header in test_headers:
            v_result = ConfigValidator.is_auth_header(header)
            a_result = self.auditor._is_auth_header(header)
            self.assertTrue(v_result, f"Validator failed on {header}")
            self.assertTrue(a_result, f"Auditor failed on {header}")
            self.assertEqual(v_result, a_result, f"Disagreement on {header}")

    def test_credential_headers_recognized_consistently(self):
        test_headers = [
            "credential", "Credential", "CREDENTIAL",
            "X-User-Credential", "x-user-credential",
            "client_credentials", "user-credentials-token",
        ]
        for header in test_headers:
            v_result = ConfigValidator.is_auth_header(header)
            a_result = self.auditor._is_auth_header(header)
            self.assertTrue(v_result, f"Validator failed on {header}")
            self.assertTrue(a_result, f"Auditor failed on {header}")
            self.assertEqual(v_result, a_result, f"Disagreement on {header}")

    def test_custom_auth_headers_recognized_consistently(self):
        custom_header = "X-Internal-Gateway-Key"
        auditor_custom = APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url="http://127.0.0.1:8080",
            identities_config={
                "owner": {"token": "Bearer O", "auth_header_names": [custom_header]},
                "visitor": {"token": "Bearer V"},
                "anonymous": {"id": None, "token": None},
            },
        )
        v_result = ConfigValidator.is_auth_header(custom_header, custom_auth_names=[custom_header])
        a_result = auditor_custom._is_auth_header(custom_header)
        self.assertTrue(v_result)
        self.assertTrue(a_result)
        self.assertEqual(v_result, a_result)

    def test_non_auth_headers_rejected_consistently(self):
        ordinary_headers = [
            "Content-Type", "Accept", "User-Agent", "X-Request-ID",
            "X-Correlation-ID", "Cache-Control", "Origin", "Host",
        ]
        for header in ordinary_headers:
            v_result = ConfigValidator.is_auth_header(header)
            a_result = self.auditor._is_auth_header(header)
            self.assertFalse(v_result, f"Validator falsely marked {header} as auth")
            self.assertFalse(a_result, f"Auditor falsely marked {header} as auth")
            self.assertEqual(v_result, a_result)


class OperationKeyStrictFormattingTests(unittest.TestCase):
    """Verify strict single canonical format for operation keys and no lookup mismatch."""

    def test_parse_operation_key_rejects_multiple_spaces(self):
        valid, _, _, _, err = parse_operation_key("PATCH  /api/users")
        self.assertFalse(valid)
        self.assertIn("separated by a single space", err or "")

    def test_parse_operation_key_rejects_leading_trailing_spaces(self):
        for bad_key in [" PATCH /api/users", "PATCH /api/users ", "  PATCH /api/users  "]:
            valid, _, _, _, err = parse_operation_key(bad_key)
            self.assertFalse(valid, f"Failed to reject: {bad_key!r}")
            self.assertIn("whitespace", err or "")

    def test_validator_rejects_multi_spaced_operation_key(self):
        config = {
            "write_allowlist": ["PATCH  /api/users/{user_id}/settings"],
            "readbacks": {
                "PATCH  /api/users/{user_id}/settings": {
                    "method": "GET",
                    "path": "/api/users/{user_id}/settings",
                    "field_map": {"role": "role"},
                }
            },
        }
        res = ConfigValidator.validate(config)
        self.assertFalse(res.is_valid)

    def test_auditor_lookup_with_canonical_key(self):
        config_readbacks = {
            "PATCH /api/users/{user_id}/settings": {
                "method": "GET",
                "path": "/api/users/{user_id}/settings",
                "field_map": {"role": "role"},
            }
        }
        auditor = APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url="http://127.0.0.1:8080",
            readback_config=config_readbacks,
            write_allowlist=["PATCH /api/users/{user_id}/settings"],
        )
        ep = {"method": "PATCH", "path": "/api/users/{user_id}/settings"}
        self.assertIsNotNone(auditor._readback_for(ep, []))


class IgnoreReadbackPathsFullCollisionTests(unittest.TestCase):
    """Verify complete collision checking between ignore_readback_paths and field_map."""

    def test_field_map_role_to_data_role_with_ignore_data_rejected_by_validator(self):
        config = {
            "write_allowlist": ["PATCH /api/users/{id}"],
            "readbacks": {
                "PATCH /api/users/{id}": {
                    "method": "GET",
                    "path": "/api/users/{id}",
                    "field_map": {"role": "data.role"},
                    "ignore_readback_paths": ["data"],
                }
            },
        }
        res = ConfigValidator.validate(config)
        self.assertFalse(res.is_valid)
        self.assertTrue(
            any("collides with readback field 'data.role'" in e.message for e in res.errors),
            f"Expected collision error, got: {[e.message for e in res.errors]}",
        )

    def test_write_user_profile_with_ignore_child_rejected_by_validator(self):
        config = {
            "write_allowlist": ["PATCH /api/users/{id}"],
            "readbacks": {
                "PATCH /api/users/{id}": {
                    "method": "GET",
                    "path": "/api/users/{id}",
                    "field_map": {"user.profile": "profile"},
                    "ignore_readback_paths": ["user.profile.updatedAt"],
                }
            },
        }
        res = ConfigValidator.validate(config)
        self.assertFalse(res.is_valid)
        self.assertTrue(
            any("collides with written field 'user.profile'" in e.message for e in res.errors),
            f"Expected collision error, got: {[e.message for e in res.errors]}",
        )

    def test_prepare_patch_rejects_parent_of_readback_ignore(self):
        before = {"data": {"role": "admin"}}
        case = {
            "field_path": "role",
            "value": "hacked",
            "baseline": {"role": "admin"},
            "injections": {"role": "hacked"},
        }
        mapping = {
            "field_map": {"role": "data.role"},
            "ignore_readback_paths": ["data"],
        }
        with self.assertRaises(ValueError) as ctx:
            prepare_patch(before, case, mapping)
        self.assertIn("cannot ignore any part of a written field/container snapshot", str(ctx.exception))

    def test_prepare_patch_rejects_child_of_written_ignore(self):
        before = {"user": {"profile": {"status": "active"}}}
        case = {
            "field_path": "user.profile",
            "value": {"status": "disabled"},
            "baseline": {"user": {"profile": {"status": "active"}}},
            "injections": {},
        }
        mapping = {
            "field_map": {"user.profile": "user.profile"},
            "ignore_readback_paths": ["user.profile.updatedAt"],
        }
        with self.assertRaises(ValueError) as ctx:
            prepare_patch(before, case, mapping)
        self.assertIn("cannot ignore any part of a written field/container snapshot", str(ctx.exception))

    def test_paths_collide_symmetry_and_containment(self):
        # Exact equal
        self.assertTrue(paths_collide(("role",), ("role",)))
        # Parent / Child
        self.assertTrue(paths_collide(("data",), ("data", "role")))
        self.assertTrue(paths_collide(("data", "role"), ("data",)))
        # Deep child / parent
        self.assertTrue(paths_collide(("a", "b", "c"), ("a", "b")))
        self.assertTrue(paths_collide(("a", "b"), ("a", "b", "c")))
        # Disjoint
        self.assertFalse(paths_collide(("data", "role"), ("data", "status")))
        self.assertFalse(paths_collide(("role",), ("roles",)))
        self.assertFalse(paths_collide((), ("a",)))


if __name__ == "__main__":
    unittest.main()
