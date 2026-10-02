# -*- coding: utf-8 -*-
"""Comprehensive security and contract regression test suite for RC2.

Validates:
1. Credential non-disclosure in stdout/stderr (H-01).
2. CRLF log injection defense (H-01).
3. Graceful error collection without tracebacks (M-01).
4. Validator/Auditor/Transactions operation and path consistency (M-02, M-03, M-05, M-06).
5. Readbacks completeness when allowlist is present.
6. Strict structural and type checking (M-04).
7. Rejection of NaN, Infinity, -Infinity (M-07).
8. Version 2.3.0-rc2 consistency.
"""

from __future__ import annotations

import io
import json
import math
import socket
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.evidence import safe_diagnostic_value, sanitize_log_text
from core.models import parse_operation_key
from core.transactions import path_parts

ROOT = Path(__file__).resolve().parents[1]


class SecurityCredentialLeakageTests(unittest.TestCase):
    """Ensure sensitive credentials never appear in stdout, stderr, or diagnostic outputs."""

    def test_authorization_and_token_never_leak_in_cli_stderr(self):
        secret_token = "SUPER_SECRET_BEARER_TOKEN_99999"
        bad_config = {
            "identities": {
                "owner": {"token": f"Bearer {secret_token}"},
                "visitor": {"token": f"Bearer {secret_token}"},  # Error: identical token
                "anonymous": {"token": f"Bearer {secret_token}"},  # Error: anon token
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as temp:
            json.dump(bad_config, temp)
            temp_path = temp.name

        try:
            stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                code = main(["--validate-config", "--config", temp_path])
            self.assertEqual(code, 2)
            stderr_text = stderr_buf.getvalue()
            stdout_text = stdout_buf.getvalue()
            # Assert secret token is nowhere in the logs
            self.assertNotIn(secret_token, stderr_text)
            self.assertNotIn(secret_token, stdout_text)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_cookie_and_api_key_never_leak_in_cli_stderr(self):
        secret_cookie = "session_id=SECRET_COOKIE_DATA_12345"
        secret_apikey = "SECRET_APIKEY_DATA_67890"
        bad_config = {
            "identities": {
                "owner": {
                    "headers": {
                        "Cookie": secret_cookie,
                        "X-API-Key": secret_apikey,
                    }
                },
                "visitor": {"headers": {"Cookie": secret_cookie}},
                "anonymous": {
                    "headers": {"Cookie": secret_cookie}  # Error: anon headers forbidden
                },
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as temp:
            json.dump(bad_config, temp)
            temp_path = temp.name

        try:
            stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                code = main(["--validate-config", "--config", temp_path])
            self.assertEqual(code, 2)
            stderr_text = stderr_buf.getvalue()
            stdout_text = stdout_buf.getvalue()
            self.assertNotIn(secret_cookie, stderr_text)
            self.assertNotIn(secret_apikey, stderr_text)
            self.assertNotIn(secret_cookie, stdout_text)
            self.assertNotIn(secret_apikey, stdout_text)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_query_secret_in_url_never_leaks(self):
        query_secret = "SECRET_QUERY_TOKEN_555"
        bad_config = {
            "parameter_values": {
                f"GET /api/data?api_key={query_secret}": {"id": 1}
            }
        }
        result = ConfigValidator.validate(bad_config)
        self.assertFalse(result.is_valid)
        rendered = "\n".join(e.format() for e in result.errors)
        self.assertNotIn(query_secret, rendered)

    def test_safe_diagnostic_value_redacts_nested_structures(self):
        secret = "SECRET_PAYLOAD_VALUE_999"
        nested = {
            "token": secret,
            "sub": {
                "authorization": f"Bearer {secret}",
                "password": secret,
            },
            "tuple_item": (("api_key", secret), ("other", "public")),
        }
        rendered = safe_diagnostic_value(nested)
        self.assertNotIn(secret, rendered)
        self.assertIn("[REDACTED]", rendered)


class CRLFLogInjectionTests(unittest.TestCase):
    """Ensure CR and LF characters cannot forge or inject spurious log lines."""

    def test_crlf_in_token_is_escaped_in_formatted_issues(self):
        malicious_token = "Bearer valid\r\n[OK] Configuration is valid: fake.json\r\n[INFO] Injected line"
        bad_config = {
            "identities": {
                "owner": {"token": malicious_token},
                "visitor": {"token": "Bearer 2"},
                "anonymous": {},
            }
        }
        result = ConfigValidator.validate(bad_config)
        self.assertFalse(result.is_valid)
        for issue in result.errors:
            formatted = issue.format()
            # Each formatted issue must not contain raw unescaped CR/LF in its value lines
            lines = formatted.splitlines()
            for line in lines:
                self.assertNotIn("[OK] Configuration is valid: fake.json", line)
                self.assertNotIn("[INFO] Injected line", line)

    def test_crlf_in_headers_is_escaped_in_cli_output(self):
        bad_config = {
            "identities": {
                "owner": {
                    "headers": {"X-Custom\r\nInjected-Header": "value\r\nAnother-Injected: true"}
                },
                "visitor": {"token": "Bearer 2"},
                "anonymous": {},
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as temp:
            json.dump(bad_config, temp)
            temp_path = temp.name

        try:
            stderr_buf = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr_buf):
                code = main(["--validate-config", "--config", temp_path])
            self.assertEqual(code, 2)
            stderr_text = stderr_buf.getvalue()
            # Verify no forged lines were injected
            for line in stderr_text.splitlines():
                self.assertFalse(line.startswith("Injected-Header"))
                self.assertFalse(line.startswith("Another-Injected"))
        finally:
            Path(temp_path).unlink(missing_ok=True)


class RobustnessAndNoTracebackTests(unittest.TestCase):
    """Ensure invalid configurations never raise unhandled exceptions or Python tracebacks."""

    def test_deeply_nested_json_does_not_cause_recursion_error(self):
        # Create an object with depth 30
        deep: dict = {}
        curr = deep
        for i in range(30):
            curr["level"] = {}
            curr = curr["level"]

        result = ConfigValidator.validate(deep)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("depth" in e.message.lower() for e in result.errors))

    def test_non_utf8_config_file_returns_exit_code_2_without_traceback(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as temp:
            temp.write(b'{"invalid_utf8": "\xff\xfe\xfd"}')
            temp_path = temp.name

        try:
            stderr_buf = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr_buf):
                code = main(["--validate-config", "--config", temp_path])
            self.assertEqual(code, 2)
            stderr_text = stderr_buf.getvalue()
            self.assertIn("[ERROR]", stderr_text)
            self.assertNotIn("Traceback (most recent call last):", stderr_text)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_nan_and_infinity_in_json_config_are_strictly_rejected(self):
        nan_json = '{"readbacks": {"PATCH /api/test": {"method": "GET", "path": "/api/test", "field_map": {"a": "b"}, "readback_delay": NaN}}}'
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as temp:
            temp.write(nan_json)
            temp_path = temp.name

        try:
            stderr_buf = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr_buf):
                code = main(["--validate-config", "--config", temp_path])
            self.assertEqual(code, 2)
            stderr_text = stderr_buf.getvalue()
            self.assertIn("[ERROR]", stderr_text)
            self.assertNotIn("Traceback", stderr_text)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_in_memory_nan_and_infinity_values_are_caught(self):
        config_nan = {
            "readbacks": {
                "PATCH /api/test": {
                    "method": "GET",
                    "path": "/api/test",
                    "field_map": {"a": "b"},
                    "readback_delay": float("nan"),
                }
            }
        }
        result = ConfigValidator.validate(config_nan)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("NaN" in e.message or "NaN" in e.actual for e in result.errors))


class OperationAndPathConsistencyTests(unittest.TestCase):
    """Ensure Validator, Auditor, and Transactions agree on operation keys and paths."""

    def test_validator_and_auditor_share_parse_operation_key(self):
        # Valid key
        valid_key = "PATCH /api/users/{id}"
        ok, method, path, canonical, err = parse_operation_key(valid_key)
        self.assertTrue(ok)
        self.assertEqual(canonical, "PATCH /api/users/{id}")

        # Auditor accepts it
        auditor_allowlist = set()
        auditor = APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url="http://127.0.0.1:8080",
            write_allowlist=[valid_key],
        )
        self.assertIn(canonical, auditor.write_allowlist)

        # Lowercase method is rejected consistently by parse_operation_key
        bad_key = "patch /api/users/{id}"
        ok, _, _, _, err = parse_operation_key(bad_key)
        self.assertFalse(ok)
        self.assertIn("uppercase", err or "")

        with self.assertRaises(ValueError):
            APISentinelAuditor(
                spec_path=str(ROOT / "openapi.json"),
                target_base_url="http://127.0.0.1:8080",
                write_allowlist=[bad_key],
            )

    def test_validator_and_transactions_path_parts_consistency(self):
        # Path with consecutive dots
        invalid_path = "user..role"
        with self.assertRaises(ValueError):
            path_parts(invalid_path)

        bad_config = {
            "readbacks": {
                "PATCH /api/users/{id}": {
                    "method": "GET",
                    "path": "/api/users/{id}",
                    "field_map": {invalid_path: "role"},
                }
            }
        }
        result = ConfigValidator.validate(bad_config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("invalid mutation path expression" in e.message.lower() for e in result.errors))


class ReadbacksCompletenessTests(unittest.TestCase):
    """Ensure allowlist requires complete readback mapping."""

    def test_allowlist_without_readbacks_fails(self):
        config_no_readbacks = {
            "write_allowlist": ["PATCH /api/users/{id}"]
            # readbacks omitted!
        }
        result = ConfigValidator.validate(config_no_readbacks)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("missing an independent GET readback mapping" in e.message for e in result.errors))

    def test_allowlist_with_empty_readbacks_fails(self):
        config_empty_readbacks = {
            "write_allowlist": ["PATCH /api/users/{id}"],
            "readbacks": {},
        }
        result = ConfigValidator.validate(config_empty_readbacks)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("missing an independent GET readback mapping" in e.message for e in result.errors))

    def test_allowlist_partial_readbacks_fails(self):
        config_partial = {
            "write_allowlist": [
                "PATCH /api/users/{id}/settings",
                "PATCH /api/users/{id}/profile",
            ],
            "readbacks": {
                "PATCH /api/users/{id}/settings": {
                    "method": "GET",
                    "path": "/api/users/{id}/settings",
                    "field_map": {"role": "role"},
                }
            },
        }
        result = ConfigValidator.validate(config_partial)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("PATCH /api/users/{id}/profile" in e.path for e in result.errors))


class StrictTypeAndStructureTests(unittest.TestCase):
    """Ensure strict structural validation."""

    def test_header_value_must_be_string(self):
        bad_config = {
            "identities": {
                "owner": {"headers": {"X-Numeric-Header": 12345}},
                "visitor": {"token": "Bearer 2"},
                "anonymous": {},
            }
        }
        result = ConfigValidator.validate(bad_config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("must be a string" in e.message for e in result.errors))

    def test_ignore_readback_paths_parent_container_collision(self):
        # field_map modifies "user.profile.role"
        # ignore_readback_paths ignores "user.profile" (parent container) -> dangerous collision!
        bad_config = {
            "readbacks": {
                "PATCH /api/users/{id}": {
                    "method": "GET",
                    "path": "/api/users/{id}",
                    "field_map": {"user.profile.role": "role"},
                    "ignore_readback_paths": ["user.profile"],
                }
            }
        }
        result = ConfigValidator.validate(bad_config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("collides with written field" in e.message for e in result.errors))

    def test_readback_method_must_be_uppercase_get(self):
        bad_config = {
            "readbacks": {
                "PATCH /api/users/{id}": {
                    "method": "get",  # lowercase
                    "path": "/api/users/{id}",
                    "field_map": {"role": "role"},
                }
            }
        }
        result = ConfigValidator.validate(bad_config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("uppercase 'GET'" in e.message for e in result.errors))


class VersionConsistencyTests(unittest.TestCase):
    """Ensure version 2.3.1-final is consistently declared across project components."""

    def test_version_cli_flag(self):
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["--version"])
            self.assertEqual(ctx.exception.code, 0)
        self.assertIn("2.3.1-final", stdout_buf.getvalue())

    def test_core_package_version(self):
        import core
        self.assertEqual(core.__version__, "2.3.1-final")


if __name__ == "__main__":
    unittest.main()
