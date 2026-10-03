# -*- coding: utf-8 -*-
"""Comprehensive regression test suite for GrantTrace configuration validation."""

from __future__ import annotations

import io
import json
import socket
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.config_validator import ConfigValidator


ROOT = Path(__file__).resolve().parents[1]


class ConfigValidatorTests(unittest.TestCase):
    def test_full_production_config_is_valid(self):
        with (ROOT / "config.example.json").open("r", encoding="utf-8") as handle:
            config = json.load(handle)
        result = ConfigValidator.validate(config)
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.summary.identities_count, 3)
        self.assertEqual(result.summary.allowlisted_endpoints, 2)
        self.assertEqual(result.summary.readbacks_count, 2)

    def test_example_config_is_valid(self):
        with (ROOT / "config.example.json").open("r", encoding="utf-8") as handle:
            config = json.load(handle)
        result = ConfigValidator.validate(config)
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.summary.identities_count, 3)

    def test_minimal_empty_config_is_valid(self):
        result = ConfigValidator.validate({})
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)

    def test_non_dict_root_fails(self):
        result = ConfigValidator.validate(["not", "an", "object"])
        self.assertFalse(result.is_valid)
        self.assertTrue(any("JSON object" in e.message for e in result.errors))

    def test_unknown_top_level_typo_suggests_correction(self):
        config = {"read_backs": {}, "identity": {}}
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        paths = {e.path: e for e in result.errors}
        self.assertIn("read_backs", paths)
        self.assertIn("Did you mean 'readbacks'?", paths["read_backs"].suggestion or "")
        self.assertIn("identity", paths)
        self.assertIn("Did you mean 'identities'?", paths["identity"].suggestion or "")

    def test_wrong_field_types(self):
        config = {
            "write_allowlist": "not-a-list",
            "parameter_values": ["not-a-dict"],
            "readbacks": "not-a-dict",
            "bola": "not-a-dict",
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertGreaterEqual(len(result.errors), 4)

    def test_identities_missing_required_roles(self):
        config = {
            "identities": {
                "owner": {"token": "Bearer 1"},
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Missing required identity roles" in e.message for e in result.errors))

    def test_identities_crlf_injection_detected(self):
        config = {
            "identities": {
                "owner": {"token": "Bearer 1\r\nX-Injected: evil"},
                "visitor": {"token": "Bearer 2"},
                "anonymous": {},
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("line breaks" in e.message for e in result.errors))

    def test_anonymous_with_credentials_rejected(self):
        config = {
            "identities": {
                "owner": {"token": "Bearer 1"},
                "visitor": {"token": "Bearer 2"},
                "anonymous": {"token": "Bearer anon_should_not_exist"},
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Anonymous identity must not define" in e.message for e in result.errors))

    def test_identical_owner_and_visitor_credentials_rejected(self):
        config = {
            "identities": {
                "owner": {"token": "Bearer SAME_TOKEN"},
                "visitor": {"token": "Bearer SAME_TOKEN"},
                "anonymous": {},
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("distinct effective authentication" in e.message for e in result.errors))

    def test_write_allowlist_invalid_entries(self):
        config = {
            "write_allowlist": [
                "POST /api/users",
                "PATCH relative/path/without/slash",
                123,
            ]
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertEqual(len(result.errors), 3)

    def test_readbacks_missing_required_fields(self):
        config = {
            "readbacks": {
                "PATCH /api/resource": {
                    "method": "POST",  # must be GET
                    # path missing
                    # field_map missing
                }
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        error_paths = [e.path for e in result.errors]
        self.assertIn("readbacks.PATCH /api/resource.method", error_paths)
        self.assertIn("readbacks.PATCH /api/resource.path", error_paths)
        self.assertIn("readbacks.PATCH /api/resource.field_map", error_paths)

    def test_readbacks_empty_field_map_rejected(self):
        config = {
            "readbacks": {
                "PATCH /api/resource": {
                    "method": "GET",
                    "path": "/api/resource",
                    "field_map": {},
                }
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("non-empty" in e.message for e in result.errors))

    def test_consistency_typo_suggests_enum(self):
        config = {
            "readbacks": {
                "PATCH /api/resource": {
                    "method": "GET",
                    "path": "/api/resource",
                    "field_map": {"role": "role"},
                    "consistency": "Strong",
                }
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        issue = next(e for e in result.errors if "consistency" in e.path)
        self.assertIn("did you mean 'strong'?", (issue.suggestion or "").lower())

    def test_readback_ignore_path_collides_with_field_map(self):
        config = {
            "readbacks": {
                "PATCH /api/resource": {
                    "method": "GET",
                    "path": "/api/resource",
                    "field_map": {"role": "role"},
                    "ignore_readback_paths": ["role"],  # Collides with written field!
                }
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("collides with written field" in e.message for e in result.errors))

    def test_write_allowlist_missing_readback_cross_check(self):
        config = {
            "write_allowlist": ["PATCH /api/users/{id}/role"],
            "readbacks": {
                "PATCH /api/other": {
                    "method": "GET",
                    "path": "/api/other",
                    "field_map": {"a": "b"},
                }
            },
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("in write_allowlist but missing an independent GET readback" in e.message for e in result.errors))

    def test_bola_configuration_errors(self):
        config = {
            "bola": {
                "GET /api/records/{id}": {
                    "expected_public": "not-a-boolean",
                    "resource_id_paths": "not-a-list",
                    "unknown_bola_key": True,
                }
            }
        }
        result = ConfigValidator.validate(config)
        self.assertFalse(result.is_valid)
        error_paths = [e.path for e in result.errors]
        self.assertIn("bola.GET /api/records/{id}.expected_public", error_paths)
        self.assertIn("bola.GET /api/records/{id}.resource_id_paths", error_paths)
        self.assertIn("bola.GET /api/records/{id}.unknown_bola_key", error_paths)


class ValidateConfigCLITests(unittest.TestCase):
    def test_validate_config_cli_success(self):
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            code = main(["--validate-config", "--config", str(ROOT / "config.example.json")])
        self.assertEqual(code, 0)
        self.assertIn("[OK] Configuration is valid", stdout_buf.getvalue())
        self.assertEqual(stderr_buf.getvalue().strip(), "")

    def test_validate_config_cli_failure_on_corrupt_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as temp:
            temp.write("{ invalid json syntax ...")
            temp_path = temp.name

        try:
            stderr_buf = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr_buf):
                code = main(["--validate-config", "--config", temp_path])
            self.assertEqual(code, 2)
            self.assertIn("[ERROR] Failed to parse JSON configuration", stderr_buf.getvalue())
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_validate_config_cli_failure_on_invalid_semantics(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as temp:
            json.dump({"read_backs": {}}, temp)
            temp_path = temp.name

        try:
            stderr_buf = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr_buf):
                code = main(["--validate-config", "--config", temp_path])
            self.assertEqual(code, 2)
            output = stderr_buf.getvalue()
            self.assertIn("[ERROR] Configuration validation failed", output)
            self.assertIn("read_backs", output)
            self.assertIn("Did you mean 'readbacks'?", output)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_validate_config_cli_non_existent_file(self):
        stderr_buf = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr_buf):
            code = main(["--validate-config", "--config", "non_existent_config_file_12345.json"])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", stderr_buf.getvalue())

    def test_validate_config_is_strictly_offline(self):
        """Verify that running --validate-config never touches the network or opens a socket."""
        with patch("urllib.request.urlopen", side_effect=AssertionError("Network accessed via urlopen!")), \
             patch("socket.socket", side_effect=AssertionError("Network accessed via socket!")):
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                code = main(["--validate-config", "--config", str(ROOT / "config.example.json")])
            self.assertEqual(code, 0)
            self.assertIn("[OK] Configuration is valid", stdout_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
