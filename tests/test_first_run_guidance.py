"""First-run suggestions stay offline and preserve the existing safety gates."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.config_scaffold import build_config_scaffold


class FirstRunGuidanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.spec = self.folder / "api.json"
        self.config = self.folder / "config.local.json"
        self.spec.write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {
                "/items/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                    "schema": {"type": "integer"}}],
                    "get": {"responses": {}},
                    "patch": {
                        "requestBody": {"content": {"application/json": {"schema": {
                            "type": "object", "properties": {"role": {"type": "string"}}
                        }}}},
                        "responses": {},
                    },
                }
            },
        }), encoding="utf-8")
        self.config.write_text("{}", encoding="utf-8")

    def call_cli(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("socket.socket", side_effect=AssertionError("Network socket opened")), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network request sent")), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def selected_args(self, mode):
        return [*mode, "--spec", str(self.spec), "--config", str(self.config)]

    def test_missing_spec_offers_demo_and_offline_draft_without_creating_files(self):
        missing = self.folder / "missing.json"
        before = set(self.folder.iterdir())
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
            for mode in ([], ["--dry-run"], ["--validate-config"]):
                with self.subTest(mode=mode):
                    code, _, error = self.call_cli([*mode, "--spec", str(missing),
                                                    "--config", str(self.config)])
                    self.assertEqual(code, 2)
                    self.assertIn("Cannot load specification", error)
                    self.assertIn("granttrace demo", error)
                    self.assertIn("--init-config config.local.json", error)
        self.assertEqual(set(self.folder.iterdir()), before)

    def test_missing_config_suggestions_are_the_same_for_scan_and_validation(self):
        self.config.unlink()
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
            for mode in ([], ["--dry-run"], ["--validate-config"]):
                with self.subTest(mode=mode):
                    code, _, error = self.call_cli(self.selected_args(mode))
                    self.assertEqual(code, 2)
                    self.assertIn("configuration file does not exist", error.lower())
                    self.assertIn("granttrace demo", error)
                    self.assertIn("--init-config config.local.json", error)
        self.assertFalse(self.config.exists())

    def test_missing_file_path_credentials_are_redacted_in_all_modes(self):
        missing = str(self.folder / "missing-Bearer FIRST_RUN_PRIVATE_VALUE.json")
        for option in ("--config", "--spec"):
            for mode in ([], ["--dry-run"], ["--validate-config"]):
                with self.subTest(option=option, mode=mode):
                    arguments = self.selected_args(mode)
                    arguments[arguments.index(option) + 1] = missing
                    code, output, error = self.call_cli(arguments)
                    self.assertEqual(code, 2)
                    self.assertNotIn("FIRST_RUN_PRIVATE_VALUE", output + error)
                    self.assertIn("[REDACTED]", error)
                    self.assertIn("granttrace demo", error)

    def test_malformed_files_remain_parse_errors_without_missing_file_suggestions(self):
        for selected in (self.spec, self.config):
            with self.subTest(selected=selected.name):
                original = selected.read_text(encoding="utf-8")
                selected.write_text("{ malformed", encoding="utf-8")
                try:
                    for mode in (["--validate-config"], ["--dry-run"]):
                        code, _, error = self.call_cli(self.selected_args(mode))
                        self.assertEqual(code, 2)
                        self.assertNotIn("granttrace demo", error)
                finally:
                    selected.write_text(original, encoding="utf-8")

    def test_unfinished_draft_still_requires_review_without_network_or_scanner(self):
        draft, _ = build_config_scaffold(str(self.spec))
        self.config.write_text(json.dumps(draft), encoding="utf-8")
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
            for mode in ([], ["--dry-run"], ["--validate-config"]):
                code, _, error = self.call_cli(self.selected_args(mode))
                self.assertEqual(code, 2)
                self.assertIn("draft needs user input", error)
                self.assertIn("companion checklist", error)
                self.assertIn("No requests were sent", error)

    def test_missing_readback_keeps_independent_get_gate_and_offers_offline_review(self):
        self.config.write_text(json.dumps({"write_allowlist": ["PATCH /items/{id}"]}), encoding="utf-8")
        with patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor created")):
            for mode in ([], ["--validate-config"], ["--dry-run", "--allow-write-tests"]):
                code, _, error = self.call_cli(self.selected_args(mode))
                self.assertEqual(code, 2)
                self.assertIn("missing an independent GET readback", error)
                self.assertIn("Define readback mapping", error)
                self.assertIn("field_map", error)
                self.assertIn("--validate-config, then --dry-run", error)

    def test_invalid_identity_id_hint_does_not_echo_credentials_or_guess_ownership(self):
        self.config.write_text(json.dumps({"identities": {
            "owner": {"id": {}, "token": "Bearer OWNER_FIRST_RUN_PRIVATE_VALUE"},
            "visitor": {"id": 2, "token": "Bearer VISITOR_FIRST_RUN_PRIVATE_VALUE"},
            "anonymous": {},
        }}), encoding="utf-8")
        for mode in ([], ["--validate-config"], ["--dry-run"]):
            code, output, error = self.call_cli(self.selected_args(mode))
            self.assertEqual(code, 2)
            self.assertIn("Identity id must be", error)
            self.assertIn("resource IDs in parameter_values", error)
            self.assertIn("business rules", error)
            self.assertNotIn("FIRST_RUN_PRIVATE_VALUE", output + error)

    def test_requested_writes_with_empty_allowlist_remain_disabled_in_offline_plan(self):
        original = self.config.read_bytes()
        code, output, error = self.call_cli(self.selected_args(["--dry-run", "--allow-write-tests"]))
        self.assertEqual(code, 0, error)
        self.assertIn("write_allowlist is empty; no PATCH requests will be sent", error)
        self.assertIn("independent GET readbacks", error)
        plan = json.loads(output[output.index("{"):])
        patch_operation = next(operation for operation in plan["operations"] if operation["check"] == "MASS_ASSIGNMENT")
        self.assertFalse(patch_operation["writes_enabled"])
        self.assertEqual(plan["requests_sent"], 0)
        self.assertEqual(self.config.read_bytes(), original)

    def test_original_cli_read_only_plan_remains_compatible_without_write_warning(self):
        code, output, error = self.call_cli(self.selected_args(["--dry-run"]))
        self.assertEqual(code, 0, error)
        self.assertIn('"requests_sent": 0', output)
        self.assertIn('"writes_enabled": false', output)
        self.assertNotIn("write_allowlist is empty", error)


if __name__ == "__main__":
    unittest.main()
