"""Onboarding guidance preserves offline execution, privacy, and read-only defaults."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.config_scaffold import DRAFT_KEY, INPUT_PREFIX, build_config_scaffold
from core.config_validator import ConfigIssue, ConfigValidator
from core.parser import OpenAPIParser


class OnboardingCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.spec = self.folder / "API contract 中文.json"
        self.config = self.folder / "config local.json"
        self.plan_file = self.folder / "plan local.json"
        self.spec_data = {
            "openapi": "3.0.3",
            "paths": {
                "/items/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                    "schema": {"type": "string", "example": "SPEC_PRIVATE_RESOURCE"}}],
                    "get": {"responses": {}},
                    "patch": {
                        "requestBody": {"content": {"application/json": {"schema": {
                            "type": "object", "properties": {
                                "role": {"type": "string", "example": "SPEC_PRIVATE_ROLE"}
                            },
                        }}}},
                        "responses": {},
                    },
                    "delete": {"responses": {}},
                },
                "/status": {"get": {"responses": {}}},
            },
        }
        self.secret_values = (
            "OWNER_OPAQUE_TOKEN", "VISITOR_OPAQUE_TOKEN", "OWNER_PRIVATE_COOKIE",
            "VISITOR_PRIVATE_COOKIE", "OWNER_PRIVATE_API_KEY", "VISITOR_PRIVATE_API_KEY",
            "OWNER_CUSTOM_CREDENTIAL", "VISITOR_CUSTOM_CREDENTIAL",
            "OWNER_PRIVATE_RESOURCE_ID", "VISITOR_PRIVATE_RESOURCE_ID", "PRIVATE_BASELINE_PAYLOAD",
        )
        self.config_data = {
            "identities": {
                "owner": {
                    "id": "OWNER_IDENTITY_IDENTIFIER", "token": "Bearer OWNER_OPAQUE_TOKEN",
                    "headers": {
                        "Cookie": "session=OWNER_PRIVATE_COOKIE", "X-API-Key": "OWNER_PRIVATE_API_KEY",
                        "X-Custom-Access": "OWNER_CUSTOM_CREDENTIAL",
                    },
                    "auth_header_names": ["X-Custom-Access"],
                },
                "visitor": {
                    "id": "VISITOR_IDENTITY_IDENTIFIER", "token": "Basic VISITOR_OPAQUE_TOKEN",
                    "headers": {
                        "Cookie": "session=VISITOR_PRIVATE_COOKIE", "X-API-Key": "VISITOR_PRIVATE_API_KEY",
                        "X-Custom-Access": "VISITOR_CUSTOM_CREDENTIAL",
                    },
                    "auth_header_names": ["X-Custom-Access"],
                },
                "anonymous": {},
            },
            "parameter_values": {
                "GET /items/{id}": {
                    "owner": {"id": "OWNER_PRIVATE_RESOURCE_ID"},
                    "visitor": {"id": "VISITOR_PRIVATE_RESOURCE_ID"},
                },
                "PATCH /items/{id}": {
                    "owner": {"id": "OWNER_PRIVATE_RESOURCE_ID"},
                    "visitor": {"id": "VISITOR_PRIVATE_RESOURCE_ID"},
                },
            },
            "write_allowlist": [],
            "readbacks": {},
            "bola": {"GET /items/{id}": {"expected_visitor_access": "deny", "resource_id_paths": ["id"]}},
        }
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")
        self.save_config()

    def save_config(self):
        self.config.write_text(json.dumps(self.config_data), encoding="utf-8")

    def enable_write_config(self):
        self.config_data["write_allowlist"] = ["PATCH /items/{id}"]
        self.config_data["readbacks"] = {"PATCH /items/{id}": {
            "method": "GET", "path": "/items/{id}", "consistency": "strong",
            "field_map": {"role": "role"}, "baseline_payload": {"role": "PRIVATE_BASELINE_PAYLOAD"},
        }}
        self.save_config()

    @contextmanager
    def isolated_directory(self):
        previous = Path.cwd()
        os.chdir(self.folder)
        try:
            yield
        finally:
            os.chdir(previous)

    def call_cli(self, arguments, *, prohibit_auditor=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(self.isolated_directory())
            for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo",
                           "urllib.request.urlopen", "urllib.request.OpenerDirector.open",
                           "core.auditor.APISentinelAuditor._http_request"):
                stack.enter_context(patch(target, side_effect=AssertionError("Network activity in offline mode")))
            if prohibit_auditor:
                stack.enter_context(patch("api_sentinel.APISentinelAuditor",
                                          side_effect=AssertionError("Auditor constructed in offline config mode")))
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def selected_args(self, *mode):
        return [*mode, "--spec", str(self.spec), "--config", str(self.config)]

    def assert_private(self, text):
        for value in self.secret_values:
            self.assertNotIn(value, text)

    def assert_read_only_next_scan(self, text):
        commands = [line for line in text.splitlines() if "granttrace" in line and "--target" in line]
        self.assertTrue(commands, text)
        for command in commands:
            self.assertIn("<AUTHORIZED_TARGET_URL>", command)
            self.assertIn("--spec", command)
            self.assertIn("--export-json", command)
            self.assertNotIn("--allow-write-tests", command)
            self.assertNotIn("--write-endpoint", command)

    def parse_plan(self, stdout):
        return json.loads(stdout[stdout.index("{"):])

    def test_init_creates_unchanged_draft_and_checklist_without_auditor_or_network(self):
        destination = self.folder / "draft local.json"
        expected_draft, expected_checklist = build_config_scaffold(str(self.spec))
        code, stdout, stderr = self.call_cli(
            ["--spec", str(self.spec), "--init-config", str(destination)], prohibit_auditor=True
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn(str(destination), stdout)
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), expected_draft)
        checklist = destination.with_suffix(".checklist.json")
        self.assertEqual(json.loads(checklist.read_text(encoding="utf-8")), expected_checklist)
        self.assertIn(str(checklist), stdout)

    def test_init_keeps_draft_marker_placeholders_and_empty_write_allowlist(self):
        destination = self.folder / "draft.json"
        code, _, stderr = self.call_cli(
            ["--spec", str(self.spec), "--init-config", str(destination)], prohibit_auditor=True
        )
        self.assertEqual(code, 0, stderr)
        draft = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(draft[DRAFT_KEY]["status"], "needs_user_input")
        self.assertEqual(draft["write_allowlist"], [])
        self.assertIn(INPUT_PREFIX, json.dumps(draft))
        self.assertFalse(ConfigValidator.validate(draft, self.spec_data).is_valid)

    def test_init_next_steps_require_manual_review_then_validation_then_dry_run(self):
        destination = self.folder / "draft.json"
        code, stdout, stderr = self.call_cli(
            ["--spec", str(self.spec), "--init-config", str(destination)], prohibit_auditor=True
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("--validate-config", stderr)
        self.assertIn("--dry-run", stderr)
        self.assertLess(stderr.index("--validate-config"), stderr.index("--dry-run"))
        self.assertIn(INPUT_PREFIX, stdout + stderr)
        self.assertIn(DRAFT_KEY, stdout + stderr)
        self.assertIn("write_allowlist is empty", (stdout + stderr))
        self.assertIn("PATCH", stdout + stderr)
        self.assertNotIn("--allow-write-tests", stderr)
        self.assertNotIn("--target", stderr)

    def test_init_never_copies_spec_example_resource_or_payload_into_output(self):
        destination = self.folder / "draft.json"
        code, stdout, stderr = self.call_cli(
            ["--spec", str(self.spec), "--init-config", str(destination)], prohibit_auditor=True
        )
        self.assertEqual(code, 0, stderr)
        for sentinel in ("SPEC_PRIVATE_RESOURCE", "SPEC_PRIVATE_ROLE"):
            self.assertNotIn(sentinel, stdout + stderr + destination.read_text(encoding="utf-8"))

    def test_init_existing_config_or_checklist_is_not_overwritten(self):
        destination = self.folder / "draft.json"
        checklist = destination.with_suffix(".checklist.json")
        for existing in (destination, checklist):
            with self.subTest(existing=existing.name):
                existing.write_text("original bytes", encoding="utf-8")
                code, _, stderr = self.call_cli(
                    ["--spec", str(self.spec), "--init-config", str(destination)], prohibit_auditor=True
                )
                self.assertEqual(code, 2)
                self.assertIn("Refusing to overwrite", stderr)
                self.assertEqual(existing.read_text(encoding="utf-8"), "original bytes")
                self.assertFalse((checklist if existing == destination else destination).exists())
                existing.unlink()

    def test_init_control_paths_cannot_forge_output_or_executable_next_commands(self):
        hostile = "draft\r\n[OK] FORGED\t\x00\x1f\x7f.json"
        with patch("api_sentinel.write_config_scaffold", return_value=(Path(hostile), Path(hostile + ".checklist"))):
            code, stdout, stderr = self.call_cli(
                ["--spec", "API\n[NEXT] FORGED.json", "--init-config", hostile], prohibit_auditor=True
            )
        self.assertEqual(code, 0)
        self.assert_no_path_injection(stdout + stderr)
        self.assertIn("<PATH_WITH_CONTROL_CHARACTERS>", stderr)

    def assert_no_path_injection(self, output):
        self.assertNotIn("\n[OK] FORGED", output)
        self.assertNotIn("\n[NEXT] FORGED", output)
        for character in "\r\t\x00\x1f\x7f":
            self.assertNotIn(character, output)

    def test_config_only_scope_is_explicit_and_keeps_validation_offline(self):
        code, stdout, stderr = self.call_cli(
            ["--config", str(self.config), "--validate-config"], prohibit_auditor=True
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("Configuration is valid", stdout)
        text = stderr.lower()
        self.assertIn("configuration-only", text)
        self.assertIn("no openapi specification", text)
        self.assertIn("not performed", text)
        self.assertIn("--spec", stderr)

    def test_spec_aware_scope_is_explicit_and_keeps_validation_offline(self):
        code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 0, stderr)
        self.assertIn("Configuration is valid", stdout)
        self.assertIn("OpenAPI", stderr)
        self.assertIn("checked together", stderr)
        self.assertNotIn("Configuration-only validation passed", stderr)

    def test_default_openapi_file_still_gets_spec_cross_checks(self):
        default_spec = self.folder / "openapi.json"
        default_spec.write_text(json.dumps(self.spec_data), encoding="utf-8")
        code, _, stderr = self.call_cli(
            ["--config", str(self.config), "--validate-config"], prohibit_auditor=True
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("checked together", stderr)
        self.assertNotIn("Configuration-only", stderr)
        self.assertIn("openapi.json", stderr)

    def test_validation_preserves_existing_five_summary_counts(self):
        self.enable_write_config()
        code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 0, stderr)
        for label, count in (("Identities", 3), ("Write allowlist", 1), ("Readbacks", 1),
                             ("Parameter values", 2), ("BOLA policies", 1)):
            with self.subTest(label=label):
                self.assertRegex(stdout, label + r":\s+" + str(count) + r"\b")

    def test_no_allowlist_validation_identifies_read_only_first_run(self):
        code, _, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 0, stderr)
        self.assertIn("read-only", stderr.lower())
        self.assertIn("No PATCH operation is allowlisted", stderr)
        self.assert_read_only_next_scan(stderr)

    def test_allowlisted_validation_marks_patch_configuration_inactive(self):
        self.enable_write_config()
        code, _, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 0, stderr)
        self.assertIn("Allowlisted PATCH operations: 1", stderr)
        self.assertIn("readback mappings: 1", stderr.lower())
        self.assertIn("inactive", stderr.lower())
        self.assertIn("--allow-write-tests", stderr)
        self.assert_read_only_next_scan(stderr)

    def test_successful_validation_recommends_local_plan_with_actual_selected_paths(self):
        code, _, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 0, stderr)
        commands = [line for line in stderr.splitlines() if "granttrace" in line and "--dry-run" in line]
        self.assertEqual(len(commands), 1, stderr)
        self.assertIn(str(self.spec), commands[0])
        self.assertIn(str(self.config), commands[0])
        self.assertIn("--export-json", commands[0])
        self.assertNotIn("--allow-write-tests", commands[0])

    def test_validation_always_explains_structure_and_business_policy_limits(self):
        for allow_write in (False, True):
            with self.subTest(allow_write=allow_write):
                if allow_write:
                    self.enable_write_config()
                code, _, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
                self.assertEqual(code, 0, stderr)
                for concept in ("structure", "ownership", "authorization", "permission", "consistency", "rollback"):
                    self.assertIn(concept, stderr.lower())
                for unsafe_claim in ("configuration is safe", "safe to scan", "readback is reliable"):
                    self.assertNotIn(unsafe_claim, stderr.lower())

    def test_validation_output_contains_no_credentials_resources_or_baseline_values(self):
        self.enable_write_config()
        original = self.config.read_bytes()
        code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 0, stderr)
        self.assert_private(stdout + stderr)
        self.assertEqual(self.config.read_bytes(), original)

    def test_secret_and_resource_values_inside_config_filenames_are_redacted(self):
        self.enable_write_config()
        for value in self.secret_values:
            with self.subTest(value=value):
                self.config = self.folder / (value + ".json")
                self.save_config()
                for mode in ("--validate-config", "--dry-run"):
                    with self.subTest(mode=mode):
                        code, stdout, stderr = self.call_cli(
                            self.selected_args(mode), prohibit_auditor=mode == "--validate-config"
                        )
                        self.assertEqual(code, 0, stderr)
                        self.assert_private(stdout + stderr)
                        self.assertIn("<PATH_REQUIRING_MANUAL_INPUT>", stderr)

    def test_secret_resource_value_inside_spec_filename_is_redacted(self):
        self.spec = self.folder / "OWNER_PRIVATE_RESOURCE_ID.json"
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")
        for mode in ("--validate-config", "--dry-run"):
            with self.subTest(mode=mode):
                code, stdout, stderr = self.call_cli(
                    self.selected_args(mode), prohibit_auditor=mode == "--validate-config"
                )
                self.assertEqual(code, 0, stderr)
                self.assert_private(stdout + stderr)
                self.assertIn("<PATH_REQUIRING_MANUAL_INPUT>", stderr)

    def test_secret_resource_value_inside_missing_spec_filename_is_redacted(self):
        self.spec = self.folder / "missing-OWNER_PRIVATE_RESOURCE_ID.json"
        code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 2)
        self.assert_private(stdout + stderr)
        self.assertIn("<PATH_REQUIRING_MANUAL_INPUT>", stderr)
        self.assertNotIn("--target", stderr)

    def test_warning_details_are_preserved_without_changing_success_exit_code(self):
        result = ConfigValidator.validate(self.config_data, self.spec_data)
        result.issues.append(ConfigIssue("bola", "Review the supplied policy", "manual review", "configured",
                                         "Verify expectations", is_warning=True))
        result.summary.warnings_count = 1
        result.summary.total_issues += 1
        with patch("api_sentinel.ConfigValidator.validate", return_value=result):
            code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 0, stderr)
        self.assertIn("Review the supplied policy", stdout + stderr)
        self.assertIn("passed with 1 warning(s)", stderr)
        self.assert_read_only_next_scan(stderr)

    def test_validation_failure_retains_full_issue_details_then_error_warning_counts(self):
        self.config_data["read_backs"] = {}
        self.save_config()
        result = ConfigValidator.validate(self.config_data, self.spec_data)
        result.issues.append(ConfigIssue("bola", "Review the supplied policy", "manual review", "configured",
                                         "Verify expectations", is_warning=True))
        result.summary.warnings_count = 1
        result.summary.total_issues += 1
        with patch("api_sentinel.ConfigValidator.validate", return_value=result):
            code, _, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 2)
        for label in ("Path:", "Reason:", "Expected:", "Actual:", "Tip:"):
            self.assertIn(label, stderr)
        self.assertIn("Did you mean 'readbacks'?", stderr)
        self.assertIn("[SUMMARY] 1 error(s), 1 warning(s)", stderr)
        self.assertGreater(stderr.index("[SUMMARY]"), stderr.index("Review the supplied policy"))
        self.assert_private(stderr)

    def test_validation_failure_recommends_fix_and_validation_without_scan_or_plan(self):
        self.config_data["write_allowlist"] = ["PATCH /items/{id}"]
        self.save_config()
        code, _, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 2)
        self.assertIn("missing an independent GET readback", stderr)
        commands = [line for line in stderr.splitlines() if "granttrace" in line]
        self.assertTrue(commands, stderr)
        self.assertTrue(all("--validate-config" in line for line in commands))
        self.assertNotIn("--target", stderr)
        self.assertNotIn("--dry-run", "\n".join(commands))

    def test_config_only_failure_recommends_explicit_openapi_selection(self):
        self.config_data["read_backs"] = {}
        self.save_config()
        code, _, stderr = self.call_cli(
            ["--config", str(self.config), "--validate-config"], prohibit_auditor=True
        )
        self.assertEqual(code, 2)
        self.assertIn("<OPENAPI_FILE>", stderr)
        self.assertIn("--validate-config", stderr)
        self.assertNotIn("--target", stderr)

    def test_malformed_sensitive_values_never_leak_through_detailed_validation_errors(self):
        self.config_data["identities"]["owner"]["headers"]["X-API-Key"] = {"password": "OWNER_PRIVATE_API_KEY"}
        self.config_data["parameter_values"]["GET /items/{id}"] = "OWNER_PRIVATE_RESOURCE_ID"
        self.save_config()
        code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 2)
        self.assertIn("Header value", stderr)
        self.assertIn("Actual:", stderr)
        self.assert_private(stdout + stderr)

    def test_malformed_readback_sections_do_not_echo_private_strings(self):
        for malformed in (
            {"readbacks": ["READBACK_PRIVATE_CREDENTIAL"]},
            {"readbacks": {"PATCH /items/{id}": ["READBACK_PRIVATE_CREDENTIAL"]}},
        ):
            with self.subTest(malformed=malformed):
                self.config.write_text(json.dumps(malformed), encoding="utf-8")
                code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
                self.assertEqual(code, 2)
                self.assertNotIn("READBACK_PRIVATE_CREDENTIAL", stdout + stderr)
                self.assertIn("Actual:", stderr)

    def test_malformed_root_does_not_echo_private_strings(self):
        for malformed in ("ROOT_PRIVATE_CREDENTIAL", ["ROOT_PRIVATE_CREDENTIAL"]):
            with self.subTest(malformed=malformed):
                self.config.write_text(json.dumps(malformed), encoding="utf-8")
                code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
                self.assertEqual(code, 2)
                self.assertNotIn("ROOT_PRIVATE_CREDENTIAL", stdout + stderr)
                self.assertIn("Configuration validation failed", stderr)

    def test_truncated_malformed_private_values_do_not_leak_credential_prefixes(self):
        prefix = "LONG_PRIVATE_CREDENTIAL_PREFIX_"
        value = prefix + "x" * 180
        for section in ("token", "parameter_values"):
            with self.subTest(section=section):
                malformed = json.loads(json.dumps(self.config_data))
                if section == "token":
                    malformed["identities"]["owner"]["token"] = [value]
                else:
                    malformed["parameter_values"]["GET /items/{id}"] = [value]
                self.config.write_text(json.dumps(malformed), encoding="utf-8")
                code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
                self.assertEqual(code, 2)
                self.assertNotIn(value, stdout + stderr)
                self.assertNotIn(prefix, stdout + stderr)
                self.assertIn("Actual:", stderr)

    def test_short_private_identity_ids_preserve_issue_detail_labels(self):
        self.config_data["identities"]["owner"]["id"] = "a"
        self.config_data["identities"]["visitor"]["id"] = "b"
        self.config_data["identities"]["owner"]["token"] = ["SHORT_ID_PRIVATE_CREDENTIAL"]
        self.config_data["read_backs"] = {}
        self.save_config()
        code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 2)
        for label in ("Path:", "Reason:", "Expected:", "Actual:", "Tip:"):
            with self.subTest(label=label):
                self.assertIn(label, stderr)
        self.assertNotIn("SHORT_ID_PRIVATE_CREDENTIAL", stdout + stderr)
        self.assert_private(stdout + stderr)

    def test_unicode_line_separators_in_error_paths_cannot_forge_log_lines(self):
        for separator in ("\u2028", "\u2029", "\x85"):
            with self.subTest(separator=ord(separator)):
                malformed = {**self.config_data, "bad" + separator + "[OK] FORGED": {}}
                self.config.write_text(json.dumps(malformed), encoding="utf-8")
                code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
                self.assertEqual(code, 2)
                self.assertNotIn("\n[OK] FORGED", stdout + stderr)
                self.assertNotIn(separator, stdout + stderr)

    def test_unicode_line_separators_in_warning_details_cannot_forge_log_lines(self):
        result = ConfigValidator.validate(self.config_data, self.spec_data)
        result.issues.append(ConfigIssue("bola", "Review\u2028[OK] FORGED", "manual review", "configured",
                                         "Verify\u2029[NEXT] FORGED", is_warning=True))
        result.summary.warnings_count = 1
        result.summary.total_issues += 1
        with patch("api_sentinel.ConfigValidator.validate", return_value=result):
            code, stdout, stderr = self.call_cli(self.selected_args("--validate-config"), prohibit_auditor=True)
        self.assertEqual(code, 0, stderr)
        for forged in ("\n[OK] FORGED", "\n[NEXT] FORGED", "\u2028", "\u2029"):
            self.assertNotIn(forged, stdout + stderr)

    def test_validation_control_paths_cannot_forge_logs_or_next_commands(self):
        hostile = "config\r\n[OK] FORGED\t\x00\x1f\x7f.json"
        with patch("api_sentinel.Path") as path_class, patch("api_sentinel._load_spec", return_value=self.spec_data), \
             patch("core.config_validator.OpenAPIParser", return_value=OpenAPIParser(str(self.spec))):
            path_class.return_value.is_file.return_value = True
            path_class.return_value.open.return_value = io.StringIO(json.dumps(self.config_data))
            code, stdout, stderr = self.call_cli(
                ["--config", hostile, "--spec", "API\n[NEXT] FORGED.json", "--validate-config"],
                prohibit_auditor=True,
            )
        self.assertEqual(code, 0, stderr)
        self.assert_no_path_injection(stdout + stderr)
        self.assertIn("<PATH_WITH_CONTROL_CHARACTERS>", stderr)

    def test_dry_run_retains_exact_local_plan_shape_and_zero_requests(self):
        expected = APISentinelAuditor(
            str(self.spec), "http://127.0.0.1:8080", identities_config=self.config_data["identities"],
            parameter_values=self.config_data["parameter_values"], bola_config=self.config_data["bola"],
        ).build_plan()
        code, stdout, stderr = self.call_cli(self.selected_args("--dry-run"))
        self.assertEqual(code, 0, stderr)
        actual = self.parse_plan(stdout)
        self.assertEqual(actual, expected)
        self.assertEqual(set(actual), {"mode", "requests_sent", "note", "target", "operations"})
        self.assertEqual(actual["requests_sent"], 0)
        self.assertEqual(actual["mode"], "DRY_RUN")

    def test_dry_run_missing_spec_escapes_unicode_log_separators_before_auditor_creation(self):
        for separator in ("\u2028", "\u2029", "\x85"):
            with self.subTest(separator=ord(separator)):
                missing = self.folder / ("missing" + separator + "[OK] FORGED.json")
                code, stdout, stderr = self.call_cli(
                    ["--spec", str(missing), "--config", str(self.config), "--dry-run"], prohibit_auditor=True
                )
                self.assertEqual(code, 2)
                self.assertIn("Cannot load specification", stderr)
                self.assertNotIn(separator, stdout + stderr)
                self.assertNotIn("\n[OK] FORGED", stdout + stderr)
                self.assert_private(stdout + stderr)

    def test_dry_run_export_contains_only_unchanged_json_and_no_human_guidance(self):
        code, stdout, stderr = self.call_cli(
            self.selected_args("--dry-run", "--export-json", str(self.plan_file))
        )
        self.assertEqual(code, 0, stderr)
        exported = self.plan_file.read_text(encoding="utf-8")
        self.assertEqual(json.loads(exported), self.parse_plan(stdout))
        self.assertNotIn("[NEXT]", exported)
        self.assertNotIn("[PLAN]", exported)
        self.assertNotIn("[CAUTION]", exported)

    def test_dry_run_human_summary_is_on_stderr_with_correct_operation_counts(self):
        code, stdout, stderr = self.call_cli(self.selected_args("--dry-run"))
        self.assertEqual(code, 0, stderr)
        for text in ("Requests sent: 0", "Operations: 4", "BOLA checks: 2", "Mass Assignment checks: 1",
                     "Write-enabled operations in this plan: 0"):
            self.assertIn(text, stderr)
            self.assertNotIn(text, stdout)
        self.assertIn("local-only", stderr.lower())
        self.assert_read_only_next_scan(stderr)

    def test_allowlist_without_enable_flag_still_produces_read_only_plan(self):
        self.enable_write_config()
        code, stdout, stderr = self.call_cli(self.selected_args("--dry-run"))
        self.assertEqual(code, 0, stderr)
        plan = self.parse_plan(stdout)
        self.assertFalse(any(operation["writes_enabled"] for operation in plan["operations"]))
        self.assertIn("Write-enabled operations in this plan: 0", stderr)
        self.assertNotIn("[CAUTION]", stderr)
        self.assert_read_only_next_scan(stderr)

    def test_allow_write_with_allowlist_warns_about_eligible_patch_but_suggests_read_only_scan(self):
        self.enable_write_config()
        code, stdout, stderr = self.call_cli(self.selected_args("--dry-run", "--allow-write-tests"))
        self.assertEqual(code, 0, stderr)
        plan = self.parse_plan(stdout)
        self.assertEqual(plan["requests_sent"], 0)
        self.assertEqual(sum(operation["writes_enabled"] is True for operation in plan["operations"]), 1)
        self.assertIn("Write-enabled operations in this plan: 1", stderr)
        self.assertIn("[CAUTION]", stderr)
        self.assertIn("0 requests", stderr)
        self.assertIn("1 PATCH operation", stderr)
        for concept in ("disposable", "independent GET", "field_map", "consistency", "rollback"):
            self.assertIn(concept, stderr)
        self.assert_read_only_next_scan(stderr)

    def test_allow_write_with_empty_allowlist_does_not_enable_patch_in_plan(self):
        code, stdout, stderr = self.call_cli(self.selected_args("--dry-run", "--allow-write-tests"))
        self.assertEqual(code, 0, stderr)
        self.assertEqual(self.parse_plan(stdout)["requests_sent"], 0)
        self.assertIn("write_allowlist is empty; no PATCH requests will be sent", stderr)
        self.assertIn("Write-enabled operations in this plan: 0", stderr)
        self.assertNotIn("[CAUTION]", stderr)
        self.assert_read_only_next_scan(stderr)

    def test_dry_run_output_never_displays_credentials_resources_or_baseline_payload(self):
        self.enable_write_config()
        original = self.config.read_bytes()
        for flags in (("--dry-run",), ("--dry-run", "--allow-write-tests"),
                      ("--dry-run", "--allow-write-tests", "--include-sensitive-evidence")):
            with self.subTest(flags=flags):
                code, stdout, stderr = self.call_cli(self.selected_args(*flags))
                self.assertEqual(code, 0, stderr)
                self.assert_private(stdout + stderr)
        self.assertEqual(self.config.read_bytes(), original)

    def test_dry_run_next_command_uses_authorized_target_placeholder(self):
        code, _, stderr = self.call_cli(self.selected_args("--dry-run", "--target", "https://real-target.example"))
        self.assertEqual(code, 0, stderr)
        self.assert_read_only_next_scan(stderr)
        self.assertNotIn("https://real-target.example", stderr)

    def test_dry_run_without_config_keeps_optional_config_absent_from_next_scan(self):
        code, _, stderr = self.call_cli(["--spec", str(self.spec), "--dry-run"])
        self.assertEqual(code, 0, stderr)
        self.assert_read_only_next_scan(stderr)
        scan = next(line for line in stderr.splitlines() if "granttrace" in line and "--target" in line)
        self.assertNotIn("--config", scan)

    def test_sarif_remains_rejected_for_all_offline_modes_without_creating_output(self):
        output = self.folder / "should-not-exist.sarif"
        for mode in (["--validate-config"], ["--dry-run"], ["--init-config", str(self.folder / "draft.json")]):
            with self.subTest(mode=mode):
                code, _, stderr = self.call_cli([*mode, "--export-sarif", str(output)], prohibit_auditor=True)
                self.assertEqual(code, 2)
                self.assertIn("--export-sarif requires audit results", stderr)
                self.assertFalse(output.exists())

    def test_onboarding_invalid_mode_combination_keeps_usage_exit_two(self):
        code, _, stderr = self.call_cli(
            ["--spec", str(self.spec), "--init-config", str(self.folder / "draft.json"), "--allow-write-tests"],
            prohibit_auditor=True,
        )
        self.assertEqual(code, 2)
        self.assertIn("cannot be combined", stderr)

    def test_help_describes_existing_onboarding_flags_without_new_top_level_modes(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as exited:
            main(["--help"])
        self.assertEqual(exited.exception.code, 0)
        text = stdout.getvalue()
        self.assertIn("onboarding", text.lower())
        for flag in ("--init-config", "--validate-config", "--dry-run"):
            self.assertIn(flag, text)
        for flag in ("--wizard", "--interactive", "--setup", "--preflight"):
            self.assertNotIn(flag, text)

    def test_validation_and_dry_run_do_not_modify_input_files(self):
        before = (self.spec.read_bytes(), self.config.read_bytes())
        for mode in ("--validate-config", "--dry-run"):
            with self.subTest(mode=mode):
                code, _, stderr = self.call_cli(self.selected_args(mode), prohibit_auditor=mode == "--validate-config")
                self.assertEqual(code, 0, stderr)
        self.assertEqual((self.spec.read_bytes(), self.config.read_bytes()), before)


if __name__ == "__main__":
    unittest.main()
