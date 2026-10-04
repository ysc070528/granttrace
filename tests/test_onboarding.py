"""Display-only onboarding helpers quote commands and report counts without secrets."""

from __future__ import annotations

import copy
import shlex
import unittest
from unittest.mock import patch

from core.config_validator import ValidationSummary
from core.onboarding import (
    display_path,
    format_cli_command,
    init_guidance,
    plan_guidance,
    validation_failure_guidance,
    validation_guidance,
)


class OnboardingCommandTests(unittest.TestCase):
    def assert_posix_round_trip(self, arguments):
        command = format_cli_command(arguments, platform="posix")
        self.assertEqual(shlex.split(command), arguments)
        self.assertEqual(command, shlex.join(arguments))

    def test_posix_simple_arguments(self):
        self.assertEqual(format_cli_command(["granttrace", "--spec", "API.yaml"], platform="posix"),
                         "granttrace --spec API.yaml")

    def test_posix_paths_with_spaces(self):
        self.assert_posix_round_trip(["granttrace", "--spec", "/tmp/my API.yaml", "--config", "config local.json"])

    def test_posix_single_quote_is_one_literal_argument(self):
        self.assert_posix_round_trip(["granttrace", "--config", "customer's config.json"])

    def test_posix_double_quote_is_one_literal_argument(self):
        self.assert_posix_round_trip(["granttrace", "--spec", 'API "contract".yaml'])

    def test_posix_shell_metacharacters_never_add_an_argument_or_command(self):
        for path in ("a&b.json", "a;b.json", "a|b.json", "a(b).json", "$(touch injected).json",
                     "`touch injected`.json", "${HOME}.json", "#comment.json", "a>b<file.json"):
            with self.subTest(path=path):
                self.assert_posix_round_trip(["granttrace", "--config", path, "--validate-config"])

    def test_posix_unicode_and_chinese_paths(self):
        self.assert_posix_round_trip(["granttrace", "--spec", "接口合同 café.yaml", "--config", "配置 中文.json"])

    def test_posix_preserves_windows_style_path(self):
        self.assert_posix_round_trip(["granttrace", "--spec", r"C:\API specs\api.yaml"])

    def test_windows_uses_literal_powershell_arguments_and_call_operator(self):
        self.assertEqual(format_cli_command(["granttrace", "--spec", "API.yaml"], platform="windows"),
                         "& 'granttrace' '--spec' 'API.yaml'")

    def test_windows_path_with_spaces_keeps_backslashes_literal(self):
        self.assertEqual(format_cli_command(["granttrace", "--config", r"C:\Test API\config local.json"],
                                           platform="windows"),
                         "& 'granttrace' '--config' 'C:\\Test API\\config local.json'")

    def test_windows_double_quote_and_backtick_are_literal_inside_single_quotes(self):
        path = 'config "contract" `$env:USERPROFILE.json'
        self.assertEqual(format_cli_command(["granttrace", "--config", path], platform="windows"),
                         "& 'granttrace' '--config' '" + path + "'")

    def test_windows_single_quote_is_doubled(self):
        self.assertEqual(format_cli_command(["granttrace", "--config", "customer's config.json"],
                                           platform="windows"),
                         "& 'granttrace' '--config' 'customer''s config.json'")

    def test_windows_smart_quote_breakout_is_escaped_for_every_quote_variant(self):
        for quote in "'\u2018\u2019\u201a\u201b":
            with self.subTest(quote=quote):
                path = "config" + quote + "; Write-Output INJECTED; #.json"
                expected = "& 'granttrace' '--config' 'config" + quote * 2 + "; Write-Output INJECTED; #.json'"
                self.assertEqual(format_cli_command(["granttrace", "--config", path], platform="windows"), expected)

    def test_windows_shell_metacharacters_stay_inside_literal_strings(self):
        for path in ("a&b.json", "a;b.json", "a|b.json", "a(b).json", "$(Write-Output INJECTED).json",
                     "a>b<file.json", "#comment.json"):
            with self.subTest(path=path):
                self.assertEqual(format_cli_command(["granttrace", "--config", path], platform="windows"),
                                 "& 'granttrace' '--config' '" + path + "'")

    def test_windows_unicode_and_chinese_path(self):
        path = r"C:\接口 文档\café配置.json"
        self.assertEqual(format_cli_command(["granttrace", "--config", path], platform="windows"),
                         "& 'granttrace' '--config' '" + path + "'")

    def test_control_characters_get_non_executable_placeholder_in_both_shells(self):
        for platform in ("posix", "windows"):
            for character in ("\r", "\n", "\t", "\x00", "\x1f", "\x7f", "\x1b", "\u2028", "\u202e"):
                with self.subTest(platform=platform, codepoint=ord(character)):
                    command = format_cli_command(["granttrace", "--spec", "API" + character + "[OK] FORGED.yaml"],
                                                 platform=platform)
                    self.assertIn("<PATH_WITH_CONTROL_CHARACTERS>", command)
                    self.assertNotIn(character, command)
                    self.assertNotIn("FORGED", command)
                    self.assertEqual(len(command.splitlines()), 1)

    def test_recognizable_secret_path_is_not_displayed_as_a_copyable_command(self):
        for platform in ("posix", "windows"):
            with self.subTest(platform=platform):
                command = format_cli_command(["granttrace", "--config", "config-Bearer DISPLAY_SECRET.json"],
                                             platform=platform)
                self.assertNotIn("DISPLAY_SECRET", command)
                self.assertIn("<PATH_REQUIRING_MANUAL_INPUT>", command)

    def test_unknown_command_platform_is_rejected(self):
        with self.assertRaises(ValueError):
            format_cli_command(["granttrace"], platform="cmd")

    def test_display_path_escapes_terminal_controls_and_redacts_recognizable_credentials(self):
        path = "config\r\n[OK] FORGED\t\x00\x1f\x7f\x1b.json"
        safe = display_path(path)
        self.assertEqual(len(safe.splitlines()), 1)
        self.assertTrue(all(character.isprintable() for character in safe))
        self.assertNotIn("DISPLAY_SECRET", display_path("config-Bearer DISPLAY_SECRET.json"))


class OnboardingGuidanceTests(unittest.TestCase):
    def first_scan_command(self, lines):
        commands = [line for line in lines if "granttrace" in line and "--target" in line]
        self.assertEqual(len(commands), 1)
        self.assertIn("<AUTHORIZED_TARGET_URL>", commands[0])
        self.assertNotIn("--allow-write-tests", commands[0])
        return commands[0]

    def test_init_guidance_is_offline_display_only_and_requires_manual_review(self):
        with patch("builtins.open", side_effect=AssertionError("Guidance performed file I/O")), \
             patch("socket.socket", side_effect=AssertionError("Guidance opened a socket")):
            lines = init_guidance("API.yaml", "config.json", "config.checklist.json")
        text = "\n".join(lines)
        self.assertIn("intentionally incomplete", text)
        self.assertIn("No credentials", text)
        self.assertIn("write_allowlist is empty", text)
        self.assertIn("No active PATCH test has been authorized", text)
        self.assertIn("__GRANTTRACE_INPUT__:", text)
        self.assertIn("_granttrace_draft", text)
        self.assertLess(text.index("--validate-config"), text.index("--dry-run"))
        self.assertNotIn("--allow-write-tests", text)

    def test_config_only_guidance_requests_spec_validation_before_scan_preparation(self):
        lines = validation_guidance(None, "config.json", ValidationSummary())
        text = "\n".join(lines)
        self.assertIn("Configuration-only validation passed", text)
        self.assertIn("cross-checking was not performed", text)
        self.assertIn("<OPENAPI_FILE>", text)
        commands = [line for line in lines if "granttrace" in line]
        self.assertEqual(len(commands), 1)
        self.assertIn("--validate-config", commands[0])
        self.assertNotIn("--target", text)

    def test_spec_aware_guidance_preserves_summary_and_read_only_next_scan(self):
        summary = ValidationSummary(identities_count=3, parameter_endpoints=7, bola_policies_count=2)
        before = copy.deepcopy(summary)
        lines = validation_guidance("API.yaml", "config.json", summary)
        self.assertEqual(summary, before)
        text = "\n".join(lines)
        self.assertIn("Offline configuration validation passed", text)
        self.assertIn("checked together", text)
        self.assertIn("Checked configured operation keys", text)
        self.assertIn("explicit path/query parameter values against supported schemas", text)
        self.assertIn("GET readbacks absent from the specification produce a warning", text)
        self.assertIn("No PATCH operation is allowlisted", text)
        self.assertIn("--dry-run", text)
        self.first_scan_command(lines)

    def test_allowlisted_configuration_is_counted_and_remains_inactive(self):
        summary = ValidationSummary(allowlisted_endpoints=2, readbacks_count=3)
        lines = validation_guidance("API.yaml", "config.json", summary)
        text = "\n".join(lines)
        self.assertIn("Allowlisted PATCH operations: 2", text)
        self.assertIn("readback mappings: 3", text)
        self.assertIn("remain inactive unless --allow-write-tests", text)
        self.first_scan_command(lines)

    def test_successful_warning_count_is_visible(self):
        text = "\n".join(validation_guidance("API.yaml", "config.json", ValidationSummary(warnings_count=2)))
        self.assertIn("[WARN] Configuration passed with 2 warning(s)", text)

    def test_failure_guidance_preserves_counts_and_only_gives_rerun_command(self):
        for spec in (None, "API.yaml"):
            with self.subTest(spec=spec):
                lines = validation_failure_guidance(spec, "config.json", 3, 2)
                text = "\n".join(lines)
                self.assertIn("[SUMMARY] 3 error(s), 2 warning(s)", text)
                self.assertIn("Fix the issues above", text)
                self.assertNotIn("--target", text)
                commands = [line for line in lines if "granttrace" in line and "--spec" in line]
                self.assertEqual(len(commands), 1)
                self.assertIn("--validate-config", commands[0])
                self.assertNotIn("--dry-run", commands[0])
                if spec is None:
                    self.assertIn("<OPENAPI_FILE>", commands[0])

    def test_plan_summary_uses_existing_entries_and_does_not_mutate_or_print_raw_plan_data(self):
        plan = {
            "mode": "DRY_RUN", "requests_sent": 0, "target": "https://PLAN_PRIVATE_TARGET.example",
            "private": "PLAN_PRIVATE_VALUE",
            "operations": [
                {"endpoint": "GET /PLAN_PRIVATE_RESOURCE", "check": "BOLA", "writes_enabled": False},
                {"endpoint": "GET /second", "check": "BOLA", "writes_enabled": False},
                {"endpoint": "PATCH /items", "check": "MASS_ASSIGNMENT", "writes_enabled": True,
                 "baseline_payload": {"password": "PLAN_PRIVATE_PASSWORD"}},
                {"endpoint": "PATCH /other", "check": "MASS_ASSIGNMENT", "writes_enabled": False},
                {"endpoint": "DELETE /items", "check": "UNSUPPORTED", "writes_enabled": False},
            ],
        }
        before = copy.deepcopy(plan)
        lines = plan_guidance("API.yaml", "config.json", plan)
        text = "\n".join(lines)
        self.assertEqual(plan, before)
        for count in ("Requests sent: 0", "Operations: 5", "BOLA checks: 2", "Mass Assignment checks: 2",
                      "Write-enabled operations in this plan: 1"):
            self.assertIn(count, text)
        self.assertIn("[CAUTION]", text)
        self.assertIn("Dry-run itself sent 0 requests", text)
        self.assertNotIn("PLAN_PRIVATE", text)
        self.first_scan_command(lines)

    def test_plan_without_active_writes_gives_read_only_guidance(self):
        lines = plan_guidance("API.yaml", None, {"operations": [{"check": "BOLA", "writes_enabled": False}]})
        text = "\n".join(lines)
        self.assertIn("Read-only plan", text)
        self.assertIn("Write-enabled operations in this plan: 0", text)
        self.assertNotIn("[CAUTION]", text)
        self.assertNotIn("--config", self.first_scan_command(lines))

    def test_all_guidance_commands_label_their_supported_shell(self):
        for platform, label in (("nt", "PowerShell 7"), ("posix", "POSIX shell")):
            with self.subTest(platform=platform), patch("core.onboarding.os.name", platform):
                lines = init_guidance("API.yaml", "config.json", "config.checklist.json")
                lines += validation_guidance("API.yaml", "config.json", ValidationSummary())
                lines += plan_guidance("API.yaml", "config.json", {"operations": []})
                commands = [line for line in lines if "granttrace" in line and "--spec" in line]
                self.assertTrue(commands)
                self.assertTrue(all(label in command for command in commands))
                executable = "& 'granttrace'" if platform == "nt" else "granttrace"
                self.assertTrue(all(command.lstrip().startswith(executable) for command in commands))


if __name__ == "__main__":
    unittest.main()
