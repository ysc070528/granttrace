"""Safe cURL templates retain the recorded request without exporting credentials."""

import copy
import json
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote, quote_plus

from core.models import Verdict
from core.reproduction import CurlTemplate, build_reproduction_templates


class ReproductionTests(unittest.TestCase):
    def bola(self, **changes):
        finding = {
            "cwe": "CWE-639", "endpoint": "GET /api/users/{id}",
            "evidence": {"target_url": "https://example.test/api/users/1001"},
        }
        finding.update(changes)
        return finding

    def mass(self, payload=None, content_type="application/json", **changes):
        finding = {
            "cwe": "CWE-915", "endpoint": "PATCH /api/users/{id}",
            "injected_payload": {"role": "admin"} if payload is None else payload,
            "evidence": {
                "target_url": "https://example.test/api/users/1002/settings",
                "request_content_type": content_type,
            },
        }
        finding.update(changes)
        return finding

    def template(self, finding=None, headers=None, secrets=()):
        templates = build_reproduction_templates(
            [self.bola() if finding is None else finding],
            {"Authorization": "Bearer SUPER_SECRET_123"} if headers is None else headers,
            secret_values=secrets,
        )
        self.assertEqual(set(templates), {0})
        self.assertIsInstance(templates[0], CurlTemplate)
        return templates[0]

    def arguments(self, template):
        arguments = shlex.split(template.command)
        self.assertEqual(arguments[0], "curl")
        self.assertIn("--globoff", arguments)
        return arguments

    def header_arguments(self, template):
        args = self.arguments(template)
        return [args[index + 1] for index, value in enumerate(args) if value == "-H"]

    def test_confirmed_bola_uses_visitor_placeholder_and_owner_tested_resource(self):
        finding = self.bola(verdict="CONFIRMED")
        finding["evidence"]["visitor_self_url"] = "https://example.test/api/users/1002"
        template = self.template(finding)
        args = self.arguments(template)
        self.assertEqual(args[args.index("-X") + 1], "GET")
        self.assertIn("https://example.test/api/users/1001", args)
        self.assertNotIn("https://example.test/api/users/1002", args)
        self.assertEqual(self.header_arguments(template), ["Authorization: Bearer <VISITOR_TOKEN>"])
        self.assertNotIn("SUPER_SECRET_123", template.command)
        self.assertNotIn("--data", args)

    def test_confirmed_collection_contract_accepts_absent_verdict(self):
        self.assertEqual(len(build_reproduction_templates([self.bola()], {"X-API-Key": "key"})), 1)

    def test_explicit_nonconfirmed_verdicts_are_not_reproduced(self):
        for verdict in ("SECURE", "PUBLIC", "AUTHORIZED", "SUSPICIOUS", "INCONCLUSIVE", "SKIPPED", "ERROR"):
            with self.subTest(verdict=verdict):
                self.assertEqual(build_reproduction_templates([self.bola(verdict=verdict)],
                                                             {"Authorization": "Bearer secret"}), {})

    def test_verdict_enum_is_accepted_without_altering_input(self):
        finding = self.bola(verdict=Verdict.CONFIRMED)
        original = copy.deepcopy(finding)
        self.template(finding)
        self.assertEqual(finding, original)

    def test_mass_assignment_uses_patch_and_only_confirmed_injected_payload(self):
        template = self.template(self.mass(verdict="CONFIRMED"))
        args = self.arguments(template)
        self.assertEqual(args[args.index("-X") + 1], "PATCH")
        self.assertIn("https://example.test/api/users/1002/settings", args)
        self.assertEqual(json.loads(args[args.index("--data") + 1]), {"role": "admin"})

    def test_json_content_type_is_recorded_in_header(self):
        self.assertIn("Content-Type: application/json", self.header_arguments(self.template(self.mass())))

    def test_merge_patch_content_type_is_preserved(self):
        headers = self.header_arguments(self.template(self.mass(content_type="application/merge-patch+json")))
        self.assertIn("Content-Type: application/merge-patch+json", headers)
        self.assertNotIn("Content-Type: application/json", headers)

    def test_missing_or_unsupported_content_type_cannot_be_guessed(self):
        finding = self.mass()
        finding["evidence"].pop("request_content_type")
        self.assertEqual(build_reproduction_templates([finding], {"X-API-Key": "secret"}), {})
        for content_type in (None, "", "text/plain", "application/json\r\nX-Unsafe: evil"):
            with self.subTest(content_type=content_type):
                self.assertEqual(build_reproduction_templates([self.mass(content_type=content_type)],
                                                             {"X-API-Key": "secret"}), {})

    def test_content_type_cannot_echo_partially_encoded_credentials(self):
        for value in ('%50RIVATEcredential', '"%50RIVATEcredential"', '%2550RIVATEcredential'):
            with self.subTest(value=value):
                finding = self.mass(content_type="application/json; p=" + value)
                self.assertEqual(build_reproduction_templates([finding], {"X-API-Key": "different-auth"},
                                                             ["PRIVATEcredential"]), {})
        content_type = "application/merge-patch+json; charset=utf-8"
        self.assertIn("Content-Type: " + content_type,
                      self.header_arguments(self.template(self.mass(content_type=content_type))))

    def test_bearer_authentication_retains_only_scheme(self):
        template = self.template(headers={"Authorization": "bEaReR secret-token"})
        self.assertEqual(self.header_arguments(template), ["Authorization: Bearer <VISITOR_TOKEN>"])
        self.assertNotIn("secret-token", template.command)

    def test_basic_authentication_uses_credential_placeholder(self):
        template = self.template(headers={"Authorization": "Basic c2VjcmV0OnBhc3N3b3Jk"})
        self.assertEqual(self.header_arguments(template), ["Authorization: Basic <VISITOR_CREDENTIAL>"])
        self.assertNotIn("c2VjcmV0OnBhc3N3b3Jk", template.command)

    def test_unknown_authorization_scheme_does_not_export_scheme_or_value(self):
        template = self.template(headers={"Authorization": "CustomSecret real-credential"})
        self.assertEqual(self.header_arguments(template), ["Authorization: <VISITOR_TOKEN>"])
        self.assertNotIn("CustomSecret", template.command)
        self.assertNotIn("real-credential", template.command)

    def test_api_key_authentication_is_placeholder(self):
        template = self.template(headers={"X-API-Key": "real-api-key-value"})
        self.assertEqual(self.header_arguments(template), ["X-API-Key: <VISITOR_X_API_KEY>"])
        self.assertNotIn("real-api-key-value", template.command)

    def test_cookie_authentication_never_exports_cookie_names_or_values(self):
        template = self.template(headers={"Cookie": "session=real-session; password=real-password"})
        self.assertEqual(self.header_arguments(template), ["Cookie: <VISITOR_COOKIE>"])
        for value in ("session=", "real-session", "real-password"):
            self.assertNotIn(value, template.command)

    def test_custom_visitor_header_is_placeholder(self):
        template = self.template(headers={"X-Tenant-ID": "private-tenant-value"})
        self.assertEqual(self.header_arguments(template), ["X-Tenant-ID: <VISITOR_X_TENANT_ID>"])
        self.assertNotIn("private-tenant-value", template.command)

    def test_invalid_header_names_cannot_create_options_or_command_injection(self):
        for name in ("X-Evil\r\nAuthorization", "X-Evil: injected", "X-Evil;touch", "<script>"):
            with self.subTest(name=name):
                templates = build_reproduction_templates([self.bola()], {name: "secret"})
                if templates:
                    self.assertEqual(self.header_arguments(templates[0]), [])
                    self.assertNotIn(name, templates[0].command)

    def test_secret_in_header_name_is_omitted(self):
        secret = "SECRET_HEADER_NAME"
        templates = build_reproduction_templates([self.bola()], {"X-" + secret: "value"}, [secret])
        if templates:
            self.assertNotIn(secret, templates[0].command)

    def test_option_shaped_header_remains_one_header_argument(self):
        template = self.template(headers={"--data": "private-value"})
        args = self.arguments(template)
        self.assertNotIn("--data", args)
        self.assertEqual(len(self.header_arguments(template)), 1)
        self.assertNotIn("private-value", template.command)

    def test_no_visitor_headers_cannot_substitute_anonymous_access(self):
        self.assertEqual(build_reproduction_templates([self.bola()], {}), {})

    def test_url_query_userinfo_and_fragment_are_sanitized(self):
        finding = self.bola()
        finding["evidence"]["target_url"] = (
            "https://owner:owner-password@example.test/api/users/1001?token=url-secret&limit=20#private-fragment"
        )
        template = self.template(finding, secrets=["owner-password", "url-secret"])
        self.assertTrue(template.redacted)
        self.assertIn("脱敏", template.note)
        for forbidden in ("owner:", "owner-password", "url-secret", "limit=20", "#private-fragment"):
            self.assertNotIn(forbidden, template.command)
        self.assertIn("%5BREDACTED%5D", template.command)

    def test_encoded_known_secrets_are_removed_from_path_and_query(self):
        secret = "private/credential value+extra"
        variants = (secret, quote(secret, safe=""), quote_plus(secret, safe=""))
        for encoded in variants:
            with self.subTest(encoded=encoded):
                finding = self.bola()
                finding["evidence"]["target_url"] = "https://example.test/api/" + encoded + "?other=" + encoded
                templates = build_reproduction_templates([finding], {"X-API-Key": "other-auth"}, [secret])
                if templates:
                    for value in variants:
                        self.assertNotIn(value, templates[0].command)

    def test_payload_sensitive_keys_and_known_secret_values_are_redacted_again(self):
        secret = "payload-private-value"
        payload = {"role": "admin", "password": secret, "credential": secret, "extra": secret,
                   "session": secret, "secret": secret}
        template = self.template(self.mass(payload), secrets=[secret])
        args = self.arguments(template)
        rendered = args[args.index("--data") + 1]
        safe = json.loads(rendered)
        self.assertEqual(safe["role"], "admin")
        for name in ("password", "credential", "extra", "session", "secret"):
            self.assertEqual(safe[name], "[REDACTED]")
        self.assertNotIn(secret, template.command)
        self.assertTrue(template.redacted)

    def test_percent_encoded_payload_credentials_are_scrubbed_or_omitted(self):
        secret = "PRIVATEcredential"
        encoded = "".join("%%%02X" % ord(character) for character in secret)
        variants = (encoded, encoded.lower(), "%50RIVATEcredential", "%2550RIVATEcredential")
        for value in variants:
            with self.subTest(value=value):
                templates = build_reproduction_templates([self.mass({"role": value})],
                                                         {"X-API-Key": secret}, [secret])
                if templates:
                    self.assertNotIn(value, templates[0].command)
                    self.assertNotIn(secret, templates[0].command)

    def test_secret_bearing_payload_field_name_is_omitted(self):
        for field in ("PRIVATEcredential", "%50RIVATEcredential"):
            with self.subTest(field=field):
                self.assertEqual(build_reproduction_templates([self.mass({field: "admin"})],
                                                             {"X-API-Key": "different-auth"},
                                                             ["PRIVATEcredential"]), {})

    def test_partially_encoded_credentials_spanning_path_segments_are_omitted(self):
        secret = "private/credential"
        encoded = "%70rivate/credential"
        for location in ("payload", "url"):
            with self.subTest(location=location):
                finding = self.mass({"role": encoded if location == "payload" else "admin"})
                if location == "url":
                    finding["evidence"]["target_url"] = "https://example.test/" + encoded
                self.assertEqual(build_reproduction_templates([finding], {"X-API-Key": "different-auth"},
                                                             [secret]), {})

    def test_rollback_snapshot_response_body_and_restore_metadata_never_enter_command(self):
        finding = self.mass()
        finding["evidence"].update({
            "rollback_payload": {"role": "ROLLBACK_VALUE"},
            "snapshot": {"role": "SNAPSHOT_VALUE"},
            "before": {"body": "BEFORE_BODY"}, "after": {"body": "AFTER_BODY"},
            "response_body": "RESPONSE_BODY", "recovery": {"body": "RECOVERY_BODY"},
        })
        template = self.template(finding)
        self.assertIn("admin", template.command)
        for forbidden in ("ROLLBACK_VALUE", "SNAPSHOT_VALUE", "BEFORE_BODY", "AFTER_BODY",
                          "RESPONSE_BODY", "RECOVERY_BODY"):
            self.assertNotIn(forbidden, template.command)

    def test_missing_mutation_payload_does_not_fall_back_to_snapshot_or_restore(self):
        finding = self.mass()
        finding.pop("injected_payload")
        finding["evidence"].update({"rollback_payload": {"role": "user"}, "snapshot": {"role": "user"}})
        self.assertEqual(build_reproduction_templates([finding], {"Authorization": "Bearer secret"}), {})

    def test_nested_or_ambiguous_payload_fields_are_omitted(self):
        for payload in ({"role": {"nested": "admin"}}, {"roles": ["admin"]},
                        {"permissions.admin": True}, {"roles[0]": "admin"}, {}, "not-an-object"):
            with self.subTest(payload=payload):
                self.assertEqual(build_reproduction_templates([self.mass(payload)], {"X-API-Key": "secret"}), {})

    def test_nonfinite_or_unsupported_payload_values_do_not_form_commands(self):
        for value in (float("nan"), float("inf"), float("-inf"), object(), b"credential"):
            with self.subTest(value=repr(value)):
                self.assertEqual(build_reproduction_templates([self.mass({"role": value})],
                                                             {"Authorization": "Bearer secret"}), {})

    def test_finite_json_scalar_payload_values_keep_their_types(self):
        payload = {"role": "admin", "enabled": True, "level": 3, "ratio": 1.25, "optional": None}
        args = self.arguments(self.template(self.mass(payload)))
        self.assertEqual(json.loads(args[args.index("--data") + 1]), payload)

    def test_missing_unsafe_or_unresolved_target_url_does_not_guess_resource(self):
        for target in (None, "", "/api/users/1001", "javascript:alert(1)", "file:///tmp/secret",
                       "https://example.test:invalid/api", "https:///api"):
            with self.subTest(target=target):
                finding = self.bola()
                finding["evidence"]["target_url"] = target
                self.assertEqual(build_reproduction_templates([finding], {"X-API-Key": "secret"}), {})
        finding = self.bola(evidence={})
        self.assertEqual(build_reproduction_templates([finding], {"X-API-Key": "secret"}), {})

    def test_malformed_canonical_operations_or_other_methods_are_omitted(self):
        for operation in ("get /api/users/{id}", "GET", "GET api/users/{id}", "GET  /api/users/{id}",
                          "GET /api\nusers", "POST /api/users/{id}", "PUT /api/users/{id}",
                          "PATCH /api/users/{id}"):
            with self.subTest(operation=operation):
                self.assertEqual(build_reproduction_templates([self.bola(endpoint=operation)],
                                                             {"X-API-Key": "secret"}), {})
        self.assertEqual(build_reproduction_templates([self.mass(endpoint="GET /api/users/{id}")],
                                                     {"X-API-Key": "secret"}), {})

    def test_unknown_finding_type_is_not_reproduced(self):
        self.assertEqual(build_reproduction_templates([self.bola(cwe="CWE-999")],
                                                     {"X-API-Key": "secret"}), {})

    def test_controls_in_url_payload_or_auth_value_cannot_enter_command(self):
        for control in ("\n", "\r\n", "\x00", "\x1f", "\x7f"):
            with self.subTest(control=repr(control)):
                finding = self.bola()
                finding["evidence"]["target_url"] = "https://example.test/api/" + control + "unsafe"
                self.assertEqual(build_reproduction_templates([finding], {"X-API-Key": "secret"}), {})
                payload_templates = build_reproduction_templates([self.mass({"role": "admin" + control})],
                                                                {"X-API-Key": "secret"})
                if payload_templates:
                    self.assertNotIn(control, payload_templates[0].command)
                templates = build_reproduction_templates([self.bola()], {"Authorization": "Bearer secret" + control})
                if templates:
                    self.assertNotIn(control, templates[0].command)

    def test_shell_metacharacters_remain_in_one_argument(self):
        hostile = "admin'\"; echo injected && true | cat $(echo unsafe) `echo unsafe`"
        template = self.template(self.mass({"role": hostile}))
        args = self.arguments(template)
        self.assertEqual(json.loads(args[args.index("--data") + 1]), {"role": hostile})
        self.assertEqual(args.count("--data"), 1)
        shell = shutil.which("sh")
        if shell:
            # Replace cURL with a shell function that prints its argv; no HTTP or
            # malicious command is executed even if quoting accidentally regresses.
            harness = "curl() { printf '%s\\n' \"$@\"; }; " + template.command
            result = subprocess.run([shell, "-c", harness], capture_output=True, text=True,
                                    encoding="utf-8", timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), args[1:])

    def test_known_auth_values_are_scrubbed_from_other_request_components(self):
        secret = "echoed-private-auth"
        finding = self.mass({"role": secret})
        finding["evidence"]["target_url"] = "https://example.test/api/" + secret
        template = self.template(finding, headers={"X-Tenant-ID": secret})
        self.assertNotIn(secret, template.command)
        self.assertTrue(template.redacted)

    def test_mapping_indices_match_original_findings_after_omissions(self):
        findings = [self.bola(verdict="SECURE"), self.bola(), self.mass(), self.bola(cwe="CWE-999")]
        original = copy.deepcopy(findings)
        headers = {"Authorization": "Bearer visitor-only", "X-Tenant-ID": "tenant-only"}
        original_headers = dict(headers)
        templates = build_reproduction_templates(iter(findings), headers, iter(["visitor-only"]))
        self.assertEqual(set(templates), {1, 2})
        self.assertEqual(findings, original)
        self.assertEqual(headers, original_headers)

    def test_generated_command_can_be_saved_without_authentication_values(self):
        template = self.template(headers={"Authorization": "Bearer private-token", "Cookie": "sid=private-cookie"})
        with tempfile.TemporaryDirectory() as directory:
            saved = Path(directory) / "template.sh"
            saved.write_text(template.command, encoding="utf-8")
            content = saved.read_text(encoding="utf-8")
        self.assertNotIn("private-token", content)
        self.assertNotIn("private-cookie", content)
        self.assertIn("<VISITOR_TOKEN>", content)
        self.assertIn("<VISITOR_COOKIE>", content)


if __name__ == "__main__":
    unittest.main()
