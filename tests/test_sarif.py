"""SARIF reports preserve verdict confidence and disclose only safe metadata."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote, quote_plus

from core import __version__
from core.sarif import SarifReportGenerator


class SarifReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="granttrace-sarif-tests-")
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name) / "report.sarif"

    def generate(self, results=(), target="https://api.example.test", secrets=()):
        SarifReportGenerator.generate(
            results=results, target_url=target, output_path=str(self.output), secret_values=secrets,
        )
        return json.loads(self.output.read_text(encoding="utf-8"))

    def confirmed(self, check="BOLA", endpoint="GET /api/users/{id}", **extra):
        return {"check": check, "endpoint": endpoint, "verdict": "CONFIRMED", **extra}

    def test_standard_schema_and_version(self):
        report = self.generate()
        self.assertEqual(report["$schema"], "https://json.schemastore.org/sarif-2.1.0.json")
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(len(report["runs"]), 1)

    def test_driver_uses_current_granttrace_version(self):
        driver = self.generate()["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "GrantTrace")
        self.assertEqual(driver["version"], __version__)
        self.assertEqual(driver["informationUri"], "https://github.com/ysc070528/granttrace")

    def test_rules_describe_only_supported_checks_and_cwes(self):
        rules = self.generate()["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual({rule["id"] for rule in rules}, {"GT-BOLA-001", "GT-MASS-001"})
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                for key in ("name", "shortDescription", "fullDescription", "help"):
                    self.assertTrue(rule[key])
                cwe = "CWE-639" if rule["id"] == "GT-BOLA-001" else "CWE-915"
                self.assertIn("security", rule["properties"]["tags"])
                self.assertIn(cwe, rule["properties"]["tags"])

    def test_confirmed_bola_has_rule_level_message_and_properties(self):
        result = self.generate([self.confirmed()])["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "GT-BOLA-001")
        self.assertEqual(result["level"], "error")
        self.assertIn("GET /api/users/{id}", result["message"]["text"])
        self.assertEqual(result["properties"]["endpoint"], "GET /api/users/{id}")
        self.assertEqual(result["properties"]["check"], "BOLA")
        self.assertEqual(result["properties"]["cwe"], "CWE-639")
        self.assertEqual(result["properties"]["granttraceVerdict"], "CONFIRMED")
        self.assertEqual(result["properties"]["target"], "https://api.example.test")

    def test_confirmed_mass_assignment_maps_to_cwe915(self):
        finding = self.confirmed("MASS_ASSIGNMENT", "PATCH /api/users/{id}/settings")
        result = self.generate([finding])["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "GT-MASS-001")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["properties"]["check"], "MASS_ASSIGNMENT")
        self.assertEqual(result["properties"]["cwe"], "CWE-915")

    def test_results_do_not_fabricate_source_locations(self):
        result = self.generate([self.confirmed()])["runs"][0]["results"][0]
        self.assertNotIn("locations", result)
        self.assertNotIn("physicalLocation", json.dumps(result))

    def test_all_nonconfirmed_verdicts_are_excluded(self):
        for verdict in ("SECURE", "PUBLIC", "AUTHORIZED", "SKIPPED", "SUSPICIOUS", "INCONCLUSIVE", "ERROR"):
            with self.subTest(verdict=verdict):
                finding = {**self.confirmed(), "verdict": verdict, "severity": "Critical", "confirmed": True}
                self.assertEqual(self.generate([finding])["runs"][0]["results"], [])

    def test_missing_unknown_or_nonexact_verdicts_are_not_upgraded(self):
        findings = [{"check": "BOLA", "endpoint": "GET /api/users/{id}", "severity": "High"}]
        findings.extend({**self.confirmed(), "verdict": verdict}
                        for verdict in (None, True, "confirmed", " CONFIRMED", "VULNERABLE"))
        self.assertEqual(self.generate(findings)["runs"][0]["results"], [])

    def test_unknown_or_missing_checks_do_not_create_new_rule_categories(self):
        findings = [{"verdict": "CONFIRMED", "endpoint": "GET /api/users/{id}"}]
        findings.extend(self.confirmed(check=check) for check in (None, True, [], {}, "bola", "SQLI", "UNKNOWN"))
        self.assertEqual(self.generate(findings)["runs"][0]["results"], [])

    def test_multiple_confirmed_results_keep_their_matching_rules(self):
        findings = [self.confirmed(), self.confirmed("MASS_ASSIGNMENT", "PATCH /api/users/{id}/settings"),
                    self.confirmed(endpoint="GET /api/documents/{uuid}")]
        results = self.generate(iter(findings))["runs"][0]["results"]
        self.assertEqual([result["ruleId"] for result in results],
                         ["GT-BOLA-001", "GT-MASS-001", "GT-BOLA-001"])
        self.assertEqual(len(results), 3)

    def test_mixed_verdicts_export_only_exact_confirmed(self):
        findings = [self.confirmed(), {**self.confirmed(), "verdict": "SUSPICIOUS"},
                    self.confirmed("MASS_ASSIGNMENT", "PATCH /api/users/{id}/settings"),
                    {**self.confirmed(), "verdict": "INCONCLUSIVE"}]
        self.assertEqual(len(self.generate(findings)["runs"][0]["results"]), 2)

    def test_empty_scan_is_a_valid_report_with_no_results(self):
        self.assertEqual(self.generate()["runs"][0]["results"], [])

    def test_bearer_token_is_redacted_even_inside_endpoint(self):
        marker = "M9K7W2Q6R4"
        finding = self.confirmed(endpoint=f"GET /api/users/{marker}",
                                 evidence={"headers": {"Authorization": "Bearer " + marker}})
        report = self.generate([finding], secrets=["Bearer " + marker])
        self.assertNotIn(marker, json.dumps(report))
        self.assertEqual(len(report["runs"][0]["results"]), 1)
        self.assertIn("[REDACTED]", report["runs"][0]["results"][0]["properties"]["endpoint"])

    def test_cookie_components_are_redacted_without_full_header_match(self):
        session = "A6D4R8N2B7"
        other = "P3V8H1J5L9"
        finding = self.confirmed(endpoint=f"GET /api/users/{session}/{other}",
                                 evidence={"headers": {"Cookie": f"sid={session}; auth={other}"}})
        report = self.generate([finding], secrets=[f"sid={session}; auth={other}"])
        text = json.dumps(report)
        self.assertNotIn(session, text)
        self.assertNotIn(other, text)
        self.assertEqual(report["runs"][0]["results"][0]["properties"]["endpoint"],
                         "GET /api/users/[REDACTED]/[REDACTED]")

    def test_known_api_key_and_its_encoded_forms_do_not_leak(self):
        marker = "SARIF public/test+key"
        for encoded in (quote(marker, safe=""), quote_plus(marker, safe="")):
            with self.subTest(encoded=encoded):
                text = json.dumps(self.generate([self.confirmed(endpoint="GET /api/users/" + encoded)],
                                                secrets=iter([marker])))
                self.assertNotIn(marker, text)
                self.assertNotIn(encoded, text)

    def test_raw_response_headers_and_private_business_evidence_are_never_exported(self):
        marker = "SARIF_TEST_PRIVATE_RESPONSE_MARKER"
        finding = self.confirmed(
            evidence={"body": marker, "headers": {"Authorization": marker, "Cookie": marker,
                                                    "X-API-Key": marker},
                      "password": marker, "session": marker, "credential": marker},
            reason=marker, details=marker, title=marker,
        )
        result = self.generate([finding])["runs"][0]["results"][0]
        self.assertNotIn(marker, json.dumps(result))
        for key in ("evidence", "reason", "details", "headers", "body"):
            self.assertNotIn(key, result["properties"])

    def test_sensitive_evidence_optin_on_input_does_not_disable_sarif_sanitization(self):
        marker = "Q7B2M8F4X6"
        finding = self.confirmed(include_sensitive_evidence=True,
                                 evidence={"include_sensitive": True, "response_body": marker},
                                 endpoint="GET /api/users/" + marker)
        report = self.generate([finding], secrets=[marker])
        text = json.dumps(report)
        self.assertNotIn(marker, text)
        self.assertEqual(report["runs"][0]["results"][0]["properties"]["endpoint"],
                         "GET /api/users/[REDACTED]")

    def test_target_discloses_only_sanitized_http_origin(self):
        target = "https://fake-user:FAKE_TEST_PASSWORD@api.example.test:8443/private/user?api_key=FAKE_KEY#private"
        result = self.generate([self.confirmed()], target=target)["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["target"], "https://api.example.test:8443")
        for value in ("fake-user", "FAKE_TEST_PASSWORD", "FAKE_KEY", "/private/user", "#private"):
            self.assertNotIn(value, json.dumps(result))

    def test_invalid_or_nonhttp_targets_are_omitted(self):
        for target in ("file:///private/example", "C:\\Users\\SARIF_TEST_PRIVATE\\file.json", "ftp://example.test",
                       "https://[invalid", "https://example.test:wrong", "/private/local/path",
                       "https://.invalid-host", "https://", "https://host with spaces.test"):
            with self.subTest(target=target):
                result = self.generate([self.confirmed()], target=target)["runs"][0]["results"][0]
                self.assertNotIn("target", result["properties"])
                self.assertNotIn(target, json.dumps(result))

    def test_ipv6_origin_preserves_real_host_and_port_without_url_suffixes(self):
        result = self.generate([self.confirmed()], target="http://[::1]:8080/private?token=FAKE_VALUE#private")["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["target"], "http://[::1]:8080")
        self.assertNotIn("FAKE_VALUE", json.dumps(result))

    def test_known_secret_embedded_in_target_hostname_is_omitted(self):
        marker = "sarif-public-test-secret"
        result = self.generate([self.confirmed()], target=f"https://{marker}.example.test", secrets=[marker])["runs"][0]["results"][0]
        self.assertNotIn("target", result["properties"])
        self.assertNotIn(marker, json.dumps(result))

    def test_uppercase_known_credential_hostname_is_checked_before_lowercasing(self):
        marker = "M9K7W2Q6R4"
        result = self.generate([self.confirmed()], target=f"https://{marker}.example.test",
                               secrets=[marker])["runs"][0]["results"][0]
        self.assertNotIn("target", result["properties"])
        text = json.dumps(result)
        self.assertNotIn(marker, text)
        self.assertNotIn(marker.lower(), text)

    def test_local_paths_cannot_be_exported_as_endpoints_or_locations(self):
        for path in ("C:\\Users\\SARIF_TEST_PRIVATE\\spec.json", "/Users/SARIF_TEST_PRIVATE/spec.json",
                     "/home/SARIF_TEST_PRIVATE/spec.json", "file:///tmp/SARIF_TEST_PRIVATE/spec.json"):
            with self.subTest(path=path):
                result = self.generate([self.confirmed(endpoint=path)])["runs"][0]["results"][0]
                self.assertNotIn("SARIF_TEST_PRIVATE", json.dumps(result))
                self.assertNotIn("locations", result)

    def test_operation_shaped_local_paths_and_traversal_are_also_omitted(self):
        for endpoint in ("GET /Users/SARIF_TEST_PRIVATE/spec.json", "GET /home/SARIF_TEST_PRIVATE/spec.json",
                         "GET /private/SARIF_TEST_PRIVATE/spec.json", "GET /tmp/SARIF_TEST_PRIVATE/spec.json",
                         "GET /api/../SARIF_TEST_PRIVATE", "GET //remote.example/SARIF_TEST_PRIVATE"):
            with self.subTest(endpoint=endpoint):
                result = self.generate([self.confirmed(endpoint=endpoint)])["runs"][0]["results"][0]
                self.assertNotIn("endpoint", result["properties"])
                self.assertNotIn("SARIF_TEST_PRIVATE", json.dumps(result))

    def test_missing_or_nonstr_endpoint_retains_confirmed_result_without_endpoint(self):
        for endpoint in (None, [], {}, 123):
            with self.subTest(endpoint=endpoint):
                results = self.generate([self.confirmed(endpoint=endpoint)])["runs"][0]["results"]
                self.assertEqual(len(results), 1)
                self.assertNotIn("endpoint", results[0]["properties"])
                self.assertTrue(results[0]["message"]["text"])

    def test_credential_shaped_route_is_omitted_even_without_known_secret_values(self):
        for route in ("/api/Bearer/SARIF_PRIVATE", "/api/api-key/SARIF_PRIVATE",
                      "/api/password/SARIF_PRIVATE", "/api/session/SARIF_PRIVATE"):
            with self.subTest(route=route):
                result = self.generate([self.confirmed(endpoint="GET " + route)])["runs"][0]["results"][0]
                self.assertNotIn("endpoint", result["properties"])
                self.assertNotIn("SARIF_PRIVATE", json.dumps(result))

    def test_dotted_credential_route_is_omitted_without_known_secret_values(self):
        for endpoint in ("GET /api/api.key/pk_live_fixture", "GET /api/private.key/private-key-fixture"):
            with self.subTest(endpoint=endpoint):
                result = self.generate([self.confirmed(endpoint=endpoint)])["runs"][0]["results"][0]
                self.assertNotIn("endpoint", result["properties"])
                self.assertNotIn("pk_live_fixture", json.dumps(result))
                self.assertNotIn("private-key-fixture", json.dumps(result))

    def test_wsl_and_system_filesystem_paths_are_omitted(self):
        for endpoint in ("GET /mnt/c/Users/private-user/spec.json", "GET /var/log/private-report.json",
                         "GET /etc/private.key", "GET /opt/private-user/spec.json", "GET /mnt", "GET /etc"):
            with self.subTest(endpoint=endpoint):
                result = self.generate([self.confirmed(endpoint=endpoint)])["runs"][0]["results"][0]
                self.assertNotIn("endpoint", result["properties"])
                self.assertNotIn("private-user", json.dumps(result))
                self.assertNotIn("private-report", json.dumps(result))

    def test_query_fragment_and_url_credentials_are_not_endpoint_metadata(self):
        finding = self.confirmed(endpoint="GET /api/users/{id}?token=SARIF_QUERY_PRIVATE#SARIF_FRAGMENT_PRIVATE")
        text = json.dumps(self.generate([finding]))
        self.assertNotIn("SARIF_QUERY_PRIVATE", text)
        self.assertNotIn("SARIF_FRAGMENT_PRIVATE", text)

    def test_generator_does_not_mutate_auditor_results(self):
        finding = self.confirmed(evidence={"response_body": "SARIF_TEST_PRIVATE_RESPONSE"})
        original = json.dumps(finding, sort_keys=True)
        self.generate([finding])
        self.assertEqual(json.dumps(finding, sort_keys=True), original)

    def test_existing_directory_is_not_treated_as_successful_output_file(self):
        with self.assertRaises(OSError):
            SarifReportGenerator.generate(results=[], target_url="https://api.example.test",
                                          output_path=str(self.output.parent), secret_values=())


if __name__ == "__main__":
    unittest.main()
