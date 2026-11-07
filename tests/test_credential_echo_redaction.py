"""Offline regressions for credential echoes at result and report boundaries."""

import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote, quote_plus

from core.auditor import APISentinelAuditor
from core.evidence import REDACTED, sanitize_body, sanitize_evidence
from core.models import HTTPResult, Verdict
from core.reporter import SecurityReportGenerator


ROOT = Path(__file__).resolve().parents[1]


class ReleaseEvidenceTests(unittest.TestCase):
    def make_auditor(self, include_sensitive=False, owner_cookie=None):
        return APISentinelAuditor(
            spec_path=str(ROOT / "openapi.json"),
            target_base_url="http://127.0.0.1:8080",
            request_delay=0,
            include_sensitive_evidence=include_sensitive,
            identities_config={
                "owner": {
                    "id": "1001",
                    "headers": {"Cookie": owner_cookie or "sid=COOKIE_A_42; csrftoken=CSRF_A_42"},
                    "parameters": {"user_id": "1001"},
                },
                "visitor": {
                    "id": "1002",
                    "headers": {"Cookie": "sid=COOKIE_B_42; csrftoken=CSRF_B_42"},
                    "parameters": {"user_id": "1002"},
                },
                "anonymous": {"id": None, "parameters": {}},
            },
        )

    def test_cookie_components_are_redacted_in_unlabelled_body_echoes(self):
        header = "sid=session/opaque+value; csrftoken=csrf-secret-value"
        body = json.dumps({"debug": "session/opaque+value", "rows": ["csrf-secret-value"]})
        safe = json.loads(sanitize_body(body, secret_values=[header]))
        self.assertEqual(safe, {"debug": REDACTED, "rows": [REDACTED]})

    def test_cookie_components_have_encoded_variants(self):
        secret = "session/opaque+value"
        forms = [secret, quote(secret, safe=""), quote_plus(secret, safe="")]
        safe = sanitize_evidence({"echoes": forms}, secret_values=(s for s in ["sid=" + secret]))
        self.assertEqual(safe["echoes"], [REDACTED] * len(forms))

    def test_quoted_and_single_cookie_values_are_redacted(self):
        for header, component in [
            ('sid="quoted credential"; csrf="second/credential"', "quoted credential"),
            ("JSESSIONID=single-cookie-credential", "single-cookie-credential"),
        ]:
            with self.subTest(header=header):
                safe = json.loads(sanitize_body(json.dumps({"debug": component}), secret_values=[header]))
                self.assertEqual(safe["debug"], REDACTED)

    def test_non_cookie_secrets_still_redact_as_complete_strings(self):
        secret = "opaque=one; this is not a cookie"
        safe = sanitize_evidence({"whole": secret, "unrelated": "one"}, secret_values=[secret])
        self.assertEqual(safe, {"whole": REDACTED, "unrelated": "one"})

    def test_request_cookie_names_are_not_reinterpreted_as_response_attributes(self):
        for name in ("path", "domain", "secure", "version", "expires", "httponly", "samesite"):
            for prefix in ("", "sid=ordinary-credential; "):
                with self.subTest(name=name, prefix=prefix):
                    secret = name.upper() + "_AUTH_SECRET"
                    header = prefix + name + "=" + secret
                    safe = json.loads(sanitize_body(json.dumps({"debug": secret}), secret_values=[header]))
                    self.assertEqual(safe["debug"], REDACTED)

    def test_reserved_cookie_name_quoted_value_is_decoded_and_encoded(self):
        secret = "quoted credential/with+encoding"
        header = 'path="quoted\\040credential/with+encoding"; domain="another;credential"'
        body = {"first": secret, "encoded": quote(secret, safe=""), "second": "another;credential"}
        safe = json.loads(sanitize_body(json.dumps(body), secret_values=[header]))
        self.assertEqual(safe, {"first": REDACTED, "encoded": REDACTED, "second": REDACTED})

    def test_numeric_secret_echoes_are_redacted_without_changing_other_values(self):
        body = '{"echo":123456789012,"float_echo":1.23456789012e11,"count":3,"enabled":true,"status":"ok"}'
        safe = json.loads(sanitize_body(body, secret_values=["123456789012"]))
        self.assertEqual(safe, {"echo": REDACTED, "float_echo": REDACTED, "count": 3,
                                "enabled": True, "status": "ok"})

    def test_numeric_cookie_component_is_redacted(self):
        safe = json.loads(sanitize_body('{"debug":123456}', secret_values=["sid=123456"]))
        self.assertEqual(safe["debug"], REDACTED)

    def test_opaque_numeric_looking_secrets_do_not_abort_sanitization(self):
        secret = "1e999999999999999999999999"
        safe = sanitize_evidence({"secret_echo": secret, "count": 3}, secret_values=[secret])
        self.assertEqual(safe, {"secret_echo": REDACTED, "count": 3})

    def test_explicit_sensitive_opt_in_preserves_cookie_and_numeric_echoes(self):
        body = {"first": "COOKIE_A_42", "second": "CSRF_A_42", "number": 123456789012}
        secrets = ["sid=COOKIE_A_42; csrftoken=CSRF_A_42", "123456789012"]
        self.assertEqual(json.loads(sanitize_body(json.dumps(body), include_sensitive=True,
                                                secret_values=secrets)), body)
        self.assertEqual(sanitize_evidence(body, include_sensitive=True, secret_values=secrets), body)

    def test_actual_auditor_results_and_html_do_not_disclose_cookie_components(self):
        auditor = self.make_auditor(owner_cookie="sid=COOKIE_A_42; csrftoken=CSRF_A_42; otp=123456789012")
        body = json.dumps({"debug": "COOKIE_A_42", "other": "CSRF_A_42", "numeric_echo": 123456789012,
                           "count": 3})
        evidence = {"owner": auditor._safe_body(HTTPResult(200, body))}
        finding = {"type": "Synthetic finding", "severity": "High", "endpoint": "GET /items/{id}",
                   "details": "Offline boundary regression", "evidence": evidence}
        auditor._record_result({"method": "GET", "path": "/items/{id}"}, "BOLA", Verdict.CONFIRMED,
                               finding["details"], evidence, finding)
        for value in (auditor.results, auditor.findings):
            rendered = json.dumps(value)
            self.assertNotIn("COOKIE_A_42", rendered)
            self.assertNotIn("CSRF_A_42", rendered)
            self.assertNotIn("123456789012", rendered)
        self.assertEqual(json.loads(auditor.results[0]["evidence"]["owner"]["body"])["count"], 3)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            SecurityReportGenerator.generate(auditor.stats, auditor.findings, auditor.target_base_url,
                                             str(report), results=auditor.results)
            html = report.read_text(encoding="utf-8")
        self.assertNotIn("COOKIE_A_42", html)
        self.assertNotIn("CSRF_A_42", html)
        self.assertNotIn("123456789012", html)
        self.assertIn(REDACTED, html)

    def test_actual_auditor_preserves_explicit_sensitive_opt_in(self):
        auditor = self.make_auditor(include_sensitive=True)
        body = {"debug": "COOKIE_A_42", "other": "CSRF_A_42", "count": 3}
        evidence = {"owner": auditor._safe_body(HTTPResult(200, json.dumps(body)))}
        result = auditor._record_result({"method": "GET", "path": "/items/{id}"}, "BOLA",
                                        Verdict.SUSPICIOUS, "Offline boundary regression", evidence)
        self.assertEqual(json.loads(result["evidence"]["owner"]["body"]), body)

    def test_reserved_request_cookie_names_are_protected_at_actual_boundaries(self):
        auditor = self.make_auditor(owner_cookie="path=PATH_AUTH_SECRET; domain=DOMAIN_AUTH_SECRET")
        body = json.dumps({"first": "PATH_AUTH_SECRET", "second": "DOMAIN_AUTH_SECRET", "count": 3})
        evidence = {"owner": auditor._safe_body(HTTPResult(200, body))}
        finding = {"type": "Synthetic finding", "severity": "High", "endpoint": "GET /items/{id}",
                   "details": "Offline reserved-cookie regression", "evidence": evidence}
        auditor._record_result({"method": "GET", "path": "/items/{id}"}, "BOLA", Verdict.CONFIRMED,
                               finding["details"], evidence, finding)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            SecurityReportGenerator.generate(auditor.stats, auditor.findings, auditor.target_base_url,
                                             str(report), results=auditor.results)
            html = report.read_text(encoding="utf-8")
        for output in (json.dumps(auditor.results), json.dumps(auditor.findings), html):
            self.assertNotIn("PATH_AUTH_SECRET", output)
            self.assertNotIn("DOMAIN_AUTH_SECRET", output)
        self.assertEqual(json.loads(auditor.results[0]["evidence"]["owner"]["body"])["count"], 3)


if __name__ == "__main__":
    unittest.main()
