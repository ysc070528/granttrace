"""Regression checks for R09: evidence boundaries must not disclose credentials."""

import json
import unittest
from urllib.parse import parse_qs, quote, urlsplit

from core.evidence import (
    MAX_TOTAL_TEXT_CHARS,
    body_sha256,
    redact_payload,
    sanitize_body,
    sanitize_evidence,
    sanitize_text,
    sanitize_url,
)


class EvidenceSanitizationTests(unittest.TestCase):
    def assertNoSecrets(self, value, *secrets):
        rendered = json.dumps(value, ensure_ascii=False)
        for secret in secrets:
            self.assertNotIn(secret, rendered)

    def test_review_body_counterexamples(self):
        cases = [
            "password=DEMO_PASS_ONLY",
            '{"password":"DEMO_PASS_ONLY","detail":"truncated',
            '{"privateKey":"DEMO_KEY_ONLY"}',
            '{"message":"Bearer DEMO_TOKEN_ONLY"}',
        ]
        for body in cases:
            with self.subTest(body=body):
                self.assertNotIn("DEMO_", sanitize_body(body))

    def test_unparseable_bodies_fail_closed_and_preserve_original_hash(self):
        for body in ("<html>DEMO_PASSWORD</html>", 'token: DEMO_PASSWORD',
                     '{"fullName":"Alice Sensitive","unterminated":'):
            safe = sanitize_body(body)
            self.assertIn(body_sha256(body), safe)
            self.assertIn("OMITTED", safe)
            self.assertNoSecrets(safe, "DEMO_PASSWORD", "Alice Sensitive")
            self.assertEqual(sanitize_body(safe), safe)

    def test_camel_case_keys_and_nested_pii(self):
        payload = {
            "privateKey": "PRIVATE_VALUE", "accessToken": "ACCESS_VALUE",
            "APIKey": "API_VALUE", "fullName": "Alice Sensitive",
            "rows": [{"phoneNumber": "13812345678", "salary": "25,000 USD"}],
            "status": "CONFIRMED", "resourceId": 42,
        }
        safe = redact_payload(payload)
        self.assertNoSecrets(safe, "PRIVATE_VALUE", "ACCESS_VALUE", "API_VALUE", "Alice Sensitive", "13812345678", "25,000 USD")
        self.assertEqual(safe["status"], "CONFIRMED")
        self.assertEqual(safe["resourceId"], 42)

    def test_known_secret_iterator_applies_to_every_leaf_and_encoded_form(self):
        secret = "session/opaque+value"
        safe = sanitize_evidence(
            {"first": secret, "second": {"echo": secret}, "encoded": quote(secret, safe="")},
            secret_values=(value for value in [secret]),
        )
        self.assertNoSecrets(safe, secret, quote(secret, safe=""))

    def test_bearer_header_secret_is_redacted_even_without_scheme(self):
        safe = sanitize_evidence({"error": "opaque-token-value", "message": "Bearer opaque-token-value"},
                                 secret_values=["Bearer opaque-token-value"])
        self.assertNoSecrets(safe, "opaque-token-value")

    def test_messages_scrub_quoted_assignments_bearers_json_and_pii(self):
        messages = [
            'failure: "privateKey": "secret with spaces"',
            "authorization rejected Bearer DEMO_TOKEN_ONLY",
            "API key = 'secret with spaces'; request rejected",
            'failure: fullName="Alice Sensitive"; retrying',
            "contact alice.private@example.net or 13812345678",
            '{"nested":{"fullName":"Alice Sensitive","apiKey":"DEMO_KEY_ONLY"},"ok":false}',
            '{"password":"DEMO_PASSWORD_ONLY",',
        ]
        for message in messages:
            with self.subTest(message=message):
                safe = sanitize_evidence({"error": message})
                self.assertNoSecrets(safe, "secret with spaces", "DEMO_", "Alice Sensitive", "alice.private@example.net", "13812345678")

    def test_urls_remove_userinfo_fragment_and_all_query_values(self):
        safe = sanitize_url("https://user:SECRET_PASS@example.test/users?token=SECRET_TOKEN&arbitrary=PRIVATE_PII#SECRET_HASH")
        self.assertNoSecrets(safe, "SECRET_", "PRIVATE_PII", "user:")
        self.assertEqual(urlsplit(safe).netloc, "example.test")
        self.assertEqual(parse_qs(urlsplit(safe).query), {"token": ["[REDACTED]"], "arbitrary": ["[REDACTED]"]})
        self.assertNotIn("OPAQUE_QUERY", sanitize_url("/items?OPAQUE_QUERY"))
        self.assertNotIn("OPAQUE_QUERY", sanitize_url("/items?OPAQUE_QUERY&sort=asc"))

    def test_encoded_pii_in_url_paths_and_known_encoded_secrets(self):
        safe = sanitize_url("https://example.test/users/alice%40example.net/profile")
        self.assertNoSecrets(safe, "alice", "example.net")
        self.assertIn("profile", safe)
        safe = sanitize_evidence({"url": "https://example.test/items/session%2fopaque"},
                                 secret_values=["session/opaque"])
        self.assertNoSecrets(safe, "opaque")

    def test_url_keys_and_error_text_cover_relative_urls(self):
        safe = sanitize_evidence({
            "errorURL": "https://example.test/items?anything=DEMO_QUERY_ONLY",
            "url": "/items?arbitrary=PRIVATE_PII",
            "error": "GET /items?unknown=DEMO_QUERY_ONLY failed; https://example.test?opaque=PRIVATE_PII",
        })
        self.assertNoSecrets(safe, "DEMO_QUERY_ONLY", "PRIVATE_PII")
        self.assertIn("failed", safe["error"])

    def test_whole_result_keeps_diagnostics_and_redacts_nested_raw_payload(self):
        safe = sanitize_evidence({
            "title": "Object authorization failure", "status": "CONFIRMED",
            "reason": "A foreign resource was returned despite anonymous denial.",
            "payload": {"title": "PRIVATE_DOCUMENT", "password": "PRIVATE_PASSWORD"},
            "requestPayload": "unstructured PRIVATE_RAW_PAYLOAD",
            "evidence": {"responseBody": '{"privateKey":"PRIVATE_KEY"}',
                         "body": "plain text PRIVATE_TEXT"},
        })
        self.assertEqual(safe["title"], "Object authorization failure")
        self.assertEqual(safe["status"], "CONFIRMED")
        self.assertIn("foreign resource", safe["reason"])
        self.assertNoSecrets(safe, "PRIVATE_DOCUMENT", "PRIVATE_PASSWORD", "PRIVATE_KEY", "PRIVATE_TEXT", "PRIVATE_RAW_PAYLOAD")

    def test_unstructured_json_scalar_body_is_omitted_by_default(self):
        body = json.dumps("Alice Sensitive with an unlabelled credential")
        safe = sanitize_body(body)
        self.assertIn(body_sha256(body), safe)
        self.assertNotIn("Alice Sensitive", safe)

    def test_explicit_sensitive_opt_in_preserves_small_values(self):
        value = {
            "privateKey": "PRIVATE_KEY", "title": "Document title",
            "body": "plaintext PRIVATE_PASSWORD",
            "errorURL": "https://user:PASS@example.test?token=TOKEN#FRAGMENT",
            "message": "Bearer SECRET alice@example.test",
        }
        self.assertEqual(sanitize_evidence(value, include_sensitive=True, secret_values=["SECRET"]), value)
        self.assertEqual(sanitize_url(value["errorURL"], include_sensitive=True), value["errorURL"])
        self.assertEqual(json.loads(sanitize_body('{"fullName":"Alice"}', include_sensitive=True)), {"fullName": "Alice"})

    def test_limits_cover_deep_wide_cyclic_and_large_inputs(self):
        cyclic = {"status": "ERROR"}
        cyclic["child"] = cyclic
        self.assertIn("DEPTH_LIMIT", json.dumps(sanitize_evidence(cyclic)))
        wide = {"rows": [{"message": "x" * 8000} for _ in range(1000)]}
        rendered = json.dumps(sanitize_evidence(wide))
        self.assertLess(len(rendered), MAX_TOTAL_TEXT_CHARS + 20000)
        self.assertIn("TRUNCATED", rendered)
        self.assertIn("ITEM_LIMIT", rendered)
        self.assertLess(len(sanitize_body(json.dumps(wide), max_chars=64)), 100)

    def test_marker_text_and_safe_diagnostics_are_not_mistaken_for_secrets(self):
        safe = sanitize_evidence({"status": "INCONCLUSIVE", "reason": "Authentication token is absent.",
                                  "message": "[REDACTED]", "rollback_verified": False})
        self.assertEqual(safe["status"], "INCONCLUSIVE")
        self.assertEqual(safe["reason"], "Authentication token is absent.")
        self.assertEqual(safe["message"], "[REDACTED]")
        self.assertFalse(safe["rollback_verified"])

    def test_pem_and_json_string_values_do_not_expose_secrets(self):
        pem = "-----BEGIN PRIVATE KEY-----\nPRIVATE_BYTES\n-----END PRIVATE KEY-----"
        safe = sanitize_body(json.dumps({"message": pem, "extra": json.dumps({"token": "INNER_TOKEN"})}))
        self.assertNoSecrets(safe, "PRIVATE_BYTES", "INNER_TOKEN")
        self.assertNotIn("TOKEN_VALUE", sanitize_text("Bearer TOKEN_VALUE"))


if __name__ == "__main__":
    unittest.main()
