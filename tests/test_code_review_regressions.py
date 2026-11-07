"""Regressions found during a line-by-line code review.

Each test pins one behaviour that previously relied on an implementation
accident: secret publication across worker threads, an error message that was
swallowed by its own exception handler, and response classification reuse.
"""

from __future__ import annotations

import json
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from core.auditor import APISentinelAuditor
from core.diff import ResponseDiffEngine
from core.parameters import ParameterSerializationError, normalize_parameter_value
from core.remote_refs import PinnedIPHTTPSConnection, _verified_tls_context


IDENTITIES = {
    "owner": {"id": "1001", "token": "Bearer OWNER_TOKEN", "parameters": {"id": "doc-owner"}},
    "visitor": {"id": "1002", "token": "Bearer VISITOR_TOKEN", "parameters": {"id": "doc-visitor"}},
    "anonymous": {"id": None, "token": None, "parameters": {}},
}


def _spec_with_secret_header_default(directory: Path) -> Path:
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "review", "version": "1"},
        "paths": {
            "/api/documents/{id}": {
                "get": {
                    "operationId": "getDocument",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                        # Not an authentication header, but a sensitive name whose
                        # spec default is only learned while building a request.
                        {"name": "X-Secret", "in": "header", "required": False,
                         "schema": {"type": "string", "default": "spec-default-secret-value"}},
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    path = directory / "openapi.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


class SecretPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        spec = _spec_with_secret_header_default(Path(self.directory.name))
        self.auditor = APISentinelAuditor(
            str(spec), "http://127.0.0.1:9", request_delay=0, identities_config=IDENTITIES,
        )
        self.endpoint = next(ep for ep in self.auditor.parser.get_endpoints() if ep["method"] == "GET")

    def test_request_headers_never_mutate_a_published_secret_snapshot(self) -> None:
        # Other workers iterate the published set without a lock, and
        # _read_observation replaces it atomically. An in-place add can
        # raise "Set changed size during iteration" or land in a stale set.
        published = self.auditor._secret_values
        before = frozenset(published)
        self.assertNotIn("spec-default-secret-value", before)

        headers = self.auditor._build_request_headers(self.endpoint, "owner", "owner")

        self.assertEqual(headers["X-Secret"], "spec-default-secret-value")
        self.assertEqual(frozenset(published), before)
        self.assertIn("spec-default-secret-value", self.auditor._secret_values)

    def test_concurrent_header_building_keeps_every_discovered_secret(self) -> None:
        errors = []

        def build() -> None:
            try:
                for _ in range(50):
                    self.auditor._build_request_headers(self.endpoint, "owner", "visitor")
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

        workers = [threading.Thread(target=build) for _ in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(errors, [])
        self.assertIn("spec-default-secret-value", self.auditor._secret_values)


class NumberNormalizationMessageTests(unittest.TestCase):
    def test_precision_loss_reports_its_own_reason(self) -> None:
        # "1.10" parses as 1.1; the specific diagnostic used to be replaced
        # by the generic handler because ParameterSerializationError is a
        # ValueError raised inside the same try block.
        with self.assertRaisesRegex(ParameterSerializationError, "without precision loss"):
            normalize_parameter_value({"in": "query", "name": "n", "schema": {"type": "number"}}, "1.10")

    def test_non_finite_number_reports_precision_reason(self) -> None:
        with self.assertRaisesRegex(ParameterSerializationError, "native wire representation"):
            normalize_parameter_value({"in": "query", "name": "n", "schema": {"type": "number"}}, "1e999")

    def test_integer_too_large_for_float_fails_closed(self) -> None:
        with self.assertRaisesRegex(ParameterSerializationError, "cannot be represented safely"):
            normalize_parameter_value({"in": "query", "name": "n", "schema": {"type": "number"}}, "1" + "0" * 400)

    def test_canonical_number_is_still_normalized(self) -> None:
        self.assertEqual(
            normalize_parameter_value({"in": "query", "name": "n", "schema": {"type": "number"}}, "1.5"), 1.5,
        )


class ResponseAssessmentTests(unittest.TestCase):
    def test_success_classifications_are_unchanged_by_single_parse(self) -> None:
        cases = {
            (200, '{"id": 1, "name": "x"}'): ResponseDiffEngine.RESPONSE_VALID,
            (200, ""): ResponseDiffEngine.RESPONSE_EMPTY,
            (200, "   "): ResponseDiffEngine.RESPONSE_EMPTY,
            (200, "null"): ResponseDiffEngine.RESPONSE_EMPTY,
            (200, "{}"): ResponseDiffEngine.RESPONSE_EMPTY,
            (200, "not json"): ResponseDiffEngine.RESPONSE_INVALID,
            (200, '{"v": NaN}'): ResponseDiffEngine.RESPONSE_INVALID,
            (200, '{"error": "boom"}'): ResponseDiffEngine.RESPONSE_APPLICATION_ERROR,
            (200, '{"code": 401}'): ResponseDiffEngine.RESPONSE_AUTH_DENIED,
            (401, '{"id": 1}'): ResponseDiffEngine.RESPONSE_AUTH_DENIED,
            (404, "not json"): ResponseDiffEngine.RESPONSE_HTTP_CLIENT_ERROR,
        }
        for (status, body), kind in cases.items():
            with self.subTest(status=status, body=body):
                self.assertEqual(ResponseDiffEngine.assess_response(status, body)["kind"], kind)
        self.assertEqual(ResponseDiffEngine.assess_response(401, '{"id": 1}')["data"], {"id": 1})
        self.assertIsNone(ResponseDiffEngine.assess_response(404, "not json")["data"])

    def test_structure_similarity_matches_public_helper(self) -> None:
        owner = json.dumps({"data": {"id": "1", "items": [{"a": 1, "b": 2}], "note": "o"}})
        visitor = json.dumps({"data": {"id": "1", "items": [{"a": 1}], "extra": True}})
        result = ResponseDiffEngine.evaluate_bola((200, owner), (200, visitor), (401, '{"error": "unauthorized"}'))
        expected = round(ResponseDiffEngine.calculate_jaccard_similarity(owner, visitor), 6)
        self.assertEqual(result["evidence"]["structure_similarity"], expected)
        self.assertEqual(result["similarity"], expected)


class RemoteReferenceTLSTests(unittest.TestCase):
    def test_default_contexts_require_tls_1_2_with_verification(self) -> None:
        # Python 3.9's create_default_context still permits TLS 1.0/1.1.
        connection = PinnedIPHTTPSConnection(pinned_ip="192.0.2.1", target_hostname="schemas.example.com")
        for context in (_verified_tls_context(), connection.ssl_ctx):
            with self.subTest(context=context):
                self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(context.check_hostname)


if __name__ == "__main__":
    unittest.main()
