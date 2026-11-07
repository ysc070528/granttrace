"""Small correctness fixes found during review.

- An identity id used as a resource parameter is used exactly or not at all;
  it is never silently normalized or replaced by a specification example.
- Non-string media types in a specification do not crash parsing.
- Header values with surrounding whitespace are rejected, since servers strip it.
- BOPLA evaluation reuses response assessments without changing any decision.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.bopla import BOPLAEvidence
from core.models import HTTPResult, Verdict
from core.parameters import ParameterSerializationError, serialize_header_parameter
from core.parser import OpenAPIParser


def write_spec(directory: Path, spec: dict, name: str = "openapi.json") -> str:
    path = directory / name
    path.write_text(spec if isinstance(spec, str) else json.dumps(spec), encoding="utf-8")
    return str(path)


class IdentityResourceIdTests(unittest.TestCase):
    """Previously "007" became 7, "1_001" became 1001, and an id outside the
    schema (e.g. "abc" or below the minimum) was replaced by the spec's
    example 4242, testing a resource that is not the configured Owner's."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.spec = write_spec(self.directory, {
            "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
            "paths": {
                "/users/{user_id}": {"get": {
                    "parameters": [{"name": "user_id", "in": "path", "required": True,
                                    "schema": {"type": "integer", "minimum": 1}, "example": 4242}],
                    "responses": {"200": {"description": "ok"}}}},
                "/accounts/{account_id}": {"get": {
                    "parameters": [{"name": "account_id", "in": "path", "required": True,
                                    "schema": {"type": "string"}, "example": "acct-example"}],
                    "responses": {"200": {"description": "ok"}}}},
                "/orders": {"get": {
                    "parameters": [{"name": "order_id", "in": "query", "required": True,
                                    "schema": {"type": "integer"}, "example": 9},
                                   {"name": "page", "in": "query", "required": True,
                                    "schema": {"type": "integer"}, "example": 3}],
                    "responses": {"200": {"description": "ok"}}}},
            },
        })

    def auditor(self, owner_id, parameter_values=None) -> APISentinelAuditor:
        identities = {
            "owner": {"id": owner_id, "token": "Bearer OWNER"},
            "visitor": {"id": "2002", "token": "Bearer VISITOR"},
            "anonymous": {"id": None, "token": None},
        }
        return APISentinelAuditor(self.spec, "http://127.0.0.1:9", request_delay=0,
                                  identities_config=identities, parameter_values=parameter_values)

    @staticmethod
    def endpoint(auditor: APISentinelAuditor, path: str) -> dict:
        return next(ep for ep in auditor.parser.get_endpoints() if ep["path"] == path)

    def test_canonical_ids_are_used_exactly(self) -> None:
        for owner_id, path, expected in (("1001", "/users/{user_id}", "/users/1001"),
                                         (1001, "/users/{user_id}", "/users/1001"),
                                         (1001, "/accounts/{account_id}", "/accounts/1001"),
                                         ("acct 7", "/accounts/{account_id}", "/accounts/acct%207")):
            with self.subTest(owner_id=owner_id, path=path):
                auditor = self.auditor(owner_id)
                self.assertTrue(auditor._build_url(self.endpoint(auditor, path), "owner").endswith(expected))

    def test_non_canonical_or_invalid_ids_are_refused(self) -> None:
        for owner_id in ("007", "1_001", " 1002 ", "+5", "abc", "0", "1001.0", True):
            with self.subTest(owner_id=owner_id):
                auditor = self.auditor(owner_id)
                with self.assertRaisesRegex(ParameterSerializationError, "no request was sent"):
                    auditor._build_url(self.endpoint(auditor, "/users/{user_id}"), "owner")

    def test_query_resource_identifiers_follow_the_same_rule(self) -> None:
        auditor = self.auditor("1001")
        self.assertTrue(auditor._build_url(self.endpoint(auditor, "/orders"), "owner").endswith(
            "/orders?order_id=1001&page=3"))  # A non-resource parameter still uses the schema example.
        auditor = self.auditor("007")
        with self.assertRaises(ParameterSerializationError):
            auditor._build_url(self.endpoint(auditor, "/orders"), "owner")

    def test_explicit_parameter_values_take_precedence(self) -> None:
        auditor = self.auditor("abc", parameter_values={"GET /users/{user_id}": {"owner": {"user_id": 55}}})
        self.assertTrue(auditor._build_url(self.endpoint(auditor, "/users/{user_id}"), "owner").endswith("/users/55"))

    def test_audit_records_inconclusive_without_requests(self) -> None:
        auditor = self.auditor("abc")
        auditor._audit_endpoint_bola(self.endpoint(auditor, "/users/{user_id}"))
        [result] = auditor.results
        self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE.value)
        self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
        self.assertEqual(result["evidence"]["requests_attempted"], 0)
        self.assertEqual(auditor.stats["transport_attempts"], 0)


class MediaTypeTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def test_swagger2_consumes_with_non_string_entry(self) -> None:
        # Previously: AttributeError: 'int' object has no attribute 'split'.
        spec = write_spec(self.directory, {
            "swagger": "2.0", "info": {"title": "t", "version": "1"}, "consumes": [123, "application/json"],
            "paths": {"/u/{id}": {"patch": {"parameters": [
                {"name": "id", "in": "path", "required": True, "type": "string"},
                {"name": "body", "in": "body", "schema": {"type": "object", "properties": {"role": {"type": "string"}}}}],
                "responses": {"200": {"description": "ok"}}}}}})
        [endpoint] = OpenAPIParser(spec).get_endpoints()
        self.assertEqual(endpoint["request_content_type"], "application/json")
        self.assertEqual(endpoint["request_content_types"], ["application/json"])

    def test_openapi_content_with_non_string_key(self) -> None:
        spec = write_spec(self.directory, (
            "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /u:\n    patch:\n"
            "      requestBody:\n        content:\n          1: {schema: {type: string}}\n"
            "          application/json: {schema: {type: object, properties: {role: {type: string}}}}\n"
            "      responses: {'200': {description: ok}}\n"), "openapi.yaml")
        [endpoint] = OpenAPIParser(spec).get_endpoints()
        self.assertEqual(endpoint["request_content_type"], "application/json")
        self.assertEqual(endpoint["request_content_types"], ["application/json"])


class HeaderWhitespaceTests(unittest.TestCase):
    """Servers strip surrounding whitespace (RFC 9110 5.5), inconsistently: a
    test server received '  acct-1001\\t' as 'acct-1001\\t'."""

    META = {"name": "X-Account", "in": "header", "schema": {"type": "string"}}

    def test_surrounding_whitespace_is_rejected(self) -> None:
        cases = [
            (self.META, "  acct-1001"), (self.META, "acct-1001\t"),
            ({"name": "X-List", "in": "header", "schema": {"type": "array", "items": {"type": "string"}}}, ["a", " b"]),
            ({"name": "X-Obj", "in": "header", "schema": {"type": "object"}}, {"k": "v "}),
            ({"name": "X-Obj", "in": "header", "schema": {"type": "object"}}, {" k": "v"}),
        ]
        for metadata, value in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ParameterSerializationError, "whitespace"):
                    serialize_header_parameter(metadata, value)

    def test_swagger2_header_is_rejected_too(self) -> None:
        with self.assertRaisesRegex(ParameterSerializationError, "whitespace"):
            serialize_header_parameter({"name": "X-Account", "in": "header", "type": "string"}, " a", swagger2=True)

    def test_inner_whitespace_and_plain_values_still_work(self) -> None:
        self.assertEqual(serialize_header_parameter(self.META, "acct 1001"), ("X-Account", "acct 1001"))
        self.assertEqual(serialize_header_parameter(self.META, "acct-1001"), ("X-Account", "acct-1001"))


class BOPLAAssessmentReuseTests(unittest.TestCase):
    def setUp(self) -> None:
        owner_doc = {"id": "1001", "tenant": "t1", **{f"secret{j}": f"owner-{j}" for j in range(4)}}
        self.owner = HTTPResult(200, json.dumps(owner_doc))
        self.responses = {
            "leak": HTTPResult(200, json.dumps(owner_doc)),
            "denied": HTTPResult(403, json.dumps({"error": "forbidden"})),
            "other": HTTPResult(200, json.dumps({**owner_doc, "secret0": "different"})),
            "broken": HTTPResult(200, "not json"),
        }
        self.policy = {"policy_id": "p1", "context_id": "c1", "resource_binding": {"id": "1001", "tenant": "t1"},
                       "fields": [{"rule_id": f"r{j}", "path": f"secret{j}", "baseline_representation": "full_private_value",
                                   "value_is_resource_specific": True,
                                   "access": {"owner": "allow", "visitor": "deny" if j % 2 else "allow", "anonymous": "deny"}}
                                  for j in range(4)]}

    def test_shared_assessments_give_identical_decisions_with_fewer_parses(self) -> None:
        for name, other in self.responses.items():
            with self.subTest(response=name):
                cache: dict = {}
                with patch.object(BOPLAEvidence, "_assess", wraps=BOPLAEvidence._assess) as counted:
                    for rule in self.policy["fields"]:
                        for identity in ("visitor", "anonymous"):
                            plain = BOPLAEvidence.evaluate(self.owner, other, policy=self.policy, field=rule,
                                                           identity=identity, visitor_self=self.owner)
                            calls_before = counted.call_count
                            shared = BOPLAEvidence.evaluate(self.owner, other, policy=self.policy, field=rule,
                                                            identity=identity, visitor_self=self.owner, assessments=cache)
                            self.assertEqual(json.dumps(plain, default=str, sort_keys=True),
                                             json.dumps(shared, default=str, sort_keys=True))
                            self.assertLessEqual(counted.call_count - calls_before, 2)
                    # Two distinct responses: each is assessed once across all fields and identities.
                    self.assertEqual(len(cache), 2)

    def test_cache_never_confuses_distinct_results(self) -> None:
        cache: dict = {}
        rule = self.policy["fields"][1]
        leaked = BOPLAEvidence.evaluate(self.owner, self.responses["leak"], policy=self.policy, field=rule,
                                        identity="visitor", assessments=cache)
        denied = BOPLAEvidence.evaluate(self.owner, self.responses["denied"], policy=self.policy, field=rule,
                                        identity="visitor", assessments=cache)
        self.assertEqual(leaked["verdict"], Verdict.CONFIRMED)
        self.assertEqual(denied["verdict"], Verdict.SECURE)


if __name__ == "__main__":
    unittest.main()
