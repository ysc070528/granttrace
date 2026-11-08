"""Optional query parameters nobody configured are not sent with invented values.

A generated value such as as_user=sample_text, status=active or
include_deleted=false can make the target filter out the resource, reject the
request or change its behavior, so the comparison no longer measures
authorization. The checklist tells users to fill optional query parameters
deliberately; header and cookie parameters already follow this rule.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlsplit

from core.auditor import APISentinelAuditor

OPERATION = "GET /documents/{doc_id}"


class UnconfiguredQueryParameterTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def build(self, query: List[Dict[str, Any]], values: Dict[str, Any], *, swagger2: bool = False) -> Dict[str, str]:
        path_parameter: Dict[str, Any] = {"name": "doc_id", "in": "path", "required": True}
        if swagger2:
            path_parameter["type"] = "integer"
            spec: Dict[str, Any] = {"swagger": "2.0", "info": {"title": "t", "version": "1"}}
        else:
            path_parameter["schema"] = {"type": "integer"}
            spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}}
        spec["paths"] = {"/documents/{doc_id}": {"get": {
            "parameters": [path_parameter, *query], "responses": {"200": {"description": "ok"}}}}}
        spec_file = self.folder / "spec.json"
        spec_file.write_text(json.dumps(spec), encoding="utf-8")
        auditor = APISentinelAuditor(
            spec_path=str(spec_file), target_base_url="http://127.0.0.1:9", allow_http=True,
            identities_config={
                "owner": {"id": "1001", "token": "Bearer owner-test"},
                "visitor": {"id": "1002", "token": "Bearer visitor-test"},
                "anonymous": {"id": None, "token": None},
            },
            parameter_values={OPERATION: {"owner": {"doc_id": 11, **values}, "visitor": {"doc_id": 22}}},
        )
        (endpoint,) = auditor.parser.get_endpoints()
        return dict(parse_qsl(urlsplit(auditor._build_url(endpoint, "owner")).query))

    def test_optional_parameters_without_value_or_default_are_not_sent(self) -> None:
        query = self.build([
            {"name": "include_deleted", "in": "query", "schema": {"type": "boolean"}},
            {"name": "as_user", "in": "query", "schema": {"type": "string"}},
            {"name": "status", "in": "query", "schema": {"type": "string", "enum": ["active", "archived"]}},
            {"name": "fields", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}},
            {"name": "sort", "in": "query", "schema": {"type": "string", "example": "-created"}},
        ], {})
        self.assertEqual(query, {})

    def test_optional_parameter_with_a_default_sends_the_default(self) -> None:
        query = self.build([{"name": "limit", "in": "query", "schema": {"type": "integer", "default": 20}}], {})
        self.assertEqual(query, {"limit": "20"})

    def test_swagger2_optional_parameter_follows_the_same_rule(self) -> None:
        query = self.build([
            {"name": "status", "in": "query", "type": "string", "enum": ["active", "archived"]},
            {"name": "limit", "in": "query", "type": "integer", "default": 50},
        ], {}, swagger2=True)
        self.assertEqual(query, {"limit": "50"})

    def test_configured_optional_parameter_is_sent(self) -> None:
        query = self.build([{"name": "status", "in": "query", "schema": {"type": "string"}}], {"status": "archived"})
        self.assertEqual(query, {"status": "archived"})

    def test_optional_resource_identifier_still_takes_the_identity_id(self) -> None:
        query = self.build([{"name": "owner_id", "in": "query", "schema": {"type": "string"}}], {})
        self.assertEqual(query, {"owner_id": "1001"})

    def test_required_parameter_without_value_is_still_generated(self) -> None:
        query = self.build([
            {"name": "view", "in": "query", "required": True, "schema": {"type": "string", "enum": ["full", "summary"]}},
        ], {})
        self.assertEqual(query, {"view": "full"})


if __name__ == "__main__":
    unittest.main()
