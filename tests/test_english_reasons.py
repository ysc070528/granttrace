"""Machine-readable verdict reasons are English across all checks.

BOLA reasons from the response diff engine were Chinese while every other
check (authentication, BFLA, collections, BOPLA, mass assignment) reported
English, so JSON, SARIF and report consumers saw mixed languages. Chinese
denial messages returned by a target API must still be recognized.
"""

from __future__ import annotations

import itertools
import json
import re
import unittest

from core.diff import ResponseDiffEngine

CJK = re.compile(r"[　-〿㐀-䶿一-鿿＀-￯]")

OWNER = (200, json.dumps({"id": 1001, "owner": "alice", "balance": 9876.5, "email": "alice@example.test"}))
VISITOR_SELF = (200, json.dumps({"id": 2002, "owner": "bob", "balance": 12.25, "email": "bob@example.test"}))

RESPONSES = [
    OWNER,
    VISITOR_SELF,
    (200, json.dumps({"id": 1001, "owner": "alice"})),
    (200, json.dumps({"title": "public summary"})),
    (401, json.dumps({"error": "unauthorized"})),
    (403, ""),
    (403, json.dumps({"owner": "alice", "balance": 9876.5})),
    (404, json.dumps({"error": "not found"})),
    (409, json.dumps({"owner": "alice", "email": "alice@example.test", "balance": 9876.5})),
    (302, ""),
    (500, json.dumps({"error": "boom"})),
    (0, ""),
    ("bad", ""),
    (200, ""),
    (200, "<html>gateway</html>"),
    (200, "{}"),
    (200, json.dumps({"message": "无权访问"})),
    (200, json.dumps({"code": 401, "data": {"id": 1001}})),
    (200, json.dumps({"code": "40101"})),
    (200, json.dumps({"code": 500})),
    (200, json.dumps({"success": False})),
    (200, json.dumps({"success": "false"})),
    (200, json.dumps({"status": "error"})),
    (200, json.dumps({"error": "something went wrong"})),
    (200, json.dumps({"errors": [{"detail": "x"}]})),
    (200, json.dumps({"data": {"message": "权限不足"}})),
]


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _strings(key)
            yield from _strings(child)
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            yield from _strings(child)


class TestEnglishBolaReasons(unittest.TestCase):
    def test_response_classification_reasons_are_english(self) -> None:
        for status, body in RESPONSES:
            with self.subTest(status=status, body=body):
                result = ResponseDiffEngine.classify_response(status, body)  # type: ignore[arg-type]
                self.assertTrue(result["reason"])
                self.assertIsNone(CJK.search(result["reason"]), result["reason"])

    def test_chinese_denial_messages_are_still_recognized(self) -> None:
        for body in ({"message": "无权访问"}, {"data": {"message": "权限不足"}}, {"msg": "令牌已过期"}):
            with self.subTest(body=body):
                result = ResponseDiffEngine.classify_response(200, json.dumps(body, ensure_ascii=False))
                self.assertEqual(result["kind"], ResponseDiffEngine.RESPONSE_AUTH_DENIED)
                self.assertTrue(result["is_auth_denial"])

    def test_bola_verdict_reasons_and_evidence_are_english(self) -> None:
        reached = set()
        policies = [
            {},
            {"requires_auth": True},
            {"expected_public": True},
            {"resource_id_paths": ["id"]},
        ]
        selves = [None, VISITOR_SELF, (500, ""), OWNER]
        for visitor, anonymous in itertools.product(RESPONSES, repeat=2):
            for visitor_self, policy in itertools.product(selves, policies):
                result = ResponseDiffEngine.evaluate_bola(
                    OWNER, visitor, anonymous, visitor_self, **policy  # type: ignore[arg-type]
                )
                reached.add(result["verdict"])
                for text in _strings({"reason": result.get("reason"), "evidence": result.get("evidence")}):
                    # Response bodies echoed as evidence values may be Chinese;
                    # only the engine's own wording is checked here.
                    if text in ("无权访问", "权限不足"):
                        continue
                    self.assertIsNone(
                        CJK.search(text),
                        f"{text!r} for visitor={visitor} anonymous={anonymous} self={visitor_self} {policy}",
                    )
        # The matrix reaches every verdict family, so all reason branches are covered.
        self.assertGreaterEqual(len(reached), 5, reached)

    def test_invalid_owner_baseline_names_the_response_reason(self) -> None:
        result = ResponseDiffEngine.evaluate_bola((500, ""), OWNER, (401, ""))
        self.assertEqual(result["reason"], "Owner baseline is not valid: HTTP server error status 500")

    def test_confirmed_reason(self) -> None:
        result = ResponseDiffEngine.evaluate_bola(OWNER, OWNER, (401, ""), VISITOR_SELF, resource_id_paths=["id"])
        self.assertEqual(result["verdict"], "BOLA_CONFIRMED")
        self.assertEqual(
            result["reason"],
            "The Anonymous request was explicitly denied, while the unauthorized Visitor received "
            "concrete values or resource identifiers matching the Owner resource",
        )

    def test_resource_id_path_error_is_english(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            ResponseDiffEngine.evaluate_bola(OWNER, OWNER, (401, ""), resource_id_paths=[" "])
        self.assertIsNone(CJK.search(str(ctx.exception)))
        self.assertIn("resource_id_paths", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
