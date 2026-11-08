"""bola.<operation>.not_found_is_denial: an opt-in to read a 404 as a denial.

Some APIs hide another user's object with 404 instead of 403. Secure-mode VAmPI
looks books up by title and owner, so the Visitor's request for the Owner's book
gets {"status": "fail", "message": "Book not found!"} and GrantTrace reports
INCONCLUSIVE: by default a 404 can just as well mean a wrong parameter value.

The opt-in accepts a 404 as a denial only when the Owner received a valid
response for the same request, the body is a recognizable "not found" envelope,
and no Owner value appears in it. Every other 404 keeps its default meaning.
"""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.authorization import AuthorizationEvidence
from core.config_validator import ConfigValidator
from core.diff import ResponseDiffEngine
from core.models import HTTPResult

ROOT = Path(__file__).resolve().parents[1]

OWNER = {"book_title": "owner-book", "owner": "alice", "secret": "alice-private-note"}
VISITOR_SELF = {"book_title": "visitor-book", "owner": "bob", "secret": "bob-private-note"}
VAMPI_404 = {"status": "fail", "message": "Book not found!"}
VAMPI_401 = {"type": "about:blank", "title": "Unauthorized", "status": 401,
             "detail": "No authorization token provided"}


def body(value):
    return value if isinstance(value, str) else json.dumps(value)


def bola(visitor, anonymous=(401, VAMPI_401), owner=(200, OWNER), **options):
    return ResponseDiffEngine.evaluate_bola(
        (owner[0], body(owner[1])), (visitor[0], body(visitor[1])), (anonymous[0], body(anonymous[1])),
        visitor_self=(200, body(VISITOR_SELF)), requires_auth=True, resource_id_paths=["book_title"],
        **options,
    )


class NotFoundDenialEngineTests(unittest.TestCase):
    def test_default_keeps_a_404_inconclusive(self):
        result = bola((404, VAMPI_404))
        self.assertEqual("INCONCLUSIVE", result["verdict"])
        self.assertNotIn("not_found_is_denial", result["evidence"])  # Reports without the opt-in are unchanged.

    def test_opt_in_reads_vampi_404_as_a_denial(self):
        result = bola((404, VAMPI_404), not_found_is_denial=True)
        self.assertEqual("SECURE_ENFORCED", result["verdict"], result["reason"])
        self.assertEqual(0.95, result["confidence"])  # Below an explicit 401 / 403.
        self.assertIn("not_found_is_denial", result["reason"])
        self.assertTrue(result["evidence"]["not_found_is_denial"])
        visitor = result["evidence"]["responses"]["visitor_cross"]
        self.assertEqual((404, "AUTH_DENIED"), (visitor["status_code"], visitor["kind"]))

    def test_common_not_found_bodies_are_denials(self):
        bodies = {
            "empty body": "",
            "plain text": "Not Found",
            "Django REST framework": {"detail": "Not found."},
            "error and numeric status": {"error": "Not Found", "status": 404},
            "code and message": {"code": 404, "message": "Resource not found"},
            "requested resource": {"message": "The requested resource was not found"},
            "does not exist": {"error": "Record does not exist"},
            "Problem Details": {"type": "about:blank", "title": "Not Found", "status": 404,
                                "detail": "Book not found"},
            "Chinese": {"code": "404", "msg": "资源不存在"},
        }
        for name, value in bodies.items():
            with self.subTest(name):
                result = bola((404, value), not_found_is_denial=True)
                self.assertEqual("SECURE_ENFORCED", result["verdict"], result["reason"])

    def test_404_that_may_carry_data_is_never_a_denial(self):
        bodies = {
            "business member": {**VAMPI_404, "owner": "alice"},
            "Owner value as the noun": {"message": "alice not found"},
            "requested value echoed": {"message": "Book owner-book not found"},
            "explanation": {"message": "Book not found because it belongs to alice"},
            "HTML page": "<html><title>404 Not Found</title><p>owner-book</p></html>",
            "unknown member": {"message": "Not found", "path": "/books/v1/owner-book"},
            "Problem Details instance": {"title": "Not Found", "status": 404, "instance": "/books/alice"},
            "Owner value in an array": {"errors": ["Not found", "alice"]},
        }
        for name, value in bodies.items():
            with self.subTest(name):
                result = bola((404, value), not_found_is_denial=True)
                self.assertNotEqual("SECURE_ENFORCED", result["verdict"], result["reason"])

    def test_only_a_404_after_a_valid_owner_baseline_is_read_as_a_denial(self):
        for name, visitor, owner in (
            ("Owner also got 404", (404, VAMPI_404), (404, VAMPI_404)),
            ("Owner got an empty list", (404, VAMPI_404), (200, [])),
            ("410 Gone", (410, VAMPI_404), (200, OWNER)),
            ("400 Bad Request", (400, {"message": "Bad request"}), (200, OWNER)),
        ):
            with self.subTest(name):
                result = bola(visitor, owner=owner, not_found_is_denial=True)
                self.assertEqual("INCONCLUSIVE", result["verdict"], result["reason"])

    def test_anonymous_404_serves_as_the_denial_baseline(self):
        anonymous = (404, {"detail": "Not found."})
        self.assertEqual("INCONCLUSIVE", bola((200, OWNER), anonymous=anonymous)["verdict"])
        confirmed = bola((200, OWNER), anonymous=anonymous, not_found_is_denial=True)
        self.assertEqual("BOLA_CONFIRMED", confirmed["verdict"], confirmed["reason"])
        secure = bola((404, VAMPI_404), anonymous=anonymous, not_found_is_denial=True)
        self.assertEqual("SECURE_ENFORCED", secure["verdict"], secure["reason"])

    def test_opt_in_never_hides_owner_data_returned_with_200(self):
        result = bola((200, OWNER), not_found_is_denial=True)
        self.assertEqual("BOLA_CONFIRMED", result["verdict"])

    def test_missing_body_is_an_empty_denial(self):
        visitor = ResponseDiffEngine.assess_response(404, None)
        owner = ResponseDiffEngine.assess_response(200, body(OWNER))
        self.assertEqual("AUTH_DENIED", ResponseDiffEngine.not_found_as_denial(visitor, None, owner)["kind"])

    def test_not_found_messages_are_not_authentication_denials_by_default(self):
        assessment = ResponseDiffEngine.assess_response(401, body({"message": "Book not found"}))
        self.assertFalse(ResponseDiffEngine.denial_body_is_clean(assessment, body({"message": "Book not found"})))


def result(status, value):
    return HTTPResult(status, body(value))


class NotFoundDenialReadCheckTests(unittest.TestCase):
    """Broken Authentication, BFLA and collection checks of the same operation."""

    def test_broken_authentication(self):
        owner, anonymous = result(200, OWNER), result(404, {"detail": "Not found."})
        default = AuthorizationEvidence.evaluate_auth(owner, anonymous, requires_auth=True)
        self.assertEqual("INCONCLUSIVE", default["verdict"])
        opted = AuthorizationEvidence.evaluate_auth(owner, anonymous, requires_auth=True, not_found_is_denial=True)
        self.assertEqual("SECURE", opted["verdict"], opted["reason"])
        self.assertTrue(opted["evidence"]["not_found_is_denial"])

    def test_function_level_authorization(self):
        roles = {"required_role": "admin", "owner_role": "admin", "visitor_role": "reader"}
        owner, visitor, anonymous = result(200, OWNER), result(404, VAMPI_404), result(401, VAMPI_401)
        default = AuthorizationEvidence.evaluate_bfla(owner, visitor, anonymous, role_policy=roles)
        self.assertEqual("INCONCLUSIVE", default["verdict"])
        opted = AuthorizationEvidence.evaluate_bfla(
            owner, visitor, anonymous, role_policy=dict(roles, not_found_is_denial=True))
        self.assertEqual("SECURE", opted["verdict"], opted["reason"])

    def test_collection(self):
        owner = result(200, {"items": [OWNER]})
        visitor, anonymous = result(404, {"detail": "Not found."}), result(401, VAMPI_401)
        policy = {"private_data_paths": ["items[0].secret"]}
        default = AuthorizationEvidence.evaluate_collection(owner, visitor, anonymous, policy=policy)
        self.assertEqual("INCONCLUSIVE", default["verdict"])
        opted = AuthorizationEvidence.evaluate_collection(
            owner, visitor, anonymous, policy=dict(policy, not_found_is_denial=True))
        self.assertEqual("SECURE", opted["verdict"], opted["reason"])


class NotFoundDenialConfigurationTests(unittest.TestCase):
    def test_validator_accepts_only_a_boolean(self):
        for value in (True, False):
            with self.subTest(value=value):
                outcome = ConfigValidator.validate({"bola": {"GET /books/{id}": {"not_found_is_denial": value}}})
                self.assertFalse(
                    [issue for issue in outcome.errors if "not_found_is_denial" in issue.path], outcome.errors)
        for value in ("true", 1, None, [], {}):
            with self.subTest(value=value):
                outcome = ConfigValidator.validate({"bola": {"GET /books/{id}": {"not_found_is_denial": value}}})
                self.assertTrue(any("not_found_is_denial" in issue.path for issue in outcome.errors))

    def test_schema_declares_the_setting(self):
        schema = json.loads((ROOT / "config.schema.json").read_text(encoding="utf-8"))
        entry = schema["definitions"]["bola_entry"]["properties"]["not_found_is_denial"]
        self.assertEqual("boolean", entry["type"])

    def scan(self, policy):
        auditor = APISentinelAuditor(
            str(ROOT / "openapi.json"), "http://127.0.0.1:8080", request_delay=0,
            bola_config={"GET /api/users/{user_id}/profile": policy},
        )
        endpoint = next(ep for ep in auditor.parser.get_endpoints() if ep["path"] == "/api/users/{user_id}/profile")

        def response(method, url, data=None, identity_name="owner", **kwargs):
            if identity_name == "anonymous":
                return HTTPResult(401, json.dumps({"error": "Unauthorized"}))
            if identity_name == "visitor" and "/1002/" in url:
                return HTTPResult(200, json.dumps({"id": "1002", "title": "Visitor data", "private_note": "Visitor note"}))
            if identity_name == "visitor":
                return HTTPResult(404, json.dumps({"status": "fail", "message": "Profile not found"}))
            return HTTPResult(200, json.dumps({"id": "1001", "title": "Owner data", "private_note": "Owner note"}))

        with patch.object(auditor, "_http_request", side_effect=response):
            auditor.audit_endpoint_bola(endpoint)
        return auditor.results[0]

    def test_scan_applies_the_operation_policy(self):
        self.assertEqual("INCONCLUSIVE", self.scan({})["verdict"])
        record = self.scan({"not_found_is_denial": True})
        self.assertEqual("SECURE", record["verdict"], record["reason"])
        self.assertTrue(record["evidence"]["decision_evidence"]["not_found_is_denial"])


if __name__ == "__main__":
    unittest.main()
