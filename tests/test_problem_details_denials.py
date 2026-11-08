"""RFC 9457 (RFC 7807) Problem Details bodies are recognized as clean denials.

connexion returns 401 and 403 as application/problem+json, and ASP.NET Core
and Spring can be configured to. A run against VAmPI, a deliberately vulnerable API,
missed its BOLA: the Visitor read the Owner's book, but the Anonymous 401 body
{"type": "about:blank", "title": "Unauthorized", "status": 401, "detail": "No
authorization token provided"} was treated as possible business data, so the
anonymous denial could not support a confirmation. A problem body is clean only
when every member is a standard one carrying a denial, never data.
"""

import json
import unittest

from core.diff import ResponseDiffEngine

OWNER = {"book_title": "owner-book", "owner": "alice", "secret": "alice-private-note"}
VISITOR_SELF = {"book_title": "visitor-book", "owner": "bob", "secret": "bob-private-note"}
VAMPI_401 = {"type": "about:blank", "title": "Unauthorized", "status": 401,
             "detail": "No authorization token provided"}


def clean(status, body):
    text = body if isinstance(body, str) else json.dumps(body)
    assessment = ResponseDiffEngine.assess_response(status, text)
    return ResponseDiffEngine.denial_body_is_clean(assessment, text)


class ProblemDetailsDenialTests(unittest.TestCase):
    def test_framework_problem_details_denials_are_clean(self):
        cases = {
            "connexion / VAmPI": (401, VAMPI_401),
            "ASP.NET Core 401": (401, {"type": "https://tools.ietf.org/html/rfc9110#section-15.5.2",
                                       "title": "Unauthorized", "status": 401,
                                       "traceId": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00"}),
            "ASP.NET Core 403": (403, {"type": "https://tools.ietf.org/html/rfc7231#section-6.5.3",
                                       "title": "Forbidden", "status": 403}),
            "Spring ProblemDetail": (403, {"type": "about:blank", "title": "Forbidden", "status": 403,
                                           "detail": "Access Denied"}),
            "status as text": (401, {"title": "Unauthorized", "status": "401"}),
        }
        for name, (status, body) in cases.items():
            with self.subTest(name):
                self.assertTrue(clean(status, body))

    def test_problem_details_carrying_data_or_unknown_content_are_not_clean(self):
        cases = {
            "business extension member": {**VAMPI_401, "owner": "alice"},
            "unknown extension member": {**VAMPI_401, "balance": 10},
            "explanatory detail": {**VAMPI_401, "detail": "Book owner-book belongs to alice"},
            "non-denial title": {**VAMPI_401, "title": "alice-private-note"},
            "non-denial status": {**VAMPI_401, "status": 404},
            "custom type URI": {**VAMPI_401, "type": "https://api.example.test/problems/user/1001"},
            # The body cannot tell the requested path from another user's resource.
            "instance naming a resource": {**VAMPI_401, "instance": "/books/alice-private-note"},
            "instance that is not a path": {**VAMPI_401, "instance": "alice@example.test"},
            "nested object": {**VAMPI_401, "errors": {"owner": "alice"}},
        }
        for name, body in cases.items():
            with self.subTest(name):
                self.assertFalse(clean(401, body))

    def test_numeric_denial_status_and_token_phrase_in_ordinary_envelopes(self):
        self.assertTrue(clean(401, {"status": 401, "error": "Unauthorized"}))
        self.assertTrue(clean(403, {"status": 403, "message": "Forbidden"}))
        self.assertTrue(clean(401, {"message": "No authorization token provided"}))
        self.assertTrue(clean(401, {"message": "no token provided"}))
        self.assertFalse(clean(401, {"status": 200, "error": "Unauthorized"}))
        self.assertFalse(clean(401, {"message": "No authorization token provided for alice"}))

    def test_vampi_bola_is_confirmed_behind_a_problem_details_denial(self):
        result = ResponseDiffEngine.evaluate_bola(
            (200, json.dumps(OWNER)), (200, json.dumps(OWNER)), (401, json.dumps(VAMPI_401)),
            visitor_self=(200, json.dumps(VISITOR_SELF)), requires_auth=True,
            resource_id_paths=["book_title"],
        )
        self.assertEqual("BOLA_CONFIRMED", result["verdict"], result["reason"])
        self.assertFalse(result["evidence"]["denial_body_conflict"])

    def test_problem_details_instance_naming_owner_data_is_not_secure(self):
        forbidden = {"title": "Forbidden", "status": 403, "instance": "/books/alice-private-note"}
        result = ResponseDiffEngine.evaluate_bola(
            (200, json.dumps(OWNER)), (403, json.dumps(forbidden)), (401, json.dumps(VAMPI_401)),
            visitor_self=(200, json.dumps(VISITOR_SELF)), requires_auth=True,
        )
        self.assertNotEqual("SECURE_ENFORCED", result["verdict"], result["reason"])

    def test_secure_problem_details_denials_stay_secure(self):
        result = ResponseDiffEngine.evaluate_bola(
            (200, json.dumps(OWNER)), (403, json.dumps({"title": "Forbidden", "status": 403})),
            (401, json.dumps(VAMPI_401)), visitor_self=(200, json.dumps(VISITOR_SELF)), requires_auth=True,
        )
        self.assertEqual("SECURE_ENFORCED", result["verdict"], result["reason"])


if __name__ == "__main__":
    unittest.main()
