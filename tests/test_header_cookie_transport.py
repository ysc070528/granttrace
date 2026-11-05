"""Business parameters must preserve transport framing and valid Cookie syntax."""

from __future__ import annotations

import threading
import unittest
from http.server import ThreadingHTTPServer

from core.models import Verdict
from core.parameters import ParameterSerializationError, serialize_header_parameter
from tests import test_header_cookie_parameters as helpers


INVALID_HEADER_VALUES = [
    f"HEADER_SECRET_{chr(code)}_END" for code in range(32) if code != 9
] + [
    "HEADER_SECRET_\x7f_END",
    "HEADER_SECRET_\x80_END",
    "HEADER_SECRET_\xe9_END",
    "HEADER_SECRET_\u4e2d_END",
    "HEADER_SECRET_\r\nInjected: value",
    "HEADER_SECRET_\r\n folded",
    "HEADER_SECRET_\r\n\tfolded",
]


class HeaderCookieTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), helpers.ParameterRecordingHandler)
        cls.target_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    @staticmethod
    def _as_swagger2(spec: dict) -> dict:
        spec.pop("openapi")
        spec["swagger"] = "2.0"
        spec.pop("components")
        spec["securityDefinitions"] = {
            "BearerAuth": {"type": "apiKey", "in": "header", "name": "Authorization"},
        }
        for item in spec["paths"].values():
            for parameter in item["get"]["parameters"]:
                parameter.update(parameter.pop("schema"))
        return spec

    def _assert_parameter_rejected(
        self, location: str, name: str, value: str, *, swagger2: bool = False,
    ) -> None:
        with helpers.ParameterRecordingHandler.lock:
            helpers.ParameterRecordingHandler.requests.clear()
        fixture = helpers.HeaderCookieParameterTests()
        fixture.target_url = self.target_url
        spec = fixture._make_spec([
            {"name": name, "in": location, "required": True, "schema": {"type": "string"}},
        ])
        if swagger2:
            spec = self._as_swagger2(spec)
        config = fixture._make_config(parameter_values={
            "GET /api/documents/{doc_id}": {"common": {name: value}},
        })
        auditor = fixture._run_audit(spec, config)
        self.assertEqual(helpers.ParameterRecordingHandler.requests, [])
        self.assertEqual(auditor.stats["transport_attempts"], 0)
        self.assertTrue(auditor.results)
        for result in auditor.results:
            self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE)
            self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
            self.assertEqual(result["evidence"]["requests_attempted"], 0)
            self.assertIn("no request was sent", result["reason"])
            self.assertNotIn("HEADER_SECRET", str(result))

    def test_header_scalar_invalid_characters_raise_before_serialization(self) -> None:
        for swagger2 in (True, False):
            parameter = {"name": "X-Probe", "in": "header"}
            parameter.update({"type": "string"} if swagger2 else {"schema": {"type": "string"}})
            for value in INVALID_HEADER_VALUES:
                with self.subTest(swagger2=swagger2, value=repr(value)):
                    with self.assertRaises(ParameterSerializationError) as raised:
                        serialize_header_parameter(parameter, value, swagger2=swagger2)
                    self.assertIn("no request was sent", str(raised.exception))
                    self.assertNotIn("HEADER_SECRET", str(raised.exception))

    def test_header_scalar_invalid_characters_rejected_before_transport(self) -> None:
        for swagger2 in (True, False):
            for value in INVALID_HEADER_VALUES:
                with self.subTest(swagger2=swagger2, value=repr(value)):
                    self._assert_parameter_rejected("header", "X-Probe", value, swagger2=swagger2)

    def test_header_scalar_legal_values_and_htab_preserve_wire_and_identities(self) -> None:
        for swagger2 in (True, False):
            for value in ("plain value", "left,right", "left\tright"):
                with self.subTest(swagger2=swagger2, value=repr(value)):
                    with helpers.ParameterRecordingHandler.lock:
                        helpers.ParameterRecordingHandler.requests.clear()
                    fixture = helpers.HeaderCookieParameterTests()
                    fixture.target_url = self.target_url
                    spec = fixture._make_spec([
                        {"name": "X-Probe", "in": "header", "required": True,
                         "schema": {"type": "string"}},
                    ])
                    if swagger2:
                        spec = self._as_swagger2(spec)
                    config = fixture._make_config(parameter_values={
                        "GET /api/documents/{doc_id}": {"common": {"X-Probe": value}},
                    })
                    auditor = fixture._run_audit(spec, config)
                    requests = helpers.ParameterRecordingHandler.requests
                    self.assertEqual(len(requests), 4)
                    self.assertEqual(auditor.stats["transport_attempts"], 4)
                    self.assertCountEqual(
                        [headers.get("Authorization", "") for _, _, headers in requests],
                        ["Bearer OWNER_TOKEN", "Bearer VISITOR_TOKEN", "Bearer VISITOR_TOKEN", ""],
                    )
                    for method, _, headers in requests:
                        self.assertEqual(method, "GET")
                        self.assertEqual(headers.get("X-Probe"), value)

    def test_business_headers_cannot_override_transport_headers(self) -> None:
        """Case variations cannot alter the target, body framing or built-in headers."""
        cases = [
            ("hOsT", "different-target.invalid"),
            ("cOnTeNt-LeNgTh", "5"),
            ("tRaNsFeR-EnCoDiNg", "chunked"),
            ("cOnNeCtIoN", "keep-alive"),
            ("uSeR-aGeNt", "different-agent"),
            ("aCcEpT-eNcOdInG", "gzip"),
        ]
        for name, value in cases:
            with self.subTest(name=name):
                self._assert_parameter_rejected("header", name, value)

    def test_invalid_cookie_octets_send_no_requests(self) -> None:
        """Invalid raw Cookie characters cannot corrupt subsequent cookie pairs."""
        values = [
            "value with spaces",
            '"unterminated',
            "value,other=1",
            "value\\other",
            "value\r\nInjected: evil",
            "value; injected=evil",
        ]
        for value in values:
            with self.subTest(value=value):
                self._assert_parameter_rejected("cookie", "theme", value)

    def test_authentication_cookie_compares_serialized_credentials(self) -> None:
        """Canonical scalar strings cannot hide equal Owner and Visitor cookies."""
        for owner_value, visitor_value in [(12345, "12345"), ("12345", 12345)]:
            with self.subTest(owner=owner_value, visitor=visitor_value):
                with helpers.ParameterRecordingHandler.lock:
                    helpers.ParameterRecordingHandler.requests.clear()
                fixture = helpers.HeaderCookieParameterTests()
                fixture.target_url = self.target_url
                spec = fixture._make_spec([
                    {"name": "session_token", "in": "cookie", "required": True,
                     "schema": {"type": "integer"}},
                ])
                config = fixture._make_config(parameter_values={
                    "GET /api/documents/{doc_id}": {
                        "owner": {"session_token": owner_value},
                        "visitor": {"session_token": visitor_value},
                    },
                })
                auditor = fixture._run_audit(spec, config)
                self.assertEqual(helpers.ParameterRecordingHandler.requests, [])
                self.assertEqual(auditor.stats["transport_attempts"], 0)
                self.assertTrue(auditor.results)
                for result in auditor.results:
                    self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE)
                    self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
                    self.assertEqual(result["evidence"]["requests_attempted"], 0)
                    self.assertIn("cannot share value with Owner", result["reason"])


if __name__ == "__main__":
    unittest.main()
