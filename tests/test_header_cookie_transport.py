"""Business parameters must preserve transport framing and valid Cookie syntax."""

from __future__ import annotations

import threading
import unittest
from http.server import ThreadingHTTPServer

from core.models import Verdict
from tests import test_header_cookie_parameters as helpers


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

    def _assert_parameter_rejected(self, location: str, name: str, value: str) -> None:
        with helpers.ParameterRecordingHandler.lock:
            helpers.ParameterRecordingHandler.requests.clear()
        fixture = helpers.HeaderCookieParameterTests()
        fixture.target_url = self.target_url
        spec = fixture._make_spec([
            {"name": name, "in": location, "required": True, "schema": {"type": "string"}},
        ])
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
