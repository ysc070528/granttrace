"""core.transport: the HTTP layer the auditor sends every request through.

The transport was split out of the auditor without behavior changes. These
tests pin its contract directly: redirects are returned rather than followed,
responses are cut at the size limit, a failed request never raises, and the
accounting hooks run only when a request really leaves. They also check that
the auditor still has a single entry point, so a test that replaces
``_http_request`` cannot reach the network through another path.
"""

from __future__ import annotations

import ast
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import List
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.models import HTTPResult
from core.transport import HttpTransport

ROOT = Path(__file__).resolve().parents[1]


class _Handler(BaseHTTPRequestHandler):
    hits: List[str] = []

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        self.hits.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"x" * 5000 if self.path == "/large" else json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _transport(**overrides: object) -> HttpTransport:
    settings = {"request_delay": 0.0, "request_timeout": 3.0, "max_response_bytes": 1024, "insecure_ssl": False}
    settings.update(overrides)
    return HttpTransport(**settings)  # type: ignore[arg-type]


class HttpTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        _Handler.hits = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def test_redirect_is_returned_not_followed(self) -> None:
        result = _transport().send("GET", self.base + "/redirect", {"authorization": "Bearer T"})
        self.assertEqual(result.status, 302)
        self.assertEqual(_Handler.hits, ["/redirect"])

    def test_response_is_cut_at_the_size_limit(self) -> None:
        result = _transport(max_response_bytes=1024).send("GET", self.base + "/large", {})
        self.assertEqual((result.status, len(result.body), result.truncated), (200, 1024, True))

    def test_hooks_run_once_per_request_that_leaves(self) -> None:
        events: List[str] = []
        result = _transport().send(
            "GET", self.base + "/ok", {},
            on_attempt=lambda: events.append("attempt"), on_response=lambda: events.append("response"),
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(events, ["attempt", "response"])

    def test_failures_return_a_result_instead_of_raising(self) -> None:
        events: List[str] = []
        invalid = _transport().send("GET", "not-a-url", {}, on_attempt=lambda: events.append("attempt"))
        self.assertEqual(invalid.status, 0)
        self.assertTrue(invalid.error.startswith("ValueError: "))
        self.assertEqual(events, [], "a request that cannot be built is not an attempt")

        refused = _transport().send("GET", "http://127.0.0.1:9/", {}, on_attempt=lambda: events.append("attempt"))
        self.assertEqual(refused.status, 0)
        self.assertIsNotNone(refused.error)
        self.assertEqual(events, ["attempt"])

        unencodable = _transport().send("PATCH", self.base + "/ok", {}, data={"value": float("nan")})
        self.assertEqual(unencodable.status, 0)
        self.assertTrue(unencodable.error.startswith("ValueError: "))

    def test_default_headers_can_be_overridden(self) -> None:
        transport = _transport()
        with patch.object(transport.opener, "open", side_effect=OSError("stop")) as opener:
            transport.send("PATCH", self.base + "/ok", {"accept": "text/plain"}, data={"a": 1})
        request = opener.call_args.args[0]
        self.assertEqual(request.get_header("Accept"), "text/plain")
        self.assertTrue(request.get_header("User-agent").startswith("GrantTrace/"))
        self.assertEqual(request.get_header("Content-type"), "application/json")


class SingleEntryPointTests(unittest.TestCase):
    def test_only_send_http_request_reaches_the_transport(self) -> None:
        tree = ast.parse((ROOT / "core" / "auditor.py").read_text(encoding="utf-8"))
        watched = {("_transport", "send"), ("self", "_send_http_request"), ("_transport", "opener")}
        callers: dict = {}
        for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            for method in (item for item in cls.body if isinstance(item, ast.FunctionDef)):
                for node in ast.walk(method):
                    if not isinstance(node, ast.Attribute):
                        continue
                    if isinstance(node.value, ast.Attribute):
                        owner = node.value.attr
                    elif isinstance(node.value, ast.Name):
                        owner = node.value.id
                    else:
                        continue
                    if (owner, node.attr) in watched:
                        callers.setdefault(f"{owner}.{node.attr}", set()).add(method.name)
        self.assertEqual(callers, {
            "_transport.send": {"_send_http_request"},
            "self._send_http_request": {"_http_request"},
        })

    def test_replacing_http_request_keeps_a_scan_off_the_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = Path(directory) / "openapi.json"
            spec.write_text((ROOT / "openapi.json").read_text(encoding="utf-8"), encoding="utf-8")
            config = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
            auditor = APISentinelAuditor(
                str(spec), "https://api.example.test", request_delay=0,
                identities_config=config["identities"], parameter_values=config["parameter_values"],
                bola_config=config.get("bola"),
            )
            stub = HTTPResult(status=403, body='{"error":"forbidden"}')
            with patch.object(auditor._transport.opener, "open", side_effect=AssertionError("network")) as opener, \
                    patch.object(auditor, "_http_request", return_value=stub) as fake:
                auditor.run()
            self.assertGreater(fake.call_count, 0)
            opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
