"""HTTP 429 / Retry-After handling for read requests.

A rate-limited read used to become an INCONCLUSIVE result immediately. Reads
are now retried a bounded number of times, honoring Retry-After and pausing
every worker; writes are never retried because the server may have applied
them. Waits beyond the cap fail closed with the original response.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Tuple

from core.auditor import APISentinelAuditor
from mock_server.server import TargetMockHandler

IDENTITIES = {
    "owner": {"id": "1001", "token": "Bearer OWNER_TOKEN", "parameters": {}},
    "visitor": {"id": "1002", "token": "Bearer VISITOR_TOKEN", "parameters": {}},
    "anonymous": {"id": None, "token": None, "parameters": {}},
}

Response = Tuple[int, Dict[str, str]]


class ScriptedHandler(BaseHTTPRequestHandler):
    """Serve scripted statuses per path, then 200 JSON; record arrival times."""

    scripts: Dict[str, List[Response]] = {}
    arrivals: List[Tuple[str, str, float]] = []
    lock = threading.Lock()

    def log_message(self, *args: object) -> None:  # Keep test output quiet.
        pass

    def _respond(self) -> None:
        if self.command == "PATCH":
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.lock:
            self.arrivals.append((self.command, self.path, time.monotonic()))
            script = self.scripts.get(self.path, [])
            status, headers = script.pop(0) if script else (200, {})
        body = json.dumps({"id": "1001", "note": "ok"} if status == 200 else {"error": "slow down"}).encode()
        self.send_response(status)
        for name, value in {"Content-Type": "application/json", **headers}.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_PATCH = _respond


class RateLimitRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        ScriptedHandler.scripts = {}
        ScriptedHandler.arrivals = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ScriptedHandler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        spec = Path(directory.name) / "openapi.json"
        spec.write_text(json.dumps({"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}}))
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.auditor = APISentinelAuditor(str(spec), self.base, request_delay=0, identities_config=IDENTITIES)
        self.auditor.RATE_LIMIT_BACKOFF = 0.05  # Keep backoff-only tests fast.

    def script(self, path: str, *responses: Response) -> None:
        ScriptedHandler.scripts[path] = list(responses)

    def requests_to(self, path: str) -> List[float]:
        return [arrived for _, request_path, arrived in ScriptedHandler.arrivals if request_path == path]

    def get(self, path: str):
        return self.auditor._http_request("GET", self.base + path, identity_name="owner")

    def test_retry_after_seconds_is_honored_then_succeeds(self) -> None:
        self.script("/a", (429, {"Retry-After": "1"}))
        result = self.get("/a")
        self.assertEqual(result.status, 200)
        first, second = self.requests_to("/a")
        self.assertGreaterEqual(second - first, 0.9)
        self.assertEqual(self.auditor.stats["rate_limit_retries"], 1)
        self.assertEqual(self.auditor.stats["transport_attempts"], 2)

    def test_retry_after_http_date_is_honored(self) -> None:
        when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=2), usegmt=True)
        self.script("/date", (429, {"Retry-After": when}))
        self.assertEqual(self.get("/date").status, 200)
        first, second = self.requests_to("/date")
        self.assertGreaterEqual(second - first, 0.5)  # HTTP dates have one-second resolution.

    def test_backoff_without_retry_after(self) -> None:
        self.script("/b", (429, {}), (429, {}))
        self.assertEqual(self.get("/b").status, 200)
        self.assertEqual(len(self.requests_to("/b")), 3)

    def test_retries_are_bounded_and_fail_closed(self) -> None:
        self.script("/c", *[(429, {"Retry-After": "0"})] * 5)
        result = self.get("/c")
        self.assertEqual(result.status, 429)  # Classified as an inconclusive HTTP client error.
        self.assertEqual(len(self.requests_to("/c")), 1 + APISentinelAuditor.RATE_LIMIT_RETRIES)

    def test_wait_beyond_cap_is_not_slept(self) -> None:
        self.script("/d", (429, {"Retry-After": "3600"}))
        started = time.monotonic()
        self.assertEqual(self.get("/d").status, 429)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(len(self.requests_to("/d")), 1)

    def test_writes_are_never_retried(self) -> None:
        self.script("/w", (429, {"Retry-After": "0"}))
        result = self.auditor._http_request("PATCH", self.base + "/w", data={"role": "user"}, identity_name="visitor")
        self.assertEqual(result.status, 429)
        self.assertEqual(len(self.requests_to("/w")), 1)

    def test_503_is_retried_only_with_retry_after(self) -> None:
        self.script("/e", (503, {"Retry-After": "0"}))
        self.assertEqual(self.get("/e").status, 200)
        self.script("/f", (503, {}))
        self.assertEqual(self.get("/f").status, 503)
        self.assertEqual(len(self.requests_to("/f")), 1)

    def test_rate_limit_pauses_every_worker(self) -> None:
        self.script("/limited", (429, {"Retry-After": "1"}))
        limited = threading.Thread(target=self.get, args=("/limited",))
        limited.start()
        while not self.requests_to("/limited"):
            time.sleep(0.01)
        time.sleep(0.1)  # Let the limited worker register its pause.
        self.get("/other")
        limited.join()
        self.assertGreaterEqual(self.requests_to("/other")[0] - self.requests_to("/limited")[0], 0.8)

    def test_retry_after_parsing(self) -> None:
        parse = APISentinelAuditor._retry_after_seconds
        self.assertEqual(parse({"Retry-After": "7"}), 7.0)
        self.assertEqual(parse({"retry-after": " 0 "}), 0.0)
        self.assertIsNone(parse({}))
        self.assertIsNone(parse({"Retry-After": "soon"}))
        self.assertIsNone(parse({"Retry-After": "-5"}))
        self.assertEqual(parse({"Retry-After": "9" * 40}), float("inf"))
        past = format_datetime(datetime.now(timezone.utc) - timedelta(hours=1), usegmt=True)
        self.assertEqual(parse({"Retry-After": past}), 0.0)


ROOT = Path(__file__).resolve().parents[1]


class RateLimitingMockHandler(TargetMockHandler):
    """The repository's mock target, answering each path's first GET with 429."""

    seen_paths: set = set()
    seen_lock = threading.Lock()

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        with self.seen_lock:
            first = self.path not in self.seen_paths
            self.seen_paths.add(self.path)
        if not first:
            super().do_GET()
            return
        body = b'{"error": "rate limited"}'
        self.send_response(429)
        self.send_header("Retry-After", "0")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RateLimitedScanTests(unittest.TestCase):
    def scan(self, handler: type) -> APISentinelAuditor:
        TargetMockHandler.reset_database()
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            config = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
            auditor = APISentinelAuditor(
                spec_path=str(ROOT / "openapi.json"), target_base_url=f"http://127.0.0.1:{server.server_port}",
                max_workers=3, request_delay=0, identities_config=config["identities"],
                parameter_values=config["parameter_values"], readback_config=config["readbacks"],
            )
            with contextlib.redirect_stdout(io.StringIO()):
                auditor.run()
            return auditor
        finally:
            server.shutdown()
            server.server_close()
            TargetMockHandler.reset_database()

    def test_rate_limited_scan_reaches_the_same_verdicts(self) -> None:
        RateLimitingMockHandler.seen_paths = set()
        baseline = self.scan(TargetMockHandler)
        limited = self.scan(RateLimitingMockHandler)

        def verdicts(auditor: APISentinelAuditor):
            return sorted((item["endpoint"], item["check"], item["verdict"]) for item in auditor.results)

        self.assertEqual(verdicts(limited), verdicts(baseline))
        self.assertEqual(limited.stats["bola_confirmed"], 1)
        self.assertEqual(limited.stats["inconclusive_count"], baseline.stats["inconclusive_count"])
        self.assertGreater(limited.stats["rate_limit_retries"], 0)
        self.assertEqual(baseline.stats["rate_limit_retries"], 0)


if __name__ == "__main__":
    unittest.main()
