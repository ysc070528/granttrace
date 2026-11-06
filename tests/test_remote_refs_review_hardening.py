"""Remote $ref hardening found by a line-by-line review of the fetcher.

Network tests use a real local TCP server. Only TLS is replaced (a plain
socket stands in for the pinned HTTPS connection), so http.client parsing,
socket timeouts and the fetcher's own deadline logic run unmodified.
"""

from __future__ import annotations

import contextlib
import io
import ipaddress
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Callable
from unittest.mock import patch

from core.auditor import APISentinelAuditor
from core.models import Verdict
from core.remote_refs import (
    PinnedIPHTTPSConnection,
    RemoteRefConfig,
    RemoteRefFetcher,
    RemoteRefLimitExceededError,
    RemoteRefResolutionError,
    RemoteRefSecurityError,
    _embedded_ipv4_addresses,
    validate_ip_address,
)

TIMEOUT = 0.3
# Generous scheduling margin; the slow servers below run for about 3 seconds.
DEADLINE_MARGIN = 1.0


class LocalServer:
    """Accept one connection, read the request, then run ``respond``."""

    def __init__(self, respond: Callable[[socket.socket], None]) -> None:
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.respond = respond
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        connection, _ = self.listener.accept()
        try:
            connection.recv(65536)
            self.respond(connection)
        except OSError:
            pass  # The client may abort the connection at its deadline.
        finally:
            connection.close()
            self.listener.close()


def drip(connection: socket.socket, data: bytes, interval: float = 0.05) -> None:
    for byte in data:
        connection.sendall(bytes([byte]))
        time.sleep(interval)


class FetchHarness(unittest.TestCase):
    def fetch(self, respond: Callable[[socket.socket], None], timeout: float = TIMEOUT):
        server = LocalServer(respond)

        def plain_connect(connection: PinnedIPHTTPSConnection) -> None:
            connection.sock = socket.create_connection(("127.0.0.1", server.port), connection.timeout)

        config = RemoteRefConfig.create(
            allow_remote_refs=True, remote_ref_hosts=["schemas.example.com"], timeout=timeout,
        )
        with patch("core.remote_refs.resolve_safe_ips", return_value=["93.184.216.34"]), \
                patch.object(PinnedIPHTTPSConnection, "connect", plain_connect):
            return RemoteRefFetcher(config).fetch_document("https://schemas.example.com/models.json")

    def assert_times_out(self, respond: Callable[[socket.socket], None]) -> None:
        started = time.perf_counter()
        with self.assertRaisesRegex(RemoteRefLimitExceededError, "timeout"):
            self.fetch(respond)
        self.assertLess(time.perf_counter() - started, TIMEOUT + DEADLINE_MARGIN)


class AbsoluteDeadlineTests(FetchHarness):
    """Socket timeouts apply per receive; one read can span many receives."""

    def test_header_drip_cannot_outlast_the_deadline(self) -> None:
        def respond(connection: socket.socket) -> None:
            connection.sendall(b"HTTP/1.1 200 OK\r\n")
            drip(connection, b"X" * 60)  # About 3 s of header bytes.

        self.assert_times_out(respond)

    def test_body_drip_inside_one_read_cannot_outlast_the_deadline(self) -> None:
        def respond(connection: socket.socket) -> None:
            body = b'{"a": "' + b"x" * 100 + b'"}'
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body))
            drip(connection, body[:60])

        self.assert_times_out(respond)

    def test_complete_looking_body_is_not_accepted_after_the_deadline(self) -> None:
        # Close-delimited body: a valid document followed by a slow trickle.
        # Ending the read at the deadline must not look like a complete document.
        def respond(connection: socket.socket) -> None:
            connection.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{"a": 1}')
            drip(connection, b" " * 60)

        self.assert_times_out(respond)

    def test_tls_handshake_drip_cannot_outlast_the_deadline(self) -> None:
        # Real PinnedIPHTTPSConnection.connect and TLS handshake: the server
        # announces a 256-byte handshake record, then drips it slowly. CPython
        # bounds one do_handshake() call by the socket timeout; keep it so.
        def respond(connection: socket.socket) -> None:
            connection.sendall(b"\x16\x03\x03\x01\x00")
            drip(connection, b"\x00" * 60)

        server = LocalServer(respond)
        original_create_connection = socket.create_connection

        def to_local_server(address, timeout=None, source_address=None):
            self.assertEqual(address, ("93.184.216.34", 443))  # The pinned IP is still used.
            return original_create_connection(("127.0.0.1", server.port), timeout, source_address)

        config = RemoteRefConfig.create(
            allow_remote_refs=True, remote_ref_hosts=["schemas.example.com"], timeout=TIMEOUT,
        )
        started = time.perf_counter()
        with patch("core.remote_refs.resolve_safe_ips", return_value=["93.184.216.34"]), \
                patch("core.remote_refs.socket.create_connection", side_effect=to_local_server):
            with self.assertRaisesRegex(RemoteRefLimitExceededError, "(?i)time(out|d out)"):
                RemoteRefFetcher(config).fetch_document("https://schemas.example.com/models.json")
        self.assertLess(time.perf_counter() - started, TIMEOUT + DEADLINE_MARGIN)

    def test_prompt_response_still_succeeds(self) -> None:
        def respond(connection: socket.socket) -> None:
            body = json.dumps({"components": {"schemas": {"User": {"type": "object"}}}}).encode()
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

        self.assertEqual(self.fetch(respond, timeout=2.0)["components"]["schemas"]["User"]["type"], "object")


class MalformedResponseTests(FetchHarness):
    """Bad remote content must stay a per-reference failure, never abort the scan."""

    def test_malformed_status_line_is_a_resolution_error(self) -> None:
        def respond(connection: socket.socket) -> None:
            connection.sendall(b"NOT-HTTP garbage\r\n\r\n")

        with self.assertRaises(RemoteRefResolutionError):
            self.fetch(respond, timeout=2.0)

    def test_truncated_body_is_a_resolution_error(self) -> None:
        def respond(connection: socket.socket) -> None:
            connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"a": 1}')

        with self.assertRaises(RemoteRefResolutionError):
            self.fetch(respond, timeout=2.0)

    def test_deeply_nested_json_is_a_resolution_error(self) -> None:
        def respond(connection: socket.socket) -> None:
            body = b"[" * 200_000 + b"]" * 200_000
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

        with self.assertRaises(RemoteRefResolutionError):
            self.fetch(respond, timeout=5.0)


class EmbeddedIPv4Tests(unittest.TestCase):
    """IPv6 transition addresses carry an IPv4 destination.

    CPython before the 2024 ipaddress update (e.g. 3.9.19, 3.12.3) classifies
    6to4 addresses that embed 169.254.169.254 or 127.0.0.1 as global. The
    embedded address must be checked directly, independent of those tables.
    """

    def test_embedded_addresses_are_extracted(self) -> None:
        cases = {
            "2002:a9fe:a9fe::1": ["169.254.169.254"],          # 6to4
            "64:ff9b::7f00:1": ["127.0.0.1"],                   # NAT64 well-known prefix
            "2001:0:4136:e378:8000:63bf:3fff:fdd2": ["65.54.227.120", "192.0.2.45"],  # Teredo
            "::ffff:169.254.169.254": ["169.254.169.254"],     # IPv4-mapped
            "2606:4700::1111": [],                              # Ordinary global IPv6
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                found = sorted(str(ip) for ip in _embedded_ipv4_addresses(ipaddress.ip_address(address)))
                self.assertEqual(found, sorted(expected))

    def test_internal_destinations_behind_transition_prefixes_are_blocked(self) -> None:
        # 64:ff9b:1::/48 (local-use NAT64), ::/96 (IPv4-compatible) and fec0::/10
        # (site-local) are never global; they are blocked whatever they embed.
        for address in ("2002:a9fe:a9fe::1", "2002:7f00:1::1", "2002:a00:1::1", "64:ff9b::a9fe:a9fe",
                        "64:ff9b:1::7f00:1", "64:ff9b:1::5db8:d822", "2001:0:4136:e378:8000:63bf:5601:5601",
                        "::169.254.169.254", "fec0::1"):
            with self.subTest(address=address):
                with self.assertRaises(RemoteRefSecurityError):
                    validate_ip_address(address)

    def test_embedded_check_does_not_depend_on_python_tables(self) -> None:
        # Simulate interpreter tables that call every IPv6 address global.
        with patch.object(ipaddress.IPv6Address, "is_private", new=property(lambda self: False)), \
                patch.object(ipaddress.IPv6Address, "is_global", new=property(lambda self: True)), \
                patch.object(ipaddress.IPv6Address, "is_reserved", new=property(lambda self: False)):
            for address in ("2002:a9fe:a9fe::1", "64:ff9b::7f00:1", "2001:0:4136:e378:8000:63bf:5601:5601",
                            "64:ff9b:1::5db8:d822", "::169.254.169.254", "fec0::1"):
                with self.subTest(address=address):
                    with self.assertRaises(RemoteRefSecurityError):
                        validate_ip_address(address)

    def test_public_destinations_remain_allowed(self) -> None:
        validate_ip_address("93.184.216.34")
        validate_ip_address("2606:4700::1111")


class UnresolvedPathItemTests(unittest.TestCase):
    def test_failed_path_item_reference_is_inconclusive_not_skipped(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        spec = Path(directory.name) / "openapi.json"
        spec.write_text(json.dumps({
            "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
            "paths": {"/admin/{id}": {"$ref": "https://schemas.example.com/paths.json#/admin"}},
        }), encoding="utf-8")
        config = RemoteRefConfig.create(allow_remote_refs=True, remote_ref_hosts=["schemas.example.com"])
        failure = RemoteRefResolutionError("HTTP 503 Service Unavailable fetching remote schema")
        with patch.object(RemoteRefFetcher, "fetch_document", side_effect=failure):
            auditor = APISentinelAuditor(str(spec), "http://127.0.0.1:9", request_delay=0,
                                         remote_ref_config=config)
            with contextlib.redirect_stdout(io.StringIO()):
                auditor.run()
        [result] = auditor.results
        self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE.value)
        self.assertEqual(result["evidence"]["reason_category"], "unresolved_reference")
        self.assertEqual(result["evidence"]["requests_attempted"], 0)
        self.assertIn("HTTP 503", result["reason"])
        self.assertEqual(auditor.stats["inconclusive_count"], 1)
        self.assertEqual(auditor.stats["skipped_count"], 0)


if __name__ == "__main__":
    unittest.main()
