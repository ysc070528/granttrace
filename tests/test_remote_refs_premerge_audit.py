# -*- coding: utf-8 -*-
"""Pre-merge security audit test suite for GrantTrace PR #48.

Validates:
1. Strict TLS security boundaries (CERT_NONE rejected, check_hostname=False rejected).
2. DNS and Slowloris timeout budgets (absolute wall-clock deadline).
3. Dry-run sensitive information leak prevention (credentials, tokens, keys redacted).
4. DNS Pinning real socket connection and mixed DNS fail-closed handling.
5. Endpoints with unresolved remote schemas fail closed (0 requests, INCONCLUSIVE).
"""

from __future__ import annotations

import io
import json
import socket
import ssl
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.models import Verdict
from core.remote_refs import (
    PinnedIPHTTPSConnection,
    RemoteRefConfig,
    RemoteRefFetcher,
    RemoteRefLimitExceededError,
    RemoteRefResolutionError,
    RemoteRefSecurityError,
    resolve_safe_ips,
    sanitize_error_message,
    sanitize_ref_url,
    validate_ssl_context,
)


class TestTLSSecurityBoundaries(unittest.TestCase):
    """Enforce TLS certificate and hostname verification boundaries."""

    def test_cert_none_rejected_by_validator(self) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with self.assertRaises(RemoteRefSecurityError) as exc_ctx:
            validate_ssl_context(ctx)
        self.assertIn("CERT_REQUIRED", str(exc_ctx.exception))

    def test_cert_none_rejected_by_fetcher_init(self) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
        )
        with self.assertRaises(RemoteRefSecurityError):
            RemoteRefFetcher(cfg, ssl_context=ctx)

    def test_cert_none_rejected_by_pinned_connection(self) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with self.assertRaises(RemoteRefSecurityError):
            PinnedIPHTTPSConnection("93.184.216.34", "schemas.example.com", context=ctx)

    def test_check_hostname_false_rejected(self) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        with self.assertRaises(RemoteRefSecurityError) as exc_ctx:
            validate_ssl_context(ctx)
        self.assertIn("hostname verification cannot be disabled", str(exc_ctx.exception))

    def test_default_tls_enforces_cert_and_hostname(self) -> None:
        conn = PinnedIPHTTPSConnection("93.184.216.34", "schemas.example.com")
        self.assertTrue(conn.ssl_ctx.check_hostname)
        self.assertEqual(conn.ssl_ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_allow_loopback_rejected_in_config_create(self) -> None:
        with self.assertRaises(RemoteRefSecurityError) as exc_ctx:
            RemoteRefConfig.create(
                allow_remote_refs=True,
                remote_ref_hosts=["localhost"],
                allow_loopback_for_testing=True,
            )
        self.assertIn("Loopback address resolution cannot be enabled", str(exc_ctx.exception))


class TestDNSAndNetworkTimeouts(unittest.TestCase):
    """Enforce absolute wall-clock timeout budgets across DNS, connection, and streaming."""

    def test_dns_timeout_exceeded(self) -> None:
        def slow_getaddrinfo(*args: Any, **kwargs: Any) -> Any:
            time.sleep(0.3)
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]

        with patch("socket.getaddrinfo", side_effect=slow_getaddrinfo):
            with self.assertRaises(RemoteRefLimitExceededError) as exc_ctx:
                resolve_safe_ips("slow.example.com", timeout=0.05)
            self.assertIn("DNS resolution timed out", str(exc_ctx.exception))

    def test_dns_resolution_failure_propagated(self) -> None:
        with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
            with self.assertRaises(RemoteRefResolutionError) as exc_ctx:
                resolve_safe_ips("notfound.example.com", timeout=1.0)
            self.assertIn("DNS resolution failed", str(exc_ctx.exception))

    def test_slowloris_body_streaming_timeout(self) -> None:
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            timeout=0.1,
        )
        fetcher = RemoteRefFetcher(cfg)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = None

        # Generator that yields tiny chunks while sleeping beyond the deadline
        def slow_chunks(size: int = 8192) -> bytes:
            time.sleep(0.15)
            return b'{"title": "slow"}'

        mock_resp.read.side_effect = slow_chunks

        with patch("core.remote_refs.resolve_safe_ips", return_value=["93.184.216.34"]):
            with patch.object(PinnedIPHTTPSConnection, "connect"):
                with patch.object(PinnedIPHTTPSConnection, "request"):
                    with patch.object(PinnedIPHTTPSConnection, "getresponse", return_value=mock_resp):
                        with self.assertRaises(RemoteRefLimitExceededError) as exc_ctx:
                            fetcher.fetch_document("https://schemas.example.com/slow.json")
                        self.assertTrue(
                            "Overall timeout exceeded" in str(exc_ctx.exception)
                            or "Timed out fetching" in str(exc_ctx.exception)
                        )


class TestDryRunSecretRedaction(unittest.TestCase):
    """Verify that credentials, tokens, and secret parameters in remote URLs never leak."""

    def test_sanitize_ref_url_strips_credentials_and_redacts_query(self) -> None:
        url = "https://admin:my_secret_pass@schemas.example.com/spec.json?token=SECRET_TOKEN_XYZ&api_key=SECRET_API_KEY#User"
        clean = sanitize_ref_url(url)
        self.assertNotIn("my_secret_pass", clean)
        self.assertNotIn("admin:", clean)
        self.assertNotIn("SECRET_TOKEN_XYZ", clean)
        self.assertNotIn("SECRET_API_KEY", clean)
        self.assertIn("token=[REDACTED]", clean)
        self.assertIn("api_key=[REDACTED]", clean)
        self.assertIn("https://schemas.example.com/spec.json?", clean)
        self.assertIn("#User", clean)

    def test_sanitize_error_message(self) -> None:
        msg = "Fetch failed: https://user:pass123@schemas.example.com/api?secret=SUPER_SECRET_VALUE"
        cleaned = sanitize_error_message(msg)
        self.assertNotIn("pass123", cleaned)
        self.assertNotIn("SUPER_SECRET_VALUE", cleaned)
        self.assertIn("secret=[REDACTED]", cleaned)

    def test_dry_run_and_export_json_never_leak_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            config_path = dir_path / "config.json"
            export_path = dir_path / "dry_run_plan.json"

            # Fake canary values for this redaction check, not credentials: the
            # assertions below prove they never reach stdout, stderr or the plan.
            redaction_canary_token = "TOP_SECRET_REDACTION_CHECK_12345"
            redaction_canary_password = "VERY_SECRET_PASSWORD_67890"

            spec_content = {
                "openapi": "3.0.3",
                "info": {"title": "Sensitive URL API", "version": "1.0.0"},
                "paths": {
                    "/users/{id}": {
                        "parameters": [
                            {
                                "$ref": (
                                    f"https://user:{redaction_canary_password}@schemas.example.com/models.json"
                                    f"?token={redaction_canary_token}#/components/parameters/UserId"
                                )
                            }
                        ],
                        "get": {
                            "operationId": "getUser",
                            "responses": {
                                "200": {
                                    "description": "OK",
                                }
                            },
                        }
                    }
                },
            }
            spec_path.write_text(json.dumps(spec_content), encoding="utf-8")

            config_content = {
                "identities": {
                    "owner": {"headers": {"Authorization": "Bearer owner-token"}},
                    "visitor": {"headers": {"Authorization": "Bearer visitor-token"}},
                    "anonymous": {"headers": {}},
                },
            }
            config_path.write_text(json.dumps(config_content), encoding="utf-8")

            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()

            with patch("sys.stdout", stdout_capture), patch("sys.stderr", stderr_capture):
                exit_code = main([
                    "--spec", str(spec_path),
                    "--config", str(config_path),
                    "--target", "https://api.example.com",
                    "--dry-run",
                    "--export-json", str(export_path),
                ])

            self.assertEqual(exit_code, 0)

            stdout_output = stdout_capture.getvalue()
            stderr_output = stderr_capture.getvalue()
            plan_file_content = export_path.read_text(encoding="utf-8")

            # Assert secrets are completely absent from stdout
            self.assertNotIn(redaction_canary_token, stdout_output)
            self.assertNotIn(redaction_canary_password, stdout_output)

            # Assert secrets are completely absent from stderr
            self.assertNotIn(redaction_canary_token, stderr_output)
            self.assertNotIn(redaction_canary_password, stderr_output)

            # Assert secrets are completely absent from exported plan JSON
            self.assertNotIn(redaction_canary_token, plan_file_content)
            self.assertNotIn(redaction_canary_password, plan_file_content)

            # Assert the redacted parameter is present
            self.assertIn("token=[REDACTED]", plan_file_content)


class TestDNSPinningRealVerification(unittest.TestCase):
    """Verify that DNS Pinning binds directly to pre-resolved IPs and fails closed on mixed DNS."""

    def test_pinned_connection_socket_creation(self) -> None:
        conn = PinnedIPHTTPSConnection(
            pinned_ip="93.184.216.34",
            target_hostname="schemas.example.com",
            port=443,
            timeout=3.0,
        )

        mock_raw_socket = MagicMock()
        mock_wrapped_socket = MagicMock()

        with patch("socket.create_connection", return_value=mock_raw_socket) as mock_create:
            with patch.object(conn.ssl_ctx, "wrap_socket", return_value=mock_wrapped_socket) as mock_wrap:
                conn.connect()

                # Verify socket connects directly to pinned IP (not hostname)
                mock_create.assert_called_once_with(("93.184.216.34", 443), 3.0, None)
                # Verify TLS wrap specifies original target_hostname for SNI / cert check
                mock_wrap.assert_called_once_with(mock_raw_socket, server_hostname="schemas.example.com")
                self.assertIs(conn.sock, mock_wrapped_socket)

    def test_mixed_dns_safe_and_loopback_rejected_fail_closed(self) -> None:
        mixed_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mixed_addrinfo):
            with self.assertRaises(RemoteRefSecurityError) as exc_ctx:
                resolve_safe_ips("mixed.example.com")
            self.assertIn("Loopback IP address is blocked", str(exc_ctx.exception))

    def test_mixed_dns_safe_and_cloud_metadata_rejected(self) -> None:
        mixed_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mixed_addrinfo):
            with self.assertRaises(RemoteRefSecurityError) as exc_ctx:
                resolve_safe_ips("metadata-mixed.example.com")
            self.assertIn("Access to cloud metadata IP is blocked", str(exc_ctx.exception))

    def test_mixed_dns_ipv6_loopback_rejected(self) -> None:
        mixed_addrinfo = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)),
        ]
        with patch("socket.getaddrinfo", return_value=mixed_addrinfo):
            with self.assertRaises(RemoteRefSecurityError) as exc_ctx:
                resolve_safe_ips("mixed-ipv6.example.com")
            self.assertIn("Loopback IP address is blocked", str(exc_ctx.exception))


class TestFailClosedEndpointState(unittest.TestCase):
    """Verify that unresolved remote references produce INCONCLUSIVE with zero requests."""

    def test_unresolved_remote_schema_auditor_zero_requests(self) -> None:
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Unresolved API", "version": "1.0.0"},
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "getItems",
                        "parameters": [
                            {
                                "$ref": "https://schemas.example.com/items.json#/components/parameters/ItemParam"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "OK",
                            }
                        },
                    },
                    "patch": {
                        "operationId": "patchItems",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "https://schemas.example.com/items.json#/components/schemas/ItemPatch"
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "OK"}},
                    },
                }
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            spec_path = Path(temp_dir) / "openapi.json"
            spec_path.write_text(json.dumps(spec_content), encoding="utf-8")

            cfg = RemoteRefConfig.create(
                allow_remote_refs=True,
                remote_ref_hosts=["schemas.example.com"],
            )

            # Auditor initialized with remote ref config in offline mode
            auditor = APISentinelAuditor(
                spec_path=str(spec_path),
                target_base_url="https://api.example.com",
                identities_config={
                    "owner": {"headers": {"Authorization": "Bearer owner"}},
                    "visitor": {"headers": {"Authorization": "Bearer visitor"}},
                    "anonymous": {"headers": {}},
                },
                remote_ref_config=cfg,
                offline=True,
            )

            # Build plan
            plan = auditor.build_plan()
            for op in plan["operations"]:
                self.assertEqual(op["check"], "INCONCLUSIVE")
                self.assertFalse(op["writes_enabled"])
                self.assertEqual(op.get("reason_category"), "unresolved_reference")

            # Audit endpoint BOLA directly
            endpoints = auditor.parser.get_endpoints()
            self.assertEqual(len(endpoints), 2)
            get_ep = [ep for ep in endpoints if ep["method"] == "GET"][0]
            patch_ep = [ep for ep in endpoints if ep["method"] == "PATCH"][0]

            auditor.audit_endpoint_bola(get_ep)
            self.assertEqual(len(auditor.results), 1)
            self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE)
            self.assertEqual(auditor.results[0]["evidence"]["requests_sent"], 0)
            self.assertEqual(len(auditor.findings), 0)

            # Audit endpoint Mass Assignment directly
            auditor._audit_endpoint_mass_assignment(patch_ep, endpoints)
            self.assertEqual(len(auditor.results), 2)
            self.assertEqual(auditor.results[1]["verdict"], Verdict.INCONCLUSIVE)
            self.assertEqual(auditor.results[1]["evidence"]["requests_sent"], 0)
            self.assertEqual(len(auditor.findings), 0)


if __name__ == "__main__":
    unittest.main()
