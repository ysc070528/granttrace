# -*- coding: utf-8 -*-
"""Comprehensive pre-merge security hardening tests for remote $ref resolution.

Covers:
1. Strict Zero-Network offline mode for --validate-config, --dry-run, and ConfigValidator.
2. Unified remote reference depth budget with exact boundaries for depth 9, 10, 11 and cross-helper retention.
3. Total budget isolation, URL deduplication, and byte accumulation on failure across multiple parsers.
4. Circular reference detection (direct and indirect) and unresolved reference fail-closed handling.
"""

from __future__ import annotations

import io
import json
import socket
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.models import Verdict
from core.parser import OpenAPIParser
from core.remote_refs import (
    PinnedIPHTTPSConnection,
    RemoteRefConfig,
    RemoteRefFetcher,
    RemoteRefLimitExceededError,
    RemoteRefResolutionError,
    RemoteRefSession,
)


class TestOfflineZeroNetworkRemoteRefs(unittest.TestCase):
    """Verify that offline modes perform zero network activity (zero DNS, zero TCP, zero HTTP)."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.spec_file = self.dir_path / "openapi.json"
        self.config_file = self.dir_path / "config.json"

        # Specification containing real remote $refs in both GET and PATCH
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Test Remote API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "getUsers",
                        "parameters": [
                            {
                                "name": "filter",
                                "in": "query",
                                "schema": {
                                    "$ref": "https://schemas.example.com/models/filter.json#/Filter"
                                },
                            }
                        ],
                        "responses": {"200": {"description": "OK"}},
                    },
                    "patch": {
                        "operationId": "updateUser",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "https://schemas.example.com/models/user_patch.json#/UserPatch"
                                    }
                                }
                            },
                        },
                        "responses": {"200": {"description": "OK"}},
                    },
                }
            },
        }
        self.spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        config_content = {
            "write_allowlist": ["PATCH /users"],
            "readbacks": {
                "PATCH /users": {
                    "method": "GET",
                    "path": "/users",
                    "field_map": {"name": "name"},
                }
            },
        }
        self.config_file.write_text(json.dumps(config_content), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_parser_offline_mode_raises_offline_blocked_error_zero_network(self) -> None:
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
        )
        parser = OpenAPIParser(str(self.spec_file), remote_ref_config=cfg, offline=True)
        self.assertTrue(parser.offline)
        self.assertIsNone(parser.remote_fetcher)

        with patch("socket.getaddrinfo", side_effect=AssertionError("Network DNS probed in offline mode")), \
             patch("socket.socket", side_effect=AssertionError("Socket created in offline mode")):
            endpoints = parser.get_endpoints()

        # Endpoints are preserved, but schema resolution errors are recorded
        self.assertEqual(len(endpoints), 2)
        for ep in endpoints:
            self.assertIn("unresolved_schema_error", ep)
            self.assertIn("offline mode", ep["unresolved_schema_error"])
            self.assertIsNone(ep["request_schema"])

    def test_validate_config_cli_is_strictly_zero_network_and_reports_unresolved(self) -> None:
        """--validate-config must make zero network requests and exit with 2 because remote ref cannot be fetched offline."""
        err_stream = io.StringIO()
        out_stream = io.StringIO()

        with patch("sys.stderr", err_stream), \
             patch("sys.stdout", out_stream), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS probed in --validate-config")), \
             patch("socket.socket", side_effect=AssertionError("Socket created in --validate-config")):
            ret = main([
                "--spec", str(self.spec_file),
                "--config", str(self.config_file),
                "--validate-config",
                "--allow-remote-refs",
                "--remote-ref-host", "schemas.example.com",
            ])

        self.assertEqual(ret, 2)
        err_output = err_stream.getvalue()
        self.assertIn("Configuration validation failed", err_output)
        self.assertIn("Remote $ref resolution is blocked in offline mode", err_output)

    def test_dry_run_cli_is_strictly_zero_network_and_marks_inconclusive(self) -> None:
        """--dry-run must make zero network requests and plan unresolved remote operations as INCONCLUSIVE."""
        out_stream = io.StringIO()

        with patch("sys.stdout", out_stream), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS probed in --dry-run")), \
             patch("socket.socket", side_effect=AssertionError("Socket created in --dry-run")):
            ret = main([
                "--spec", str(self.spec_file),
                "--config", str(self.config_file),
                "--dry-run",
                "--allow-remote-refs",
                "--remote-ref-host", "schemas.example.com",
            ])

        self.assertEqual(ret, 0)
        output = out_stream.getvalue()
        self.assertIn('"mode": "DRY_RUN"', output)
        self.assertIn('"requests_sent": 0', output)
        self.assertIn('"check": "INCONCLUSIVE"', output)
        self.assertIn('"reason_category": "unresolved_reference"', output)
        self.assertIn('"writes_enabled": false', output)


class TestRemoteRefDepthBudgetAndBoundaries(unittest.TestCase):
    """Test unified depth budget with boundary tests at 9, 10, 11 and cross-helper depth retention."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_depth=10,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _build_chain_spec(self, length: int) -> Path:
        """Create a local spec referencing doc1, which references doc2 ... up to length."""
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Depth Test", "version": "1.0"},
            "paths": {
                "/item": {
                    "post": {
                        "operationId": "createItem",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "https://schemas.example.com/doc1.json#/Item"}
                                }
                            },
                        },
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / f"spec_depth_{length}.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")
        return spec_file

    def _mock_chain_fetcher(self, parser: OpenAPIParser, length: int) -> None:
        """Set up mock fetcher returning doc1 -> doc2 -> ... -> docN."""
        def fetch_doc(url: str) -> Dict[str, Any]:
            import re
            m = re.search(r"doc(\d+)\.json", url)
            if not m:
                raise ValueError(f"Unknown mock url: {url}")
            idx = int(m.group(1))
            if idx < length:
                next_url = f"https://schemas.example.com/doc{idx + 1}.json#/Item"
                return {"Item": {"$ref": next_url}}
            return {"Item": {"type": "object", "properties": {"final": {"type": "string"}}}}

        assert parser.remote_fetcher is not None
        parser.remote_fetcher.fetch_document = MagicMock(side_effect=fetch_doc)  # type: ignore

    def test_depth_9_allowed(self) -> None:
        """Depth 9 remote hops resolve successfully within budget of 10."""
        spec_file = self._build_chain_spec(9)
        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
        self._mock_chain_fetcher(parser, 9)

        endpoints = parser.get_endpoints()
        self.assertEqual(len(endpoints), 1)
        schema = endpoints[0]["request_schema"]
        self.assertIsNotNone(schema)
        self.assertEqual(schema["type"], "object")
        self.assertIn("final", schema["properties"])

    def test_depth_10_allowed(self) -> None:
        """Depth 10 remote hops resolve successfully at the exact boundary."""
        spec_file = self._build_chain_spec(10)
        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
        self._mock_chain_fetcher(parser, 10)

        endpoints = parser.get_endpoints()
        self.assertEqual(len(endpoints), 1)
        schema = endpoints[0]["request_schema"]
        self.assertIsNotNone(schema)
        self.assertEqual(schema["type"], "object")
        self.assertIn("final", schema["properties"])

    def test_depth_11_exceeds_budget(self) -> None:
        """Depth 11 remote hops exceeds max_depth of 10 and marks endpoint as unresolved schema error."""
        spec_file = self._build_chain_spec(11)
        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
        self._mock_chain_fetcher(parser, 11)

        endpoints = parser.get_endpoints()
        self.assertEqual(len(endpoints), 1)
        self.assertIn("unresolved_schema_error", endpoints[0])
        self.assertIn("Remote reference depth limit (10) exceeded at depth 11", endpoints[0]["unresolved_schema_error"])
        self.assertIsNone(endpoints[0]["request_schema"])

    def test_cross_helper_depth_retention(self) -> None:
        """Depth budget is NOT reset between _resolve_ref_chain and _deep_resolve_schema."""
        # requestBody $ref takes 6 hops, then inside schema it takes another 5 hops = 11 hops total
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Cross Helper", "version": "1.0"},
            "paths": {
                "/item": {
                    "post": {
                        "operationId": "createItem",
                        "requestBody": {
                            "$ref": "https://schemas.example.com/body1.json#/Body"
                        },
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / "spec_cross.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        def fetch_doc(url: str) -> Dict[str, Any]:
            import re
            if "body" in url:
                m = re.search(r"body(\d+)\.json", url)
                idx = int(m.group(1)) if m else 1
                if idx < 6:
                    return {"Body": {"$ref": f"https://schemas.example.com/body{idx + 1}.json#/Body"}}
                return {
                    "Body": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "https://schemas.example.com/schema1.json#/Schema"}
                            }
                        }
                    }
                }
            if "schema" in url:
                m = re.search(r"schema(\d+)\.json", url)
                idx = int(m.group(1)) if m else 1
                if idx < 5:
                    return {"Schema": {"$ref": f"https://schemas.example.com/schema{idx + 1}.json#/Schema"}}
                return {"Schema": {"type": "object", "properties": {"done": {"type": "boolean"}}}}
            raise ValueError(f"Unknown {url}")

        parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
        assert parser.remote_fetcher is not None
        parser.remote_fetcher.fetch_document = MagicMock(side_effect=fetch_doc)  # type: ignore

        endpoints = parser.get_endpoints()
        self.assertEqual(len(endpoints), 1)
        self.assertIn("unresolved_schema_error", endpoints[0])
        self.assertIn("depth limit (10) exceeded", endpoints[0]["unresolved_schema_error"])


class TestSharedSessionBudgetIsolation(unittest.TestCase):
    """Test process-wide total download budgets, URL deduplication, and byte counting upon failure."""

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_shared_session_deduplicates_downloads_across_parsers(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        doc_user = {"User": {"type": "object", "properties": {"id": {"type": "string"}}}}
        body = json.dumps(doc_user).encode()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = str(len(body))
        mock_resp.read.side_effect = [body, b""]
        mock_getresponse.return_value = mock_resp

        session = RemoteRefSession()
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            session=session,
        )

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(json.dumps({
                "openapi": "3.0.3",
                "info": {"title": "T", "version": "1"},
                "paths": {
                    "/a": {
                        "post": {
                            "operationId": "opA",
                            "requestBody": {
                                "content": {"application/json": {"schema": {"$ref": "https://schemas.example.com/user.json#/User"}}}
                            },
                            "responses": {"200": {"description": "OK"}},
                        }
                    }
                },
            }))
            spec_file = f.name

        # Parser 1 fetches doc_user
        parser1 = OpenAPIParser(spec_file, remote_ref_config=cfg)
        endpoints1 = parser1.get_endpoints()
        self.assertEqual(mock_getresponse.call_count, 1)

        # Parser 2 with same config/session accesses doc_user without network request
        parser2 = OpenAPIParser(spec_file, remote_ref_config=cfg)
        endpoints2 = parser2.get_endpoints()
        self.assertEqual(mock_getresponse.call_count, 1)

        self.assertEqual(endpoints1[0]["request_schema"], endpoints2[0]["request_schema"])

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_cumulative_byte_limit_accumulates_across_failed_and_multiple_parsers(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        session = RemoteRefSession()
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_doc_bytes=1000,
            max_total_bytes=1500,
            session=session,
        )

        fetcher1 = RemoteRefFetcher(cfg)

        # Document 1 downloads 900 bytes (within doc limit 1000, cumulative 900 <= 1500)
        body1 = b'{"Root": {"type": "string"}}' + b" " * 850
        resp1 = MagicMock()
        resp1.status = 200
        resp1.getheader.return_value = str(len(body1))
        resp1.read.side_effect = [body1, b""]
        mock_getresponse.return_value = resp1

        fetcher1.fetch_document("https://schemas.example.com/doc1.json")
        self.assertEqual(session.total_bytes_downloaded, len(body1))

        # Document 2 attempts to download 800 bytes, exceeding cumulative limit 1500
        body2_chunk1 = b'{"Other": ' + b" " * 700
        resp2 = MagicMock()
        resp2.status = 200
        resp2.getheader.return_value = None
        resp2.read.side_effect = [body2_chunk1]
        mock_getresponse.return_value = resp2

        fetcher2 = RemoteRefFetcher(cfg)
        with self.assertRaises(RemoteRefLimitExceededError) as ctx:
            fetcher2.fetch_document("https://schemas.example.com/doc2.json")
        self.assertIn("Cumulative remote download exceeded limit", str(ctx.exception))

        self.assertGreater(session.total_bytes_downloaded, 1500)
        self.assertIn("https://schemas.example.com/doc2.json", session.failed_urls)

        # Subsequent attempt for doc2 fails fast without network
        with self.assertRaises(RemoteRefResolutionError) as ctx2:
            fetcher2.fetch_document("https://schemas.example.com/doc2.json")
        self.assertIn("Previous fetch attempt for remote schema failed", str(ctx2.exception))


class TestCircularAndUnresolvedReferencesFailClosed(unittest.TestCase):
    """Test direct and indirect remote circular references, fail-closed handling, and zero requests."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_direct_self_cycle_in_remote_schema_fails_closed(self) -> None:
        """A remote schema referencing itself is rejected with RemoteRefResolutionError and 0 requests."""
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Self Cycle", "version": "1.0"},
            "paths": {
                "/cycle": {
                    "post": {
                        "operationId": "createCycle",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "https://schemas.example.com/cycle.json#/Self"}
                                }
                            },
                        },
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / "spec_self_cycle.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        remote_doc = {
            "Self": {"$ref": "https://schemas.example.com/cycle.json#/Self"}
        }

        with patch.object(RemoteRefFetcher, "fetch_document", return_value=remote_doc):
            parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
            endpoints = parser.get_endpoints()

            self.assertEqual(len(endpoints), 1)
            self.assertIn("unresolved_schema_error", endpoints[0])
            self.assertIn("Circular", endpoints[0]["unresolved_schema_error"])
            self.assertIsNone(endpoints[0]["request_schema"])

            # Auditor must mark this endpoint as INCONCLUSIVE and send 0 requests
            auditor = APISentinelAuditor(
                spec_path=str(spec_file),
                target_base_url="https://api.example.com",
                remote_ref_config=self.cfg,
            )

            with patch.object(auditor, "_http_request") as mock_http:
                auditor.audit_endpoint_mass_assignment(endpoints[0], endpoints)
                mock_http.assert_not_called()

            self.assertEqual(len(auditor.results), 1)
            self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE.value)
            self.assertEqual(auditor.results[0]["evidence"]["requests_sent"], 0)

    def test_indirect_cycle_across_remote_documents_fails_closed(self) -> None:
        """Doc A -> Doc B -> Doc A is detected as a cycle and marked as INCONCLUSIVE with zero requests."""
        spec_content = {
            "openapi": "3.0.3",
            "info": {"title": "Indirect Cycle", "version": "1.0"},
            "paths": {
                "/items": {
                    "post": {
                        "operationId": "createItem",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "https://schemas.example.com/a.json#/NodeA"}
                                }
                            },
                        },
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = self.dir_path / "spec_indirect_cycle.json"
        spec_file.write_text(json.dumps(spec_content), encoding="utf-8")

        doc_a = {"NodeA": {"$ref": "https://schemas.example.com/b.json#/NodeB"}}
        doc_b = {"NodeB": {"$ref": "https://schemas.example.com/a.json#/NodeA"}}

        def mock_fetch(url: str) -> Dict[str, Any]:
            if "a.json" in url:
                return doc_a
            if "b.json" in url:
                return doc_b
            raise ValueError(f"Unknown: {url}")

        with patch.object(RemoteRefFetcher, "fetch_document", side_effect=mock_fetch):
            parser = OpenAPIParser(str(spec_file), remote_ref_config=self.cfg)
            endpoints = parser.get_endpoints()

            self.assertEqual(len(endpoints), 1)
            self.assertIn("unresolved_schema_error", endpoints[0])
            self.assertIn("Circular", endpoints[0]["unresolved_schema_error"])

            # Dry-run plan must mark as INCONCLUSIVE
            auditor = APISentinelAuditor(
                spec_path=str(spec_file),
                target_base_url="https://api.example.com",
                remote_ref_config=self.cfg,
            )
            plan = auditor.build_plan()
            op = plan["operations"][0]
            self.assertEqual(op["check"], "INCONCLUSIVE")
            self.assertEqual(op["reason_category"], "unresolved_reference")
            self.assertFalse(op["writes_enabled"])


class TestMaxDocsFailedRequestBudget(unittest.TestCase):
    """Test Section 1: max_docs budget accounting including failed HTTP requests and deduplication."""

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_four_different_urls_fail_fifth_is_rejected_without_network(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        session = RemoteRefSession()
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_docs=4,
            session=session,
        )
        fetcher = RemoteRefFetcher(cfg)

        resp404 = MagicMock(status=404, reason="Not Found")
        resp500 = MagicMock(status=500, reason="Internal Server Error")

        # 1. 404
        mock_getresponse.return_value = resp404
        with self.assertRaises(RemoteRefResolutionError):
            fetcher.fetch_document("https://schemas.example.com/fail1.json")

        # 2. Timeout
        mock_getresponse.side_effect = socket.timeout("timed out")
        with self.assertRaises(RemoteRefLimitExceededError):
            fetcher.fetch_document("https://schemas.example.com/fail2.json")
        mock_getresponse.side_effect = None

        # 3. TLS error
        mock_getresponse.side_effect = OSError("TLS handshake failed")
        with self.assertRaises(RemoteRefResolutionError):
            fetcher.fetch_document("https://schemas.example.com/fail3.json")
        mock_getresponse.side_effect = None

        # 4. 500 Internal Server Error
        mock_getresponse.return_value = resp500
        with self.assertRaises(RemoteRefResolutionError):
            fetcher.fetch_document("https://schemas.example.com/fail4.json")

        self.assertEqual(len(session.attempted_urls), 4)

        # Reset mocks to verify URL 5 NEVER reaches DNS or Socket
        mock_getaddrinfo.reset_mock()
        mock_request.reset_mock()

        # 5. Fifth distinct URL rejected by max_docs BEFORE DNS and Socket connection
        with self.assertRaises(RemoteRefLimitExceededError) as ctx:
            fetcher.fetch_document("https://schemas.example.com/fail5.json")

        self.assertIn("Maximum remote document limit (4) reached", str(ctx.exception))
        mock_getaddrinfo.assert_not_called()
        mock_request.assert_not_called()

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_failed_url_repeated_access_does_not_consume_additional_budget_or_network(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        session = RemoteRefSession()
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_docs=4,
            session=session,
        )
        fetcher = RemoteRefFetcher(cfg)

        mock_getresponse.return_value = MagicMock(status=404, reason="Not Found")
        url = "https://schemas.example.com/fail_once.json"

        # First attempt: sends request, fails 404
        with self.assertRaises(RemoteRefResolutionError):
            fetcher.fetch_document(url)

        self.assertEqual(mock_request.call_count, 1)
        self.assertEqual(len(session.attempted_urls), 1)
        self.assertIn(url, session.failed_urls)

        # Second attempt: fails fast from session.failed_urls, 0 new requests
        with self.assertRaises(RemoteRefResolutionError) as ctx:
            fetcher.fetch_document(url)

        self.assertIn("Previous fetch attempt for remote schema failed", str(ctx.exception))
        self.assertEqual(mock_request.call_count, 1)  # Still 1, no new request
        self.assertEqual(len(session.attempted_urls), 1)  # Still 1, no extra budget consumed

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_max_docs_budget_shared_across_distinct_parser_instances(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_getresponse.return_value = MagicMock(status=404, reason="Not Found")

        session = RemoteRefSession()
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_docs=4,
            session=session,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec1_path = dir_path / "spec1.json"
            spec1_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "paths": {
                    "/p1": {"get": {"parameters": [{"$ref": "https://schemas.example.com/p1.json#/param"}]}},
                    "/p2": {"get": {"parameters": [{"$ref": "https://schemas.example.com/p2.json#/param"}]}},
                }
            }))

            spec2_path = dir_path / "spec2.json"
            spec2_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "paths": {
                    "/p3": {"get": {"parameters": [{"$ref": "https://schemas.example.com/p3.json#/param"}]}},
                    "/p4": {"get": {"parameters": [{"$ref": "https://schemas.example.com/p4.json#/param"}]}},
                }
            }))

            spec3_path = dir_path / "spec3.json"
            spec3_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "paths": {
                    "/p5": {"get": {"parameters": [{"$ref": "https://schemas.example.com/p5.json#/param"}]}},
                }
            }))

            parser1 = OpenAPIParser(str(spec1_path), remote_ref_config=cfg)
            parser1.get_endpoints()

            parser2 = OpenAPIParser(str(spec2_path), remote_ref_config=cfg)
            parser2.get_endpoints()

            self.assertEqual(len(session.attempted_urls), 4)

            mock_request.reset_mock()
            mock_getaddrinfo.reset_mock()

            parser3 = OpenAPIParser(str(spec3_path), remote_ref_config=cfg)
            endpoints3 = parser3.get_endpoints()
            self.assertEqual(len(endpoints3), 1)
            self.assertIn("unresolved_schema_error", endpoints3[0])
            self.assertIn("Maximum remote document limit (4) reached", endpoints3[0]["unresolved_schema_error"])
            mock_request.assert_not_called()
            mock_getaddrinfo.assert_not_called()


class TestCacheDepthAdversarialAndPointerCounting(unittest.TestCase):
    """Test Section 2: Cache hits cannot bypass remote depth budget, and intra-document pointer hops count consistently."""

    def test_cache_hit_cannot_bypass_remote_depth_budget(self) -> None:
        """Adversarial test: shallow chain enters cache, then deeper reference to cached item exceeds 10."""
        docs = {
            "https://schemas.example.com/chain_head.json": {"Item": {"$ref": "https://schemas.example.com/hop2.json#/Item"}},
            "https://schemas.example.com/hop2.json": {"Item": {"$ref": "https://schemas.example.com/hop3.json#/Item"}},
            "https://schemas.example.com/hop3.json": {"Item": {"$ref": "https://schemas.example.com/hop4.json#/Item"}},
            "https://schemas.example.com/hop4.json": {"Item": {"$ref": "https://schemas.example.com/hop5.json#/Item"}},
            "https://schemas.example.com/hop5.json": {"Item": {"type": "object", "properties": {"val": {"type": "string"}}}},
            "https://schemas.example.com/deep_head.json": {"Item": {"$ref": "https://schemas.example.com/d2.json#/Item"}},
            "https://schemas.example.com/d2.json": {"Item": {"$ref": "https://schemas.example.com/d3.json#/Item"}},
            "https://schemas.example.com/d3.json": {"Item": {"$ref": "https://schemas.example.com/d4.json#/Item"}},
            "https://schemas.example.com/d4.json": {"Item": {"$ref": "https://schemas.example.com/d5.json#/Item"}},
            "https://schemas.example.com/d5.json": {"Item": {"$ref": "https://schemas.example.com/d6.json#/Item"}},
            "https://schemas.example.com/d6.json": {"Item": {"$ref": "https://schemas.example.com/chain_head.json#/Item"}},
        }

        session = RemoteRefSession()
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_depth=10,
            session=session,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "paths": {
                    "/shallow": {
                        "post": {
                            "operationId": "shallowOp",
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "https://schemas.example.com/chain_head.json#/Item"}
                                    }
                                }
                            }
                        }
                    },
                    "/deep": {
                        "post": {
                            "operationId": "deepOp",
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "https://schemas.example.com/deep_head.json#/Item"}
                                    }
                                }
                            }
                        }
                    }
                }
            }))

            parser = OpenAPIParser(str(spec_path), remote_ref_config=cfg)
            assert parser.remote_fetcher is not None
            parser.remote_fetcher.fetch_document = MagicMock(side_effect=lambda u: docs[u])  # type: ignore

            endpoints = parser.get_endpoints()
            self.assertEqual(len(endpoints), 2)
            shallow_ep = next(ep for ep in endpoints if ep["path"] == "/shallow")
            deep_ep = next(ep for ep in endpoints if ep["path"] == "/deep")

            # Shallow endpoint succeeds and chain_head is placed in cache with depth_cost = 5
            self.assertIsNone(shallow_ep.get("unresolved_schema_error"))
            self.assertIsNotNone(shallow_ep["request_schema"])
            self.assertEqual(shallow_ep["request_schema"]["type"], "object")

            # Deep endpoint hits cache for chain_head, but 6 + 5 = 11 > 10, so it MUST be rejected!
            self.assertIn("unresolved_schema_error", deep_ep)
            self.assertIn("Remote reference depth limit (10) exceeded", deep_ep["unresolved_schema_error"])

    def test_intra_document_remote_json_pointers_counted_consistently(self) -> None:
        """Multiple JSON Pointer hops within the same remote document count against remote depth budget."""
        doc_content: Dict[str, Any] = {}
        for i in range(11):
            doc_content[f"Node{i}"] = {"$ref": f"#/Node{i+1}"}
        doc_content["Node11"] = {"type": "string"}

        session = RemoteRefSession()
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_depth=10,
            session=session,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "paths": {
                    "/intra": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "https://schemas.example.com/tree.json#/Node0"}
                                    }
                                }
                            }
                        }
                    }
                }
            }))

            parser = OpenAPIParser(str(spec_path), remote_ref_config=cfg)
            assert parser.remote_fetcher is not None
            parser.remote_fetcher.fetch_document = MagicMock(return_value=doc_content)  # type: ignore

            endpoints = parser.get_endpoints()
            self.assertEqual(len(endpoints), 1)
            self.assertIn("unresolved_schema_error", endpoints[0])
            self.assertIn("Remote reference depth limit (10) exceeded", endpoints[0]["unresolved_schema_error"])


class TestDepthExhaustionFailClosed(unittest.TestCase):
    """Test Section 3: Depth exhaustion raises exception, never returns raw $ref, fails closed on parameters and request bodies."""

    def test_depth_exhaustion_in_resolve_ref_chain_raises_exception_never_returns_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({"openapi": "3.0.3", "paths": {}}))
            parser = OpenAPIParser(str(spec_path))

            with self.assertRaises(ValueError) as ctx:
                parser._resolve_ref_chain("#/dummy", spec_path, max_depth=0)
            self.assertIn("Reference depth limit", str(ctx.exception))

    def test_mixed_local_and_remote_depth_budget(self) -> None:
        """Mixing local and remote references correctly tracks remote depth while respecting local max_depth."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "paths": {
                    "/test": {
                        "get": {
                            "parameters": [{"$ref": "./local1.json#/param"}]
                        }
                    }
                }
            }))
            local1_path = dir_path / "local1.json"
            local1_path.write_text(json.dumps({
                "param": {"$ref": "https://schemas.example.com/r1.json#/param"}
            }))

            cfg = RemoteRefConfig.create(
                allow_remote_refs=True,
                remote_ref_hosts=["schemas.example.com"],
                max_depth=10,
            )

            # 10 remote docs: allowed
            def mock_fetch(url: str) -> Dict[str, Any]:
                import re
                m = re.search(r"r(\d+)\.json", url)
                idx = int(m.group(1)) if m else 1
                if idx < 10:
                    return {"param": {"$ref": f"https://schemas.example.com/r{idx+1}.json#/param"}}
                return {"param": {"name": "test_param", "in": "query", "schema": {"type": "string"}}}

            parser10 = OpenAPIParser(str(spec_path), remote_ref_config=cfg)
            assert parser10.remote_fetcher is not None
            parser10.remote_fetcher.fetch_document = MagicMock(side_effect=mock_fetch)  # type: ignore
            eps10 = parser10.get_endpoints()
            self.assertIsNone(eps10[0].get("unresolved_schema_error"))
            self.assertEqual(len(eps10[0]["parameters"]), 1)
            self.assertEqual(eps10[0]["parameters"][0]["name"], "test_param")

            # 11 remote docs: exceeds budget
            def mock_fetch11(url: str) -> Dict[str, Any]:
                import re
                m = re.search(r"r(\d+)\.json", url)
                idx = int(m.group(1)) if m else 1
                if idx < 11:
                    return {"param": {"$ref": f"https://schemas.example.com/r{idx+1}.json#/param"}}
                return {"param": {"name": "test_param", "in": "query", "schema": {"type": "string"}}}

            parser11 = OpenAPIParser(str(spec_path), remote_ref_config=cfg)
            assert parser11.remote_fetcher is not None
            parser11.remote_fetcher.fetch_document = MagicMock(side_effect=mock_fetch11)  # type: ignore
            eps11 = parser11.get_endpoints()
            self.assertIn("unresolved_schema_error", eps11[0])
            self.assertIn("Remote reference depth limit (10) exceeded", eps11[0]["unresolved_schema_error"])

    def test_unresolved_parameter_ref_fails_closed_marks_inconclusive_zero_requests(self) -> None:
        """When parameter resolution fails due to remote error, auditor marks INCONCLUSIVE and sends 0 requests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "paths": {
                    "/users/{id}": {
                        "get": {
                            "parameters": [
                                {"$ref": "https://schemas.example.com/unresolved_param.json#/param"}
                            ],
                            "responses": {"200": {"description": "OK"}}
                        }
                    }
                }
            }))

            cfg = RemoteRefConfig.create(
                allow_remote_refs=True,
                remote_ref_hosts=["schemas.example.com"],
            )
            with patch.object(RemoteRefFetcher, "fetch_document", side_effect=RemoteRefResolutionError("404 Not Found")):
                parser = OpenAPIParser(str(spec_path), remote_ref_config=cfg)
                endpoints = parser.get_endpoints()
                self.assertEqual(len(endpoints), 1)
                self.assertIn("unresolved_schema_error", endpoints[0])

                auditor = APISentinelAuditor(
                    spec_path=str(spec_path),
                    target_base_url="https://api.example.com",
                    remote_ref_config=cfg,
                )
                auditor.audit_endpoint_bola(endpoints[0])
                self.assertEqual(len(auditor.results), 1)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE.value)
                self.assertEqual(len(auditor.findings), 0)
                self.assertEqual(auditor.results[0]["evidence"]["requests_sent"], 0)

    def test_unresolved_request_body_schema_fails_closed_zero_requests(self) -> None:
        """When requestBody schema resolution fails, Mass Assignment marks INCONCLUSIVE and sends 0 requests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "paths": {
                    "/users/{id}": {
                        "patch": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "https://schemas.example.com/unresolved_body.json#/Body"}
                                    }
                                }
                            },
                            "responses": {"200": {"description": "OK"}}
                        }
                    }
                }
            }))

            cfg = RemoteRefConfig.create(
                allow_remote_refs=True,
                remote_ref_hosts=["schemas.example.com"],
            )
            with patch.object(RemoteRefFetcher, "fetch_document", side_effect=RemoteRefResolutionError("404 Not Found")):
                parser = OpenAPIParser(str(spec_path), remote_ref_config=cfg)
                endpoints = parser.get_endpoints()
                self.assertEqual(len(endpoints), 1)
                self.assertIn("unresolved_schema_error", endpoints[0])

                auditor = APISentinelAuditor(
                    spec_path=str(spec_path),
                    target_base_url="https://api.example.com",
                    remote_ref_config=cfg,
                )
                auditor._audit_endpoint_mass_assignment(endpoints[0], endpoints)
                self.assertEqual(len(auditor.results), 1)
                self.assertEqual(auditor.results[0]["verdict"], Verdict.INCONCLUSIVE.value)
                self.assertEqual(len(auditor.findings), 0)
                self.assertEqual(auditor.results[0]["evidence"]["requests_sent"], 0)


class TestRemoteSecuritySchemesOnlineAndOffline(unittest.TestCase):
    """Test Section 4: ConfigValidator and OpenAPIParser remote securitySchemes handling."""

    @patch("socket.create_connection")
    @patch("socket.getaddrinfo")
    def test_offline_mode_remote_security_schemes_strictly_zero_network_reports_unresolved(
        self,
        mock_getaddrinfo: MagicMock,
        mock_create_conn: MagicMock,
    ) -> None:
        mock_getaddrinfo.side_effect = AssertionError("DNS resolution must not occur in offline mode!")
        mock_create_conn.side_effect = AssertionError("TCP connection must not occur in offline mode!")

        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "components": {
                    "securitySchemes": {
                        "RemoteAuth": {
                            "$ref": "https://schemas.example.com/auth.yaml#/components/securitySchemes/ApiKey"
                        }
                    }
                },
                "paths": {
                    "/users": {
                        "get": {"responses": {"200": {"description": "OK"}}}
                    }
                }
            }))

            cfg = RemoteRefConfig.create(
                allow_remote_refs=True,
                remote_ref_hosts=["schemas.example.com"],
            )

            result = ConfigValidator.validate(
                {},
                spec_path=str(spec_path),
                remote_ref_config=cfg,
                offline=True,
            )

            mock_getaddrinfo.assert_not_called()
            mock_create_conn.assert_not_called()

            self.assertFalse(result.is_valid)
            issues = [i for i in result.errors if "cannot be fetched in offline validation mode" in i.message]
            self.assertTrue(len(issues) >= 1)
            self.assertEqual(issues[0].actual, "unresolved_reference")

    def test_online_authorized_remote_security_scheme_resolves_successfully(self) -> None:
        """Online mode with explicit authorization resolves remote security scheme."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "components": {
                    "securitySchemes": {
                        "RemoteToken": {
                            "$ref": "https://schemas.example.com/auth.yaml#/components/securitySchemes/ApiKey"
                        }
                    }
                },
                "paths": {
                    "/users": {
                        "get": {
                            "security": [{"RemoteToken": []}],
                            "responses": {"200": {"description": "OK"}}
                        }
                    }
                }
            }))

            auth_doc = {
                "components": {
                    "securitySchemes": {
                        "ApiKey": {
                            "type": "apiKey",
                            "name": "X-Custom-Auth",
                            "in": "header"
                        }
                    }
                }
            }

            cfg = RemoteRefConfig.create(
                allow_remote_refs=True,
                remote_ref_hosts=["schemas.example.com"],
            )

            with patch.object(RemoteRefFetcher, "fetch_document", return_value=auth_doc):
                parser = OpenAPIParser(str(spec_path), remote_ref_config=cfg, offline=False)
                schemes = parser.get_security_schemes()
                self.assertIn("RemoteToken", schemes)
                self.assertEqual(schemes["RemoteToken"]["name"], "X-Custom-Auth")
                self.assertEqual(schemes["RemoteToken"]["in"], "header")

                # ConfigValidator in online mode also resolves auth headers safely
                auth_names = ConfigValidator._extract_spec_auth_headers(
                    parser.raw_spec,
                    spec_path=str(spec_path),
                    remote_ref_config=cfg,
                    offline=False,
                )
                self.assertIn("x-custom-auth", auth_names)

    def test_unsupported_remote_security_scheme_type_raises_error(self) -> None:
        """Unsupported remote security scheme definition raises explicit ValueError."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            spec_path = dir_path / "openapi.json"
            spec_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "components": {
                    "securitySchemes": {
                        "BadScheme": {
                            "$ref": "https://schemas.example.com/auth.yaml#/components/securitySchemes/Bad"
                        }
                    }
                },
                "paths": {}
            }))

            auth_doc = {
                "components": {
                    "securitySchemes": {
                        "Bad": {
                            "type": "unsupported_protocol_scheme",
                        }
                    }
                }
            }

            cfg = RemoteRefConfig.create(
                allow_remote_refs=True,
                remote_ref_hosts=["schemas.example.com"],
            )

            parser = OpenAPIParser(str(spec_path), remote_ref_config=cfg, offline=False)
            assert parser.remote_fetcher is not None
            parser.remote_fetcher.fetch_document = MagicMock(return_value=auth_doc)  # type: ignore

            with self.assertRaises(ValueError) as ctx:
                parser.get_security_schemes()

            self.assertIn("not a supported security scheme", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
