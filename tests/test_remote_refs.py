# -*- coding: utf-8 -*-
"""Unit tests for secure remote $ref resolution and transport."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import MagicMock, patch

from core.remote_refs import (
    PinnedIPHTTPSConnection,
    RemoteRefConfig,
    RemoteRefDisabledError,
    RemoteRefFetcher,
    RemoteRefLimitExceededError,
    RemoteRefNotAllowedHostError,
    RemoteRefResolutionError,
    RemoteRefSecurityError,
    resolve_remote_reference_uri,
    resolve_safe_ips,
    split_remote_ref,
    validate_ip_address,
)


class TestIPValidation(unittest.TestCase):
    """Test IP address safety classification and SSRF filtering."""

    def test_safe_public_ips_allowed(self) -> None:
        safe_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "140.82.112.4",
            "2606:2800:220:1:248:1893:25c8:1946",
            "2001:4860:4860::8888",
        ]
        for ip in safe_ips:
            with self.subTest(ip=ip):
                validate_ip_address(ip)

    def test_loopback_ips_blocked(self) -> None:
        loopbacks = [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.255",
            "::1",
        ]
        for ip in loopbacks:
            with self.subTest(ip=ip):
                with self.assertRaises(RemoteRefSecurityError):
                    validate_ip_address(ip)

    def test_loopback_allowed_only_when_explicitly_flagged(self) -> None:
        validate_ip_address("127.0.0.1", allow_loopback=True)
        validate_ip_address("::1", allow_loopback=True)

    def test_private_ips_blocked(self) -> None:
        private_ips = [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.100",
            "fc00::1",
            "fd00::1",
        ]
        for ip in private_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(RemoteRefSecurityError):
                    validate_ip_address(ip)

    def test_link_local_and_multicast_blocked(self) -> None:
        blocked = [
            "169.254.0.1",
            "169.254.169.254",
            "fe80::1",
            "224.0.0.1",
            "ff02::1",
        ]
        for ip in blocked:
            with self.subTest(ip=ip):
                with self.assertRaises(RemoteRefSecurityError):
                    validate_ip_address(ip)

    def test_cloud_metadata_blocked(self) -> None:
        metadata_ips = [
            "169.254.169.254",
            "100.100.100.200",
            "169.254.170.2",
        ]
        for ip in metadata_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(RemoteRefSecurityError):
                    validate_ip_address(ip)

    def test_carrier_grade_nat_blocked(self) -> None:
        cgnat_ips = ["100.64.0.1", "100.127.255.254"]
        for ip in cgnat_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(RemoteRefSecurityError):
                    validate_ip_address(ip)

    def test_ipv4_mapped_ipv6_blocked(self) -> None:
        mapped = [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:192.168.1.1",
        ]
        for ip in mapped:
            with self.subTest(ip=ip):
                with self.assertRaises(RemoteRefSecurityError):
                    validate_ip_address(ip)

    def test_malformed_ip_blocked(self) -> None:
        with self.assertRaises(RemoteRefSecurityError):
            validate_ip_address("999.999.999.999")
        with self.assertRaises(RemoteRefSecurityError):
            validate_ip_address("not-an-ip")


class TestDNSResolution(unittest.TestCase):
    """Test DNS resolution and SSRF defense."""

    @patch("socket.getaddrinfo")
    def test_safe_domain_resolves(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        ips = resolve_safe_ips("schemas.example.com")
        self.assertEqual(ips, ["93.184.216.34"])

    @patch("socket.getaddrinfo")
    def test_domain_resolving_to_private_ip_is_blocked(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))
        ]
        with self.assertRaises(RemoteRefSecurityError):
            resolve_safe_ips("internal.corp")

    @patch("socket.getaddrinfo")
    def test_mixed_resolution_fails_closed(self, mock_getaddrinfo: MagicMock) -> None:
        # If any IP in A/AAAA records is private, whole domain is rejected
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with self.assertRaises(RemoteRefSecurityError):
            resolve_safe_ips("rebinding.example.com")

    @patch("socket.getaddrinfo")
    def test_dns_resolution_failure_raises(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.side_effect = socket.gaierror(8, "nodename nor servname provided")
        with self.assertRaises(RemoteRefResolutionError):
            resolve_safe_ips("nonexistent.domain.xyz")


class TestURLValidation(unittest.TestCase):
    """Test remote ref URL policy and host allowlisting."""

    def test_disabled_by_default(self) -> None:
        fetcher = RemoteRefFetcher(RemoteRefConfig())
        with self.assertRaises(RemoteRefDisabledError):
            fetcher.validate_ref_url("https://schemas.example.com/user.json")

    def test_missing_host_allowlist(self) -> None:
        cfg = RemoteRefConfig.create(allow_remote_refs=True, remote_ref_hosts=[])
        fetcher = RemoteRefFetcher(cfg)
        with self.assertRaises(RemoteRefDisabledError):
            fetcher.validate_ref_url("https://schemas.example.com/user.json")

    def test_non_https_rejected(self) -> None:
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True, remote_ref_hosts=["schemas.example.com"]
        )
        fetcher = RemoteRefFetcher(cfg)
        forbidden_schemes = [
            "http://schemas.example.com/user.json",
            "file:///etc/passwd",
            "ftp://schemas.example.com/user.json",
            "data:text/json,{}",
            "gopher://schemas.example.com/user.json",
        ]
        for url in forbidden_schemes:
            with self.subTest(url=url):
                with self.assertRaises(RemoteRefSecurityError):
                    fetcher.validate_ref_url(url)

    def test_non_standard_port_rejected(self) -> None:
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True, remote_ref_hosts=["schemas.example.com"]
        )
        fetcher = RemoteRefFetcher(cfg)
        with self.assertRaises(RemoteRefSecurityError):
            fetcher.validate_ref_url("https://schemas.example.com:8443/user.json")
        with self.assertRaises(RemoteRefSecurityError):
            fetcher.validate_ref_url("https://schemas.example.com:80/user.json")

    def test_userinfo_rejected(self) -> None:
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True, remote_ref_hosts=["schemas.example.com"]
        )
        fetcher = RemoteRefFetcher(cfg)
        with self.assertRaises(RemoteRefSecurityError):
            fetcher.validate_ref_url("https://admin:pass@schemas.example.com/user.json")
        with self.assertRaises(RemoteRefSecurityError):
            fetcher.validate_ref_url("https://user@schemas.example.com/user.json")

    def test_host_allowlist_exact_match(self) -> None:
        cfg = RemoteRefConfig.create(
            allow_remote_refs=True, remote_ref_hosts=["schemas.example.com"]
        )
        fetcher = RemoteRefFetcher(cfg)

        # Exact match (case insensitive) passes
        host, path, port = fetcher.validate_ref_url("https://schemas.example.com/models/user.json")
        self.assertEqual(host, "schemas.example.com")
        self.assertEqual(path, "/models/user.json")
        self.assertEqual(port, 443)

        host, _, _ = fetcher.validate_ref_url("https://SCHEMAS.EXAMPLE.COM/models/user.json")
        self.assertEqual(host, "schemas.example.com")

        # Subdomains or prefix/suffix variations are rejected
        with self.assertRaises(RemoteRefNotAllowedHostError):
            fetcher.validate_ref_url("https://sub.schemas.example.com/user.json")
        with self.assertRaises(RemoteRefNotAllowedHostError):
            fetcher.validate_ref_url("https://evil-schemas.example.com/user.json")
        with self.assertRaises(RemoteRefNotAllowedHostError):
            fetcher.validate_ref_url("https://other.org/user.json")


class TestReferenceURIHelpers(unittest.TestCase):
    """Test split_remote_ref and resolve_remote_reference_uri."""

    def test_split_remote_ref(self) -> None:
        doc_url, fragment = split_remote_ref("https://schemas.example.com/user.json#/components/schemas/User")
        self.assertEqual(doc_url, "https://schemas.example.com/user.json")
        self.assertEqual(fragment, "/components/schemas/User")

        doc_url2, fragment2 = split_remote_ref("https://schemas.example.com/user.json")
        self.assertEqual(doc_url2, "https://schemas.example.com/user.json")
        self.assertEqual(fragment2, "")

    def test_resolve_remote_reference_uri_relative(self) -> None:
        base = "https://schemas.example.com/v1/user.yaml"

        # Intra-document pointer
        doc_url, fragment = resolve_remote_reference_uri(base, "#/components/schemas/Address")
        self.assertEqual(doc_url, "https://schemas.example.com/v1/user.yaml")
        self.assertEqual(fragment, "/components/schemas/Address")

        # Relative document on same host
        doc_url, fragment = resolve_remote_reference_uri(base, "common.yaml#/definitions/Id")
        self.assertEqual(doc_url, "https://schemas.example.com/v1/common.yaml")
        self.assertEqual(fragment, "/definitions/Id")

        # Absolute path on same host
        doc_url, fragment = resolve_remote_reference_uri(base, "/v2/base.json#/Item")
        self.assertEqual(doc_url, "https://schemas.example.com/v2/base.json")
        self.assertEqual(fragment, "/Item")


class TestRemoteRefFetcherLimitsAndMock(unittest.TestCase):
    """Test fetcher resource limits, caching, and security checks."""

    def setUp(self) -> None:
        self.cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_doc_bytes=1024,
            max_total_bytes=2048,
            max_docs=2,
            timeout=1.0,
        )
        self.fetcher = RemoteRefFetcher(self.cfg)

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_successful_json_fetch_and_cache(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = None
        mock_resp.read.side_effect = [b'{"type": "object", "properties": {"name": {"type": "string"}}}', b""]
        mock_getresponse.return_value = mock_resp

        doc = self.fetcher.fetch_document("https://schemas.example.com/user.json")
        self.assertEqual(doc["type"], "object")
        self.assertIn("name", doc["properties"])
        self.assertEqual(self.fetcher.fetched_document_count, 1)

        # Second fetch should hit cache without network calls
        mock_request.reset_mock()
        doc2 = self.fetcher.fetch_document("https://schemas.example.com/user.json")
        self.assertEqual(doc2, doc)
        mock_request.assert_not_called()

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_redirect_strictly_forbidden(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        for code in (301, 302, 303, 307, 308):
            with self.subTest(status=code):
                mock_resp = MagicMock()
                mock_resp.status = code
                mock_resp.getheader.return_value = "https://schemas.example.com/redirected.json"
                mock_getresponse.return_value = mock_resp

                fetcher = RemoteRefFetcher(self.cfg)
                with self.assertRaises(RemoteRefSecurityError) as ctx:
                    fetcher.fetch_document(f"https://schemas.example.com/doc-{code}.json")
                self.assertIn("HTTP redirect", str(ctx.exception))

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_single_document_size_limit_exceeded(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = "2000"  # Exceeds max_doc_bytes (1024)
        mock_getresponse.return_value = mock_resp

        with self.assertRaises(RemoteRefLimitExceededError):
            self.fetcher.fetch_document("https://schemas.example.com/huge.json")

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_max_document_count_limit(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = None
        mock_resp.read.side_effect = [b'{"type": "string"}', b""]
        mock_getresponse.return_value = mock_resp

        # Fetch doc 1 (passes)
        self.fetcher.fetch_document("https://schemas.example.com/doc1.json")
        # Fetch doc 2 (passes, limit is 2)
        mock_resp.read.side_effect = [b'{"type": "number"}', b""]
        self.fetcher.fetch_document("https://schemas.example.com/doc2.json")
        # Fetch doc 3 (must raise limit exceeded)
        with self.assertRaises(RemoteRefLimitExceededError) as ctx:
            self.fetcher.fetch_document("https://schemas.example.com/doc3.json")
        self.assertIn("Maximum remote document limit", str(ctx.exception))



    def test_unspecified_and_reserved_ips_blocked(self) -> None:
        blocked = ["0.0.0.0", "::", "240.0.0.1"]
        for ip in blocked:
            with self.subTest(ip=ip):
                with self.assertRaises(RemoteRefSecurityError):
                    validate_ip_address(ip)

    def test_is_remote_ref(self) -> None:
        self.assertTrue(self.fetcher.is_remote_ref("https://schemas.example.com/item.json"))
        self.assertTrue(self.fetcher.is_remote_ref("//schemas.example.com/item.json"))
        self.assertFalse(self.fetcher.is_remote_ref("#/definitions/Item"))
        self.assertFalse(self.fetcher.is_remote_ref("common.yaml#/Item"))
        self.assertFalse(self.fetcher.is_remote_ref(""))

    def test_properties_reporting(self) -> None:
        self.assertEqual(self.fetcher.fetched_document_count, 0)
        self.assertEqual(self.fetcher.total_bytes_downloaded, 0)

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_http_error_status_raises(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.reason = "Not Found"
        mock_getresponse.return_value = mock_resp

        with self.assertRaises(RemoteRefResolutionError) as ctx:
            self.fetcher.fetch_document("https://schemas.example.com/missing.json")
        self.assertIn("HTTP 404 Not Found", str(ctx.exception))

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_chunk_streaming_size_limit_exceeded(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = None  # No Content-Length header
        mock_resp.read.side_effect = [b"a" * 800, b"b" * 800]  # Total 1600 > max_doc_bytes (1024)
        mock_getresponse.return_value = mock_resp

        with self.assertRaises(RemoteRefLimitExceededError) as ctx:
            self.fetcher.fetch_document("https://schemas.example.com/stream-huge.json")
        self.assertIn("exceeded limit", str(ctx.exception))

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_cumulative_size_limit_exceeded(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = None
        custom_cfg = RemoteRefConfig.create(
            allow_remote_refs=True,
            remote_ref_hosts=["schemas.example.com"],
            max_doc_bytes=2000,
            max_total_bytes=2500,
            max_docs=4,
        )
        fetcher = RemoteRefFetcher(custom_cfg)
        mock_resp.read.side_effect = [b"x" * 1500, b"", b"y" * 1500, b""]
        mock_getresponse.return_value = mock_resp

        with patch.object(fetcher, "_parse_schema_content", return_value={"test": 1}):
            fetcher.fetch_document("https://schemas.example.com/d1.json")
            with self.assertRaises(RemoteRefLimitExceededError) as ctx:
                fetcher.fetch_document("https://schemas.example.com/d2.json")
            self.assertIn("Cumulative remote download exceeded limit", str(ctx.exception))

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_timeout_and_network_errors(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_request.side_effect = TimeoutError("Connection timed out")

        with self.assertRaises(RemoteRefLimitExceededError) as ctx:
            self.fetcher.fetch_document("https://schemas.example.com/timeout.json")
        self.assertIn("Timed out", str(ctx.exception))

        mock_request.side_effect = OSError("Connection reset by peer")
        with self.assertRaises(RemoteRefResolutionError) as ctx:
            self.fetcher.fetch_document("https://schemas.example.com/oserror.json")
        self.assertIn("Network/TLS error", str(ctx.exception))

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_non_utf8_and_non_dict_root_rejected(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = None
        mock_resp.read.side_effect = [b"\xff\xfe\x00\x00", b""]
        mock_getresponse.return_value = mock_resp

        with self.assertRaises(RemoteRefResolutionError) as ctx:
            self.fetcher.fetch_document("https://schemas.example.com/bad-utf8.json")
        self.assertIn("not valid UTF-8", str(ctx.exception))

        mock_resp.read.side_effect = [b'["array", "root", "not", "dict"]', b""]
        with self.assertRaises(RemoteRefResolutionError) as ctx:
            self.fetcher.fetch_document("https://schemas.example.com/array-root.json")
        self.assertIn("root must be a JSON/YAML mapping", str(ctx.exception))

    @patch("socket.getaddrinfo")
    @patch.object(PinnedIPHTTPSConnection, "request")
    @patch.object(PinnedIPHTTPSConnection, "getresponse")
    def test_yaml_schema_parsing(
        self,
        mock_getresponse: MagicMock,
        mock_request: MagicMock,
        mock_getaddrinfo: MagicMock,
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        yaml_content = b"title: Sample\ntype: object\nproperties:\n  id:\n    type: integer\n"
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = str(len(yaml_content))
        mock_resp.read.side_effect = [yaml_content, b""]
        mock_getresponse.return_value = mock_resp

        data = self.fetcher.fetch_document("https://schemas.example.com/schema.yaml")
        self.assertIsInstance(data, dict)
        self.assertEqual(data["title"], "Sample")
        self.assertIn("id", data["properties"])


if __name__ == "__main__":
    unittest.main()
