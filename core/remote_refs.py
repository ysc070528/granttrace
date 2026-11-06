# -*- coding: utf-8 -*-
"""Secure remote OpenAPI $ref resolution and transport for GrantTrace.

This module enforces strict security controls for fetching remote OpenAPI
schemas:
1. Explicit opt-in via --allow-remote-refs and exact host allowlisting.
2. HTTPS only with strict TLS certificate verification on standard port 443.
3. SSRF mitigation: full DNS A/AAAA resolution, rejection of private,
   loopback, link-local, multicast, cloud metadata, and IPv4-mapped IPv6 IPs.
4. DNS Rebinding protection: socket connects directly to the pre-validated IP
   while SNI and TLS certificate verification validate the target hostname.
5. Zero HTTP redirects permitted (3xx is rejected).
6. Strict resource limits: 512 KiB per document, 2 MiB cumulative, 4 documents
   maximum, recursion depth 10, 3-second timeout, no compression auto-expansion.
7. Credential isolation: never sends Authorization, Cookie, or API keys.
8. Context isolation: remote documents cannot reference local files.
"""

from __future__ import annotations

import errno
import http.client
import ipaddress
import json
import socket
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit


class RemoteRefError(ValueError):
    """Base exception for all remote $ref errors."""


class RemoteRefDisabledError(RemoteRefError):
    """Raised when remote $ref resolution is not enabled."""


class RemoteRefOfflineBlockedError(RemoteRefDisabledError):
    """Raised when a remote $ref is encountered in an offline mode."""


class RemoteRefNotAllowedHostError(RemoteRefError):
    """Raised when the target host is not in the allowlist."""


class RemoteRefSecurityError(RemoteRefError):
    """Raised when an SSRF or transport security violation is detected."""


class RemoteRefLimitExceededError(RemoteRefError):
    """Raised when size, document count, depth or timeout limits are exceeded."""


class RemoteRefResolutionError(RemoteRefError):
    """Raised when a remote reference cannot be fetched or resolved."""


# Specific cloud metadata and non-routable IP networks/addresses to block
_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT / Shared Address Space (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("198.18.0.0/15"),    # Network benchmark tests (RFC 2544)
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network (RFC 1122)
)

_BLOCKED_EXACT_IPS = {
    "169.254.169.254",  # AWS, GCP, Azure, OpenStack instance metadata
    "100.100.100.200",  # Alibaba Cloud instance metadata
    "169.254.170.2",    # AWS ECS task metadata
}


@dataclass
class RemoteRefSession:
    """State shared across all RemoteRefFetcher and OpenAPIParser instances in a session."""

    document_cache: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    total_bytes_downloaded: int = 0
    failed_urls: Set[str] = field(default_factory=set)
    attempted_urls: Set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass(frozen=True)
class RemoteRefConfig:
    """Security configuration for remote $ref resolution."""

    allow_remote_refs: bool = False
    remote_ref_hosts: FrozenSet[str] = field(default_factory=frozenset)
    max_doc_bytes: int = 512 * 1024       # 512 KiB
    max_total_bytes: int = 2 * 1024 * 1024  # 2 MiB
    max_docs: int = 4
    max_depth: int = 10
    timeout: float = 3.0
    allow_loopback_for_testing: bool = False  # ONLY for internal tests
    session: RemoteRefSession = field(default_factory=RemoteRefSession)

    @classmethod
    def create(
        cls,
        allow_remote_refs: bool = False,
        remote_ref_hosts: Optional[Set[str] | List[str]] = None,
        max_doc_bytes: int = 512 * 1024,
        max_total_bytes: int = 2 * 1024 * 1024,
        max_docs: int = 4,
        max_depth: int = 10,
        timeout: float = 3.0,
        allow_loopback_for_testing: bool = False,
        session: Optional[RemoteRefSession] = None,
    ) -> RemoteRefConfig:
        normalized_hosts = frozenset(
            h.strip().lower() for h in (remote_ref_hosts or []) if h and h.strip()
        )
        return cls(
            allow_remote_refs=bool(allow_remote_refs),
            remote_ref_hosts=normalized_hosts,
            max_doc_bytes=max_doc_bytes,
            max_total_bytes=max_total_bytes,
            max_docs=max_docs,
            max_depth=max_depth,
            timeout=timeout,
            allow_loopback_for_testing=allow_loopback_for_testing,
            session=session if session is not None else RemoteRefSession(),
        )


def validate_ip_address(ip_str: str, allow_loopback: bool = False) -> None:
    """Validate that an IP address is a safe public routable address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as exc:
        raise RemoteRefSecurityError(f"Invalid IP address format: {ip_str}") from exc

    # Unpack IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        check_ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ip.ipv4_mapped
    else:
        check_ip = ip

    ip_repr = str(check_ip)

    if allow_loopback and check_ip.is_loopback:
        return

    # Check against known cloud metadata IPs
    if ip_repr in _BLOCKED_EXACT_IPS:
        raise RemoteRefSecurityError(f"Access to cloud metadata IP is blocked: {ip_str}")

    # Check against blocked special CIDRs
    for net in _BLOCKED_NETWORKS:
        if isinstance(check_ip, ipaddress.IPv4Address) and check_ip in net:
            raise RemoteRefSecurityError(f"Access to reserved IP range {net} is blocked: {ip_str}")

    # Standard RFC IP classification
    if check_ip.is_loopback:
        raise RemoteRefSecurityError(f"Loopback IP address is blocked: {ip_str}")
    if check_ip.is_private:
        raise RemoteRefSecurityError(f"Private IP address is blocked: {ip_str}")
    if check_ip.is_link_local:
        raise RemoteRefSecurityError(f"Link-local IP address is blocked: {ip_str}")
    if check_ip.is_multicast:
        raise RemoteRefSecurityError(f"Multicast IP address is blocked: {ip_str}")
    if check_ip.is_reserved:
        raise RemoteRefSecurityError(f"Reserved IP address is blocked: {ip_str}")
    if check_ip.is_unspecified:
        raise RemoteRefSecurityError(f"Unspecified IP address is blocked: {ip_str}")
    if not check_ip.is_global:
        raise RemoteRefSecurityError(f"Non-global IP address is blocked: {ip_str}")


def resolve_safe_ips(hostname: str, allow_loopback: bool = False) -> List[str]:
    """Resolve all A/AAAA records for hostname and verify all are safe."""
    try:
        addrinfo = socket.getaddrinfo(
            hostname, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise RemoteRefResolutionError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    if not addrinfo:
        raise RemoteRefResolutionError(f"No DNS records found for '{hostname}'")

    safe_ips: List[str] = []
    for entry in addrinfo:
        sockaddr = entry[4]
        ip_str = str(sockaddr[0])
        validate_ip_address(ip_str, allow_loopback=allow_loopback)
        if ip_str not in safe_ips:
            safe_ips.append(ip_str)

    if not safe_ips:
        raise RemoteRefResolutionError(f"No safe IP addresses found for '{hostname}'")

    return safe_ips


def split_remote_ref(ref_uri: str) -> Tuple[str, str]:
    """Split a remote ref URI into its document URL and JSON Pointer fragment."""
    if not isinstance(ref_uri, str) or not ref_uri.strip():
        raise RemoteRefResolutionError("$ref must be a non-empty string")

    parsed = urlsplit(ref_uri)
    doc_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    fragment = unquote(parsed.fragment)
    return doc_url, fragment


def resolve_remote_reference_uri(base_doc_url: str, ref_uri: str) -> Tuple[str, str]:
    """Resolve a $ref URI against a remote base document URL.

    Handles relative sub-paths (e.g., 'common.yaml#/Item') as well as intra-document
    fragments (e.g., '#/components/schemas/User').
    """
    if not isinstance(ref_uri, str) or not ref_uri.strip():
        raise RemoteRefResolutionError("$ref must be a non-empty string")

    joined = urljoin(base_doc_url, ref_uri)
    parsed = urlsplit(joined)
    doc_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    fragment = unquote(parsed.fragment)
    return doc_url, fragment


class PinnedIPHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that binds directly to a pre-validated IP to stop DNS Rebinding.

    The underlying TCP socket connects to ``pinned_ip:port`` without performing
    another DNS lookup. The TLS handshake validates ``target_hostname`` via SNI
    and certificate subject checking.
    """

    def __init__(
        self,
        pinned_ip: str,
        target_hostname: str,
        port: int = 443,
        timeout: float = 3.0,
        context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.ssl_ctx = context or ssl.create_default_context()
        super().__init__(host=pinned_ip, port=port, timeout=timeout, context=self.ssl_ctx)
        self.target_hostname = target_hostname

    def connect(self) -> None:
        source_addr = getattr(self, "source_address", None)
        self.sock = socket.create_connection(
            (self.host, self.port), self.timeout, source_addr
        )
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            if exc.errno != errno.ENOPROTOOPT:
                raise

        self.sock = self.ssl_ctx.wrap_socket(
            self.sock, server_hostname=self.target_hostname
        )


class RemoteRefFetcher:
    """Secure stateful fetcher for remote OpenAPI schemas."""

    def __init__(
        self,
        config: RemoteRefConfig,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.config = config
        self._custom_ssl_context = ssl_context
        self.session = config.session

    @property
    def _document_cache(self) -> Dict[str, Dict[str, Any]]:
        return self.session.document_cache

    @property
    def fetched_document_count(self) -> int:
        return len(self.session.document_cache)

    @property
    def attempted_document_count(self) -> int:
        return len(self.session.attempted_urls)

    @property
    def total_bytes_downloaded(self) -> int:
        return self.session.total_bytes_downloaded

    def is_remote_ref(self, ref_uri: str) -> bool:
        if not isinstance(ref_uri, str) or not ref_uri:
            return False
        parsed = urlsplit(ref_uri)
        return bool(parsed.scheme or parsed.netloc)

    def validate_ref_url(self, url: str) -> Tuple[str, str, int]:
        """Validate that a URL complies with all security policies."""
        if not self.config.allow_remote_refs:
            raise RemoteRefDisabledError(
                f"Remote $ref resolution is disabled; pass --allow-remote-refs and "
                f"--remote-ref-host to authorize: {url}"
            )

        if not self.config.remote_ref_hosts:
            raise RemoteRefDisabledError(
                f"No remote $ref hosts authorized; pass --remote-ref-host <HOST>: {url}"
            )

        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise RemoteRefSecurityError(
                f"Only HTTPS remote $ref values are permitted (got '{parsed.scheme}'): {url}"
            )

        netloc = parsed.netloc
        if not netloc:
            raise RemoteRefSecurityError(f"Remote $ref URL missing host: {url}")

        if "@" in netloc or parsed.username or parsed.password:
            raise RemoteRefSecurityError(
                f"Userinfo credentials in remote $ref URL are forbidden: {url}"
            )

        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            raise RemoteRefSecurityError(f"Invalid host in remote $ref URL: {url}")

        if any(ord(c) < 32 or ord(c) >= 127 for c in hostname):
            raise RemoteRefSecurityError(f"Control or non-ASCII characters in host: {url}")

        # Port validation: only standard 443 permitted
        port = parsed.port or 443
        if port != 443:
            raise RemoteRefSecurityError(
                f"Non-standard port {port} is forbidden for remote $ref: {url}"
            )

        # Host allowlist exact matching
        if hostname not in self.config.remote_ref_hosts:
            raise RemoteRefNotAllowedHostError(
                f"Remote host '{hostname}' is not in the authorized allowlist "
                f"{sorted(self.config.remote_ref_hosts)}: {url}"
            )

        return hostname, parsed.path or "/", port

    def fetch_document(self, doc_url: str) -> Dict[str, Any]:
        """Fetch, validate, and parse a remote OpenAPI JSON/YAML schema document."""
        canonical_url = urlunsplit(urlsplit(doc_url)[:4] + ("",))

        # Host allowlist and URL syntax validation
        hostname, path, port = self.validate_ref_url(canonical_url)

        with self.session.lock:
            # 1. Check cache first (deduplication across entire execution)
            if canonical_url in self.session.document_cache:
                return self.session.document_cache[canonical_url]

            # 2. Check failed URLs
            if canonical_url in self.session.failed_urls:
                raise RemoteRefResolutionError(
                    f"Previous fetch attempt for remote schema failed: {canonical_url}"
                )

            # 3. Check document count limit before DNS and Socket connection
            if canonical_url not in self.session.attempted_urls:
                if len(self.session.attempted_urls) >= self.config.max_docs:
                    raise RemoteRefLimitExceededError(
                        f"Maximum remote document limit ({self.config.max_docs}) reached; "
                        f"refusing to fetch: {doc_url}"
                    )
                self.session.attempted_urls.add(canonical_url)

        conn: Optional[PinnedIPHTTPSConnection] = None
        try:
            # DNS resolution and SSRF defense
            safe_ips = resolve_safe_ips(
                hostname, allow_loopback=self.config.allow_loopback_for_testing
            )
            pinned_ip = safe_ips[0]

            # Prepare SSL context
            if self._custom_ssl_context is not None:
                ctx = self._custom_ssl_context
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED

            # Connection setup with IP pinning
            conn = PinnedIPHTTPSConnection(
                pinned_ip=pinned_ip,
                target_hostname=hostname,
                port=port,
                timeout=self.config.timeout,
                context=ctx,
            )

            req_path = path
            parsed_query = urlsplit(canonical_url).query
            if parsed_query:
                req_path = f"{path}?{parsed_query}"

            headers = {
                "Host": hostname,
                "User-Agent": "GrantTrace-Schema-Fetcher/2.5.3",
                "Accept": "application/json, application/yaml, text/yaml, */*",
                "Connection": "close",
            }
            conn.request("GET", req_path, headers=headers)
            resp = conn.getresponse()

            # Forbid all HTTP redirects
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location", "")
                raise RemoteRefSecurityError(
                    f"HTTP redirect ({resp.status}) to '{location}' is forbidden for remote $ref: {canonical_url}"
                )

            if resp.status != 200:
                raise RemoteRefResolutionError(
                    f"HTTP {resp.status} {resp.reason} fetching remote schema: {canonical_url}"
                )

            # Check declared Content-Length
            content_length_header = resp.getheader("Content-Length")
            if content_length_header:
                try:
                    declared_len: Optional[int] = int(content_length_header)
                except (ValueError, TypeError):
                    declared_len = None

                if declared_len is not None and declared_len > self.config.max_doc_bytes:
                    raise RemoteRefLimitExceededError(
                        f"Remote document Content-Length ({declared_len} bytes) exceeds limit "
                        f"({self.config.max_doc_bytes} bytes): {canonical_url}"
                    )

            # Stream body with chunk-by-chunk enforcement
            chunks: List[bytes] = []
            doc_bytes = 0
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                doc_bytes += len(chunk)
                with self.session.lock:
                    self.session.total_bytes_downloaded += len(chunk)
                    if doc_bytes > self.config.max_doc_bytes:
                        self.session.failed_urls.add(canonical_url)
                        raise RemoteRefLimitExceededError(
                            f"Remote document body exceeded limit of {self.config.max_doc_bytes} bytes: {canonical_url}"
                        )
                    if self.session.total_bytes_downloaded > self.config.max_total_bytes:
                        self.session.failed_urls.add(canonical_url)
                        raise RemoteRefLimitExceededError(
                            f"Cumulative remote download exceeded limit of {self.config.max_total_bytes} bytes"
                        )
                chunks.append(chunk)

            raw_bytes = b"".join(chunks)

            # Decode and parse JSON/YAML
            try:
                text = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise RemoteRefResolutionError(
                    f"Remote document is not valid UTF-8: {canonical_url}"
                ) from exc

            parsed_data = self._parse_schema_content(text, canonical_url)

            if not isinstance(parsed_data, dict):
                raise RemoteRefResolutionError(
                    f"Remote schema root must be a JSON/YAML mapping: {canonical_url}"
                )

            with self.session.lock:
                self.session.document_cache[canonical_url] = parsed_data
            return parsed_data

        except (socket.timeout, TimeoutError) as exc:
            with self.session.lock:
                self.session.failed_urls.add(canonical_url)
            raise RemoteRefLimitExceededError(
                f"Timed out fetching remote $ref after {self.config.timeout}s: {canonical_url}"
            ) from exc
        except (ssl.SSLError, OSError) as exc:
            with self.session.lock:
                self.session.failed_urls.add(canonical_url)
            if isinstance(exc, RemoteRefError):
                raise
            raise RemoteRefResolutionError(
                f"Network/TLS error fetching remote $ref '{canonical_url}': {exc}"
            ) from exc
        except Exception:
            with self.session.lock:
                self.session.failed_urls.add(canonical_url)
            raise
        finally:
            if conn is not None:
                conn.close()

    @staticmethod
    def _parse_schema_content(text: str, source_url: str) -> Any:
        """Parse text as JSON or YAML."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                "YAML remote schema files require the PyYAML package; "
                "install it with 'pip install pyyaml'"
            ) from exc

        try:
            return yaml.safe_load(text)
        except Exception as exc:
            raise RemoteRefResolutionError(
                f"Failed to parse remote schema as JSON or YAML: {source_url}: {exc}"
            ) from exc
