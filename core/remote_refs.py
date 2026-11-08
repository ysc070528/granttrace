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
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from core import __version__
from core.yaml_safety import safe_load_yaml


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


class InvalidRemoteRefHostError(RemoteRefError):
    """Raised when an allowlist entry can never equal a remote $ref URL host."""


_HOST_LABEL_RE = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
_MAX_HOST_NAME_LENGTH = 253


def _canonical_ip_literal(host: str) -> Optional[str]:
    """Return the canonical text of an IP literal, or None for a host name."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def normalize_remote_ref_host(value: object) -> str:
    """Return the allowlist form of a --remote-ref-host value.

    Remote $ref URLs are authorized by exact host. A value that can never be
    such a host (scheme, port, path, userinfo, wildcard) used to be accepted
    and then authorize nothing, so it is rejected here. Messages never echo
    the value: callers decide how to display it safely.
    """
    if not isinstance(value, str):
        raise InvalidRemoteRefHostError("the value must be a string")
    host = value.strip().lower()
    if not host:
        raise InvalidRemoteRefHostError("the value is empty")
    if any(char.isspace() for char in host):
        raise InvalidRemoteRefHostError("the value contains whitespace")
    if any(ord(char) < 32 or ord(char) == 127 for char in host):
        raise InvalidRemoteRefHostError("the value contains control characters")
    if not host.isascii():
        hint = ""
        try:
            hint = f"; use the IDNA form '{value.strip().encode('idna').decode('ascii')}'"
        except UnicodeError:
            pass
        raise InvalidRemoteRefHostError(f"the host name must be ASCII{hint}")
    if "://" in host:
        raise InvalidRemoteRefHostError(
            "the value contains a URL scheme; pass only the host name, e.g. 'schemas.example.com'"
        )
    if "@" in host:
        raise InvalidRemoteRefHostError("the value contains credentials ('@'); pass only the host name")
    if "*" in host:
        raise InvalidRemoteRefHostError(
            "wildcards are not supported; repeat --remote-ref-host for each exact host"
        )
    if any(char in host for char in "/?#\\"):
        raise InvalidRemoteRefHostError(
            "the value contains a path, query or fragment; pass only the host name"
        )
    if "[" in host or "]" in host:
        if host.startswith("[") and "]:" in host:
            raise InvalidRemoteRefHostError(
                "the value contains a port; remote $ref URLs must use the default HTTPS port 443"
            )
        inner = host[1:-1] if host.startswith("[") and host.endswith("]") else ""
        address = _canonical_ip_literal(inner) if ":" in inner else None
        if address is None:
            raise InvalidRemoteRefHostError("the bracketed value is not a valid IPv6 address")
        return address
    address = _canonical_ip_literal(host)
    if address is not None:
        return address
    if ":" in host:
        raise InvalidRemoteRefHostError(
            "the value contains a port; remote $ref URLs must use the default HTTPS port 443"
        )
    name = host[:-1] if host.endswith(".") else host
    if len(host) > _MAX_HOST_NAME_LENGTH or not all(
        _HOST_LABEL_RE.fullmatch(label) for label in name.split(".")
    ):
        raise InvalidRemoteRefHostError("the value is not a valid host name")
    return host


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

# Never globally routable, whatever they embed. Listed explicitly because
# CPython's is_private/is_global tables differ between patch releases.
_BLOCKED_IPV6_NETWORKS = (
    ipaddress.ip_network("::/96"),           # Deprecated IPv4-compatible addresses
    ipaddress.ip_network("64:ff9b:1::/48"),  # Local-use NAT64 prefix (RFC 8215)
    ipaddress.ip_network("fec0::/10"),       # Deprecated site-local addresses (RFC 3879)
)
_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")  # RFC 6052


def _embedded_ipv4_addresses(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> List[ipaddress.IPv4Address]:
    """Return the IPv4 destinations an IPv6 transition address delivers to.

    6to4, Teredo, NAT64 and IPv4-mapped addresses route to an embedded IPv4
    address, so they must pass the IPv4 checks too. CPython before its 2024
    ipaddress update (for example 3.9.19 and 3.12.3) classifies 6to4 addresses
    embedding 169.254.169.254 or 127.0.0.1 as global.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    embedded: List[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        embedded.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        embedded.append(ip.sixtofour)
    if ip.teredo is not None:
        embedded.extend(ip.teredo)  # (server, client); the client is de-obfuscated.
    if ip in _NAT64_WELL_KNOWN_PREFIX:
        embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return embedded

_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'`]+")


def _verified_tls_context() -> ssl.SSLContext:
    """Return a certificate- and hostname-verifying TLS 1.2+ client context.

    Python 3.9 still permits TLS 1.0/1.1 in ``create_default_context``;
    remote schema hosts never need those protocol versions.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def validate_ssl_context(ctx: ssl.SSLContext) -> None:
    """Validate that an SSL context enforces strict certificate and hostname verification."""
    if not isinstance(ctx, ssl.SSLContext):
        raise RemoteRefSecurityError(f"Invalid SSL context type: {type(ctx).__name__}")
    if ctx.verify_mode != ssl.CERT_REQUIRED:
        raise RemoteRefSecurityError(
            f"Insecure TLS configuration: certificate verification cannot be disabled "
            f"(verify_mode must be CERT_REQUIRED, got {ctx.verify_mode})"
        )
    if not ctx.check_hostname:
        raise RemoteRefSecurityError(
            "Insecure TLS configuration: hostname verification cannot be disabled "
            "(check_hostname must be True)"
        )


def sanitize_ref_url(url: Any) -> str:
    """Sanitize a URL or $ref string by removing userinfo and redacting query parameters."""
    if not isinstance(url, str) or not url.strip():
        return ""
    try:
        parsed = urlsplit(url)
        if parsed.scheme or parsed.netloc:
            netloc = parsed.netloc
            if "@" in netloc:
                netloc = netloc.rsplit("@", 1)[-1]

            query = ""
            if parsed.query:
                pairs = []
                for item in parsed.query.split("&"):
                    if not item:
                        continue
                    if "=" in item:
                        k, _, _ = item.partition("=")
                        pairs.append(f"{k}=[REDACTED]")
                    else:
                        pairs.append(f"{item}=[REDACTED]")
                query = "&".join(pairs)

            return urlunsplit((
                parsed.scheme,
                netloc,
                parsed.path,
                query,
                parsed.fragment,
            ))
        if "?" in url or "@" in url:
            path, sep, query = url.partition("?")
            if sep:
                pairs = []
                for item in query.split("&"):
                    if not item:
                        continue
                    if "=" in item:
                        k, _, _ = item.partition("=")
                        pairs.append(f"{k}=[REDACTED]")
                    else:
                        pairs.append(f"{item}=[REDACTED]")
                return f"{path}?{'&'.join(pairs)}"
        return url
    except Exception:
        return "[REDACTED_URL]"


def sanitize_error_message(msg: str) -> str:
    """Sanitize an error message by stripping userinfo and redacting query parameters in URLs."""
    if not isinstance(msg, str):
        return ""
    cleaned = _URL_IN_TEXT.sub(lambda m: sanitize_ref_url(m.group(0)), msg)
    cleaned = re.sub(r"://[^/:]+:[^/@]+@", "://", cleaned)
    return cleaned


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
    allow_loopback_for_testing: bool = False  # Maintained for internal structure
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
        if allow_loopback_for_testing:
            raise RemoteRefSecurityError(
                "Loopback address resolution cannot be enabled for remote references"
            )
        normalized_hosts = frozenset(
            normalize_remote_ref_host(host) for host in (remote_ref_hosts or [])
        )
        return cls(
            allow_remote_refs=bool(allow_remote_refs),
            remote_ref_hosts=normalized_hosts,
            max_doc_bytes=max_doc_bytes,
            max_total_bytes=max_total_bytes,
            max_docs=max_docs,
            max_depth=max_depth,
            timeout=timeout,
            allow_loopback_for_testing=False,
            session=session if session is not None else RemoteRefSession(),
        )


def validate_ip_address(ip_str: str, allow_loopback: bool = False) -> None:
    """Validate that an IP address is a safe public routable address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as exc:
        raise RemoteRefSecurityError(f"Invalid IP address format: {ip_str}") from exc

    if isinstance(ip, ipaddress.IPv6Address):
        for net in _BLOCKED_IPV6_NETWORKS:
            # :: and ::1 lie in ::/96 but keep their unspecified/loopback handling.
            if ip in net and int(ip) > 1:
                raise RemoteRefSecurityError(f"Access to non-global IPv6 range {net} is blocked: {ip_str}")
        for embedded in _embedded_ipv4_addresses(ip):
            try:
                validate_ip_address(str(embedded), allow_loopback=allow_loopback)
            except RemoteRefSecurityError as exc:
                raise RemoteRefSecurityError(
                    f"IPv6 address {ip_str} delivers to a blocked IPv4 destination: {exc}"
                ) from exc

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


def _dns_lookup_worker(
    hostname: str,
    result_holder: List[Any],
    error_holder: List[BaseException],
) -> None:
    try:
        addrinfo = socket.getaddrinfo(
            hostname, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        result_holder.append(addrinfo)
    except BaseException as exc:
        error_holder.append(exc)


def resolve_safe_ips(
    hostname: str,
    allow_loopback: bool = False,
    timeout: Optional[float] = 3.0,
) -> List[str]:
    """Resolve all A/AAAA records for hostname within timeout and verify all are safe."""
    result_holder: List[Any] = []
    error_holder: List[BaseException] = []

    thread = threading.Thread(
        target=_dns_lookup_worker,
        args=(hostname, result_holder, error_holder),
        name=f"gt-dns-{hostname}",
        daemon=True,
    )
    thread.start()
    effective_timeout = timeout if timeout is not None and timeout > 0 else 3.0
    thread.join(timeout=effective_timeout)

    if thread.is_alive():
        raise RemoteRefLimitExceededError(
            f"DNS resolution timed out for '{hostname}' after {effective_timeout:.1f}s"
        )

    if error_holder:
        exc = error_holder[0]
        if isinstance(exc, socket.gaierror):
            raise RemoteRefResolutionError(f"DNS resolution failed for '{hostname}': {exc}") from exc
        raise RemoteRefResolutionError(f"DNS resolution error for '{hostname}': {exc}") from exc

    if not result_holder or not result_holder[0]:
        raise RemoteRefResolutionError(f"No DNS records found for '{hostname}'")

    addrinfo = result_holder[0]
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
        if context is not None:
            validate_ssl_context(context)
            self.ssl_ctx = context
        else:
            self.ssl_ctx = _verified_tls_context()

        super().__init__(host=pinned_ip, port=port, timeout=timeout, context=self.ssl_ctx)
        self.target_hostname = target_hostname

    def update_timeout(self, timeout: float) -> None:
        self.timeout = timeout
        sock = getattr(self, "sock", None)
        if sock is not None:
            try:
                sock.settimeout(timeout)
            except OSError:
                pass

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
        if ssl_context is not None:
            validate_ssl_context(ssl_context)
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
        clean_url = sanitize_ref_url(url)
        if not self.config.allow_remote_refs:
            raise RemoteRefDisabledError(
                f"Remote $ref resolution is disabled; pass --allow-remote-refs and "
                f"--remote-ref-host to authorize: {clean_url}"
            )

        if not self.config.remote_ref_hosts:
            raise RemoteRefDisabledError(
                f"No remote $ref hosts authorized; pass --remote-ref-host <HOST>: {clean_url}"
            )

        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise RemoteRefSecurityError(
                f"Only HTTPS remote $ref values are permitted (got '{parsed.scheme}'): {clean_url}"
            )

        netloc = parsed.netloc
        if not netloc:
            raise RemoteRefSecurityError(f"Remote $ref URL missing host: {clean_url}")

        if "@" in netloc or parsed.username or parsed.password:
            raise RemoteRefSecurityError(
                f"Userinfo credentials in remote $ref URL are forbidden: {clean_url}"
            )

        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            raise RemoteRefSecurityError(f"Invalid host in remote $ref URL: {clean_url}")

        if any(ord(c) < 32 or ord(c) >= 127 for c in hostname):
            raise RemoteRefSecurityError(f"Control or non-ASCII characters in host: {clean_url}")

        # Port validation: only standard 443 permitted
        port = parsed.port or 443
        if port != 443:
            raise RemoteRefSecurityError(
                f"Non-standard port {port} is forbidden for remote $ref: {clean_url}"
            )

        # Host allowlist exact matching; IP literals compare in canonical form,
        # as the allowlist stores them.
        if (_canonical_ip_literal(hostname) or hostname) not in self.config.remote_ref_hosts:
            raise RemoteRefNotAllowedHostError(
                f"Remote host '{hostname}' is not in the authorized allowlist "
                f"{sorted(self.config.remote_ref_hosts)}: {clean_url}"
            )

        return hostname, parsed.path or "/", port

    def fetch_document(self, doc_url: str) -> Dict[str, Any]:
        """Fetch, validate, and parse a remote OpenAPI JSON/YAML schema document."""
        clean_display_url = sanitize_ref_url(doc_url)
        canonical_url = urlunsplit(urlsplit(doc_url)[:4] + ("",))
        clean_canonical_url = sanitize_ref_url(canonical_url)

        # Host allowlist and URL syntax validation
        hostname, path, port = self.validate_ref_url(canonical_url)

        with self.session.lock:
            # 1. Check cache first (deduplication across entire execution)
            if canonical_url in self.session.document_cache:
                return self.session.document_cache[canonical_url]

            # 2. Check failed URLs
            if canonical_url in self.session.failed_urls:
                raise RemoteRefResolutionError(
                    f"Previous fetch attempt for remote schema failed: {clean_canonical_url}"
                )

            # 3. Check document count limit before DNS and Socket connection
            if canonical_url not in self.session.attempted_urls:
                if len(self.session.attempted_urls) >= self.config.max_docs:
                    raise RemoteRefLimitExceededError(
                        f"Maximum remote document limit ({self.config.max_docs}) reached; "
                        f"refusing to fetch: {clean_display_url}"
                    )
                self.session.attempted_urls.add(canonical_url)

        deadline = time.monotonic() + self.config.timeout
        deadline_expired = threading.Event()

        def _timeout_error() -> RemoteRefLimitExceededError:
            return RemoteRefLimitExceededError(
                f"Overall timeout exceeded ({self.config.timeout}s) fetching remote schema: {clean_canonical_url}"
            )

        def _remaining_time() -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _timeout_error()
            return remaining

        conn: Optional[PinnedIPHTTPSConnection] = None

        # getresponse() detaches the socket from a connection that will close,
        # so remember the one in use once the request has been sent.
        request_sockets: List[socket.socket] = []

        def _abort_at_deadline() -> None:
            # Socket timeouts apply per receive, and one getresponse() or read()
            # spans many receives: a server dripping bytes could hold it far past
            # the deadline. Shutting the socket down wakes the blocked call.
            deadline_expired.set()
            for sock in (getattr(conn, "sock", None), *request_sockets):
                if sock is None:
                    continue
                try:
                    # The base method leaves an SSLSocket's own state untouched.
                    socket.socket.shutdown(sock, socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(max(0.0, deadline - time.monotonic()), _abort_at_deadline)
        watchdog.daemon = True
        watchdog.start()
        try:
            # DNS resolution and SSRF defense
            dns_time = _remaining_time()
            safe_ips = resolve_safe_ips(
                hostname, allow_loopback=self.config.allow_loopback_for_testing, timeout=dns_time
            )
            pinned_ip = safe_ips[0]

            # Prepare SSL context
            if self._custom_ssl_context is not None:
                validate_ssl_context(self._custom_ssl_context)
                ctx = self._custom_ssl_context
            else:
                ctx = _verified_tls_context()

            # Connection setup with IP pinning
            conn_time = _remaining_time()
            conn = PinnedIPHTTPSConnection(
                pinned_ip=pinned_ip,
                target_hostname=hostname,
                port=port,
                timeout=conn_time,
                context=ctx,
            )

            req_path = path
            parsed_query = urlsplit(canonical_url).query
            if parsed_query:
                req_path = f"{path}?{parsed_query}"

            headers = {
                "Host": hostname,
                "User-Agent": f"GrantTrace-Schema-Fetcher/{__version__}",
                "Accept": "application/json, application/yaml, text/yaml, */*",
                "Connection": "close",
            }

            conn.update_timeout(_remaining_time())
            conn.request("GET", req_path, headers=headers)
            if conn.sock is not None:
                request_sockets.append(conn.sock)

            conn.update_timeout(_remaining_time())
            resp = conn.getresponse()

            # Forbid all HTTP redirects
            if resp.status in (301, 302, 303, 307, 308):
                location = sanitize_ref_url(resp.getheader("Location", ""))
                raise RemoteRefSecurityError(
                    f"HTTP redirect ({resp.status}) to '{location}' is forbidden for remote $ref: {clean_canonical_url}"
                )

            if resp.status != 200:
                raise RemoteRefResolutionError(
                    f"HTTP {resp.status} {resp.reason} fetching remote schema: {clean_canonical_url}"
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
                        f"({self.config.max_doc_bytes} bytes): {clean_canonical_url}"
                    )

            # Stream body with chunk-by-chunk enforcement and slowloris deadline
            chunks: List[bytes] = []
            doc_bytes = 0
            while True:
                conn.update_timeout(_remaining_time())
                chunk = resp.read(8192)
                if not chunk:
                    break
                doc_bytes += len(chunk)
                with self.session.lock:
                    self.session.total_bytes_downloaded += len(chunk)
                    if doc_bytes > self.config.max_doc_bytes:
                        self.session.failed_urls.add(canonical_url)
                        raise RemoteRefLimitExceededError(
                            f"Remote document body exceeded limit of {self.config.max_doc_bytes} bytes: {clean_canonical_url}"
                        )
                    if self.session.total_bytes_downloaded > self.config.max_total_bytes:
                        self.session.failed_urls.add(canonical_url)
                        raise RemoteRefLimitExceededError(
                            f"Cumulative remote download exceeded limit of {self.config.max_total_bytes} bytes"
                        )
                chunks.append(chunk)

            # A read cut short at the deadline can end like a complete
            # close-delimited body; never accept it as the document.
            if deadline_expired.is_set():
                raise _timeout_error()
            # On a premature close, http.client's read(n) returns b"" instead of
            # raising, leaving the undelivered byte count in resp.length. A
            # truncated prefix often still parses (YAML especially); reject it.
            undelivered = getattr(resp, "length", None)
            if isinstance(undelivered, int) and not isinstance(undelivered, bool) and undelivered > 0:
                raise RemoteRefResolutionError(
                    f"Remote document ended {undelivered} bytes before its declared Content-Length: "
                    f"{clean_canonical_url}"
                )
            raw_bytes = b"".join(chunks)

            # Decode and parse JSON/YAML
            try:
                text = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise RemoteRefResolutionError(
                    f"Remote document is not valid UTF-8: {clean_canonical_url}"
                ) from exc

            parsed_data = self._parse_schema_content(text, clean_canonical_url)

            if not isinstance(parsed_data, dict):
                raise RemoteRefResolutionError(
                    f"Remote schema root must be a JSON/YAML mapping: {clean_canonical_url}"
                )

            with self.session.lock:
                self.session.document_cache[canonical_url] = parsed_data
            return parsed_data

        except (socket.timeout, TimeoutError) as exc:
            with self.session.lock:
                self.session.failed_urls.add(canonical_url)
            raise RemoteRefLimitExceededError(
                f"Timed out fetching remote $ref after {self.config.timeout}s: {clean_canonical_url}"
            ) from exc
        except (ssl.SSLError, OSError, http.client.HTTPException) as exc:
            # HTTPException covers malformed status lines, oversized headers and
            # truncated bodies; like transport errors, they fail this reference
            # instead of escaping as an unexpected error that aborts the scan.
            with self.session.lock:
                self.session.failed_urls.add(canonical_url)
            if deadline_expired.is_set():
                raise _timeout_error() from exc
            # HTTPException text echoes raw server bytes; report only its type.
            detail = type(exc).__name__ if isinstance(exc, http.client.HTTPException) else str(exc)
            raise RemoteRefResolutionError(
                f"Network/TLS error fetching remote $ref '{clean_canonical_url}': {detail}"
            ) from exc
        except Exception:
            with self.session.lock:
                self.session.failed_urls.add(canonical_url)
            raise
        finally:
            watchdog.cancel()
            if conn is not None:
                conn.close()

    @staticmethod
    def _parse_schema_content(text: str, source_url: str) -> Any:
        """Parse text as JSON or YAML."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        except RecursionError as exc:
            # Excessively nested JSON fails this reference, not the whole scan.
            raise RemoteRefResolutionError(
                f"Remote schema nesting exceeds the supported depth: {source_url}"
            ) from exc

        try:
            import yaml  # noqa: F401  # Availability check for a clear error message.
        except ImportError as exc:
            raise RuntimeError(
                "YAML remote schema files require the PyYAML package; "
                "install it with 'pip install pyyaml'"
            ) from exc

        try:
            # Bounded: a small remote document cannot expand exponentially.
            return safe_load_yaml(text)
        except Exception as exc:
            raise RemoteRefResolutionError(
                f"Failed to parse remote schema as JSON or YAML: {source_url}: {exc}"
            ) from exc
