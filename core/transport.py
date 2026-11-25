"""HTTP transport for audit requests: one send, shared throttling, rate-limit policy.

The auditor decides what to send and records what happened; this module moves
bytes and is the last place the read-only request policy is applied. Every
request is checked as urllib is about to send it, after any retry or URL
unwrapping, in the method spelling that is sent (see HttpTransport for the
policy layers and their trust boundary). Redirects are returned to the caller
instead of being followed, so credentials are never forwarded to another
location. Responses are read up to a fixed size and reported as truncated
beyond it. ``send`` never raises: a failed or refused request becomes an
``HTTPResult`` with ``status=0`` and an error message.
"""

from __future__ import annotations

import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping, Optional, Tuple

from core import __version__
from core.models import HTTPResult
from core.scan_safety import (
    InvalidHttpMethod,
    canonical_http_method,
    concrete_request_risk,
    invalid_method_risk,
    method_override_risk,
    query_write_risk,
    read_only_body_risk,
)

# An additional, refusal-only request policy: guard(method, url) receives the
# canonical method and the URL urllib will send. It returns None to add no
# refusal, or a mapping whose "safety_reason" is a non-empty string to refuse.
# Any other value, or an exception, refuses the request. A guard cannot allow a
# request that the base policy refuses.
RequestGuard = Callable[[str, str], Optional[Mapping[str, str]]]
_UNCHECKED_REFUSAL = "Read-only safety policy could not check the request; no request was sent"

# The methods the auditor uses to read; PATCH and PUT are the separately gated writes.
_READ_METHODS = frozenset({"GET", "HEAD", "POST"})


def request_refusal(method: str, url: str, headers: Mapping[str, str], data: Optional[Any]) -> Optional[str]:
    """Why a request must not leave this transport, or None.

    The same rules as configuration validation and the auditor's request check
    (core.scan_safety), applied to the request actually about to be sent, so
    they hold however the auditor was built and whatever changed after it was
    built: no request may carry a header that overrides the HTTP method to one
    that can change state; no read request (GET, HEAD, or POST, which the
    auditor sends only to operations declared read-only) may carry a query
    string that asks for a write; and no POST may carry a body that asks for a
    write. PATCH and PUT, the writes of the separately gated mass-assignment
    check, keep their bodies and queries.
    """
    if any(method_override_risk(str(name), str(value)) for name, value in headers.items()):
        return ("Read-only safety policy blocked a request with a header that overrides the HTTP method "
                "to one that can change state; no request was sent")
    try:
        method = canonical_http_method(method)
    except InvalidHttpMethod:
        return invalid_method_risk()["safety_reason"]
    if method in _READ_METHODS:
        query = query_write_risk(url)
        if query:
            return query["safety_reason"]
    if method == "POST" and data is not None:
        risk = read_only_body_risk(data)
        if risk:
            return risk["safety_reason"]
    return None


def _refusal_reason(decision: object) -> str:
    """The reason of a refusal decision; a decision without a usable reason still refuses."""
    if isinstance(decision, Mapping):
        reason = decision.get("safety_reason")
        if isinstance(reason, str) and reason.strip():
            return reason
    return _UNCHECKED_REFUSAL


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return 30x to the detector instead of forwarding credentials."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _nothing() -> None:
    return None


class HttpTransport:
    """Send audit requests after two independent policy decisions; either refusal wins.

    1. The base policy always runs and cannot be switched off through this
       class's configuration: the method must be a single RFC 9110 token (it is
       checked and sent in one canonical upper-case spelling), and a GET, HEAD
       or POST must not have an ambiguous URL or a state-changing concrete path
       below ``base_url`` (core.scan_safety.concrete_request_risk). It depends
       only on core.scan_safety and on ``base_url``, which is fixed when the
       transport is built; not on ``request_guard`` and not on any auditor
       method. ``base_url`` is the operator's configured target: its own path
       is not read as data, everything after it is. Without it the whole path
       is checked, which is stricter. ``request_refusal`` (method-override
       headers, write query strings, write POST bodies) is part of the base
       policy as well and runs first, on the canonical method.
    2. ``request_guard`` (optional) adds refusals only; see RequestGuard. The
       auditor installs its specification-aware check here (documented
       templates whose metadata names a write), so that layer follows the
       auditor's own, overridable, policy methods.

    A refused request opens no connection and runs neither callback.

    Trust boundary: these are guarantees for the supported configuration and
    extension points (constructor arguments, ``request_guard``, the auditor's
    documented overrides). They are not a sandbox: code running in the same
    Python process can replace this class or its methods, patch
    core.scan_safety, or open connections without this transport.
    """

    # Rate limiting: only idempotent reads are retried. A write may already have
    # been applied, so its outcome stays with the transaction's own recovery.
    RETRYABLE_METHODS = {"GET", "HEAD"}
    RATE_LIMIT_RETRIES = 2
    RATE_LIMIT_BACKOFF = 1.0  # Seconds before the first retry without Retry-After; doubles after.
    MAX_RETRY_WAIT = 30.0  # A longer requested wait fails closed with the original response.

    def __init__(
        self,
        *,
        request_delay: float,
        request_timeout: float,
        max_response_bytes: int,
        insecure_ssl: bool,
        request_guard: Optional[RequestGuard] = None,
        base_url: str = "",
    ) -> None:
        self.request_guard = request_guard
        self._base_url = str(base_url or "")
        self.request_delay = request_delay
        self.request_timeout = request_timeout
        self.max_response_bytes = max_response_bytes
        context = ssl._create_unverified_context() if insecure_ssl else ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            NoRedirectHandler(), urllib.request.HTTPSHandler(context=context)
        )
        self._rate_lock = threading.Lock()
        self._next_request_at = 0.0

    def throttle(self) -> None:
        # Honor a rate-limit pause even when no per-request delay is configured.
        with self._rate_lock:
            wait_for = self._next_request_at - time.monotonic()
            if wait_for > 0:
                time.sleep(wait_for)
            if self.request_delay > 0:
                self._next_request_at = time.monotonic() + self.request_delay

    def defer(self, seconds: float) -> None:
        """Pause every worker: a rate limit applies to this client, not one request."""
        with self._rate_lock:
            self._next_request_at = max(self._next_request_at, time.monotonic() + seconds)

    @staticmethod
    def retry_after_seconds(headers: Mapping[str, str]) -> Optional[float]:
        """Parse Retry-After as delay-seconds or an HTTP date (RFC 9110 section 10.2.3)."""
        value = next((str(item) for name, item in headers.items() if str(name).lower() == "retry-after"), None)
        if value is None:
            return None
        value = value.strip()
        if re.fullmatch(r"[0-9]+", value):
            return float(int(value)) if len(value) <= 12 else float("inf")
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())

    def rate_limit_wait(self, method: str, result: HTTPResult, attempt: int) -> Optional[float]:
        """Return how long to wait before retrying, or None to keep this response."""
        if (str(method).upper() not in self.RETRYABLE_METHODS or result.error is not None
                or result.status not in (429, 503)):
            return None
        retry_after = self.retry_after_seconds(result.headers)
        if result.status == 503 and retry_after is None:
            return None  # Only an explicit Retry-After marks a 503 as temporary.
        wait = retry_after if retry_after is not None else self.RATE_LIMIT_BACKOFF * (2 ** attempt)
        wait = max(wait, self.request_delay)
        return wait if wait <= self.MAX_RETRY_WAIT else None

    @property
    def base_url(self) -> str:
        """The operator's target base URL whose own path the base policy does not read as data."""
        return self._base_url

    def read_policy_refusal(self, method: str, url: str) -> Optional[str]:
        """Why this request must not leave the transport, or None.

        The base policy decides first and always; ``request_guard`` is then
        asked only to add a refusal. A decision that cannot be made (an
        exception) or that is malformed (see RequestGuard) refuses the request.
        """
        try:
            base = concrete_request_risk(method, url, self._base_url)
        except Exception:
            return _UNCHECKED_REFUSAL
        if base is not None:
            return _refusal_reason(base)
        guard = self.request_guard
        if guard is None:
            return None
        try:
            decision = guard(method, url)
        except Exception:
            return _UNCHECKED_REFUSAL
        return None if decision is None else _refusal_reason(decision)

    def read_limited(self, response) -> Tuple[str, bool]:  # noqa: ANN001
        raw = response.read(self.max_response_bytes + 1)
        truncated = len(raw) > self.max_response_bytes
        raw = raw[: self.max_response_bytes]
        charset = response.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace"), truncated

    def send(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        data: Optional[Any] = None,
        content_type: str = "application/json",
        *,
        on_attempt: Callable[[], None] = _nothing,
        on_response: Callable[[], None] = _nothing,
    ) -> HTTPResult:
        """Send one request without throttling; the caller calls ``throttle`` first.

        ``on_attempt`` runs just before the request leaves, ``on_response`` once a
        response (including an HTTP error status) has arrived. The method is
        sent in its canonical spelling, the one every check uses; a method that
        is not a single valid token, or a request that ``request_refusal`` or
        ``read_policy_refusal`` rejects, is returned as a failed result before
        either callback runs: no connection is opened and nothing is counted as
        attempted.
        """
        try:
            try:
                method = canonical_http_method(method)
            except InvalidHttpMethod:
                return HTTPResult(status=0, body="", error=invalid_method_risk()["safety_reason"])
            # Inside the try: a check that cannot run fails closed, like a failed send.
            refusal = request_refusal(method, url, headers, data)
            if refusal:
                return HTTPResult(status=0, body="", error=refusal)
            request_headers = {
                "accept": "application/json",
                "user-agent": f"GrantTrace/{__version__}",
                **headers,
            }
            encoded_data = None
            if data is not None:
                request_headers["content-type"] = content_type
                encoded_data = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
            request = urllib.request.Request(url, data=encoded_data, method=method, headers=request_headers)
            # Check the method and URL urllib will send, after it unwrapped the URL.
            refusal = self.read_policy_refusal(request.get_method(), request.full_url)
            if refusal:
                return HTTPResult(status=0, body="", error=refusal)
            on_attempt()
            try:
                response = self.opener.open(request, timeout=self.request_timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                on_response()
                body, truncated = self.read_limited(response)
                return HTTPResult(
                    status=response.status, body=body, truncated=truncated,
                    headers={str(k): str(v) for k, v in response.headers.items()},
                )
        except Exception as exc:
            # Includes malformed encodings and truncated/chunked transport reads.
            # A PATCH may already have committed; the transaction owns recovery.
            return HTTPResult(status=0, body="", error=f"{type(exc).__name__}: {exc}")
