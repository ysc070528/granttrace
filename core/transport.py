"""HTTP transport for audit requests: one send, shared throttling, rate-limit policy.

The auditor decides what to send and records what happened; this module only
moves bytes. Redirects are returned to the caller instead of being followed, so
credentials are never forwarded to another location. Responses are read up to a
fixed size and reported as truncated beyond it. ``send`` never raises: a failed
request becomes an ``HTTPResult`` with ``status=0`` and an error message.
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
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from core import __version__
from core.models import HTTPResult


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return 30x to the detector instead of forwarding credentials."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _nothing() -> None:
    return None


class HttpTransport:
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
    ) -> None:
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
        data: Optional[Dict[str, Any]] = None,
        content_type: str = "application/json",
        *,
        on_attempt: Callable[[], None] = _nothing,
        on_response: Callable[[], None] = _nothing,
    ) -> HTTPResult:
        """Send one request without throttling; the caller calls ``throttle`` first.

        ``on_attempt`` runs just before the request leaves, ``on_response`` once a
        response (including an HTTP error status) has arrived.
        """
        try:
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
