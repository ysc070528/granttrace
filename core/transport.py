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
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

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
_METHOD_OVERRIDE_REASON = ("Read-only safety policy blocked a request with a header that overrides the HTTP method "
                           "to one that can change state; no request was sent")

# Where a refusal was decided; recorded as HTTPResult.refusal["policy_layer"].
LAYER_REQUEST = "transport_request"  # method-override headers, write query strings, write POST bodies
LAYER_BASE = "transport_base"  # the method token and the concrete-request policy below base_url
LAYER_GUARD = "transport_guard"  # the optional, refusal-only request_guard

# The methods the auditor uses to read; PATCH and PUT are the separately gated writes.
_READ_METHODS = frozenset({"GET", "HEAD", "POST"})


def request_refusal_risk(method: str, url: str, headers: Mapping[str, str],
                         data: Optional[Any]) -> Optional[Dict[str, str]]:
    """The request rules as a decision (``safety_reason`` and ``safety_signal``), or None.

    The same rules as configuration validation and the auditor's request check
    (core.scan_safety), applied by ``send`` to the request urllib is about to
    send, so they hold however the auditor was built and whatever changed after
    it was built: no request may carry a header that overrides the HTTP method
    to one that can change state; no read request (GET, HEAD, or POST, which the
    auditor sends only to operations declared read-only) may carry a query
    string that asks for a write; and no POST may carry a body that asks for a
    write. PATCH and PUT, the writes of the separately gated mass-assignment
    check, keep their bodies and queries.
    """
    if any(method_override_risk(str(name), str(value)) for name, value in headers.items()):
        return {"safety_reason": _METHOD_OVERRIDE_REASON, "safety_signal": "method_override_header"}
    try:
        method = canonical_http_method(method)
    except InvalidHttpMethod:
        return invalid_method_risk()
    if method in _READ_METHODS:
        query = query_write_risk(url)
        if query:
            return dict(query)
    if method == "POST" and data is not None:
        risk = read_only_body_risk(data)
        if risk:
            return dict(risk)
    return None


def request_refusal(method: str, url: str, headers: Mapping[str, str], data: Optional[Any]) -> Optional[str]:
    """Why a request must not leave this transport under the request rules, or None.

    The reason of ``request_refusal_risk``; kept for callers of the string form.
    """
    risk = request_refusal_risk(method, url, headers, data)
    return None if risk is None else risk["safety_reason"]


def _plain_text(value: object) -> Optional[str]:
    """A non-blank ``str`` value as a plain ``str`` copy, or None; never raises.

    The base ``str`` methods are used, so a ``str`` subclass cannot raise or
    change its text after the check.
    """
    if not isinstance(value, str):
        return None
    text = str.__str__(value)
    return text if str.strip(text) else None


def refusal_decision(decision: object, layer: str) -> Dict[str, str]:
    """A structured refusal from any decision value; it never raises.

    A mapping with a non-blank ``safety_reason`` keeps its reason and signal.
    Anything else (another type, a mapping without a usable reason, a mapping
    whose lookups raise) still refuses, with the generic "could not check"
    reason and the ``policy_error`` signal.
    """
    try:
        if isinstance(decision, Mapping):
            reason = _plain_text(decision.get("safety_reason"))
            if reason is not None:
                signal = _plain_text(decision.get("safety_signal")) or "unspecified"
                return {"safety_reason": reason, "safety_signal": signal, "policy_layer": layer}
    except Exception:
        pass
    return {"safety_reason": _UNCHECKED_REFUSAL, "safety_signal": "policy_error", "policy_layer": layer}


def _refusal_reason(decision: object) -> str:
    """The reason of a refusal decision; a decision without a usable reason still refuses."""
    return refusal_decision(decision, LAYER_GUARD)["safety_reason"]


def _refused(refusal: Dict[str, str]) -> HTTPResult:
    return HTTPResult(status=0, body="", error=refusal["safety_reason"], refusal=refusal)


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
       is checked, which is stricter. The request rules
       (``request_refusal_risk``: method-override headers, write query strings,
       write POST bodies) are part of the base policy as well and run first.
       Every rule reads the request urllib sends (``request_decision``), not
       the caller's arguments.
    2. ``request_guard`` (optional) adds refusals only; see RequestGuard. The
       auditor installs its specification-aware check here (documented
       templates whose metadata names a write), so that layer follows the
       auditor's own, overridable, policy methods.

    A refused request opens no connection and runs neither callback.

    Trust boundary: these are guarantees for the supported configuration and
    extension points (constructor arguments, ``request_guard``, the auditor's
    documented overrides). They are not a sandbox: code running in the same
    Python process can replace this class or its methods, patch
    core.scan_safety, or open connections without this transport. Overriding
    the auditor's private policy methods (``_request_risk``,
    ``_transport_request_risk`` and the like) is not a supported extension: it
    changes only the auditor's additional layer, never the base policy.

    Scope: the read-only rules apply to GET, HEAD and POST, the methods the
    auditor reads with. A valid PATCH, PUT, DELETE or other method passed to
    ``send`` directly is sent (only a method-override header is refused for
    every method): the auditor gates its own writes separately, and this class
    is not a read-only sandbox for arbitrary callers.
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

    def read_policy_decision(self, method: str, url: str) -> Optional[Dict[str, str]]:
        """The path-policy refusal for this request (reason, signal, layer), or None.

        The base policy decides first and always; ``request_guard`` is then
        asked only to add a refusal. A decision that cannot be made (an
        exception) or that is malformed (see RequestGuard) refuses the request.
        This method never raises.
        """
        try:
            base = concrete_request_risk(method, url, self._base_url)
        except Exception:
            return refusal_decision(None, LAYER_BASE)
        if base is not None:
            return refusal_decision(base, LAYER_BASE)
        guard = self.request_guard
        if guard is None:
            return None
        try:
            decision = guard(method, url)
        except Exception:
            return refusal_decision(None, LAYER_GUARD)
        return None if decision is None else refusal_decision(decision, LAYER_GUARD)

    def read_policy_refusal(self, method: str, url: str) -> Optional[str]:
        """Why this request must not leave the transport under the path policy, or None; never raises."""
        decision = self.read_policy_decision(method, url)
        return None if decision is None else decision["safety_reason"]

    def request_decision(self, request: urllib.request.Request) -> Optional[Dict[str, str]]:
        """The whole read-only decision for ``request`` exactly as urllib will send it, or None.

        Every rule reads the sent object: the method ``get_method()`` returns,
        ``full_url`` after urllib unwrapped and stripped the URL, the headers
        as urllib holds them (one value per case-insensitive name) and the JSON
        body decoded from the encoded bytes, so a tuple is checked as the array
        it becomes. The request rules run first, then the path policy. A check
        that cannot run refuses the request; this method never raises.
        """
        try:
            method = request.get_method()
            url = request.full_url
            data = request.data
            if data is not None and not isinstance(data, (bytes, bytearray)):
                raise TypeError("the request body must be encoded bytes")
            body = None if data is None else json.loads(data)
            risk = request_refusal_risk(method, url, dict(request.header_items()), body)
        except Exception:
            return refusal_decision(None, LAYER_REQUEST)
        if risk is not None:
            return refusal_decision(risk, LAYER_REQUEST)
        return self.read_policy_decision(method, url)

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
        is not a single valid token, or a request that ``request_decision``
        rejects, is returned as a failed result before either callback runs: no
        connection is opened and nothing is counted as attempted. A refused
        result carries the structured decision in ``HTTPResult.refusal``; a
        result with an error and no ``refusal`` is a transport failure.
        """
        try:
            try:
                method = canonical_http_method(method)
            except InvalidHttpMethod:
                return _refused(refusal_decision(invalid_method_risk(), LAYER_BASE))
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
            # One decision on the object urllib sends; it never raises and refuses what it cannot check.
            refusal = self.request_decision(request)
            if refusal is not None:
                return _refused(refusal)
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
