"""Bounded evidence sanitization for bodies, URLs, errors, and result metadata.

Detection operates on original responses. Use these helpers at evidence/report
boundaries. ``include_sensitive=True`` is an explicit disclosure opt-in.
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from http.cookies import CookieError, SimpleCookie
from typing import Any, Iterable
from urllib.parse import quote, quote_plus, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

MAX_TEXT_CHARS = 4096
MAX_DEPTH = 12
MAX_CONTAINER_ITEMS = 100
MAX_NODES = 1000
MAX_TOTAL_TEXT_CHARS = 65536
REDACTED = "[REDACTED]"

SENSITIVE_KEYS = {
    "authorization", "password", "passwd", "secret", "cookie", "token", "api_key",
    "apikey", "private_key", "salary", "ssn", "phone", "email", "address",
    "name", "full_name", "first_name", "last_name", "phone_number", "mobile",
    "telephone", "id_number", "identity_number", "national_id", "credit_card",
}
# A report title is diagnostic metadata, but a response title/content may carry
# arbitrary private business data. Keep that distinction at the output boundary.
BUSINESS_CONTENT_KEYS = {"title", "department", "content"}
BODY_KEYS = {"body", "response_body", "request_body", "raw_body"}
PAYLOAD_KEYS = {"payload", "request_payload", "response_payload"}
URL_KEYS = {"url", "uri", "target", "endpoint_url", "request_url", "response_url", "error_url"}

_URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|wss?)://[^\s<>\"']+|(?<!\w)/[^\s<>\"']*\?[^\s<>\"']*"
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"""(?ix)(?<![\w])['"]?
    (password|passwd|secret|access[_ -]?token|refresh[_ -]?token|token|
     api[_ -]?key|private[_ -]?key|authorization|cookie|full[_ -]?name|
     first[_ -]?name|last[_ -]?name|phone(?:[_ -]?number)?|mobile|salary|
     ssn|email|address|national[_ -]?id|id[_ -]?number)
    ['"]?\s*[:=]\s*
    (?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^;\r\n&}\]]+)
    """
)
_COOKIE_PAIR = r'''[!#$%&'*+\-.^_`|~0-9A-Za-z]+\s*=\s*(?:"(?:\\.|[^"\\])*"|[^\x00-\x20\x7f";,]*)'''
_COOKIE_PAIR_PATTERN = re.compile(_COOKIE_PAIR)
_COOKIE_HEADER = re.compile(r"\s*" + _COOKIE_PAIR + r"(?:\s*;\s*" + _COOKIE_PAIR + r")*\s*;?\s*")
_NUMERIC_SECRET = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")


def _normalized_key(key: str) -> str:
    key = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return re.sub(r"[\s.-]+", "_", key.lower())


def _is_sensitive_key(key: str) -> bool:
    key = _normalized_key(key)
    compact = key.replace("_", "")
    return key in SENSITIVE_KEYS or compact in {"fullname", "firstname", "lastname", "phonenumber"} or any(
        token in compact for token in (
            "password", "passwd", "secret", "token", "apikey", "privatekey", "authorization", "cookie",
            "session", "credential",
        )
    )


def body_sha256(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()


def _secret_variants(secret_values: Iterable[str]) -> tuple[str, ...]:
    # A generator must be consumed once, not once per leaf. Cover common encoded
    # echoes and tokens echoed without their Authorization scheme as well.
    if isinstance(secret_values, str):
        secret_values = (secret_values,)
    values = {str(value) for value in secret_values if value}
    for value in tuple(values):
        match = re.fullmatch(r"(?i)(?:Bearer|Basic)\s+(.+)", value)
        if match:
            values.add(match.group(1))
        # Cookies are supplied as complete headers, but applications may echo
        # just one cookie's credential. Only split a complete cookie-shaped
        # string; retain the original secret even when parsing fails.
        if _COOKIE_HEADER.fullmatch(value):
            for pair in _COOKIE_PAIR_PATTERN.finditer(value):
                component = pair.group().partition("=")[2].lstrip()
                if component.startswith('"'):
                    # SimpleCookie interprets request-cookie names such as
                    # path/domain/secure as Set-Cookie attributes. Use a
                    # neutral name only to decode the quoted value.
                    cookie = SimpleCookie()
                    try:
                        cookie.load("credential=" + component)
                    except CookieError:
                        continue
                    if "credential" not in cookie:
                        continue
                    component = cookie["credential"].value
                if component:
                    values.add(component)
    variants: set[str] = set()
    for value in values:
        variants.update((value, quote(value, safe=""), quote_plus(value, safe=""),
                         json.dumps(value, ensure_ascii=True)[1:-1],
                         json.dumps(value, ensure_ascii=False)[1:-1]))
    return tuple(sorted(variants, key=len, reverse=True))


class _Sanitizer:
    def __init__(self, include_sensitive: bool, secret_values: Iterable[str]):
        self.include_sensitive = include_sensitive
        self.secrets = () if include_sensitive else _secret_variants(secret_values)
        self.numeric_secrets = set()
        for secret in self.secrets:
            if _NUMERIC_SECRET.fullmatch(secret):
                try:
                    self.numeric_secrets.add(Decimal(secret))
                except InvalidOperation:
                    # An opaque token may look numeric but have an exponent
                    # outside Decimal's supported range. Text redaction still
                    # applies to the complete credential.
                    pass
        self.nodes_remaining = MAX_NODES
        self.chars_remaining = MAX_TOTAL_TEXT_CHARS

    def _limit_text(self, text: str, limit: int = MAX_TEXT_CHARS) -> str:
        limit = max(0, min(limit, self.chars_remaining))
        result = text[:limit]
        self.chars_remaining -= len(result)
        return result + ("...[TRUNCATED]" if len(text) > limit else "")

    def _replace_known_secrets(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, REDACTED)
        return text

    def _scrub_inline(self, text: str) -> str:
        text = self._replace_known_secrets(text)
        text = re.sub(
            r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|$)",
            "[PRIVATE KEY REDACTED]", text, flags=re.DOTALL,
        )
        text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", text)
        text = _SENSITIVE_ASSIGNMENT.sub(lambda m: m.group(1) + "=" + REDACTED, text)
        text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", REDACTED, text)
        text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL REDACTED]", text)
        text = re.sub(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)", "[PHONE REDACTED]", text)
        text = re.sub(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", "[SSN REDACTED]", text)
        return text

    def url(self, url: str) -> str:
        if self.include_sensitive:
            return url
        try:
            parts = urlsplit(url)
            netloc = self._scrub_inline(parts.netloc.rsplit("@", 1)[-1])
            pairs = []
            fields = parts.query.split("&", MAX_CONTAINER_ITEMS) if parts.query else ()
            for index, field in enumerate(fields):
                if index >= MAX_CONTAINER_ITEMS:
                    pairs.append(("_truncated_params", REDACTED))
                    break
                name = unquote_plus(field.partition("=")[0])
                safe_name = self._scrub_inline(name) if "=" in field else "param"
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", safe_name):
                    safe_name = "param"
                pairs.append((safe_name, REDACTED))
            # Match the complete decoded path too: a credential can contain
            # '/' and be partially percent-encoded across multiple segments.
            # This changes display metadata only, never the wire request URL.
            decoded_path = unquote(parts.path)
            scrubbed_path = self._replace_known_secrets(decoded_path)
            if scrubbed_path != decoded_path:
                path = "/".join(quote(self._scrub_inline(segment), safe="[]_-.~{}")
                                for segment in scrubbed_path.split("/"))
            else:
                path_segments = []
                for segment in parts.path.split("/"):
                    decoded = unquote(segment)
                    scrubbed = self._scrub_inline(decoded)
                    path_segments.append(quote(scrubbed, safe="[]_-.~{}") if scrubbed != decoded else segment)
                path = "/".join(path_segments)
            # A configured credential can span path segments (for example a
            # token containing '/'). Segment decoding alone cannot match it.
            return self._replace_known_secrets(urlunsplit((parts.scheme, netloc, path, urlencode(pairs), "")))
        except (ValueError, UnicodeError):
            return "[URL OMITTED]"

    def text(self, text: str, depth: int = 0, business_payload: bool = False) -> str:
        if not self.include_sensitive:
            stripped = text.lstrip()
            # A result field can itself hold an encoded JSON object. Redact it
            # structurally rather than allowing quoted sensitive keys through.
            looks_like_array = re.match(r'\[\s*(?:[\[{"\d-]|true\b|false\b|null\b|\])', stripped)
            if stripped.startswith("{") or looks_like_array:
                try:
                    parsed = json.loads(text)
                except (ValueError, RecursionError):
                    return "[UNPARSEABLE JSON TEXT OMITTED; sha256=" + body_sha256(text) + "]"
                if isinstance(parsed, (dict, list)):
                    safe = self.payload(parsed, depth + 1, business_payload)
                    return self._limit_text(json.dumps(safe, ensure_ascii=False, sort_keys=True))
            text = _URL_PATTERN.sub(lambda match: self.url(match.group()), text)
            text = self._scrub_inline(text)
        return self._limit_text(text)

    def body(self, body: str, max_chars: int = MAX_TEXT_CHARS, depth: int = 0) -> str:
        text = body or ""
        # Preserve the original hash when already sanitized evidence crosses a
        # second output boundary.
        if re.fullmatch(r"\[UNPARSEABLE BODY OMITTED; sha256=[0-9a-f]{64}\]", text):
            return text
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError, RecursionError):
            if not self.include_sensitive:
                return "[UNPARSEABLE BODY OMITTED; sha256=" + body_sha256(text) + "]"
            return self._limit_text(text, max_chars)
        if isinstance(parsed, str) and not self.include_sensitive:
            return "[UNSTRUCTURED JSON STRING OMITTED; sha256=" + body_sha256(text) + "]"
        rendered = json.dumps(self.payload(parsed, depth + 1, True), ensure_ascii=False, sort_keys=True)
        return self._limit_text(rendered, max_chars)

    def payload(self, value: Any, depth: int = 0, business_payload: bool = False) -> Any:
        if depth > MAX_DEPTH:
            return "[DEPTH_LIMIT]"
        if self.nodes_remaining <= 0:
            return "[NODE_LIMIT]"
        self.nodes_remaining -= 1
        if isinstance(value, dict):
            dict_result: dict[str, object] = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= MAX_CONTAINER_ITEMS or self.nodes_remaining <= 0:
                    dict_result["_truncated_entries"] = len(value) - index
                    break
                normalized = _normalized_key(str(key))
                safe_key = self.text(str(key), depth)
                if not self.include_sensitive and (_is_sensitive_key(str(key)) or
                        (business_payload and normalized in BUSINESS_CONTENT_KEYS)):
                    self.nodes_remaining -= 1
                    dict_result[safe_key] = REDACTED
                elif normalized in BODY_KEYS | PAYLOAD_KEYS and isinstance(item, str):
                    self.nodes_remaining -= 1
                    dict_result[safe_key] = self.body(item, depth=depth + 1)
                elif normalized in URL_KEYS and isinstance(item, str):
                    self.nodes_remaining -= 1
                    dict_result[safe_key] = self._limit_text(self.url(item))
                else:
                    dict_result[safe_key] = self.payload(item, depth + 1, business_payload or normalized in PAYLOAD_KEYS)
            return dict_result
        if isinstance(value, (list, tuple)):
            list_result: list[object] = []
            for index, item in enumerate(value):
                if index >= MAX_CONTAINER_ITEMS or self.nodes_remaining <= 0:
                    list_result.append("[ITEM_LIMIT]")
                    break
                list_result.append(self.payload(item, depth + 1, business_payload))
            return list_result
        if isinstance(value, str):
            return self.text(value, depth, business_payload)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            # JSON can turn an echoed numeric credential into a number, so
            # string-only substitution cannot protect this output boundary.
            if not self.include_sensitive and Decimal(str(value)) in self.numeric_secrets:
                return REDACTED
            return value
        if value is None or isinstance(value, bool):
            return value
        # repr() of bytes, exceptions, or user objects may contain credentials.
        return "[UNSUPPORTED VALUE OMITTED]"


def sanitize_url(url: str, include_sensitive: bool = False,
                 secret_values: Iterable[str] = ()) -> str:
    sanitizer = _Sanitizer(include_sensitive, secret_values)
    return sanitizer._limit_text(sanitizer.url(url))


def sanitize_text(text: str, include_sensitive: bool = False, secret_values: Iterable[str] = ()) -> str:
    return _Sanitizer(include_sensitive, secret_values).text(text)


def redact_payload(value: Any, include_sensitive: bool = False, depth: int = 0,
                   secret_values: Iterable[str] = ()) -> Any:
    return _Sanitizer(include_sensitive, secret_values).payload(value, depth, True)


def sanitize_body(body: str, include_sensitive: bool = False, max_chars: int = MAX_TEXT_CHARS,
                  secret_values: Iterable[str] = ()) -> str:
    return _Sanitizer(include_sensitive, secret_values).body(body, max_chars)


def sanitize_evidence(value: Any, include_sensitive: bool = False,
                      secret_values: Iterable[str] = ()) -> Any:
    return _Sanitizer(include_sensitive, secret_values).payload(value)


def sanitize_log_text(text: Any) -> str:
    """Escape CR, LF, TAB, and ASCII control characters to prevent log injection and line forgery."""
    if text is None:
        return ""
    s = str(text)
    # Escape common control characters
    s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    # Escape any other control character (0x00 - 0x1f, 0x7f)
    return re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\x{ord(m.group(0)):02x}", s)


def safe_diagnostic_value(value: Any, depth: int = 0, secret_values: Iterable[str] = ()) -> str:
    """Format an 'actual' or diagnostic value for safe output without leaking secrets or allowing log injection."""
    if depth > 10:
        return "[DEPTH_LIMIT]"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        import math
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        return str(value)
    if isinstance(value, str):
        sanitized = sanitize_text(value, secret_values=secret_values)
        if any(w in sanitized.lower() for w in ("bearer ", "basic ", "token ", "key ", "cookie:", "session:")):
            sanitized = re.sub(r"(?i)\b(Bearer|Basic|Token|Key|Session|Cookie:?)\s+[^\s,;]+", r"\1 [REDACTED]", sanitized)
        # Scrub assignments like api_key=xyz or secret=xyz
        sanitized = _SENSITIVE_ASSIGNMENT.sub(lambda m: m.group(1) + "=" + REDACTED, sanitized)
        # Also clean raw JWT
        sanitized = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", REDACTED, sanitized)
        # Limit length to avoid huge log dumps
        truncated = sanitized if len(sanitized) <= 120 else sanitized[:117] + "..."
        return sanitize_log_text(repr(truncated))
    if isinstance(value, dict):
        safe_pairs = []
        for k, v in list(value.items())[:20]:
            k_str = str(k)
            if _is_sensitive_key(k_str):
                safe_pairs.append(f"{sanitize_log_text(repr(k_str))}: '[REDACTED]'")
            else:
                safe_pairs.append(f"{sanitize_log_text(repr(k_str))}: {safe_diagnostic_value(v, depth + 1, secret_values)}")
        if len(value) > 20:
            safe_pairs.append("... [TRUNCATED]")
        return "{" + ", ".join(safe_pairs) + "}"
    if isinstance(value, (list, tuple)):
        is_tuple = isinstance(value, tuple)
        safe_items = []
        for item in value[:20]:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str) and _is_sensitive_key(item[0]):
                safe_items.append(f"({sanitize_log_text(repr(item[0]))}, '[REDACTED]')")
            else:
                safe_items.append(safe_diagnostic_value(item, depth + 1, secret_values))
        if len(value) > 20:
            safe_items.append("... [TRUNCATED]")
        content = ", ".join(safe_items)
        return f"({content})" if is_tuple else f"[{content}]"
    return sanitize_log_text(repr(type(value).__name__))

