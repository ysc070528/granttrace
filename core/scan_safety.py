"""Conservative local checks for read-path ambiguity and mutation semantics.

These rules cannot prove that an operation is side-effect free. They identify
command-like paths/operation identifiers and affirmative mutation descriptions;
an undocumented server-side effect still requires operator review.

POST is not read-only by HTTP semantics. A POST is considered only after the
operator declares ``read_only: true``; the declaration is then checked against
a wider mutation vocabulary and must be corroborated by an explicit read action
(search, query, lookup...) in the path, operationId or summary. A heuristic
match never proves a POST is safe; it only refuses ones that are not plausibly
read-only.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Optional
from urllib.parse import unquote, urlsplit


def is_loopback_target(url: str) -> bool:
    """Return True only when a target URL unambiguously names this machine.

    Accepted hosts are the exact name ``localhost`` and IP literals in a
    loopback range (127.0.0.0/8, ::1 and IPv4-mapped loopback). Everything else
    counts as remote, including look-alike names (``localhost.example.com``,
    ``127.0.0.1.nip.io``), a trailing-dot ``localhost.``, shortened, integer or
    non-ASCII IPv4 spellings, IPv6 zone indexes, user information, and any URL
    with whitespace, control characters or backslashes that parsers may read
    differently. A wrong "remote" answer only makes the caller stricter.
    """
    if not isinstance(url, str) or any(ord(character) <= 32 or ord(character) == 127 for character in url):
        return False
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        _ = parts.port  # an invalid port raises ValueError here
    except ValueError:
        return False
    if (parts.scheme not in {"http", "https"} or not hostname or not hostname.isascii()
            or "\\" in parts.netloc or "%" in hostname
            or parts.username is not None or parts.password is not None):
        return False
    if hostname == "localhost":
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


_PATH_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\\]")
_BAD_PATH_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_PATH_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")
_ENCODED_SLASH_EDGE = re.compile(r"(?:^|/)%2f|%2f(?:/|$)", re.IGNORECASE)


def read_path_risk(url: str) -> Optional[Dict[str, str]]:
    """Reject routing ambiguity without rewriting a concrete read URL.

    Ordinary interior encoded slashes and query data remain usable. Nested
    escapes are rejected after one decode instead of guessing a proxy's decode
    depth. Inspect controls before urlsplit can silently remove them.
    """
    prefix = url.split("?", 1)[0].split("#", 1)[0]
    ambiguous = bool(_PATH_CONTROL.search(prefix))
    path = urlsplit(url).path or "/"
    if _BAD_PATH_ESCAPE.search(path) or _ENCODED_SLASH_EDGE.search(path):
        ambiguous = True
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeDecodeError:
        ambiguous = True
    else:
        if (_PATH_ESCAPE.search(decoded) or _PATH_CONTROL.search(decoded)
                or "//" in decoded
                or any(part.split(";", 1)[0] in {".", ".."} for part in decoded.split("/"))):
            ambiguous = True
    if not ambiguous:
        return None
    return {
        "safety_reason": "Read-only safety policy blocked an ambiguous request path; no request was sent",
        "safety_signal": "path_ambiguity",
    }


_ACTIONS = (
    "create", "update", "delete", "remove", "assign", "convert", "send",
    "submit", "upload", "reset", "revoke", "approve", "reject", "activate",
    "deactivate", "enable", "disable", "execute", "trigger", "start", "stop",
    "cancel", "purchase", "pay", "transfer", "withdraw", "deposit", "write",
    "save", "insert", "modify", "publish", "unpublish", "enqueue", "dispatch",
    "generate", "import", "restore", "terminate", "invalidate", "schedule",
)
# Extra verbs that only apply to an operator-declared read-only POST. They
# exclude words whose plural is a common resource name (orders, comments,
# reports, links...), so a path such as /orders/search is not refused.
_POST_ACTIONS = _ACTIONS + (
    "add", "register", "edit", "change", "replace", "patch", "grant", "invite", "sign",
    "apply", "accept", "decline", "unarchive", "unlock", "rename", "move", "clone", "merge",
    "sync", "refresh", "rotate", "checkout", "subscribe", "unsubscribe", "follow", "unfollow",
    "attach", "detach", "unlink", "refund", "confirm", "login", "logout", "signin", "signout",
    "signup", "authenticate", "verify", "redeem", "renew", "extend", "retry", "resend",
    "notify", "increment", "decrement", "toggle", "upsert", "append", "purge", "clear",
    "destroy", "drop", "kill", "ban", "unban", "unblock", "mute", "unmute", "unshare",
)
# A read-only POST must name one of these actions: the declaration alone is not
# accepted as evidence that a command-like POST has no side effects.
_POST_READ_INTENTS = (
    "search", "msearch", "query", "lookup", "find", "get", "mget", "list", "fetch", "retrieve",
    "read", "view", "show", "describe", "count", "filter", "browse", "inspect", "preview",
    "check", "validate", "calculate", "compute", "estimate",
)


def _word_forms(verbs: tuple[str, ...]) -> set[str]:
    forms = set(verbs)
    for verb in verbs:
        forms.add(verb + ("es" if verb.endswith(("s", "x", "z", "ch", "sh", "o")) else "s"))
        forms.add((verb[:-1] if verb.endswith("e") else verb) + "ing")
        if verb in {"reset", "submit", "stop", "transfer", "drop", "ban", "unban"}:
            forms.add(verb + verb[-1] + "ing")
    return forms


def _alternation(forms: set[str]) -> str:
    return r"(?:" + "|".join(sorted(forms, key=lambda word: (-len(word), word))) + r")\b"


class _ActionPatterns:
    def __init__(self, verbs: tuple[str, ...], methods: str) -> None:
        word = _alternation(_word_forms(verbs))
        self.leading = re.compile(r"^" + word, re.IGNORECASE)
        self.conjoined = re.compile(r"\b(?:and|then|also)\s+(?:it\s+)?" + word, re.IGNORECASE)
        self.description = re.compile(
            r"^(?:(?:this|the)\s+(?:(?:" + methods + r")\s+)?"
            r"(?:endpoint|operation|request|api|method|" + methods + r")\s+"
            r"(?:(?:is\s+(?:used|designed|intended)\s+to|will|may|can|also|is)\s+)?"
            r"|(?:will|may|can)\s+)?" + word,
            re.IGNORECASE,
        )
        self.informational = re.compile(
            r"^" + word + r"\s+(?:are|were)\s+(?:available|supported|listed|documented|possible)\b",
            re.IGNORECASE,
        )


_READ_PATTERNS = _ActionPatterns(_ACTIONS, "get|head")
_POST_PATTERNS = _ActionPatterns(_POST_ACTIONS, "get|head|post")
_LEADING_READ_INTENT = re.compile(r"^" + _alternation(_word_forms(_POST_READ_INTENTS)), re.IGNORECASE)
# Retained names: the GET/HEAD vocabulary is unchanged.
_LEADING_ACTION = _READ_PATTERNS.leading
_CONJOINED_ACTION = _READ_PATTERNS.conjoined


def _words(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    # Retain word boundaries for identifiers such as convertVideo/create_report.
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return re.sub(r"[^a-zA-Z0-9]+", " ", value).strip().lower()


def _mutation_signal(endpoint: Dict[str, Any], patterns: _ActionPatterns) -> str:
    identifier = _words(endpoint.get("operation_id", ""))
    if patterns.leading.search(identifier) or patterns.conjoined.search(identifier):
        return "operation_id"
    path = str(endpoint.get("path", ""))
    # Object placeholders are data, not action names.
    path = re.sub(r"\{[^}]*\}", "", path)
    if any(patterns.leading.search(_words(part)) for part in path.split("/")):
        return "path"
    for field in ("summary", "description"):
        value = endpoint.get(field, "")
        if not isinstance(value, str):
            continue
        # Match affirmative operation clauses, not arbitrary mentions of
        # write verbs such as "Return the report created by POST".
        clauses = re.split(r"[.!?;\n]+", value)
        words = [_words(clause) for clause in clauses]
        if any((patterns.description.search(clause)
                and not patterns.informational.search(clause))
               or patterns.conjoined.search(clause) for clause in words):
            return field
    return ""


def _has_read_intent(endpoint: Dict[str, Any]) -> bool:
    if _LEADING_READ_INTENT.search(_words(endpoint.get("operation_id", ""))):
        return True
    path = re.sub(r"\{[^}]*\}", "", str(endpoint.get("path", "")))
    if any(_LEADING_READ_INTENT.search(_words(part)) for part in path.split("/")):
        return True
    summary = endpoint.get("summary", "")
    return isinstance(summary, str) and bool(_LEADING_READ_INTENT.search(_words(summary)))


def read_only_risk(endpoint: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Return a safe-to-display signal if an operation may change state.

    GET/HEAD are refused only when their metadata explicitly suggests mutation.
    A POST is refused when its metadata uses the wider POST mutation vocabulary
    or does not name a read action. Other methods are not read operations and
    are gated by their callers. Metadata values are never echoed: specification
    prose can contain credentials or private examples. A benign summary cannot
    override a command-like path.
    """
    method = str(endpoint.get("method", "")).upper()
    if method in {"GET", "HEAD"}:
        signal = _mutation_signal(endpoint, _READ_PATTERNS)
    elif method == "POST":
        signal = _mutation_signal(endpoint, _POST_PATTERNS)
        if not signal and not _has_read_intent(endpoint):
            return {
                "safety_reason": "Read-only POST safety policy requires the path, operationId or summary to name a "
                                 "read action such as search, query or lookup; no request was sent",
                "safety_signal": "post_read_intent",
            }
    else:
        return None
    if not signal:
        return None
    return {
        "safety_reason": "Read-only safety policy blocked an operation with explicit state-changing semantics; no request was sent",
        "safety_signal": signal,
    }


def post_path_risk(path: str) -> Optional[Dict[str, str]]:
    """Refuse a concrete POST path whose segments, including filled values, name a mutation."""
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeDecodeError:
        decoded = path
    for candidate in {path, decoded}:
        # Check matrix parameters too: a router may ignore them, a handler may not.
        pieces = [piece for part in candidate.split("/") for piece in part.split(";")]
        if any(_POST_PATTERNS.leading.search(_words(piece)) for piece in pieces):
            return {
                "safety_reason": "Read-only safety policy blocked a POST path with explicit state-changing semantics; "
                                 "no request was sent",
                "safety_signal": "path",
            }
    return None
