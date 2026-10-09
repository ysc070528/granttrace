"""Conservative local checks for read-path ambiguity and mutation semantics.

These rules cannot prove that an operation is side-effect free. They identify
command-like paths/operation identifiers and affirmative mutation descriptions;
an undocumented server-side effect still requires operator review.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import unquote, urlsplit


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
_ACTION_FORMS = set(_ACTIONS)
for _verb in _ACTIONS:
    _ACTION_FORMS.add(_verb + ("es" if _verb.endswith(("s", "x", "z", "ch", "sh", "o")) else "s"))
    _ACTION_FORMS.add((_verb[:-1] if _verb.endswith("e") else _verb) + "ing")
    if _verb in {"reset", "submit", "stop", "transfer"}:
        _ACTION_FORMS.add(_verb + _verb[-1] + "ing")
_ACTION_WORD = r"(?:" + "|".join(sorted(_ACTION_FORMS, key=lambda word: (-len(word), word))) + r")\b"
_LEADING_ACTION = re.compile(r"^" + _ACTION_WORD, re.IGNORECASE)
_CONJOINED_ACTION = re.compile(r"\b(?:and|then|also)\s+(?:it\s+)?" + _ACTION_WORD, re.IGNORECASE)
_OPERATION_DESCRIPTION = re.compile(
    r"^(?:(?:this|the)\s+(?:(?:get|head)\s+)?"
    r"(?:endpoint|operation|request|api|method|get|head)\s+"
    r"(?:(?:is\s+(?:used|designed|intended)\s+to|will|may|can|also|is)\s+)?"
    r"|(?:will|may|can)\s+)?" + _ACTION_WORD,
    re.IGNORECASE,
)
_INFORMATIONAL_ACTION_NOUN = re.compile(
    r"^" + _ACTION_WORD + r"\s+(?:are|were)\s+(?:available|supported|listed|documented|possible)\b",
    re.IGNORECASE,
)


def _words(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    # Retain word boundaries for identifiers such as convertVideo/create_report.
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return re.sub(r"[^a-zA-Z0-9]+", " ", value).strip().lower()


def read_only_risk(endpoint: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Return a safe-to-display signal if GET/HEAD explicitly suggests mutation.

    Metadata values are never echoed: specification prose can contain credentials
    or private examples. A benign summary cannot override a command-like path.
    """
    if str(endpoint.get("method", "")).upper() not in {"GET", "HEAD"}:
        return None

    identifier = _words(endpoint.get("operation_id", ""))
    if _LEADING_ACTION.search(identifier) or _CONJOINED_ACTION.search(identifier):
        signal = "operation_id"
    else:
        path = str(endpoint.get("path", ""))
        # Object placeholders are data, not action names.
        path = re.sub(r"\{[^}]*\}", "", path)
        if any(_LEADING_ACTION.search(_words(part)) for part in path.split("/")):
            signal = "path"
        else:
            signal = ""
            for field in ("summary", "description"):
                value = endpoint.get(field, "")
                if not isinstance(value, str):
                    continue
                # Match affirmative operation clauses, not arbitrary mentions of
                # write verbs such as "Return the report created by POST".
                clauses = re.split(r"[.!?;\n]+", value)
                words = [_words(clause) for clause in clauses]
                if any((_OPERATION_DESCRIPTION.search(clause)
                        and not _INFORMATIONAL_ACTION_NOUN.search(clause))
                       or _CONJOINED_ACTION.search(clause) for clause in words):
                    signal = field
                    break
            if not signal:
                return None

    return {
        "safety_reason": "Read-only safety policy blocked an operation with explicit state-changing semantics; no request was sent",
        "safety_signal": signal,
    }
