"""Small shared data models for transport and scan accounting."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple


def strict_json_loads(text: str) -> Any:
    """Decode JSON without non-standard constants or overflowing floats."""
    def reject_constant(value: str) -> None:
        raise ValueError(f"Non-standard JSON number is not permitted: {value}")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("JSON number exceeds the supported finite range")
        return number

    return json.loads(text, parse_constant=reject_constant, parse_float=finite_float)


def json_values_equal(left, right) -> bool:
    """Compare JSON without Python's True == 1 / False == 0 coercion."""
    try:
        return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
            right, sort_keys=True, allow_nan=False
        )
    except (TypeError, ValueError, RecursionError):
        return False


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    SECURE = "SECURE"
    PUBLIC = "PUBLIC"
    SUSPICIOUS = "SUSPICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class HTTPResult:
    status: int
    body: str
    error: Optional[str] = None
    truncated: bool = False
    headers: Dict[str, str] = field(default_factory=dict)

    def as_tuple(self) -> Tuple[int, str]:
        return self.status, self.body

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300


STANDARD_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE")


def parse_operation_key(key: Any) -> Tuple[bool, str, str, str, Optional[str]]:
    """Parse and validate an operation key such as 'PATCH /api/users/{id}'.

    Returns:
        (is_valid, method, path, canonical_key, error_message)
    """
    if not isinstance(key, str):
        return False, "", "", "", f"operation key must be a string, got {type(key).__name__}"

    if key != key.strip():
        return False, "", "", "", "operation key must not contain leading or trailing whitespace"

    parts = key.split(" ")
    if len(parts) != 2:
        return False, "", "", "", "operation key must be '<METHOD> /<path>' separated by a single space"

    raw_method, path = parts[0], parts[1]
    if not raw_method:
        return False, "", "", "", "HTTP method cannot be empty"
    # Enforce uppercase method in configuration
    if raw_method != raw_method.upper():
        return False, "", "", "", f"HTTP method must be uppercase, got '{raw_method}'"

    method = raw_method.upper()
    if method not in STANDARD_HTTP_METHODS:
        return False, "", "", "", f"unsupported HTTP method '{method}', expected one of {list(STANDARD_HTTP_METHODS)}"

    if not path.startswith("/"):
        return False, "", "", "", f"operation path must start with '/', got '{path}'"

    if "?" in path or "#" in path:
        return False, "", "", "", "operation path must not contain query parameters or fragments"

    if any(c in path for c in "\r\n\t "):
        return False, "", "", "", "operation path must not contain whitespace or line breaks"

    canonical_key = f"{method} {path}"
    return True, method, path, canonical_key, None

