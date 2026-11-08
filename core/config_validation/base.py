"""Shared pieces of configuration validation: issue records, known keys and helpers."""

from __future__ import annotations

import difflib
import math
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional, Sequence, Set

from core.evidence import sanitize_log_text, sanitize_text


@dataclass
class ConfigIssue:
    path: str
    message: str
    expected: str
    actual: str
    suggestion: Optional[str] = None
    is_warning: bool = False

    def format(self) -> str:
        prefix = "  [WARN]" if self.is_warning else "  - Path:"
        safe_path = sanitize_log_text(sanitize_text(self.path))
        safe_msg = sanitize_log_text(sanitize_text(self.message))
        lines = [f"{prefix} '{safe_path}'", f"    Reason:   {safe_msg}"]
        if self.expected:
            lines.append(f"    Expected: {sanitize_log_text(sanitize_text(self.expected))}")
        if self.actual:
            lines.append(f"    Actual:   {sanitize_log_text(sanitize_text(self.actual))}")
        if self.suggestion:
            lines.append(f"    Tip:      {sanitize_log_text(sanitize_text(self.suggestion))}")
        return "\n".join(lines)


@dataclass
class ValidationSummary:
    total_issues: int = 0
    errors_count: int = 0
    warnings_count: int = 0
    identities_count: int = 0
    allowlisted_endpoints: int = 0
    readbacks_count: int = 0
    parameter_endpoints: int = 0
    bola_policies_count: int = 0
    bopla_policies_count: int = 0


@dataclass
class ConfigValidationResult:
    is_valid: bool
    issues: List[ConfigIssue] = field(default_factory=list)
    summary: ValidationSummary = field(default_factory=ValidationSummary)

    @property
    def errors(self) -> List[ConfigIssue]:
        return [issue for issue in self.issues if not issue.is_warning]

    @property
    def warnings(self) -> List[ConfigIssue]:
        return [issue for issue in self.issues if issue.is_warning]


class ValidatorBase:
    """Known configuration keys and helpers shared by every section check."""

    MAX_RECURSION_DEPTH = 15

    KNOWN_TOP_LEVEL_KEYS = {
        "$schema",
        "description",
        "identities",
        "parameter_values",
        "write_allowlist",
        "readbacks",
        "bola",
        "bopla",
    }

    KNOWN_IDENTITY_KEYS = {
        "id",
        "token",
        "headers",
        "parameters",
        "auth_header_names",
    }

    KNOWN_READBACK_KEYS = {
        "method",
        "path",
        "consistency",
        "field_map",
        "parameters",
        "parameter_values",
        "snapshot_path",
        "snapshot_field_map",
        "ignore_readback_paths",
        "readback_attempts",
        "readback_delay",
        "baseline_payload",
    }

    KNOWN_BOLA_KEYS = {
        "expected_public",
        "expected_visitor_access",
        "resource_id_paths",
        "private_data_paths",
        "required_role",
        "owner_role",
        "visitor_role",
        "not_found_is_denial",
    }

    VALID_CONSISTENCY_VALUES = ("strong", "weak", "eventual")
    STANDARD_AUTH_HEADER_WORDS = ("authorization", "token", "api_key", "apikey", "cookie", "session", "credential")
    # A cookie whose normalized name contains one of these words carries authentication.
    STANDARD_AUTH_COOKIE_WORDS = STANDARD_AUTH_HEADER_WORDS + (
        "auth", "jwt", "sid", "secret", "ticket", "pass", "login",
    )
    # Query parameters that carry credentials without an apiKey scheme declaring
    # them: RFC 6750 section 2.3 sends bearer tokens as access_token.
    STANDARD_AUTH_QUERY_PARAMETERS = ("access_token",)

    @classmethod
    def _find_closest_match(cls, word: str, candidates: Sequence[str]) -> Optional[str]:
        matches = difflib.get_close_matches(word, candidates, n=1, cutoff=0.6)
        return matches[0] if matches else None

    @classmethod
    def _check_depth(cls, obj: Any, current_depth: int, max_depth: int) -> bool:
        if current_depth > max_depth:
            return False
        if isinstance(obj, dict):
            for v in obj.values():
                if not cls._check_depth(v, current_depth + 1, max_depth):
                    return False
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                if not cls._check_depth(item, current_depth + 1, max_depth):
                    return False
        return True

    @classmethod
    def _check_no_nan_or_inf(cls, obj: Any, path: str, issues: List[ConfigIssue]) -> None:
        if isinstance(obj, float):
            if math.isnan(obj):
                issues.append(
                    ConfigIssue(
                        path=path,
                        message="Non-standard JSON number NaN is not permitted in configuration",
                        expected="standard finite JSON number",
                        actual="NaN",
                    )
                )
            elif math.isinf(obj):
                issues.append(
                    ConfigIssue(
                        path=path,
                        message="Non-standard JSON number Infinity is not permitted in configuration",
                        expected="standard finite JSON number",
                        actual="Infinity" if obj > 0 else "-Infinity",
                    )
                )
        elif isinstance(obj, dict):
            for k, v in obj.items():
                sub_path = f"{path}.{k}" if path else str(k)
                cls._check_no_nan_or_inf(v, sub_path, issues)
        elif isinstance(obj, (list, tuple)):
            for i, item in enumerate(obj):
                cls._check_no_nan_or_inf(item, f"{path}[{i}]", issues)

    @classmethod
    def is_auth_header(
        cls,
        name: str,
        custom_auth_names: Optional[Iterable[str]] = None,
        spec_auth_names: Optional[Iterable[str]] = None,
    ) -> bool:
        normalized = str(name).lower().replace("-", "_")
        if any(word in normalized for word in cls.STANDARD_AUTH_HEADER_WORDS):
            return True
        declared: Set[str] = set()
        if custom_auth_names:
            declared.update(str(k).lower() for k in custom_auth_names if isinstance(k, str))
        if spec_auth_names:
            declared.update(str(k).lower() for k in spec_auth_names if isinstance(k, str))
        return str(name).lower() in declared

    @classmethod
    def _is_auth_header(
        cls,
        name: str,
        custom_auth_names: Sequence[str] = (),
        spec_auth_names: Sequence[str] = (),
    ) -> bool:
        return cls.is_auth_header(name, custom_auth_names, spec_auth_names)
