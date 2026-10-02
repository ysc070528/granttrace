# -*- coding: utf-8 -*-
"""Authoritative configuration validation engine for API-Sentinel (v2.3.1-final).

Provides offline, comprehensive semantic validation for API-Sentinel configuration
files. Reuses the exact security rules and constraints enforced by the auditor
and transaction managers without requiring external dependencies like jsonschema.
"""

from __future__ import annotations

import difflib
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from core.evidence import _is_sensitive_key, safe_diagnostic_value, sanitize_log_text, sanitize_text
from core.models import STANDARD_HTTP_METHODS, parse_operation_key
from core.transactions import path_parts, paths_collide


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


class ConfigValidator:
    """Authoritative semantic validator for API-Sentinel configuration objects."""

    MAX_RECURSION_DEPTH = 15

    KNOWN_TOP_LEVEL_KEYS = {
        "$schema",
        "description",
        "identities",
        "parameter_values",
        "write_allowlist",
        "readbacks",
        "bola",
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
        "resource_id_paths",
    }

    VALID_CONSISTENCY_VALUES = ("strong", "weak", "eventual")
    STANDARD_AUTH_HEADER_WORDS = ("authorization", "token", "api_key", "apikey", "cookie", "session", "credential")

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
    def validate(cls, config: Any, raw_spec: Optional[Dict[str, Any]] = None) -> ConfigValidationResult:
        """Validate a loaded configuration mapping and collect all issues without early exit."""
        issues: List[ConfigIssue] = []
        summary = ValidationSummary()

        if not isinstance(config, dict):
            issues.append(
                ConfigIssue(
                    path="<root>",
                    message="Configuration root must be a JSON object",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(config),
                )
            )
            summary.total_issues = len(issues)
            summary.errors_count = len(issues)
            return ConfigValidationResult(is_valid=False, issues=issues, summary=summary)

        # 0. Check maximum recursion depth to defend against malicious/circular payloads
        if not cls._check_depth(config, 0, cls.MAX_RECURSION_DEPTH):
            issues.append(
                ConfigIssue(
                    path="<root>",
                    message=f"Configuration nesting exceeds maximum supported depth of {cls.MAX_RECURSION_DEPTH}",
                    expected=f"depth <= {cls.MAX_RECURSION_DEPTH}",
                    actual="excessive nesting",
                )
            )
            summary.total_issues = len(issues)
            summary.errors_count = len(issues)
            return ConfigValidationResult(is_valid=False, issues=issues, summary=summary)

        # Check for NaN / Infinity numbers
        try:
            cls._check_no_nan_or_inf(config, "", issues)
        except Exception as exc:
            issues.append(
                ConfigIssue(
                    path="<root>",
                    message=f"Error inspecting numeric values: {exc}",
                    expected="valid JSON values",
                    actual=safe_diagnostic_value(type(exc).__name__),
                )
            )

        # 1. Check top-level unrecognized keys and typos
        for key in list(config.keys()):
            if key not in cls.KNOWN_TOP_LEVEL_KEYS:
                closest = cls._find_closest_match(str(key), sorted(cls.KNOWN_TOP_LEVEL_KEYS))
                suggestion = f"Did you mean '{closest}'?" if closest else None
                issues.append(
                    ConfigIssue(
                        path=str(key),
                        message=f"Unrecognized top-level configuration key '{key}'",
                        expected=f"one of {sorted(cls.KNOWN_TOP_LEVEL_KEYS)}",
                        actual=safe_diagnostic_value(key),
                        suggestion=suggestion,
                    )
                )

        # Description / $schema
        if "$schema" in config and not isinstance(config["$schema"], str):
            issues.append(
                ConfigIssue(
                    path="$schema",
                    message="$schema declaration must be a string",
                    expected="string",
                    actual=safe_diagnostic_value(config["$schema"]),
                )
            )
        if "description" in config and not isinstance(config["description"], str):
            issues.append(
                ConfigIssue(
                    path="description",
                    message="Description must be a string",
                    expected="string",
                    actual=safe_diagnostic_value(config["description"]),
                )
            )

        # 2. Section: identities
        try:
            spec_auth_names = cls._extract_spec_auth_headers(raw_spec)
        except (TypeError, ValueError) as exc:
            issues.append(ConfigIssue(
                path="<spec>.securitySchemes",
                message=f"Invalid specification authentication definitions: {exc}",
                expected="object-valued securityDefinitions, components, and securitySchemes",
                actual="malformed specification structure",
            ))
            spec_auth_names = set()
        if "identities" in config:
            try:
                cls._validate_identities_section(
                    config["identities"], issues, summary, spec_auth_names=spec_auth_names
                )
            except Exception as exc:
                issues.append(
                    ConfigIssue(
                        path="identities",
                        message=f"Validation failed on identities section: {exc}",
                        expected="valid identities object",
                        actual=safe_diagnostic_value(type(exc).__name__),
                    )
                )

        # 3. Section: write_allowlist
        allowlisted_set: Set[str] = set()
        if "write_allowlist" in config:
            try:
                cls._validate_write_allowlist_section(
                    config["write_allowlist"], issues, summary, allowlisted_set
                )
            except Exception as exc:
                issues.append(
                    ConfigIssue(
                        path="write_allowlist",
                        message=f"Validation failed on write_allowlist section: {exc}",
                        expected="list of strings",
                        actual=safe_diagnostic_value(type(exc).__name__),
                    )
                )

        # 4. Section: readbacks
        readbacks_set: Set[str] = set()
        if "readbacks" in config:
            try:
                cls._validate_readbacks_section(
                    config["readbacks"], issues, summary, readbacks_set
                )
            except Exception as exc:
                issues.append(
                    ConfigIssue(
                        path="readbacks",
                        message=f"Validation failed on readbacks section: {exc}",
                        expected="dict mapping operation keys to readback configurations",
                        actual=safe_diagnostic_value(type(exc).__name__),
                    )
                )

        # Cross-check: write_allowlist endpoints MUST have a valid readback mapping!
        # Must execute even if 'readbacks' section is omitted or empty.
        if allowlisted_set:
            missing_readbacks = sorted(allowlisted_set - readbacks_set)
            for missing_op in missing_readbacks:
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{missing_op}",
                        message=f"Operation '{missing_op}' is in write_allowlist but missing an independent GET readback mapping",
                        expected=f"an entry in 'readbacks' for '{missing_op}'",
                        actual="missing",
                        suggestion=f"Define readback mapping under 'readbacks' for '{missing_op}' with method 'GET' and field_map",
                    )
                )

        # 5. Section: parameter_values
        if "parameter_values" in config:
            try:
                cls._validate_parameter_values_section(config["parameter_values"], issues, summary)
            except Exception as exc:
                issues.append(
                    ConfigIssue(
                        path="parameter_values",
                        message=f"Validation failed on parameter_values section: {exc}",
                        expected="dict indexed by operation keys",
                        actual=safe_diagnostic_value(type(exc).__name__),
                    )
                )

        # 6. Section: bola
        if "bola" in config:
            try:
                cls._validate_bola_section(config["bola"], issues, summary)
            except Exception as exc:
                issues.append(
                    ConfigIssue(
                        path="bola",
                        message=f"Validation failed on bola section: {exc}",
                        expected="dict indexed by operation keys",
                        actual=safe_diagnostic_value(type(exc).__name__),
                    )
                )

        errors = [issue for issue in issues if not issue.is_warning]
        summary.total_issues = len(issues)
        summary.errors_count = len(errors)
        summary.warnings_count = len(issues) - len(errors)

        return ConfigValidationResult(
            is_valid=(len(errors) == 0),
            issues=issues,
            summary=summary,
        )

    @classmethod
    def _extract_spec_auth_headers(cls, raw_spec: Optional[Dict[str, Any]]) -> Set[str]:
        if not isinstance(raw_spec, dict):
            return set()
        legacy = raw_spec.get("securityDefinitions", {})
        components = raw_spec.get("components", {})
        if not isinstance(legacy, dict) or not isinstance(components, dict):
            raise ValueError("securityDefinitions and components must be objects")
        modern = components.get("securitySchemes", {})
        if not isinstance(modern, dict):
            raise ValueError("components.securitySchemes must be an object")
        schemes = dict(legacy)
        schemes.update(modern)
        return {
            str(scheme.get("name", "")).lower()
            for scheme in schemes.values()
            if isinstance(scheme, dict) and scheme.get("in") == "header" and scheme.get("name")
        }

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

    @classmethod
    def _validate_identities_section(
        cls,
        identities: Any,
        issues: List[ConfigIssue],
        summary: ValidationSummary,
        spec_auth_names: Optional[Set[str]] = None,
    ) -> None:
        if not isinstance(identities, dict):
            issues.append(
                ConfigIssue(
                    path="identities",
                    message="'identities' must be an object containing 'owner', 'visitor', and 'anonymous'",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(identities),
                )
            )
            return

        expected_identities = {"owner", "visitor", "anonymous"}
        missing_required = expected_identities - set(identities)
        if missing_required:
            issues.append(
                ConfigIssue(
                    path="identities",
                    message=f"Missing required identity roles: {sorted(missing_required)}",
                    expected="all of ['anonymous', 'owner', 'visitor']",
                    actual=f"present: {sorted(str(k) for k in identities.keys())}",
                    suggestion="Ensure 'owner', 'visitor', and 'anonymous' are all defined in 'identities'",
                )
            )

        for identity_name, identity_data in identities.items():
            if identity_name not in expected_identities:
                closest = cls._find_closest_match(str(identity_name), sorted(expected_identities))
                suggestion = f"Did you mean '{closest}'?" if closest else None
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}",
                        message=f"Unrecognized identity role '{identity_name}'",
                        expected="one of ['owner', 'visitor', 'anonymous']",
                        actual=safe_diagnostic_value(identity_name),
                        suggestion=suggestion,
                    )
                )
                continue

            if not isinstance(identity_data, dict):
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}",
                        message=f"Identity '{identity_name}' must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(identity_data),
                    )
                )
                continue

            summary.identities_count += 1
            cls._validate_single_identity(identity_name, identity_data, issues)

        # Collect all custom auth header names across all identities
        all_custom_names: Set[str] = set()
        if isinstance(identities, dict):
            for id_data in identities.values():
                if isinstance(id_data, dict) and isinstance(id_data.get("auth_header_names"), list):
                    for n in id_data["auth_header_names"]:
                        if isinstance(n, str) and n.strip():
                            all_custom_names.add(n.strip().lower())

        # Cross-identity effective authentication verification
        if all(k in identities and isinstance(identities[k], dict) for k in ("owner", "visitor", "anonymous")):
            cls._validate_identity_authentication_integrity(
                identities, issues, custom_names=all_custom_names, spec_names=spec_auth_names
            )

    @classmethod
    def _validate_single_identity(
        cls,
        identity_name: str,
        identity: Dict[str, Any],
        issues: List[ConfigIssue],
    ) -> None:
        for key in identity.keys():
            if key not in cls.KNOWN_IDENTITY_KEYS:
                closest = cls._find_closest_match(str(key), sorted(cls.KNOWN_IDENTITY_KEYS))
                suggestion = f"Did you mean '{closest}'?" if closest else None
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}.{key}",
                        message=f"Unrecognized field '{key}' in identity '{identity_name}'",
                        expected=f"one of {sorted(cls.KNOWN_IDENTITY_KEYS)}",
                        actual=safe_diagnostic_value(key),
                        suggestion=suggestion,
                    )
                )

        # token
        token = identity.get("token")
        if token is not None:
            if not isinstance(token, str):
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}.token",
                        message="Identity token must be a string or null",
                        expected="string or null",
                        actual=safe_diagnostic_value(token),
                    )
                )
            elif any(c in token for c in "\r\n\t"):
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}.token",
                        message="Identity token must not contain line breaks or control characters",
                        expected="single-line clean string",
                        # Do NOT leak token value!
                        actual="<token string with line breaks/control chars>",
                    )
                )

        # id
        ident_id = identity.get("id")
        if ident_id is not None:
            if isinstance(ident_id, bool) or not isinstance(ident_id, (str, int)):
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}.id",
                        message="Identity id must be a string, integer, or null",
                        expected="string, integer, or null",
                        actual=safe_diagnostic_value(ident_id),
                    )
                )
            elif isinstance(ident_id, str) and any(c in ident_id for c in "\r\n\t"):
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}.id",
                        message="Identity id must not contain line breaks or control characters",
                        expected="clean identifier string",
                        actual=safe_diagnostic_value(ident_id),
                    )
                )

        # headers
        headers = identity.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}.headers",
                        message=f"Headers for '{identity_name}' must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(headers),
                    )
                )
            else:
                seen_headers: Set[str] = set()
                for h_key, h_val in headers.items():
                    norm_h = str(h_key).strip().lower()
                    if norm_h in seen_headers:
                        issues.append(
                            ConfigIssue(
                                path=f"identities.{identity_name}.headers.{h_key}",
                                message=f"Duplicate case-insensitive header '{norm_h}'",
                                expected="unique case-insensitive header names",
                                actual=safe_diagnostic_value(h_key),
                            )
                        )
                    seen_headers.add(norm_h)

                    if not isinstance(h_val, str):
                        issues.append(
                            ConfigIssue(
                                path=f"identities.{identity_name}.headers.{h_key}",
                                message=f"Header value for '{h_key}' must be a string",
                                expected="string",
                                actual=safe_diagnostic_value(h_val),
                            )
                        )
                    elif any(c in str(h_key) + str(h_val) for c in "\r\n\t"):
                        issues.append(
                            ConfigIssue(
                                path=f"identities.{identity_name}.headers.{h_key}",
                                message="Identity header names and values must not contain line breaks or control characters",
                                expected="single-line header key/value",
                                actual=f"{safe_diagnostic_value(h_key)}: [VALUE WITH LINEBREAKS REDACTED]",
                            )
                        )

        # parameters
        parameters = identity.get("parameters")
        if parameters is not None:
            if not isinstance(parameters, dict):
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}.parameters",
                        message="Identity parameters must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(parameters),
                    )
                )
            else:
                for p_k in parameters.keys():
                    if not isinstance(p_k, str) or not p_k.strip():
                        issues.append(
                            ConfigIssue(
                                path=f"identities.{identity_name}.parameters",
                                message="Parameter names must be non-empty strings",
                                expected="non-empty string key",
                                actual=safe_diagnostic_value(p_k),
                            )
                        )

        # auth_header_names
        auth_names = identity.get("auth_header_names")
        if auth_names is not None:
            if not isinstance(auth_names, list) or any(not isinstance(k, str) or not k.strip() for k in auth_names):
                issues.append(
                    ConfigIssue(
                        path=f"identities.{identity_name}.auth_header_names",
                        message="auth_header_names must be a list of non-empty header name strings",
                        expected="list of non-empty strings",
                        actual=safe_diagnostic_value(auth_names),
                    )
                )
            else:
                for k in auth_names:
                    if any(c in k for c in "\r\n\t"):
                        issues.append(
                            ConfigIssue(
                                path=f"identities.{identity_name}.auth_header_names",
                                message="Header names in auth_header_names must not contain line breaks or control characters",
                                expected="clean header name",
                                actual=safe_diagnostic_value(k),
                            )
                        )

    @classmethod
    def _extract_effective_auth_material(
        cls,
        identity_name: str,
        identity: Dict[str, Any],
        custom_names: Optional[Iterable[str]] = None,
        spec_names: Optional[Iterable[str]] = None,
    ) -> Tuple[Tuple[str, str], ...]:
        combined_custom: Set[str] = set()
        if custom_names:
            combined_custom.update(str(k).lower() for k in custom_names if isinstance(k, str))
        for k in (identity.get("auth_header_names") or []):
            if isinstance(k, str) and k.strip():
                combined_custom.add(k.strip().lower())

        headers: Dict[str, str] = {}
        for k, v in (identity.get("headers") or {}).items():
            if isinstance(v, str):
                headers[str(k).strip().lower()] = str(v).strip()
        token = identity.get("token")
        if isinstance(token, str) and token.strip():
            headers["authorization"] = token.strip()

        material = []
        for key, value in headers.items():
            if cls.is_auth_header(key, combined_custom, spec_names) and value:
                normalized = value
                if key == "authorization" and " " in normalized:
                    scheme, credential = normalized.split(None, 1)
                    normalized = scheme.lower() + " " + credential.strip()
                material.append((key, normalized))
        return tuple(sorted(material))

    @classmethod
    def _validate_identity_authentication_integrity(
        cls,
        identities: Dict[str, Any],
        issues: List[ConfigIssue],
        custom_names: Optional[Iterable[str]] = None,
        spec_names: Optional[Iterable[str]] = None,
    ) -> None:
        owner_mat = cls._extract_effective_auth_material("owner", identities["owner"], custom_names, spec_names)
        visitor_mat = cls._extract_effective_auth_material("visitor", identities["visitor"], custom_names, spec_names)
        anon_mat = cls._extract_effective_auth_material("anonymous", identities["anonymous"], custom_names, spec_names)

        if not owner_mat:
            issues.append(
                ConfigIssue(
                    path="identities.owner",
                    message="Owner identity has no effective authentication material (token, Authorization, or custom auth header)",
                    expected="non-empty authentication credentials",
                    actual="empty auth material",
                )
            )
        if not visitor_mat:
            issues.append(
                ConfigIssue(
                    path="identities.visitor",
                    message="Visitor identity has no effective authentication material (token, Authorization, or custom auth header)",
                    expected="non-empty authentication credentials",
                    actual="empty auth material",
                )
            )
        if owner_mat and visitor_mat and owner_mat == visitor_mat:
            issues.append(
                ConfigIssue(
                    path="identities.visitor",
                    message="Owner and visitor must use distinct effective authentication credentials to verify authorization boundaries",
                    expected="distinct credentials from owner",
                    actual="identical auth material to owner (redacted)",
                )
            )
        if anon_mat:
            auth_header_keys = [k for k, _ in anon_mat]
            issues.append(
                ConfigIssue(
                    path="identities.anonymous",
                    message="Anonymous identity must not define authentication credentials or auth headers",
                    expected="empty authentication material",
                    # Never leak token value!
                    actual=f"credentials configured under: {auth_header_keys}",
                )
            )

        # Anonymous structure constraints
        anon = identities.get("anonymous", {})
        if isinstance(anon, dict):
            if anon.get("id") is not None:
                issues.append(
                    ConfigIssue(
                        path="identities.anonymous.id",
                        message="Anonymous identity id must be null",
                        expected="null",
                        actual=safe_diagnostic_value(anon.get("id")),
                    )
                )
            if anon.get("token") is not None:
                issues.append(
                    ConfigIssue(
                        path="identities.anonymous.token",
                        message="Anonymous identity token must be null",
                        expected="null",
                        actual="[TOKEN PRESENT REDACTED]",
                    )
                )
            if anon.get("headers"):
                issues.append(
                    ConfigIssue(
                        path="identities.anonymous.headers",
                        message="Anonymous identity headers must be empty",
                        expected="empty object",
                        actual=f"{len(anon['headers'])} header(s) configured",
                    )
                )

    @classmethod
    def _validate_write_allowlist_section(
        cls,
        allowlist: Any,
        issues: List[ConfigIssue],
        summary: ValidationSummary,
        allowlisted_set: Set[str],
    ) -> None:
        if not isinstance(allowlist, list):
            issues.append(
                ConfigIssue(
                    path="write_allowlist",
                    message="'write_allowlist' must be a list of 'PATCH /path' strings",
                    expected="list of strings",
                    actual=safe_diagnostic_value(allowlist),
                )
            )
            return

        for index, item in enumerate(allowlist):
            is_valid, method, path, canonical, err_msg = parse_operation_key(item)
            if not is_valid:
                issues.append(
                    ConfigIssue(
                        path=f"write_allowlist[{index}]",
                        message=f"Write allowlist entry is invalid: {err_msg}",
                        expected="'PATCH /case-sensitive-path'",
                        actual=safe_diagnostic_value(item),
                        suggestion="Ensure method is uppercase 'PATCH' followed by a space and a path starting with '/'",
                    )
                )
            elif method != "PATCH":
                issues.append(
                    ConfigIssue(
                        path=f"write_allowlist[{index}]",
                        message=f"Write allowlist only supports 'PATCH' operations (got '{method}')",
                        expected="'PATCH /path'",
                        actual=safe_diagnostic_value(item),
                        suggestion="Change method to 'PATCH'",
                    )
                )
            else:
                allowlisted_set.add(canonical)
                summary.allowlisted_endpoints += 1

    @classmethod
    def _validate_readbacks_section(
        cls,
        readbacks: Any,
        issues: List[ConfigIssue],
        summary: ValidationSummary,
        readbacks_set: Set[str],
    ) -> None:
        if not isinstance(readbacks, dict):
            issues.append(
                ConfigIssue(
                    path="readbacks",
                    message="'readbacks' must be an object mapping 'PATCH /path' to readback definitions",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(readbacks),
                )
            )
            return

        for op_key, rb_data in readbacks.items():
            is_valid, method, path, canonical, err_msg = parse_operation_key(op_key)
            if not is_valid:
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}",
                        message=f"Invalid readback operation key: {err_msg}",
                        expected="'PATCH /path'",
                        actual=safe_diagnostic_value(op_key),
                    )
                )
            elif method != "PATCH":
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}",
                        message=f"Readback keys must strictly be 'PATCH /path' operations (got '{method}')",
                        expected="'PATCH /path'",
                        actual=safe_diagnostic_value(op_key),
                    )
                )
            else:
                readbacks_set.add(canonical)

            if not isinstance(rb_data, dict):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}",
                        message=f"Readback definition for '{op_key}' must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(rb_data),
                    )
                )
                continue

            summary.readbacks_count += 1
            cls._validate_single_readback(op_key, rb_data, issues)

    @classmethod
    def _validate_single_readback(
        cls,
        op_key: str,
        readback: Dict[str, Any],
        issues: List[ConfigIssue],
    ) -> None:
        # Check unknown keys
        for key in readback.keys():
            if key not in cls.KNOWN_READBACK_KEYS:
                closest = cls._find_closest_match(str(key), sorted(cls.KNOWN_READBACK_KEYS))
                suggestion = f"Did you mean '{closest}'?" if closest else None
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.{key}",
                        message=f"Unrecognized field '{key}' in readback configuration",
                        expected=f"one of {sorted(cls.KNOWN_READBACK_KEYS)}",
                        actual=safe_diagnostic_value(key),
                        suggestion=suggestion,
                    )
                )

        # method (Required to be uppercase GET)
        method = readback.get("method")
        if method is None:
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.method",
                    message="Readback requires an explicit 'method' specifying 'GET'",
                    expected="'GET'",
                    actual="missing",
                )
            )
        elif not isinstance(method, str):
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.method",
                    message="Readback method must be a string",
                    expected="'GET'",
                    actual=safe_diagnostic_value(method),
                )
            )
        elif method != "GET":
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.method",
                    message=f"Readback method must strictly be uppercase 'GET' (got '{method}')",
                    expected="'GET'",
                    actual=safe_diagnostic_value(method),
                    suggestion="Set method to 'GET'",
                )
            )

        # path (Required, starts with /)
        path = readback.get("path")
        if path is None:
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.path",
                    message="Readback requires an explicit 'path'",
                    expected="string path starting with '/'",
                    actual="missing",
                )
            )
        elif not isinstance(path, str) or not path.startswith("/") or any(c in path for c in "\r\n\t "):
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.path",
                    message="Readback path must be a clean string starting with '/' without whitespace",
                    expected="string starting with '/'",
                    actual=safe_diagnostic_value(path),
                )
            )

        # The readback URL builder consumes a list of Parameter Objects directly;
        # mappings, reference objects, and unsupported locations are not expanded.
        if "parameters" in readback:
            parameters = readback["parameters"]
            if not isinstance(parameters, list):
                issues.append(ConfigIssue(
                    path=f"readbacks.{op_key}.parameters",
                    message="Readback parameters must be an array of path/query parameter objects",
                    expected="list of objects with name, in, and schema",
                    actual=safe_diagnostic_value(parameters),
                ))
            else:
                identities: Set[Tuple[str, str]] = set()
                for index, parameter in enumerate(parameters):
                    parameter_path = f"readbacks.{op_key}.parameters[{index}]"
                    if not isinstance(parameter, dict):
                        issues.append(ConfigIssue(
                            path=parameter_path,
                            message="Readback parameter must be an object",
                            expected="object with name, in, and schema",
                            actual=safe_diagnostic_value(parameter),
                        ))
                        continue
                    name, location = parameter.get("name"), parameter.get("in")
                    valid_name = isinstance(name, str) and bool(name) and not any(
                        character.isspace() or ord(character) < 32 for character in name
                    )
                    if not valid_name:
                        issues.append(ConfigIssue(
                            path=parameter_path + ".name",
                            message="Readback parameter name must be a non-empty clean string",
                            expected="non-empty name without whitespace or control characters",
                            actual=safe_diagnostic_value(name),
                        ))
                    if location not in ("path", "query"):
                        issues.append(ConfigIssue(
                            path=parameter_path + ".in",
                            message="Readback parameter location must be supported by the URL builder",
                            expected="'path' or 'query'",
                            actual=safe_diagnostic_value(location),
                        ))
                    if not isinstance(parameter.get("schema"), dict):
                        issues.append(ConfigIssue(
                            path=parameter_path + ".schema",
                            message="Readback parameter requires a schema object",
                            expected="JSON object",
                            actual=safe_diagnostic_value(parameter.get("schema")),
                        ))
                    if valid_name and location in ("path", "query"):
                        identity = (name, location)
                        if identity in identities:
                            issues.append(ConfigIssue(
                                path=parameter_path,
                                message="Duplicate readback parameter name and location",
                                expected="unique (name, in) pair",
                                actual=safe_diagnostic_value(name),
                            ))
                        identities.add(identity)

        if "parameter_values" in readback:
            values = readback["parameter_values"]
            if not isinstance(values, dict):
                issues.append(ConfigIssue(
                    path=f"readbacks.{op_key}.parameter_values",
                    message="Readback parameter_values must be an object",
                    expected="parameter name -> value object",
                    actual=safe_diagnostic_value(values),
                ))
            else:
                for name in values:
                    if not isinstance(name, str) or not name or any(
                        character.isspace() or ord(character) < 32 for character in name
                    ):
                        issues.append(ConfigIssue(
                            path=f"readbacks.{op_key}.parameter_values",
                            message="Readback parameter value names must be non-empty clean strings",
                            expected="non-empty names without whitespace or control characters",
                            actual=safe_diagnostic_value(name),
                        ))

        # field_map (Required, non-empty dict of valid_path -> valid_path)
        field_map = readback.get("field_map")
        parsed_written_paths: List[Tuple[Any, ...]] = []
        parsed_readback_paths: List[Tuple[Any, ...]] = []
        if field_map is None:
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.field_map",
                    message="Readback requires an explicit non-empty 'field_map'",
                    expected="non-empty object mapping write field path to readback field path",
                    actual="missing",
                )
            )
        elif not isinstance(field_map, dict) or len(field_map) == 0:
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.field_map",
                    message="'field_map' must be a non-empty object mapping write fields to readback paths",
                    expected="non-empty dict",
                    actual=safe_diagnostic_value(field_map),
                )
            )
        else:
            for w_path, r_path in field_map.items():
                if not isinstance(w_path, str) or not isinstance(r_path, str):
                    issues.append(
                        ConfigIssue(
                            path=f"readbacks.{op_key}.field_map",
                            message="field_map keys and values must be string path expressions",
                            expected="string -> string",
                            actual=f"{safe_diagnostic_value(w_path)} -> {safe_diagnostic_value(r_path)}",
                        )
                    )
                    continue

                # Verify dot/bracket path syntax compatible with transactions.path_parts
                try:
                    parts_w = path_parts(w_path)
                    parsed_written_paths.append(parts_w)
                except ValueError as exc:
                    issues.append(
                        ConfigIssue(
                            path=f"readbacks.{op_key}.field_map.{w_path}",
                            message=f"Invalid mutation path expression in field_map: {exc}",
                            expected="valid dot/bracket path (e.g. 'role', 'members[0].role')",
                            actual=safe_diagnostic_value(w_path),
                        )
                    )
                try:
                    parts_r = path_parts(r_path)
                    parsed_readback_paths.append(parts_r)
                except ValueError as exc:
                    issues.append(
                        ConfigIssue(
                            path=f"readbacks.{op_key}.field_map.{w_path}",
                            message=f"Invalid readback path expression in field_map: {exc}",
                            expected="valid dot/bracket path (e.g. 'data.role')",
                            actual=safe_diagnostic_value(r_path),
                        )
                    )

        # consistency (Optional enum: strong, weak, eventual)
        consistency = readback.get("consistency")
        if consistency is not None:
            if not isinstance(consistency, str) or consistency not in cls.VALID_CONSISTENCY_VALUES:
                closest = cls._find_closest_match(
                    str(consistency).lower(), cls.VALID_CONSISTENCY_VALUES
                )
                suggestion = f"Did you mean '{closest}'?" if closest else None
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.consistency",
                        message=f"Invalid readback consistency '{consistency}'",
                        expected=f"one of {list(cls.VALID_CONSISTENCY_VALUES)}",
                        actual=safe_diagnostic_value(consistency),
                        suggestion=suggestion,
                    )
                )

        # readback_attempts (int in [1, 10], not bool)
        attempts = readback.get("readback_attempts")
        if attempts is not None:
            if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1 or attempts > 10:
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.readback_attempts",
                        message="readback_attempts must be an integer between 1 and 10",
                        expected="integer in range [1, 10]",
                        actual=safe_diagnostic_value(attempts),
                    )
                )

        # readback_delay (float or int in [0.0, 5.0], not bool, finite)
        delay = readback.get("readback_delay")
        if delay is not None:
            if (
                not isinstance(delay, (int, float))
                or isinstance(delay, bool)
                or math.isnan(delay)
                or math.isinf(delay)
                or delay < 0.0
                or delay > 5.0
            ):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.readback_delay",
                        message="readback_delay must be a finite number between 0.0 and 5.0 seconds",
                        expected="number in range [0.0, 5.0]",
                        actual=safe_diagnostic_value(delay),
                    )
                )

        # snapshot_path
        snapshot_path = readback.get("snapshot_path")
        if snapshot_path is not None:
            if not isinstance(snapshot_path, str):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.snapshot_path",
                        message="snapshot_path must be a string dot/bracket path",
                        expected="string path",
                        actual=safe_diagnostic_value(snapshot_path),
                    )
                )
            else:
                try:
                    parts_sp = path_parts(snapshot_path)
                    parsed_readback_paths.append(parts_sp)
                except ValueError as exc:
                    issues.append(
                        ConfigIssue(
                            path=f"readbacks.{op_key}.snapshot_path",
                            message=f"Invalid snapshot_path expression: {exc}",
                            expected="valid dot/bracket path",
                            actual=safe_diagnostic_value(snapshot_path),
                        )
                    )

        # snapshot_field_map
        snapshot_field_map = readback.get("snapshot_field_map")
        if snapshot_field_map is not None:
            if not isinstance(snapshot_field_map, dict):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.snapshot_field_map",
                        message="snapshot_field_map must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(snapshot_field_map),
                    )
                )
            else:
                for k, v in snapshot_field_map.items():
                    if not isinstance(k, str) or not isinstance(v, str):
                        issues.append(
                            ConfigIssue(
                                path=f"readbacks.{op_key}.snapshot_field_map",
                                message="snapshot_field_map keys and values must be strings",
                                expected="string -> string",
                                actual=f"{safe_diagnostic_value(k)} -> {safe_diagnostic_value(v)}",
                            )
                        )
                    else:
                        for p in (k, v):
                            try:
                                path_parts(p)
                            except ValueError as exc:
                                issues.append(
                                    ConfigIssue(
                                        path=f"readbacks.{op_key}.snapshot_field_map",
                                        message=f"Invalid path in snapshot_field_map: {exc}",
                                        expected="valid dot/bracket path",
                                        actual=safe_diagnostic_value(p),
                                    )
                                )
                        try:
                            parsed_written_paths.append(path_parts(k))
                            parsed_readback_paths.append(path_parts(v))
                        except ValueError:
                            pass

        # baseline_payload
        baseline_payload = readback.get("baseline_payload")
        if baseline_payload is not None and not isinstance(baseline_payload, dict):
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.baseline_payload",
                    message="baseline_payload must be an object",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(baseline_payload),
                )
            )

        # ignore_readback_paths & collision check with written and readback fields (parent, child, exact)
        ignored_paths = readback.get("ignore_readback_paths")
        if ignored_paths is not None:
            if not isinstance(ignored_paths, list) or any(not isinstance(p, str) for p in ignored_paths):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.ignore_readback_paths",
                        message="ignore_readback_paths must be a list of field path strings",
                        expected="list of strings",
                        actual=safe_diagnostic_value(ignored_paths),
                    )
                )
            else:
                for ignored in ignored_paths:
                    try:
                        ig_parts = path_parts(ignored)
                    except ValueError as exc:
                        issues.append(
                            ConfigIssue(
                                path=f"readbacks.{op_key}.ignore_readback_paths",
                                message=f"Invalid path in ignore_readback_paths: {exc}",
                                expected="valid dot/bracket path",
                                actual=safe_diagnostic_value(ignored),
                            )
                        )
                        continue

                    # Collision: ignored path cannot match, be a parent of, or be a child of any written field
                    for w_parts in parsed_written_paths:
                        if paths_collide(ig_parts, w_parts):
                            w_str = ".".join(str(p) for p in w_parts)
                            issues.append(
                                ConfigIssue(
                                    path=f"readbacks.{op_key}.ignore_readback_paths",
                                    message=f"Dangerous ignore_readback_paths entry '{ignored}' collides with written field '{w_str}' in field_map",
                                    expected="only non-written volatile fields (e.g. 'updatedAt')",
                                    actual=f"written field or its parent/child path '{ignored}' is ignored",
                                    suggestion="Never ignore written probe fields or their parent/child paths during rollback verification",
                                )
                            )
                    # Collision: ignored path cannot match, be a parent of, or be a child of any readback field
                    for r_parts in parsed_readback_paths:
                        if paths_collide(ig_parts, r_parts):
                            r_str = ".".join(str(p) for p in r_parts)
                            issues.append(
                                ConfigIssue(
                                    path=f"readbacks.{op_key}.ignore_readback_paths",
                                    message=f"Dangerous ignore_readback_paths entry '{ignored}' collides with readback field '{r_str}' in field_map",
                                    expected="only non-written volatile fields (e.g. 'updatedAt')",
                                    actual=f"readback field or its parent/child path '{ignored}' is ignored",
                                    suggestion="Never ignore readback target fields or their parent/child paths during rollback verification",
                                )
                            )

    @classmethod
    def _validate_parameter_values_section(
        cls,
        parameter_values: Any,
        issues: List[ConfigIssue],
        summary: ValidationSummary,
    ) -> None:
        if not isinstance(parameter_values, dict):
            issues.append(
                ConfigIssue(
                    path="parameter_values",
                    message="'parameter_values' must be an object indexed by 'METHOD /path'",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(parameter_values),
                )
            )
            return

        for ep_key, values in parameter_values.items():
            is_valid, method, path, canonical, err_msg = parse_operation_key(ep_key)
            if not is_valid:
                issues.append(
                    ConfigIssue(
                        path=f"parameter_values.{ep_key}",
                        message=f"Invalid operation key in parameter_values: {err_msg}",
                        expected="'METHOD /path' (e.g. 'GET /api/users/{id}')",
                        actual=safe_diagnostic_value(ep_key),
                    )
                )
            if not isinstance(values, dict):
                issues.append(
                    ConfigIssue(
                        path=f"parameter_values.{ep_key}",
                        message=f"Parameter values for '{ep_key}' must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(values),
                    )
                )
            else:
                summary.parameter_endpoints += 1
                for k, v in values.items():
                    if not isinstance(k, str) or not k.strip():
                        issues.append(
                            ConfigIssue(
                                path=f"parameter_values.{ep_key}",
                                message="Parameter names must be non-empty strings",
                                expected="non-empty string key",
                                actual=safe_diagnostic_value(k),
                            )
                        )

    @classmethod
    def _validate_bola_section(
        cls,
        bola: Any,
        issues: List[ConfigIssue],
        summary: ValidationSummary,
    ) -> None:
        if not isinstance(bola, dict):
            issues.append(
                ConfigIssue(
                    path="bola",
                    message="'bola' section must be an object indexed by 'METHOD /path'",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(bola),
                )
            )
            return

        for ep_key, policy in bola.items():
            is_valid, method, path, canonical, err_msg = parse_operation_key(ep_key)
            if not is_valid:
                issues.append(
                    ConfigIssue(
                        path=f"bola.{ep_key}",
                        message=f"Invalid operation key in bola section: {err_msg}",
                        expected="'METHOD /path' (e.g. 'GET /records/{id}')",
                        actual=safe_diagnostic_value(ep_key),
                    )
                )

            if not isinstance(policy, dict):
                issues.append(
                    ConfigIssue(
                        path=f"bola.{ep_key}",
                        message=f"BOLA policy for '{ep_key}' must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(policy),
                    )
                )
                continue

            summary.bola_policies_count += 1
            for p_key in policy.keys():
                if p_key not in cls.KNOWN_BOLA_KEYS:
                    closest = cls._find_closest_match(str(p_key), sorted(cls.KNOWN_BOLA_KEYS))
                    suggestion = f"Did you mean '{closest}'?" if closest else None
                    issues.append(
                        ConfigIssue(
                            path=f"bola.{ep_key}.{p_key}",
                            message=f"Unrecognized BOLA policy setting '{p_key}'",
                            expected=f"one of {sorted(cls.KNOWN_BOLA_KEYS)}",
                            actual=safe_diagnostic_value(p_key),
                            suggestion=suggestion,
                        )
                    )

            if "expected_public" in policy and not isinstance(policy["expected_public"], bool):
                issues.append(
                    ConfigIssue(
                        path=f"bola.{ep_key}.expected_public",
                        message="'expected_public' must be a boolean",
                        expected="boolean",
                        actual=safe_diagnostic_value(policy["expected_public"]),
                    )
                )

            if "resource_id_paths" in policy:
                paths = policy["resource_id_paths"]
                if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths):
                    issues.append(
                        ConfigIssue(
                            path=f"bola.{ep_key}.resource_id_paths",
                            message="'resource_id_paths' must be a list of string field paths",
                            expected="list of strings",
                            actual=safe_diagnostic_value(paths),
                        )
                    )
                else:
                    for p in paths:
                        try:
                            path_parts(p)
                        except ValueError as exc:
                            issues.append(
                                ConfigIssue(
                                    path=f"bola.{ep_key}.resource_id_paths",
                                    message=f"Invalid path expression in resource_id_paths: {exc}",
                                    expected="valid dot/bracket path",
                                    actual=safe_diagnostic_value(p),
                                )
                            )
