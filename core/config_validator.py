# -*- coding: utf-8 -*-
"""Authoritative configuration validation engine for GrantTrace.

Provides offline, comprehensive semantic validation for GrantTrace configuration
files. Reuses the exact security rules and constraints enforced by the auditor
and transaction managers without requiring external dependencies like jsonschema.

ConfigValidator combines the section checks in core.config_validation; import
it and its result types from here.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.config_validation.base import ConfigIssue, ConfigValidationResult, ValidationSummary
from core.config_validation.bola import BolaChecks
from core.config_validation.identities import IdentityChecks
from core.config_validation.readbacks import ReadbackChecks
from core.config_validation.spec_checks import SpecChecks
from core.evidence import safe_diagnostic_value
from core.remote_refs import RemoteRefConfig, RemoteRefOfflineBlockedError

__all__ = ["ConfigIssue", "ConfigValidationResult", "ConfigValidator", "ValidationSummary"]


class ConfigValidator(SpecChecks, IdentityChecks, ReadbackChecks, BolaChecks):
    """Authoritative semantic validator for GrantTrace configuration objects."""

    @classmethod
    def validate(
        cls, config: Any, raw_spec: Optional[Dict[str, Any]] = None, *, spec_path: Optional[str] = None, remote_ref_config: Optional[RemoteRefConfig] = None, offline: bool = True, allow_offline_unresolved: bool = False,
    ) -> ConfigValidationResult:
        """Validate a loaded configuration mapping and collect all issues without early exit."""
        issues: List[ConfigIssue] = []
        summary = ValidationSummary()

        root_issue = cls._root_issue(config)
        if root_issue is not None:
            return cls._result([root_issue], summary)
        cls._check_numbers(config, issues)
        cls._check_top_level_keys(config, issues)

        spec_auth_names = cls._spec_auth_header_names(
            raw_spec, issues, spec_path=spec_path, remote_ref_config=remote_ref_config,
            offline=offline, allow_offline_unresolved=allow_offline_unresolved,
        )
        allowlisted_set: Set[str] = set()
        readbacks_set: Set[str] = set()
        cls._run_section(config, "identities", "valid identities object", issues, lambda value: (
            cls._validate_identities_section(value, issues, summary, spec_auth_names=spec_auth_names)))
        cls._run_section(config, "write_allowlist", "list of strings", issues, lambda value: (
            cls._validate_write_allowlist_section(value, issues, summary, allowlisted_set)))
        cls._run_section(
            config, "readbacks", "dict mapping operation keys to readback configurations", issues,
            lambda value: cls._validate_readbacks_section(value, issues, summary, readbacks_set))
        cls._check_allowlisted_readbacks(allowlisted_set, readbacks_set, issues)
        cls._run_section(config, "parameter_values", "dict indexed by operation keys", issues, lambda value: (
            cls._validate_parameter_values_section(value, issues, summary)))
        cls._run_section(config, "bola", "dict indexed by operation keys", issues, lambda value: (
            cls._validate_bola_section(value, issues, summary)))
        if "bopla" in config:
            cls._validate_bopla_section(config["bopla"], issues, summary)

        checked_parameters: Set[Tuple[str, str]] = set()
        cls._validate_configured_readback_parameters(config, issues, checked_parameters)
        if raw_spec is not None:
            cls._validate_spec_cross_checks(config, raw_spec, issues, spec_path=spec_path, seen=checked_parameters, remote_ref_config=remote_ref_config, offline=offline, allow_offline_unresolved=allow_offline_unresolved)
        return cls._result(issues, summary)

    @staticmethod
    def _result(issues: List[ConfigIssue], summary: ValidationSummary) -> ConfigValidationResult:
        errors = [issue for issue in issues if not issue.is_warning]
        summary.total_issues = len(issues)
        summary.errors_count = len(errors)
        summary.warnings_count = len(issues) - len(errors)
        return ConfigValidationResult(is_valid=(len(errors) == 0), issues=issues, summary=summary)

    @classmethod
    def _root_issue(cls, config: Any) -> Optional[ConfigIssue]:
        """The issue that stops validation before any section: a non-object or too deep root."""
        if not isinstance(config, dict):
            return ConfigIssue(
                path="<root>",
                message="Configuration root must be a JSON object",
                expected="dict / JSON object",
                actual=safe_diagnostic_value(config),
            )
        # Defend against malicious or circular payloads before walking them.
        if not cls._check_depth(config, 0, cls.MAX_RECURSION_DEPTH):
            return ConfigIssue(
                path="<root>",
                message=f"Configuration nesting exceeds maximum supported depth of {cls.MAX_RECURSION_DEPTH}",
                expected=f"depth <= {cls.MAX_RECURSION_DEPTH}",
                actual="excessive nesting",
            )
        return None

    @classmethod
    def _check_numbers(cls, config: Dict[str, Any], issues: List[ConfigIssue]) -> None:
        """Reject NaN and Infinity outside the bopla section."""
        try:
            # BOPLA diagnostics never echo policy keys or binding values. Its
            # dedicated validator checks finite numbers without interpolating input.
            cls._check_no_nan_or_inf({key: value for key, value in config.items() if key != "bopla"}, "", issues)
        except Exception as exc:
            issues.append(
                ConfigIssue(
                    path="<root>",
                    message=f"Error inspecting numeric values: {exc}",
                    expected="valid JSON values",
                    actual=safe_diagnostic_value(type(exc).__name__),
                )
            )

    @classmethod
    def _check_top_level_keys(cls, config: Dict[str, Any], issues: List[ConfigIssue]) -> None:
        """Unrecognized keys with typo hints, and the $schema and description strings."""
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

    @classmethod
    def _spec_auth_header_names(
        cls, raw_spec: Optional[Dict[str, Any]], issues: List[ConfigIssue], *, spec_path: Optional[str],
        remote_ref_config: Optional[RemoteRefConfig], offline: bool, allow_offline_unresolved: bool,
    ) -> Set[str]:
        """The specification's authentication header names; an empty set and an issue on failure."""
        try:
            return cls._extract_spec_auth_headers(
                raw_spec,
                spec_path=spec_path,
                remote_ref_config=remote_ref_config,
                offline=offline,
            )
        except RemoteRefOfflineBlockedError as exc:
            issues.append(ConfigIssue(
                path="<spec>.securitySchemes",
                message=f"Specification contains remote security scheme $ref which cannot be fetched in offline validation mode: {exc}",
                expected="locally resolvable security schemes without remote network requests",
                actual="unresolved_reference",
                suggestion="Provide a locally resolvable specification or run an online scan with --allow-remote-refs",
                is_warning=allow_offline_unresolved,
            ))
        except (TypeError, ValueError) as exc:
            issues.append(ConfigIssue(
                path="<spec>.securitySchemes",
                message=f"Invalid specification authentication definitions: {exc}",
                expected="object-valued securityDefinitions, components, and securitySchemes",
                actual="malformed specification structure",
            ))
        return set()

    @staticmethod
    def _run_section(
        config: Dict[str, Any], key: str, expected: str, issues: List[ConfigIssue], check: Callable[[Any], None],
    ) -> None:
        """Run one section's checks when present; an unexpected failure becomes an issue."""
        if key not in config:
            return
        try:
            check(config[key])
        except Exception as exc:
            issues.append(
                ConfigIssue(
                    path=key,
                    message=f"Validation failed on {key} section: {exc}",
                    expected=expected,
                    actual=safe_diagnostic_value(type(exc).__name__),
                )
            )

    @staticmethod
    def _check_allowlisted_readbacks(
        allowlisted: Set[str], readbacks: Set[str], issues: List[ConfigIssue],
    ) -> None:
        """Every write_allowlist operation needs a readback, even when 'readbacks' is absent."""
        for missing_op in sorted(allowlisted - readbacks):
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{missing_op}",
                    message=f"Operation '{missing_op}' is in write_allowlist but missing an independent GET readback mapping",
                    expected=f"an entry in 'readbacks' for '{missing_op}'",
                    actual="missing",
                    suggestion=f"Define readback mapping under 'readbacks' for '{missing_op}' with method 'GET' and field_map",
                )
            )
