# -*- coding: utf-8 -*-
"""Authoritative configuration validation engine for GrantTrace.

Provides offline, comprehensive semantic validation for GrantTrace configuration
files. Reuses the exact security rules and constraints enforced by the auditor
and transaction managers without requiring external dependencies like jsonschema.

ConfigValidator combines the section checks in core.config_validation; import
it and its result types from here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

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
            spec_auth_names = cls._extract_spec_auth_headers(
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
            spec_auth_names = set()
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

        if "bopla" in config:
            cls._validate_bopla_section(config["bopla"], issues, summary)

        checked_parameters: Set[Tuple[str, str]] = set()
        cls._validate_configured_readback_parameters(config, issues, checked_parameters)
        if raw_spec is not None:
            cls._validate_spec_cross_checks(config, raw_spec, issues, spec_path=spec_path, seen=checked_parameters, remote_ref_config=remote_ref_config, offline=offline, allow_offline_unresolved=allow_offline_unresolved)

        errors = [issue for issue in issues if not issue.is_warning]
        summary.total_issues = len(issues)
        summary.errors_count = len(errors)
        summary.warnings_count = len(issues) - len(errors)

        return ConfigValidationResult(
            is_valid=(len(errors) == 0),
            issues=issues,
            summary=summary,
        )
