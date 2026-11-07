"""Validation of the BOLA and BOPLA policy sections."""

from __future__ import annotations

from typing import Any, List

from core.bopla import validate_bopla_policy
from core.config_validation.base import ConfigIssue, ValidationSummary, ValidatorBase
from core.evidence import safe_diagnostic_value
from core.models import parse_operation_key
from core.transactions import path_parts


class BolaChecks(ValidatorBase):
    """Object- and property-level authorization policies."""

    @staticmethod
    def _validate_bopla_section(
        bopla: Any, issues: List[ConfigIssue], summary: ValidationSummary,
    ) -> None:
        # Use positional diagnostic paths: operation names, rule IDs, field
        # paths and binding values may themselves contain private data.
        if not isinstance(bopla, dict):
            issues.append(ConfigIssue(
                path="bopla", message="BOPLA policies must be an operation map",
                expected="object indexed by GET operation keys", actual="invalid BOPLA section",
            ))
            return
        for index, (operation, policy) in enumerate(bopla.items()):
            valid, method, _, _, _ = parse_operation_key(operation)
            if not valid or method != "GET":
                issues.append(ConfigIssue(
                    path=f"bopla[{index}]", message="BOPLA supports exact GET operation keys only",
                    expected="GET /case-sensitive-path", actual="invalid BOPLA operation key",
                ))
            errors = validate_bopla_policy(policy)
            for error in errors:
                issues.append(ConfigIssue(
                    path=f"bopla[{index}]", message=error,
                    expected="explicit BOPLA field rules and selected-resource bindings",
                    actual="invalid BOPLA policy",
                ))
            if valid and method == "GET" and not errors:
                summary.bopla_policies_count += 1

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

            if "expected_visitor_access" in policy and policy["expected_visitor_access"] not in ("allow", "deny"):
                issues.append(
                    ConfigIssue(
                        path=f"bola.{ep_key}.expected_visitor_access",
                        message="'expected_visitor_access' must explicitly be 'allow' or 'deny'",
                        expected="allow or deny (defaults to deny)",
                        actual=safe_diagnostic_value(policy["expected_visitor_access"]),
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
                            # BOLA evidence paths support array wildcards. Use a
                            # representative index for syntax validation only.
                            path_parts(p.replace("[]", "[0]"))
                        except ValueError as exc:
                            issues.append(
                                ConfigIssue(
                                    path=f"bola.{ep_key}.resource_id_paths",
                                    message=f"Invalid path expression in resource_id_paths: {exc}",
                                    expected="valid dot/bracket path",
                                    actual=safe_diagnostic_value(p),
                                )
                            )

            if "private_data_paths" in policy:
                private_paths = policy["private_data_paths"]
                if not isinstance(private_paths, list) or any(not isinstance(p, str) for p in private_paths):
                    issues.append(
                        ConfigIssue(
                            path=f"bola.{ep_key}.private_data_paths",
                            message="'private_data_paths' must be a list of exact Owner-private scalar field paths",
                            expected="list of dot/bracket paths, e.g. items[0].private_note",
                            actual=safe_diagnostic_value(private_paths),
                        )
                    )
                else:
                    for private_path in private_paths:
                        try:
                            if private_path != private_path.strip():
                                raise ValueError("leading or trailing whitespace is unsupported")
                            path_parts(private_path)
                        except ValueError as exc:
                            issues.append(
                                ConfigIssue(
                                    path=f"bola.{ep_key}.private_data_paths",
                                    message=f"Invalid path expression in private_data_paths: {exc}",
                                    expected="exact dot/bracket path with numeric array indexes; no wildcards",
                                    actual=safe_diagnostic_value(private_path),
                                )
                            )

            for role_key in ("required_role", "owner_role", "visitor_role"):
                if role_key not in policy:
                    continue
                role = policy[role_key]
                if (not isinstance(role, str) or not role or role != role.strip()
                        or any(ord(char) < 32 or ord(char) == 127 for char in role)):
                    issues.append(
                        ConfigIssue(
                            path=f"bola.{ep_key}.{role_key}",
                            message=f"'{role_key}' must be an explicit nonempty role name without control characters",
                            expected="nonempty string with no surrounding whitespace or control characters",
                            actual=safe_diagnostic_value(role),
                        )
                    )
