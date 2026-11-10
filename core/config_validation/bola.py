"""Validation of the BOLA and BOPLA policy sections."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

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

            if "not_found_is_denial" in policy and not isinstance(policy["not_found_is_denial"], bool):
                issues.append(
                    ConfigIssue(
                        path=f"bola.{ep_key}.not_found_is_denial",
                        message="'not_found_is_denial' must be a boolean",
                        expected="boolean (defaults to false)",
                        actual=safe_diagnostic_value(policy["not_found_is_denial"]),
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

            cls._validate_read_only_post(ep_key, is_valid, method, policy, issues)

            if "detect_sensitive_exposure" in policy and not isinstance(policy["detect_sensitive_exposure"], bool):
                issues.append(
                    ConfigIssue(
                        path=f"bola.{ep_key}.detect_sensitive_exposure",
                        message="'detect_sensitive_exposure' must be a boolean",
                        expected="boolean",
                        actual=safe_diagnostic_value(policy["detect_sensitive_exposure"]),
                    )
                )

    # Request bodies are operator selectors sent to a live target: keep them
    # small, finite JSON. Diagnostics never echo a body value.
    MAX_POST_BODY_BYTES = 65536
    MAX_POST_BODY_DEPTH = 32
    POST_BODY_KEYS = ("body", "identity_bodies")
    IDENTITY_BODY_KEYS = ("owner", "visitor_self")

    @classmethod
    def _payload_problem(cls, value: Any) -> Optional[str]:
        if value is None:
            return "null is not a request body"
        try:
            encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError, RecursionError):
            return "not finite, JSON-serializable data"
        if len(encoded.encode("utf-8")) > cls.MAX_POST_BODY_BYTES:
            return f"larger than {cls.MAX_POST_BODY_BYTES} bytes"
        stack = [(value, 1)]
        while stack:
            item, depth = stack.pop()
            if depth > cls.MAX_POST_BODY_DEPTH:
                return f"nested deeper than {cls.MAX_POST_BODY_DEPTH} levels"
            children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
            stack.extend((child, depth + 1) for child in children)
        return None

    @classmethod
    def _validate_read_only_post(
        cls, ep_key: Any, is_valid: bool, method: str, policy: Dict[str, Any], issues: List[ConfigIssue],
    ) -> None:
        """A POST is audited only when declared read-only with an explicit body.

        Bodies apply to POST alone: a GET never carries one. ``body`` is sent
        verbatim by every identity; ``identity_bodies`` names the Owner's
        object (``owner``) and optionally the Visitor's own (``visitor_self``).
        """
        configured = [key for key in ("read_only", *cls.POST_BODY_KEYS) if key in policy]
        if is_valid and method != "POST":
            for key in configured:
                issues.append(ConfigIssue(
                    path=f"bola.{ep_key}.{key}",
                    message=f"'{key}' applies to read-only POST operations only; no request body is ever sent with {method}",
                    expected="remove this setting, or use it on a POST operation",
                    actual=f"'{key}' on a {method} operation",
                ))
            return
        if "read_only" in policy and not isinstance(policy["read_only"], bool):
            issues.append(ConfigIssue(
                path=f"bola.{ep_key}.read_only",
                message="'read_only' must be a boolean",
                expected="true to allow the read-only POST audit",
                actual=safe_diagnostic_value(policy["read_only"]),
            ))
        if "body" in policy and "identity_bodies" in policy:
            issues.append(ConfigIssue(
                path=f"bola.{ep_key}",
                message="Use either 'body' or 'identity_bodies', not both",
                expected="one request body source",
                actual="both 'body' and 'identity_bodies'",
            ))
        if "body" in policy:
            problem = cls._payload_problem(policy["body"])
            if problem:
                issues.append(ConfigIssue(
                    path=f"bola.{ep_key}.body",
                    message=f"'body' must be the literal JSON request payload; it is {problem}",
                    expected="JSON object, array, string or number sent unchanged by every identity",
                    actual="invalid request body (value not shown)",
                ))
        if "identity_bodies" in policy:
            bodies = policy["identity_bodies"]
            if not isinstance(bodies, dict):
                issues.append(ConfigIssue(
                    path=f"bola.{ep_key}.identity_bodies",
                    message="'identity_bodies' must be an object with 'owner' and optional 'visitor_self'",
                    expected="{\"owner\": <body>, \"visitor_self\": <body>}",
                    actual=safe_diagnostic_value(type(bodies).__name__),
                ))
            else:
                for key in bodies:
                    if key not in cls.IDENTITY_BODY_KEYS:
                        issues.append(ConfigIssue(
                            path=f"bola.{ep_key}.identity_bodies.{key}",
                            message=("Unsupported identity body: the Visitor's cross request and Anonymous always "
                                     "repeat the Owner body, so only 'owner' and 'visitor_self' are accepted"),
                            expected="owner or visitor_self",
                            actual=safe_diagnostic_value(key),
                        ))
                if "owner" not in bodies:
                    issues.append(ConfigIssue(
                        path=f"bola.{ep_key}.identity_bodies.owner",
                        message="'identity_bodies' must include the Owner body that selects the Owner's object",
                        expected="owner request body",
                        actual="missing",
                    ))
                for key in cls.IDENTITY_BODY_KEYS:
                    if key in bodies:
                        problem = cls._payload_problem(bodies[key])
                        if problem:
                            issues.append(ConfigIssue(
                                path=f"bola.{ep_key}.identity_bodies.{key}",
                                message=f"Identity body '{key}' must be a JSON request payload; it is {problem}",
                                expected="JSON object, array, string or number",
                                actual="invalid request body (value not shown)",
                            ))
        if not is_valid or method != "POST":
            return
        if policy.get("read_only") is True and not any(key in policy for key in cls.POST_BODY_KEYS):
            issues.append(ConfigIssue(
                path=f"bola.{ep_key}.body",
                message="A read-only POST needs the request body to send; no request is sent without one",
                expected="'body' or 'identity_bodies'",
                actual="missing",
            ))
        if policy.get("read_only") is not True:
            issues.append(ConfigIssue(
                path=f"bola.{ep_key}.read_only",
                message="POST operation in BOLA policy is skipped unless it declares 'read_only: true'; declare it only for operations without side effects",
                expected="read_only: true",
                actual=safe_diagnostic_value(policy.get("read_only")),
                suggestion="Add '\"read_only\": true' only after confirming this POST changes no state",
                is_warning=True,
            ))
