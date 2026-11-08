"""Validation of the identities section: credentials, ids and their isolation."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from core.config_validation.base import ConfigIssue, ValidationSummary, ValidatorBase
from core.evidence import safe_diagnostic_value


class IdentityChecks(ValidatorBase):
    """Owner, visitor and anonymous identities and their authentication material."""

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
            if identity_name == "roles":
                if not isinstance(identity_data, dict):
                    issues.append(
                        ConfigIssue(
                            path="identities.roles",
                            message="'identities.roles' must be an object of roles",
                            expected="dict / JSON object",
                            actual=safe_diagnostic_value(identity_data),
                        )
                    )
                else:
                    for role_name, role_info in identity_data.items():
                        if not isinstance(role_info, dict):
                            issues.append(
                                ConfigIssue(
                                    path=f"identities.roles.{role_name}",
                                    message=f"Role '{role_name}' must be an object",
                                    expected="dict / JSON object",
                                    actual=safe_diagnostic_value(role_info),
                                )
                            )
                continue
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
