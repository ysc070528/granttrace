"""Read-only property authorization with explicit, resource-bound business rules.

Rules describe one selected resource and identity context. Neither field names,
OpenAPI readOnly, public object access nor response differences infer a rule.
Raw values stay in memory; evidence records paths and booleans only.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from core.authorization import AuthorizationEvidence
from core.models import HTTPResult, Verdict, json_values_equal
from core.transactions import get_path, path_parts, paths_collide


def _scalar(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value))


def _path(value: Any) -> Tuple[Any, ...]:
    if (not isinstance(value, str) or value != value.strip() or "*" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("invalid exact path")
    return path_parts(value)


def validate_bopla_policy(policy: Any) -> List[str]:
    """Return fixed diagnostics, never interpolating policy paths or values."""
    if not isinstance(policy, dict):
        return ["BOPLA policy must be an object"]
    errors = []
    if set(policy) - {"policy_id", "context_id", "resource_binding", "fields"}:
        errors.append("Unknown BOPLA policy setting")
    if not all(_identifier(policy.get(key)) for key in ("policy_id", "context_id")):
        errors.append("Policy and context identifiers must be explicit safe identifiers")
    bindings = policy.get("resource_binding")
    binding_parts = []
    if not isinstance(bindings, dict) or not bindings:
        errors.append("Resource binding must contain selected exact paths and scalar values")
    else:
        for path, value in bindings.items():
            try:
                parts = _path(path)
                if not isinstance(parts[-1], str) or not _scalar(value):
                    raise ValueError("invalid binding value")
                binding_parts.append(parts)
            except (TypeError, ValueError, OverflowError):
                errors.append("Resource binding requires exact paths and finite nonempty scalar values")
    fields = policy.get("fields")
    if not isinstance(fields, list) or not fields:
        return errors + ["Fields must be a nonempty list of explicit property rules"]
    seen_ids = set()
    seen_paths: List[Tuple[Any, ...]] = []
    for rule in fields:
        if not isinstance(rule, dict):
            errors.append("Each field rule must be an object")
            continue
        if set(rule) - {"rule_id", "path", "baseline_representation", "value_is_resource_specific", "access"}:
            errors.append("Unknown field rule setting")
        if not _identifier(rule.get("rule_id")) or rule.get("rule_id") in seen_ids:
            errors.append("Field rule identifiers must be unique safe identifiers")
        elif isinstance(rule["rule_id"], str):
            seen_ids.add(rule["rule_id"])
        try:
            parts = _path(rule.get("path"))
            if any(paths_collide(parts, previous) for previous in (*seen_paths, *binding_parts)):
                errors.append("Field paths must not overlap other rules or resource bindings")
            seen_paths.append(parts)
            for index, part in enumerate(parts):
                if isinstance(part, int):
                    entry = parts[:index + 1]
                    if not any(bound[:len(entry)] == entry and len(bound) > len(entry) for bound in binding_parts):
                        errors.append("Every selected array entry requires an exact same-entry resource binding")
        except (TypeError, ValueError):
            errors.append("Field paths must be exact dot/bracket paths with fixed numeric array indexes")
        access = rule.get("access")
        if (not isinstance(access, dict) or set(access) - {"owner", "visitor", "anonymous"}
                or access.get("owner") != "allow"
                or any(value not in ("allow", "deny") for value in access.values())):
            errors.append("Access requires an allowed Owner and explicit allow or deny for configured identities")
        if "baseline_representation" in rule and rule["baseline_representation"] != "full_private_value":
            errors.append("Only a declared complete private baseline representation is supported")
        if "value_is_resource_specific" in rule and not isinstance(rule["value_is_resource_specific"], bool):
            errors.append("Resource-specific value declaration must be a boolean")
    return list(dict.fromkeys(errors))


def confirmation_supported(evidence: Mapping[str, Any]) -> bool:
    """Output consumers must not promote incomplete/legacy evidence to BOPLA."""
    path = evidence.get("field_path")
    return bool(
        all(_identifier(evidence.get(key)) for key in ("policy_id", "context_id", "rule_id"))
        and isinstance(path, str) and path
        and evidence.get("subject_identity") in ("visitor", "anonymous")
        and evidence.get("field_access") == "deny"
        and evidence.get("owner_baseline_valid") is True
        and evidence.get("resource_bound") is True
        and evidence.get("private_value_identifiable") is True
        and evidence.get("other_response_valid") is True
        and evidence.get("matched_private_data_paths") == [path]
        and not evidence.get("missing_evidence")
    )


class BOPLAEvidence:
    """Pure evaluation of existing GET observations; never sends a request."""

    @staticmethod
    def _assess(result: HTTPResult) -> Dict[str, Any]:
        assessment = AuthorizationEvidence._assess(result)
        if 200 <= result.status < 300 and result.status != 200:
            assessment["complete"] = False
        # A nominal 200 with a partial representation is not a complete baseline.
        if any(key.lower() == "content-range" for key in result.headers):
            assessment["complete"] = False

        def unique_object(pairs):
            document = {}
            for key, value in pairs:
                if key in document:
                    raise ValueError("ambiguous JSON object")
                document[key] = value
            return document

        try:
            json.loads(result.body, object_pairs_hook=unique_object)
        except (TypeError, ValueError, RecursionError):
            assessment["complete"] = False
        return assessment

    @staticmethod
    def _bound(data: Any, bindings: Mapping[str, Any]) -> bool:
        for path, expected in bindings.items():
            parts = _path(path)
            found, value = get_path(data, parts)
            if not found or not json_values_equal(expected, value):
                return False
            # Duplicate identities in a selected array cannot locate one entity.
            for offset, part in enumerate(parts):
                if isinstance(part, int):
                    exists, entries = get_path(data, parts[:offset]) if offset else (True, data)
                    if not exists or not isinstance(entries, list):
                        return False
                    matches = 0
                    for entry in entries:
                        exists, candidate = get_path(entry, parts[offset + 1:])
                        if exists and json_values_equal(candidate, expected):
                            matches += 1
                    if matches != 1:
                        return False
        return True

    @staticmethod
    def _identifiable(value: Any) -> bool:
        if not _scalar(value):
            return False
        if isinstance(value, str):
            # Known lossy representations cannot substantiate a full-value claim.
            lowered = value.strip().lower()
            return ("*" not in value and lowered not in {"[redacted]", "[masked]", "redacted", "masked"})
        return True

    @classmethod
    def evaluate(
        cls, owner: HTTPResult, other: HTTPResult, *, policy: Mapping[str, Any],
        field: Mapping[str, Any], identity: str, visitor_self: Optional[HTTPResult] = None,
    ) -> Dict[str, Any]:
        """Compare one explicitly selected field and identity, with no inference."""
        evidence: Dict[str, Any] = {
            "owner_baseline_valid": False, "resource_bound": False, "resource_binding_valid": False,
            "private_value_identifiable": False, "other_response_valid": False,
            "denial_body_clean": False, "comparison_valid": False,
            "matched_private_data_paths": [], "owner_private_data_paths": [], "missing_evidence": [],
        }

        def result(verdict: Verdict, reason: str, missing: Optional[str] = None) -> Dict[str, Any]:
            if missing:
                evidence["missing_evidence"].append(missing)
            return {"verdict": verdict, "reason": reason, "evidence": evidence}

        if validate_bopla_policy(policy) or field not in policy.get("fields", ()):
            return result(Verdict.INCONCLUSIVE, "Field authorization policy is invalid", "valid_field_policy")
        evidence.update({"policy_id": policy["policy_id"], "context_id": policy["context_id"],
                         "rule_id": field["rule_id"], "field_path": field["path"],
                         "subject_identity": identity, "field_access": field["access"].get(identity),
                         "policy_scope": "Selected operation, resource, identity context and exact field only"})
        permission = field["access"].get(identity)
        if identity not in ("visitor", "anonymous") or permission not in ("allow", "deny"):
            return result(Verdict.INCONCLUSIVE, "No explicit field permission exists for this identity", "identity_field_permission")
        own, low = cls._assess(owner), cls._assess(other)
        own_valid = AuthorizationEvidence._valid(own)
        evidence["owner_baseline_valid"] = own_valid
        if not own_valid:
            return result(Verdict.INCONCLUSIVE, "A complete valid Owner baseline is required", "owner_baseline")
        bindings = policy["resource_binding"]
        if not cls._bound(own["data"], bindings):
            return result(Verdict.INCONCLUSIVE, "Owner baseline does not identify the selected resource", "owner_resource_binding")
        path = field["path"]
        values = AuthorizationEvidence._private_values(own["data"], (path,))
        value = values.get(path)
        identifiable = path in values and cls._identifiable(value)
        if permission == "deny":
            identifiable = bool(identifiable and field.get("baseline_representation") == "full_private_value"
                                and field.get("value_is_resource_specific") is True)
        evidence["private_value_identifiable"] = identifiable
        if not identifiable:
            return result(Verdict.INCONCLUSIVE, "A declared identifiable complete private baseline is required", "identifiable_private_baseline")
        evidence["owner_private_data_paths"] = [path]
        if visitor_self is not None and identity == "visitor":
            self_assessment = cls._assess(visitor_self)
            if not AuthorizationEvidence._valid(self_assessment):
                return result(Verdict.INCONCLUSIVE, "Visitor self baseline is not valid", "visitor_self_baseline")
            self_values = AuthorizationEvidence._private_values(self_assessment["data"], (path,))
            if path in self_values and json_values_equal(value, self_values[path]):
                return result(Verdict.INCONCLUSIVE, "Value also occurs in Visitor self data and cannot identify Owner data", "resource_specific_value")
        if not low["complete"]:
            return result(Verdict.INCONCLUSIVE, "The comparison response is incomplete or failed transport", "complete_other_response")
        clean = AuthorizationEvidence._clean_denial(low, other)
        evidence["denial_body_clean"] = clean
        if clean:
            evidence["comparison_valid"] = True
            if permission == "deny":
                return result(Verdict.SECURE, "This exact field rule, identity and selected resource received a clean denial")
            return result(Verdict.INCONCLUSIVE, "Field access was denied despite an explicit allow rule", "positive_allowed_field_access")
        other_values = AuthorizationEvidence._private_values(low["data"], (path,))
        matched = path in other_values and json_values_equal(value, other_values[path])
        if matched:
            evidence["matched_private_data_paths"] = [path]
        low_valid = AuthorizationEvidence._valid(low)
        evidence["other_response_valid"] = low_valid
        if matched and not low_valid and permission == "deny":
            return result(Verdict.SUSPICIOUS, "An error or denial body contains matching protected data; valid field access is unproven")
        if not low_valid:
            return result(Verdict.INCONCLUSIVE, "A complete valid data response or clean denial is required", "valid_other_response")
        bound = cls._bound(low["data"], bindings)
        evidence["resource_bound"] = bound
        evidence["resource_binding_valid"] = bound
        if not bound:
            return result(Verdict.INCONCLUSIVE, "Response does not identify the selected resource and context", "other_resource_binding")
        evidence["comparison_valid"] = True
        if not matched:
            return result(Verdict.INCONCLUSIVE, "Missing, different, transformed or masked field data does not prove full-value disclosure or safety", "exact_private_value_match")
        if permission == "allow":
            return result(Verdict.AUTHORIZED, "Observed exact field access matches this identity's explicit allow rule")
        return result(Verdict.CONFIRMED, "Identity denied this exact field received identifiable Owner-private data on the selected resource")
