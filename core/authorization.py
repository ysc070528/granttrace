"""Read-only authorization decisions backed by explicitly configured evidence.

``private_data_paths`` is an operator assertion about the selected Owner data:
values at these paths are private to this Owner and must not be disclosed to
Anonymous. Visitor access is denied by default; an explicit sharing policy or
the explicitly required role may authorize this configured Visitor. A field name, a role keyword,
an HTTP status, and matching public response bodies do not establish that
assertion. These decisions make no claim about authoritative persisted state.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Tuple

from core.diff import ResponseDiffEngine
from core.models import HTTPResult, Verdict, json_values_equal
from core.transactions import get_path, path_parts


class AuthorizationEvidence:
    """Evaluate responses without making requests or changing resource state."""

    @staticmethod
    def _assess(result: HTTPResult) -> Dict[str, Any]:
        assessment = ResponseDiffEngine._assess_response(result.status, result.body)
        assessment["complete"] = not result.error and not result.truncated
        return assessment

    @staticmethod
    def _valid(assessment: Mapping[str, Any]) -> bool:
        return bool(assessment["complete"] and assessment["status_code"] == 200
                    and assessment["kind"] == ResponseDiffEngine.RESPONSE_VALID)

    @staticmethod
    def _clean_denial(assessment: Dict[str, Any], result: HTTPResult) -> bool:
        return bool(assessment["complete"]
                    and assessment["kind"] == ResponseDiffEngine.RESPONSE_AUTH_DENIED
                    and ResponseDiffEngine._denial_body_is_clean(assessment, result.body))

    @staticmethod
    def _private_values(data: Any, paths: Iterable[str]) -> Dict[str, Any]:
        """Use exact approved business paths; never infer ownership from text."""
        values: Dict[str, Any] = {}
        for path in paths:
            if not isinstance(path, str):
                continue
            try:
                parts = path_parts(path)
            except ValueError:
                continue
            if any(isinstance(part, str) and (
                ResponseDiffEngine._is_request_metadata_key(ResponseDiffEngine._normalise_key(part))
                or ResponseDiffEngine._normalise_key(part) in ResponseDiffEngine.NON_RESOURCE_VALUE_KEYS
            ) for part in parts):
                continue
            found, value = get_path(data, parts)
            # Empty values and common boolean flags cannot identify Owner data.
            # An operator must select a concrete nonempty private scalar.
            if found and ((isinstance(value, str) and value.strip()) or type(value) in (int, float)):
                values[path] = value
        return values

    @classmethod
    def _evidence(
        cls, owner: HTTPResult, other: HTTPResult, anonymous: HTTPResult,
        private_data_paths: Iterable[str], other_name: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        owner_assessment = cls._assess(owner)
        other_assessment = cls._assess(other)
        anonymous_assessment = cls._assess(anonymous)
        paths = () if isinstance(private_data_paths, (str, bytes)) else tuple(private_data_paths)
        owner_values = cls._private_values(owner_assessment["data"], paths)
        other_values = cls._private_values(other_assessment["data"], paths)
        matched = sorted(path for path, value in owner_values.items()
                         if path in other_values and json_values_equal(value, other_values[path]))
        evidence: Dict[str, Any] = {
            "policy_scope": "Configured Owner/Visitor/Anonymous identities and selected operation only",
            "private_data_paths": list(paths),
            "owner_private_data_paths": sorted(owner_values),
            "matched_private_data_paths": matched,
            "owner_baseline_valid": cls._valid(owner_assessment),
            "anonymous_denial_body_clean": cls._clean_denial(anonymous_assessment, anonymous),
            "responses": {
                "owner": ResponseDiffEngine._assessment_evidence(owner_assessment),
                other_name: ResponseDiffEngine._assessment_evidence(other_assessment),
                "anonymous": ResponseDiffEngine._assessment_evidence(anonymous_assessment),
            },
            "missing_evidence": [],
        }
        if not cls._valid(owner_assessment):
            evidence["missing_evidence"].append("owner_baseline")
        if not owner_values:
            evidence["missing_evidence"].append("configured_owner_private_data")
        if not matched:
            evidence["missing_evidence"].append("owner_private_data_match")
        return owner_assessment, other_assessment, anonymous_assessment, evidence

    @staticmethod
    def _result(verdict: Verdict, reason: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        return {"verdict": verdict, "reason": reason, "evidence": evidence}

    @classmethod
    def evaluate_auth(
        cls, owner: HTTPResult, anonymous: HTTPResult, *, requires_auth: bool,
        expected_public: bool = False, private_data_paths: Iterable[str] = (),
    ) -> Dict[str, Any]:
        own, anon, _, evidence = cls._evidence(owner, anonymous, anonymous, private_data_paths, "anonymous")
        evidence.update({"requires_auth": requires_auth, "expected_public": expected_public})
        if not own["complete"] or not anon["complete"]:
            return cls._result(Verdict.INCONCLUSIVE, "An authentication response is incomplete or failed transport", evidence)
        if expected_public:
            if evidence["private_data_paths"]:
                return cls._result(Verdict.INCONCLUSIVE, "Public policy conflicts with configured Owner-private data paths", evidence)
            if (not requires_auth and cls._valid(own) and cls._valid(anon)
                    and json_values_equal(own["data"], anon["data"])):
                return cls._result(Verdict.PUBLIC, "Explicit public policy matches complete Owner and Anonymous baselines", evidence)
            return cls._result(Verdict.INCONCLUSIVE, "Public policy lacks equivalent baselines or conflicts with required authentication", evidence)
        if not requires_auth:
            return cls._result(Verdict.INCONCLUSIVE, "No authenticated access requirement establishes an anonymous authorization boundary", evidence)
        if not cls._valid(own):
            return cls._result(Verdict.INCONCLUSIVE, "A valid Owner baseline is required for authentication conclusions", evidence)
        if evidence["anonymous_denial_body_clean"]:
            return cls._result(Verdict.SECURE, "Anonymous access was denied with a clean response and a valid Owner baseline", evidence)
        if evidence["matched_private_data_paths"]:
            if cls._valid(anon):
                return cls._result(Verdict.CONFIRMED, "Anonymous response exposes configured Owner private data on an authenticated operation", evidence)
            return cls._result(Verdict.SUSPICIOUS, "An error or denial response contains matching Owner private values; confirmation requires a valid response", evidence)
        if cls._valid(anon) and not evidence["owner_private_data_paths"]:
            return cls._result(Verdict.SUSPICIOUS, "Anonymous received valid data, but no configured private-data evidence proves sensitive exposure", evidence)
        return cls._result(Verdict.INCONCLUSIVE, "Anonymous response does not establish either clean denial or Owner private-data exposure", evidence)

    @classmethod
    def evaluate_bfla(
        cls, owner: HTTPResult, visitor: HTTPResult, anonymous: HTTPResult, *,
        role_policy: Mapping[str, Any], private_data_paths: Iterable[str] = (), candidate: bool = False,
    ) -> Dict[str, Any]:
        own, vis, anon, evidence = cls._evidence(owner, visitor, anonymous, private_data_paths, "visitor")
        roles = {key: role_policy.get(key) for key in ("required_role", "owner_role", "visitor_role")}
        evidence.update({"role_policy": roles, "privileged_candidate": candidate})
        if role_policy.get("expected_public") is True and (roles["required_role"] or evidence["private_data_paths"]):
            return cls._result(Verdict.INCONCLUSIVE, "Public policy conflicts with the configured privileged role or Owner-private data", evidence)
        if not all(isinstance(value, str) and value.strip() for value in roles.values()):
            evidence["missing_evidence"].append("explicit_privilege_boundary")
            return cls._result(Verdict.SUSPICIOUS if candidate or any(roles.values()) else Verdict.INCONCLUSIVE,
                               "Administrative naming is a candidate only; explicit identity roles and required role are missing", evidence)
        if roles["owner_role"] != roles["required_role"]:
            return cls._result(Verdict.INCONCLUSIVE, "Configured Owner role does not establish the required privileged baseline", evidence)
        if not all(item["complete"] for item in (own, vis, anon)) or not cls._valid(own):
            return cls._result(Verdict.INCONCLUSIVE, "Complete responses and a valid privileged Owner baseline are required", evidence)
        if not evidence["anonymous_denial_body_clean"]:
            evidence["missing_evidence"].append("clean_anonymous_denial_body")
            return cls._result(Verdict.INCONCLUSIVE, "Anonymous access is not cleanly denied; the function-level boundary cannot be isolated", evidence)
        if roles["visitor_role"] == roles["required_role"]:
            if cls._valid(vis) and evidence["matched_private_data_paths"]:
                return cls._result(Verdict.AUTHORIZED, "Configured Visitor has the required role and accesses matching protected baseline data", evidence)
            return cls._result(Verdict.INCONCLUSIVE, "Visitor is configured with the required role, but authorized access lacks positive data evidence", evidence)
        if cls._clean_denial(vis, visitor):
            return cls._result(Verdict.SECURE, "Visitor lacks the required role and received a clean denial with a valid privileged baseline", evidence)
        if evidence["matched_private_data_paths"]:
            if cls._valid(vis):
                return cls._result(Verdict.CONFIRMED, "Visitor lacks the explicitly required role but receives configured protected Owner data", evidence)
            return cls._result(Verdict.SUSPICIOUS, "Visitor error or denial response contains protected Owner values; valid access is unproven", evidence)
        return cls._result(Verdict.INCONCLUSIVE, "Visitor access lacks positive protected-data evidence or a clean denial", evidence)

    @classmethod
    def evaluate_collection(
        cls, owner: HTTPResult, visitor: HTTPResult, anonymous: HTTPResult, *,
        policy: Mapping[str, Any], requires_auth: bool = True,
    ) -> Dict[str, Any]:
        own, vis, anon, evidence = cls._evidence(
            owner, visitor, anonymous, policy.get("private_data_paths", ()), "visitor",
        )
        expected_access = policy.get("expected_visitor_access", "deny")
        expected_public = policy.get("expected_public") is True
        evidence.update({"expected_visitor_access": expected_access, "expected_public": expected_public,
                         "requires_auth": requires_auth})
        if expected_access not in ("allow", "deny"):
            return cls._result(Verdict.INCONCLUSIVE, "Collection access policy is invalid", evidence)
        if not all(item["complete"] for item in (own, vis, anon)) or not cls._valid(own):
            return cls._result(Verdict.INCONCLUSIVE, "Complete responses and a valid Owner collection baseline are required", evidence)
        if expected_public:
            if evidence["private_data_paths"]:
                return cls._result(Verdict.INCONCLUSIVE, "Public policy conflicts with configured Owner-private data paths", evidence)
            if (not requires_auth and cls._valid(vis) and cls._valid(anon)
                    and json_values_equal(own["data"], vis["data"])
                    and json_values_equal(own["data"], anon["data"])):
                return cls._result(Verdict.PUBLIC, "Explicit public policy matches complete Owner, Visitor and Anonymous baselines", evidence)
            return cls._result(Verdict.INCONCLUSIVE, "Public collection policy lacks equivalent baselines or conflicts with required authentication", evidence)
        if not evidence["anonymous_denial_body_clean"]:
            evidence["missing_evidence"].append("clean_anonymous_denial_body")
            return cls._result(Verdict.INCONCLUSIVE, "Anonymous access is not cleanly denied; private collection isolation is unproven", evidence)
        if cls._clean_denial(vis, visitor):
            if expected_access == "allow":
                return cls._result(Verdict.INCONCLUSIVE, "Visitor was denied although the configured pair should have access", evidence)
            return cls._result(Verdict.SECURE, "Visitor collection access was cleanly denied with a valid Owner baseline", evidence)
        if evidence["matched_private_data_paths"]:
            if cls._valid(vis):
                if expected_access == "allow":
                    return cls._result(Verdict.AUTHORIZED, "Positive Owner private-data access matches the configured sharing policy for this pair", evidence)
                return cls._result(Verdict.CONFIRMED, "Visitor collection response exposes configured Owner private data", evidence)
            return cls._result(Verdict.SUSPICIOUS, "Visitor error or denial response contains Owner private values; valid collection access is unproven", evidence)
        return cls._result(Verdict.INCONCLUSIVE, "Absence of an Owner identifier or private-value match does not prove collection isolation", evidence)
