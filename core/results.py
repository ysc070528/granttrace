"""Recording audit results: verdict mapping, evidence redaction, coverage.

ResultRecorderMixin appends each check's result and finding under the
auditor's result lock, keeps request accounting with the result, redacts
secret and private values from evidence (including values discovered after a
record was written), and computes the coverage statistics at the end of a
scan. It is mixed into APISentinelAuditor, which owns the lock, the result
lists and the published secret set.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from core.bopla import resource_scope, validate_bopla_policy
from core.evidence import PROPERTY_EVIDENCE_LOCK, sanitize_evidence, sanitize_property_record
from core.models import HTTPResult, Verdict, strict_json_loads
from core.transactions import get_path, path_parts


class ResultRecorderMixin:
    """Mixed into APISentinelAuditor, which provides the attributes below."""

    results: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    stats: Dict[str, Any]
    bopla_config: Dict[str, Any]
    include_sensitive_evidence: bool
    _result_lock: threading.Lock
    _secret_values: Set[str]
    _bopla_secret_values: Set[str]
    _bopla_leak_groups: Dict[Tuple[Any, ...], str]
    _bopla_resource_groups: Dict[Tuple[Any, ...], int]
    _request_accounting: threading.local

    if TYPE_CHECKING:
        # Declared for type checking only; RequestBuilderMixin provides it.
        @staticmethod
        def _operation_key(ep: Dict[str, Any]) -> str: ...

    @staticmethod
    def _private_evidence_values(owner: HTTPResult, policy: Dict[str, Any]) -> Tuple[str, ...]:
        # Redact configured private values from every identity's stored body,
        # including echoes at other paths. Evaluation still uses original HTTP.
        try:
            document = strict_json_loads(owner.body)
        except (TypeError, ValueError, RecursionError):
            return ()
        values = []
        for path in policy.get("private_data_paths", []):
            exists, value = get_path(document, path)
            if exists and ((isinstance(value, str) and value) or type(value) in (int, float)):
                values.append(str(value))
        return tuple(values)

    def _record_result(
        self,
        ep: Dict[str, Any],
        check: str,
        verdict: Verdict,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
        finding: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        evidence = dict(evidence or {})
        # Count transport attempts, including failed connections, rather than
        # treating a local preflight conclusion as an executed check.
        attempts = getattr(self._request_accounting, "attempts", None)
        if attempts is None:
            # Response records also support callers that provide an isolated
            # transport fixture instead of using the built-in HTTP executor.
            def response_count(value: Any) -> int:
                if isinstance(value, dict):
                    if {"status", "body", "sha256", "truncated"}.issubset(value):
                        return 1
                    return sum(response_count(child) for child in value.values())
                if isinstance(value, list):
                    return sum(response_count(child) for child in value)
                return 0
            attempts = response_count(evidence)
        if getattr(self._request_accounting, "attempts", None) is not None:
            evidence["requests_attempted"] = attempts
        else:
            evidence.setdefault("requests_attempted", attempts)
        primary = check != "ROLLBACK"
        attempted = evidence["requests_attempted"] > 0
        conclusive = verdict in {Verdict.CONFIRMED, Verdict.SECURE, Verdict.PUBLIC, Verdict.AUTHORIZED}
        if "reason_category" not in evidence:
            if verdict == Verdict.SKIPPED:
                category = "detector_unimplemented" if check == "UNSUPPORTED" else "not_applicable"
            elif verdict == Verdict.ERROR:
                category = "error"
            elif conclusive:
                category = "conclusive"
            else:
                missing = evidence.get("decision_evidence", {}).get("missing_evidence", [])
                category = "missing_baseline" if not attempted or any(
                    item in missing for item in ("owner_baseline", "visitor_self_baseline", "distinct_visitor_self_resource")
                ) else "insufficient_evidence"
            evidence["reason_category"] = category
        if primary:
            self._request_accounting.attempts = None
        result = {
            "endpoint": self._operation_key(ep),
            "operation_id": ep.get("operation_id", ""),
            "check": check,
            "verdict": verdict.value,
            "reason": reason,
            "evidence": evidence,
        }
        force_safe = self._operation_key(ep) in self.bopla_config
        with self._result_lock, PROPERTY_EVIDENCE_LOCK:
            duplicate = False
            resource_group = None
            if force_safe:
                policy = self.bopla_config[self._operation_key(ep)]
                proof = evidence.get("decision_evidence", {})
                field_path = proof.get("field_path") if check == "BOPLA" else None
                if isinstance(policy, dict) and not validate_bopla_policy(policy) and (field_path or finding):
                    if check != "BOPLA":
                        # A legacy collection/object finding can prove exposure
                        # of the very field a property rule selects. Associate
                        # that one finding with one actually matched resource;
                        # other array resources retain independent leak groups.
                        shared_paths = proof.get("matched_private_data_paths") or proof.get("owner_specific_shared_value_paths", ())
                        matched_paths = set()
                        for path in shared_paths:
                            try:
                                matched_paths.add(path_parts(path))
                            except (TypeError, ValueError):
                                continue  # Arbitrary JSON keys need not be valid policy paths.
                        field_path = next((rule["path"] for rule in policy["fields"]
                                           if path_parts(rule["path"]) in matched_paths), None)
                    selected = (self._operation_key(ep), str(evidence.get("target_url", "")),
                                str(policy["context_id"]), resource_scope(policy, field_path))
                    resource_group = self._bopla_resource_groups.setdefault(selected, len(self._bopla_resource_groups) + 1)
                    evidence["resource_group"] = resource_group
            if force_safe and finding and verdict == Verdict.CONFIRMED:
                identity = (evidence.get("decision_evidence", {}).get("subject_identity")
                            if check == "BOPLA" else "anonymous" if check == "BROKEN_AUTH" else "visitor")
                context = self.bopla_config[self._operation_key(ep)].get("context_id", "")
                group_key = (self._operation_key(ep), str(evidence.get("target_url", "")),
                             str(context), str(identity), resource_group)
                group = self._bopla_leak_groups.get(group_key)
                if group:
                    duplicate = True
                    result["evidence"]["duplicate_of"] = group
                    finding = None
                else:
                    group = "read-leak-" + str(len(self._bopla_leak_groups) + 1)
                    self._bopla_leak_groups[group_key] = group
                result["evidence"]["leak_group"] = group
            # The mandatory boundary covers all operations in a BOPLA scan.
            # It preserves trusted control metadata while sanitizing business
            # observations and prevents a concurrent append escaping late cleanup.
            if self.bopla_config:
                result["evidence"]["property_privacy_pending"] = True
                result = self._property_safe_record(result)
                if finding:
                    finding.setdefault("evidence", {})["property_privacy_pending"] = True
                    finding = self._property_safe_record(finding)
            else:
                result = sanitize_evidence(result, self.include_sensitive_evidence, self._secret_values)
                if finding:
                    finding = sanitize_evidence(finding, self.include_sensitive_evidence, self._secret_values)
            self.results.append(result)
            self.stats["total_checks"] += 1
            if primary and attempted:
                self.stats["audited_count"] += 1
            if primary and attempted and conclusive:
                self.stats["conclusive_count"] += 1
            if verdict == Verdict.CONFIRMED and not duplicate:
                self.stats["confirmed"] += 1
            elif verdict == Verdict.SECURE:
                self.stats["secure_endpoints"] += 1
            elif verdict == Verdict.PUBLIC:
                self.stats["public_endpoints"] += 1
            elif verdict == Verdict.AUTHORIZED:
                self.stats["authorized_endpoints"] += 1
            elif verdict == Verdict.SUSPICIOUS:
                self.stats["suspicious_count"] += 1
            elif verdict == Verdict.INCONCLUSIVE:
                self.stats["inconclusive_count"] += 1
            elif verdict == Verdict.SKIPPED:
                self.stats["skipped_count"] += 1
            elif verdict == Verdict.ERROR:
                self.stats["error_count"] += 1
            if finding:
                self.findings.append(finding)
            # Per-detector counts measure confirmed decisions, even when their
            # shared observation contributes only one independent finding.
            if check == "BROKEN_AUTH" and verdict == Verdict.CONFIRMED:
                self.stats["broken_auth_confirmed"] += 1
            elif check == "BFLA" and verdict == Verdict.CONFIRMED:
                self.stats["bfla_confirmed"] += 1
        return result

    @staticmethod
    def _map_bola_verdict(raw: str) -> Verdict:
        mapping = {
            "BOLA_CONFIRMED": Verdict.CONFIRMED,
            "CONFIRMED": Verdict.CONFIRMED,
            "PUBLIC_ENDPOINT": Verdict.PUBLIC,
            "PUBLIC": Verdict.PUBLIC,
            "SECURE_ENFORCED": Verdict.SECURE,
            "SECURE": Verdict.SECURE,
            "LOW_SUSPICION": Verdict.SUSPICIOUS,
            "SUSPICIOUS": Verdict.SUSPICIOUS,
            "ERROR": Verdict.ERROR,
        }
        return mapping.get(str(raw).upper(), Verdict.INCONCLUSIVE)

    def _property_safe_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_property_record(record, self._secret_values,
                                        omit_responses=bool(self._bopla_secret_values))

    @staticmethod
    def _replace_evidence_in_place(current: Any, safe: Any) -> None:
        # Callers can retain a record, a list, or a nested evidence dictionary.
        # Replacing only the auditor's outer collection leaves those aliases live.
        if isinstance(current, dict) and isinstance(safe, dict):
            for key in list(current):
                if key not in safe:
                    del current[key]
            for key, value in safe.items():
                if key in current and isinstance(current[key], (dict, list)) and isinstance(value, type(current[key])):
                    ResultRecorderMixin._replace_evidence_in_place(current[key], value)
                else:
                    current[key] = value
        elif isinstance(current, list) and isinstance(safe, list):
            for index, value in enumerate(safe):
                if index < len(current) and isinstance(current[index], (dict, list)) and isinstance(value, type(current[index])):
                    ResultRecorderMixin._replace_evidence_in_place(current[index], value)
                elif index < len(current):
                    current[index] = value
                else:
                    current.append(value)
            del current[len(safe):]

    def _redact_property_history(self) -> None:
        # The result lock is held by callers, including registration and finalization.
        with PROPERTY_EVIDENCE_LOCK:
            for collection in (self.results, self.findings):
                for record in collection:
                    self._replace_evidence_in_place(record, self._property_safe_record(record))

    def _record_task_error(self, ep: Dict[str, Any], check: str, exc: BaseException) -> None:
        message = ("Property audit failed; response details omitted" if self.bopla_config
                   else f"Unhandled {type(exc).__name__}: {exc}")
        self._record_result(ep, check, Verdict.ERROR, message)

    def _finalise_coverage(self) -> None:
        with self._result_lock, PROPERTY_EVIDENCE_LOCK:
            self._finalise_coverage_locked()

    def _finalise_coverage_locked(self) -> None:
        if self._bopla_secret_values:
            # Include observations recorded before another worker learned a
            # protected value. Sensitive opt-in cannot remove this boundary.
            self._redact_property_history()
        total = max(1, int(self.stats["total_endpoints"]))
        endpoint_results = [item for item in self.results if item["check"] != "ROLLBACK"]
        attempted_keys = {item["endpoint"] for item in endpoint_results
                          if item.get("evidence", {}).get("requests_attempted", 0) > 0}
        # Multiple detection items on one endpoint share a coverage denominator.
        # Every selected item must have a conclusive attempted observation. Legacy
        # repeated results for the same item retain their existing any-result rule.
        item_states: Dict[str, Dict[str, bool]] = {}
        for item in endpoint_results:
            states = item_states.setdefault(item["endpoint"], {})
            conclusive_item = item.get("evidence", {}).get("requests_attempted", 0) > 0 and item["verdict"] in {
                Verdict.CONFIRMED.value, Verdict.SECURE.value, Verdict.PUBLIC.value, Verdict.AUTHORIZED.value}
            if item["check"] == "BOPLA":
                states["BOPLA"] = states.get("BOPLA", True) and conclusive_item
            else:
                states[item["check"]] = states.get(item["check"], False) or conclusive_item
        conclusive_keys = {endpoint for endpoint, states in item_states.items() if all(states.values())}
        attempted = len(attempted_keys)
        conclusive = len(conclusive_keys)
        self.stats["attempted_endpoints"] = attempted
        self.stats["conclusive_endpoints"] = conclusive
        self.stats["coverage_pct"] = round(attempted * 100.0 / total, 1)
        self.stats["conclusive_coverage_pct"] = round(conclusive * 100.0 / total, 1)
        self.stats["confirmed_endpoints"] = len({item["endpoint"] for item in endpoint_results
                                                 if item["verdict"] == Verdict.CONFIRMED.value})
        self.stats["detection_items"] = sum(len(states) for states in item_states.values())
        if self.bopla_config:
            fields = [item for item in endpoint_results if item["check"] == "BOPLA"]
            def field_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
                proof = item["evidence"].get("decision_evidence", {})
                return (item["endpoint"], item["evidence"].get("target_url"), proof.get("context_id"),
                        item["evidence"].get("resource_group"), proof.get("field_path"))
            self.stats["bopla_field_checks"] = sum(bool(item["evidence"].get("decision_evidence", {}).get("field_path")) for item in fields)
            self.stats["bopla_fields_checked"] = len({field_key(item) for item in fields
                if item["evidence"].get("decision_evidence", {}).get("comparison_valid")})
            self.stats["bopla_fields_confirmed"] = len({field_key(item) for item in fields
                if item["verdict"] == "CONFIRMED"})
            self.stats["bopla_inconclusive_count"] = sum(item["verdict"] == "INCONCLUSIVE" for item in fields)
            self.stats["bopla_skipped_count"] = sum(item["verdict"] == "SKIPPED" for item in fields)
            self.stats["unique_confirmed_vulnerabilities"] = len(self.findings)
            self.stats["confirmed_detection_items"] = sum(item["verdict"] == "CONFIRMED" for item in endpoint_results)
