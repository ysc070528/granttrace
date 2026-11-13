"""Offline comparison of two GrantTrace JSON scan reports.

``granttrace diff BASELINE.json CURRENT.json`` reads two reports with
``report_schema_version`` 2 and classifies every confirmed finding as new,
persisting, resolved or not comparable. Nothing is sent over the network.

A finding is identified by its check, its operation template and, where a check
produces several results per operation, its subject (BOPLA field rule and
identity, RBAC role, mass-assignment field). Targets, ports, times and concrete
resource values are not part of the identifier; they decide whether two results
are comparable.

A conclusion that depends on scope (new, persisting, resolved) needs evidence
that both scans covered the same target (scheme, host, port and base path), the
same test accounts, policy and resources:

* With ``GRANTTRACE_COMPARISON_KEY`` set during both scans, reports carry a
  ``comparison_context`` of HMAC-SHA256 fingerprints, which ``diff`` compares
  without needing the key. Without the key they cannot be enumerated offline.
* Without the key, reports carry no fingerprints. ``diff`` then compares the
  report targets exactly and the resource paths in the evidence; a change of
  test accounts cannot be detected, and an unreadable target (for example a
  BOPLA report's omitted target) makes every finding not comparable.

A finding is only reported as resolved when the same check on the same subject
and scope now has a conclusive non-vulnerable verdict (SECURE, PUBLIC or
AUTHORIZED). A SKIPPED, INCONCLUSIVE, ERROR or SUSPICIOUS result, or a missing
one, never counts as a fix. A finding on an operation the baseline did not
contain is a first detection, not a proven regression, and is not comparable.

The comparison output holds identifiers, verdicts and enumerated reason codes
only: no evidence, response data, URLs, credentials or free text from the
reports.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from core import __version__
from core.models import parse_operation_key, strict_json_loads

COMPARISON_SCHEMA_VERSION = 1
CONTEXT_VERSION = 1
CONTEXT_ALGORITHM = "hmac-sha256"
COMPARISON_KEY_ENV = "GRANTTRACE_COMPARISON_KEY"
MIN_COMPARISON_KEY_LENGTH = 16
MAX_REPORT_BYTES = 64 * 1024 * 1024

CONFIRMED = "CONFIRMED"
CONCLUSIVE_NEGATIVE = frozenset({"SECURE", "PUBLIC", "AUTHORIZED"})
KNOWN_VERDICTS = frozenset({"CONFIRMED", "SECURE", "PUBLIC", "AUTHORIZED",
                            "SUSPICIOUS", "INCONCLUSIVE", "SKIPPED", "ERROR"})
CHECK_CWE = {"BOLA": "CWE-639", "BROKEN_AUTH": "CWE-306", "BFLA": "CWE-285", "RBAC": "CWE-285",
             "BOPLA": "CWE-200", "BOPLA_EXPOSURE": "CWE-200", "MASS_ASSIGNMENT": "CWE-915"}
STATUS_ORDER = ("new", "not_comparable", "persisting", "resolved")

_CHECK_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_FINGERPRINT = re.compile(r"[0-9a-f]{16}")
_SUBJECT_LIMIT = 512

Key = Tuple[str, str, Optional[str]]


class ReportError(ValueError):
    """An input report cannot be used for comparison."""


class ComparisonKeyError(ValueError):
    """GRANTTRACE_COMPARISON_KEY is set but unusable; the message never contains the key."""


# ---------------------------------------------------------------------------
# Identifiers, keys and fingerprints


def finding_id(check: str, operation: str, subject: Optional[str] = None) -> str:
    """Stable identifier of a check result: independent of target, port, time and resource values."""
    material = "\0".join(("granttrace/finding/v1", check, operation, subject or ""))
    return "gtf_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def comparison_key_from_environment(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """The comparison key, or None when it is not set (an empty value counts as not set)."""
    value = (os.environ if environ is None else environ).get(COMPARISON_KEY_ENV)
    if not value:
        return None
    if len(value) < MIN_COMPARISON_KEY_LENGTH:
        raise ComparisonKeyError(
            f"{COMPARISON_KEY_ENV} must be at least {MIN_COMPARISON_KEY_LENGTH} characters; generate one with "
            "python -c \"import secrets; print(secrets.token_hex(32))\" and keep it secret, like a password")
    return value


def target_identity(value: Any) -> Optional[Tuple[str, str, int, str]]:
    """Scheme, host, port (default ports filled in) and base path of an http(s) target, or None."""
    if not isinstance(value, str) or not value.startswith(("http://", "https://")):
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme, host, port, parts.path.rstrip("/")


def _keyed(key: str, kind: str, value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    digest = hmac.new(key.encode("utf-8"), f"granttrace/{kind}/v1\0{canonical}".encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()[:16]


def _mask(value: Any, secrets: Tuple[str, ...]) -> Any:
    """Replace strings that contain a credential before anything is fingerprinted."""
    if isinstance(value, str):
        if any(secret == value or (len(secret) >= 4 and secret in value) for secret in secrets):
            return "[REDACTED]"
        return value
    if isinstance(value, Mapping):
        return {str(key): _mask(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask(item, secrets) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _canonical_operation(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    valid, _, _, canonical, _ = parse_operation_key(value.strip())
    return canonical if valid else None


def _by_operation(section: Any) -> Dict[str, Any]:
    if not isinstance(section, Mapping):
        return {}
    mapped: Dict[str, Any] = {}
    for key, value in section.items():
        operation = _canonical_operation(key)
        if operation is not None:
            mapped[operation] = value
    return mapped


def build_comparison_context(
    *,
    key: str,
    target: str,
    identities: Any,
    parameter_values: Any = None,
    bola_config: Any = None,
    bopla_config: Any = None,
    readback_config: Any = None,
    write_allowlist: Iterable[Any] = (),
    secret_values: Iterable[str] = (),
) -> Dict[str, Any]:
    """Keyed fingerprints of what a scan compared, for later comparability checks.

    Every fingerprint is a truncated HMAC-SHA256 under the comparison key, so
    short account IDs, resource values and the target cannot be enumerated
    without the key, and ``diff`` compares them without needing it. The target
    fingerprint covers scheme, host, port and base path. Identities are
    fingerprinted from their ``id``, ``role`` and identity parameters; tokens,
    headers and cookies are never included, and any string containing a known
    credential is masked first. Operations are fingerprinted from their
    configured policy and resource values.
    """
    secrets = tuple(sorted({value for value in secret_values if isinstance(value, str) and value}))

    def identity_fingerprint(data: Any) -> Optional[str]:
        if not isinstance(data, Mapping):
            return None
        parameters = data.get("parameters") if isinstance(data.get("parameters"), Mapping) else {}
        material = {"id": data.get("id"), "role": data.get("role"), "parameters": parameters}
        if material["id"] is None and material["role"] is None and not parameters:
            return None
        return _keyed(key, "identity", _mask(material, secrets))

    def operation_fingerprints(policy: Mapping[str, Any], resources: Any) -> Dict[str, str]:
        return {"policy": _keyed(key, "policy", _mask(policy, secrets)),
                "resources": _keyed(key, "resources", _mask(resources, secrets))}

    identity_map = identities if isinstance(identities, Mapping) else {}
    declared: Dict[str, Any] = {name: identity_fingerprint(identity_map.get(name))
                                for name in ("owner", "visitor", "anonymous")}
    roles = identity_map.get("roles")
    declared["roles"] = ({str(name): identity_fingerprint(data)
                          for name, data in sorted(roles.items(), key=lambda item: str(item[0]))}
                         if isinstance(roles, Mapping) else {})

    parameters = _by_operation(parameter_values)
    bola = _by_operation(bola_config)
    bopla = _by_operation(bopla_config)
    readbacks = _by_operation(readback_config)
    allowlisted = {operation for operation in map(_canonical_operation, write_allowlist or ()) if operation}
    operations: Dict[str, Dict[str, str]] = {}
    for operation in sorted(set(parameters) | set(bola) | set(bopla) | set(readbacks) | allowlisted):
        operations[operation] = operation_fingerprints(
            {"bola": bola.get(operation), "bopla": bopla.get(operation), "readback": readbacks.get(operation),
             "write_allowlisted": operation in allowlisted},
            parameters.get(operation))
    identity_of_target = target_identity(target)
    return {
        "version": CONTEXT_VERSION,
        "algorithm": CONTEXT_ALGORITHM,
        "key_id": _keyed(key, "comparison-key-id", None),
        "target": _keyed(key, "target", list(identity_of_target)) if identity_of_target else None,
        "identities": declared,
        "operations": operations,
        "unconfigured_operation": operation_fingerprints(
            {"bola": None, "bopla": None, "readback": None, "write_allowlisted": False}, None),
    }


# ---------------------------------------------------------------------------
# Loading reports


def load_report(path: str) -> Dict[str, Any]:
    """Read and validate one GrantTrace JSON scan report."""
    file = Path(path)
    try:
        if not file.is_file():
            raise ReportError("report file does not exist or is not a regular file")
        if file.stat().st_size > MAX_REPORT_BYTES:
            raise ReportError(f"report is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB")
        text = file.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ReportError("report is not valid UTF-8") from exc
    except OSError as exc:
        raise ReportError(f"cannot read report ({type(exc).__name__})") from exc
    try:
        data = strict_json_loads(text)
    except (ValueError, RecursionError) as exc:
        raise ReportError("report is not valid JSON") from exc
    validate_report(data)
    return data


def validate_report(data: Any) -> None:
    if not isinstance(data, dict):
        raise ReportError("report root must be a JSON object")
    if data.get("mode") == "DRY_RUN" or ("operations" in data and "results" not in data):
        raise ReportError("this is a --dry-run plan, not a scan report; compare JSON reports from real scans")
    if "runs" in data and "results" not in data:
        raise ReportError("this is a SARIF file; compare the GrantTrace JSON reports (--export-json)")
    version = data.get("report_schema_version")
    if type(version) is not int or version != 2:
        raise ReportError("unsupported report_schema_version; GrantTrace JSON reports with version 2 are supported")
    if not isinstance(data.get("results"), list):
        raise ReportError("report has no results list")
    if not isinstance(data.get("tool_version"), str):
        raise ReportError("report has no tool_version")


# ---------------------------------------------------------------------------
# Indexing results


class _Entry:
    __slots__ = ("verdicts", "scopes")

    def __init__(self) -> None:
        self.verdicts: Set[str] = set()
        self.scopes: Set[Tuple[Tuple[str, str], ...]] = set()

    @property
    def confirmed(self) -> bool:
        return CONFIRMED in self.verdicts

    @property
    def conclusive_negative(self) -> bool:
        return bool(self.verdicts) and self.verdicts <= CONCLUSIVE_NEGATIVE

    @property
    def conclusive(self) -> bool:
        return bool(self.verdicts) and self.verdicts <= CONCLUSIVE_NEGATIVE | {CONFIRMED}


def _bounded_subject(prefix: str, value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value or len(value) > _SUBJECT_LIMIT:
        return None
    return f"{prefix}:{value}"


def _subjects(check: str, verdict: str, evidence: Mapping[str, Any]) -> List[Tuple[Optional[str], str]]:
    """Expand one result record into (subject, verdict) pairs."""
    if check == "MASS_ASSIGNMENT":
        field = _bounded_subject("field", evidence.get("field"))
        if field is not None:
            return [(field, verdict)]
        safe = evidence.get("safe_fields")
        if verdict == "SECURE" and isinstance(safe, list):
            # A SECURE record verifies each safe field individually.
            pairs: List[Tuple[Optional[str], str]] = [
                (subject, "SECURE") for subject in (_bounded_subject("field", name) for name in safe) if subject]
            return pairs + [(None, verdict)]
        return [(None, verdict)]
    if check == "BOPLA":
        decision = evidence.get("decision_evidence")
        decision = decision if isinstance(decision, Mapping) else {}
        rule = decision.get("rule_id") if isinstance(decision.get("rule_id"), str) else decision.get("field_path")
        subject = _bounded_subject("field", rule)
        identity = decision.get("subject_identity")
        if subject is not None and isinstance(identity, str) and identity and len(identity) <= _SUBJECT_LIMIT:
            subject += f"|identity:{identity}"
        return [(subject, verdict)]
    if check == "RBAC":
        return [(_bounded_subject("role", evidence.get("rbac_role")), verdict)]
    return [(None, verdict)]


def _url_scope(value: Any) -> Optional[str]:
    """Path and query of an evidence URL; the target itself is compared separately."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    return parts.path + (("?" + parts.query) if parts.query else "")


def _evidence_scope(evidence: Mapping[str, Any]) -> Optional[Tuple[Tuple[str, str], ...]]:
    items = []
    for name in ("target_url", "visitor_self_url", "readback_url"):
        scope = _url_scope(evidence.get(name))
        if scope is not None:
            items.append((name, scope))
    for name in ("role", "required_role"):
        value = evidence.get(name)
        if isinstance(value, str):
            items.append((name, value))
    return tuple(sorted(items)) or None


class _Index:
    def __init__(self, report: Mapping[str, Any]) -> None:
        self.entries: Dict[Key, _Entry] = {}
        self.operations: Set[str] = set()
        self.unreadable = 0
        for record in report.get("results", []):
            if not isinstance(record, Mapping):
                self.unreadable += 1
                continue
            check = record.get("check")
            operation = _canonical_operation(record.get("endpoint"))
            if not isinstance(check, str) or not _CHECK_NAME.fullmatch(check) or operation is None:
                self.unreadable += 1
                continue
            verdict = record.get("verdict")
            verdict = verdict if isinstance(verdict, str) and verdict in KNOWN_VERDICTS else "UNKNOWN"
            evidence = record.get("evidence")
            evidence = evidence if isinstance(evidence, Mapping) else {}
            scope = _evidence_scope(evidence)
            self.operations.add(operation)
            for subject, subject_verdict in _subjects(check, verdict, evidence):
                entry = self.entries.setdefault((check, operation, subject), _Entry())
                entry.verdicts.add(subject_verdict)
                if scope is not None:
                    entry.scopes.add(scope)

    def operation_level(self, key: Key) -> Optional[_Entry]:
        if key[2] is None:
            return None
        return self.entries.get((key[0], key[1], None))


# ---------------------------------------------------------------------------
# Comparison


def _context(report: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """A keyed comparison context, or None (absent, unkeyed or malformed contexts are not used)."""
    context = report.get("comparison_context")
    if not isinstance(context, Mapping) or context.get("version") != CONTEXT_VERSION:
        return None
    key_id = context.get("key_id")
    if (context.get("algorithm") != CONTEXT_ALGORITHM or not isinstance(key_id, str)
            or not _FINGERPRINT.fullmatch(key_id)):
        return None
    if not all(isinstance(context.get(name), Mapping)
               for name in ("identities", "operations", "unconfigured_operation")):
        return None
    return context


def _identity_changes(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> Tuple[List[str], List[str]]:
    changed: List[str] = []
    undeclared: List[str] = []
    for name in ("owner", "visitor"):
        left, right = baseline.get(name), current.get(name)
        if left is None and right is None:
            undeclared.append(name)
        elif left != right:
            changed.append(name)
    left_value, right_value = baseline.get("roles"), current.get("roles")
    left_roles: Mapping[str, Any] = left_value if isinstance(left_value, Mapping) else {}
    right_roles: Mapping[str, Any] = right_value if isinstance(right_value, Mapping) else {}
    for name in sorted(set(left_roles) | set(right_roles)):
        if left_roles.get(name) != right_roles.get(name):
            changed.append(f"role:{name}")
    return changed, undeclared


def _numeric_stats(report: Mapping[str, Any]) -> Dict[str, float]:
    stats = report.get("stats")
    stats = stats if isinstance(stats, Mapping) else {}
    keys = ("total_endpoints", "coverage_pct", "conclusive_coverage_pct", "conclusive_count",
            "inconclusive_count", "skipped_count", "error_count", "confirmed")
    return {key: stats[key] for key in keys
            if type(stats.get(key)) in (int, float) and stats[key] == stats[key]}


def _sorted_verdicts(entry: Optional[_Entry]) -> List[str]:
    return sorted(entry.verdicts) if entry is not None else []


def _describe(key: Key) -> Dict[str, Any]:
    check, operation, subject = key
    described: Dict[str, Any] = {"finding_id": finding_id(check, operation, subject), "check": check,
                                 "operation": operation}
    if subject is not None:
        described["subject"] = subject
    if check in CHECK_CWE:
        described["cwe"] = CHECK_CWE[check]
    return described


def _plain(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and len(value) <= 64 and value.isprintable() else None


def compare_reports(baseline: Mapping[str, Any], current: Mapping[str, Any], *,
                    assume_same_target: bool = False) -> Dict[str, Any]:
    """Compare two validated reports; see the module docstring for the rules.

    ``assume_same_target`` is the caller's explicit statement that both scans
    targeted the same deployment although their targets differ or cannot be
    read (for example a local service restarted on a new port). It removes only
    the target condition, is recorded in the output and keeps the comparison
    from being reported as fully comparable.
    """
    old, new = _Index(baseline), _Index(current)
    old_context, new_context = _context(baseline), _context(current)
    notes: Set[str] = set()
    if old_context is not None and new_context is not None and old_context["key_id"] != new_context["key_id"]:
        notes.add("comparison_keys_differ")
        old_context = new_context = None
    declared = old_context is not None and new_context is not None
    basis = "declared" if declared else "evidence"

    changes: List[Dict[str, Any]] = []
    blocking: List[str] = []
    assumptions: List[str] = []
    if baseline.get("tool_version") != current.get("tool_version"):
        changes.append({"kind": "tool_version", "baseline": baseline.get("tool_version"),
                        "current": current.get("tool_version"), "blocking": False})

    # Target: keyed fingerprints when declared, otherwise the report targets themselves.
    if old_context is not None and new_context is not None:
        old_target, new_target = old_context.get("target"), new_context.get("target")
    else:
        old_target, new_target = target_identity(baseline.get("target")), target_identity(current.get("target"))
    target_state = ("unknown" if old_target is None or new_target is None
                    else "changed" if old_target != new_target else "same")
    if target_state != "same":
        if assume_same_target:
            assumptions.append("same_target")
            changes.append({"kind": "target", "state": target_state, "acknowledged": True, "blocking": False})
        else:
            blocking.append(f"target_{target_state}")
            changes.append({"kind": "target", "state": target_state, "blocking": True})

    if old_context is not None and new_context is not None:
        changed, undeclared = _identity_changes(old_context["identities"], new_context["identities"])
        if changed:
            changes.append({"kind": "identities", "identities": changed, "blocking": True})
            blocking.append("identities_changed")
        if undeclared:
            notes.add("identity_account_ids_not_declared")
    else:
        notes.add("identities_unverified")
    added = sorted(new.operations - old.operations)
    removed = sorted(old.operations - new.operations)
    if added:
        changes.append({"kind": "operations_added", "count": len(added), "blocking": False})
    if removed:
        changes.append({"kind": "operations_removed", "count": len(removed), "blocking": False})
    if old.unreadable or new.unreadable:
        notes.add("unreadable_results_ignored")

    def declared_operation_reasons(operation: str) -> List[str]:
        assert old_context is not None and new_context is not None
        before = old_context["operations"].get(operation, old_context["unconfigured_operation"])
        after = new_context["operations"].get(operation, new_context["unconfigured_operation"])
        before = before if isinstance(before, Mapping) else {}
        after = after if isinstance(after, Mapping) else {}
        reasons = []
        if before.get("policy") != after.get("policy"):
            reasons.append("policy_changed")
        if before.get("resources") != after.get("resources"):
            reasons.append("resources_changed")
        return reasons

    operation_changes: Dict[str, Set[str]] = {}
    if old_context is not None and new_context is not None:
        # Operations in only one report are already reported as added or removed.
        for operation in sorted(old.operations & new.operations):
            reasons = declared_operation_reasons(operation)
            if reasons:
                operation_changes[operation] = set(reasons)

    def scope_reasons(key: Key, left: _Entry, right: _Entry) -> List[str]:
        reasons = list(blocking)
        if declared:
            reasons.extend(sorted(operation_changes.get(key[1], ())))
        elif not left.scopes or not right.scopes:
            reasons.append("scope_unknown")
            operation_changes.setdefault(key[1], set()).add("scope_unknown")
        elif left.scopes != right.scopes:
            reasons.append("resources_changed")
            operation_changes.setdefault(key[1], set()).add("resources_changed")
        return reasons

    issues: List[Dict[str, Any]] = []
    for key in sorted(set(old.entries) | set(new.entries), key=lambda item: (item[1], item[0], item[2] or "")):
        before, after = old.entries.get(key), new.entries.get(key)
        if not ((before is not None and before.confirmed) or (after is not None and after.confirmed)):
            continue
        if after is not None and after.confirmed:
            if before is not None and before.confirmed:
                reasons = scope_reasons(key, before, after)
                status = "not_comparable" if reasons else "persisting"
            elif before is None and key[1] not in old.operations:
                # First detection on an operation the baseline did not contain: not a proven regression.
                status, reasons = "not_comparable", list(blocking) + ["operation_not_in_baseline"]
            elif before is None:
                status, reasons = "not_comparable", ["not_checked_in_baseline"]
                before = old.operation_level(key)
            elif before.conclusive_negative:
                reasons = scope_reasons(key, before, after)
                status = "not_comparable" if reasons else "new"
            else:
                status, reasons = "not_comparable", ["baseline_unverified"]
        else:
            assert before is not None
            if after is None:
                fallback = new.operation_level(key)
                if key[1] not in new.operations:
                    status, reasons = "not_comparable", ["operation_not_in_current"]
                elif fallback is not None and not fallback.conclusive_negative:
                    status, reasons = "not_comparable", ["current_unverified"]
                    after = fallback
                else:
                    status, reasons = "not_comparable", ["missing_in_current"]
            elif after.conclusive_negative:
                reasons = scope_reasons(key, before, after)
                status = "not_comparable" if reasons else "resolved"
            else:
                status, reasons = "not_comparable", ["current_unverified"]
        issue = _describe(key)
        issue.update({"status": status, "baseline_verdicts": _sorted_verdicts(before),
                      "current_verdicts": _sorted_verdicts(after)})
        if reasons:
            issue["reasons"] = reasons
        issues.append(issue)
    issues.sort(key=lambda item: (STATUS_ORDER.index(item["status"]), item["operation"], item["check"],
                                  item.get("subject", "")))

    lost: List[Dict[str, Any]] = []
    gained: List[Dict[str, Any]] = []
    for key in sorted(set(old.entries) | set(new.entries), key=lambda item: (item[1], item[0], item[2] or "")):
        before, after = old.entries.get(key), new.entries.get(key)
        was = before is not None and before.conclusive
        now = after is not None and after.conclusive
        if was != now:
            item = _describe(key)
            item.update({"baseline_verdicts": _sorted_verdicts(before), "current_verdicts": _sorted_verdicts(after)})
            (lost if was else gained).append(item)
    old_stats, new_stats = _numeric_stats(baseline), _numeric_stats(current)
    old_cov, new_cov = old_stats.get("conclusive_coverage_pct"), new_stats.get("conclusive_coverage_pct")
    coverage_decreased = bool(lost) or (old_cov is not None and new_cov is not None and new_cov < old_cov)
    if coverage_decreased:
        changes.append({"kind": "coverage_decreased", "blocking": False})

    summary = {status: sum(1 for issue in issues if issue["status"] == status) for status in STATUS_ORDER}
    summary["current_confirmed_not_comparable"] = sum(
        1 for issue in issues if issue["status"] == "not_comparable" and CONFIRMED in issue["current_verdicts"])
    summary["baseline_confirmed"] = sum(1 for entry in old.entries.values() if entry.confirmed)
    summary["current_confirmed"] = sum(1 for entry in new.entries.values() if entry.confirmed)
    return {
        "comparison_schema_version": COMPARISON_SCHEMA_VERSION,
        "tool_version": __version__,
        "baseline": {"tool_version": baseline.get("tool_version"), "generated_at": _plain(baseline.get("generated_at")),
                     "context": "keyed" if _context(baseline) is not None else "absent"},
        "current": {"tool_version": current.get("tool_version"), "generated_at": _plain(current.get("generated_at")),
                    "context": "keyed" if _context(current) is not None else "absent"},
        "comparability": {
            "basis": basis,
            # True only when the target, test accounts, policy and resources were all verified
            # as unchanged from keyed contexts, without any assumption.
            "fully_comparable": declared and not blocking and not assumptions and not operation_changes,
            "blocking": blocking,
            "assumptions": assumptions,
            "operation_changes": [{"operation": operation, "reasons": sorted(reasons)}
                                  for operation, reasons in sorted(operation_changes.items())],
            "changes": changes,
            "notes": sorted(notes),
        },
        "summary": summary,
        "issues": issues,
        "coverage": {"baseline": old_stats, "current": new_stats, "decreased": coverage_decreased,
                     "conclusive_lost": lost, "conclusive_gained": gained,
                     "operations_added": len(added), "operations_removed": len(removed)},
    }


# ---------------------------------------------------------------------------
# Command line


def _printable(value: Any) -> str:
    text = str(value)
    return "".join(character if character.isprintable() else f"\\u{ord(character):04x}" for character in text)


_NOTE_TEXT = {
    "identities_unverified": "no keyed comparison context in one or both reports; a change of test accounts "
                             f"cannot be detected (set {COMPARISON_KEY_ENV} for both scans)",
    "comparison_keys_differ": "the reports were made with different comparison keys; keyed fingerprints "
                              "were not used",
    "identity_account_ids_not_declared": "owner/visitor have no account id in the configuration; "
                                         "a change of test accounts cannot be detected",
    "unreadable_results_ignored": "some result records could not be read and were ignored",
}


def summary_lines(comparison: Mapping[str, Any]) -> List[str]:
    summary = comparison["summary"]
    comparability = comparison["comparability"]
    coverage = comparison["coverage"]
    lines = [
        "GrantTrace report comparison",
        f"Baseline: GrantTrace {_printable(comparison['baseline']['tool_version'])}, "
        f"generated {_printable(comparison['baseline']['generated_at'] or 'unknown')}",
        f"Current:  GrantTrace {_printable(comparison['current']['tool_version'])}, "
        f"generated {_printable(comparison['current']['generated_at'] or 'unknown')}",
    ]
    if comparability["blocking"]:
        lines.append("Comparability: NOT comparable for any finding (" + ", ".join(comparability["blocking"]) + ")")
    elif comparability["fully_comparable"]:
        lines.append("Comparability: verified (keyed comparison context in both reports)")
    else:
        limits = []
        if comparability["basis"] != "declared":
            limits.append("test accounts not verified")
        if comparability["assumptions"]:
            limits.append("same target assumed by --assume-same-target")
        if comparability["operation_changes"]:
            limits.append(f"{len(comparability['operation_changes'])} operation(s) changed or unverifiable")
        lines.append("Comparability: limited (" + "; ".join(limits) + ")")
    for change in comparability["changes"]:
        if change["kind"] == "tool_version":
            lines.append(f"  note: tool version changed from {_printable(change['baseline'])} "
                         f"to {_printable(change['current'])}")
        elif change["kind"] == "identities":
            lines.append("  identities changed: " + ", ".join(_printable(name) for name in change["identities"]))
        elif change["kind"] == "target":
            state = "could not be read" if change["state"] == "unknown" else "differs"
            suffix = " (acknowledged by --assume-same-target)" if change.get("acknowledged") else ""
            lines.append(f"  target {state}{suffix}")
    for item in comparability["operation_changes"]:
        lines.append(f"  operation {_printable(item['operation'])}: " + ", ".join(item["reasons"]))
    for note in comparability["notes"]:
        if note in _NOTE_TEXT:
            lines.append("  note: " + _NOTE_TEXT[note])
    old_cov = coverage["baseline"].get("conclusive_coverage_pct")
    new_cov = coverage["current"].get("conclusive_coverage_pct")
    coverage_line = "Conclusive coverage: "
    coverage_line += (f"{old_cov}% -> {new_cov}%" if old_cov is not None and new_cov is not None else "not recorded")
    if coverage["decreased"]:
        coverage_line += f" (DECREASED; {len(coverage['conclusive_lost'])} conclusive check(s) lost)"
    lines.append(coverage_line)
    if coverage["operations_added"] or coverage["operations_removed"]:
        lines.append(f"Operations: {coverage['operations_added']} added, {coverage['operations_removed']} removed")
    lines.append(f"Confirmed findings: {summary['new']} new, {summary['persisting']} persisting, "
                 f"{summary['resolved']} resolved, {summary['not_comparable']} not comparable")
    labels = {"new": "NEW", "persisting": "PERSISTING", "resolved": "RESOLVED", "not_comparable": "NOT COMPARABLE"}
    for issue in comparison["issues"]:
        subject = f" [{_printable(issue['subject'])}]" if issue.get("subject") else ""
        line = (f"  {labels[issue['status']]:<15} {issue['finding_id']} {issue['check']} "
                f"{_printable(issue['operation'])}{subject}")
        if issue.get("reasons"):
            line += " (" + ", ".join(issue["reasons"]) + ")"
        lines.append(line)
    if summary["not_comparable"]:
        lines.append("Not comparable findings are neither proven new nor fixed; see the reason codes.")
    if summary["current_confirmed_not_comparable"]:
        lines.append(f"{summary['current_confirmed_not_comparable']} of them are confirmed in the current scan "
                     "without comparable baseline evidence.")
    return lines


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="granttrace diff",
        description=("Compare two GrantTrace JSON scan reports offline. Confirmed findings are classified as "
                     "new, persisting, resolved or not comparable; SKIPPED or INCONCLUSIVE results never count "
                     "as fixed. No network access; no evidence or response data is copied."),
        epilog=(f"Set the same {COMPARISON_KEY_ENV} (16+ characters) during both scans so that the reports "
                "carry keyed fingerprints of target, test accounts, policy and resources, and diff can verify "
                "that they are comparable. Without it, accounts cannot be verified and BOPLA reports, whose "
                "target is omitted, are never comparable."),
    )
    parser.add_argument("baseline", metavar="BASELINE.json", help="Earlier GrantTrace JSON report (--export-json)")
    parser.add_argument("current", metavar="CURRENT.json", help="Later GrantTrace JSON report (--export-json)")
    parser.add_argument("--export-json", metavar="PATH", default=None,
                        help="Write the machine-readable comparison to PATH")
    parser.add_argument("--assume-same-target", action="store_true",
                        help=("State that both scans targeted the same deployment although their targets differ "
                              "or cannot be read (for example a local service restarted on a new port). The "
                              "assumption is recorded in the output; use it only when you know it is true"))
    return parser


def _checked_output(path: str, inputs: Sequence[str]) -> Path:
    if not path.strip() or any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise ReportError("--export-json requires a non-empty path without control characters")
    output = Path(path).expanduser().resolve()
    for source in inputs:
        candidate = Path(source).expanduser().resolve()
        if output == candidate or (output.exists() and candidate.exists() and output.samefile(candidate)):
            raise ReportError("--export-json must not overwrite an input report")
    return output


def diff_main(argv: Sequence[str]) -> int:
    args = _build_parser().parse_args(list(argv))
    try:
        output = _checked_output(args.export_json, (args.baseline, args.current)) if args.export_json else None
        reports = []
        for label, path in (("baseline", args.baseline), ("current", args.current)):
            try:
                reports.append(load_report(path))
            except ReportError as exc:
                raise ReportError(f"{label} report: {exc}") from exc
        comparison = compare_reports(reports[0], reports[1], assume_same_target=args.assume_same_target)
    except ReportError as exc:
        print(f"[ERROR] {_printable(exc)}", file=sys.stderr)
        return 2
    for line in summary_lines(comparison):
        print(line)
    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("w", encoding="utf-8") as handle:
                json.dump(comparison, handle, indent=2, ensure_ascii=False, allow_nan=False)
                handle.write("\n")
        except OSError as exc:
            print(f"[ERROR] cannot write comparison JSON ({type(exc).__name__})", file=sys.stderr)
            return 2
        print(f"[OK] Comparison JSON: {_printable(output)}")
    return 0
