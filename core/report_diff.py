"""Offline comparison of two GrantTrace JSON scan reports.

``granttrace diff BASELINE.json CURRENT.json`` reads two reports with
``report_schema_version`` 2 and classifies every confirmed finding as new,
persisting, resolved or not comparable. Nothing is sent over the network.

A finding is identified by its check, its operation template and, where a check
produces several results per operation, its subject (BOPLA field rule and
identity, RBAC role, mass-assignment field). Targets, ports, times and concrete
resource values are not part of the identifier; they decide whether two results
are comparable.

A finding is only reported as resolved when the same check on the same subject
and scope now has a conclusive non-vulnerable verdict (SECURE, PUBLIC or
AUTHORIZED). A SKIPPED, INCONCLUSIVE, ERROR or SUSPICIOUS result, or a missing
one, never counts as a fix.

The comparison output holds identifiers, verdicts and enumerated reason codes
only: no evidence, response data, URLs, credentials or free text from the
reports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from core import __version__
from core.models import parse_operation_key, strict_json_loads

COMPARISON_SCHEMA_VERSION = 1
CONTEXT_VERSION = 1
MAX_REPORT_BYTES = 64 * 1024 * 1024

CONFIRMED = "CONFIRMED"
CONCLUSIVE_NEGATIVE = frozenset({"SECURE", "PUBLIC", "AUTHORIZED"})
KNOWN_VERDICTS = frozenset({"CONFIRMED", "SECURE", "PUBLIC", "AUTHORIZED",
                            "SUSPICIOUS", "INCONCLUSIVE", "SKIPPED", "ERROR"})
CHECK_CWE = {"BOLA": "CWE-639", "BROKEN_AUTH": "CWE-306", "BFLA": "CWE-285", "RBAC": "CWE-285",
             "BOPLA": "CWE-200", "BOPLA_EXPOSURE": "CWE-200", "MASS_ASSIGNMENT": "CWE-915"}
STATUS_ORDER = ("new", "not_comparable", "persisting", "resolved")

_CHECK_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_SUBJECT_LIMIT = 512

Key = Tuple[str, str, Optional[str]]


class ReportError(ValueError):
    """An input report cannot be used for comparison."""


# ---------------------------------------------------------------------------
# Identifiers and fingerprints


def finding_id(check: str, operation: str, subject: Optional[str] = None) -> str:
    """Stable identifier of a check result: independent of target, port, time and resource values."""
    material = "\0".join(("granttrace/finding/v1", check, operation, subject or ""))
    return "gtf_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _fingerprint(kind: str, value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(f"granttrace/{kind}/v1\0{canonical}".encode("utf-8")).hexdigest()[:16]


def _mask(value: Any, secrets: Tuple[str, ...]) -> Any:
    """Replace strings that contain a credential before anything is hashed."""
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


def _operation_fingerprints(policy: Mapping[str, Any], resources: Any) -> Dict[str, str]:
    return {"policy": _fingerprint("policy", policy), "resources": _fingerprint("resources", resources)}


_UNCONFIGURED_POLICY = {"bola": None, "bopla": None, "readback": None, "write_allowlisted": False}
DEFAULT_OPERATION_FINGERPRINTS = _operation_fingerprints(_UNCONFIGURED_POLICY, None)


def build_comparison_context(
    *,
    identities: Any,
    parameter_values: Any = None,
    bola_config: Any = None,
    bopla_config: Any = None,
    readback_config: Any = None,
    write_allowlist: Iterable[Any] = (),
    secret_values: Iterable[str] = (),
) -> Dict[str, Any]:
    """Describe what a scan compared, without credentials, for later comparability checks.

    Identities are fingerprinted from their account ``id``, ``role`` and
    identity parameters; tokens, headers and cookies are never included, and
    any string containing a known credential is masked before hashing.
    Operations are fingerprinted from their configured policy and resource
    values. Fingerprints are truncated SHA-256 digests of these non-credential
    values.
    """
    secrets = tuple(sorted({value for value in secret_values if isinstance(value, str) and value}))

    def identity_fingerprint(data: Any) -> Optional[str]:
        if not isinstance(data, Mapping):
            return None
        parameters = data.get("parameters") if isinstance(data.get("parameters"), Mapping) else {}
        material = {"id": data.get("id"), "role": data.get("role"), "parameters": parameters}
        if material["id"] is None and material["role"] is None and not parameters:
            return None
        return _fingerprint("identity", _mask(material, secrets))

    identity_map = identities if isinstance(identities, Mapping) else {}
    declared: Dict[str, Any] = {name: identity_fingerprint(identity_map.get(name))
                                for name in ("owner", "visitor", "anonymous")}
    roles = identity_map.get("roles")
    declared["roles"] = ({str(name): identity_fingerprint(data) for name, data in sorted(roles.items(), key=lambda item: str(item[0]))}
                         if isinstance(roles, Mapping) else {})

    parameters = _by_operation(parameter_values)
    bola = _by_operation(bola_config)
    bopla = _by_operation(bopla_config)
    readbacks = _by_operation(readback_config)
    allowlisted = {operation for operation in map(_canonical_operation, write_allowlist or ()) if operation}
    operations: Dict[str, Dict[str, str]] = {}
    for operation in sorted(set(parameters) | set(bola) | set(bopla) | set(readbacks) | allowlisted):
        policy = {"bola": bola.get(operation), "bopla": bopla.get(operation),
                  "readback": readbacks.get(operation), "write_allowlisted": operation in allowlisted}
        operations[operation] = _operation_fingerprints(_mask(policy, secrets),
                                                        _mask(parameters.get(operation), secrets))
    return {"version": CONTEXT_VERSION, "identities": declared, "operations": operations}


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
    """Path and query of an evidence URL; scheme, host and port are dropped."""
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
    context = report.get("comparison_context")
    if (isinstance(context, Mapping) and context.get("version") == CONTEXT_VERSION
            and isinstance(context.get("identities"), Mapping) and isinstance(context.get("operations"), Mapping)):
        return context
    return None


def _target_identity(value: Any) -> Optional[Tuple[str, str, str]]:
    """Scheme, host and base path of a report target; the port is ignored."""
    if not isinstance(value, str) or not value.startswith(("http://", "https://")):
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    return parts.scheme, host, parts.path.rstrip("/")


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


def compare_reports(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> Dict[str, Any]:
    """Compare two validated reports; see the module docstring for the rules."""
    old, new = _Index(baseline), _Index(current)
    old_context, new_context = _context(baseline), _context(current)
    basis = "declared" if old_context is not None and new_context is not None else "evidence"

    changes: List[Dict[str, Any]] = []
    notes: List[str] = []
    blocking: List[str] = []
    if baseline.get("tool_version") != current.get("tool_version"):
        changes.append({"kind": "tool_version", "baseline": baseline.get("tool_version"),
                        "current": current.get("tool_version"), "blocking": False})
    old_target, new_target = _target_identity(baseline.get("target")), _target_identity(current.get("target"))
    if old_target is None or new_target is None:
        notes.append("target_not_comparable_in_reports")
    elif old_target != new_target:
        changes.append({"kind": "target", "blocking": True})
        blocking.append("target_changed")
    if old_context is not None and new_context is not None:
        changed, undeclared = _identity_changes(old_context["identities"], new_context["identities"])
        if changed:
            changes.append({"kind": "identities", "identities": changed, "blocking": True})
            blocking.append("identities_changed")
        if undeclared:
            notes.append("identity_account_ids_not_declared")
    else:
        notes.append("identities_not_recorded_in_reports")
    added = sorted(new.operations - old.operations)
    removed = sorted(old.operations - new.operations)
    if added:
        changes.append({"kind": "operations_added", "count": len(added), "blocking": False})
    if removed:
        changes.append({"kind": "operations_removed", "count": len(removed), "blocking": False})
    if old.unreadable or new.unreadable:
        notes.append("unreadable_results_ignored")

    def operation_fingerprints(context: Optional[Mapping[str, Any]], operation: str) -> Mapping[str, Any]:
        entry = context["operations"].get(operation) if context is not None else None
        return entry if isinstance(entry, Mapping) else DEFAULT_OPERATION_FINGERPRINTS

    def scope_reasons(key: Key, left: _Entry, right: _Entry) -> List[str]:
        reasons = list(blocking)
        if basis == "declared":
            before, after = operation_fingerprints(old_context, key[1]), operation_fingerprints(new_context, key[1])
            if before.get("policy") != after.get("policy"):
                reasons.append("policy_changed")
            if before.get("resources") != after.get("resources"):
                reasons.append("resources_changed")
        elif not left.scopes or not right.scopes:
            reasons.append("scope_unknown")
        elif left.scopes != right.scopes:
            reasons.append("resources_changed")
        return reasons

    issues: List[Dict[str, Any]] = []
    for key in sorted(set(old.entries) | set(new.entries), key=lambda item: (item[1], item[0], item[2] or "")):
        before, after = old.entries.get(key), new.entries.get(key)
        if not ((before is not None and before.confirmed) or (after is not None and after.confirmed)):
            continue
        reasons: List[str] = []
        if after is not None and after.confirmed:
            if before is not None and before.confirmed:
                reasons = scope_reasons(key, before, after)
                status = "not_comparable" if reasons else "persisting"
            elif before is None:
                if key[1] not in old.operations:
                    reasons = list(blocking)
                    status = "not_comparable" if reasons else "new"
                    if not reasons:
                        reasons = ["operation_not_in_baseline"]
                else:
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
    summary["baseline_confirmed"] = sum(1 for entry in old.entries.values() if entry.confirmed)
    summary["current_confirmed"] = sum(1 for entry in new.entries.values() if entry.confirmed)
    return {
        "comparison_schema_version": COMPARISON_SCHEMA_VERSION,
        "tool_version": __version__,
        "baseline": {"tool_version": baseline.get("tool_version"), "generated_at": _plain(baseline.get("generated_at")),
                     "context": "declared" if old_context is not None else "absent"},
        "current": {"tool_version": current.get("tool_version"), "generated_at": _plain(current.get("generated_at")),
                    "context": "declared" if new_context is not None else "absent"},
        "comparability": {"basis": basis, "fully_comparable": not blocking, "changes": changes,
                          "notes": sorted(set(notes))},
        "summary": summary,
        "issues": issues,
        "coverage": {"baseline": old_stats, "current": new_stats, "decreased": coverage_decreased,
                     "conclusive_lost": lost, "conclusive_gained": gained,
                     "operations_added": len(added), "operations_removed": len(removed)},
    }


def _plain(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and len(value) <= 64 and value.isprintable() else None


# ---------------------------------------------------------------------------
# Command line


def _printable(value: Any) -> str:
    text = str(value)
    return "".join(character if character.isprintable() else f"\\u{ord(character):04x}" for character in text)


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
    blocking = [change["kind"] for change in comparability["changes"] if change.get("blocking")]
    if blocking:
        lines.append("Comparability: NOT fully comparable (" + ", ".join(blocking) + " changed)")
    else:
        lines.append(f"Comparability: comparable (basis: {comparability['basis']})")
    for change in comparability["changes"]:
        if change["kind"] == "tool_version":
            lines.append(f"  note: tool version changed from {_printable(change['baseline'])} "
                         f"to {_printable(change['current'])}")
        elif change["kind"] == "identities":
            lines.append("  identities changed: " + ", ".join(_printable(name) for name in change["identities"]))
    note_text = {
        "identities_not_recorded_in_reports": "identities are not recorded in one or both reports "
                                              "(reports from 2.7.1 or earlier); a change of test accounts "
                                              "cannot be detected",
        "identity_account_ids_not_declared": "owner/visitor have no account id in the configuration; "
                                             "a change of test accounts cannot be detected",
        "target_not_comparable_in_reports": "the report targets cannot be compared",
        "unreadable_results_ignored": "some result records could not be read and were ignored",
    }
    for note in comparability["notes"]:
        if note in note_text:
            lines.append("  note: " + note_text[note])
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
        lines.append("Not comparable findings are neither new nor fixed; see the reason codes.")
    return lines


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="granttrace diff",
        description=("Compare two GrantTrace JSON scan reports offline. Confirmed findings are classified as "
                     "new, persisting, resolved or not comparable; SKIPPED or INCONCLUSIVE results never count "
                     "as fixed. No network access; no evidence or response data is copied."),
    )
    parser.add_argument("baseline", metavar="BASELINE.json", help="Earlier GrantTrace JSON report (--export-json)")
    parser.add_argument("current", metavar="CURRENT.json", help="Later GrantTrace JSON report (--export-json)")
    parser.add_argument("--export-json", metavar="PATH", default=None,
                        help="Write the machine-readable comparison to PATH")
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
        comparison = compare_reports(reports[0], reports[1])
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
