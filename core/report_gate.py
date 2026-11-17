"""Optional CI security gate on a ``granttrace diff`` comparison.

``granttrace diff`` only classifies findings and exits 0 once the comparison is
done. With ``--fail-on-new``, ``--fail-on-coverage-decrease`` or
``--fail-on-not-comparable`` it also decides whether a pipeline may continue:

* exit 0: every enabled condition was shown to hold;
* exit 1: an enabled condition is violated, with comparable evidence;
* exit 2: invalid input or options, or an output could not be written;
* exit 3: an enabled condition could neither be shown to be violated nor to
  hold.

The gate fails closed. A condition only passes when the comparison has no
blocking reason, the current report holds at least one conclusive result, and
no assumption stated with ``--assume-*`` is involved, unless
``--gate-allow-assumptions`` says that such assumptions may count; a pass that
relies on them is labelled as such. Findings that are not comparable, results
without evidence and assumptions never count as verified.

``--fail-on-new`` does not pass merely because the current report has no new
confirmed finding: a confirmed finding that cannot be shown to be present in
the baseline, a check the baseline verified as not vulnerable that is no longer
conclusive, and a check that is now accepted (PUBLIC or AUTHORIZED) after its
specification, policy or resources changed all leave the condition unverified.

A pass means that the enabled conditions were not found. It does not show that
the API is secure: persisting findings, checks that neither scan verified,
report integrity and test data on the server are outside the gate.

The gate output holds the same kinds of values as the comparison: identifiers,
check names, operation templates, subjects, verdicts and enumerated reason
codes.
"""

from __future__ import annotations

import re
import secrets
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from core.report_diff import CONFIRMED, Key, ResultState, finding_id, resource_scope_issue

GATE_SCHEMA_VERSION = 1
CONDITIONS = ("new", "coverage_decrease", "not_comparable")
CONDITION_FLAGS = {"new": "--fail-on-new", "coverage_decrease": "--fail-on-coverage-decrease",
                   "not_comparable": "--fail-on-not-comparable"}
EXIT_PASSED, EXIT_FAILED, EXIT_INVALID, EXIT_UNVERIFIED = 0, 1, 2, 3
# Verdicts that accept access because a specification or policy declares it, rather than observe a denial.
DECLARED_ACCEPTANCE = frozenset({"PUBLIC", "AUTHORIZED"})

_REASON_ORDER = ("new_finding", "conclusive_check_lost", "coverage_pct_decreased", "confirmed_not_comparable",
                 "no_longer_verified", "accepted_after_declaration_change", "finding_not_comparable")
_CONDITION_LABEL = {"new": "new confirmed findings", "coverage_decrease": "conclusive coverage",
                    "not_comparable": "comparability of confirmed findings"}
_TERMINAL_ITEMS = 50
_SUMMARY_ROWS = 100
_ANNOTATIONS = 9
_CELL = 120
# Codes, check names and finding IDs that are plain words joined by single underscores need no escaping.
_PLAIN_CODE = re.compile(r"[A-Za-z0-9]+(?:_[A-Za-z0-9]+)*")
_MARKDOWN_PLAIN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /{}-")
_NOT_A_PROOF = ("A pass means that the enabled conditions were not found; it does not show that the API is "
                "secure. Reports are not authenticated, and test data on the server may differ between the scans.")
EXIT_CODES_LINE = "Gate exit codes: 0 passed, 1 regression found, 2 invalid input, 3 could not be verified."


# ---------------------------------------------------------------------------
# Evaluation


def _effective_status(issue: Mapping[str, Any], allow_assumptions: bool) -> str:
    """The comparison status, except that a conclusion resting on a disallowed assumption is not comparable."""
    if issue["status"] != "not_comparable" and issue.get("assumptions") and not allow_assumptions:
        return "not_comparable"
    return str(issue["status"])


def _issue_item(issue: Mapping[str, Any], reason: str, allow_assumptions: bool) -> Dict[str, Any]:
    item: Dict[str, Any] = {"reason": reason}
    for name in ("finding_id", "check", "operation", "subject"):
        if name in issue:
            item[name] = issue[name]
    item["baseline_verdicts"] = list(issue["baseline_verdicts"])
    item["current_verdicts"] = list(issue["current_verdicts"])
    if issue.get("reasons"):
        item["comparison_reasons"] = list(issue["reasons"])
    elif _effective_status(issue, allow_assumptions) != issue["status"]:
        item["comparison_reasons"] = ["assumptions_not_allowed"]
    if issue.get("assumptions") and allow_assumptions:
        item["assumptions"] = list(issue["assumptions"])
    return item


def _key_item(key: Key, before: Optional[ResultState], after: Optional[ResultState], reason: str) -> Dict[str, Any]:
    check, operation, subject = key
    item: Dict[str, Any] = {"reason": reason, "finding_id": finding_id(check, operation, subject), "check": check,
                            "operation": operation}
    if subject is not None:
        item["subject"] = subject
    item["baseline_verdicts"] = sorted(before.verdicts) if before is not None else []
    item["current_verdicts"] = sorted(after.verdicts) if after is not None else []
    return item


def _coverage_item(lost: Mapping[str, Any]) -> Dict[str, Any]:
    item: Dict[str, Any] = {"reason": "conclusive_check_lost"}
    for name in ("finding_id", "check", "operation", "subject", "baseline_verdicts", "current_verdicts"):
        if name in lost:
            item[name] = list(lost[name]) if isinstance(lost[name], list) else lost[name]
    return item


def _sort_items(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(items, key=lambda item: (_REASON_ORDER.index(item["reason"]), item.get("operation", ""),
                                           item.get("check", ""), item.get("subject", "")))


def _scope_changed(key: Key, before: ResultState, after: ResultState, changed: Iterable[str],
                   declared: bool) -> bool:
    """Whether the specification, policy or resources of a check are not shown unchanged.

    The rule compare_reports applies to findings: keyed fingerprints where the
    reports have them, and the evidence on either basis, judged by
    resource_scope_issue. Evidence URLs that differ in any way also count as a
    change here, so accepted access is never verified on a resource that only
    one report shows in readable form.
    """
    if key[1] in changed:
        return True
    if before.resources and after.resources:
        if (before.resources != after.resources
                or resource_scope_issue(before.resources, after.resources, declared=declared) is not None):
            return True
    elif not declared:
        return True
    return bool(before.policy and after.policy and before.policy != after.policy)


def _condition_result(regressions: List[Dict[str, Any]], unverified: List[Dict[str, Any]],
                      prerequisites_met: bool) -> str:
    if regressions:
        return "failed"
    if unverified or not prerequisites_met:
        return "unverified"
    return "passed"


def evaluate_gate(comparison: Mapping[str, Any], baseline: Mapping[Key, ResultState],
                  current: Mapping[Key, ResultState], *, conditions: Iterable[str],
                  allow_assumptions: bool = False) -> Dict[str, Any]:
    """Decide the enabled conditions for a comparison made by compare_reports.

    ``baseline`` and ``current`` are the result_states of the two reports that
    were compared. See the module docstring for the rules.
    """
    enabled = set(conditions)
    unknown = enabled - set(CONDITIONS)
    if unknown or not enabled:
        raise ValueError("unknown or no gate conditions")
    comparability = comparison["comparability"]
    assumptions = list(comparability["assumptions"])

    prerequisites: List[Dict[str, Any]] = []
    if comparability["blocking"]:
        prerequisites.append({"reason": "comparison_blocked", "blocking": list(comparability["blocking"])})
    if assumptions and not allow_assumptions:
        prerequisites.append({"reason": "assumptions_not_allowed", "assumptions": assumptions})
    if not any(state.conclusive for state in current.values()):
        prerequisites.append({"reason": "no_conclusive_results"})
    met = not prerequisites
    issues = comparison["issues"]

    results: List[Dict[str, Any]] = []
    for condition in CONDITIONS:
        if condition not in enabled:
            continue
        regressions: List[Dict[str, Any]] = []
        unverified: List[Dict[str, Any]] = []
        if condition == "new":
            for issue in issues:
                status = _effective_status(issue, allow_assumptions)
                if status == "new":
                    regressions.append(_issue_item(issue, "new_finding", allow_assumptions))
                elif CONFIRMED in issue["current_verdicts"] and status != "persisting":
                    unverified.append(_issue_item(issue, "confirmed_not_comparable", allow_assumptions))
            changed = {item["operation"] for item in comparability["operation_changes"]}
            declared = comparability["basis"] == "declared"
            for key, before in baseline.items():
                if not before.conclusive_negative:
                    continue
                after = current.get(key)
                if after is None or not after.conclusive:
                    unverified.append(_key_item(key, before, after, "no_longer_verified"))
                elif (not after.confirmed and (after.verdicts & DECLARED_ACCEPTANCE) - before.verdicts
                      and _scope_changed(key, before, after, changed, declared)):
                    unverified.append(_key_item(key, before, after, "accepted_after_declaration_change"))
        elif condition == "coverage_decrease":
            coverage = comparison["coverage"]
            regressions.extend(_coverage_item(lost) for lost in coverage["conclusive_lost"])
            old_pct = coverage["baseline"].get("conclusive_coverage_pct")
            new_pct = coverage["current"].get("conclusive_coverage_pct")
            if old_pct is not None and new_pct is not None and new_pct < old_pct:
                regressions.append({"reason": "coverage_pct_decreased", "baseline_pct": old_pct,
                                    "current_pct": new_pct})
        else:
            unverified.extend(_issue_item(issue, "finding_not_comparable", allow_assumptions) for issue in issues
                              if _effective_status(issue, allow_assumptions) == "not_comparable")
        if not met:
            # A change seen between reports that are not shown to be comparable is not a proven regression.
            unverified, regressions = regressions + unverified, []
        results.append({"condition": condition, "flag": CONDITION_FLAGS[condition],
                        "result": _condition_result(regressions, unverified, met),
                        "regressions": _sort_items(regressions), "unverified": _sort_items(unverified)})

    outcomes = {item["result"] for item in results}
    result = "failed" if "failed" in outcomes else "unverified" if "unverified" in outcomes else "passed"
    relied = assumptions if allow_assumptions else []
    return {
        "gate_schema_version": GATE_SCHEMA_VERSION,
        "result": result,
        "exit_code": {"failed": EXIT_FAILED, "unverified": EXIT_UNVERIFIED, "passed": EXIT_PASSED}[result],
        # True when the result rests on the reports alone, without any assumption stated by the caller.
        "verified": result != "unverified" and not relied,
        "allow_assumptions": allow_assumptions,
        "relies_on_assumptions": relied,
        "prerequisites": prerequisites,
        "conditions": results,
    }


# ---------------------------------------------------------------------------
# Terminal


def _ascii(value: Any) -> str:
    """Printable ASCII only; anything else is escaped."""
    return "".join(character if " " <= character <= "~" else f"\\u{ord(character):04x}" for character in str(value))


def _describe_item(item: Mapping[str, Any]) -> str:
    if item["reason"] == "coverage_pct_decreased":
        return f"conclusive coverage {item['baseline_pct']}% -> {item['current_pct']}%"
    text = f"{item['finding_id']} {item['check']} {_ascii(item['operation'])}"
    if item.get("subject"):
        text += f" [{_ascii(item['subject'])}]"
    return text


def _item_line(condition: str, kind: str, item: Mapping[str, Any]) -> str:
    detail = item["reason"]
    if item.get("comparison_reasons"):
        detail += ": " + ", ".join(item["comparison_reasons"])
    line = f"  {kind:<11} [{condition}] {_describe_item(item)} ({detail})"
    if item.get("assumptions"):
        line += " [assumed: " + ", ".join(item["assumptions"]) + "]"
    return line


def _prerequisite_text(prerequisite: Mapping[str, Any], join: Callable[[Sequence[str]], str] = ", ".join) -> str:
    if prerequisite["reason"] == "comparison_blocked":
        return "the reports are not comparable (" + join(prerequisite["blocking"]) + ")"
    if prerequisite["reason"] == "assumptions_not_allowed":
        return ("the comparison relies on assumptions (" + join(prerequisite["assumptions"])
                + "); add --gate-allow-assumptions only if they may decide the gate")
    return "the current report holds no conclusive result"


def gate_lines(gate: Mapping[str, Any]) -> List[str]:
    flags = ", ".join(item["flag"] for item in gate["conditions"])
    headline = {"failed": "FAILED, a regression was found", "unverified": "NOT VERIFIED",
                "passed": "PASSED"}[gate["result"]]
    lines = [f"Security gate ({flags}): {headline} (exit {gate['exit_code']})"]
    for prerequisite in gate["prerequisites"]:
        lines.append("  cannot pass: " + _prerequisite_text(prerequisite))
    for item in gate["conditions"]:
        counts = []
        if item["regressions"]:
            counts.append(f"{len(item['regressions'])} regression(s)")
        if item["unverified"]:
            counts.append(f"{len(item['unverified'])} not verified")
        lines.append(f"  {_CONDITION_LABEL[item['condition']]}: {item['result'].upper()}"
                     + (" (" + ", ".join(counts) + ")" if counts else ""))
    entries = [(item["condition"], "REGRESSION", entry) for item in gate["conditions"] for entry in item["regressions"]]
    entries += [(item["condition"], "UNVERIFIED", entry) for item in gate["conditions"] for entry in item["unverified"]]
    lines.extend(_item_line(condition, kind, entry) for condition, kind, entry in entries[:_TERMINAL_ITEMS])
    if len(entries) > _TERMINAL_ITEMS:
        lines.append(f"  ... {len(entries) - _TERMINAL_ITEMS} more; see --export-json")
    if gate["relies_on_assumptions"]:
        lines.append("  This result relies on assumptions stated by the caller, not on verification: "
                     + ", ".join(gate["relies_on_assumptions"]) + ".")
    lines.append(EXIT_CODES_LINE)
    lines.append(_NOT_A_PROOF)
    return lines


# ---------------------------------------------------------------------------
# GitHub Actions


def stop_commands_token() -> str:
    """A token for ::stop-commands::, so that no text taken from a report runs as a workflow command."""
    return "granttrace-" + secrets.token_hex(16)


def _command_data(value: str) -> str:
    """Escape the data of a workflow command (the text after the second ::)."""
    return _ascii(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _annotation(level: str, message: str) -> str:
    return f"::{level} title=GrantTrace security gate::{_command_data(message)}"


def github_annotations(gate: Mapping[str, Any]) -> List[str]:
    """Workflow commands for the gate result: errors for regressions, warnings for what was not verified."""
    regressions = [(item["condition"], entry) for item in gate["conditions"] for entry in item["regressions"]]
    unverified = [(item["condition"], entry) for item in gate["conditions"] for entry in item["unverified"]]
    lines = [_annotation("error", f"[{condition}] regression: {_describe_item(entry)} ({entry['reason']})")
             for condition, entry in regressions[:_ANNOTATIONS]]
    lines += [_annotation("warning", f"[{condition}] not verified: {_describe_item(entry)} ({entry['reason']})")
              for condition, entry in unverified[:_ANNOTATIONS]]
    hidden = max(0, len(regressions) - _ANNOTATIONS) + max(0, len(unverified) - _ANNOTATIONS)
    more = f" {hidden} more item(s) in the log and the step summary." if hidden else ""
    if gate["result"] == "failed":
        lines.append(_annotation("error", f"Gate failed (exit 1): a regression was found.{more}"))
    elif gate["result"] == "unverified":
        reasons = "; ".join(_prerequisite_text(item) for item in gate["prerequisites"])
        lines.append(_annotation("error", "Gate not verified (exit 3): the enabled conditions could not be shown "
                                 f"to hold{': ' + reasons if reasons else ''}.{more}"))
    elif gate["relies_on_assumptions"]:
        lines.append(_annotation("warning", "Gate passed (exit 0) relying on assumptions stated by the caller, not "
                                 "on verification: " + ", ".join(gate["relies_on_assumptions"]) + "."))
    else:
        lines.append(_annotation("notice", "Gate passed (exit 0): the enabled conditions were not found. This does "
                                 "not show that the API is secure."))
    return lines


def _cell(value: Any) -> str:
    """Report text for a Markdown table cell: only letters, digits, spaces and / { } - stay literal."""
    text = _ascii(value)
    if len(text) > _CELL:
        text = text[:_CELL] + "..."
    return "".join(character if character in _MARKDOWN_PLAIN else f"&#{ord(character)};" for character in text)


def _code(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 64 and _PLAIN_CODE.fullmatch(text) else _cell(text)


def _codes(values: Sequence[str]) -> str:
    return ", ".join(_code(value) for value in values) if values else "-"


def _number(value: Any) -> str:
    return repr(float(value)) if isinstance(value, (int, float)) and not isinstance(value, bool) else "?"


def _coverage(coverage: Mapping[str, Any]) -> str:
    old, new = coverage["baseline"].get("conclusive_coverage_pct"), coverage["current"].get("conclusive_coverage_pct")
    text = "not recorded" if old is None or new is None else f"{_number(old)}% -> {_number(new)}%"
    return text + (" (decreased)" if coverage["decreased"] else "")


def github_step_summary(comparison: Mapping[str, Any], gate: Optional[Mapping[str, Any]]) -> str:
    """A Markdown summary for $GITHUB_STEP_SUMMARY. Text from the reports is entity-encoded."""
    summary, comparability, coverage = comparison["summary"], comparison["comparability"], comparison["coverage"]
    lines: List[str] = []
    if gate is None:
        lines.append("## GrantTrace report comparison")
    else:
        headline = {"failed": "FAILED", "unverified": "NOT VERIFIED", "passed": "PASSED"}[gate["result"]]
        lines.append(f"## GrantTrace security gate: {headline} (exit {gate['exit_code']})")
    lines.append("")
    if comparability["blocking"]:
        state = "not comparable (" + _codes(comparability["blocking"]) + ")"
    elif comparability["fully_comparable"]:
        state = "fully comparable"
    else:
        state = "limited"
    lines.append(f"- Comparability: {state}; basis {_code(comparability['basis'])}")
    lines.append("- Assumptions stated by the caller: " + _codes(comparability["assumptions"])
                 + ("" if gate is None or not comparability["assumptions"]
                    else " (allowed in the gate)" if gate["allow_assumptions"] else " (not allowed in the gate)"))
    lines.append(f"- Confirmed findings: {int(summary['new'])} new, {int(summary['persisting'])} persisting, "
                 f"{int(summary['resolved'])} resolved, {int(summary['not_comparable'])} not comparable")
    lines.append("- Conclusive coverage: " + _coverage(coverage))
    rows: List[str] = []
    if gate is not None:
        for prerequisite in gate["prerequisites"]:
            lines.append("- Cannot pass: " + _prerequisite_text(prerequisite, _codes))
        lines += ["", "| Condition | Option | Result |", "|---|---|---|"]
        lines += [f"| {_CONDITION_LABEL[item['condition']]} | {item['flag']} | {item['result'].upper()} |"
                  for item in gate["conditions"]]
        header = ["| Result | Condition | Reason | Finding | Check | Operation | Subject |",
                  "|---|---|---|---|---|---|---|"]
        for item in gate["conditions"]:
            for kind, entries in (("REGRESSION", item["regressions"]), ("NOT VERIFIED", item["unverified"])):
                for entry in entries:
                    if entry["reason"] == "coverage_pct_decreased":
                        rows.append(f"| {kind} | {item['condition']} | {entry['reason']} | - | - | "
                                    f"conclusive coverage {_number(entry['baseline_pct'])}% -> "
                                    f"{_number(entry['current_pct'])}% | - |")
                        continue
                    reason = _code(entry["reason"]) + (" (" + _codes(entry["comparison_reasons"]) + ")"
                                                       if entry.get("comparison_reasons") else "")
                    rows.append(f"| {kind} | {item['condition']} | {reason} | {_code(entry['finding_id'])} | "
                                f"{_code(entry['check'])} | {_cell(entry['operation'])} | "
                                f"{_cell(entry['subject']) if 'subject' in entry else '-'} |")
    else:
        header = ["| Status | Finding | Check | Operation | Subject | Reasons |", "|---|---|---|---|---|---|"]
        rows = [f"| {_code(issue['status'])} | {_code(issue['finding_id'])} | {_code(issue['check'])} | "
                f"{_cell(issue['operation'])} | {_cell(issue['subject']) if 'subject' in issue else '-'} | "
                f"{_codes(issue.get('reasons', []))} |"
                for issue in comparison["issues"]]
    if rows:
        lines += ["", *header, *rows[:_SUMMARY_ROWS]]
        if len(rows) > _SUMMARY_ROWS:
            lines.append(f"\n{len(rows) - _SUMMARY_ROWS} more row(s) are in the comparison JSON (--export-json).")
    if gate is not None and gate["relies_on_assumptions"]:
        lines += ["", "This result relies on assumptions stated by the caller, not on verification: "
                  + _codes(gate["relies_on_assumptions"]) + "."]
    lines += ["", _NOT_A_PROOF if gate is not None else
              "Reports are not authenticated, and test data on the server may differ between the scans.", ""]
    return "\n".join(lines) + "\n"

