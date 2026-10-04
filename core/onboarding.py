"""Display-only guidance for local configuration preparation.

Accept paths, validation counts and an existing plan, never configuration
contents, identities or auditor objects. No I/O or policy inference occurs here.
"""

from __future__ import annotations

import os
import shlex
from typing import Mapping, Optional, Sequence

from core.config_validator import ValidationSummary
from core.evidence import sanitize_log_text, sanitize_text


def display_path(value: str) -> str:
    text = sanitize_log_text(sanitize_text(value))
    return "".join(character if character.isprintable() else
                   (f"\\u{ord(character):04x}" if ord(character) <= 0xffff else f"\\U{ord(character):08x}")
                   for character in text)


def format_cli_command(argv: Sequence[str], platform: Optional[str] = None) -> str:
    """Format display-only POSIX or PowerShell 7 commands, with no raw controls.

    Windows uses PowerShell literal strings, not CMD quoting: list2cmdline only
    escapes native argv and does not protect CMD metacharacters. PowerShell's
    smart single quotes must also be doubled to prevent leaving a string.
    """
    selected = ("windows" if os.name == "nt" else "posix") if platform is None else platform
    if selected not in {"windows", "posix"}:
        raise ValueError("Command display platform must be posix or windows")
    arguments = []
    for argument in argv:
        if any(not character.isprintable() for character in argument):
            arguments.append("<PATH_WITH_CONTROL_CHARACTERS>")
        else:
            safe = sanitize_text(argument)
            arguments.append(safe if safe == argument else "<PATH_REQUIRING_MANUAL_INPUT>")
    if selected == "posix":
        return shlex.join(arguments)
    quoted = ["'" + "".join(c * 2 if c in "'\u2018\u2019\u201a\u201b" else c for c in arg) + "'"
              for arg in arguments]
    return "& " + " ".join(quoted)


def _command(argv: Sequence[str]) -> str:
    shell = "PowerShell 7" if os.name == "nt" else "POSIX shell"
    return "       " + format_cli_command(argv) + f" # {shell}"


def _arguments(spec_path: Optional[str], config_path: Optional[str]) -> list[str]:
    argv = ["granttrace", "--spec", spec_path if spec_path is not None else "<OPENAPI_FILE>"]
    if config_path is not None:
        argv.extend(("--config", config_path))
    return argv


def _first_scan(spec_path: Optional[str], config_path: Optional[str]) -> list[str]:
    return [
        "[NEXT] Recommended first real scan (read-only; sends requests to an authorized test target):",
        _command([*_arguments(spec_path, config_path), "--target", "<AUTHORIZED_TARGET_URL>",
                  "--export-json", "result.local.json"]),
        "[SAFETY] Active write mode remains an explicit separate decision; this command has no --allow-write-tests.",
    ]


def init_guidance(spec_path: str, config_path: str, checklist_path: str) -> list[str]:
    return [
        "[REVIEW] This is intentionally incomplete. No credentials, resource ownership, authorization policy, "
        "readback guarantee or write permission was inferred.",
        "[SAFE DEFAULT] write_allowlist is empty. No active PATCH test has been authorized.",
        "[NOTE] Local-only preparation: no requests were sent.",
        "[NEXT] 1. Open the configuration and checklist: " + display_path(checklist_path),
        "[NEXT] 2. Fill Owner / Visitor test identities and real disposable resource values.",
        "[NEXT] 3. Review BOLA expectations and PATCH readback mappings manually; contract hints are not guarantees.",
        "[NEXT] 4. Replace all __GRANTTRACE_INPUT__: placeholders.",
        "[NEXT] 5. Remove _granttrace_draft only after completing review.",
        "[NEXT] Validate offline:",
        _command([*_arguments(spec_path, config_path), "--validate-config"]),
        "[NEXT] After validation, inspect the local plan:",
        _command([*_arguments(spec_path, config_path), "--dry-run", "--export-json", "plan.local.json"]),
    ]


def validation_failure_guidance(
    spec_path: Optional[str], config_path: Optional[str], errors: int, warnings: int,
) -> list[str]:
    return [
        f"[SUMMARY] {errors} error(s), {warnings} warning(s).",
        "[NEXT] Review identities, resource IDs in parameter_values, and independent GET readback mappings. "
        "Access expectations must come from your API's business rules.",
        "[NEXT] Fix the issues above, then rerun offline validation:",
        _command([*_arguments(spec_path, config_path), "--validate-config"]),
        "[NEXT] After editing, run --validate-config, then --dry-run with the same files. Both checks are offline.",
    ]


def validation_guidance(
    spec_path: Optional[str], config_path: str, summary: ValidationSummary,
) -> list[str]:
    if spec_path is None:
        lines = [
            "[OK] Configuration-only validation passed.",
            "[NOTE] No OpenAPI specification was selected; operation/spec cross-checking was not performed.",
            "[NEXT] Run again with --spec before relying on dry-run/scan preparation:",
            _command([*_arguments(None, config_path), "--validate-config"]),
        ]
    else:
        lines = [
            "[OK] Offline configuration validation passed.",
            "[SCOPE] Configuration + selected OpenAPI specification were checked together: " + display_path(spec_path),
            "[SCOPE] Checked configured operation keys, specification authentication headers, and explicit path/query "
            "parameter values against supported schemas.",
            "[NOTE] Independent GET readbacks absent from the specification produce a warning and require manual verification.",
        ]
    lines.append("[NOTE] Validation is offline: no requests were sent, including no PATCH.")
    if summary.warnings_count:
        lines.append(f"[WARN] Configuration passed with {summary.warnings_count} warning(s).")
    if summary.allowlisted_endpoints:
        lines.extend((
            "[MODE] Active PATCH configuration is present; it is not enabled by this validation.",
            f"       Allowlisted PATCH operations: {summary.allowlisted_endpoints}; readback mappings: {summary.readbacks_count}.",
            "[SAFETY] These entries remain inactive unless --allow-write-tests is explicitly supplied during a real scan. "
            "Runtime safety and recovery conditions still apply.",
        ))
    else:
        lines.extend(("[MODE] Read-only first-run path.", "       No PATCH operation is allowlisted."))
    lines.append(
        "[NOTE] Offline validation checks configuration structure and supported semantics only. It does not prove "
        "resource ownership, intended authorization policy, legal permission to test, real-target readback consistency "
        "or rollback safety."
    )
    if spec_path is not None:
        lines.extend(("[NEXT] Review the request plan locally:",
                      _command([*_arguments(spec_path, config_path), "--dry-run", "--export-json", "plan.local.json"])))
        lines.extend(_first_scan(spec_path, config_path))
    return lines


def plan_guidance(
    spec_path: str, config_path: Optional[str], plan: Mapping[str, object],
) -> list[str]:
    raw_operations = plan.get("operations")
    operations = [item for item in raw_operations if isinstance(item, Mapping)] if isinstance(raw_operations, list) else []
    bola = sum(item.get("check") == "BOLA" for item in operations)
    mass = sum(item.get("check") == "MASS_ASSIGNMENT" for item in operations)
    writes = sum(item.get("writes_enabled") is True for item in operations)
    lines = [
        "[PLAN] Local-only dry run complete.",
        "[PLAN] Requests sent: 0 (no GET, PATCH, login, DNS or connectivity probe).",
        f"[PLAN] Operations: {len(operations)}",
        f"[PLAN] BOLA checks: {bola}",
        f"[PLAN] Mass Assignment checks: {mass}",
        f"[PLAN] Write-enabled operations in this plan: {writes}",
    ]
    if writes:
        lines.extend((
            f"[CAUTION] Dry-run itself sent 0 requests. {writes} PATCH operation(s) would become eligible for active "
            "testing in a real scan because both the configuration allowlist and --allow-write-tests are present.",
            "[REVIEW] Before any active test, review disposable test resources, independent GET readback, field_map, "
            "consistency and rollback expectations. Runtime safety conditions still apply.",
        ))
    else:
        lines.append("[MODE] Read-only plan: no active PATCH testing is enabled.")
    lines.append("[NOTE] This local plan does not prove business authorization, readback reliability or rollback safety.")
    lines.extend(_first_scan(spec_path, config_path))
    return lines
