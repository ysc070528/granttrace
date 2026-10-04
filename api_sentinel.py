# -*- coding: utf-8 -*-
"""Command-line entry point for GrantTrace."""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from core import __version__
from core.auditor import APISentinelAuditor
from core.config_scaffold import config_needs_input, write_config_scaffold
from core.config_validator import ConfigIssue, ConfigValidator
from core.evidence import safe_diagnostic_value, sanitize_log_text, sanitize_text
from core.models import parse_operation_key
from core.onboarding import (
    display_path, init_guidance, plan_guidance, validation_failure_guidance, validation_guidance,
)
from core.parser import OpenAPIParser
from core.reporter import SecurityReportGenerator
from core.reproduction import build_reproduction_templates
from core.sarif import SarifReportGenerator


BANNER = rf"""
 ###  ## #   ###  #  #  ##### ##### ## #   ###   ###  ####
 #    #  #  #  #  ## #    #     #   #  #  #  #  #     #
 # ## ##    ####  # ##    #     #   ##    ####  #     ###
 #  # # #   #  #  #  #    #     #   # #   #  #  #     #
 ###  #  #  #  #  #  #    #     #   #  #  #  #   ###  ####
             safety-first API authorization auditing  v{__version__}
"""


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safety-first OpenAPI authorization and mass-assignment auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Built-in local demo: granttrace demo (no spec, config or credentials needed)\n\n"
                "Recommended onboarding (local preparation before any target requests):\n"
                "  1. granttrace --spec API.yaml --init-config config.local.json\n"
                "  2. Review and fill the config + checklist manually.\n"
                "  3. granttrace --spec API.yaml --config config.local.json --validate-config\n"
                "  4. granttrace --spec API.yaml --config config.local.json --dry-run\n"
                "  5. Start with a read-only real scan; active PATCH is a separate explicit decision."),
    )
    parser.add_argument("--spec", "-s", default=None,
                        help="OpenAPI/Swagger JSON or YAML (default: openapi.json)")
    parser.add_argument(
        "--target", "-t", default="http://127.0.0.1:8080", help="Target API base URL"
    )
    parser.add_argument("--config", "-c", default=None, help="Identity and readback JSON config")
    parser.add_argument(
        "--init-config", metavar="CONFIG.json", default=None,
        help="Create an incomplete offline config and companion checklist from --spec; never overwrite files",
    )
    parser.add_argument("--workers", "-w", type=int, default=4, help="Concurrent read-only checks")
    parser.add_argument(
        "--delay",
        "-d",
        type=float,
        default=0.05,
        help="Global minimum delay between requests in seconds",
    )
    parser.add_argument("--timeout", type=float, default=6.0, help="Per-request timeout in seconds")
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=1024 * 1024,
        help="Maximum response bytes retained per request",
    )
    parser.add_argument(
        "--output", "-o", default="granttrace_report.html", help="HTML report path (default: granttrace_report.html)"
    )
    parser.add_argument("--export-json", default=None, help="Optional machine-readable JSON report")
    parser.add_argument("--export-sarif", default=None,
                        help="Optional SARIF 2.1.0 report containing confirmed vulnerabilities only")
    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification for an isolated test environment",
    )
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="Allow clear-text HTTP to non-loopback targets",
    )
    parser.add_argument(
        "--allow-write-tests",
        action="store_true",
        help="Enable allowlisted PATCH mass-assignment checks with readback and rollback",
    )
    parser.add_argument(
        "--write-endpoint",
        action="append",
        default=[],
        metavar="'PATCH /path'",
        help="Allow one PATCH operation for active testing; repeat as needed",
    )
    parser.add_argument(
        "--include-sensitive-evidence",
        action="store_true",
        help="Retain sensitive response fields in reports instead of redacting them",
    )
    parser.add_argument(
        "--fail-on-vuln",
        action="store_true",
        help="Exit 1 when a vulnerability is confirmed",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Exit 2 on errors, inconclusive results, or no conclusive checks",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Print/export a local-only plan without sending any target requests")
    parser.add_argument("--min-coverage", type=float, default=0.0, metavar="PERCENT",
                        help="Require this percentage of endpoints to have conclusive results; exit 2 otherwise")
    parser.add_argument("--fail-on-suspicious", action="store_true",
                        help="Exit 2 if any result remains suspicious")
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration syntax and semantics offline without network activity",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"GrantTrace {__version__}",
        help="Show program version and exit",
    )
    return parser


def _reject_constant(val: str) -> None:
    raise ValueError(f"Non-standard JSON number not allowed: {val}")


_MISSING_FILE_GUIDANCE = (
    "For the built-in local demo, run 'granttrace demo'. "
    "For your own API, select a local OpenAPI file and create a draft with "
    "'granttrace --spec <openapi-file> --init-config config.local.json'."
)


def _print_onboarding(lines: Sequence[str]) -> None:
    for line in lines:
        print(line, file=sys.stderr)


def _onboarding_private_values(config: Any) -> tuple[str, ...]:
    """Collect local privacy values for output only, including malformed branches.

    Never pass these values or configuration objects into the onboarding helper.
    The existing evidence sanitizer handles schemes, cookies and encoded echoes.
    """
    if not isinstance(config, dict):
        pending = [config]
    else:
        pending = [config.get("parameter_values")]
        identities = config.get("identities")
        if isinstance(identities, dict):
            for identity in identities.values():
                if isinstance(identity, dict):
                    pending.extend(identity.get(key) for key in ("id", "token", "headers", "parameters"))
                else:
                    pending.append(identity)
        else:
            pending.append(identities)
        readbacks = config.get("readbacks")
        if isinstance(readbacks, dict):
            for readback in readbacks.values():
                if isinstance(readback, dict):
                    pending.extend(readback.get(key) for key in ("parameters", "parameter_values", "baseline_payload"))
                else:
                    pending.append(readback)
        else:
            pending.append(readbacks)
    values = set()
    seen = set()
    while pending:
        item = pending.pop()
        if isinstance(item, (dict, list)):
            if id(item) in seen:
                continue
            seen.add(id(item))
            pending.extend(item.values() if isinstance(item, dict) else item)
        elif isinstance(item, str) and item:
            values.add(item)
            # Diagnostics may quote, escape or truncate a private string before
            # output. Include the existing formatter's exact representation so
            # a prefix cannot bypass full-value substitution at this boundary.
            values.add(safe_diagnostic_value(item))
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            values.add(str(item))
    return tuple(values)


def _next_path(path: Optional[str], private_values: Sequence[str] = ()) -> Optional[str]:
    if path is None:
        return None
    if sanitize_text(path, secret_values=private_values) != path:
        return "<PATH_REQUIRING_MANUAL_INPUT>"
    if any(not character.isprintable() for character in path):
        return "<PATH_WITH_CONTROL_CHARACTERS>"
    return path


def _format_private_issue(issue: ConfigIssue, private_values: Sequence[str]) -> str:
    # Keep trusted diagnostic labels readable even when a private value is a
    # single character. Only the formatted field contents are untrusted.
    prefixes = ("  - Path: ", "  [WARN] ", "    Reason:   ", "    Expected: ",
                "    Actual:   ", "    Tip:      ")
    lines = []
    for line in issue.format().split("\n"):
        prefix = next((value for value in prefixes if line.startswith(value)), "")
        contents = line[len(prefix):]
        lines.append(prefix + display_path(sanitize_text(contents, secret_values=private_values)))
    return "\n".join(lines)


def _print_issues(issues: Sequence[ConfigIssue], private_values: Sequence[str]) -> None:
    for issue in issues:
        print(_format_private_issue(issue, private_values), file=sys.stderr)


def _print_validation_failure(
    spec_path: Optional[str], config_path: Optional[str], errors: int = 1, warnings: int = 0,
    private_values: Sequence[str] = (),
) -> None:
    _print_onboarding(validation_failure_guidance(
        _next_path(spec_path, private_values), _next_path(config_path, private_values), errors, warnings,
    ))


def _load_spec(path: str) -> Dict[str, Any]:
    """Use the scanner's local JSON/YAML loader for both preflight modes."""
    try:
        return OpenAPIParser(path).raw_spec
    except FileNotFoundError as exc:
        raise ValueError(f"Cannot load specification '{path}': {exc}. {_MISSING_FILE_GUIDANCE}") from exc
    except Exception as exc:
        raise ValueError(f"Cannot load specification '{path}': {exc}") from exc


def _reject_incomplete_draft(config: Any) -> None:
    if config_needs_input(config):
        raise ValueError(
            "Configuration draft needs user input. Complete the companion checklist, replace all "
            "__GRANTTRACE_INPUT__: placeholders, and remove _granttrace_draft after reviewing identities, "
            "resources, authorization policy, and any write/readback mappings. No requests were sent."
        )


def run_config_validation(config_path_str: str, spec_path: Optional[str] = None) -> int:
    config_file = Path(config_path_str)
    safe_path_str = display_path(config_path_str)
    if not config_file.is_file():
        print(f"[ERROR] Configuration file does not exist: {safe_path_str}", file=sys.stderr)
        print("[NEXT] " + _MISSING_FILE_GUIDANCE, file=sys.stderr)
        _print_validation_failure(spec_path, config_path_str)
        return 2
    try:
        with config_file.open("r", encoding="utf-8") as handle:
            raw_data = json.load(handle, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        safe_err = display_path(str(exc))
        print(f"[ERROR] Failed to parse JSON configuration '{safe_path_str}': {safe_err}", file=sys.stderr)
        _print_validation_failure(spec_path, config_path_str)
        return 2
    except UnicodeDecodeError as exc:
        safe_err = display_path(str(exc))
        print(f"[ERROR] Configuration file must be valid UTF-8: {safe_err}", file=sys.stderr)
        _print_validation_failure(spec_path, config_path_str)
        return 2
    except OSError as exc:
        safe_err = display_path(str(exc))
        print(f"[ERROR] Cannot read configuration file '{safe_path_str}': {safe_err}", file=sys.stderr)
        _print_validation_failure(spec_path, config_path_str)
        return 2
    except Exception as exc:
        safe_err = display_path(f"{type(exc).__name__}: {exc}")
        print(f"[ERROR] Unexpected error inspecting configuration: {safe_err}", file=sys.stderr)
        _print_validation_failure(spec_path, config_path_str)
        return 2

    private_values = _onboarding_private_values(raw_data)
    safe_path_str = display_path(sanitize_text(config_path_str, secret_values=private_values))
    try:
        _reject_incomplete_draft(raw_data)
    except ValueError as exc:
        print("[ERROR] " + str(exc), file=sys.stderr)
        _print_validation_failure(spec_path, config_path_str, private_values=private_values)
        return 2

    # Config-only validation remains available without a default specification.
    # An explicitly selected specification must load successfully.
    selected_spec = spec_path if spec_path is not None else (
        "openapi.json" if Path("openapi.json").is_file() else None
    )
    try:
        raw_spec = _load_spec(selected_spec) if selected_spec is not None else None
    except ValueError as exc:
        print("[ERROR] " + display_path(sanitize_text(str(exc), secret_values=private_values)), file=sys.stderr)
        _print_validation_failure(selected_spec, config_path_str, private_values=private_values)
        return 2

    result = ConfigValidator.validate(raw_data, raw_spec=raw_spec)
    if not result.is_valid:
        error_word = "error" if result.summary.errors_count == 1 else "errors"
        print(
            f"[ERROR] Configuration validation failed for '{safe_path_str}' "
            f"({result.summary.errors_count} {error_word} found):",
            file=sys.stderr,
        )
        _print_issues(result.errors, private_values)
        if result.warnings:
            print(f"[WARN] In addition, {result.summary.warnings_count} warning(s) observed:", file=sys.stderr)
            _print_issues(result.warnings, private_values)
        _print_validation_failure(selected_spec, config_path_str, result.summary.errors_count,
                                  result.summary.warnings_count, private_values)
        return 2

    print(f"[OK] Configuration is valid: {safe_path_str}")
    print(f"     - Identities:        {result.summary.identities_count} configured (owner, visitor, anonymous)")
    print(f"     - Write allowlist:   {result.summary.allowlisted_endpoints} endpoint(s)")
    print(f"     - Readbacks:         {result.summary.readbacks_count} mapped endpoint(s)")
    print(f"     - Parameter values:  {result.summary.parameter_endpoints} endpoint(s)")
    print(f"     - BOLA policies:     {result.summary.bola_policies_count} operation(s)")
    if result.warnings:
        for warning in result.warnings:
            print(_format_private_issue(warning, private_values))
    _print_onboarding(validation_guidance(
        _next_path(selected_spec, private_values), _next_path(config_path_str, private_values) or "<CONFIG_FILE>",
        result.summary,
    ))
    return 0


def _load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    config_path = Path(path)
    if not config_path.is_file():
        raise ValueError(f"configuration file does not exist: {path}. {_MISSING_FILE_GUIDANCE}")
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            config = json.load(handle, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise ValueError(f"configuration file must be valid UTF-8: {exc}") from exc
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"cannot read configuration '{path}': {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("configuration root must be a JSON object")
    _reject_incomplete_draft(config)
    return config


def _ensure_parent(path: str) -> None:
    parent = Path(path).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)


def _paths_alias(left: Path, right: Path) -> bool:
    return left == right or (left.exists() and right.exists() and left.samefile(right))


def main(argv: Optional[Sequence[str]] = None) -> int:
    selected = list(sys.argv[1:] if argv is None else argv)
    if selected and selected[0] == "demo":
        from core.demo import demo_main
        return demo_main(selected[1:])
    args = build_argument_parser().parse_args(selected)
    if args.export_sarif is not None:
        if not args.export_sarif.strip() or any(ord(char) < 32 or ord(char) == 127
                                              for char in args.export_sarif):
            print("[ERROR] --export-sarif requires a non-empty output path without control characters",
                  file=sys.stderr)
            return 2
        if args.dry_run or args.init_config is not None or args.validate_config:
            print("[ERROR] --export-sarif requires audit results and cannot be combined with "
                  "--dry-run, --init-config, or --validate-config", file=sys.stderr)
            return 2
        try:
            sarif_path = Path(args.export_sarif).expanduser().resolve()
            report_paths = [Path(args.output).expanduser().resolve(), sarif_path]
            if args.export_json is not None:
                report_paths.append(Path(args.export_json).expanduser().resolve())
            if any(_paths_alias(left, right) for index, left in enumerate(report_paths)
                   for right in report_paths[:index]):
                print("[ERROR] HTML, JSON and SARIF outputs must use separate paths", file=sys.stderr)
                return 2
            input_paths = [args.spec if args.spec is not None else "openapi.json"]
            if args.config is not None:
                input_paths.append(args.config)
            for other_path in input_paths:
                other = Path(other_path).expanduser().resolve()
                if _paths_alias(sarif_path, other):
                    print("[ERROR] --export-sarif must use a separate path from spec/config inputs", file=sys.stderr)
                    return 2
        except (ValueError, OSError, RuntimeError):
            print("[ERROR] Invalid --export-sarif output path", file=sys.stderr)
            return 2
    print(BANNER)
    if args.init_config is not None:
        if args.config or args.validate_config or args.dry_run or args.allow_write_tests or args.write_endpoint:
            print("[ERROR] --init-config cannot be combined with --config, --validate-config, "
                  "--dry-run, --allow-write-tests, or --write-endpoint", file=sys.stderr)
            return 2
        try:
            output, checklist = write_config_scaffold(
                args.spec if args.spec is not None else "openapi.json", args.init_config
            )
        except Exception as exc:
            print("[ERROR] Cannot create configuration draft: " +
                  display_path(str(exc)), file=sys.stderr)
            return 2
        print("[OK] Offline configuration draft: " + display_path(str(output)))
        print("[OK] Review checklist: " + display_path(str(checklist)))
        print("[REVIEW] Needs user input; validation and scans remain blocked until review is complete. "
              "Write tests are disabled.")
        _print_onboarding(init_guidance(
            _next_path(args.spec if args.spec is not None else "openapi.json") or "<OPENAPI_FILE>",
            _next_path(str(output)) or "<CONFIG_FILE>", _next_path(str(checklist)) or "<CHECKLIST_FILE>",
        ))
        return 0
    if args.validate_config:
        config_path = args.config or "config.json"
        return run_config_validation(config_path, args.spec)

    spec_path = args.spec if args.spec is not None else "openapi.json"
    if (args.workers < 1 or args.delay < 0 or args.timeout <= 0 or args.max_response_bytes < 1024
            or not all(math.isfinite(v) for v in (args.delay, args.timeout, args.min_coverage))
            or not 0 <= args.min_coverage <= 100):
        print("[ERROR] Invalid worker, delay, timeout, or response-size option", file=sys.stderr)
        return 2

    config: Dict[str, Any] = {}
    try:
        config = _load_config(args.config)
        raw_spec = _load_spec(spec_path)
    except ValueError as exc:
        safe_err = display_path(sanitize_text(str(exc), secret_values=_onboarding_private_values(config)))
        print(f"[ERROR] {safe_err}", file=sys.stderr)
        return 2

    # Validate write_endpoint options if provided on CLI
    if args.write_endpoint:
        for item in args.write_endpoint:
            is_valid, method, path, canonical, err_msg = parse_operation_key(item)
            if not is_valid or method != "PATCH":
                print(
                    f"[ERROR] Invalid --write-endpoint '{sanitize_log_text(str(item))}': {err_msg or 'must be uppercase PATCH'}",
                    file=sys.stderr,
                )
                return 2

    # If configuration is loaded, run full ConfigValidator semantic validation
    if args.config or args.write_endpoint:
        val_config = dict(config)
        # Explicit CLI selection narrows/replaces, never silently unions scope
        if args.write_endpoint:
            val_config["write_allowlist"] = list(args.write_endpoint)

        val_result = ConfigValidator.validate(val_config, raw_spec=raw_spec)
        if not val_result.is_valid:
            private_values = _onboarding_private_values(config)
            safe_cfg_path = display_path(sanitize_text(args.config or "CLI configuration", secret_values=private_values))
            error_word = "error" if val_result.summary.errors_count == 1 else "errors"
            print(
                f"[ERROR] Configuration validation failed for '{safe_cfg_path}' "
                f"({val_result.summary.errors_count} {error_word} found):",
                file=sys.stderr,
            )
            _print_issues(val_result.errors, private_values)
            _print_issues(val_result.warnings, private_values)
            _print_validation_failure(spec_path, args.config, val_result.summary.errors_count,
                                      val_result.summary.warnings_count, private_values)
            return 2

    try:
        # Explicit CLI selection narrows/replaces, never silently unions scope.
        write_allowlist = list(args.write_endpoint) if args.write_endpoint else config.get("write_allowlist", [])
        if not isinstance(write_allowlist, list):
            raise ValueError("write_allowlist must be a list")

        if args.allow_write_tests and not write_allowlist:
            print("[WARN] Write tests requested, but write_allowlist is empty; no PATCH requests will be sent. "
                  "Review explicit PATCH entries and independent GET readbacks, then run --validate-config "
                  "and --dry-run before scanning.", file=sys.stderr)

        auditor = APISentinelAuditor(
            spec_path=spec_path,
            target_base_url=args.target,
            max_workers=args.workers,
            request_delay=args.delay,
            identities_config=config.get("identities"),
            insecure_ssl=args.insecure,
            allow_http=args.allow_http,
            allow_write_tests=args.allow_write_tests,
            readback_config=config.get("readbacks"),
            parameter_values=config.get("parameter_values"),
            write_allowlist=write_allowlist,
            request_timeout=args.timeout,
            max_response_bytes=args.max_response_bytes,
            include_sensitive_evidence=args.include_sensitive_evidence,
            bola_config=config.get("bola"),
        )
        if args.dry_run:
            plan = auditor.build_plan()
            print(json.dumps(plan, indent=2, ensure_ascii=False))
            if args.export_json:
                _ensure_parent(args.export_json)
                with open(args.export_json, "w", encoding="utf-8") as handle:
                    json.dump(plan, handle, indent=2, ensure_ascii=False)
            private_values = _onboarding_private_values(config)
            _print_onboarding(plan_guidance(
                _next_path(spec_path, private_values) or "<OPENAPI_FILE>",
                _next_path(args.config, private_values), plan,
            ))
            return 0
        started = time.time()
        auditor.run()
        elapsed = time.time() - started

        _ensure_parent(args.output)
        reproduction_secrets = set(auditor._secret_values)
        for identity_name in auditor.identities:
            reproduction_secrets.update(auditor._identity_headers(identity_name).values())
        reproduction_templates = build_reproduction_templates(
            auditor.findings, auditor._identity_headers("visitor"), reproduction_secrets,
        )
        SecurityReportGenerator.generate(
            stats=auditor.stats,
            findings=auditor.findings,
            results=auditor.results,
            target_url=args.target,
            output_path=args.output,
            reproduction_templates=reproduction_templates,
        )
        print(f"[OK] HTML report: {args.output}")

        if args.export_json:
            _ensure_parent(args.export_json)
            with open(args.export_json, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "tool_version": __version__,
                        "report_schema_version": 2,
                        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "elapsed_seconds": round(elapsed, 3),
                        "target": args.target,
                        "stats": auditor.stats,
                        "results": auditor.results,
                        "findings": auditor.findings,
                    },
                    handle,
                    indent=2,
                    ensure_ascii=False,
                )
            print(f"[OK] JSON report: {args.export_json}")
        if args.export_sarif is not None:
            _ensure_parent(args.export_sarif)
            SarifReportGenerator.generate(
                results=auditor.results,
                target_url=args.target,
                output_path=args.export_sarif,
                secret_values=auditor._secret_values,
                spec_path=spec_path,
            )
            print("[OK] SARIF report: " + sanitize_log_text(
                sanitize_text(args.export_sarif, secret_values=auditor._secret_values)
            ))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("[ERROR] " + sanitize_log_text(sanitize_text(str(exc), secret_values=getattr(locals().get("auditor"), "_secret_values", ()))), file=sys.stderr)
        return 2
    except Exception as exc:  # The CLI must not emit a healthy report after a fatal error.
        print("[ERROR] Audit aborted: " + sanitize_log_text(sanitize_text(f"{type(exc).__name__}: {exc}", secret_values=getattr(locals().get("auditor"), "_secret_values", ()))), file=sys.stderr)
        return 2

    if args.fail_on_error and (
        auditor.stats.get("error_count", 0) > 0
        or auditor.stats.get("inconclusive_count", 0) > 0
        or auditor.stats.get("conclusive_count", 0) == 0
    ):
        return 2
    if auditor.stats.get("conclusive_coverage_pct", 0) < args.min_coverage:
        return 2
    if args.fail_on_suspicious and auditor.stats.get("suspicious_count", 0) > 0:
        return 2
    if args.fail_on_vuln and auditor.stats.get("confirmed", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

