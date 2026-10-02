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

from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.evidence import sanitize_log_text, sanitize_text
from core.models import parse_operation_key
from core.parser import OpenAPIParser
from core.reporter import SecurityReportGenerator


BANNER = r"""
 ###  ## #   ###  #  #  ##### ##### ## #   ###   ###  ####
 #    #  #  #  #  ## #    #     #   #  #  #  #  #     #
 # ## ##    ####  # ##    #     #   ##    ####  #     ###
 #  # # #   #  #  #  #    #     #   # #   #  #  #     #
 ###  #  #  #  #  #  #    #     #   #  #  #  #   ###  ####
             safety-first API authorization auditing  v2.3.1-final
"""


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safety-first OpenAPI authorization and mass-assignment auditor"
    )
    parser.add_argument("--spec", "-s", default=None,
                        help="OpenAPI/Swagger JSON or YAML (default: openapi.json)")
    parser.add_argument(
        "--target", "-t", default="http://127.0.0.1:8080", help="Target API base URL"
    )
    parser.add_argument("--config", "-c", default=None, help="Identity and readback JSON config")
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
        "--output", "-o", default="API_Security_Report.html", help="HTML report path"
    )
    parser.add_argument("--export-json", default=None, help="Optional machine-readable JSON report")
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
        version="GrantTrace 2.3.1-final",
        help="Show program version and exit",
    )
    return parser


def _reject_constant(val: str) -> None:
    raise ValueError(f"Non-standard JSON number not allowed: {val}")


def _load_spec(path: str) -> Dict[str, Any]:
    """Use the scanner's local JSON/YAML loader for both preflight modes."""
    try:
        return OpenAPIParser(path).raw_spec
    except Exception as exc:
        raise ValueError(f"Cannot load specification '{path}': {exc}") from exc


def run_config_validation(config_path_str: str, spec_path: Optional[str] = None) -> int:
    config_file = Path(config_path_str)
    safe_path_str = sanitize_log_text(config_path_str)
    if not config_file.is_file():
        print(f"[ERROR] Configuration file does not exist: {safe_path_str}", file=sys.stderr)
        return 2
    try:
        with config_file.open("r", encoding="utf-8") as handle:
            raw_data = json.load(handle, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        safe_err = sanitize_log_text(sanitize_text(str(exc)))
        print(f"[ERROR] Failed to parse JSON configuration '{safe_path_str}': {safe_err}", file=sys.stderr)
        return 2
    except UnicodeDecodeError as exc:
        safe_err = sanitize_log_text(str(exc))
        print(f"[ERROR] Configuration file must be valid UTF-8: {safe_err}", file=sys.stderr)
        return 2
    except OSError as exc:
        safe_err = sanitize_log_text(str(exc))
        print(f"[ERROR] Cannot read configuration file '{safe_path_str}': {safe_err}", file=sys.stderr)
        return 2
    except Exception as exc:
        safe_err = sanitize_log_text(f"{type(exc).__name__}: {exc}")
        print(f"[ERROR] Unexpected error inspecting configuration: {safe_err}", file=sys.stderr)
        return 2

    # Config-only validation remains available without a default specification.
    # An explicitly selected specification must load successfully.
    selected_spec = spec_path if spec_path is not None else (
        "openapi.json" if Path("openapi.json").is_file() else None
    )
    try:
        raw_spec = _load_spec(selected_spec) if selected_spec is not None else None
    except ValueError as exc:
        print("[ERROR] " + sanitize_log_text(sanitize_text(str(exc))), file=sys.stderr)
        return 2

    result = ConfigValidator.validate(raw_data, raw_spec=raw_spec)
    if not result.is_valid:
        error_word = "error" if result.summary.errors_count == 1 else "errors"
        print(
            f"[ERROR] Configuration validation failed for '{safe_path_str}' "
            f"({result.summary.errors_count} {error_word} found):",
            file=sys.stderr,
        )
        for issue in result.errors:
            print(issue.format(), file=sys.stderr)
        if result.warnings:
            print(f"[WARN] In addition, {result.summary.warnings_count} warning(s) observed:", file=sys.stderr)
            for warning in result.warnings:
                print(warning.format(), file=sys.stderr)
        return 2

    print(f"[OK] Configuration is valid: {safe_path_str}")
    print(f"     - Identities:        {result.summary.identities_count} configured (owner, visitor, anonymous)")
    print(f"     - Write allowlist:   {result.summary.allowlisted_endpoints} endpoint(s)")
    print(f"     - Readbacks:         {result.summary.readbacks_count} mapped endpoint(s)")
    print(f"     - Parameter values:  {result.summary.parameter_endpoints} endpoint(s)")
    print(f"     - BOLA policies:     {result.summary.bola_policies_count} operation(s)")
    if result.warnings:
        for warning in result.warnings:
            print(warning.format())
    return 0


def _load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    config_path = Path(path)
    if not config_path.is_file():
        raise ValueError(f"configuration file does not exist: {path}")
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            config = json.load(handle, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise ValueError(f"configuration file must be valid UTF-8: {exc}") from exc
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"cannot read configuration '{path}': {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("configuration root must be a JSON object")
    return config


def _ensure_parent(path: str) -> None:
    parent = Path(path).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_argument_parser().parse_args(argv)
    print(BANNER)
    if args.validate_config:
        config_path = args.config or "config.json"
        return run_config_validation(config_path, args.spec)

    spec_path = args.spec if args.spec is not None else "openapi.json"
    if (args.workers < 1 or args.delay < 0 or args.timeout <= 0 or args.max_response_bytes < 1024
            or not all(math.isfinite(v) for v in (args.delay, args.timeout, args.min_coverage))
            or not 0 <= args.min_coverage <= 100):
        print("[ERROR] Invalid worker, delay, timeout, or response-size option", file=sys.stderr)
        return 2

    try:
        config = _load_config(args.config)
        raw_spec = _load_spec(spec_path)
    except ValueError as exc:
        safe_err = sanitize_log_text(sanitize_text(str(exc)))
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
            safe_cfg_path = sanitize_log_text(args.config or "CLI configuration")
            error_word = "error" if val_result.summary.errors_count == 1 else "errors"
            print(
                f"[ERROR] Configuration validation failed for '{safe_cfg_path}' "
                f"({val_result.summary.errors_count} {error_word} found):",
                file=sys.stderr,
            )
            for issue in val_result.errors:
                print(issue.format(), file=sys.stderr)
            return 2

    try:
        # Explicit CLI selection narrows/replaces, never silently unions scope.
        write_allowlist = list(args.write_endpoint) if args.write_endpoint else config.get("write_allowlist", [])
        if not isinstance(write_allowlist, list):
            raise ValueError("write_allowlist must be a list")

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
            return 0
        started = time.time()
        auditor.run()
        elapsed = time.time() - started

        _ensure_parent(args.output)
        SecurityReportGenerator.generate(
            stats=auditor.stats,
            findings=auditor.findings,
            results=auditor.results,
            target_url=args.target,
            output_path=args.output,
        )
        print(f"[OK] HTML report: {args.output}")

        if args.export_json:
            _ensure_parent(args.export_json)
            with open(args.export_json, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "tool_version": "2.3.1-final",
                        "report_schema_version": 1,
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

