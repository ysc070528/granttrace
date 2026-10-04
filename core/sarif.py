"""SARIF 2.1.0 export of explicitly confirmed authorization findings.

The export deliberately contains operation metadata, not HTTP evidence. It
always applies the existing redaction helpers, including when another report
has opted in to sensitive evidence.
"""

from __future__ import annotations

import json
import re
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable, Mapping, Optional
from urllib.parse import quote, urlsplit, urlunsplit

from core import __version__
from core.evidence import sanitize_evidence, sanitize_text, sanitize_url
from core.models import parse_operation_key


_RULES: tuple[dict[str, object], ...] = (
    {
        "id": "GT-BOLA-001",
        "name": "BrokenObjectLevelAuthorization",
        "shortDescription": {"text": "Broken Object Level Authorization"},
        "fullDescription": {
            "text": "An identity accessed another identity's resource without the required authorization."
        },
        "help": {
            "text": "Validate the requesting identity's authorization for each resource before returning its data."
        },
        "properties": {"tags": ["security", "authorization", "CWE-639"]},
    },
    {
        "id": "GT-MASS-001",
        "name": "MassAssignment",
        "shortDescription": {"text": "Mass Assignment"},
        "fullDescription": {
            "text": "An unauthorized property change persisted and was confirmed through independent GET readback."
        },
        "help": {
            "text": "Explicitly allow writable fields and authorize each change before persisting it."
        },
        "properties": {"tags": ["security", "mass-assignment", "CWE-915"]},
    },
)

_CHECK_RULES = {
    "BOLA": (0, "GT-BOLA-001", "CWE-639", "Confirmed broken object level authorization"),
    "MASS_ASSIGNMENT": (1, "GT-MASS-001", "CWE-915", "Confirmed mass assignment"),
}


def _safe_endpoint(value: object, secret_values: tuple[str, ...]) -> Optional[str]:
    valid, method, path, _, _ = parse_operation_key(value)
    if not valid:
        return None
    # Use the existing URL-aware evidence boundary so encoded credentials in
    # valid operation paths receive the same redaction as HTTP evidence.
    safe_evidence = sanitize_evidence({"endpoint_url": path}, secret_values=secret_values)
    safe_path = safe_evidence.get("endpoint_url") if isinstance(safe_evidence, dict) else None
    if not isinstance(safe_path, str):
        return None
    return sanitize_text(f"{method} {safe_path}", secret_values=secret_values)


def _safe_spec_uri(spec_path: Optional[str], secret_values: tuple[str, ...]) -> Optional[str]:
    """Locate the actual specification inside the current workspace only."""
    if not isinstance(spec_path, str) or not spec_path or re.search(r"[\x00-\x1f\x7f]", spec_path):
        return None
    try:
        root = Path.cwd().resolve(strict=True)
        source = Path(spec_path)
        if not source.is_absolute():
            source = root / source
        source = source.resolve(strict=True)
        if not source.is_file():
            return None
        # Resolve before containment checking so an outward symlink cannot
        # turn a workspace-relative URI into a reference to a private file.
        relative = source.relative_to(root).as_posix()
        if re.search(r"[\\\x00-\x1f\x7f]", relative):
            return None
        uri = quote(relative, safe="/")
        if (sanitize_text(relative, secret_values=secret_values) != relative
                or sanitize_text(uri, secret_values=secret_values) != uri):
            return None
        # Preserve literal filename delimiters while letting the existing
        # URL sanitizer inspect any encoded credential already in the name.
        privacy_uri = quote(relative, safe="/%")
        safe_evidence = sanitize_evidence({"endpoint_url": privacy_uri}, secret_values=secret_values)
        safe_uri = safe_evidence.get("endpoint_url") if isinstance(safe_evidence, dict) else None
        if not isinstance(safe_uri, str) or safe_uri != privacy_uri:
            return None
        return uri
    except (OSError, ValueError, RuntimeError, UnicodeError):
        return None


def _safe_origin(target_url: str, secret_values: tuple[str, ...]) -> Optional[str]:
    # Origin alone is sufficient context; resource IDs, query values, fragments
    # and credentials embedded in the target URL never cross this boundary.
    if re.search(r"[\s\\\x00-\x1f\x7f]", target_url):
        return None
    try:
        parts = urlsplit(target_url)
        authority = parts.netloc.rsplit("@", 1)[-1]
        # urlsplit.hostname normalizes case. Check the original authority
        # first so normalization cannot hide an exact known credential.
        if sanitize_text(authority, secret_values=secret_values) != authority:
            return None
        host = parts.hostname
        port = parts.port
        if parts.scheme not in {"http", "https"} or not host:
            return None
        try:
            address = ip_address(host)
            host = f"[{address}]" if address.version == 6 else str(address)
        except ValueError:
            if not re.fullmatch(
                r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?", host,
            ):
                return None
        netloc = host if port is None else f"{host}:{port}"
        origin = urlunsplit((parts.scheme, netloc, "", "", ""))
        safe = sanitize_text(sanitize_url(origin), secret_values=secret_values)
        # A redacted hostname is useful neither as an origin nor as an API
        # location. Omit it rather than serializing a malformed URI.
        return origin if safe == origin else None
    except (ValueError, UnicodeError):
        return None


class SarifReportGenerator:
    """Write confirmed audit results without changing their verdicts."""

    @staticmethod
    def generate(
        results: Iterable[Mapping[str, object]],
        target_url: str,
        output_path: str,
        secret_values: Iterable[str] = (),
        *,
        spec_path: Optional[str] = None,
    ) -> None:
        secrets = tuple(secret_values)
        target = _safe_origin(target_url, secrets)
        spec_uri = _safe_spec_uri(spec_path, secrets)
        sarif_results: list[dict[str, object]] = []
        for result in results:
            check = result.get("check")
            if result.get("verdict") != "CONFIRMED" or not isinstance(check, str) or check not in _CHECK_RULES:
                continue
            index, rule_id, cwe, message = _CHECK_RULES[check]
            properties: dict[str, object] = {
                "check": check, "cwe": cwe, "granttraceVerdict": "CONFIRMED",
            }
            endpoint = _safe_endpoint(result.get("endpoint"), secrets)
            if endpoint is not None:
                properties["endpoint"] = endpoint
                message += f" at {endpoint}"
            if target is not None:
                properties["target"] = target
            sarif_result: dict[str, object] = {
                "ruleId": rule_id, "ruleIndex": index, "level": "error",
                "message": {"text": message + "."}, "properties": properties,
            }
            if spec_uri is not None:
                sarif_result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": spec_uri}}}]
            sarif_results.append(sarif_result)
        report = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "GrantTrace", "version": __version__,
                    "informationUri": "https://github.com/ysc070528/granttrace", "rules": _RULES,
                }},
                "results": sarif_results,
            }],
        }
        with Path(output_path).open("w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
