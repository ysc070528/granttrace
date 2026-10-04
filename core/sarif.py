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
from urllib.parse import urlsplit, urlunsplit

from core import __version__
from core.evidence import sanitize_text, sanitize_url


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
_PRIVATE_PATH_PREFIXES = (
    "/users", "/home", "/root", "/documents and settings", "/tmp", "/private", "/mnt", "/var",
    "/etc", "/opt", "/volumes", "/applications", "/library", "/windows", "/programdata", "/usr",
    "/srv", "/run", "/proc", "/sys", "/dev", "/media",
)
_CREDENTIAL_PATH_WORDS = (
    "authorization", "bearer", "password", "passwd", "cookie", "session", "token", "apikey",
    "credential", "secret", "privatekey",
)


def _safe_endpoint(value: object, secret_values: tuple[str, ...]) -> Optional[str]:
    # Only a specification operation template is eligible. Concrete URLs,
    # queries, encoded paths, local paths and arbitrary diagnostic text are not.
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|TRACE) (/[A-Za-z0-9_./{}~-]*)", value)
    if match is None:
        return None
    method, path = match.groups()
    private_path = any(path.casefold() == prefix or path.casefold().startswith(prefix + "/")
                       for prefix in _PRIVATE_PATH_PREFIXES)
    if path.startswith("//") or private_path or ".." in path.split("/"):
        return None
    compact_path = path.lower().replace("_", "").replace("-", "").replace(".", "")
    if any(word in compact_path for word in _CREDENTIAL_PATH_WORDS):
        return None
    return sanitize_text(f"{method} {sanitize_url(path)}", secret_values=secret_values)


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
    ) -> None:
        secrets = tuple(secret_values)
        target = _safe_origin(target_url, secrets)
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
            sarif_results.append({
                "ruleId": rule_id, "ruleIndex": index, "level": "error",
                "message": {"text": message + "."}, "properties": properties,
            })
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
