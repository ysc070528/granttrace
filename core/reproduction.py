"""Safe POSIX cURL templates for the runtime's confirmed finding collection.

Identity values are consumed here and never become report metadata. This output
boundary always redacts, independently of the sensitive-evidence opt-in.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Iterable, Mapping, Optional
from urllib.parse import quote, unquote, urlsplit

from core.evidence import MAX_TEXT_CHARS, REDACTED, redact_payload, sanitize_evidence, sanitize_text, sanitize_url
from core.models import parse_operation_key


_HEADER_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_HOST = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?\Z"
)
_CONTENT_TYPE = re.compile(
    r'application/(?:json|merge-patch\+json)'
    r'(?: *; *[!#$%&\'*+\-.^_`|~0-9A-Za-z]+ *= *'
    r'(?:[!#$%&\'*+\-.^_`|~0-9A-Za-z]+|"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\[\x20-\x7e])*"))*\Z',
    re.IGNORECASE,
)
_LIMIT_MARKERS = ("[TRUNCATED]", "[DEPTH_LIMIT]", "[NODE_LIMIT]", "[ITEM_LIMIT]", "_truncated_entries")
_NOTE = "POSIX shell；认证值为 Visitor 占位符，请填入授权测试凭据。"


@dataclass(frozen=True)
class CurlTemplate:
    command: str
    redacted: bool
    note: str


def _encoded_text_is_safe(value: str, secrets: tuple[str, ...]) -> bool:
    if re.search(r"%25", value, re.IGNORECASE):
        return False
    if not re.search(r"%[0-9A-Fa-f]{2}", value):
        return True
    # Inspect the entire text as one URI segment using the existing URL-aware
    # boundary. Literal slashes must not split a partially encoded credential.
    uri = quote(value, safe="%")
    safe = sanitize_evidence({"request_url": uri}, secret_values=secrets)
    return isinstance(safe, dict) and safe.get("request_url") == uri


def _safe_headers(
    visitor_headers: Mapping[str, str], secrets: tuple[str, ...],
) -> Optional[list[tuple[str, str]]]:
    headers = []
    seen = set()
    for name, value in visitor_headers.items():
        if (not isinstance(name, str) or not isinstance(value, str) or not value
                or not _HEADER_TOKEN.fullmatch(name) or "%" in name
                or any(not character.isprintable() for character in value)
                or sanitize_text(name, secret_values=secrets) != name):
            return None
        normalized = name.lower()
        if normalized in seen:
            return None
        seen.add(normalized)
        if normalized == "authorization":
            display_name = "Authorization"
            if re.match(r"(?i)^Bearer(?: |$)", value):
                placeholder = "Bearer <VISITOR_TOKEN>"
            elif re.match(r"(?i)^Basic(?: |$)", value):
                placeholder = "Basic <VISITOR_CREDENTIAL>"
            else:
                placeholder = "<VISITOR_TOKEN>"
        else:
            acronyms = {"api": "API", "id": "ID"}
            display_name = "-".join(acronyms.get(part.lower(), part.capitalize()) for part in name.split("-"))
            label = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper() or "HEADER"
            placeholder = f"<VISITOR_{label}>"
        if (sanitize_text(display_name, secret_values=secrets) != display_name
                or sanitize_text(placeholder, secret_values=secrets) != placeholder):
            return None
        headers.append((display_name, placeholder))
    # A missing Visitor authentication shape must not become an anonymous curl.
    return headers or None


def _valid_url(value: str) -> bool:
    if (not value or len(value) > MAX_TEXT_CHARS
            or any(character.isspace() or character == "\\" or not character.isprintable()
                   for character in value)
            or re.search(r"%(?![0-9A-Fa-f]{2})|%25", value, re.IGNORECASE)):
        return False
    decoded = unquote(value)
    if any(character == "\\" or not character.isprintable() for character in decoded):
        return False
    try:
        parts = urlsplit(value)
        host = parts.hostname
        # Accessing .port also validates its syntax and range.
        parts.port
        if parts.scheme not in {"http", "https"} or not host or "%" in host:
            return False
        try:
            address = ip_address(host)
            authority_pattern = (r"\[[0-9A-Fa-f:.]+\](?::[0-9]+)?\Z"
                                 if address.version == 6 else r"[0-9.]+(?::[0-9]+)?\Z")
        except ValueError:
            if not _HOST.fullmatch(host) or re.fullmatch(r"[0-9.]+", host):
                return False
            authority_pattern = r"[A-Za-z0-9.-]+(?::[0-9]+)?\Z"
        if not re.fullmatch(authority_pattern, parts.netloc.rsplit("@", 1)[-1]):
            return False
        return True
    except (ValueError, UnicodeError):
        return False


def _safe_url(value: object, secrets: tuple[str, ...]) -> Optional[tuple[str, bool]]:
    if not isinstance(value, str) or not _valid_url(value):
        return None
    authority = urlsplit(value).netloc.rsplit("@", 1)[-1]
    if sanitize_text(authority, secret_values=secrets) != authority:
        return None
    # Preserve the existing omission boundary for an encoded private path.
    # Sanitizing it first would erase the reason the original cannot be used
    # as a reproduction target, especially across literal '/' segments.
    if not _encoded_text_is_safe(urlsplit(value).path, secrets):
        return None
    # The URL-aware boundary decodes path segments before known-secret matching.
    # Nested percent encoding is rejected above rather than risking another
    # encoded echo beyond the existing sanitizer's supported decoding depth.
    evidence = sanitize_evidence({"request_url": sanitize_url(value)}, secret_values=secrets)
    safe = evidence.get("request_url") if isinstance(evidence, dict) else None
    if not isinstance(safe, str):
        return None
    safe = sanitize_text(safe, secret_values=secrets)
    if (not _valid_url(safe) or any(marker in safe for marker in _LIMIT_MARKERS)
            or not _encoded_text_is_safe(urlsplit(safe).path, secrets)):
        return None
    return safe, safe != value or REDACTED in unquote(safe)


def _safe_payload(value: object, secrets: tuple[str, ...]) -> Optional[tuple[str, bool]]:
    if not isinstance(value, dict) or not value:
        return None
    # Runtime injected_payload keys are field paths, not a serialized PATCH
    # document. Only unambiguous object-root fields can express this template.
    if any(not isinstance(key, str) or not key or any(character in key for character in ".[]")
           or any(not character.isprintable() for character in key) for key in value):
        return None
    if any(item is not None and not isinstance(item, (str, bool, int, float)) for item in value.values()):
        return None
    try:
        original = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        # Plain JSON strings are not necessarily URLs. When they contain URL
        # escapes, ask the existing URL-aware boundary to inspect decoded
        # segments too; omit ambiguous text rather than preserving an encoded
        # credential that the ordinary text boundary cannot recognize.
        texts = [*value, *(item for item in value.values() if isinstance(item, str))]
        if any(not _encoded_text_is_safe(text, secrets) for text in texts):
            return None
        safe = redact_payload(value, include_sensitive=False, secret_values=secrets)
        # A redacted field name cannot still describe the tested mutation.
        if not isinstance(safe, dict) or set(safe) != set(value):
            return None
        rendered = json.dumps(safe, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if any(marker in rendered for marker in _LIMIT_MARKERS):
            return None
        return rendered, rendered != original or REDACTED in rendered
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None


def build_reproduction_templates(
    findings: Iterable[Mapping[str, object]],
    visitor_headers: Mapping[str, str],
    secret_values: Iterable[str] = (),
) -> dict[int, CurlTemplate]:
    """Build templates indexed by finding position, omitting unsafe metadata.

    The runtime finding collection contains confirmed records without a verdict
    field. An explicit verdict is accepted only when it is exactly CONFIRMED.
    The supplied headers must be the auditor's effective Visitor headers, after
    its token override; every value is replaced here with a safe placeholder.
    """
    supplied_secrets = (secret_values,) if isinstance(secret_values, str) else tuple(secret_values)
    secrets = tuple(value for value in (*supplied_secrets, *visitor_headers.values())
                    if isinstance(value, str) and value)
    headers = _safe_headers(visitor_headers, secrets)
    if headers is None:
        return {}
    templates = {}
    for index, finding in enumerate(findings):
        if "verdict" in finding and finding["verdict"] != "CONFIRMED":
            continue
        cwe = finding.get("cwe")
        expected_method = "GET" if cwe == "CWE-639" else "PATCH" if cwe == "CWE-915" else None
        valid, method, path, _, _ = parse_operation_key(finding.get("endpoint"))
        if (not valid or method != expected_method
                or any(character == "\\" or not character.isprintable() for character in path)):
            continue
        evidence = finding.get("evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        evidence_target = evidence.get("target_url")
        finding_target = finding.get("target_url")
        if evidence_target and finding_target and evidence_target != finding_target:
            continue
        target = evidence_target or finding_target
        url = _safe_url(target, secrets)
        if url is None:
            continue
        safe_url, redacted = url
        lines = ["curl --globoff -X " + shlex.quote(method) + " " + shlex.quote(safe_url)]
        lines.extend("-H " + shlex.quote(name + ": " + placeholder) for name, placeholder in headers
                     if method != "PATCH" or name.lower() != "content-type")
        if method == "PATCH":
            content_type = evidence.get("request_content_type")
            if (not isinstance(content_type, str) or not _CONTENT_TYPE.fullmatch(content_type)
                    or sanitize_text(content_type, secret_values=secrets) != content_type
                    or not _encoded_text_is_safe(content_type, secrets)):
                continue
            payload = _safe_payload(finding.get("injected_payload"), secrets)
            if payload is None:
                continue
            rendered, payload_redacted = payload
            redacted = redacted or payload_redacted
            lines.extend(("-H " + shlex.quote("Content-Type: " + content_type),
                          "--data " + shlex.quote(rendered)))
        note = _NOTE + (" 部分值已脱敏，请补全测试值。" if redacted else "")
        command = " ".join(lines)
        templates[index] = CurlTemplate(command, redacted, note)
    return templates
