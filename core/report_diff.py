"""Offline comparison of two GrantTrace JSON scan reports.

``granttrace diff BASELINE.json CURRENT.json`` reads two reports with
``report_schema_version`` 2 and classifies every confirmed finding as new,
persisting, resolved or not comparable. Nothing is sent over the network.

A finding is identified by its check, its operation template and, where a check
produces several results per operation, its subject (BOPLA field rule and
identity, RBAC role, mass-assignment field). Targets, ports, times and concrete
resource values are not part of the identifier; they decide whether two results
are comparable.

A conclusion that depends on scope (new, persisting, resolved) is only drawn
when both scans are shown to cover the same target (scheme, host, port and base
path), the same test identities, and the same specification, policy and
resources for the operation:

* With ``GRANTTRACE_COMPARISON_KEY`` set during both scans, reports carry a
  ``comparison_context`` of keyed fingerprints, which ``diff`` compares without
  needing the key. Every test identity must declare an account ``id``.
* Without it (or with different keys, identities without an ``id``, or reports
  from 2.7.1 and earlier) the test identities cannot be verified, and nothing
  is reported as new, persisting or resolved unless the caller states the
  assumption explicitly (``--assume-same-identities``). An unreadable or
  different target needs ``--assume-same-target`` in the same way. Assumptions
  are recorded on the comparison and on every finding that relies on them.

A finding is only reported as resolved when the same check on the same subject
and scope now has a conclusive non-vulnerable verdict (SECURE, PUBLIC or
AUTHORIZED). A SKIPPED, INCONCLUSIVE, ERROR or SUSPICIOUS result, or a missing
one, never counts as a fix. A finding is only new when the baseline verified the
same check as not vulnerable; a first detection is not comparable.

Equal fingerprints show that the declared configuration did not change. They do
not authenticate the reports, and they do not prove which account a credential
belongs to: credentials are never fingerprinted, so that rotating them does not
change a report.

The comparison output holds identifiers, verdicts and enumerated reason codes
only: no evidence, response data, URLs, credentials or free text from the
reports.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import hmac
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from core import __version__
from core.models import parse_operation_key

COMPARISON_SCHEMA_VERSION = 1
CONTEXT_VERSION = 2
CONTEXT_ALGORITHM = "pbkdf2-sha256-200000/hmac-sha256"
COMPARISON_KEY_ENV = "GRANTTRACE_COMPARISON_KEY"
MIN_COMPARISON_KEY_LENGTH = 32
MIN_COMPARISON_KEY_DISTINCT = 8
MAX_REPORT_BYTES = 64 * 1024 * 1024

CONFIRMED = "CONFIRMED"
CONCLUSIVE_NEGATIVE = frozenset({"SECURE", "PUBLIC", "AUTHORIZED"})
KNOWN_VERDICTS = frozenset({"CONFIRMED", "SECURE", "PUBLIC", "AUTHORIZED",
                            "SUSPICIOUS", "INCONCLUSIVE", "SKIPPED", "ERROR"})
CHECK_CWE = {"BOLA": "CWE-639", "BROKEN_AUTH": "CWE-306", "BFLA": "CWE-285", "RBAC": "CWE-285",
             "BOPLA": "CWE-200", "BOPLA_EXPOSURE": "CWE-200", "MASS_ASSIGNMENT": "CWE-915"}
STATUS_ORDER = ("new", "not_comparable", "persisting", "resolved")
# What no fingerprint can establish; reported with every comparison. Reports are not signed, and
# the accounts' data and permissions on the server may change between two scans.
NOT_VERIFIED = ("report_integrity", "server_side_test_data")

_KEY_SALT = b"granttrace/comparison-key/v2"
_KEY_ITERATIONS = 200_000
_CHECK_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_FINGERPRINT = re.compile(r"[0-9a-f]{16}")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_ACCOUNT = re.compile(r"owner|visitor|role:[A-Za-z0-9_.-]{1,128}")
_VERSION = re.compile(r"[0-9]{1,6}(?:\.[0-9A-Za-z]{1,16}){1,5}(?:[-+][0-9A-Za-z.]{1,24})?")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_SUBJECT_LIMIT = 512
_OPERATION_LIMIT = 512
_STAT_LIMIT = 1e12
_OPERATION_FINGERPRINTS = (("definition", "spec_changed"), ("policy", "policy_changed"),
                           ("resources", "resources_changed"))

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
    return "gtf_" + hashlib.sha256(material.encode("utf-8", "backslashreplace")).hexdigest()[:16]


def validate_comparison_key(value: Any) -> str:
    """Return a usable comparison key or raise; a weak key would allow offline guessing of the fingerprints."""
    if (not isinstance(value, str) or len(value) < MIN_COMPARISON_KEY_LENGTH
            or len(set(value)) < MIN_COMPARISON_KEY_DISTINCT):
        raise ComparisonKeyError(
            f"{COMPARISON_KEY_ENV} must be a random secret of at least {MIN_COMPARISON_KEY_LENGTH} characters, "
            "not a repeated pattern; generate one with "
            "python -c \"import secrets; print(secrets.token_hex(32))\" and keep it secret, like a password")
    return value


def comparison_key_from_environment(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """The comparison key, or None when it is not set (an empty value counts as not set)."""
    value = (os.environ if environ is None else environ).get(COMPARISON_KEY_ENV)
    return validate_comparison_key(value) if value else None


@functools.lru_cache(maxsize=8)
def _working_key(key: str) -> bytes:
    # Stretching makes each offline guess of a human-chosen key 200,000 times more expensive.
    return hashlib.pbkdf2_hmac("sha256", key.encode("utf-8", "backslashreplace"), _KEY_SALT, _KEY_ITERATIONS)


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
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    digest = hmac.new(_working_key(key), f"granttrace/{kind}/v2\0{canonical}".encode("ascii"), hashlib.sha256)
    return digest.hexdigest()[:16]


def _mask(value: Any, secrets: Tuple[str, ...]) -> Any:
    """JSON-safe copy in which strings that contain a credential are replaced before fingerprinting."""
    if isinstance(value, str):
        if any(secret == value or (len(secret) >= 4 and secret in value) for secret in secrets):
            return "[REDACTED]"
        return value
    if isinstance(value, Mapping):
        return {str(key): _mask(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask(item, secrets) for item in value]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    return str(value)


def _redacted_strings(value: Any, secrets: Tuple[str, ...], path: Tuple[str, ...] = ()) -> List[List[str]]:
    """Every string that `_mask` replaces, with its location: the credentials inside a configuration."""
    if isinstance(value, str):
        return [[*path, value]] if _mask(value, secrets) != value else []
    if isinstance(value, Mapping):
        return [leaf for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
                for leaf in _redacted_strings(item, secrets, path + (str(key),))]
    if isinstance(value, (list, tuple)):
        return [leaf for index, item in enumerate(value)
                for leaf in _redacted_strings(item, secrets, path + (str(index),))]
    return []


def _canonical_operation(value: Any) -> Optional[str]:
    if not isinstance(value, str) or len(value) > _OPERATION_LIMIT or not value.isprintable():
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


def specification_security_schemes(specification: Any) -> Any:
    """The security scheme definitions of an OpenAPI 3 or Swagger 2 document; they decide how requests authenticate."""
    if not isinstance(specification, Mapping):
        return None
    components = specification.get("components")
    return {"components": components.get("securitySchemes") if isinstance(components, Mapping) else None,
            "definitions": specification.get("securityDefinitions")}


def _declares_account(identity: Any) -> bool:
    value = identity.get("id") if isinstance(identity, Mapping) else None
    return isinstance(value, (str, int)) and not isinstance(value, bool) and bool(str(value).strip())


def build_comparison_context(
    *,
    key: str,
    target: str,
    identities: Any,
    endpoints: Iterable[Any] = (),
    security_schemes: Any = None,
    parameter_values: Any = None,
    bola_config: Any = None,
    bopla_config: Any = None,
    readback_config: Any = None,
    write_allowlist: Iterable[Any] = (),
    secret_values: Iterable[str] = (),
) -> Dict[str, Any]:
    """Keyed fingerprints of what a scan compared, for later comparability checks.

    Every fingerprint is a truncated HMAC-SHA256 under a key derived from the
    comparison key, so account IDs, resource values and the target cannot be
    enumerated without the key, and ``diff`` compares them without needing it.

    * target: scheme, host, port and base path.
    * identities (owner, visitor, anonymous and every role): ``id``, ``role``,
      identity parameters, header names with their non-credential values,
      ``auth_header_names`` and a role's request body. Tokens are not part of
      them, and any value that contains a known credential is masked first, so
      rotating credentials does not look like another identity.
    * operations: the operation as defined by the specification (``endpoints``
      and the security schemes), its configured policy and its resource values.
    * credentials: one fingerprint over all credentials together (tokens, the
      identities' header values and every configured value that contains a
      known credential). When it differs, a credential changed: a rotation and
      another account's credential look the same, so ``diff`` then needs the
      caller to state that the accounts are the same. Being one digest over
      all of them, it cannot be used to test a guess of a single credential.
    """
    validate_comparison_key(key)
    secrets = tuple(sorted({value for value in secret_values if isinstance(value, str) and value}))

    def fingerprint(kind: str, value: Any) -> Optional[str]:
        try:
            return _keyed(key, kind, value)
        except (TypeError, ValueError, RecursionError):
            return None  # diff treats a missing fingerprint as not comparable

    def identity_fingerprint(data: Any) -> Optional[str]:
        if not isinstance(data, Mapping):
            return None
        raw_headers, raw_names = data.get("headers"), data.get("auth_header_names")
        headers: Mapping[Any, Any] = raw_headers if isinstance(raw_headers, Mapping) else {}
        names: List[Any] = raw_names if isinstance(raw_names, list) else []
        try:
            material = {
                # The account id and role are compared exactly; everything else is masked for credentials.
                "id": data.get("id") if isinstance(data.get("id"), (str, int)) else None,
                "role": data.get("role") if isinstance(data.get("role"), str) else None,
                "parameters": _mask(data.get("parameters") or {}, secrets),
                "headers": {str(name).strip().lower(): _mask(value, secrets) for name, value in headers.items()},
                "auth_header_names": sorted(str(name).strip().lower() for name in names),
                "body": _mask(data.get("body"), secrets),
            }
        except RecursionError:
            return None
        return fingerprint("identity", material)

    identity_map = identities if isinstance(identities, Mapping) else {}
    declared: Dict[str, Any] = {name: identity_fingerprint(identity_map.get(name))
                                for name in ("owner", "visitor", "anonymous")}
    accounts = [name for name in ("owner", "visitor") if _declares_account(identity_map.get(name))]
    declared["roles"] = {}
    roles = identity_map.get("roles")
    for name, data in sorted(roles.items(), key=lambda item: str(item[0])) if isinstance(roles, Mapping) else ():
        label = str(name) if _NAME.fullmatch(str(name)) else "role-" + str(fingerprint("role-name", str(name)))
        declared["roles"][label] = identity_fingerprint(data)
        if _declares_account(data):
            accounts.append("role:" + label)

    definitions: Dict[str, Any] = {}
    for endpoint in endpoints or ():
        if isinstance(endpoint, Mapping):
            operation = _canonical_operation(f"{endpoint.get('method')} {endpoint.get('path')}")
            if operation is not None:
                definitions[operation] = {name: value for name, value in endpoint.items()
                                          if name not in ("method", "path")}
    parameters = _by_operation(parameter_values)
    bola = _by_operation(bola_config)
    bopla = _by_operation(bopla_config)
    readbacks = _by_operation(readback_config)
    allowlisted = {operation for operation in map(_canonical_operation, write_allowlist or ()) if operation}
    operations: Dict[str, Dict[str, Optional[str]]] = {}
    for operation in sorted(set(definitions) | set(parameters) | set(bola) | set(bopla) | set(readbacks)
                            | allowlisted):
        try:
            material = {
                "definition": _mask({"endpoint": definitions.get(operation), "security_schemes": security_schemes},
                                    secrets),
                "policy": _mask({"bola": bola.get(operation), "bopla": bopla.get(operation),
                                 "readback": readbacks.get(operation),
                                 "write_allowlisted": operation in allowlisted}, secrets),
                "resources": _mask(parameters.get(operation), secrets),
            }
        except RecursionError:
            operations[operation] = {name: None for name, _ in _OPERATION_FINGERPRINTS}
            continue
        operations[operation] = {name: fingerprint(name, material[name]) for name, _ in _OPERATION_FINGERPRINTS}
    identity_of_target = target_identity(target)
    everyone = {str(name): data for name, data in identity_map.items() if name != "roles"}
    if isinstance(roles, Mapping):
        everyone.update({"roles/" + str(name): data for name, data in roles.items()})
    try:
        credentials_hash = fingerprint("credentials", _mask({
            # Tokens and header values are credentials wherever the scanner learned its secrets from.
            "identities": {name: {"token": data.get("token"), "headers": data.get("headers")}
                           for name, data in everyone.items() if isinstance(data, Mapping)},
            "configured": _redacted_strings({
                "identities": {name: {"parameters": data.get("parameters"), "body": data.get("body")}
                               for name, data in everyone.items() if isinstance(data, Mapping)},
                "parameter_values": parameter_values, "bola": bola_config, "bopla": bopla_config,
                "readbacks": readback_config}, secrets)}, ()))
    except RecursionError:
        credentials_hash = None
    return {
        "version": CONTEXT_VERSION,
        "algorithm": CONTEXT_ALGORITHM,
        "key_id": _keyed(key, "comparison-key-id", None),
        "target": fingerprint("target", list(identity_of_target)) if identity_of_target else None,
        "identities": declared,
        "account_ids": sorted(accounts),
        "credentials": credentials_hash,
        "operations": operations,
    }


# ---------------------------------------------------------------------------
# Loading reports


def _strict_json(text: str) -> Any:
    """Decode JSON without non-standard constants, overflowing floats or duplicate object keys."""
    def reject_constant(value: str) -> None:
        raise ValueError("non-standard JSON constant")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("JSON number exceeds the finite range")
        return number

    def unique_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                # Parsers disagree on which duplicate wins; a report must not read differently elsewhere.
                raise ValueError("duplicate object key")
            result[name] = value
        return result

    return json.loads(text, parse_constant=reject_constant, parse_float=finite_float,
                      object_pairs_hook=unique_object)


def load_report(path: str) -> Dict[str, Any]:
    """Read and validate one GrantTrace JSON scan report."""
    file = Path(path)
    try:
        if not file.is_file():
            raise ReportError("report file does not exist or is not a regular file")
        with file.open("rb") as handle:
            raw = handle.read(MAX_REPORT_BYTES + 1)  # bounded even if the file grows after it was checked
        if len(raw) > MAX_REPORT_BYTES:
            raise ReportError(f"report is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB")
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ReportError("report is not valid UTF-8") from exc
    except OSError as exc:
        raise ReportError(f"cannot read report ({type(exc).__name__})") from exc
    try:
        data = _strict_json(text)
    except (ValueError, RecursionError) as exc:
        raise ReportError("report is not valid JSON, or it repeats an object key") from exc
    except MemoryError as exc:
        raise ReportError("report is too large to process") from exc
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
    __slots__ = ("verdicts", "resources", "policy", "ambiguous")

    def __init__(self) -> None:
        self.verdicts: Set[str] = set()
        self.resources: Set[Tuple[Tuple[str, str], ...]] = set()
        self.policy: Set[Tuple[Tuple[str, str], ...]] = set()
        # A confirmed record whose subject could not be read: it may belong to any subject.
        self.ambiguous = False

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
    if not isinstance(value, str) or not value or len(value) > _SUBJECT_LIMIT or not value.isprintable():
        return None
    return f"{prefix}:{value}"


def _subjects(check: str, verdict: str, evidence: Mapping[str, Any]) -> List[Tuple[Optional[str], str, bool]]:
    """Expand one result record into (subject, verdict, ambiguous) triples.

    A confirmed record whose subject cannot be read is ambiguous: it is kept at
    operation level and never matched with another record. Any other record
    without a readable subject stays at operation level, where it can only
    show that a subject was not verified.
    """
    confirmed = verdict == CONFIRMED
    if check == "MASS_ASSIGNMENT":
        if evidence.get("field") is not None:
            field = _bounded_subject("field", evidence.get("field"))
            return [(field, verdict, field is None and confirmed)]
        safe = evidence.get("safe_fields")
        if verdict == "SECURE" and isinstance(safe, list):
            # A SECURE summary verifies each safe field individually.
            pairs: List[Tuple[Optional[str], str, bool]] = [
                (subject, "SECURE", False) for subject in (_bounded_subject("field", name) for name in safe)
                if subject]
            return pairs + [(None, verdict, False)]
        # A summary is never confirmed; a confirmed record without its field cannot be attributed.
        return [(None, verdict, confirmed)]
    if check == "BOPLA":
        decision = evidence.get("decision_evidence")
        decision = decision if isinstance(decision, Mapping) else {}
        rule = decision.get("rule_id") if isinstance(decision.get("rule_id"), str) else decision.get("field_path")
        subject = _bounded_subject("field", rule)
        identity = decision.get("subject_identity")
        if subject is None or not isinstance(identity, str) or not _NAME.fullmatch(identity):
            return [(None, verdict, confirmed)]
        # Identity names cannot contain "|", so the pair cannot collide with another rule.
        return [(f"{subject}|identity:{identity}", verdict, False)]
    if check == "RBAC":
        # Role names are free text in a configuration; any readable one identifies its results.
        role = _bounded_subject("role", evidence.get("rbac_role"))
        return [(role, verdict, role is None and confirmed)]
    return [(None, verdict, False)]


def _url_scope(value: Any) -> Optional[str]:
    """Path and query of an evidence URL; the target itself is compared separately."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    return parts.path + (("?" + parts.query) if parts.query else "")


def _evidence_scope(evidence: Mapping[str, Any]) -> Tuple[Tuple[Tuple[str, str], ...], Tuple[Tuple[str, str], ...]]:
    """What the evidence says about the resources a check used and the policy it was judged by."""
    resources = []
    for name in ("target_url", "visitor_self_url", "readback_url"):
        scope = _url_scope(evidence.get(name))
        if scope is not None:
            resources.append((name, scope))
    policy = []
    for name in ("role", "required_role"):
        if isinstance(evidence.get(name), str):
            policy.append((name, evidence[name]))
    decision = evidence.get("decision_evidence")
    if isinstance(decision, Mapping):
        for name in ("requires_auth", "expected_public", "expected_visitor_access"):
            if isinstance(decision.get(name), (bool, str)):
                policy.append((name, str(decision[name])))
    return tuple(sorted(resources)), tuple(sorted(policy))


class _Index:
    def __init__(self, report: Mapping[str, Any]) -> None:
        self.entries: Dict[Key, _Entry] = {}
        self.operations: Set[str] = set()
        self.unreadable = 0
        # Unreadable records that may be confirmed findings on any operation.
        self.unattributed = 0
        for record in report.get("results", []):
            check = record.get("check") if isinstance(record, Mapping) else None
            operation = _canonical_operation(record.get("endpoint")) if isinstance(record, Mapping) else None
            verdict = record.get("verdict") if isinstance(record, Mapping) else None
            verdict = verdict if isinstance(verdict, str) and verdict in KNOWN_VERDICTS else "UNKNOWN"
            if not isinstance(check, str) or not _CHECK_NAME.fullmatch(check) or operation is None:
                self.unreadable += 1
                if verdict in (CONFIRMED, "UNKNOWN"):
                    self.unattributed += 1
                continue
            evidence = record.get("evidence")
            evidence = evidence if isinstance(evidence, Mapping) else {}
            resources, policy = _evidence_scope(evidence)
            self.operations.add(operation)
            for subject, subject_verdict, ambiguous in _subjects(check, verdict, evidence):
                entry = self.entries.setdefault((check, operation, subject), _Entry())
                entry.verdicts.add(subject_verdict)
                entry.ambiguous = entry.ambiguous or ambiguous
                if resources:
                    entry.resources.add(resources)
                if policy:
                    entry.policy.add(policy)

    def operation_level(self, key: Key) -> Optional[_Entry]:
        if key[2] is None:
            return None
        return self.entries.get((key[0], key[1], None))


# ---------------------------------------------------------------------------
# Comparison


def _fingerprint_or_none(value: Any) -> bool:
    return value is None or (isinstance(value, str) and bool(_FINGERPRINT.fullmatch(value)))


def _context(report: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """A well-formed keyed comparison context, or None.

    Anything else (absent, another version or algorithm, missing or mistyped
    parts) is not used at all, so that a truncated context cannot pass as an
    unchanged one. Well-formed is not authenticated: reports are not signed.
    """
    context = report.get("comparison_context")
    if not isinstance(context, Mapping) or type(context.get("version")) is not int:
        return None
    key_id = context.get("key_id")
    if (context["version"] != CONTEXT_VERSION or context.get("algorithm") != CONTEXT_ALGORITHM
            or not isinstance(key_id, str) or not _FINGERPRINT.fullmatch(key_id)
            or not _fingerprint_or_none(context.get("target"))
            or not _fingerprint_or_none(context.get("credentials"))):
        return None
    identities, accounts, operations = context.get("identities"), context.get("account_ids"), context.get("operations")
    if not isinstance(identities, Mapping) or not isinstance(accounts, list) or not isinstance(operations, Mapping):
        return None
    roles = identities.get("roles")
    if (set(identities) != {"owner", "visitor", "anonymous", "roles"} or not isinstance(roles, Mapping)
            or not all(_fingerprint_or_none(identities[name]) for name in ("owner", "visitor", "anonymous"))
            or not all(isinstance(name, str) and _NAME.fullmatch(name) and _fingerprint_or_none(value)
                       for name, value in roles.items())
            or not all(isinstance(name, str) and _ACCOUNT.fullmatch(name) for name in accounts)):
        return None
    for operation, fingerprints in operations.items():
        if (_canonical_operation(operation) != operation or not isinstance(fingerprints, Mapping)
                or set(fingerprints) != {name for name, _ in _OPERATION_FINGERPRINTS}
                or not all(_fingerprint_or_none(value) for value in fingerprints.values())):
            return None
    return context


def _identity_state(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> Tuple[List[str], List[str]]:
    """Identities whose declared fingerprint changed, and identities that declare no account id."""
    old, new = baseline["identities"], current["identities"]
    changed = [name for name in ("owner", "visitor", "anonymous") if old[name] != new[name]]
    missing = object()
    role_names = sorted(set(old["roles"]) | set(new["roles"]))
    changed.extend(f"role:{name}" for name in role_names
                   if old["roles"].get(name, missing) != new["roles"].get(name, missing))

    def fingerprint(side: Mapping[str, Any], name: str) -> Any:
        return side["roles"].get(name[5:]) if name.startswith("role:") else side[name]

    # Every identity that sends requests must be fingerprinted and declare an account id in both reports.
    without_id = [name for name in ["owner", "visitor"] + [f"role:{name}" for name in role_names]
                  if name not in baseline["account_ids"] or name not in current["account_ids"]
                  or fingerprint(old, name) is None or fingerprint(new, name) is None]
    return changed, without_id


def _version(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _VERSION.fullmatch(value) else None


def _timestamp(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _TIMESTAMP.fullmatch(value) else None


def _numeric_stats(report: Mapping[str, Any]) -> Dict[str, float]:
    stats = report.get("stats")
    stats = stats if isinstance(stats, Mapping) else {}
    keys = ("total_endpoints", "coverage_pct", "conclusive_coverage_pct", "conclusive_count",
            "inconclusive_count", "skipped_count", "error_count", "confirmed")
    return {key: stats[key] for key in keys
            if type(stats.get(key)) in (int, float) and 0 <= stats[key] <= _STAT_LIMIT}


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


def _context_label(report: Mapping[str, Any]) -> str:
    if _context(report) is not None:
        return "keyed"
    return "absent" if report.get("comparison_context") is None else "invalid"


def _matching_contexts(baseline: Mapping[str, Any], current: Mapping[str, Any],
                       notes: Set[str]) -> Optional[Tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Both keyed contexts when each report has a well-formed one made with the same key."""
    old, new = _context(baseline), _context(current)
    if "invalid" in (_context_label(baseline), _context_label(current)):
        notes.add("comparison_context_invalid")
    if old is None or new is None:
        return None
    if old["key_id"] != new["key_id"]:
        notes.add("comparison_keys_differ")
        return None
    return old, new


def _declared_operation_changes(contexts: Tuple[Mapping[str, Any], Mapping[str, Any]],
                                operations: Iterable[str]) -> Dict[str, List[str]]:
    """Per operation, what the keyed fingerprints show as changed or cannot show at all."""
    changes: Dict[str, List[str]] = {}
    for operation in sorted(operations):
        before = contexts[0]["operations"].get(operation)
        after = contexts[1]["operations"].get(operation)
        if before is None or after is None or None in before.values() or None in after.values():
            changes[operation] = ["context_incomplete"]
            continue
        reasons = [reason for name, reason in _OPERATION_FINGERPRINTS if before[name] != after[name]]
        if reasons:
            changes[operation] = reasons
    return changes


def compare_reports(baseline: Mapping[str, Any], current: Mapping[str, Any], *,
                    assume_same_target: bool = False, assume_same_identities: bool = False) -> Dict[str, Any]:
    """Compare two validated reports; see the module docstring for the rules.

    The two assumptions are the caller's explicit statements for what the
    reports cannot show. ``assume_same_target``: both scans targeted the same
    deployment although their targets differ or cannot be read (for example a
    local service restarted on a new port). ``assume_same_identities``: both
    scans used the same test accounts although no keyed context verifies it.
    Neither overrides a detected change of identities, specification, policy or
    resources. Each is recorded on the comparison and on every finding that
    relies on it, and keeps the comparison from being fully comparable.
    """
    old, new = _Index(baseline), _Index(current)
    notes: Set[str] = set()
    contexts = _matching_contexts(baseline, current, notes)
    declared = contexts is not None

    changes: List[Dict[str, Any]] = []
    blocking: List[str] = []
    assumptions: List[str] = []
    old_version, new_version = _version(baseline.get("tool_version")), _version(current.get("tool_version"))
    same_version = old_version is not None and old_version == new_version
    if not same_version:
        changes.append({"kind": "tool_version", "baseline": old_version, "current": new_version, "blocking": False})

    # Target: keyed fingerprints when declared, otherwise the report targets themselves.
    if contexts is not None:
        old_target, new_target = contexts[0]["target"], contexts[1]["target"]
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

    # Identities: verified only by keyed fingerprints of identities that declare an account id,
    # with unchanged credentials.
    cause: Optional[str] = "no_keyed_context"
    unverified: List[str] = []
    if contexts is not None:
        changed, unverified = _identity_state(*contexts)
        if changed:
            # A detected change is a fact, not something an assumption can cover.
            changes.append({"kind": "identities", "state": "changed", "identities": changed, "blocking": True})
            blocking.append("identities_changed")
            cause = None
        elif unverified:
            cause = "no_account_id"
        elif contexts[0]["credentials"] is None or contexts[0]["credentials"] != contexts[1]["credentials"]:
            # The same declared identities with another credential: rotated, or another account's.
            cause = "credentials_changed"
        else:
            cause = None
    if cause is not None:
        change: Dict[str, Any] = {"kind": "identities", "state": "unverified", "cause": cause,
                                  "identities": unverified}
        if assume_same_identities:
            assumptions.append("same_identities")
            change.update({"acknowledged": True, "blocking": False})
        else:
            blocking.append("identities_unverified")
            change["blocking"] = True
        changes.append(change)

    if old.unreadable or new.unreadable:
        # An unreadable record that may be a confirmed finding could contradict any conclusion.
        unattributed = bool(old.unattributed or new.unattributed)
        changes.append({"kind": "unreadable_results", "baseline": old.unreadable, "current": new.unreadable,
                        "blocking": unattributed})
        if unattributed:
            blocking.append("unreadable_results")
        else:
            notes.add("unreadable_results_ignored")
    added = sorted(new.operations - old.operations)
    removed = sorted(old.operations - new.operations)
    if added:
        changes.append({"kind": "operations_added", "count": len(added), "blocking": False})
    if removed:
        changes.append({"kind": "operations_removed", "count": len(removed), "blocking": False})

    # Operations in only one report are already reported as added or removed.
    declared_changes = (_declared_operation_changes(contexts, old.operations & new.operations)
                        if contexts is not None else {})
    operation_changes: Dict[str, Set[str]] = {operation: set(reasons)
                                              for operation, reasons in declared_changes.items()}

    def scope_reasons(key: Key, left: _Entry, right: _Entry) -> List[str]:
        local = set(declared_changes.get(key[1], ()))
        # The evidence is compared on either basis: it also shows what no fingerprint covers.
        if left.resources and right.resources:
            if left.resources != right.resources:
                local.add("resources_changed")
        elif not declared:
            local.add("scope_unknown")
        if left.policy and right.policy and left.policy != right.policy:
            local.add("policy_changed")
        if local:
            operation_changes.setdefault(key[1], set()).update(local)
        return blocking + sorted(local)

    issues: List[Dict[str, Any]] = []
    for key in sorted(set(old.entries) | set(new.entries), key=lambda item: (item[1], item[0], item[2] or "")):
        before, after = old.entries.get(key), new.entries.get(key)
        if not ((before is not None and before.confirmed) or (after is not None and after.confirmed)):
            continue
        if (before is not None and before.ambiguous) or (after is not None and after.ambiguous):
            status, reasons = "not_comparable", blocking + ["subject_unknown"]
        elif after is not None and after.confirmed:
            if before is not None and before.confirmed:
                reasons = scope_reasons(key, before, after)
                status = "not_comparable" if reasons else "persisting"
            elif before is None and key[1] not in old.operations:
                # First detection on an operation the baseline did not contain: not a proven regression.
                status, reasons = "not_comparable", blocking + ["operation_not_in_baseline"]
            elif before is None:
                status, reasons = "not_comparable", blocking + ["not_checked_in_baseline"]
                before = old.operation_level(key)
            elif before.conclusive_negative:
                reasons = scope_reasons(key, before, after)
                status = "not_comparable" if reasons else "new"
            else:
                status, reasons = "not_comparable", blocking + ["baseline_unverified"]
        else:
            assert before is not None
            if after is None:
                fallback = new.operation_level(key)
                if key[1] not in new.operations:
                    status, reasons = "not_comparable", blocking + ["operation_not_in_current"]
                elif fallback is not None and not fallback.conclusive_negative:
                    status, reasons = "not_comparable", blocking + ["current_unverified"]
                    after = fallback
                else:
                    status, reasons = "not_comparable", blocking + ["missing_in_current"]
            elif after.conclusive_negative:
                reasons = scope_reasons(key, before, after)
                status = "not_comparable" if reasons else "resolved"
            else:
                status, reasons = "not_comparable", blocking + ["current_unverified"]
        issue = _describe(key)
        issue.update({"status": status, "baseline_verdicts": _sorted_verdicts(before),
                      "current_verdicts": _sorted_verdicts(after)})
        if reasons:
            issue["reasons"] = reasons
        if status != "not_comparable" and assumptions:
            issue["assumptions"] = list(assumptions)
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
    summary["relying_on_assumptions"] = sum(1 for issue in issues if issue.get("assumptions"))
    summary["baseline_confirmed"] = sum(1 for entry in old.entries.values() if entry.confirmed)
    summary["current_confirmed"] = sum(1 for entry in new.entries.values() if entry.confirmed)
    return {
        "comparison_schema_version": COMPARISON_SCHEMA_VERSION,
        "tool_version": __version__,
        "baseline": {"tool_version": old_version, "generated_at": _timestamp(baseline.get("generated_at")),
                     "context": _context_label(baseline)},
        "current": {"tool_version": new_version, "generated_at": _timestamp(current.get("generated_at")),
                    "context": _context_label(current)},
        "comparability": {
            "basis": "declared" if declared else "evidence",
            # True only when keyed contexts show the same target, identities (each with an account
            # id), specification, policy and resources, the same tool version produced both reports,
            # every result could be read and nothing was assumed.
            "fully_comparable": (declared and not blocking and not assumptions and not operation_changes
                                 and same_version and not old.unreadable and not new.unreadable),
            "blocking": blocking,
            "assumptions": assumptions,
            "operation_changes": [{"operation": operation, "reasons": sorted(reasons)}
                                  for operation, reasons in sorted(operation_changes.items())],
            "changes": changes,
            "notes": sorted(notes),
            "not_verified": list(NOT_VERIFIED),
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


def _ascii(value: Any) -> str:
    """Text taken from a report, for a terminal: printable ASCII only."""
    return "".join(character if " " <= character <= "~" else f"\\u{ord(character):04x}" for character in str(value))


_NOTE_TEXT = {
    "comparison_keys_differ": "the reports were made with different comparison keys; keyed fingerprints "
                              "were not used",
    "comparison_context_invalid": "a comparison context is malformed or from an unsupported version and "
                                  "was not used",
    "unreadable_results_ignored": "some result records could not be read and were ignored",
}
_BLOCKING_HINT = {
    "target_changed": "the targets differ (scheme, host, port or base path). If both scans tested the same "
                      "deployment, state it with --assume-same-target",
    "target_unknown": "a target cannot be read. Set the comparison key for both scans, or state the same "
                      "deployment with --assume-same-target",
    "identities_changed": "the declared test identities differ; these scans are not comparable",
    "unreadable_results": "a result record that may be a confirmed finding could not be read",
}


_IDENTITY_CAUSE = {
    "no_keyed_context": f"test accounts not verified: both scans need the same {COMPARISON_KEY_ENV}",
    "no_account_id": "test accounts not verified: identities without an account id",
    "credentials_changed": "test accounts not verified: a credential differs between the scans (a rotation "
                           "and another account's credential look the same)",
}


def summary_lines(comparison: Mapping[str, Any]) -> List[str]:
    summary = comparison["summary"]
    comparability = comparison["comparability"]
    coverage = comparison["coverage"]
    lines = [
        "GrantTrace report comparison",
        f"Baseline: GrantTrace {_ascii(comparison['baseline']['tool_version'] or 'unknown version')}, "
        f"generated {_ascii(comparison['baseline']['generated_at'] or 'unknown')}",
        f"Current:  GrantTrace {_ascii(comparison['current']['tool_version'] or 'unknown version')}, "
        f"generated {_ascii(comparison['current']['generated_at'] or 'unknown')}",
    ]
    if comparability["blocking"]:
        lines.append("Comparability: NOT comparable for any finding (" + ", ".join(comparability["blocking"]) + ")")
        lines.extend("  " + _BLOCKING_HINT[reason] for reason in comparability["blocking"] if reason in _BLOCKING_HINT)
    elif comparability["fully_comparable"]:
        lines.append("Comparability: declared configuration unchanged (keyed fingerprints in both reports)")
    else:
        limits = [f"assumed by the caller: {name}" for name in comparability["assumptions"]]
        if comparability["operation_changes"]:
            limits.append(f"{len(comparability['operation_changes'])} operation(s) changed or unverifiable")
        if any(change["kind"] == "tool_version" for change in comparability["changes"]):
            limits.append("different or unknown tool versions")
        if any(change["kind"] == "unreadable_results" for change in comparability["changes"]):
            limits.append("unreadable results")
        lines.append("Comparability: limited (" + "; ".join(limits or ["see notes"]) + ")")
    for change in comparability["changes"]:
        if change["kind"] == "tool_version":
            lines.append(f"  note: tool versions: {_ascii(change['baseline'] or 'unknown')} and "
                         f"{_ascii(change['current'] or 'unknown')}")
        elif change["kind"] == "identities" and change["state"] == "changed":
            lines.append("  identities changed: " + ", ".join(_ascii(name) for name in change["identities"]))
        elif change["kind"] == "identities":
            line = "  " + _IDENTITY_CAUSE[change["cause"]]
            if change["identities"]:
                line += ": " + ", ".join(_ascii(name) for name in change["identities"])
            line += (" (assumed the same by --assume-same-identities)" if change.get("acknowledged")
                     else "; state the same accounts with --assume-same-identities only if you know it")
            lines.append(line)
    for item in comparability["operation_changes"]:
        lines.append(f"  operation {_ascii(item['operation'])}: " + ", ".join(item["reasons"]))
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
        subject = f" [{_ascii(issue['subject'])}]" if issue.get("subject") else ""
        line = (f"  {labels[issue['status']]:<15} {issue['finding_id']} {issue['check']} "
                f"{_ascii(issue['operation'])}{subject}")
        if issue.get("reasons"):
            line += " (" + ", ".join(issue["reasons"]) + ")"
        if issue.get("assumptions"):
            line += " [assumed: " + ", ".join(issue["assumptions"]) + "]"
        lines.append(line)
    if summary["not_comparable"]:
        lines.append("Not comparable findings are neither proven new nor fixed; see the reason codes.")
    if summary["current_confirmed_not_comparable"]:
        lines.append("Confirmed in the current scan without comparable baseline evidence: "
                     f"{summary['current_confirmed_not_comparable']}.")
    if summary["relying_on_assumptions"]:
        lines.append("Conclusions that rely on assumptions stated by the caller, not on verification: "
                     f"{summary['relying_on_assumptions']}.")
    lines.append("Reports are not authenticated, and test data on the server may differ between the scans; "
                 "resolved means no longer reproduced with this configuration.")
    return lines


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="granttrace diff",
        allow_abbrev=False,  # an assumption must be spelled out in full
        description=("Compare two GrantTrace JSON scan reports offline. Confirmed findings are classified as "
                     "new, persisting, resolved or not comparable; SKIPPED or INCONCLUSIVE results never count "
                     "as fixed. No network access; no evidence or response data is copied."),
        epilog=(f"Set the same {COMPARISON_KEY_ENV} ({MIN_COMPARISON_KEY_LENGTH}+ random characters) during both "
                "scans and give every test identity an account id, so that the reports carry keyed fingerprints "
                "of target, identities, specification, policy and resources and diff can verify that the declared "
                "configuration is unchanged. Otherwise findings are not comparable unless you state the "
                "assumptions below."),
    )
    parser.add_argument("baseline", metavar="BASELINE.json", help="Earlier GrantTrace JSON report (--export-json)")
    parser.add_argument("current", metavar="CURRENT.json", help="Later GrantTrace JSON report (--export-json)")
    parser.add_argument("--export-json", metavar="PATH", default=None,
                        help="Write the machine-readable comparison to PATH")
    parser.add_argument("--assume-same-target", action="store_true",
                        help=("State that both scans targeted the same deployment although their targets differ "
                              "or cannot be read (for example a local service restarted on a new port). Recorded "
                              "in the output; use it only when you know it is true"))
    parser.add_argument("--assume-same-identities", action="store_true",
                        help=("State that both scans used the same test accounts although the reports cannot "
                              "show it (no comparison key, different keys, or identities without an account id). "
                              "It never overrides a detected change. Recorded in the output; use it only when "
                              "you know it is true"))
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
        output = (_checked_output(args.export_json, (args.baseline, args.current))
                  if args.export_json is not None else None)
        reports = []
        for label, path in (("baseline", args.baseline), ("current", args.current)):
            try:
                reports.append(load_report(path))
            except ReportError as exc:
                raise ReportError(f"{label} report: {exc}") from exc
        comparison = compare_reports(reports[0], reports[1], assume_same_target=args.assume_same_target,
                                     assume_same_identities=args.assume_same_identities)
    except ReportError as exc:
        print(f"[ERROR] {_printable(exc)}", file=sys.stderr)
        return 2
    for line in summary_lines(comparison):
        print(line)
    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("w", encoding="utf-8") as handle:
                # ASCII only: no bidirectional or other invisible characters reach a viewer of the file.
                json.dump(comparison, handle, indent=2, ensure_ascii=True, allow_nan=False)
                handle.write("\n")
        except OSError as exc:
            print(f"[ERROR] cannot write comparison JSON ({type(exc).__name__})", file=sys.stderr)
            return 2
        print(f"[OK] Comparison JSON: {_printable(output)}")
    return 0
