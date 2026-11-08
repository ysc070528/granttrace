# -*- coding: utf-8 -*-
"""Safety-first API audit orchestration.

Read-only BOLA checks run by default. State-changing mass-assignment checks
require an explicit opt-in and an independent readback mapping. Confirmed
changes are rolled back and the rollback is verified.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Pattern, Set, Tuple

from core import __version__
from core.authorization import AuthorizationEvidence
from core.bopla import BOPLAEvidence, validate_bopla_policy
from core.config_validator import ConfigValidator
from core.diff import ResponseDiffEngine
from core.evidence import body_sha256, sanitize_body, sanitize_evidence
from core.transactions import PatchSnapshot, ensure_reversible_merge_patch, get_path, prepare_patch
from core.generator import SmartDataGenerator
from core.models import HTTPResult, Verdict, json_values_equal, parse_operation_key, strict_json_loads
from core.parser import OpenAPIParser
from core.remote_refs import RemoteRefConfig, RemoteRefError, sanitize_error_message
from core.request_builder import RequestBuilderMixin
from core.results import ResultRecorderMixin
from core.parameters import ParameterSerializationError
from core.scan_safety import read_only_risk, read_path_risk
from core.transport import HttpTransport


@dataclass(frozen=True)
class _ReadSafetyCache:
    parser: OpenAPIParser
    routes: Tuple[Tuple[Pattern[str], Optional[Tuple[Tuple[str, str], ...]]], ...]
    readbacks: Mapping[Tuple[str, str], Mapping[str, Any]]


class APISentinelAuditor(RequestBuilderMixin, ResultRecorderMixin):
    # Both methods require independent actual-state authority. PUT additionally
    # requires an unambiguous full root-document replacement snapshot.
    WRITE_METHODS = {"PATCH", "PUT"}
    AUTH_DENIAL_STATUSES = {401, 403}
    INVALID_TEST_STATUSES = {400, 404, 405, 409, 415, 422}

    def __init__(
        self,
        spec_path: str,
        target_base_url: str,
        max_workers: int = 4,
        request_delay: float = 0.05,
        identities_config: Optional[Dict[str, Any]] = None,
        insecure_ssl: bool = False,
        allow_http: bool = False,
        allow_write_tests: bool = False,
        readback_config: Optional[Dict[str, Any]] = None,
        parameter_values: Optional[Dict[str, Any]] = None,
        write_allowlist: Optional[Iterable[str]] = None,
        request_timeout: float = 6.0,
        max_response_bytes: int = 1024 * 1024,
        include_sensitive_evidence: bool = False,
        bola_config: Optional[Dict[str, Any]] = None,
        bopla_config: Optional[Dict[str, Any]] = None,
        remote_ref_config: Optional[RemoteRefConfig] = None,
        offline: bool = False,
    ) -> None:
        self._validate_target(target_base_url, allow_http)
        self.remote_ref_config = remote_ref_config
        self.offline = bool(offline)
        self.parser = OpenAPIParser(spec_path, remote_ref_config=remote_ref_config, offline=self.offline)
        self.parser.get_security_schemes()  # Validate authentication before identity checks or transport.
        self.target_base_url = target_base_url.rstrip("/")
        self.max_workers = max(1, int(max_workers))
        self._transport = HttpTransport(
            request_delay=max(0.0, float(request_delay)),
            request_timeout=max(0.1, float(request_timeout)),
            max_response_bytes=max(1024, int(max_response_bytes)),
            insecure_ssl=bool(insecure_ssl),
        )
        self.insecure_ssl = bool(insecure_ssl)
        self.allow_write_tests = bool(allow_write_tests)
        self.include_sensitive_evidence = bool(include_sensitive_evidence)
        def _canonical_op_key(k: Any) -> str:
            if not isinstance(k, str):
                return str(k)
            parts = k.strip().split()
            if len(parts) == 2:
                return f"{parts[0]} {parts[1]}"
            return k.strip()

        self.readback_config = {
            _canonical_op_key(k): v
            for k, v in (readback_config or {}).items()
        }
        self.parameter_values = {
            _canonical_op_key(k): v
            for k, v in (parameter_values or {}).items()
        }
        self.bola_config = {
            _canonical_op_key(k): v
            for k, v in (bola_config or {}).items()
        }
        self.bopla_config = dict(bopla_config or {})
        self._bopla_local = threading.local()
        self._bopla_leak_groups: Dict[Tuple[Any, ...], str] = {}
        self._bopla_resource_groups: Dict[Tuple[Any, ...], int] = {}
        self._bopla_secret_values: set[str] = set()
        self.write_allowlist = set()
        for item in write_allowlist or []:
            c_key = _canonical_op_key(item)
            is_valid, method, path, canonical, err_msg = parse_operation_key(c_key)
            if not is_valid or method not in self.WRITE_METHODS:
                raise ValueError("write_allowlist entries must be 'PATCH /case-sensitive-path' or 'PUT /case-sensitive-path'")
            self.write_allowlist.add(canonical)
        self._writes_halted_reason: Optional[str] = None

        self._result_lock = threading.Lock()
        self._write_lock = threading.RLock()
        self._request_accounting = threading.local()
        self._resource_locks: Dict[str, threading.Lock] = {}
        self._resource_locks_guard = threading.Lock()

        self.identities = identities_config or {
            "owner": {
                "id": "1001",
                "token": "Bearer TOKEN_ALICE_OWNER_1001",
                "parameters": {"user_id": "1001"},
            },
            "visitor": {
                "id": "1002",
                "token": "Bearer TOKEN_BOB_VISITOR_1002",
                "parameters": {"user_id": "1002"},
            },
            "anonymous": {"id": None, "token": None, "parameters": {}},
        }
        self._validate_identities()
        self._secret_values = self._collect_auth_secret_values()
        self._auth_parser = self.parser
        self._auth_parser_lock = threading.Lock()

        self.findings: List[Dict[str, Any]] = []
        self.results: List[Dict[str, Any]] = []
        self.stats: Dict[str, Any] = {
            "total_endpoints": 0,
            "total_checks": 0,
            "audited_count": 0,
            "conclusive_count": 0,
            "attempted_endpoints": 0,
            "conclusive_endpoints": 0,
            "confirmed": 0,
            "bola_confirmed": 0,
            "mass_assignment_confirmed": 0,
            "broken_auth_confirmed": 0,
            "bfla_confirmed": 0,
            "transport_attempts": 0,
            "http_requests_sent": 0,
            "rate_limit_retries": 0,
            "public_endpoints": 0,
            "authorized_endpoints": 0,
            "secure_endpoints": 0,
            "suspicious_count": 0,
            "inconclusive_count": 0,
            "skipped_count": 0,
            "error_count": 0,
            "raw_filtered_count": 0,
            "coverage_pct": 0.0,
            "conclusive_coverage_pct": 0.0,
        }
        self._read_safety_cache_lock = threading.Lock()
        self._read_safety_cache = self._build_read_safety_cache(self.parser)

    @staticmethod
    def _validate_target(target: str, allow_http: bool) -> None:
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an absolute http:// or https:// URL")
        if parsed.username or parsed.password:
            raise ValueError("credentials must not be embedded in the target URL")
        if parsed.query or parsed.fragment:
            raise ValueError("target must be a base URL without query parameters or fragments")
        if parsed.scheme == "http" and not allow_http:
            hostname = parsed.hostname.lower()
            is_loopback = hostname == "localhost"
            if not is_loopback:
                try:
                    is_loopback = ipaddress.ip_address(hostname).is_loopback
                except ValueError:
                    is_loopback = False
            if not is_loopback:
                raise ValueError("plain HTTP is allowed only for loopback targets; use --allow-http to opt in")

    @property
    def request_delay(self) -> float:
        return self._transport.request_delay

    @property
    def request_timeout(self) -> float:
        return self._transport.request_timeout

    @property
    def max_response_bytes(self) -> int:
        return self._transport.max_response_bytes

    def secret_values(self) -> FrozenSet[str]:
        """Return the secret values published so far, for redacting output.

        The set grows while a scan discovers secrets, so callers take a new
        snapshot after the scan. The published set is only ever replaced,
        never mutated, so reading it needs no lock.
        """
        return frozenset(self._secret_values)

    def _publish_secret_values(self, values: Set[str]) -> None:
        """Replace the published secret set; never mutate a shared snapshot.

        Workers iterate ``_secret_values`` without a lock while recording
        evidence, and ``_read_observation`` replaces it under the result lock.
        An unlocked in-place ``add`` could raise during that iteration or land
        in a set that was already replaced, losing a value from redaction.
        """
        if not values or values <= self._secret_values:
            return
        with self._result_lock:
            self._secret_values = self._secret_values | values

    def _ensure_parser_auth(self) -> None:
        # Replacing the parser is supported only between scans. Publish its
        # authentication state after validation, including for direct requests.
        if self._auth_parser is self.parser:
            return
        with self._auth_parser_lock:
            parser = self.parser
            if self._auth_parser is parser:
                return
            parser.get_security_schemes()
            self._validate_identities()
            secrets = self._secret_values.union(self._collect_auth_secret_values())
            with self._result_lock:
                self._secret_values = secrets
                # A previously ordinary value may now be an authentication
                # secret. Scrub earlier observations and retained aliases too.
                if self.bopla_config:
                    self._redact_property_history()
                else:
                    for collection in (self.results, self.findings):
                        for record in collection:
                            safe = sanitize_evidence(record, self.include_sensitive_evidence, secrets)
                            self._replace_evidence_in_place(record, safe)
            self._auth_parser = parser

    @staticmethod
    def _build_read_safety_cache(parser: OpenAPIParser) -> _ReadSafetyCache:
        routes = []
        readbacks: Dict[Tuple[str, str], Mapping[str, Any]] = {}
        for endpoint in parser.get_endpoints():
            method, path = endpoint["method"], endpoint["path"]
            shape = re.sub(r"\{[^}]+\}", "{}", path)
            metadata = {key: endpoint[key] for key in (
                "method", "path", "operation_id", "summary", "description", "spec_version", "parameters"
            )}
            readbacks.setdefault((method, shape), MappingProxyType(metadata))
            if method in {"GET", "HEAD"}:
                pattern = re.escape(path)
                pattern = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", pattern)
                risk = read_only_risk(endpoint)
                routes.append((re.compile(pattern), tuple(risk.items()) if risk else None))
        return _ReadSafetyCache(parser, tuple(routes), MappingProxyType(readbacks))

    def _read_safety_snapshot(self) -> _ReadSafetyCache:
        # Specifications and references are load-once parser snapshots. Replacing
        # the parser explicitly reloads safety metadata; arbitrary in-place edits
        # of raw_spec are not a supported reload mechanism.
        cache = self._read_safety_cache
        if cache.parser is self.parser:
            return cache
        with self._read_safety_cache_lock:
            if self._read_safety_cache.parser is not self.parser:
                replacement = self._build_read_safety_cache(self.parser)
                self._read_safety_cache = replacement
            return self._read_safety_cache

    def _read_request_risk(self, method: str, url: str) -> Optional[Dict[str, str]]:
        """Check concrete routing semantics before transport or write baselines."""
        if str(method).upper() in {"GET", "HEAD"}:
            # Inspect the entire concrete path, including the target prefix,
            # on every call. A cached safe template cannot certify its values.
            ambiguity = read_path_risk(url)
            if ambiguity:
                return ambiguity
            request_path = urllib.parse.urlsplit(url).path or "/"
            base_path = urllib.parse.urlsplit(self.target_base_url).path.rstrip("/")
            if base_path and request_path == base_path:
                request_path = "/"
            elif base_path and request_path.startswith(base_path + "/"):
                request_path = request_path[len(base_path):]
            request_paths = {request_path, urllib.parse.unquote(request_path)}
            # Some routers ignore trailing slashes or matrix suffixes. These
            # candidates can add a risky match, never certify a safe route.
            risk_paths = {path.rstrip("/") or "/" for path in request_paths}
            for path in request_paths:
                if ";" in path:
                    parts = [part.split(";", 1)[0] for part in path.split("/")]
                    risk_paths.add("/" + "/".join(part for part in parts if part))
            documented = False
            for pattern, risk in self._read_safety_snapshot().routes:
                if any(pattern.fullmatch(path) for path in request_paths):
                    documented = True
                    if risk:
                        return dict(risk)
                elif risk and any(pattern.fullmatch(path) for path in risk_paths):
                    return dict(risk)
            if not documented:
                return read_only_risk({"method": method, "path": urllib.parse.unquote(request_path)})
        return None

    def _http_request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        identity_name: str = "anonymous",
        content_type: str = "application/json",
        headers: Optional[Dict[str, str]] = None,
    ) -> HTTPResult:
        """Send one request; every request the auditor makes passes through here.

        This applies the read-safety check, request accounting and the bounded
        rate-limit retry for GET/HEAD. Tests and the bundled demo replace it to
        answer without a network. Together with ``_authoritative_patch_state`` it
        is a supported extension point: both keep their names and signatures.
        """
        self._ensure_parser_auth()
        if getattr(self._request_accounting, "attempts", None) is None:
            self._request_accounting.attempts = 0
        risk = self._read_request_risk(method, url)
        if risk:
            return HTTPResult(status=0, body="", error=risk["safety_reason"])
        attempt = 0
        while True:
            result = self._send_http_request(method, url, data, identity_name, content_type, headers)
            wait = (self._transport.rate_limit_wait(method, result, attempt)
                    if attempt < self._transport.RATE_LIMIT_RETRIES else None)
            if wait is None:
                return result
            with self._result_lock:
                self.stats["rate_limit_retries"] += 1
            self._transport.defer(wait)
            attempt += 1

    def _send_http_request(
        self, method: str, url: str, data: Optional[Dict[str, Any]], identity_name: str,
        content_type: str, headers: Optional[Dict[str, str]],
    ) -> HTTPResult:
        self._transport.throttle()
        try:
            request_headers = headers if headers is not None else self.identity_headers(identity_name)
        except Exception as exc:
            return HTTPResult(status=0, body="", error=f"{type(exc).__name__}: {exc}")
        return self._transport.send(
            method, url, request_headers, data, content_type,
            on_attempt=self._count_transport_attempt, on_response=self._count_request_sent,
        )

    def _count_transport_attempt(self) -> None:
        self._request_accounting.attempts = (getattr(self._request_accounting, "attempts", None) or 0) + 1
        with self._result_lock:
            self.stats["transport_attempts"] += 1

    def _count_request_sent(self) -> None:
        with self._result_lock:
            self.stats["http_requests_sent"] += 1

    def _safe_body(self, result: HTTPResult, private_values: Iterable[str] = ()) -> Dict[str, Any]:
        if getattr(self._bopla_local, "policy", None) is not None:
            # Shared legacy observations must not persist property values or
            # enumerable response hashes, even with sensitive evidence opt-in.
            return {"status": result.status, "body": "[BOPLA RESPONSE OMITTED]",
                    "sha256": None, "truncated": result.truncated,
                    "error": "Transport failed" if result.error else None}
        secrets = (*self._secret_values, *private_values)
        if self.bopla_config:
            # A different worker may only discover a private reference later.
            # Pending bodies stay internal for comparison compatibility; every
            # public report omits them and no response digest is ever retained.
            body = "[BOPLA RESPONSE OMITTED]" if self._bopla_secret_values else sanitize_body(
                result.body, include_sensitive=False, max_chars=min(self.max_response_bytes, 4096),
                secret_values=secrets)
            body = re.sub(r"sha256=[0-9a-f]{64}", "digest omitted", body)
            return {"status": result.status, "body": body, "sha256": None,
                    "truncated": result.truncated, "error": "Transport failed" if result.error else None}
        return sanitize_evidence({
            "status": result.status,
            "body": sanitize_body(
                result.body,
                include_sensitive=self.include_sensitive_evidence,
                max_chars=min(self.max_response_bytes, 4096),
                secret_values=secrets,
            ),
            "sha256": body_sha256(result.body),
            "truncated": result.truncated,
            "error": result.error,
        }, self.include_sensitive_evidence, secrets)

    def _read_observation(
        self, method: str, url: str, identity_name: str, headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> HTTPResult:
        result = self._http_request(method, url, data=data, identity_name=identity_name, headers=headers)
        observations = getattr(self._bopla_local, "observations", None)
        if observations is not None:
            observations[(url, identity_name)] = result
            # Register known values before recording any shared legacy evidence.
            try:
                document = strict_json_loads(result.body)
                values = []
                for rule in self._bopla_local.policy.get("fields", []):
                    found, value = get_path(document, rule["path"])
                    if found and ((isinstance(value, str) and value) or type(value) in (int, float)):
                        values.append(str(value))
            except (TypeError, ValueError, KeyError, RecursionError):
                # Malformed observations remain available to the evaluator's
                # conservative invalid-response decision. Redaction failures
                # themselves must not be silently swallowed.
                return result
            with self._result_lock:
                self._bopla_secret_values = self._bopla_secret_values.union(values)
                # Replace sets atomically: other workers may be iterating an
                # older snapshot while preserving the ordinary secret API.
                self._secret_values = self._secret_values.union(values)
                if values:
                    self._redact_property_history()
        return result

    def audit_endpoint_bola(self, ep: Dict[str, Any]) -> None:
        key = self._operation_key(ep)
        if ep.get("unresolved_schema_error"):
            sanitized_err = sanitize_error_message(ep["unresolved_schema_error"])
            reason = f"Schema could not be resolved safely: {sanitized_err}; no request was sent"
            if key in self.bopla_config:
                self._record_result(ep, "BOPLA", Verdict.INCONCLUSIVE, reason, {"requests_attempted": 0, "requests_sent": 0, "reason_category": "unresolved_reference"})
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE, reason, {"requests_attempted": 0, "requests_sent": 0, "reason_category": "unresolved_reference"})
            return
        if key not in self.bopla_config:
            self._audit_endpoint_bola(ep)
            return
        policy = self.bopla_config[key]
        if validate_bopla_policy(policy):
            self._record_result(ep, "BOPLA", Verdict.INCONCLUSIVE,
                                "Invalid property policy; run offline configuration validation; no request sent",
                                {"requests_attempted": 0, "reason_category": "invalid_input"})
            return
        risk = read_only_risk(ep)
        if str(ep.get("method", "")).upper() != "GET" or risk:
            self._record_result(ep, "BOPLA", Verdict.SKIPPED,
                                "Property checks require a safe GET; no request sent",
                                {"requests_attempted": 0, "reason_category": "safety_policy"})
            return
        try:
            url = self._build_url(ep, "owner")
            self_url = self._build_url(ep, "visitor")
            observation_headers = {
                identity: self._build_request_headers(ep, "owner", identity)
                for identity in ("owner", "visitor", "anonymous")
            }
        except (ParameterSerializationError, RemoteRefError) as exc:
            self._record_result(ep, "BOPLA", Verdict.INCONCLUSIVE,
                                f"Property resource parameters cannot be serialized: {exc}",
                                {"requests_attempted": 0, "reason_category": "invalid_input"})
            return
        if self._read_request_risk("GET", url) or self._read_request_risk("GET", self_url):
            self._record_result(ep, "BOPLA", Verdict.SKIPPED,
                                "Property resource GET is unsafe; no request sent",
                                {"requests_attempted": 0, "reason_category": "safety_policy"})
            return
        self._bopla_local.policy = policy
        self._bopla_local.observations = {}
        try:
            self._audit_endpoint_bola(ep)
            observations = self._bopla_local.observations
            for identity in ("owner", "visitor", "anonymous"):
                if (url, identity) not in observations:
                    self._read_observation("GET", url, identity, headers=observation_headers[identity])
            owner = observations[(url, "owner")]
            # Every field rule compares the same observations; parse each once.
            assessments: Dict[int, Tuple[HTTPResult, Dict[str, Any]]] = {}
            for rule in policy["fields"]:
                for identity in ("visitor", "anonymous"):
                    decision = BOPLAEvidence.evaluate(
                        owner, observations[(url, identity)], policy=policy,
                        field=rule, identity=identity,
                        visitor_self=observations.get((self_url, "visitor")) if self_url != url else None,
                        assessments=assessments,
                    )
                    evidence = {"observation_group": key + ":read", "shared_observations": True,
                                "target_url": url, "requests_attempted": len(observations),
                                "decision_evidence": decision["evidence"]}
                    finding = None
                    if decision["verdict"] == Verdict.CONFIRMED:
                        finding = {"check": "BOPLA", "type": "BOPLA (Broken Object Property Level Authorization)",
                                   "cwe": "CWE-200", "severity": "High", "endpoint": key,
                                   "target_url": url, "details": decision["reason"], "evidence": evidence}
                    self._record_result(ep, "BOPLA", decision["verdict"], decision["reason"], evidence, finding)
        finally:
            self._bopla_local.policy = None
            self._bopla_local.observations = None


    SENSITIVE_KEY_PATTERN = re.compile(
        r"(?i)^(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"private[_-]?key|ssn|social[_-]?security|id[_-]?card|national[_-]?id|salary|income|"
        r"credit[_-]?card|bank[_-]?card|card[_-]?number|cvv|mobile|phone|telephone)$"
    )

    @classmethod
    def _extract_sensitive_values(cls, data: Any, current_path: str = "") -> List[Tuple[str, str, Any]]:
        findings = []
        if isinstance(data, dict):
            for k, v in data.items():
                p = f"{current_path}.{k}" if current_path else str(k)
                if cls.SENSITIVE_KEY_PATTERN.match(str(k)):
                    if isinstance(v, (str, int, float)) and str(v).strip():
                        s_val = str(v).strip()
                        # Skip already masked values (e.g. ***, [REDACTED], 138****0000)
                        if not ("*" in s_val or "[REDACTED]" in s_val.upper() or len(s_val) < 3):
                            findings.append((p, str(k), v))
                if isinstance(v, (dict, list)):
                    findings.extend(cls._extract_sensitive_values(v, p))
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                p = f"{current_path}[{idx}]"
                if isinstance(item, (dict, list)):
                    findings.extend(cls._extract_sensitive_values(item, p))
        return findings

    def _detect_sensitive_property_exposure(
        self, ep: Dict[str, Any], owner: HTTPResult, visitor: HTTPResult, evidence: Dict[str, Any]
    ) -> None:
        """Heuristic check for sensitive data unmasked to Visitor (OWASP API3: BOPLA / Excessive Exposure)."""
        if owner.status != 200 or visitor.status != 200 or not owner.body or not visitor.body:
            return
        try:
            owner_doc = strict_json_loads(owner.body)
            visitor_doc = strict_json_loads(visitor.body)
        except Exception:
            return
        owner_sensitives = self._extract_sensitive_values(owner_doc)
        if not owner_sensitives:
            return
        visitor_sensitives = dict((path, val) for path, _, val in self._extract_sensitive_values(visitor_doc))
        exposed_fields = []
        for path, key, val in owner_sensitives:
            # Check if exactly matching value leaked in visitor response
            if path in visitor_sensitives and json_values_equal(visitor_sensitives[path], val):
                exposed_fields.append((path, key))
            elif isinstance(visitor_doc, dict) and any(json_values_equal(v_val, val) for v_val in visitor_sensitives.values()):
                exposed_fields.append((path, key))
        if exposed_fields:
            field_names = [f[0] for f in exposed_fields]
            reason = f"Sensitive property exposure (BOPLA): unmasked sensitive fields {field_names} returned to unauthorized visitor"
            finding = {
                "type": "BOPLA (Excessive Sensitive Data Exposure)",
                "cwe": "CWE-200",
                "severity": "High",
                "endpoint": self._operation_key(ep),
                "target_url": evidence.get("target_url"),
                "details": reason,
                "evidence": {**evidence, "exposed_sensitive_paths": field_names},
            }
            with self._result_lock:
                self.stats["confirmed"] += 1
            self._record_result(ep, "BOPLA_EXPOSURE", Verdict.CONFIRMED, reason, evidence, finding)


    def _execute_rbac_matrix_checks(self, ep: Dict[str, Any]) -> None:
        """Evaluate multi-role RBAC access matrix across configured roles."""
        key = self._operation_key(ep)
        roles = self.identities.get("roles", {})
        if not roles or not isinstance(roles, dict):
            return
        matrix_entry: Dict[str, Any] = {"endpoint": key, "method": ep["method"], "roles": {}}
        policy = self.bola_config.get(key, {})
        required_role = policy.get("required_role")
        for role_name, role_data in roles.items():
            if not isinstance(role_data, dict):
                continue
            role_headers = dict(role_data.get("headers", {}))
            if role_data.get("token"):
                role_headers["Authorization"] = role_data["token"]
            try:
                url = self._build_url(ep, "owner")
                # For read-only POST or GET, send request
                body_data = policy.get("body")
                res = self._http_request(ep["method"], url, data=body_data, identity_name=role_name, headers=role_headers)
                status_code = res.status
                is_denied = status_code in (401, 403)
                is_ok = status_code == 200
                access_verdict = "ALLOWED" if is_ok else "DENIED" if is_denied else f"HTTP_{status_code}"
                # Check for privilege violation if endpoint requires specific higher role
                has_violation = False
                user_role = role_data.get("role", role_name)
                if required_role and is_ok and user_role != required_role:
                    has_violation = True
                    access_verdict = "VIOLATION"
                matrix_entry["roles"][role_name] = {
                    "status": status_code,
                    "access": access_verdict,
                    "role": user_role,
                    "violation": has_violation,
                }
                if has_violation:
                    reason = f"RBAC Privilege Violation: Role '{role_name}' accessed restricted endpoint requiring '{required_role}'"
                    finding = {
                        "type": "BFLA (RBAC Matrix Privilege Violation)",
                        "cwe": "CWE-285",
                        "severity": "High",
                        "endpoint": key,
                        "target_url": url,
                        "details": reason,
                        "evidence": {"role": role_name, "required_role": required_role, "status": status_code},
                    }
                    with self._result_lock:
                        self.stats["confirmed"] += 1
                    self._record_result(ep, "RBAC_VIOLATION", Verdict.CONFIRMED, reason, matrix_entry, finding)
            except Exception as exc:
                matrix_entry["roles"][role_name] = {"error": str(exc), "access": "ERROR"}
        with self._result_lock:
            if not hasattr(self, "rbac_matrix"):
                self.rbac_matrix = {}
            self.rbac_matrix[key] = matrix_entry

    def _audit_endpoint_bola(self, ep: Dict[str, Any]) -> None:
        method = str(ep.get("method", "")).upper()
        if method not in ("GET", "POST"):
            self._record_result(ep, "BOLA", Verdict.SKIPPED,
                                "BOLA read-only checks support GET and read-only POST; no method substitution or request was made",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, "safety_signal": "method"})
            return
        policy = self.bola_config.get(self._operation_key(ep), {})
        if method == "POST" and not policy.get("read_only"):
            self._record_result(ep, "BOLA", Verdict.SKIPPED,
                                "POST operations require explicit 'read_only: true' policy for BOLA auditing; state-changing requests are blocked",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, "safety_signal": "method"})
            return
        risk = read_only_risk(ep)
        if risk:
            self._record_result(ep, "BOLA", Verdict.SKIPPED, risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, **risk})
            return
        validation = ConfigValidator.validate({"bola": {self._operation_key(ep): policy}})
        if not validation.is_valid:
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE,
                                "BOLA operation policy is invalid; run offline configuration validation; no request was sent",
                                evidence={"reason_category": "invalid_input", "requests_attempted": 0})
            return
        has_selector = self._has_object_selector(ep) or (method == "POST" and bool(policy.get("body")))
        if not has_selector or ("{" not in ep["path"] and policy.get("private_data_paths")):
            self._audit_collection(ep, policy)
            return
        expected_access = policy.get("expected_visitor_access", "deny")
        try:
            owner_url = self._build_url(ep, "owner")
            visitor_self_url = self._build_url(ep, "visitor")
            owner_headers = self._build_request_headers(ep, "owner", "owner")
            visitor_cross_headers = self._build_request_headers(ep, "owner", "visitor")
            anonymous_headers = self._build_request_headers(ep, "owner", "anonymous")
            visitor_self_headers = self._build_request_headers(ep, "visitor", "visitor")
        except (ParameterSerializationError, RemoteRefError) as exc:
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE, str(exc),
                                evidence={"reason_category": "invalid_input", "requests_attempted": 0})
            return
        body_config = policy.get("body")
        owner_data = None
        visitor_cross_data = None
        visitor_self_data = None
        if isinstance(body_config, dict):
            if "owner" in body_config or "visitor" in body_config or "visitor_self" in body_config:
                owner_data = body_config.get("owner")
                visitor_cross_data = body_config.get("visitor", owner_data)
                visitor_self_data = body_config.get("visitor_self")
            else:
                owner_data = body_config
                visitor_cross_data = body_config
                visitor_self_data = body_config

        risk = self._read_request_risk(method, owner_url) or self._read_request_risk(method, visitor_self_url)
        if risk:
            self._record_result(ep, "BOLA", Verdict.SKIPPED, risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, **risk})
            return
        owner = self._read_observation(ep["method"], owner_url, identity_name="owner", headers=owner_headers, data=owner_data)
        visitor_cross = self._read_observation(ep["method"], owner_url, identity_name="visitor", headers=visitor_cross_headers, data=visitor_cross_data)
        anonymous = self._read_observation(ep["method"], owner_url, identity_name="anonymous", headers=anonymous_headers, data=visitor_cross_data)
        visitor_self = None
        if visitor_self_url != owner_url or visitor_self_headers != visitor_cross_headers or visitor_self_data != visitor_cross_data:
            visitor_self = self._read_observation(
                ep["method"], visitor_self_url, identity_name="visitor", headers=visitor_self_headers, data=visitor_self_data
            )

        request_results = {
            "owner": owner,
            "visitor_cross": visitor_cross,
            "anonymous": anonymous,
        }
        if visitor_self is not None:
            request_results["visitor_self"] = visitor_self
        transport_errors = [f"{name}: {item.error}" for name, item in request_results.items() if item.error]
        private_values = self._private_evidence_values(owner, policy)
        evidence: Dict[str, Any] = {
            "requests_attempted": len(request_results),
            "target_url": owner_url,
            "visitor_self_url": visitor_self_url if visitor_self is not None else None,
            **{name: self._safe_body(item, private_values) for name, item in request_results.items()},
        }
        if any(item.truncated for item in request_results.values()):
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE,
                                "A response was truncated; authorization comparison is incomplete", evidence=evidence)
            return
        if transport_errors:
            reason = "A property observation failed transport" if self.bopla_config else "; ".join(transport_errors)
            self._record_result(ep, "BOLA", Verdict.ERROR, reason, evidence=evidence)
            return

        security = ep.get("security", [])
        requires_auth = bool(security) and {} not in security
        expected_public = policy.get("expected_public") is True or (
            ep.get("security_declared", False) and security == []
        )
        evaluation = ResponseDiffEngine.evaluate_bola(
            owner.as_tuple(),
            visitor_cross.as_tuple(),
            anonymous.as_tuple(),
            visitor_self=visitor_self.as_tuple() if visitor_self is not None else None,
            expected_public=expected_public,
            requires_auth=requires_auth,
            resource_id_paths=policy.get("resource_id_paths"),
            not_found_is_denial=policy.get("not_found_is_denial") is True,
        )

        verdict = self._map_bola_verdict(evaluation.get("verdict", "INCONCLUSIVE"))
        reason = evaluation.get("reason", "No reason supplied")
        # OpenAPI cannot establish business authorization. Apply ONLY the explicit
        # expectation for this selected identity/resource pair after the existing
        # data, self-baseline and anonymous-denial evidence checks have succeeded.
        if expected_access == "allow" and verdict == Verdict.CONFIRMED:
            verdict = Verdict.AUTHORIZED
            reason = "Configured Visitor is authorized to read this selected Owner resource; observed access matches this pair's explicit policy"
        elif expected_access == "allow" and verdict == Verdict.SECURE:
            verdict = Verdict.INCONCLUSIVE
            reason = "Configured Visitor should have access to this selected Owner resource, but was denied; verify the identity and sharing/admin policy"
        evidence["metrics"] = {
            key: value
            for key, value in evaluation.items()
            if key not in {"verdict", "reason"} and isinstance(value, (str, int, float, bool, type(None)))
        }
        evidence["decision_evidence"] = evaluation.get("evidence", {})
        evidence["decision_evidence"]["expected_visitor_access"] = expected_access
        evidence["decision_evidence"]["policy_scope"] = "Configured Owner/Visitor identities and selected resource pair only"
        if owner.status == 404:
            evidence["reason_category"] = "missing_resource_id"
        finding = None
        if verdict == Verdict.CONFIRMED:
            finding = {
                "type": "BOLA (Broken Object Level Authorization)",
                "cwe": "CWE-639",
                "severity": "High",
                "endpoint": self._operation_key(ep),
                "target_url": owner_url,
                "details": evaluation.get("reason", "Cross-identity access was confirmed"),
                "evidence": evidence,
            }
            with self._result_lock:
                self.stats["bola_confirmed"] += 1
        self._record_result(
            ep,
            "BOLA",
            verdict,
            reason,
            evidence=evidence,
            finding=finding,
        )
        if policy.get('detect_sensitive_exposure'):
            self._detect_sensitive_property_exposure(ep, owner, visitor_cross, evidence)
        self._execute_rbac_matrix_checks(ep)
        # Legacy object checks retain their evidence model and result count.
        # Extra detection items are selected by explicit new policy; incidental
        # anonymous access and admin words remain leads in the existing evidence.
        if policy.get("private_data_paths") or policy.get("required_role"):
            self._record_expanded_read_checks(ep, policy, owner, visitor_cross, anonymous, evidence)

    @staticmethod
    def _is_admin_endpoint(ep: Dict[str, Any]) -> bool:
        tokens = {"admin", "administrator", "system", "management", "internal", "privileged"}
        path = set(str(ep.get("path", "")).lower().strip("/").split("/"))
        metadata = " ".join(str(ep.get(key, "")) for key in ("tags", "operation_id", "summary")).lower()
        return bool(path.intersection(tokens)) or any(token in metadata for token in tokens)

    def _record_expanded_read_checks(
        self, ep: Dict[str, Any], policy: Dict[str, Any], owner: HTTPResult,
        visitor: HTTPResult, anonymous: HTTPResult, evidence: Dict[str, Any], *, collection: bool = False,
    ) -> None:
        security = ep.get("security", [])
        requires_auth = bool(security) and {} not in security
        expected_public = policy.get("expected_public") is True or (
            ep.get("security_declared", False) and (security == [] or {} in security))
        private_paths = policy.get("private_data_paths", [])
        decisions = []
        if collection:
            collection_policy = dict(policy, expected_public=expected_public)
            decisions.append(("BOLA", "CWE-639", AuthorizationEvidence.evaluate_collection(
                owner, visitor, anonymous, policy=collection_policy, requires_auth=requires_auth)))
        if requires_auth or private_paths:
            decisions.append(("BROKEN_AUTH", "CWE-306", AuthorizationEvidence.evaluate_auth(
                owner, anonymous, requires_auth=requires_auth, expected_public=expected_public,
                private_data_paths=private_paths, not_found_is_denial=policy.get("not_found_is_denial") is True)))
        candidate = self._is_admin_endpoint(ep)
        if candidate or policy.get("required_role"):
            decisions.append(("BFLA", "CWE-285", AuthorizationEvidence.evaluate_bfla(
                owner, visitor, anonymous, role_policy=dict(policy, expected_public=expected_public), private_data_paths=private_paths,
                candidate=candidate)))
        # All results describe the same observations, not additional HTTP traffic.
        group_id = self._operation_key(ep) + ":read"
        for check, cwe, decision in decisions:
            decision_evidence = dict(evidence)
            decision_evidence.update({"observation_group": group_id, "shared_observations": True,
                                      "decision_evidence": decision["evidence"]})
            verdict = decision["verdict"]
            finding = None
            if verdict == Verdict.CONFIRMED:
                finding = {"type": {"BOLA": "BOLA (Collection Private Data Exposure)",
                                    "BROKEN_AUTH": "Broken Authentication (Private Data Exposure)",
                                    "BFLA": "Broken Function Level Authorization"}[check],
                           "cwe": cwe, "severity": "High", "endpoint": self._operation_key(ep),
                           "target_url": evidence.get("target_url"), "details": decision["reason"],
                           "evidence": decision_evidence}
                if check == "BOLA":
                    with self._result_lock:
                        self.stats["bola_confirmed"] += 1
            self._record_result(ep, check, verdict, decision["reason"], decision_evidence, finding)

    def _audit_collection(self, ep: Dict[str, Any], policy: Dict[str, Any]) -> None:
        security = ep.get("security", [])
        if not (bool(security) and {} not in security or self._is_admin_endpoint(ep)
                or policy.get("private_data_paths") or policy.get("required_role")):
            self._record_result(ep, "BOLA", Verdict.SKIPPED,
                                "No object selector or selected collection evidence policy was found",
                                evidence={"reason_category": "not_applicable", "requests_attempted": 0})
            return
        collection_selected = not ("resource_id_paths" in policy and "private_data_paths" not in policy)
        if not collection_selected:
            # An existing resource-identifier policy selects the object detector;
            # it does not declare Owner-private collection values. Preserve that
            # detector's not-applicable result when there is no object selector.
            # Authentication/function probes are separate selected checks; they
            # cannot turn missing collection comparison evidence into isolation.
            self._record_result(ep, "BOLA", Verdict.SKIPPED,
                                "Object identifier policy has no object selector; no private-data collection policy was supplied",
                                evidence={"reason_category": "not_applicable", "requests_attempted": 0})
        try:
            url = self._build_url(ep, "owner")
            owner_headers = self._build_request_headers(ep, "owner", "owner")
            visitor_headers = self._build_request_headers(ep, "owner", "visitor")
            anonymous_headers = self._build_request_headers(ep, "owner", "anonymous")
        except (ParameterSerializationError, RemoteRefError) as exc:
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE, str(exc),
                                evidence={"reason_category": "invalid_input", "requests_attempted": 0})
            return
        risk = self._read_request_risk("GET", url)
        if risk:
            self._record_result(ep, "BOLA", Verdict.SKIPPED, risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0, **risk})
            return
        owner = self._read_observation("GET", url, identity_name="owner", headers=owner_headers)
        visitor = self._read_observation("GET", url, identity_name="visitor", headers=visitor_headers)
        anonymous = self._read_observation("GET", url, identity_name="anonymous", headers=anonymous_headers)
        # Capture once before recording resets this worker's accounting.
        attempts = getattr(self._request_accounting, "attempts", None)
        private_values = self._private_evidence_values(owner, policy)
        evidence = {"target_url": url, "requests_attempted": 3 if attempts is None else attempts,
                    "owner": self._safe_body(owner, private_values), "visitor_cross": self._safe_body(visitor, private_values),
                    "anonymous": self._safe_body(anonymous, private_values)}
        self._record_expanded_read_checks(ep, policy, owner, visitor, anonymous, evidence, collection=collection_selected)
        if policy.get('detect_sensitive_exposure'):
            self._detect_sensitive_property_exposure(ep, owner, visitor, evidence)
        self._execute_rbac_matrix_checks(ep)

    @staticmethod
    def _has_object_selector(ep: Dict[str, Any]) -> bool:
        return "{" in ep["path"] or any(item.get("in") == "query" for item in ep.get("parameters", []))

    def _authoritative_patch_state(
        self, ep: Dict[str, Any], mutation_url: str, readback: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """No generic HTTP observation can establish authoritative resource state.

        The bundled in-process Demo overrides this with direct database access.
        This is an internal integration seam, never a configuration assertion or
        a cache-header heuristic. External CLI targets have no implementation.
        """
        return None

    def _has_patch_state_authority(self) -> bool:
        implementation = getattr(self._authoritative_patch_state, "__func__", None)
        return implementation is not APISentinelAuditor._authoritative_patch_state

    def _verified_patch_document(
        self, result: HTTPResult, ep: Dict[str, Any], mutation_url: str, readback: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        document = self._json_object(result)
        if document is None:
            return None
        try:
            authority = self._authoritative_patch_state(ep, mutation_url, readback)
        except Exception:
            return None
        # Exact complete-document equality is required before ignoring volatile
        # paths for restoration comparison. Matching HTTP content alone is not proof.
        if not isinstance(authority, dict) or not json_values_equal(document, authority):
            return None
        return document

    @staticmethod
    def _json_object(result: HTTPResult) -> Optional[Dict[str, Any]]:
        # HTTP shape checks only; callers must separately verify state authority.
        # Generic 2xx includes pending, transformed and partial representations;
        # those cannot certify snapshots, persistence or restoration.
        if result.error is not None or result.status != 200 or result.truncated:
            return None
        headers = {name.lower(): value for name, value in result.headers.items()}
        if "content-range" in headers:
            return None
        # Explicitly aged/stale representations cannot support a state claim,
        # even when a gateway gives them HTTP 200. Absence of these headers is
        # not proof of freshness; active transactions separately require authority.
        if "age" in headers:
            try:
                if int(headers["age"]) != 0:
                    return None
            except ValueError:
                return None
        if re.search(r"(?:^|,)\s*11[01]\s", headers.get("warning", "")):
            return None
        try:
            value = strict_json_loads(result.body)
        except (ValueError, RecursionError):
            return None
        if not isinstance(value, dict) or not value:
            return None
        assessment = ResponseDiffEngine.classify_response(result.status, result.body)
        return value if assessment.get("kind") == ResponseDiffEngine.RESPONSE_VALID else None

    def _normalise_mutation_cases(self, schema: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cases: List[Dict[str, Any]] = []
        builder = getattr(SmartDataGenerator, "build_mass_assignment_cases", None)
        if callable(builder):
            generated = builder(schema)
            for item in generated or []:
                if not isinstance(item, dict):
                    continue
                if "field_path" in item and "value" in item:
                    cases.append(
                        {
                            "field_path": str(item["field_path"]),
                            "path": item.get("path", item["field_path"]),
                            "value": item["value"],
                            "payload": copy.deepcopy(item.get("payload"))
                            if isinstance(item.get("payload"), dict)
                            else {},
                        }
                    )
                    continue
                if "path" in item and "value" in item:
                    cases.append({
                        "field_path": str(item["path"]),
                        "path": item["path"],
                        "value": item["value"],
                        "payload": copy.deepcopy(item.get("payload"))
                        if isinstance(item.get("payload"), dict)
                        else {},
                    })
                    continue
                configured_payload = item.get("payload")
                payload = configured_payload if isinstance(configured_payload, dict) else item
                for field_path, value in payload.items():
                    cases.append({
                        "field_path": str(field_path),
                        "path": field_path,
                        "value": value,
                        "payload": copy.deepcopy(payload),
                    })
        if not cases:
            payload = SmartDataGenerator.build_mass_assignment_payload(schema)
            cases = [
                {
                    "field_path": str(key),
                    "path": key,
                    "value": value,
                    "payload": {key: copy.deepcopy(value)},
                }
                for key, value in payload.items()
            ]

        unique: Dict[str, Dict[str, Any]] = {}
        for case in cases:
            unique.setdefault(case["field_path"], case)
        return list(unique.values())

    def _readback_for(self, ep: Dict[str, Any], all_endpoints: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        configured = self.readback_config.get(self._operation_key(ep))
        if isinstance(configured, dict):
            return configured
        return None

    def _readback_endpoint(
        self,
        ep: Dict[str, Any],
        mapping: Dict[str, Any],
    ) -> Dict[str, Any]:
        # Renaming a path placeholder does not change the executed operation.
        # Keep declared semantic metadata even for an equivalent configured
        # template, so an unsafe readback is rejected during planning.
        mapping_shape = re.sub(r"\{[^}]+\}", "{}", str(mapping["path"]))
        documented = self._read_safety_snapshot().readbacks.get(
            (str(mapping.get("method", "GET")).upper(), mapping_shape)
        )
        # Semantic equivalence does not rename parameter metadata. Preserve the
        # historical fallback unless the declared template matches exactly.
        parameter_source = documented if documented and documented["path"] == str(mapping["path"]) else ep
        return {
            "method": str(mapping.get("method", "GET")).upper(),
            "path": str(mapping["path"]),
            "parameters": mapping["parameters"] if "parameters" in mapping else copy.deepcopy(parameter_source.get("parameters", [])),
            "spec_version": (documented or ep).get("spec_version", self.parser.raw_spec.get("openapi", self.parser.raw_spec.get("swagger", ""))),
            "operation_id": (documented or {}).get("operation_id", ""),
            "summary": (documented or {}).get("summary", ""),
            "description": (documented or {}).get("description", ""),
        }

    def _readback_result(
        self,
        ep: Dict[str, Any],
        mapping: Dict[str, Any],
        identity_name: str,
    ) -> Tuple[str, HTTPResult]:
        read_ep = self._readback_endpoint(ep, mapping)
        if read_ep["method"] != "GET":
            raise ParameterSerializationError("Readback must use GET; no method substitution or request was made")
        risk = read_only_risk(read_ep)
        if risk:
            raise ParameterSerializationError(risk["safety_reason"])
        url = self._build_url(read_ep, identity_name, mapping.get("parameter_values"))
        risk = self._read_request_risk("GET", url)
        if risk:
            raise ParameterSerializationError(risk["safety_reason"])
        headers = self._build_request_headers(read_ep, identity_name, identity_name, mapping.get("parameter_values"))
        return url, self._http_request(read_ep["method"], url, identity_name=identity_name, headers=headers)

    def _resource_lock(self, key: str) -> threading.Lock:
        with self._resource_locks_guard:
            return self._resource_locks.setdefault(key, threading.Lock())

    @staticmethod
    def _poll_settings(readback: Dict[str, Any]) -> Tuple[int, float]:
        try:
            attempts = min(10, max(1, int(readback.get("readback_attempts", 3))))
            delay = min(5.0, max(0.0, float(readback.get("readback_delay", 0.1))))
            return attempts, delay
        except (TypeError, ValueError, OverflowError):
            return 3, 0.1

    def _write_request(self, ep: Dict[str, Any], url: str, payload: Dict[str, Any]) -> HTTPResult:
        content_type = str(ep.get("request_content_type") or "application/json")
        if content_type.lower() == "application/json":
            return self._http_request(ep["method"], url, data=payload, identity_name="visitor")
        return self._http_request(ep["method"], url, data=payload, identity_name="visitor",
                                  content_type=content_type)

    def _rollback_and_verify(
        self, ep: Dict[str, Any], mutation_url: str,
        readback: Dict[str, Any], snapshot: PatchSnapshot,
    ) -> Tuple[bool, HTTPResult, HTTPResult]:
        """Restore every written container and verify the entire snapshot, not just the probe."""
        try:
            rollback_http = self._write_request(ep, mutation_url, snapshot.restore)
        except Exception as exc:
            rollback_http = HTTPResult(0, "", error=f"{type(exc).__name__}: {exc}")
        attempts, delay = self._poll_settings(readback)
        restored_http = HTTPResult(0, "", error="rollback readback was not attempted")
        verified = False
        for attempt in range(attempts):
            try:
                _, restored_http = self._readback_result(ep, readback, "visitor")
                verified = snapshot.matches(self._verified_patch_document(
                    restored_http, ep, mutation_url, readback))
            except Exception as exc:
                restored_http = HTTPResult(0, "", error=f"{type(exc).__name__}: {exc}")
            # A response that cannot be decoded, or async restoration, is not a safe success.
            if verified and rollback_http.ok and rollback_http.status != 202:
                return True, rollback_http, restored_http
            if attempt + 1 < attempts:
                time.sleep(delay)
        return False, rollback_http, restored_http

    def _execute_patch_case(
        self, ep: Dict[str, Any], mutation_url: str, readback: Dict[str, Any],
        snapshot: PatchSnapshot,
    ) -> Dict[str, Any]:
        """Every possibly-sent mutation passes through finally-based recovery."""
        mutation = HTTPResult(0, "", error="mutation was not completed")
        after_http = HTTPResult(0, "", error="read-after-write was not completed")
        after = None
        recovery_needed = True
        rollback_ok = False
        rollback_http = HTTPResult(0, "", error="not attempted")
        restored_http = HTTPResult(0, "", error="not attempted")
        failure = None
        try:
            mutation = self._write_request(ep, mutation_url, snapshot.mutation)
            attempts, delay = self._poll_settings(readback)
            for attempt in range(attempts):
                _, after_http = self._readback_result(ep, readback, "visitor")
                after = self._verified_patch_document(after_http, ep, mutation_url, readback)
                if after is not None and not snapshot.covers_document(after):
                    after = None
                if (after is not None and not snapshot.matches(after)) or attempt + 1 == attempts:
                    break
                time.sleep(delay)
            # Only an independently checked complete state allows skipping a
            # redundant restore; a configured consistency label is not proof.
            recovery_needed = not (
                readback.get("consistency") == "strong"
                and snapshot.matches(after)
                and not mutation.error
                and mutation.status != 202
                and (mutation.ok or mutation.status in self.AUTH_DENIAL_STATUSES)
            )
            if not recovery_needed:
                rollback_ok = True
                restored_http = after_http
        except Exception as exc:
            failure = f"{type(exc).__name__}: {exc}"
        finally:
            # Fail closed BEFORE invoking recovery: recovery code can itself fail.
            previous_halt = self._writes_halted_reason
            self._writes_halted_reason = (
                "Recovery could not be guaranteed; later write tests stopped. "
                "Inspect the dedicated test resource before retrying."
            )
            try:
                if recovery_needed:
                    rollback_ok, rollback_http, restored_http = self._rollback_and_verify(
                        ep, mutation_url, readback, snapshot
                    )
            except Exception as exc:
                rollback_ok = False
                failure = f"Recovery raised {type(exc).__name__}: {exc}"
                rollback_http = HTTPResult(0, "", error=failure)
            if rollback_ok and mutation.status != 202 and rollback_http.status != 202:
                self._writes_halted_reason = previous_halt
        return {
            "mutation": mutation, "after_http": after_http, "after": after,
            "rollback": rollback_http, "restored": restored_http,
            "rollback_verified": rollback_ok, "recovery_sent": recovery_needed,
            "failure": failure,
        }

    def audit_endpoint_mass_assignment(
        self, ep: Dict[str, Any], all_endpoints: List[Dict[str, Any]]
    ) -> None:
        # Keep the halt check and entire transaction under one gate, including
        # direct library calls. A waiting caller must observe an earlier failure.
        with self._write_lock:
            self._audit_endpoint_mass_assignment(ep, all_endpoints)

    def _audit_endpoint_mass_assignment(
        self, ep: Dict[str, Any], all_endpoints: List[Dict[str, Any]]
    ) -> None:
        plan = self._mass_assignment_preflight(ep, all_endpoints)
        if plan is None:
            return
        with self._resource_lock(plan["mutation_url"]):
            for case in plan["cases"]:
                if self._mass_assignment_case(ep, plan, case):
                    return
        self._record_mass_assignment_summary(ep, plan)

    def _mass_assignment_preflight(
        self, ep: Dict[str, Any], all_endpoints: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Run every check that precedes a write.

        Returns None after recording why no write may be sent; otherwise the
        prepared cases, the shared result lists and the values the cases need.
        """
        if ep.get("unresolved_schema_error"):
            sanitized_err = sanitize_error_message(ep["unresolved_schema_error"])
            self._record_result(
                ep,
                "MASS_ASSIGNMENT",
                Verdict.INCONCLUSIVE,
                f"Schema could not be resolved safely: {sanitized_err}; no request was sent",
                evidence={"reason_category": "unresolved_reference", "requests_attempted": 0, "requests_sent": 0},
            )
            return None
        if str(ep.get("method", "")).upper() not in self.WRITE_METHODS:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Only explicitly allowlisted reversible PATCH/PUT checks are supported; no method substitution or request was made",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, "safety_signal": "method"})
            return None
        operation_key = self._operation_key(ep)
        if self._writes_halted_reason:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED, self._writes_halted_reason,
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0})
            return None
        if not self.allow_write_tests:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "State-changing checks are disabled; pass --allow-write-tests to opt in",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0})
            return None
        if operation_key not in self.write_allowlist:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Endpoint is not in the explicit, case-sensitive write-test allowlist",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0})
            return None
        schema = ep.get("request_schema")
        if not isinstance(schema, dict) or not schema:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "No request schema is available; no write was sent")
            return None
        content_type = str(ep.get("request_content_type") or "").split(";", 1)[0].strip().lower()
        allowed_types = {"application/json"} if ep["method"].upper() == "PUT" else {
            "application/json", "application/merge-patch+json"}
        if content_type not in allowed_types:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Only object application/json and application/merge-patch+json are supported; "
                                "JSON Patch operation arrays and arbitrary vendor formats are not implemented",
                                evidence={"reason_category": "detector_unimplemented", "requests_attempted": 0})
            return None
        readback = self._readback_for(ep, all_endpoints)
        if (not readback or not readback.get("path")
                or str(readback.get("method", "GET")).upper() != "GET"):
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                "An independent GET readback mapping is required; no write was sent")
            return None
        risk = read_only_risk(self._readback_endpoint(ep, readback))
        if risk:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Unsafe readback: " + risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, **risk})
            return None
        field_map = readback.get("field_map")
        if not isinstance(field_map, dict) or not field_map:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                "An explicit non-empty field_map is required; no write was sent")
            return None
        try:
            generated = self._normalise_mutation_cases(schema)
        except ValueError as exc:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                f"A valid baseline could not be generated: {exc}; no write was sent")
            return None
        cases = [case for case in generated if case["field_path"] in field_map]
        generated_paths = {case["field_path"] for case in cases}
        unverified = [f"{name}: no mutation case was generated" for name in field_map if name not in generated_paths]
        verified_safe: List[str] = []
        tested: List[str] = []
        case_summaries: List[Dict[str, Any]] = []
        for p in ep.get("parameters", []) or []:
            if not isinstance(p, dict):
                continue
            loc = p.get("in")
            p_name = p.get("name", "")
            if loc == "header" and str(p_name).lower() in {"authorization", "accept", "content-type"}:
                continue
            # Distinct name: ``schema`` above is the request body schema.
            param_schema = p.get("schema", {}) if isinstance(p.get("schema"), dict) else {}
            p_type = param_schema.get("type", p.get("type"))
            configured_val = self._operation_parameter_values(ep, "visitor").get(p_name)
            is_array = (p_type == "array" or "items" in p or "items" in param_schema
                        or p.get("collectionFormat") or isinstance(configured_val, list))
            is_object = (p_type == "object" or "properties" in p or "properties" in param_schema
                         or isinstance(configured_val, dict))
            if loc == "cookie":
                self._record_result(
                    ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                    f"Cookie parameter '{p_name}' serialization is not supported for {ep['method']} write operations; no write was sent",
                    evidence={"reason_category": "invalid_input", "requests_attempted": 0, "requests_sent": 0}
                )
                return None
            if loc == "header" and (is_array or is_object):
                kind = "array" if is_array else "object"
                self._record_result(
                    ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                    f"Header {kind} parameter '{p_name}' serialization is not supported for {ep['method']} write operations; no write was sent",
                    evidence={"reason_category": "invalid_input", "requests_attempted": 0, "requests_sent": 0}
                )
                return None
        try:
            mutation_url = self._build_url(ep, "visitor")
            read_ep = self._readback_endpoint(ep, readback)
            readback_url = self._build_url(read_ep, "visitor", readback.get("parameter_values"))
            self._build_request_headers(read_ep, "visitor", "visitor", readback.get("parameter_values"))
        except (ParameterSerializationError, RemoteRefError) as exc:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE, str(exc),
                                evidence={"reason_category": "invalid_input", "requests_attempted": 0})
            return None
        risk = self._read_request_risk("GET", readback_url)
        if risk:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Unsafe readback: " + risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, **risk})
            return None

        if not self._has_patch_state_authority():
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                "Authoritative resource state cannot be verified; no write was sent. "
                                "Ordinary HTTP readbacks and consistency declarations are insufficient.",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, "rollback_verified": False,
                                          "recovery_sent": False, "safety_signal": "unverified_state_authority"})
            return None
        return {
            "operation_key": operation_key, "content_type": content_type, "readback": readback,
            "field_map": field_map, "cases": cases, "mutation_url": mutation_url,
            "unverified": unverified, "verified_safe": verified_safe, "tested": tested,
            "case_summaries": case_summaries,
        }

    def _mass_assignment_case(self, ep: Dict[str, Any], plan: Dict[str, Any], case: Dict[str, Any]) -> bool:
        """Test one field under the resource lock; True when a final result was recorded."""
        operation_key = plan["operation_key"]
        content_type = plan["content_type"]
        readback = plan["readback"]
        field_map = plan["field_map"]
        mutation_url = plan["mutation_url"]
        unverified = plan["unverified"]
        verified_safe = plan["verified_safe"]
        tested = plan["tested"]
        case_summaries = plan["case_summaries"]
        field_path = case["field_path"]
        try:
            read_url, before_http = self._readback_result(ep, readback, "visitor")
        except (ParameterSerializationError, RemoteRefError) as exc:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE, str(exc))
            return True
        if before_http.error:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.ERROR,
                                f"Read-before-write failed: {before_http.error}",
                                evidence={"readback_url": read_url, "before": self._safe_body(before_http)})
            return True
        before = self._verified_patch_document(before_http, ep, mutation_url, readback)
        if before is None:
            unverified.append(f"{field_path}: readback requires a complete HTTP 200 JSON object matching independently verified authoritative state")
            return False
        try:
            snapshot = (prepare_patch(before, case, readback, method="PUT")
                        if ep["method"].upper() == "PUT" else prepare_patch(before, case, readback))
            if not snapshot.matches(before):
                raise ValueError("original readback snapshot cannot be verified")
            # Merge Patch null members remove fields; they cannot restore an
            # explicitly present null from an object snapshot.
            def has_null_member(value):
                if isinstance(value, dict):
                    return any(item is None or has_null_member(item) for item in value.values())
                return False  # Arrays replace as complete values.
            if content_type == "application/merge-patch+json" and has_null_member(snapshot.restore):
                raise ValueError("Merge Patch cannot restore present null object members")
            if content_type == "application/merge-patch+json":
                ensure_reversible_merge_patch(snapshot)
        except (ValueError, KeyError, TypeError) as exc:
            unverified.append(f"{field_path}: {exc}; no write was sent")
            return False

        # Recheck the authority immediately before transport; it may
        # become unavailable while preparing the reversible snapshot.
        if self._verified_patch_document(before_http, ep, mutation_url, readback) is None:
            unverified.append(f"{field_path}: authoritative initial state became unavailable; no write was sent")
            return False
        tested.append(field_path)
        transaction = self._execute_patch_case(ep, mutation_url, readback, snapshot)
        mutation = transaction["mutation"]
        after = transaction["after"]
        exists, value = get_path(after or {}, snapshot.read_path)
        persisted = exists and json_values_equal(value, snapshot.target)
        evidence = {
            "field": field_path, "readback_field": field_map[field_path],
            "target_url": mutation_url,
            "readback_url": read_url,
            "request_content_type": (
                "application/json"
                if str(ep.get("request_content_type") or "application/json").lower() == "application/json"
                else str(ep.get("request_content_type") or "application/json")
            ),
            "snapshot_fields": list(snapshot.restore),
            "verification_scope": "Authoritatively checked full readback document except explicitly ignored volatile paths",
            "ignored_readback_paths": readback.get("ignore_readback_paths", []),
            "mutation": self._safe_body(mutation),
            "after": self._safe_body(transaction["after_http"]),
            "rollback": self._safe_body(transaction["rollback"]),
            "restored": self._safe_body(transaction["restored"]),
            "rollback_verified": transaction["rollback_verified"],
            "recovery_sent": transaction["recovery_sent"],
            "tested_fields": list(tested),
            "untested_fields": [name for name in field_map if name not in tested],
            "readback_consistency": readback.get("consistency", "unspecified"),
        }
        case_summaries.append({
            "field": field_path, "readback_field": field_map[field_path],
            "persisted": persisted,
            "rollback_verified": transaction["rollback_verified"],
            "recovery_sent": transaction["recovery_sent"],
        })
        if persisted:
            finding: Dict[str, Any] = {
                "type": "Mass Assignment (independent readback confirmed)",
                "cwe": "CWE-915", "severity": "Critical", "endpoint": operation_key,
                "target_url": mutation_url,
                "details": f"Privilege field '{field_path}' persisted after mutation",
                "injected_payload": {field_path: snapshot.target},
                "evidence": evidence,
            }
            with self._result_lock:
                self.stats["mass_assignment_confirmed"] += 1
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.CONFIRMED,
                                finding["details"], evidence, finding)
            if self._writes_halted_reason:
                self._record_result(ep, "ROLLBACK", Verdict.ERROR,
                                    self._writes_halted_reason, evidence)
            return True
        if self._writes_halted_reason:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.ERROR,
                                self._writes_halted_reason, evidence)
            return True
        if transaction["failure"] or mutation.error or mutation.status == 0 or mutation.status >= 500:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.ERROR,
                                "Mutation outcome was ambiguous; recovery was verified. "
                                + str(transaction["failure"] or mutation.error or mutation.status), evidence)
            return True
        if after is None:
            unverified.append(f"{field_path}: invalid read-after-write; original snapshot restored")
            return False
        if not snapshot.matches(after):
            unverified.append(f"{field_path}: unexpected state change; original snapshot restored")
            return False
        if readback.get("consistency") != "strong":
            unverified.append(f"{field_path}: unchanged state is not conclusive without strongly consistent readback")
            return False
        if mutation.status in self.AUTH_DENIAL_STATUSES:
            verified_safe.append(field_path)
            return False
        assessment = (ResponseDiffEngine.classify_response(mutation.status, mutation.body)
                      if mutation.status != 204 else {"kind": ResponseDiffEngine.RESPONSE_VALID})
        if mutation.ok and assessment.get("kind") == ResponseDiffEngine.RESPONSE_VALID:
            verified_safe.append(field_path)
        else:
            unverified.append(f"{field_path}: mutation was rejected or returned a business error")
        return False

    def _record_mass_assignment_summary(self, ep: Dict[str, Any], plan: Dict[str, Any]) -> None:
        """Record SECURE only when every configured field was verified safe."""
        readback = plan["readback"]
        field_map = plan["field_map"]
        mutation_url = plan["mutation_url"]
        unverified = plan["unverified"]
        verified_safe = plan["verified_safe"]
        tested = plan["tested"]
        case_summaries = plan["case_summaries"]
        evidence = {"tested_fields": tested, "safe_fields": verified_safe, "unverified": unverified,
                    "configured_fields": list(field_map), "target_url": mutation_url,
                    "cases": case_summaries,
                    "rollback_verified": all(case["rollback_verified"] is True for case in case_summaries) if case_summaries else None,
                    "recovery_sent": any(case["recovery_sent"] for case in case_summaries),
                    "ignored_readback_paths": readback.get("ignore_readback_paths", [])}
        if verified_safe and not unverified and len(verified_safe) == len(field_map):
            with self._result_lock:
                self.stats["raw_filtered_count"] += 1
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SECURE,
                                "Strongly consistent readback showed no persistence for all configured fields", evidence)
        else:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                "; ".join(unverified) or "No configured mutation case could be executed safely", evidence)

    def _audit_bola_task(self, ep: Dict[str, Any]) -> None:
        # A worker must report its own error while transport accounting is still
        # available in that thread. Reused workers start with a fresh check.
        self._request_accounting.attempts = None
        try:
            self.audit_endpoint_bola(ep)
        except Exception as exc:
            self._record_task_error(ep, "BOLA", exc)

    def build_plan(self) -> Dict[str, Any]:
        """Inspect local specification/configuration only; this never makes requests."""
        self._ensure_parser_auth()
        entries = []
        for ep in self.parser.get_endpoints():
            key = self._operation_key(ep)
            readback = self.readback_config.get(key, {})
            entry = {"endpoint": key, "check": "UNSUPPORTED", "writes_enabled": False}
            if ep.get("unresolved_schema_error"):
                sanitized_err = sanitize_error_message(ep["unresolved_schema_error"])
                entry["check"] = "INCONCLUSIVE"
                entry["reason_category"] = "unresolved_reference"
                entry["reason"] = f"Schema could not be resolved safely: {sanitized_err}; no request was sent"
                entry["writes_enabled"] = False
                entries.append(entry)
                continue
            if ep["method"] == "GET" or (ep["method"] == "POST" and self.bola_config.get(key, {}).get("read_only")):
                entry["check"] = "BOLA"
                risk = read_only_risk(ep)
                parameter_error = None
                if not risk:
                    try:
                        risk = (self._read_request_risk("GET", self._build_url(ep, "owner"))
                                or self._read_request_risk("GET", self._build_url(ep, "visitor")))
                    except (ParameterSerializationError, RemoteRefError) as exc:
                        parameter_error = str(exc)
                if risk:
                    entry.update({"safety_blocked": True, "reason_category": "safety_policy",
                                  "reason": risk["safety_reason"], "safety_signal": risk["safety_signal"]})
                elif not self._has_object_selector(ep) and (
                    ep.get("security") or self._is_admin_endpoint(ep)
                    or self.bola_config.get(key, {}).get("private_data_paths")
                    or self.bola_config.get(key, {}).get("required_role")
                ):
                    entry.update({"check": "COLLECTION_AUTHORIZATION",
                                  "reason": "Read-only evidence comparison; missing private-data or role policy remains inconclusive"})
                elif not self._has_object_selector(ep):
                    entry.update({"reason_category": "not_applicable",
                                  "reason": "No object selector was found; this operation is not applicable to the current object-level detector"})
                elif parameter_error:
                    entry.update({"reason_category": "invalid_input", "reason": parameter_error})
            elif ep["method"] in self.WRITE_METHODS:
                entry.update({
                    "check": "MASS_ASSIGNMENT",
                    "writes_enabled": (self.allow_write_tests and key in self.write_allowlist
                                       and self._has_patch_state_authority()),
                    "content_type": ep.get("request_content_type"),
                    "readback_path": readback.get("path"),
                    "configured_fields": list(readback.get("field_map", {})),
                    "readback_consistency": readback.get("consistency", "unspecified"),
                })
                if self.allow_write_tests and key in self.write_allowlist and not self._has_patch_state_authority():
                    entry.update({"safety_blocked": True, "reason_category": "safety_policy",
                                  "safety_signal": "unverified_state_authority",
                                  "reason": "Authoritative resource state cannot be verified; no write will be sent"})
                if isinstance(readback, dict) and readback.get("path"):
                    read_ep = self._readback_endpoint(ep, readback)
                    risk = read_only_risk(read_ep)
                    if not risk and read_ep["method"] == "GET":
                        try:
                            risk = self._read_request_risk("GET", self._build_url(read_ep, "visitor", readback.get("parameter_values")))
                        except (ParameterSerializationError, RemoteRefError):
                            pass
                    if risk:
                        entry.update({"writes_enabled": False, "safety_blocked": True,
                                      "reason_category": "safety_policy", "reason": "Unsafe readback: " + risk["safety_reason"],
                                      "safety_signal": risk["safety_signal"]})
            else:
                entry.update({"reason_category": "detector_unimplemented",
                              "reason": f"No detector is implemented for {ep['method']}"})
            if key in self.bopla_config:
                policy = self.bopla_config[key]
                entry["property_check"] = "BOPLA"
                entry["property_policy_valid"] = not validate_bopla_policy(policy)
                entry["property_fields"] = [rule.get("path") for rule in policy.get("fields", [])
                                             if isinstance(rule, dict)] if isinstance(policy, dict) else []
                if not entry["property_policy_valid"]:
                    entry.update({"safety_blocked": True, "reason_category": "invalid_input",
                                  "reason": "Invalid property policy; no request will be sent"})
            entries.append(entry)
        return sanitize_evidence({"mode": "DRY_RUN", "requests_sent": 0,
                                  "note": "Local plan only; not a successful scan or a recovery guarantee",
                                  "target": self.target_base_url, "operations": entries},
                                 self.include_sensitive_evidence, self._secret_values)

    def run(self) -> None:
        self._ensure_parser_auth()
        endpoints = self.parser.get_endpoints()
        self.stats["total_endpoints"] = len(endpoints)
        print("=" * 68)
        print(f"GrantTrace {__version__} safety-first audit")
        print(f"Specification: {self.parser.version} | endpoints: {len(endpoints)}")
        print(
            "Write tests: "
            + ("ENABLED with independent state authority" if self.allow_write_tests and self._has_patch_state_authority()
               else "BLOCKED (no state authority)" if self.allow_write_tests else "DISABLED (read-only mode)")
        )
        print("=" * 68)

        get_endpoints = [
            ep for ep in endpoints
            if ep["method"] == "GET" or (ep["method"] == "POST" and self.bola_config.get(self._operation_key(ep), {}).get("read_only"))
        ]
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ep = {executor.submit(self._audit_bola_task, ep): ep for ep in get_endpoints}
            for future in as_completed(future_to_ep):
                ep = future_to_ep[future]
                try:
                    future.result()
                except Exception as exc:  # A task must always become a reportable error.
                    self._record_task_error(ep, "BOLA", exc)

        # State-changing checks are deliberately serial to prevent readback
        # attribution races between endpoints that share a resource.
        for ep in endpoints:
            try:
                if ep["method"] in self.WRITE_METHODS:
                    self.audit_endpoint_mass_assignment(ep, endpoints)
                elif ep["method"] != "GET" and ep.get("unresolved_schema_error"):
                    # A failed path-item reference hides which operations exist
                    # (method UNKNOWN). Keep it INCONCLUSIVE like other unresolved
                    # operations; a skipped "unsupported method" would let
                    # --fail-on-error pass an unaudited path.
                    sanitized_err = sanitize_error_message(ep["unresolved_schema_error"])
                    self._record_result(
                        ep, "BOLA", Verdict.INCONCLUSIVE,
                        f"Schema could not be resolved safely: {sanitized_err}; no request was sent",
                        {"requests_attempted": 0, "requests_sent": 0, "reason_category": "unresolved_reference"},
                    )
                elif ep["method"] == "POST" and self.bola_config.get(self._operation_key(ep), {}).get("read_only"):
                    pass
                elif ep["method"] != "GET":
                    self._record_result(
                        ep,
                        "UNSUPPORTED",
                        Verdict.SKIPPED,
                        f"No detector is implemented for {ep['method']}",
                    )
            except Exception as exc:
                self._record_task_error(ep, "MASS_ASSIGNMENT", exc)

        self._finalise_coverage()
        print("\n" + "=" * 68)
        print(f"Confirmed vulnerabilities: {self.stats['confirmed']}")
        print(f"Errors: {self.stats['error_count']} | inconclusive: {self.stats['inconclusive_count']}")
        print(
            f"Attempted coverage: {self.stats['coverage_pct']:.1f}% | "
            f"conclusive coverage: {self.stats['conclusive_coverage_pct']:.1f}%"
        )
        print("=" * 68)

