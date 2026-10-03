# -*- coding: utf-8 -*-
"""Safety-first API audit orchestration.

Read-only BOLA checks run by default. State-changing mass-assignment checks
require an explicit opt-in and an independent readback mapping. Confirmed
changes are rolled back and the rollback is verified.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from core import __version__
from core.config_validator import ConfigValidator
from core.diff import ResponseDiffEngine
from core.evidence import body_sha256, sanitize_body, sanitize_evidence
from core.transactions import PatchSnapshot, get_path, prepare_patch
from core.generator import SmartDataGenerator
from core.models import HTTPResult, Verdict, json_values_equal, parse_operation_key, strict_json_loads
from core.parser import OpenAPIParser
from core.parameters import ParameterSerializationError, serialize_path_parameter, serialize_query_parameter


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return 30x to the detector instead of forwarding credentials."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class APISentinelAuditor:
    # PATCH has reversible partial-update semantics. POST and PUT require an
    # operation-specific compensation/full-snapshot design that this release
    # deliberately does not attempt to guess.
    WRITE_METHODS = {"PATCH"}
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
    ) -> None:
        self._validate_target(target_base_url, allow_http)
        self.parser = OpenAPIParser(spec_path)
        self.target_base_url = target_base_url.rstrip("/")
        self.max_workers = max(1, int(max_workers))
        self.request_delay = max(0.0, float(request_delay))
        self.request_timeout = max(0.1, float(request_timeout))
        self.max_response_bytes = max(1024, int(max_response_bytes))
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
        self.write_allowlist = set()
        for item in write_allowlist or []:
            c_key = _canonical_op_key(item)
            is_valid, method, path, canonical, err_msg = parse_operation_key(c_key)
            if not is_valid or method != "PATCH":
                raise ValueError("write_allowlist entries must be 'PATCH /case-sensitive-path'")
            self.write_allowlist.add(canonical)
        self._writes_halted_reason: Optional[str] = None

        context = ssl._create_unverified_context() if insecure_ssl else ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            _NoRedirectHandler(), urllib.request.HTTPSHandler(context=context)
        )
        self._rate_lock = threading.Lock()
        self._next_request_at = 0.0
        self._result_lock = threading.Lock()
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
        self._secret_values = set()
        for identity_name in self.identities:
            for key, value in self._identity_headers(identity_name).items():
                if self._is_auth_header(key):
                    self._secret_values.add(value)
                    if key.lower() == "authorization" and " " in value:
                        self._secret_values.add(value.split(" ", 1)[1])

        self.findings: List[Dict[str, Any]] = []
        self.results: List[Dict[str, Any]] = []
        self.stats: Dict[str, Any] = {
            "total_endpoints": 0,
            "total_checks": 0,
            "audited_count": 0,
            "conclusive_count": 0,
            "confirmed": 0,
            "bola_confirmed": 0,
            "mass_assignment_confirmed": 0,
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

    def _is_auth_header(self, name: str) -> bool:
        schemes = dict(self.parser.raw_spec.get("securityDefinitions") or {})
        schemes.update((self.parser.raw_spec.get("components") or {}).get("securitySchemes") or {})
        spec_headers = [
            str(scheme.get("name", ""))
            for scheme in schemes.values()
            if isinstance(scheme, dict) and scheme.get("in") == "header" and scheme.get("name")
        ]
        custom_headers = []
        for identity in self.identities.values():
            extra = identity.get("auth_header_names", [])
            if not isinstance(extra, list) or any(not isinstance(key, str) for key in extra):
                raise ValueError("auth_header_names must be a list of header names")
            custom_headers.extend(extra)
        return ConfigValidator.is_auth_header(
            name,
            custom_auth_names=custom_headers,
            spec_auth_names=spec_headers,
        )

    def _validate_identities(self) -> None:
        missing = {"owner", "visitor", "anonymous"} - set(self.identities)
        if missing:
            raise ValueError(f"identity configuration is missing: {', '.join(sorted(missing))}")
        for name, identity in self.identities.items():
            if not isinstance(identity, dict):
                raise ValueError(f"identity '{name}' must be an object")
            if not isinstance(identity.get("headers", {}), dict):
                raise ValueError(f"identity '{name}' headers must be an object")
        fingerprints = {}
        for name in ("owner", "visitor", "anonymous"):
            material = []
            for key, value in self._identity_headers(name).items():
                if self._is_auth_header(key) and value.strip():
                    normalized = value.strip()
                    if key.lower() == "authorization" and " " in normalized:
                        scheme, credential = normalized.split(None, 1)
                        normalized = scheme.lower() + " " + credential.strip()
                    material.append((key.lower(), normalized))
            fingerprints[name] = tuple(sorted(material))
        if (not fingerprints["owner"] or not fingerprints["visitor"]
                or fingerprints["owner"] == fingerprints["visitor"]):
            raise ValueError("owner and visitor must use distinct, non-empty effective authentication material")
        if fingerprints["anonymous"]:
            raise ValueError("anonymous identity must not define authentication material")

    def _throttle(self) -> None:
        if self.request_delay <= 0:
            return
        with self._rate_lock:
            now = time.monotonic()
            wait_for = max(0.0, self._next_request_at - now)
            if wait_for:
                time.sleep(wait_for)
            self._next_request_at = time.monotonic() + self.request_delay

    def _identity_headers(self, identity_name: str) -> Dict[str, str]:
        identity = self.identities[identity_name]
        headers = {}
        for key, value in identity.get("headers", {}).items():
            normalized = str(key).strip().lower()
            if normalized in headers:
                raise ValueError("duplicate case-insensitive identity header: " + normalized)
            if any(char in str(key) + str(value) for char in "\r\n"):
                raise ValueError("identity headers must not contain line breaks")
            headers[normalized] = str(value).strip()
        token = identity.get("token")
        if token:
            if any(char in str(token) for char in "\r\n"):
                raise ValueError("identity token must not contain line breaks")
            headers["authorization"] = str(token).strip()
        return headers

    def _read_limited(self, response) -> Tuple[str, bool]:  # noqa: ANN001
        raw = response.read(self.max_response_bytes + 1)
        truncated = len(raw) > self.max_response_bytes
        raw = raw[: self.max_response_bytes]
        charset = response.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace"), truncated

    def _http_request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        identity_name: str = "anonymous",
        content_type: str = "application/json",
    ) -> HTTPResult:
        self._throttle()
        try:
            headers = {
                "accept": "application/json",
                "user-agent": f"GrantTrace/{__version__}",
                **self._identity_headers(identity_name),
            }
            encoded_data = None
            if data is not None:
                headers["content-type"] = content_type
                encoded_data = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
            request = urllib.request.Request(url, data=encoded_data, method=method, headers=headers)
            try:
                response = self._opener.open(request, timeout=self.request_timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                body, truncated = self._read_limited(response)
                return HTTPResult(
                    status=response.status, body=body, truncated=truncated,
                    headers={str(k): str(v) for k, v in response.headers.items()},
                )
        except Exception as exc:
            # Includes malformed encodings and truncated/chunked transport reads.
            # A PATCH may already have committed; the transaction owns recovery.
            return HTTPResult(status=0, body="", error=f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _operation_key(ep: Dict[str, Any]) -> str:
        return f"{ep['method'].upper()} {ep['path']}"

    def _operation_parameter_values(self, ep: Dict[str, Any], identity_name: str) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        configured = self.parameter_values.get(self._operation_key(ep), {})
        if isinstance(configured, dict):
            common = configured.get("common")
            if isinstance(common, dict):
                values.update(common)
            role_values = configured.get(identity_name)
            if isinstance(role_values, dict):
                values.update(role_values)
            for key, value in configured.items():
                if key not in {"common", "owner", "visitor", "anonymous"}:
                    values[key] = value
        identity_values = self.identities[identity_name].get("parameters", {})
        if isinstance(identity_values, dict):
            values.update(identity_values)
        return values

    def _build_url(
        self,
        ep: Dict[str, Any],
        resource_identity: str,
        extra_values: Optional[Dict[str, Any]] = None,
    ) -> str:
        raw_path = ep["path"]
        parameters = ep.get("parameters", [])
        if (not isinstance(raw_path, str) or not raw_path.startswith("/")
                or any(character in raw_path for character in "?#\r\n")):
            raise ParameterSerializationError("Operation path must be an absolute path without a query/fragment; no request was sent")
        if not isinstance(parameters, list) or any(not isinstance(item, dict) for item in parameters):
            raise ParameterSerializationError("Operation parameters must be an array of metadata objects; no request was sent")
        swagger2 = str(ep.get("spec_version", self.parser.raw_spec.get("swagger", ""))).startswith("2.")
        supported = []
        for metadata in parameters:
            location, name = metadata.get("in"), metadata.get("name")
            if location == "body" and swagger2:
                continue  # Swagger request bodies have their own payload encoder.
            if location == "header" and isinstance(name, str):
                normalized = name.lower()
                if not swagger2 and normalized in {"authorization", "accept", "content-type"}:
                    continue  # OAS 3 requires these Parameter Objects to be ignored.
                if (self._is_auth_header(name)
                        and all(self._identity_headers(role).get(normalized) for role in ("owner", "visitor"))):
                    continue  # Authentication comes only from the actual requester.
            if location not in {"path", "query"}:
                raise ParameterSerializationError("Header/cookie/formData parameter serialization is unsupported; configure authentication in identity headers; no request was sent")
            supported.append(metadata)
        parameters = supported
        values = self._operation_parameter_values(ep, resource_identity)
        if extra_values:
            values.update(extra_values)
        candidate_id = self.identities[resource_identity].get("id")
        test_path = raw_path

        for param_name in re.findall(r"\{([^}]+)\}", raw_path):
            metadata = next(
                (
                    item
                    for item in parameters
                    if item.get("name") == param_name and item.get("in", "path") == "path"
                ),
                {"name": param_name, "in": "path", "schema": {"type": "string"}},
            )
            value = values.get(param_name) if param_name in values else SmartDataGenerator.generate_raw_value_for_param(metadata, candidate_id=candidate_id)
            test_path = test_path.replace("{" + param_name + "}", serialize_path_parameter(metadata, value, swagger2=swagger2))

        if "{" in test_path or "}" in test_path:
            raise ParameterSerializationError("Unresolved or malformed path template; no request was sent")
        template_names = set(re.findall(r"\{([^}]+)\}", raw_path))
        if any(item.get("in") == "path" and item.get("name") not in template_names for item in parameters):
            raise ParameterSerializationError("Declared path parameter is absent from the operation path; no request was sent")

        query_pairs: List[Tuple[str, str]] = []
        emitted_names: Dict[str, int] = {}
        for index, metadata in enumerate(parameters):
            if metadata.get("in") != "query":
                continue
            name = metadata.get("name")
            value = values.get(name) if name in values else SmartDataGenerator.generate_raw_value_for_param(metadata, candidate_id=candidate_id)
            pairs = serialize_query_parameter(metadata, value, swagger2=swagger2)
            for encoded_name, _ in pairs:
                if encoded_name in emitted_names and emitted_names[encoded_name] != index:
                    raise ParameterSerializationError("Different query parameters serialize to the same name; no request was sent")
                emitted_names[encoded_name] = index
            query_pairs.extend(pairs)

        url = f"{self.target_base_url}{test_path}"
        if query_pairs:
            url += "?" + "&".join(name + "=" + value for name, value in query_pairs)
        return url

    def _safe_body(self, result: HTTPResult) -> Dict[str, Any]:
        return {
            "status": result.status,
            "body": sanitize_body(
                result.body,
                include_sensitive=self.include_sensitive_evidence,
                max_chars=min(self.max_response_bytes, 4096),
                secret_values=self._secret_values,
            ),
            "sha256": body_sha256(result.body),
            "truncated": result.truncated,
            "error": result.error,
        }

    def _record_result(
        self,
        ep: Dict[str, Any],
        check: str,
        verdict: Verdict,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
        finding: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = {
            "endpoint": self._operation_key(ep),
            "operation_id": ep.get("operation_id", ""),
            "check": check,
            "verdict": verdict.value,
            "reason": reason,
            "evidence": evidence or {},
        }
        result = sanitize_evidence(result, self.include_sensitive_evidence, self._secret_values)
        if finding:
            finding = sanitize_evidence(finding, self.include_sensitive_evidence, self._secret_values)
        with self._result_lock:
            self.results.append(result)
            self.stats["total_checks"] += 1
            if verdict not in {Verdict.SKIPPED, Verdict.ERROR}:
                self.stats["audited_count"] += 1
            if verdict in {Verdict.CONFIRMED, Verdict.SECURE, Verdict.PUBLIC, Verdict.AUTHORIZED}:
                self.stats["conclusive_count"] += 1
            if verdict == Verdict.CONFIRMED:
                self.stats["confirmed"] += 1
            elif verdict == Verdict.SECURE:
                self.stats["secure_endpoints"] += 1
            elif verdict == Verdict.PUBLIC:
                self.stats["public_endpoints"] += 1
            elif verdict == Verdict.AUTHORIZED:
                self.stats["authorized_endpoints"] += 1
            elif verdict == Verdict.SUSPICIOUS:
                self.stats["suspicious_count"] += 1
            elif verdict == Verdict.INCONCLUSIVE:
                self.stats["inconclusive_count"] += 1
            elif verdict == Verdict.SKIPPED:
                self.stats["skipped_count"] += 1
            elif verdict == Verdict.ERROR:
                self.stats["error_count"] += 1
            if finding:
                self.findings.append(finding)
        return result

    @staticmethod
    def _map_bola_verdict(raw: str) -> Verdict:
        mapping = {
            "BOLA_CONFIRMED": Verdict.CONFIRMED,
            "CONFIRMED": Verdict.CONFIRMED,
            "PUBLIC_ENDPOINT": Verdict.PUBLIC,
            "PUBLIC": Verdict.PUBLIC,
            "SECURE_ENFORCED": Verdict.SECURE,
            "SECURE": Verdict.SECURE,
            "LOW_SUSPICION": Verdict.SUSPICIOUS,
            "SUSPICIOUS": Verdict.SUSPICIOUS,
            "ERROR": Verdict.ERROR,
        }
        return mapping.get(str(raw).upper(), Verdict.INCONCLUSIVE)

    def audit_endpoint_bola(self, ep: Dict[str, Any]) -> None:
        path = ep["path"]
        parameters = ep.get("parameters", [])
        has_selector = "{" in path or any(item.get("in") == "query" for item in parameters)
        if not has_selector:
            self._record_result(ep, "BOLA", Verdict.SKIPPED, "No object selector was found")
            return

        try:
            owner_url = self._build_url(ep, "owner")
            visitor_self_url = self._build_url(ep, "visitor")
        except ParameterSerializationError as exc:
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE, str(exc))
            return
        owner = self._http_request(ep["method"], owner_url, identity_name="owner")
        visitor_cross = self._http_request(ep["method"], owner_url, identity_name="visitor")
        anonymous = self._http_request(ep["method"], owner_url, identity_name="anonymous")
        visitor_self = None
        if visitor_self_url != owner_url:
            visitor_self = self._http_request(
                ep["method"], visitor_self_url, identity_name="visitor"
            )

        request_results = {
            "owner": owner,
            "visitor_cross": visitor_cross,
            "anonymous": anonymous,
        }
        if visitor_self is not None:
            request_results["visitor_self"] = visitor_self
        transport_errors = [f"{name}: {item.error}" for name, item in request_results.items() if item.error]
        evidence: Dict[str, Any] = {
            "target_url": owner_url,
            "visitor_self_url": visitor_self_url if visitor_self is not None else None,
            **{name: self._safe_body(item) for name, item in request_results.items()},
        }
        if any(item.truncated for item in request_results.values()):
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE,
                                "A response was truncated; authorization comparison is incomplete", evidence=evidence)
            return
        if transport_errors:
            self._record_result(ep, "BOLA", Verdict.ERROR, "; ".join(transport_errors), evidence=evidence)
            return

        policy = self.bola_config.get(self._operation_key(ep), {})
        if not isinstance(policy, dict):
            raise ValueError("BOLA operation policy must be an object")
        expected_access = policy.get("expected_visitor_access", "deny")
        if expected_access not in ("allow", "deny"):
            raise ValueError("expected_visitor_access must be 'allow' or 'deny'")
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

    @staticmethod
    def _json_object(result: HTTPResult) -> Optional[Dict[str, Any]]:
        if not result.ok or result.truncated:
            return None
        try:
            value = strict_json_loads(result.body)
        except (ValueError, RecursionError):
            return None
        if not isinstance(value, dict) or not value:
            return None
        assessment = ResponseDiffEngine.classify_response(result.status, result.body)
        return value if assessment.get("kind") == ResponseDiffEngine.RESPONSE_VALID else None

    @staticmethod
    def _path_parts(path: Any) -> Tuple[Any, ...]:
        if isinstance(path, (tuple, list)):
            return tuple(path)
        tokens: List[Any] = []
        for name, index in re.findall(r"(?:^|\.)([^.\[]+)|\[(\d+)\]", str(path)):
            tokens.append(int(index) if index else name)
        return tuple(tokens)

    @classmethod
    def _get_path(cls, value: Any, path: Any) -> Tuple[bool, Any]:
        current = value
        if not path:
            return True, current
        for part in cls._path_parts(path):
            if isinstance(part, str) and isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(part, int) and isinstance(current, list) and part < len(current):
                current = current[part]
            else:
                return False, None
        return True, current

    @classmethod
    def _set_path(cls, payload: Dict[str, Any], path: Any, value: Any) -> None:
        parts = cls._path_parts(path)
        if not parts:
            raise ValueError("mutation path must not be empty")
        cursor: Any = payload
        for position, part in enumerate(parts):
            last = position == len(parts) - 1
            next_part = None if last else parts[position + 1]
            if isinstance(part, str):
                if not isinstance(cursor, dict):
                    raise ValueError(f"cannot place object field '{part}' inside a non-object")
                if last:
                    cursor[part] = value
                    return
                expected: Union[List[object], Dict[str, object]] = [] if isinstance(next_part, int) else {}
                if not isinstance(cursor.get(part), type(expected)):
                    cursor[part] = expected
                cursor = cursor[part]

            else:
                if not isinstance(cursor, list):
                    raise ValueError(f"cannot place array index {part} inside a non-array")
                while len(cursor) <= part:
                    cursor.append([] if isinstance(next_part, int) else {})
                if last:
                    cursor[part] = value
                    return
                expected = [] if isinstance(next_part, int) else {}
                if not isinstance(cursor[part], type(expected)):
                    cursor[part] = expected
                cursor = cursor[part]

    @classmethod
    def _merge_payloads(cls, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively overlay configured valid fields without discarding generated ones."""
        merged = copy.deepcopy(base)
        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = cls._merge_payloads(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged

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

    def _readback_result(
        self,
        ep: Dict[str, Any],
        mapping: Dict[str, Any],
        identity_name: str,
    ) -> Tuple[str, HTTPResult]:
        documented = next((candidate for candidate in self.parser.get_endpoints()
                           if candidate["method"] == str(mapping.get("method", "GET")).upper()
                           and candidate["path"] == str(mapping["path"])), None)
        read_ep = {
            "method": str(mapping.get("method", "GET")).upper(),
            "path": str(mapping["path"]),
            "parameters": mapping.get("parameters", (documented or ep).get("parameters", [])),
            "spec_version": (documented or ep).get("spec_version", self.parser.raw_spec.get("openapi", self.parser.raw_spec.get("swagger", ""))),
            "operation_id": f"readback_{ep.get('operation_id', '')}",
        }
        url = self._build_url(read_ep, identity_name, mapping.get("parameter_values"))
        return url, self._http_request(read_ep["method"], url, identity_name=identity_name)

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
                verified = snapshot.matches(self._json_object(restored_http))
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
                after = self._json_object(after_http)
                if (after is not None and not snapshot.matches(after)) or attempt + 1 == attempts:
                    break
                time.sleep(delay)
            # Only an explicitly strongly consistent, complete observation allows
            # skipping a redundant restore. Weak/stale reads must not bypass recovery.
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
        operation_key = self._operation_key(ep)
        if self._writes_halted_reason:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED, self._writes_halted_reason)
            return
        if not self.allow_write_tests:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "State-changing checks are disabled; pass --allow-write-tests to opt in")
            return
        if operation_key not in self.write_allowlist:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Endpoint is not in the explicit, case-sensitive write-test allowlist")
            return
        schema = ep.get("request_schema")
        if not isinstance(schema, dict) or not schema:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "No request schema is available; no write was sent")
            return
        content_type = str(ep.get("request_content_type") or "").split(";", 1)[0].lower()
        if content_type not in {"application/json", "application/merge-patch+json"}:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Only object application/json and application/merge-patch+json are supported; "
                                "JSON Patch operation arrays and arbitrary vendor formats are not implemented")
            return
        readback = self._readback_for(ep, all_endpoints)
        if (not readback or not readback.get("path")
                or str(readback.get("method", "GET")).upper() != "GET"):
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                "An independent GET readback mapping is required; no write was sent")
            return
        field_map = readback.get("field_map")
        if not isinstance(field_map, dict) or not field_map:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                "An explicit non-empty field_map is required; no write was sent")
            return
        try:
            generated = self._normalise_mutation_cases(schema)
        except ValueError as exc:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                f"A valid baseline could not be generated: {exc}; no write was sent")
            return
        cases = [case for case in generated if case["field_path"] in field_map]
        generated_paths = {case["field_path"] for case in cases}
        unverified = [f"{name}: no mutation case was generated" for name in field_map if name not in generated_paths]
        verified_safe: List[str] = []
        tested: List[str] = []
        case_summaries: List[Dict[str, Any]] = []
        try:
            mutation_url = self._build_url(ep, "visitor")
        except ParameterSerializationError as exc:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE, str(exc))
            return

        with self._resource_lock(mutation_url):
            for case in cases:
                field_path = case["field_path"]
                try:
                    read_url, before_http = self._readback_result(ep, readback, "visitor")
                except ParameterSerializationError as exc:
                    self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE, str(exc))
                    return
                if before_http.error:
                    self._record_result(ep, "MASS_ASSIGNMENT", Verdict.ERROR,
                                        f"Read-before-write failed: {before_http.error}",
                                        evidence={"readback_url": read_url, "before": self._safe_body(before_http)})
                    return
                before = self._json_object(before_http)
                if before is None:
                    unverified.append(f"{field_path}: readback was not a complete successful JSON object")
                    continue
                try:
                    snapshot = prepare_patch(before, case, readback)
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
                except (ValueError, KeyError, TypeError) as exc:
                    unverified.append(f"{field_path}: {exc}; no write was sent")
                    continue

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
                    "snapshot_fields": list(snapshot.restore),
                    "verification_scope": "Full readback document except explicitly ignored volatile paths",
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
                    return
                if self._writes_halted_reason:
                    self._record_result(ep, "MASS_ASSIGNMENT", Verdict.ERROR,
                                        self._writes_halted_reason, evidence)
                    return
                if transaction["failure"] or mutation.error or mutation.status == 0 or mutation.status >= 500:
                    self._record_result(ep, "MASS_ASSIGNMENT", Verdict.ERROR,
                                        "Mutation outcome was ambiguous; recovery was verified. "
                                        + str(transaction["failure"] or mutation.error or mutation.status), evidence)
                    return
                if after is None:
                    unverified.append(f"{field_path}: invalid read-after-write; original snapshot restored")
                    continue
                if not snapshot.matches(after):
                    unverified.append(f"{field_path}: unexpected state change; original snapshot restored")
                    continue
                if readback.get("consistency") != "strong":
                    unverified.append(f"{field_path}: unchanged state is not conclusive without strongly consistent readback")
                    continue
                if mutation.status in self.AUTH_DENIAL_STATUSES:
                    verified_safe.append(field_path)
                    continue
                assessment = (ResponseDiffEngine.classify_response(mutation.status, mutation.body)
                              if mutation.status != 204 else {"kind": ResponseDiffEngine.RESPONSE_VALID})
                if mutation.ok and assessment.get("kind") == ResponseDiffEngine.RESPONSE_VALID:
                    verified_safe.append(field_path)
                else:
                    unverified.append(f"{field_path}: mutation was rejected or returned a business error")
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

    def _record_task_error(self, ep: Dict[str, Any], check: str, exc: BaseException) -> None:
        self._record_result(ep, check, Verdict.ERROR, f"Unhandled {type(exc).__name__}: {exc}")

    def _finalise_coverage(self) -> None:
        total = max(1, int(self.stats["total_endpoints"]))
        endpoint_results = [item for item in self.results if item["check"] != "ROLLBACK"]
        attempted = sum(1 for item in endpoint_results if item["verdict"] != Verdict.SKIPPED.value)
        conclusive = sum(
            1
            for item in endpoint_results
            if item["verdict"] in {Verdict.CONFIRMED.value, Verdict.SECURE.value, Verdict.PUBLIC.value, Verdict.AUTHORIZED.value}
        )
        self.stats["coverage_pct"] = round(attempted * 100.0 / total, 1)
        self.stats["conclusive_coverage_pct"] = round(conclusive * 100.0 / total, 1)

    def build_plan(self) -> Dict[str, Any]:
        """Inspect local specification/configuration only; this never makes requests."""
        entries = []
        for ep in self.parser.get_endpoints():
            key = self._operation_key(ep)
            readback = self.readback_config.get(key, {})
            entry = {"endpoint": key, "check": "UNSUPPORTED", "writes_enabled": False}
            if ep["method"] == "GET":
                entry["check"] = "BOLA"
            elif ep["method"] == "PATCH":
                entry.update({
                    "check": "MASS_ASSIGNMENT",
                    "writes_enabled": self.allow_write_tests and key in self.write_allowlist,
                    "content_type": ep.get("request_content_type"),
                    "readback_path": readback.get("path"),
                    "configured_fields": list(readback.get("field_map", {})),
                    "readback_consistency": readback.get("consistency", "unspecified"),
                })
            entries.append(entry)
        return sanitize_evidence({"mode": "DRY_RUN", "requests_sent": 0,
                                  "note": "Local plan only; not a successful scan or a recovery guarantee",
                                  "target": self.target_base_url, "operations": entries},
                                 self.include_sensitive_evidence, self._secret_values)

    def run(self) -> None:
        endpoints = self.parser.get_endpoints()
        self.stats["total_endpoints"] = len(endpoints)
        print("=" * 68)
        print(f"GrantTrace {__version__} safety-first audit")
        print(f"Specification: {self.parser.version} | endpoints: {len(endpoints)}")
        print(
            "Write tests: "
            + ("ENABLED with rollback verification" if self.allow_write_tests else "DISABLED (read-only mode)")
        )
        print("=" * 68)

        get_endpoints = [ep for ep in endpoints if ep["method"] == "GET"]
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ep = {executor.submit(self.audit_endpoint_bola, ep): ep for ep in get_endpoints}
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

