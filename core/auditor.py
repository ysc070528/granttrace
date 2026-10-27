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
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Iterable, List, Mapping, Optional, Pattern, Set, Tuple, Union

from core import __version__
from core.authorization import AuthorizationEvidence
from core.bopla import BOPLAEvidence, resource_scope, validate_bopla_policy
from core.config_validator import ConfigValidator
from core.diff import ResponseDiffEngine
from core.evidence import PROPERTY_EVIDENCE_LOCK, body_sha256, sanitize_body, sanitize_evidence, sanitize_property_record
from core.transactions import PatchSnapshot, ensure_reversible_merge_patch, get_path, path_parts, prepare_patch
from core.generator import SmartDataGenerator
from core.models import HTTPResult, Verdict, json_values_equal, parse_operation_key, strict_json_loads
from core.parser import OpenAPIParser
from core.parameters import ParameterSerializationError, serialize_cookie_parameter, serialize_header_parameter, serialize_path_parameter, serialize_query_parameter
from core.scan_safety import read_only_risk, read_path_risk


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return 30x to the detector instead of forwarding credentials."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class _ReadSafetyCache:
    parser: OpenAPIParser
    routes: Tuple[Tuple[Pattern[str], Optional[Tuple[Tuple[str, str], ...]]], ...]
    readbacks: Mapping[Tuple[str, str], Mapping[str, Any]]


class APISentinelAuditor:
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

        context = ssl._create_unverified_context() if insecure_ssl else ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            _NoRedirectHandler(), urllib.request.HTTPSHandler(context=context)
        )
        self._rate_lock = threading.Lock()
        self._next_request_at = 0.0
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
            "attempted_endpoints": 0,
            "conclusive_endpoints": 0,
            "confirmed": 0,
            "bola_confirmed": 0,
            "mass_assignment_confirmed": 0,
            "broken_auth_confirmed": 0,
            "bfla_confirmed": 0,
            "transport_attempts": 0,
            "http_requests_sent": 0,
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
        if getattr(self._request_accounting, "attempts", None) is None:
            self._request_accounting.attempts = 0
        risk = self._read_request_risk(method, url)
        if risk:
            return HTTPResult(status=0, body="", error=risk["safety_reason"])
        self._throttle()
        try:
            if headers is not None:
                request_headers = {
                    "accept": "application/json",
                    "user-agent": f"GrantTrace/{__version__}",
                    **headers,
                }
            else:
                request_headers = {
                    "accept": "application/json",
                    "user-agent": f"GrantTrace/{__version__}",
                    **self._identity_headers(identity_name),
                }
            encoded_data = None
            if data is not None:
                request_headers["content-type"] = content_type
                encoded_data = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
            request = urllib.request.Request(url, data=encoded_data, method=method, headers=request_headers)
            self._request_accounting.attempts = (getattr(self._request_accounting, "attempts", None) or 0) + 1
            with self._result_lock:
                self.stats["transport_attempts"] += 1
            try:
                response = self._opener.open(request, timeout=self.request_timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                with self._result_lock:
                    self.stats["http_requests_sent"] += 1
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

    def _build_request_headers(
        self,
        ep: Dict[str, Any],
        resource_identity: str,
        identity_name: str,
        extra_values: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        req_headers = dict(self._identity_headers(identity_name))
        parameters = ep.get("parameters", [])
        if not isinstance(parameters, list):
            return req_headers

        swagger2 = str(ep.get("spec_version", self.parser.raw_spec.get("swagger", ""))).startswith("2.")
        values = self._operation_parameter_values(ep, resource_identity)
        if extra_values:
            values.update(extra_values)

        business_headers: Dict[str, str] = {}
        emitted_headers: Set[str] = set()
        cookie_pairs: List[Tuple[str, str]] = []
        emitted_cookies: Set[str] = set()

        for metadata in parameters:
            if not isinstance(metadata, dict):
                continue
            location = metadata.get("in")
            name = metadata.get("name")
            if not isinstance(name, str) or not name:
                continue

            normalized_name = name.lower()

            if location == "header":
                if not swagger2 and normalized_name in {"authorization", "accept", "content-type"}:
                    continue
                if self._is_auth_header(name):
                    if all(self._identity_headers(role).get(normalized_name) for role in ("owner", "visitor")):
                        continue
                    raise ParameterSerializationError(
                        f"Authentication header '{name}' cannot be supplied via parameter values; no request was sent"
                    )

                if normalized_name in emitted_headers:
                    raise ParameterSerializationError(
                        "Different header parameters serialize to the same name; no request was sent"
                    )
                emitted_headers.add(normalized_name)

                if normalized_name in req_headers:
                    raise ParameterSerializationError(
                        f"Business header parameter '{name}' conflicts with identity header; no request was sent"
                    )

                is_required = metadata.get("required") is True
                if name in values:
                    val = values[name]
                elif is_required:
                    raise ParameterSerializationError(f"Missing required header parameter '{name}'; no request was sent")
                elif "default" in metadata or (isinstance(metadata.get("schema"), dict) and "default" in metadata["schema"]):
                    val = metadata.get("default", metadata.get("schema", {}).get("default"))
                else:
                    continue

                hdr_name, hdr_val = serialize_header_parameter(metadata, val, swagger2=swagger2)
                business_headers[hdr_name] = hdr_val

            elif location == "cookie":
                if swagger2:
                    raise ParameterSerializationError("Swagger 2 does not support cookie parameters; no request was sent")

                is_required = metadata.get("required") is True
                if name in values:
                    val = values[name]
                elif is_required:
                    raise ParameterSerializationError(f"Missing required cookie parameter '{name}'; no request was sent")
                elif "default" in metadata or (isinstance(metadata.get("schema"), dict) and "default" in metadata["schema"]):
                    val = metadata.get("default", metadata.get("schema", {}).get("default"))
                else:
                    continue

                c_name, c_val = serialize_cookie_parameter(metadata, val, swagger2=swagger2)
                if c_name in emitted_cookies:
                    raise ParameterSerializationError(
                        "Different cookie parameters serialize to the same name; no request was sent"
                    )
                emitted_cookies.add(c_name)
                cookie_pairs.append((c_name, c_val))

        if cookie_pairs:
            identity_cookie_names: Set[str] = set()
            existing_cookie_str = ""
            for k, v in list(req_headers.items()):
                if k.lower() == "cookie":
                    existing_cookie_str = v
                    break

            if existing_cookie_str:
                for part in existing_cookie_str.split(";"):
                    part = part.strip()
                    if part:
                        c_key = part.split("=", 1)[0].strip()
                        identity_cookie_names.add(c_key)

            for c_name, _ in cookie_pairs:
                if c_name in identity_cookie_names:
                    raise ParameterSerializationError(
                        f"Business cookie parameter '{c_name}' conflicts with identity authentication cookie; no request was sent"
                    )

            business_cookie_str = "; ".join(f"{k}={v}" for k, v in cookie_pairs)
            if existing_cookie_str:
                merged_cookie = f"{existing_cookie_str.rstrip('; ')}; {business_cookie_str}"
            else:
                merged_cookie = business_cookie_str

            cookie_key = next((k for k in req_headers if k.lower() == "cookie"), "cookie")
            req_headers[cookie_key] = merged_cookie

        req_headers.update(business_headers)
        return req_headers

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
            if location not in {"path", "query", "header", "cookie"}:
                raise ParameterSerializationError("Unsupported parameter location; no request was sent")
            if swagger2 and location == "cookie":
                raise ParameterSerializationError("Swagger 2 does not support cookie parameters; no request was sent")
            supported.append(metadata)
        parameters = supported

        # Validate header and cookie parameters for this resource identity
        self._build_request_headers(ep, resource_identity, resource_identity, extra_values)

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
                {"name": param_name, "in": "path", "schema": {}},
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

    @staticmethod
    def _private_evidence_values(owner: HTTPResult, policy: Dict[str, Any]) -> Tuple[str, ...]:
        # Redact configured private values from every identity's stored body,
        # including echoes at other paths. Evaluation still uses original HTTP.
        try:
            document = strict_json_loads(owner.body)
        except (TypeError, ValueError, RecursionError):
            return ()
        values = []
        for path in policy.get("private_data_paths", []):
            exists, value = get_path(document, path)
            if exists and ((isinstance(value, str) and value) or type(value) in (int, float)):
                values.append(str(value))
        return tuple(values)

    def _record_result(
        self,
        ep: Dict[str, Any],
        check: str,
        verdict: Verdict,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
        finding: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        evidence = dict(evidence or {})
        # Count transport attempts, including failed connections, rather than
        # treating a local preflight conclusion as an executed check.
        attempts = getattr(self._request_accounting, "attempts", None)
        if attempts is None:
            # Response records also support callers that provide an isolated
            # transport fixture instead of using the built-in HTTP executor.
            def response_count(value: Any) -> int:
                if isinstance(value, dict):
                    if {"status", "body", "sha256", "truncated"}.issubset(value):
                        return 1
                    return sum(response_count(child) for child in value.values())
                if isinstance(value, list):
                    return sum(response_count(child) for child in value)
                return 0
            attempts = response_count(evidence)
        if getattr(self._request_accounting, "attempts", None) is not None:
            evidence["requests_attempted"] = attempts
        else:
            evidence.setdefault("requests_attempted", attempts)
        primary = check != "ROLLBACK"
        attempted = evidence["requests_attempted"] > 0
        conclusive = verdict in {Verdict.CONFIRMED, Verdict.SECURE, Verdict.PUBLIC, Verdict.AUTHORIZED}
        if "reason_category" not in evidence:
            if verdict == Verdict.SKIPPED:
                category = "detector_unimplemented" if check == "UNSUPPORTED" else "not_applicable"
            elif verdict == Verdict.ERROR:
                category = "error"
            elif conclusive:
                category = "conclusive"
            else:
                missing = evidence.get("decision_evidence", {}).get("missing_evidence", [])
                category = "missing_baseline" if not attempted or any(
                    item in missing for item in ("owner_baseline", "visitor_self_baseline", "distinct_visitor_self_resource")
                ) else "insufficient_evidence"
            evidence["reason_category"] = category
        if primary:
            self._request_accounting.attempts = None
        result = {
            "endpoint": self._operation_key(ep),
            "operation_id": ep.get("operation_id", ""),
            "check": check,
            "verdict": verdict.value,
            "reason": reason,
            "evidence": evidence,
        }
        force_safe = self._operation_key(ep) in self.bopla_config
        with self._result_lock, PROPERTY_EVIDENCE_LOCK:
            duplicate = False
            resource_group = None
            if force_safe:
                policy = self.bopla_config[self._operation_key(ep)]
                proof = evidence.get("decision_evidence", {})
                field_path = proof.get("field_path") if check == "BOPLA" else None
                if isinstance(policy, dict) and not validate_bopla_policy(policy) and (field_path or finding):
                    if check != "BOPLA":
                        # A legacy collection/object finding can prove exposure
                        # of the very field a property rule selects. Associate
                        # that one finding with one actually matched resource;
                        # other array resources retain independent leak groups.
                        shared_paths = proof.get("matched_private_data_paths") or proof.get("owner_specific_shared_value_paths", ())
                        matched_paths = set()
                        for path in shared_paths:
                            try:
                                matched_paths.add(path_parts(path))
                            except (TypeError, ValueError):
                                continue  # Arbitrary JSON keys need not be valid policy paths.
                        field_path = next((rule["path"] for rule in policy["fields"]
                                           if path_parts(rule["path"]) in matched_paths), None)
                    selected = (self._operation_key(ep), str(evidence.get("target_url", "")),
                                str(policy["context_id"]), resource_scope(policy, field_path))
                    resource_group = self._bopla_resource_groups.setdefault(selected, len(self._bopla_resource_groups) + 1)
                    evidence["resource_group"] = resource_group
            if force_safe and finding and verdict == Verdict.CONFIRMED:
                identity = (evidence.get("decision_evidence", {}).get("subject_identity")
                            if check == "BOPLA" else "anonymous" if check == "BROKEN_AUTH" else "visitor")
                context = self.bopla_config[self._operation_key(ep)].get("context_id", "")
                group_key = (self._operation_key(ep), str(evidence.get("target_url", "")),
                             str(context), str(identity), resource_group)
                group = self._bopla_leak_groups.get(group_key)
                if group:
                    duplicate = True
                    result["evidence"]["duplicate_of"] = group
                    finding = None
                else:
                    group = "read-leak-" + str(len(self._bopla_leak_groups) + 1)
                    self._bopla_leak_groups[group_key] = group
                result["evidence"]["leak_group"] = group
            # The mandatory boundary covers all operations in a BOPLA scan.
            # It preserves trusted control metadata while sanitizing business
            # observations and prevents a concurrent append escaping late cleanup.
            if self.bopla_config:
                result["evidence"]["property_privacy_pending"] = True
                result = self._property_safe_record(result)
                if finding:
                    finding.setdefault("evidence", {})["property_privacy_pending"] = True
                    finding = self._property_safe_record(finding)
            else:
                result = sanitize_evidence(result, self.include_sensitive_evidence, self._secret_values)
                if finding:
                    finding = sanitize_evidence(finding, self.include_sensitive_evidence, self._secret_values)
            self.results.append(result)
            self.stats["total_checks"] += 1
            if primary and attempted:
                self.stats["audited_count"] += 1
            if primary and attempted and conclusive:
                self.stats["conclusive_count"] += 1
            if verdict == Verdict.CONFIRMED and not duplicate:
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
            # Per-detector counts measure confirmed decisions, even when their
            # shared observation contributes only one independent finding.
            if check == "BROKEN_AUTH" and verdict == Verdict.CONFIRMED:
                self.stats["broken_auth_confirmed"] += 1
            elif check == "BFLA" and verdict == Verdict.CONFIRMED:
                self.stats["bfla_confirmed"] += 1
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

    def _property_safe_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_property_record(record, self._secret_values,
                                        omit_responses=bool(self._bopla_secret_values))

    @staticmethod
    def _replace_evidence_in_place(current: Any, safe: Any) -> None:
        # Callers can retain a record, a list, or a nested evidence dictionary.
        # Replacing only the auditor's outer collection leaves those aliases live.
        if isinstance(current, dict) and isinstance(safe, dict):
            for key in list(current):
                if key not in safe:
                    del current[key]
            for key, value in safe.items():
                if key in current and isinstance(current[key], (dict, list)) and isinstance(value, type(current[key])):
                    APISentinelAuditor._replace_evidence_in_place(current[key], value)
                else:
                    current[key] = value
        elif isinstance(current, list) and isinstance(safe, list):
            for index, value in enumerate(safe):
                if index < len(current) and isinstance(current[index], (dict, list)) and isinstance(value, type(current[index])):
                    APISentinelAuditor._replace_evidence_in_place(current[index], value)
                elif index < len(current):
                    current[index] = value
                else:
                    current.append(value)
            del current[len(safe):]

    def _redact_property_history(self) -> None:
        # The result lock is held by callers, including registration and finalization.
        with PROPERTY_EVIDENCE_LOCK:
            for collection in (self.results, self.findings):
                for record in collection:
                    self._replace_evidence_in_place(record, self._property_safe_record(record))

    def _read_observation(
        self, method: str, url: str, identity_name: str, headers: Optional[Dict[str, str]] = None
    ) -> HTTPResult:
        result = self._http_request(method, url, identity_name=identity_name, headers=headers)
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
        except ParameterSerializationError:
            self._record_result(ep, "BOPLA", Verdict.INCONCLUSIVE,
                                "Property resource parameters cannot be serialized; no request sent",
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
                    obs_headers = self._build_request_headers(ep, "owner", identity)
                    self._read_observation("GET", url, identity, headers=obs_headers)
            owner = observations[(url, "owner")]
            for rule in policy["fields"]:
                for identity in ("visitor", "anonymous"):
                    decision = BOPLAEvidence.evaluate(
                        owner, observations[(url, identity)], policy=policy,
                        field=rule, identity=identity,
                        visitor_self=observations.get((self_url, "visitor")) if self_url != url else None,
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

    def _audit_endpoint_bola(self, ep: Dict[str, Any]) -> None:
        if str(ep.get("method", "")).upper() != "GET":
            self._record_result(ep, "BOLA", Verdict.SKIPPED,
                                "BOLA read-only checks support GET only; no method substitution or request was made",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, "safety_signal": "method"})
            return
        risk = read_only_risk(ep)
        if risk:
            self._record_result(ep, "BOLA", Verdict.SKIPPED, risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, **risk})
            return
        policy = self.bola_config.get(self._operation_key(ep), {})
        validation = ConfigValidator.validate({"bola": {self._operation_key(ep): policy}})
        if not validation.is_valid:
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE,
                                "BOLA operation policy is invalid; run offline configuration validation; no request was sent",
                                evidence={"reason_category": "invalid_input", "requests_attempted": 0})
            return
        if not self._has_object_selector(ep) or ("{" not in ep["path"] and policy.get("private_data_paths")):
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
        except ParameterSerializationError as exc:
            self._record_result(ep, "BOLA", Verdict.INCONCLUSIVE, str(exc),
                                evidence={"reason_category": "invalid_input", "requests_attempted": 0})
            return
        risk = self._read_request_risk("GET", owner_url) or self._read_request_risk("GET", visitor_self_url)
        if risk:
            self._record_result(ep, "BOLA", Verdict.SKIPPED, risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, **risk})
            return
        owner = self._read_observation(ep["method"], owner_url, identity_name="owner", headers=owner_headers)
        visitor_cross = self._read_observation(ep["method"], owner_url, identity_name="visitor", headers=visitor_cross_headers)
        anonymous = self._read_observation(ep["method"], owner_url, identity_name="anonymous", headers=anonymous_headers)
        visitor_self = None
        if visitor_self_url != owner_url or visitor_self_headers != visitor_cross_headers:
            visitor_self = self._read_observation(
                ep["method"], visitor_self_url, identity_name="visitor", headers=visitor_self_headers
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
                private_data_paths=private_paths)))
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
        except ParameterSerializationError as exc:
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
        if str(ep.get("method", "")).upper() not in self.WRITE_METHODS:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Only explicitly allowlisted reversible PATCH/PUT checks are supported; no method substitution or request was made",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, "safety_signal": "method"})
            return
        operation_key = self._operation_key(ep)
        if self._writes_halted_reason:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED, self._writes_halted_reason,
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0})
            return
        if not self.allow_write_tests:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "State-changing checks are disabled; pass --allow-write-tests to opt in",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0})
            return
        if operation_key not in self.write_allowlist:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Endpoint is not in the explicit, case-sensitive write-test allowlist",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0})
            return
        schema = ep.get("request_schema")
        if not isinstance(schema, dict) or not schema:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "No request schema is available; no write was sent")
            return
        content_type = str(ep.get("request_content_type") or "").split(";", 1)[0].strip().lower()
        allowed_types = {"application/json"} if ep["method"].upper() == "PUT" else {
            "application/json", "application/merge-patch+json"}
        if content_type not in allowed_types:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Only object application/json and application/merge-patch+json are supported; "
                                "JSON Patch operation arrays and arbitrary vendor formats are not implemented",
                                evidence={"reason_category": "detector_unimplemented", "requests_attempted": 0})
            return
        readback = self._readback_for(ep, all_endpoints)
        if (not readback or not readback.get("path")
                or str(readback.get("method", "GET")).upper() != "GET"):
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                "An independent GET readback mapping is required; no write was sent")
            return
        risk = read_only_risk(self._readback_endpoint(ep, readback))
        if risk:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Unsafe readback: " + risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, **risk})
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
            read_ep = self._readback_endpoint(ep, readback)
            readback_url = self._build_url(read_ep, "visitor", readback.get("parameter_values"))
        except ParameterSerializationError as exc:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE, str(exc),
                                evidence={"reason_category": "invalid_input", "requests_attempted": 0})
            return
        risk = self._read_request_risk("GET", readback_url)
        if risk:
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.SKIPPED,
                                "Unsafe readback: " + risk["safety_reason"],
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, **risk})
            return

        if not self._has_patch_state_authority():
            self._record_result(ep, "MASS_ASSIGNMENT", Verdict.INCONCLUSIVE,
                                "Authoritative resource state cannot be verified; no write was sent. "
                                "Ordinary HTTP readbacks and consistency declarations are insufficient.",
                                evidence={"reason_category": "safety_policy", "requests_attempted": 0,
                                          "requests_sent": 0, "rollback_verified": False,
                                          "recovery_sent": False, "safety_signal": "unverified_state_authority"})
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
                before = self._verified_patch_document(before_http, ep, mutation_url, readback)
                if before is None:
                    unverified.append(f"{field_path}: readback requires a complete HTTP 200 JSON object matching independently verified authoritative state")
                    continue
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
                    continue

                # Recheck the authority immediately before transport; it may
                # become unavailable while preparing the reversible snapshot.
                if self._verified_patch_document(before_http, ep, mutation_url, readback) is None:
                    unverified.append(f"{field_path}: authoritative initial state became unavailable; no write was sent")
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

    def _audit_bola_task(self, ep: Dict[str, Any]) -> None:
        # A worker must report its own error while transport accounting is still
        # available in that thread. Reused workers start with a fresh check.
        self._request_accounting.attempts = None
        try:
            self.audit_endpoint_bola(ep)
        except Exception as exc:
            self._record_task_error(ep, "BOLA", exc)

    def _record_task_error(self, ep: Dict[str, Any], check: str, exc: BaseException) -> None:
        message = ("Property audit failed; response details omitted" if self.bopla_config
                   else f"Unhandled {type(exc).__name__}: {exc}")
        self._record_result(ep, check, Verdict.ERROR, message)

    def _finalise_coverage(self) -> None:
        with self._result_lock, PROPERTY_EVIDENCE_LOCK:
            self._finalise_coverage_locked()

    def _finalise_coverage_locked(self) -> None:
        if self._bopla_secret_values:
            # Include observations recorded before another worker learned a
            # protected value. Sensitive opt-in cannot remove this boundary.
            self._redact_property_history()
        total = max(1, int(self.stats["total_endpoints"]))
        endpoint_results = [item for item in self.results if item["check"] != "ROLLBACK"]
        attempted_keys = {item["endpoint"] for item in endpoint_results
                          if item.get("evidence", {}).get("requests_attempted", 0) > 0}
        # Multiple detection items on one endpoint share a coverage denominator.
        # Every selected item must have a conclusive attempted observation. Legacy
        # repeated results for the same item retain their existing any-result rule.
        item_states: Dict[str, Dict[str, bool]] = {}
        for item in endpoint_results:
            states = item_states.setdefault(item["endpoint"], {})
            conclusive_item = item.get("evidence", {}).get("requests_attempted", 0) > 0 and item["verdict"] in {
                Verdict.CONFIRMED.value, Verdict.SECURE.value, Verdict.PUBLIC.value, Verdict.AUTHORIZED.value}
            if item["check"] == "BOPLA":
                states["BOPLA"] = states.get("BOPLA", True) and conclusive_item
            else:
                states[item["check"]] = states.get(item["check"], False) or conclusive_item
        conclusive_keys = {endpoint for endpoint, states in item_states.items() if all(states.values())}
        attempted = len(attempted_keys)
        conclusive = len(conclusive_keys)
        self.stats["attempted_endpoints"] = attempted
        self.stats["conclusive_endpoints"] = conclusive
        self.stats["coverage_pct"] = round(attempted * 100.0 / total, 1)
        self.stats["conclusive_coverage_pct"] = round(conclusive * 100.0 / total, 1)
        self.stats["confirmed_endpoints"] = len({item["endpoint"] for item in endpoint_results
                                                 if item["verdict"] == Verdict.CONFIRMED.value})
        self.stats["detection_items"] = sum(len(states) for states in item_states.values())
        if self.bopla_config:
            fields = [item for item in endpoint_results if item["check"] == "BOPLA"]
            def field_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
                proof = item["evidence"].get("decision_evidence", {})
                return (item["endpoint"], item["evidence"].get("target_url"), proof.get("context_id"),
                        item["evidence"].get("resource_group"), proof.get("field_path"))
            self.stats["bopla_field_checks"] = sum(bool(item["evidence"].get("decision_evidence", {}).get("field_path")) for item in fields)
            self.stats["bopla_fields_checked"] = len({field_key(item) for item in fields
                if item["evidence"].get("decision_evidence", {}).get("comparison_valid")})
            self.stats["bopla_fields_confirmed"] = len({field_key(item) for item in fields
                if item["verdict"] == "CONFIRMED"})
            self.stats["bopla_inconclusive_count"] = sum(item["verdict"] == "INCONCLUSIVE" for item in fields)
            self.stats["bopla_skipped_count"] = sum(item["verdict"] == "SKIPPED" for item in fields)
            self.stats["unique_confirmed_vulnerabilities"] = len(self.findings)
            self.stats["confirmed_detection_items"] = sum(item["verdict"] == "CONFIRMED" for item in endpoint_results)

    def build_plan(self) -> Dict[str, Any]:
        """Inspect local specification/configuration only; this never makes requests."""
        entries = []
        for ep in self.parser.get_endpoints():
            key = self._operation_key(ep)
            readback = self.readback_config.get(key, {})
            entry = {"endpoint": key, "check": "UNSUPPORTED", "writes_enabled": False}
            if ep["method"] == "GET":
                entry["check"] = "BOLA"
                risk = read_only_risk(ep)
                parameter_error = None
                if not risk:
                    try:
                        risk = (self._read_request_risk("GET", self._build_url(ep, "owner"))
                                or self._read_request_risk("GET", self._build_url(ep, "visitor")))
                    except ParameterSerializationError as exc:
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
                        except ParameterSerializationError:
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

        get_endpoints = [ep for ep in endpoints if ep["method"] == "GET"]
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

