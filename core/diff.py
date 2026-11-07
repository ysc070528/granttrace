# -*- coding: utf-8 -*-
"""
Semantic response diffing and classification engine.

Status codes and application-level denial signals are always checked together
with the response body. Error responses can still disclose data, and anonymous
readability does not prove that a resource is meant to be public; confirmation
evidence comes only from business values or explicitly trusted identifier paths.

Reasons are English, like those of every other check. Chinese denial messages
returned by a target API are still recognized (see AUTH_ERROR_WORDS).
"""

import json
import re
from functools import lru_cache
from typing import Any, Dict, Iterable, Optional, Set, Tuple

from core.models import json_values_equal, strict_json_loads


_JSON_PARSE_FAILED = object()


@lru_cache(maxsize=8192)
def _normalised_key_text(text: str) -> str:
    # Response walks normalise every key of every record; keys repeat heavily.
    text = text.strip().replace("-", "_")
    text = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    return text.lower()


class ResponseDiffEngine:
    """Classify API responses and evaluate object-level authorization evidence."""

    RESPONSE_VALID = "VALID"
    RESPONSE_AUTH_DENIED = "AUTH_DENIED"
    RESPONSE_APPLICATION_ERROR = "APPLICATION_ERROR"
    RESPONSE_TRANSPORT_ERROR = "TRANSPORT_ERROR"
    RESPONSE_HTTP_CLIENT_ERROR = "HTTP_CLIENT_ERROR"
    RESPONSE_SERVER_ERROR = "SERVER_ERROR"
    RESPONSE_HTTP_ERROR = "HTTP_ERROR"
    RESPONSE_EMPTY = "EMPTY_RESPONSE"
    RESPONSE_INVALID = "INVALID_RESPONSE"

    AUTH_ERROR_CODES = {401, 403, "401", "403"}
    AUTH_ERROR_WORDS = (
        "unauthorized",
        "forbidden",
        "authentication required",
        "not authenticated",
        "permission denied",
        "access denied",
        "not allowed",
        "auth_error",
        "无权访问",
        "无权限",
        "权限不足",
        "拒绝访问",
        "未授权",
        "未登录",
        "需要登录",
    )
    # Full-message grammar only: a denial prefix must not conceal a reflected
    # credential, business value, or an unknown explanatory suffix.
    AUTH_DENIAL_PATTERNS = (
        r"(?:(?:jwt|bearer|access|authentication|auth) )?token (?:is |was |has )?"
        r"(?:required|missing|invalid|expired|not provided|not valid|not found)",
        r"(?:missing|invalid|expired) (?:(?:jwt|bearer|access|authentication|auth) )?token",
        r"jwt (?:is |has )?(?:required|missing|invalid|expired)",
        r"(?:jwt|token|jwt token) (?:signature )?(?:verification|validation) failed",
        r"authentication (?:is )?(?:required|failed)",
        r"(?:authentication )?credentials (?:are |were )?"
        r"(?:required|missing|invalid|expired|not provided)",
        r"(?:invalid|bad|missing) (?:authentication )?credentials",
        r"(?:insufficient|inadequate) (?:permissions?|privileges|scope)",
        r"(?:you are not authorized|you do not have permission|not authorized) "
        r"to (?:access|view) (?:this|the) resource",
        r"(?:令牌|token|jwt|jwt令牌)(?:已)?(?:缺失|无效|失效|过期)",
        r"(?:缺少|需要)(?:有效的)?(?:令牌|token|jwt|jwt令牌)",
    )
    ERROR_STATUS_WORDS = {"error", "fail", "failed", "failure", "denied"}
    ERROR_VALUE_KEYS = {
        "error",
        "errors",
        "exception",
        "error_message",
        "errormessage",
    }
    CODE_KEYS = {
        "code",
        "error_code",
        "errorcode",
        "err_code",
        "errcode",
        "http_status",
        "status_code",
    }
    MESSAGE_KEYS = {
        "error",
        "errors",
        "message",
        "msg",
        "detail",
        "description",
        "reason",
        "status",
    }
    # Wrapper fields do not identify a returned business resource by themselves.
    NON_RESOURCE_VALUE_KEYS = {
        "code",
        "error",
        "errors",
        "message",
        "msg",
        "status",
        "success",
        "timestamp",
        "trace_id",
        "traceid",
        "request_id",
        "requestid",
        "detail",
        "description",
        "reason",
    }
    RESPONSE_WRAPPER_KEYS = {"payload", "result", "response", "data", "error", "errors"}
    METADATA_CONTAINER_KEYS = {"meta", "metadata", "request", "query", "params", "headers", "trace"}

    # Kept for callers that introspect the old constant. Detection itself is recursive.
    SOFT_ERROR_SIGNATURES = [
        ("code", [401, 403, 404, 500, 10001, 10002, -1, "401", "403", "404", "AUTH_ERROR", "FORBIDDEN", "UNAUTHORIZED"]),
        ("status", ["error", "fail", "unauthorized", "forbidden"]),
        ("success", [False, "false", 0, "0"]),
        ("error", None),
        ("message", ["unauthorized", "forbidden", "permission denied", "not allowed", "无权访问", "权限不足", "未登录"]),
    ]

    @staticmethod
    def normalise_key(key: Any) -> str:
        return _normalised_key_text(str(key))

    @classmethod
    def _walk_fields(cls, obj: Any, path: str = "") -> Iterable[Tuple[str, str, Any]]:
        """Yield every nested mapping field, including fields inside arrays."""
        if isinstance(obj, dict):
            for raw_key, value in obj.items():
                key = cls.normalise_key(raw_key)
                field_path = f"{path}.{raw_key}" if path else str(raw_key)
                yield field_path, key, value
                if isinstance(value, (dict, list)):
                    yield from cls._walk_fields(value, field_path)
        elif isinstance(obj, list):
            for index, value in enumerate(obj):
                item_path = f"{path}[{index}]" if path else f"[{index}]"
                if isinstance(value, (dict, list)):
                    yield from cls._walk_fields(value, item_path)

    @staticmethod
    def _text_contains(text: Any, words: Iterable[str]) -> Optional[str]:
        if not isinstance(text, str):
            return None
        normalised = text.strip().lower()
        for word in words:
            if word in normalised:
                return word
        return None

    @classmethod
    def _is_auth_denial_message(cls, value: Any) -> bool:
        """Recognize a complete authentication rejection, never a substring."""
        if not isinstance(value, str):
            return False
        normalised = re.sub(r"\s+", " ", value.strip().lower()).rstrip(".!?。！？")
        if normalised in cls.AUTH_ERROR_WORDS:
            return True
        return any(re.fullmatch(pattern, normalised) for pattern in cls.AUTH_DENIAL_PATTERNS)

    @classmethod
    def _detect_nested_soft_error(cls, data: Any) -> Optional[Tuple[str, str]]:
        """Inspect response envelopes, never arbitrary records or historical logs."""
        if cls._is_auth_denial_message(data):
            return cls.RESPONSE_AUTH_DENIED, "Application authentication denial message"

        def envelope_fields(value: Any, prefix: str = ""):
            if isinstance(value, dict):
                for raw_key, child in value.items():
                    key = cls.normalise_key(raw_key)
                    path = f"{prefix}.{raw_key}" if prefix else str(raw_key)
                    yield path, key, child
                    if key in cls.RESPONSE_WRAPPER_KEYS and isinstance(child, (dict, list)):
                        yield from envelope_fields(child, path)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    if isinstance(child, dict):
                        yield from envelope_fields(child, f"{prefix}[{index}]")

        fields = list(envelope_fields(data))

        # Authentication evidence wins over a generic error wrapper, even when the
        # generic field is encountered first in the JSON object.
        for path, key, value in fields:
            if key in cls.CODE_KEYS and isinstance(value, (int, str)) and value in cls.AUTH_ERROR_CODES:
                return cls.RESPONSE_AUTH_DENIED, f"Application authentication error code: {path}={value}"

            if key in cls.MESSAGE_KEYS or key in cls.CODE_KEYS:
                if cls._is_auth_denial_message(value):
                    return cls.RESPONSE_AUTH_DENIED, f"Application authentication denial envelope: {path}"

        for path, key, value in fields:
            if key in cls.CODE_KEYS:
                numeric_value = None
                try:
                    numeric_value = int(value)
                except (TypeError, ValueError):
                    pass
                if numeric_value is not None and (numeric_value < 0 or numeric_value >= 400):
                    return cls.RESPONSE_APPLICATION_ERROR, f"Application error code: {path}={value}"

            if key == "success" and value in (False, 0, "0"):
                return cls.RESPONSE_APPLICATION_ERROR, f"Application failure flag: {path}={value}"
            if key == "success" and isinstance(value, str) and value.strip().lower() == "false":
                return cls.RESPONSE_APPLICATION_ERROR, f"Application failure flag: {path}={value}"

            if key == "status" and isinstance(value, str):
                if value.strip().lower() in cls.ERROR_STATUS_WORDS:
                    return cls.RESPONSE_APPLICATION_ERROR, f"Application failure status: {path}={value}"

            if key in cls.ERROR_VALUE_KEYS:
                if isinstance(value, str):
                    if value.strip() and value.strip().lower() not in {"none", "null", "false", "0"}:
                        # A server error can echo credentials or private values.
                        # Keep the field location as evidence, not its content.
                        return cls.RESPONSE_APPLICATION_ERROR, f"Application error field is not empty: {path}"
                elif value:
                    return cls.RESPONSE_APPLICATION_ERROR, f"Application error field is not empty: {path}"

        return None

    @classmethod
    def assess_response(cls, status_code: int, body_str: str) -> Dict[str, Any]:
        """Classify one response and retain parsed JSON for internal comparison."""
        try:
            status = int(status_code)
        except (TypeError, ValueError):
            return {
                "kind": cls.RESPONSE_TRANSPORT_ERROR,
                "status_code": status_code,
                "is_error": True,
                "is_auth_denial": False,
                "reason": f"Invalid transport status code: {status_code!r}",
                "data": None,
            }

        if status <= 0:
            return {
                "kind": cls.RESPONSE_TRANSPORT_ERROR,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": False,
                "reason": "No HTTP response was received (network, TLS, timeout or connection error)",
                "data": None,
            }

        # Error bodies are evidence too: keep JSON even for 401/403 so that an
        # apparent denial cannot conceal business data returned in its body.
        # Parse once; success responses reuse this result below.
        parsed: Any
        try:
            parsed = strict_json_loads(body_str)
        except (TypeError, ValueError, RecursionError):
            parsed = _JSON_PARSE_FAILED
        error_data = None if parsed is _JSON_PARSE_FAILED else parsed

        if status in (401, 403):
            return {
                "kind": cls.RESPONSE_AUTH_DENIED,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": True,
                "reason": f"HTTP authentication denial status {status}",
                "data": error_data,
            }

        if 400 <= status <= 499:
            return {
                "kind": cls.RESPONSE_HTTP_CLIENT_ERROR,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": False,
                "reason": f"HTTP client error status {status}; it does not prove that access control was enforced",
                "data": error_data,
            }

        if 500 <= status <= 599:
            return {
                "kind": cls.RESPONSE_SERVER_ERROR,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": False,
                "reason": f"HTTP server error status {status}",
                "data": error_data,
            }

        if status < 200 or status >= 300:
            return {
                "kind": cls.RESPONSE_HTTP_ERROR,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": False,
                "reason": f"Non-success HTTP status {status}",
                "data": error_data,
            }

        if body_str is None or not str(body_str).strip():
            return {
                "kind": cls.RESPONSE_EMPTY,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": False,
                "reason": "Successful response has an empty body; no data baseline can be established",
                "data": None,
            }

        data = parsed
        if data is _JSON_PARSE_FAILED:
            return {
                "kind": cls.RESPONSE_INVALID,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": False,
                "reason": "Successful response body is not valid JSON",
                "data": None,
            }

        if data is None or data == {} or data == []:
            return {
                "kind": cls.RESPONSE_EMPTY,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": False,
                "reason": "JSON response has no data to compare",
                "data": data,
            }

        nested_error = cls._detect_nested_soft_error(data)
        if nested_error:
            kind, reason = nested_error
            return {
                "kind": kind,
                "status_code": status,
                "is_error": True,
                "is_auth_denial": kind == cls.RESPONSE_AUTH_DENIED,
                "reason": reason,
                "data": data,
            }

        return {
            "kind": cls.RESPONSE_VALID,
            "status_code": status,
            "is_error": False,
            "is_auth_denial": False,
            "reason": "Valid JSON application response",
            "data": data,
        }

    @classmethod
    def classify_response(cls, status_code: int, body_str: str) -> Dict[str, Any]:
        """Return a serialisable response classification without echoing response data."""
        assessment = cls.assess_response(status_code, body_str)
        return {key: value for key, value in assessment.items() if key != "data"}

    @classmethod
    def is_soft_error(cls, status_code: int, body_str: str) -> Tuple[bool, str]:
        """Backward-compatible error predicate used by the existing auditor."""
        assessment = cls.assess_response(status_code, body_str)
        return assessment["is_error"], assessment["reason"] if assessment["is_error"] else ""

    @staticmethod
    def _tracing_scalar_is_clean(key: str, value: Any) -> bool:
        """Permit bounded tracing syntax, not arbitrary text under a trace key."""
        if type(value) in (int, float):
            return True  # Strict JSON parsing has already rejected non-finite numbers.
        if not isinstance(value, str) or len(value) > 128:
            return False
        if key == "timestamp":
            return any(re.fullmatch(pattern, value) for pattern in (
                r"[+-]?\d+(?:\.\d+)?",
                r"\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}"
                r"(?:\.\d{1,9})?(?:[Zz]|[+-]\d{2}:?\d{2})?)?",
                r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} "
                r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
                r"\d{4} \d{2}:\d{2}:\d{2} (?:GMT|UTC)",
            ))
        # UUIDs, hexadecimal trace IDs and ordinary bounded request IDs. A
        # credential, JSON document, assignment or prose is not a tracing ID.
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value))

    @classmethod
    def denial_body_is_clean(cls, assessment: Dict[str, Any], body: str) -> bool:
        """Accept only a recognizable rejection envelope without business content.

        Unknown or unparseable content cannot prove that a denial withheld data.
        Metadata allowance is deliberately limited to scalar tracing fields.
        """
        if body is None or not str(body).strip():
            return True
        data = assessment["data"]
        if data is None:
            return cls._is_auth_denial_message(body)
        if isinstance(data, str):
            return cls._is_auth_denial_message(data)

        def clean(value: Any, key: str = "") -> bool:
            known_keys = (
                cls.RESPONSE_WRAPPER_KEYS | cls.CODE_KEYS | cls.MESSAGE_KEYS
                | cls.ERROR_VALUE_KEYS | {"success", "meta", "metadata", "timestamp",
                                          "request_id", "requestid", "trace_id", "traceid"}
            )
            if key and key not in known_keys:
                return False
            if isinstance(value, dict):
                if key and key not in cls.RESPONSE_WRAPPER_KEYS | {"meta", "metadata"}:
                    return False
                if key in {"meta", "metadata"}:
                    return all(
                        cls.normalise_key(raw) in {"timestamp", "request_id", "requestid", "trace_id", "traceid"}
                        and clean(child, cls.normalise_key(raw))
                        for raw, child in value.items()
                    )
                return all(clean(child, cls.normalise_key(raw)) for raw, child in value.items())
            if isinstance(value, list):
                return key in cls.RESPONSE_WRAPPER_KEYS and all(clean(child) for child in value)
            if value is None or value == "":
                return True
            if key in {"timestamp", "request_id", "requestid", "trace_id", "traceid"}:
                return cls._tracing_scalar_is_clean(key, value)
            if key in cls.CODE_KEYS:
                return isinstance(value, (int, str)) and value in cls.AUTH_ERROR_CODES
            if key == "success":
                return value in (False, 0, "0", "false")
            if key in cls.MESSAGE_KEYS or key in cls.ERROR_VALUE_KEYS:
                return cls._is_auth_denial_message(value) or (
                    isinstance(value, str) and value.strip().lower() in cls.ERROR_STATUS_WORDS
                )
            return False

        return clean(data)

    @classmethod
    def _extract_keys(cls, obj: Any) -> Set[str]:
        """Recursively extract structural paths from objects and object arrays."""
        keys: Set[str] = set()
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_text = str(key)
                keys.add(key_text)
                if isinstance(value, dict):
                    keys.update(f"{key_text}.{sub}" for sub in cls._extract_keys(value))
                elif isinstance(value, list):
                    keys.update(f"{key_text}[].{sub}" for sub in cls._extract_keys(value))
        elif isinstance(obj, list):
            # A few records are enough for a schema-shape hint. Structure never
            # becomes confirmation evidence on its own.
            for item in obj[:3]:
                if isinstance(item, (dict, list)):
                    keys.update(cls._extract_keys(item))
        return keys

    @classmethod
    def calculate_jaccard_similarity(cls, json_str_a: str, json_str_b: str) -> float:
        """Calculate structural-key Jaccard similarity for compatibility/reporting."""
        try:
            a = strict_json_loads(json_str_a)
            b = strict_json_loads(json_str_b)
        except (TypeError, ValueError, RecursionError):
            return 0.0
        return cls._structure_similarity(a, b)

    @classmethod
    def _structure_similarity(cls, a: Any, b: Any) -> float:
        """Jaccard similarity of already parsed documents' structural keys."""
        try:
            keys_a = cls._extract_keys(a)
            keys_b = cls._extract_keys(b)

            if not keys_a and not keys_b:
                return 1.0 if a == b else 0.0

            union = keys_a.union(keys_b)
            return len(keys_a.intersection(keys_b)) / len(union) if union else 0.0
        except (TypeError, ValueError, RecursionError):
            return 0.0

    @classmethod
    def _meaningful_record_value(cls, obj: Any) -> Any:
        """Build a typed business value without encoding nested arrays twice."""
        def canonical_key(value: Any) -> str:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if isinstance(obj, dict):
            fields = []
            for raw_key, value in obj.items():
                key = cls.normalise_key(raw_key)
                if cls.is_request_metadata_key(key):
                    continue
                if not isinstance(value, (dict, list)) and (
                    key in cls.NON_RESOURCE_VALUE_KEYS or cls._looks_like_identifier_key(key)
                ):
                    continue
                meaningful = cls._meaningful_record_value(value)
                if meaningful is not None:
                    fields.append((key, meaningful))
            return {"object": sorted(fields, key=canonical_key)} if fields else None
        if isinstance(obj, list):
            records = [cls._meaningful_record_value(value) for value in obj]
            records = [record for record in records if record is not None]
            return {"array": sorted(records, key=canonical_key)} if records else None
        return obj

    @classmethod
    def _meaningful_leaf_pairs(cls, obj: Any, path: str = "") -> Set[Tuple[str, str]]:
        """Keep object fields and unordered array records associated.

        An array is one comparison unit: its canonical value contains every
        record's meaningful fields, including repeated records. Flattening
        records to ``items[].field`` sets loses which values occurred together
        and can mistake unrelated records for an exact business-data match.
        """
        pairs: Set[Tuple[str, str]] = set()
        if isinstance(obj, dict):
            for raw_key, value in obj.items():
                key = cls.normalise_key(raw_key)
                child_path = f"{path}.{key}" if path else key
                if cls.is_request_metadata_key(key):
                    continue
                if isinstance(value, (dict, list)):
                    pairs.update(cls._meaningful_leaf_pairs(value, child_path))
                elif (
                    key not in cls.NON_RESOURCE_VALUE_KEYS
                    and not cls._looks_like_identifier_key(key)
                    and value is not None
                ):
                    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                    pairs.add((child_path, canonical))
        elif isinstance(obj, list):
            records = cls._meaningful_record_value(obj)
            if records is not None:
                canonical = json.dumps(records, ensure_ascii=False, separators=(",", ":"))
                pairs.add((f"{path}[]" if path else "[]", canonical))
        elif obj is not None:
            canonical = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            pairs.add((path or "$", canonical))
        return pairs

    @classmethod
    def is_request_metadata_key(cls, key: str) -> bool:
        return (
            key in cls.METADATA_CONTAINER_KEYS
            or key.startswith(("requested_", "request_", "trace_", "correlation_"))
            or key in {"requested", "requestid", "traceid", "correlationid"}
        )

    @classmethod
    def _normalise_resource_path(cls, path: str) -> str:
        return ".".join(
            cls.normalise_key(part) for part in re.sub(r"\[\d+\]", "[]", path).split(".")
        )

    @classmethod
    def _resource_identifier_pairs(
        cls, obj: Any, resource_id_paths: Optional[Set[str]] = None, path: str = ""
    ) -> Set[Tuple[str, str]]:
        """Only operator-approved business paths can establish resource identity."""
        if not resource_id_paths:
            return set()
        identifiers: Set[Tuple[str, str]] = set()
        if isinstance(obj, dict):
            for raw_key, value in obj.items():
                key = cls.normalise_key(raw_key)
                child_path = f"{path}.{key}" if path else key
                if cls.is_request_metadata_key(key):
                    continue
                if isinstance(value, (dict, list)):
                    identifiers.update(cls._resource_identifier_pairs(value, resource_id_paths, child_path))
                elif value is not None and child_path in resource_id_paths:
                    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                    identifiers.add((child_path, canonical))
        elif isinstance(obj, list):
            for value in obj:
                if isinstance(value, (dict, list)):
                    identifiers.update(cls._resource_identifier_pairs(
                        value, resource_id_paths, f"{path}[]" if path else "[]"
                    ))
        return identifiers

    @staticmethod
    def _looks_like_identifier_key(key: str) -> bool:
        return (
            key in {"id", "uuid", "identifier"}
            or key.endswith("_id")
            or key.endswith("_uuid")
            or key.endswith("_identifier")
        )

    @staticmethod
    def _set_similarity(left: Set[Any], right: Set[Any]) -> float:
        union = left.union(right)
        if not union:
            return 0.0
        return len(left.intersection(right)) / len(union)

    @classmethod
    def calculate_value_similarity(cls, json_str_a: str, json_str_b: str) -> float:
        """Calculate Jaccard similarity of concrete leaf path/value pairs."""
        try:
            left = cls._meaningful_leaf_pairs(strict_json_loads(json_str_a))
            right = cls._meaningful_leaf_pairs(strict_json_loads(json_str_b))
        except (TypeError, ValueError, RecursionError):
            return 0.0
        return cls._set_similarity(left, right)

    @staticmethod
    def assessment_evidence(assessment: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "kind": assessment["kind"],
            "status_code": assessment["status_code"],
            "is_auth_denial": assessment["is_auth_denial"],
            "reason": assessment["reason"],
        }

    @classmethod
    def _build_evidence(
        cls,
        owner: Dict[str, Any],
        visitor: Dict[str, Any],
        anonymous: Dict[str, Any],
        visitor_self: Optional[Dict[str, Any]],
        resource_id_paths: Optional[Set[str]] = None,
        *,
        owner_values: Optional[Set[Tuple[str, str]]] = None,
        visitor_values: Optional[Set[Tuple[str, str]]] = None,
    ) -> Dict[str, Any]:
        # Callers may pass already computed value pairs; walking a large
        # response is the dominant cost of a comparison.
        if owner_values is None:
            owner_values = cls._meaningful_leaf_pairs(owner["data"])
        if visitor_values is None:
            visitor_values = cls._meaningful_leaf_pairs(visitor["data"])
        shared_values = owner_values.intersection(visitor_values)

        owner_ids = cls._resource_identifier_pairs(owner["data"], resource_id_paths)
        visitor_ids = cls._resource_identifier_pairs(visitor["data"], resource_id_paths)
        shared_ids = owner_ids.intersection(visitor_ids)

        exact_match = bool(owner_values and owner_values == visitor_values)
        structure_similarity = 0.0
        if owner["data"] is not None and visitor["data"] is not None:
            # Same strictly parsed documents calculate_jaccard_similarity would decode.
            structure_similarity = cls._structure_similarity(owner["data"], visitor["data"])

        visitor_self_exact_match = False
        visitor_self_value_similarity = 0.0
        visitor_self_shared_ids: Set[Tuple[str, str]] = set()
        self_values: Set[Tuple[str, str]] = set()
        self_ids: Set[Tuple[str, str]] = set()
        if visitor_self and visitor_self["kind"] == cls.RESPONSE_VALID:
            self_values = cls._meaningful_leaf_pairs(visitor_self["data"])
            self_ids = cls._resource_identifier_pairs(visitor_self["data"], resource_id_paths)
            visitor_self_exact_match = bool(visitor_values and self_values == visitor_values)
            if visitor_ids and self_ids and visitor_ids != self_ids:
                visitor_self_exact_match = False
            visitor_self_value_similarity = cls._set_similarity(visitor_values, self_values)
            visitor_self_shared_ids = visitor_ids.intersection(self_ids)
        owner_only_shared_ids = shared_ids.difference(visitor_self_shared_ids)

        evidence = {
            "responses": {
                "owner": cls.assessment_evidence(owner),
                "visitor_cross": cls.assessment_evidence(visitor),
                "anonymous": cls.assessment_evidence(anonymous),
                "visitor_self": cls.assessment_evidence(visitor_self) if visitor_self else None,
            },
            "anonymous_denied": anonymous["kind"] == cls.RESPONSE_AUTH_DENIED,
            "anonymous_exact_match": False,
            "anonymous_value_similarity": 0.0,
            "structure_similarity": round(structure_similarity, 6),
            "value_similarity": round(cls._set_similarity(owner_values, visitor_values), 6),
            "exact_value_match": exact_match,
            "owner_meaningful_value_count": len(owner_values),
            "visitor_meaningful_value_count": len(visitor_values),
            "shared_value_count": len(shared_values),
            "owner_specific_shared_value_count": len(shared_values.difference(self_values)),
            "owner_specific_shared_value_paths": sorted(
                {path for path, _ in shared_values.difference(self_values)}
            ),
            "shared_resource_identifier_count": len(shared_ids),
            "shared_resource_identifier_paths": sorted({path for path, _ in shared_ids}),
            "owner_only_shared_resource_identifier_count": len(owner_only_shared_ids),
            "owner_only_shared_resource_identifier_paths": sorted(
                {path for path, _ in owner_only_shared_ids}
            ),
            "visitor_self_provided": visitor_self is not None,
            "visitor_self_exact_match": visitor_self_exact_match,
            "visitor_self_value_similarity": round(visitor_self_value_similarity, 6),
            "visitor_self_shared_resource_identifier_count": len(visitor_self_shared_ids),
            "owner_baseline_valid": owner["kind"] == cls.RESPONSE_VALID,
            "visitor_cross_baseline_valid": visitor["kind"] == cls.RESPONSE_VALID,
            "visitor_self_baseline_valid": bool(
                visitor_self and visitor_self["kind"] == cls.RESPONSE_VALID
            ),
            "owner_self_distinct": bool(
                owner["kind"] == cls.RESPONSE_VALID
                and visitor_self and visitor_self["kind"] == cls.RESPONSE_VALID
                and (owner_values != self_values or owner_ids != self_ids)
            ),
            "object_access_signals": [],
            "confirmation_signals": [],
        }
        # These candidates identify the selected Owner object; authentication
        # denial and the configured permission policy remain separate gates.
        if (
            evidence["owner_baseline_valid"] and evidence["visitor_cross_baseline_valid"]
            and evidence["visitor_self_baseline_valid"] and evidence["owner_self_distinct"]
        ):
            evidence["object_access_signals"] = cls._object_access_signals(evidence)
        return evidence

    @staticmethod
    def _object_access_signals(evidence: Dict[str, Any]) -> list:
        """Concrete object matches that survive the Visitor self comparison."""
        if evidence["visitor_self_exact_match"] or (
            evidence["owner_only_shared_resource_identifier_count"] == 0
            and evidence["visitor_self_value_similarity"] > 0
            and evidence["visitor_self_value_similarity"] >= evidence["value_similarity"]
        ):
            return []
        signals = []
        if evidence["exact_value_match"] and evidence["owner_specific_shared_value_count"] > 0:
            signals.append("exact_business_value_match")
        if evidence["owner_only_shared_resource_identifier_count"] > 0:
            signals.append("matching_resource_identifier")
        if (
            evidence["value_similarity"] >= 0.75
            and evidence["shared_value_count"] >= 2
            and evidence["owner_specific_shared_value_count"] > 0
            and evidence["value_similarity"] > evidence["visitor_self_value_similarity"] + 0.15
        ):
            signals.append("high_business_value_overlap")
        return signals

    @staticmethod
    def _result(
        verdict: str,
        confidence: float,
        reason: str,
        evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create one stable result shape for every decision branch."""
        missing = []
        if verdict in {"LOW_SUSPICION", "INCONCLUSIVE"}:
            if not evidence["owner_baseline_valid"]:
                missing.append("owner_baseline")
            if not evidence["visitor_self_baseline_valid"]:
                missing.append("visitor_self_baseline")
            elif evidence["owner_baseline_valid"] and not evidence["owner_self_distinct"]:
                missing.append("distinct_visitor_self_resource")
            if evidence["responses"]["anonymous"]["kind"] != "AUTH_DENIED":
                missing.append("anonymous_denial_baseline")
            elif evidence["anonymous_denial_body_clean"] is False:
                missing.append("clean_anonymous_denial_body")
            visitor_kind = evidence["responses"]["visitor_cross"]["kind"]
            if visitor_kind == "AUTH_DENIED":
                if evidence["visitor_denial_body_clean"] is False:
                    missing.append("clean_visitor_denial_body")
            elif not evidence["visitor_cross_baseline_valid"]:
                missing.append("visitor_cross_response")
            elif (
                evidence["owner_baseline_valid"] and evidence["visitor_self_baseline_valid"]
                and not evidence["object_access_signals"]
            ):
                missing.append("owner_resource_match")
            if (
                evidence["expected_public"] and not evidence["requires_auth"]
                and evidence["responses"]["anonymous"]["kind"] == "VALID"
            ):
                missing.append("public_response_equivalence")
        evidence["missing_evidence"] = missing
        return {
            "verdict": verdict,
            "confidence": float(confidence),
            "reason": reason,
            # Kept at the top level for existing reporting code.
            "similarity": evidence["structure_similarity"],
            "evidence": evidence,
        }

    @classmethod
    def evaluate_bola(
        cls,
        resp_owner: Tuple[int, str],
        resp_visitor: Tuple[int, str],
        resp_anon: Tuple[int, str],
        visitor_self: Optional[Tuple[int, str]] = None,
        *,
        expected_public: bool = False,
        requires_auth: bool = False,
        resource_id_paths: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate BOLA using owner, cross-visitor, anonymous and optional self baselines.

        ``visitor_self`` is the visitor identity reading its own resource. Supplying it
        helps detect APIs that ignore the requested object id and always return the
        authenticated user's object. The original three-argument call remains valid.

        PUBLIC requires explicit ``expected_public=True``, no ``requires_auth``
        requirement, and exact JSON equality across owner/visitor/anonymous.
        ``resource_id_paths`` contains trusted dot paths, e.g. ``data.user_id`` or
        ``items[].id``. No implicit *_id discovery is used for confirmation.
        Known request/trace metadata is excluded even if configured as an id path.
        """
        status_owner, body_owner = resp_owner
        status_visitor, body_visitor = resp_visitor
        status_anon, body_anon = resp_anon

        owner = cls.assess_response(status_owner, body_owner)
        visitor = cls.assess_response(status_visitor, body_visitor)
        anonymous = cls.assess_response(status_anon, body_anon)
        self_assessment = cls.assess_response(*visitor_self) if visitor_self is not None else None
        if isinstance(resource_id_paths, str):
            resource_id_paths = [resource_id_paths]
        trusted_paths = set()
        for path in resource_id_paths or ():
            if not isinstance(path, str) or not path.strip():
                raise ValueError("resource_id_paths must contain non-empty response field paths")
            trusted_paths.add(cls._normalise_resource_path(path.strip()))

        owner_values = cls._meaningful_leaf_pairs(owner["data"])
        visitor_values = cls._meaningful_leaf_pairs(visitor["data"])
        anon_values = cls._meaningful_leaf_pairs(anonymous["data"])

        evidence = cls._build_evidence(
            owner,
            visitor,
            anonymous,
            self_assessment,
            trusted_paths,
            owner_values=owner_values,
            visitor_values=visitor_values,
        )
        evidence["expected_public"] = bool(expected_public)
        evidence["requires_auth"] = bool(requires_auth)
        evidence["trusted_resource_id_paths"] = sorted(trusted_paths)
        evidence["denial_body_conflict"] = False
        evidence["visitor_denial_body_clean"] = (
            cls.denial_body_is_clean(visitor, body_visitor) if visitor["is_auth_denial"] else None
        )
        evidence["anonymous_denial_body_clean"] = (
            cls.denial_body_is_clean(anonymous, body_anon) if anonymous["is_auth_denial"] else None
        )
        evidence["anonymous_authentication_violation"] = bool(
            requires_auth and anonymous["kind"] == cls.RESPONSE_VALID
        )

        evidence["anonymous_owner_value_match"] = bool(
            owner["kind"] == cls.RESPONSE_VALID and anonymous["kind"] == cls.RESPONSE_VALID
            and owner_values and owner_values == anon_values
        )
        evidence["anonymous_owner_identifier_match"] = bool(
            owner["kind"] == cls.RESPONSE_VALID and anonymous["kind"] == cls.RESPONSE_VALID
            and cls._resource_identifier_pairs(owner["data"], trusted_paths).intersection(
                cls._resource_identifier_pairs(anonymous["data"], trusted_paths)
            )
        )
        evidence["anonymous_exact_match"] = bool(
            anonymous["data"] is not None and json_values_equal(anonymous["data"], visitor["data"])
        )
        evidence["anonymous_value_similarity"] = round(cls._set_similarity(anon_values, visitor_values), 6)
        private_increment = owner_values.intersection(visitor_values).difference(anon_values)
        evidence["owner_shared_nonpublic_value_paths"] = sorted({path for path, _ in private_increment})

        if owner["kind"] != cls.RESPONSE_VALID:
            return cls._result(
                "INCONCLUSIVE",
                0.0,
                f"Owner baseline is not valid: {owner['reason']}",
                evidence,
            )

        if requires_auth and anonymous["kind"] == cls.RESPONSE_VALID:
            return cls._result(
                "LOW_SUSPICION", 0.9,
                "The endpoint requires authentication, but the Anonymous request returned successful JSON; "
                "this access cannot be treated as intentionally public",
                evidence,
            )

        if visitor["kind"] == cls.RESPONSE_AUTH_DENIED:
            if not evidence["visitor_denial_body_clean"]:
                evidence["denial_body_conflict"] = True
                return cls._result(
                    "LOW_SUSPICION" if visitor_values else "INCONCLUSIVE",
                    0.85 if visitor_values else 0.0,
                    "The Visitor response declares an authentication denial, but its body contains business data "
                    "or unknown content; access control is not proven",
                    evidence,
                )
            # A visitor rejection proves only that identity's access was denied.
            # Anonymous success, redirects and non-authentication errors cannot
            # establish that the endpoint also withheld the owner's data.
            if anonymous["kind"] != cls.RESPONSE_AUTH_DENIED:
                if anonymous["kind"] == cls.RESPONSE_VALID:
                    return cls._result(
                        "LOW_SUSPICION", 0.25,
                        "The Visitor cross-resource request was denied, but the Anonymous request returned successful "
                        "JSON; without consistent denial evidence the endpoint cannot be judged secure",
                        evidence,
                    )
                return cls._result(
                    "LOW_SUSPICION" if anon_values else "INCONCLUSIVE",
                    0.8 if anon_values else 0.0,
                    "The Visitor cross-resource request was denied, but the Anonymous baseline is not an "
                    "explicit authentication denial"
                    + (" and its body contains business data" if anon_values else "")
                    + f": {anonymous['reason']}",
                    evidence,
                )
            if anonymous["kind"] == cls.RESPONSE_AUTH_DENIED and not evidence["anonymous_denial_body_clean"]:
                evidence["denial_body_conflict"] = True
                return cls._result(
                    "LOW_SUSPICION", 0.8,
                    "The Anonymous response declares an authentication denial, but its body contains business data "
                    "or unknown content; the access control result remains contradictory",
                    evidence,
                )
            if self_assessment is None:
                return cls._result(
                    "INCONCLUSIVE",
                    0.0,
                    "The Visitor cross-resource request was denied, but without a Visitor own-resource baseline "
                    "the Visitor credentials cannot be shown to be valid",
                    evidence,
                )
            if self_assessment["kind"] != cls.RESPONSE_VALID:
                return cls._result(
                    "INCONCLUSIVE",
                    0.0,
                    "The Visitor cross-resource request was denied, but the Visitor own-resource baseline is not "
                    f"valid: {self_assessment['reason']}",
                    evidence,
                )
            return cls._result(
                "SECURE_ENFORCED",
                1.0 if int(status_visitor) in (401, 403) else 0.95,
                "Both the Visitor cross-resource request and the Anonymous request were explicitly denied "
                f"without business data in the body: {visitor['reason']}",
                evidence,
            )

        if visitor["kind"] != cls.RESPONSE_VALID:
            # A 4xx/5xx body can disclose the selected Owner object even though
            # it cannot establish a successful-access baseline. Retain strong
            # matches as leads only; never promote error responses to CONFIRMED.
            if (
                visitor["kind"] in {cls.RESPONSE_HTTP_CLIENT_ERROR, cls.RESPONSE_SERVER_ERROR}
                and evidence["visitor_self_baseline_valid"] and evidence["owner_self_distinct"]
                and anonymous["kind"] == cls.RESPONSE_AUTH_DENIED
                and evidence["anonymous_denial_body_clean"]
                and cls._object_access_signals(evidence)
            ):
                return cls._result(
                    "LOW_SUSPICION", 0.8,
                    "The Visitor error response body matches Owner-specific business values or a trusted resource "
                    "identifier; it may disclose resource data and needs manual review",
                    evidence,
                )
            return cls._result(
                "INCONCLUSIVE",
                0.0,
                f"The Visitor cross-resource request did not receive a decidable response: {visitor['reason']}",
                evidence,
            )

        if anonymous["kind"] == cls.RESPONSE_VALID:
            if (
                expected_public and not requires_auth and visitor_values
                and json_values_equal(anonymous["data"], visitor["data"])
                and json_values_equal(visitor["data"], owner["data"])
            ):
                return cls._result(
                    "PUBLIC_ENDPOINT",
                    1.0,
                    "The endpoint is explicitly configured as public, and the complete Owner, Visitor and Anonymous "
                    "JSON responses are identical",
                    evidence,
                )
            if private_increment:
                return cls._result(
                    "LOW_SUSPICION", 0.8,
                    "The Visitor received Owner fields or values that the Anonymous response lacks; a public "
                    "summary cannot rule out private data exposure",
                    evidence,
                )
            return cls._result(
                "LOW_SUSPICION",
                0.25,
                "Anonymous access was observed, but without an explicit public policy or complete data "
                "equivalence the endpoint cannot be judged public",
                evidence,
            )

        if anonymous["kind"] != cls.RESPONSE_AUTH_DENIED:
            return cls._result(
                "INCONCLUSIVE",
                0.0,
                f"The Anonymous baseline is not an explicit authentication denial: {anonymous['reason']}",
                evidence,
            )

        if not evidence["anonymous_denial_body_clean"]:
            evidence["denial_body_conflict"] = True
            return cls._result(
                "LOW_SUSPICION", 0.8,
                "The Anonymous response declares a denial, but its body contains business data or unknown "
                "content, so it cannot serve as a non-disclosing denial baseline",
                evidence,
            )

        if self_assessment is None:
            return cls._result(
                "INCONCLUSIVE",
                0.0,
                "A Visitor own-resource baseline distinct from the Owner resource is missing; the API may "
                "return the caller's own data regardless of the requested id",
                evidence,
            )
        if self_assessment["kind"] != cls.RESPONSE_VALID:
            return cls._result(
                "INCONCLUSIVE",
                0.0,
                f"The Visitor own-resource baseline is not valid: {self_assessment['reason']}",
                evidence,
            )

        # Confirmation requires concrete values or a trusted object identifier. Structural
        # key similarity remains a diagnostic metric and never contributes a signal.
        evidence["confirmation_signals"] = list(evidence["object_access_signals"])

        # If the cross-resource result is also exactly the visitor's own baseline,
        # the API may simply be ignoring the requested id and returning the caller's
        # own record. That is not evidence of reading the owner's object.
        if evidence["visitor_self_exact_match"] or (
            evidence["owner_only_shared_resource_identifier_count"] == 0
            and evidence["visitor_self_value_similarity"] > 0
            and evidence["visitor_self_value_similarity"] >= evidence["value_similarity"]
        ):
            evidence["confirmation_signals"] = []
            return cls._result(
                "LOW_SUSPICION",
                0.2,
                "The cross-resource response matches or is closer to the Visitor own-resource baseline; it "
                "does not prove that the Owner resource was returned",
                evidence,
            )

        if evidence["confirmation_signals"]:
            confidence = 0.99 if evidence["exact_value_match"] else 0.95
            return cls._result(
                "BOLA_CONFIRMED",
                confidence,
                "The Anonymous request was explicitly denied, while the unauthorized Visitor received concrete "
                "values or resource identifiers matching the Owner resource",
                evidence,
            )

        return cls._result(
            "LOW_SUSPICION",
            0.3,
            "The Visitor request succeeded, but only structural similarity or insufficient concrete-value "
            "evidence was found; BOLA is not confirmed",
            evidence,
        )
