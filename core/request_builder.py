"""Request construction for audit requests: identities, parameters, URLs.

RequestBuilderMixin turns an operation, the identity that sends the request and
the identity whose resource it targets into concrete headers, cookies and a
URL. It refuses, before any request, values it cannot send exactly: credentials
in ordinary parameters, header or cookie collisions, values outside their
schema. Secret values discovered on the way are published through the
auditor, which owns redaction and its lock.

The methods live on a mixin rather than a separate object because they read
the auditor's current specification, identities and parameter values, and
because tests and the hash-pinned write transaction call them by these names.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from core.config_validator import ConfigValidator
from core.evidence import _is_sensitive_key
from core.generator import SmartDataGenerator
from core.parameters import (
    ParameterSerializationError,
    normalize_parameter_value,
    serialize_cookie_parameter,
    serialize_header_parameter,
    serialize_path_parameter,
    serialize_query_parameter,
)
from core.parser import OpenAPIParser


class RequestBuilderMixin:
    """Mixed into APISentinelAuditor, which provides the attributes below."""

    parser: OpenAPIParser
    identities: Dict[str, Any]
    parameter_values: Dict[str, Any]
    target_base_url: str

    if TYPE_CHECKING:
        # Declared for type checking only: a runtime stub could shadow the
        # auditor's implementation through another base class.
        def _ensure_parser_auth(self) -> None: ...

        def _publish_secret_values(self, values: Set[str]) -> None: ...

    def _is_auth_header(self, name: str) -> bool:
        spec_headers = self._spec_auth_header_names()
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

    def _spec_auth_header_names(self) -> Set[str]:
        return {
            scheme["name"].lower()
            for scheme in self.parser.get_security_schemes().values()
            if scheme.get("in") == "header" and scheme.get("name")
        }

    def _spec_auth_cookie_names(self) -> Set[str]:
        return {
            scheme["name"].lower()
            for scheme in self.parser.get_security_schemes().values()
            if scheme.get("in") == "cookie" and scheme.get("name")
        }

    def _is_auth_cookie(self, name: str) -> bool:
        norm_name = str(name).strip().lower()
        if norm_name in self._spec_auth_cookie_names():
            return True

        for identity in self.identities.values():
            for k, v in identity.get("headers", {}).items():
                if str(k).strip().lower() == "cookie":
                    for part in str(v).split(";"):
                        if "=" in part:
                            c_name = part.split("=", 1)[0].strip().lower()
                            if c_name == norm_name:
                                return True

        normalized = norm_name.replace("-", "_")
        return any(word in normalized for word in ConfigValidator.STANDARD_AUTH_COOKIE_WORDS)

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
            for key, value in self.identity_headers(name).items():
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

    def _collect_auth_secret_values(self) -> Set[str]:
        secrets: Set[str] = set()

        def _collect_from_param(p_name: str, p_val: Any) -> None:
            is_sensitive_param = (
                self._is_auth_header(p_name)
                or self._is_auth_cookie(p_name)
                or _is_sensitive_key(p_name)
            )
            if is_sensitive_param:
                if isinstance(p_val, (str, int, float)) and str(p_val):
                    secrets.add(str(p_val))
                elif isinstance(p_val, list):
                    for item in p_val:
                        if isinstance(item, (str, int, float)) and str(item):
                            secrets.add(str(item))
                elif isinstance(p_val, dict):
                    for k, v in p_val.items():
                        if isinstance(v, (str, int, float)) and str(v):
                            secrets.add(str(v))
            elif isinstance(p_val, dict):
                for k, v in p_val.items():
                    if self._is_auth_header(k) or self._is_auth_cookie(k) or _is_sensitive_key(k):
                        if isinstance(v, (str, int, float)) and str(v):
                            secrets.add(str(v))
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int, float)) and str(item):
                                    secrets.add(str(item))

        for identity_name, identity in self.identities.items():
            for key, value in self.identity_headers(identity_name).items():
                if self._is_auth_header(key):
                    secrets.add(value)
                    if key.lower() == "authorization" and " " in value:
                        secrets.add(value.split(" ", 1)[1])
                    if key.lower() == "cookie":
                        for part in value.split(";"):
                            if "=" in part:
                                c_val = part.split("=", 1)[1].strip().strip('"')
                                if c_val:
                                    secrets.add(c_val)
            for p_name, p_val in identity.get("parameters", {}).items():
                _collect_from_param(p_name, p_val)

        for conf in self.parameter_values.values():
            if isinstance(conf, dict):
                for sub_key, sub_val in conf.items():
                    if isinstance(sub_val, dict):
                        for p_name, p_val in sub_val.items():
                            _collect_from_param(p_name, p_val)
                    else:
                        p_name, p_val = sub_key, sub_val
                        _collect_from_param(p_name, p_val)

        return secrets

    def identity_headers(self, identity_name: str) -> Dict[str, str]:
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
        self._ensure_parser_auth()
        req_headers = dict(self.identity_headers(identity_name))
        parameters = ep.get("parameters", [])
        if not isinstance(parameters, list):
            return req_headers

        swagger2 = str(ep.get("spec_version", self.parser.raw_spec.get("swagger", ""))).startswith("2.")
        configured = self.parameter_values.get(self._operation_key(ep), {})

        # Requester identity values (strictly identity-isolated)
        requester_values = dict(self._operation_parameter_values(ep, identity_name))
        if extra_values:
            requester_values.update(extra_values)

        business_headers: Dict[str, str] = {}
        emitted_headers: Set[str] = set()
        cookie_pairs: List[Tuple[str, str]] = []
        emitted_cookies: Set[str] = set()
        # Collected locally and published once: other workers iterate the
        # published set without a lock, and it is replaced atomically elsewhere.
        discovered_secrets: Set[str] = set()

        for metadata in parameters:
            if not isinstance(metadata, dict):
                continue
            location = metadata.get("in")
            name = metadata.get("name")
            if not isinstance(name, str) or not name:
                continue

            if location == "header":
                header = self._header_parameter(
                    metadata, name, identity_name, requester_values, req_headers, emitted_headers, swagger2,
                )
                if header is None:
                    continue
                hdr_name, hdr_val, val, is_auth_hdr = header
                business_headers[hdr_name] = hdr_val
                discovered_secrets.update(self._header_secret_values(name, val, hdr_val, is_auth_hdr))

            elif location == "cookie":
                cookie = self._cookie_parameter(
                    metadata, name, resource_identity, identity_name, requester_values, configured,
                    req_headers, swagger2,
                )
                if cookie is None:
                    continue
                c_name, c_val, val, is_auth_cookie = cookie
                if c_name in emitted_cookies:
                    raise ParameterSerializationError(
                        "Different cookie parameters serialize to the same name; no request was sent"
                    )
                emitted_cookies.add(c_name)
                cookie_pairs.append((c_name, c_val))
                if is_auth_cookie or _is_sensitive_key(name):
                    discovered_secrets.add(c_val)
                    if isinstance(val, (str, int, float)) and str(val):
                        discovered_secrets.add(str(val))

        # Published only once every parameter was accepted: a request that is
        # refused part-way publishes nothing.
        self._publish_secret_values(discovered_secrets)

        if cookie_pairs:
            self._merge_business_cookies(req_headers, cookie_pairs)

        req_headers.update(business_headers)
        return req_headers

    def _header_parameter(
        self,
        metadata: Dict[str, Any],
        name: str,
        identity_name: str,
        requester_values: Dict[str, Any],
        req_headers: Dict[str, str],
        emitted_headers: Set[str],
        swagger2: bool,
    ) -> Optional[Tuple[str, str, Any, bool]]:
        """Serialize one header parameter, or return None when it is not sent.

        Returns the wire name and value, the configured value and whether the
        header carries authentication. Records the header in ``emitted_headers``.
        """
        normalized_name = name.lower()
        if normalized_name in {"authorization", "accept", "content-type"}:
            # Media types and authentication have dedicated spec fields;
            # ordinary parameter declarations must not replace them.
            return None
        is_auth_hdr = self._is_auth_header(name)
        if is_auth_hdr:
            if identity_name == "anonymous":
                # Missing credentials are intentional in an anonymous
                # probe, including when the spec marks them required.
                return None
            if all(self.identity_headers(role).get(normalized_name) for role in ("owner", "visitor")):
                return None
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
        if name in requester_values:
            val = requester_values[name]
        elif is_required:
            raise ParameterSerializationError(f"Missing required header parameter '{name}'; no request was sent")
        elif "default" in metadata or (isinstance(metadata.get("schema"), dict) and "default" in metadata["schema"]):
            val = metadata.get("default", metadata.get("schema", {}).get("default"))
        else:
            return None

        if normalized_name in {
            "host", "content-length", "transfer-encoding", "connection",
            "user-agent", "accept-encoding", "te", "trailer", "upgrade",
            "proxy-connection", "keep-alive", "expect",
        }:
            raise ParameterSerializationError(
                f"Business header parameter '{name}' conflicts with transport-managed header; no request was sent"
            )
        hdr_name, hdr_val = serialize_header_parameter(metadata, val, swagger2=swagger2)
        return hdr_name, hdr_val, val, is_auth_hdr

    def _header_secret_values(self, name: str, val: Any, hdr_val: str, is_auth_hdr: bool) -> Set[str]:
        """Values of a header parameter that must be redacted from evidence."""
        secrets: Set[str] = set()
        if is_auth_hdr or _is_sensitive_key(name):
            secrets.add(hdr_val)
            if isinstance(val, (str, int, float)) and str(val):
                secrets.add(str(val))
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, (str, int, float)) and str(item):
                        secrets.add(str(item))
            elif isinstance(val, dict):
                for k, v in val.items():
                    if isinstance(v, (str, int, float)) and str(v):
                        secrets.add(str(v))
        elif isinstance(val, dict):
            for k, v in val.items():
                if self._is_auth_header(k) or self._is_auth_cookie(k) or _is_sensitive_key(k):
                    if isinstance(v, (str, int, float)) and str(v):
                        secrets.add(str(v))
        return secrets

    def _cookie_parameter(
        self,
        metadata: Dict[str, Any],
        name: str,
        resource_identity: str,
        identity_name: str,
        requester_values: Dict[str, Any],
        configured: Any,
        req_headers: Dict[str, str],
        swagger2: bool,
    ) -> Optional[Tuple[str, str, Any, bool]]:
        """Serialize one cookie parameter, or return None when it is not sent.

        Returns the cookie name and value, the configured value and whether the
        cookie carries authentication.
        """
        if swagger2:
            raise ParameterSerializationError("Swagger 2 does not support cookie parameters; no request was sent")

        is_auth_cookie = self._is_auth_cookie(name)
        is_required = metadata.get("required") is True

        if is_auth_cookie:
            if identity_name == "anonymous":
                return None  # An anonymous probe intentionally omits credentials.
            scoped_values = configured.get(identity_name, {}) if isinstance(configured, dict) else {}
            scoped_val = scoped_values.get(name) if isinstance(scoped_values, dict) else None
            scoped_val = self.identities[identity_name].get("parameters", {}).get(name, scoped_val)
            identity_cookies = dict(
                (key.strip(), value.strip())
                for part in req_headers.get("cookie", "").split(";") if "=" in part
                for key, value in [part.split("=", 1)]
            )
            if name in identity_cookies and name in requester_values:
                raise ParameterSerializationError(
                    f"Business cookie parameter '{name}' conflicts with identity authentication cookie; no request was sent"
                )
            identity_cookie = identity_cookies.get(name)
            if not identity_cookie and scoped_val is None:
                if (name in requester_values or "default" in metadata
                        or (isinstance(metadata.get("schema"), dict) and "default" in metadata["schema"])):
                    raise ParameterSerializationError(
                        f"Authentication cookie '{name}' cannot be shared across identities in common parameter values or defaults; no request was sent"
                    )
                if is_required:
                    raise ParameterSerializationError(
                        f"Missing required {identity_name} authentication cookie '{name}'; no request was sent"
                    )
                return None
            val = identity_cookie if identity_cookie else scoped_val
            if identity_name == "visitor" and resource_identity != identity_name:
                owner_scoped = configured.get(resource_identity, {}) if isinstance(configured, dict) else {}
                owner_val = owner_scoped.get(name) if isinstance(owner_scoped, dict) else None
                owner_val = self.identities[resource_identity].get("parameters", {}).get(name, owner_val)
                owner_cookie = dict(
                    (key.strip(), value.strip())
                    for part in self.identity_headers(resource_identity).get("cookie", "").split(";") if "=" in part
                    for key, value in [part.split("=", 1)]
                ).get(name)
                owner_wire = owner_cookie.strip('"') if owner_cookie is not None else (
                    serialize_cookie_parameter(metadata, owner_val)[1] if owner_val is not None else None)
                visitor_wire = identity_cookie.strip('"') if identity_cookie else serialize_cookie_parameter(metadata, val)[1]
                if owner_wire == visitor_wire:
                    raise ParameterSerializationError(
                        f"Visitor authentication cookie '{name}' cannot share value with Owner; no request was sent"
                    )
            if identity_cookie:
                return None  # Already supplied by this requester's identity.
        else:
            if name in requester_values:
                val = requester_values[name]
            elif is_required:
                raise ParameterSerializationError(f"Missing required cookie parameter '{name}'; no request was sent")
            elif "default" in metadata or (isinstance(metadata.get("schema"), dict) and "default" in metadata["schema"]):
                val = metadata.get("default", metadata.get("schema", {}).get("default"))
            else:
                return None

        c_name, c_val = serialize_cookie_parameter(metadata, val, swagger2=swagger2)
        return c_name, c_val, val, is_auth_cookie

    @staticmethod
    def _merge_business_cookies(req_headers: Dict[str, str], cookie_pairs: List[Tuple[str, str]]) -> None:
        """Append business cookies to the identity's Cookie header, refusing name clashes."""
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
                if normalized in {"authorization", "accept", "content-type"}:
                    continue  # Ignore ordinary declarations in both spec versions.
                if (self._is_auth_header(name)
                        and all(self.identity_headers(role).get(normalized) for role in ("owner", "visitor"))):
                    continue  # Authentication comes only from the actual requester.
            if location not in {"path", "query", "header", "cookie"}:
                raise ParameterSerializationError("Unsupported parameter location; no request was sent")
            if swagger2 and location == "cookie":
                raise ParameterSerializationError("Swagger 2 does not support cookie parameters; no request was sent")
            if location in {"header", "cookie"} and str(ep.get("method", "")).upper() != "GET":
                raise ParameterSerializationError(
                    "Business header/cookie parameters are supported only for GET operations; no request was sent"
                )
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
            value = (values.get(param_name) if param_name in values
                     else self._unconfigured_parameter_value(metadata, candidate_id, resource_identity, swagger2))
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
            value = (values.get(name) if name in values
                     else self._unconfigured_parameter_value(metadata, candidate_id, resource_identity, swagger2))
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

    @staticmethod
    def _unconfigured_parameter_value(
        metadata: Dict[str, Any], candidate_id: Any, identity_name: str, swagger2: bool,
    ) -> Any:
        """Value for a parameter without a configured value.

        A resource identifier takes the identity's id exactly, under the same
        canonical rules as configured parameter values. It is never normalized
        by lenient int() parsing ("007" -> 7, "1_001" -> 1001) or replaced by a
        specification example, which would test a resource the identity does
        not own. Other parameters keep their generated schema value.
        """
        if candidate_id is None or not SmartDataGenerator.is_resource_identifier(metadata):
            return SmartDataGenerator.generate_raw_value_for_param(metadata)
        name = metadata.get("name")
        schema = metadata.get("schema", SmartDataGenerator.parameter_schema(metadata) if swagger2 else {})
        value = candidate_id
        if (isinstance(schema, dict) and schema.get("type") == "string"
                and isinstance(value, int) and not isinstance(value, bool)):
            value = str(value)  # An unquoted numeric id keeps its exact digits.
        try:
            value = normalize_parameter_value(metadata, value, swagger2=swagger2)
        except ParameterSerializationError as exc:
            raise ParameterSerializationError(
                f"The {identity_name} identity id cannot be used for resource parameter '{name}': {exc}"
            ) from None
        if isinstance(value, bool) or not SmartDataGenerator.validate_schema_value(value, schema, request=False):
            raise ParameterSerializationError(
                f"The {identity_name} identity id does not satisfy the schema of resource parameter "
                f"'{name}'; configure parameter_values for this operation; no request was sent"
            )
        return value
