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
from core.identity_auth import (
    IdentityAuthError,
    SpecAuth,
    isolation_problems,
    merge_session_cookies,
    parse_cookie_header,
    problems_for,
    session_cookie_parameters,
)
from core.parameters import (
    ParameterSerializationError,
    normalize_parameter_value,
    serialize_cookie_parameter,
    serialize_header_parameter,
    serialize_path_parameter,
    serialize_query_parameter,
)
from core.parser import OpenAPIParser
from core.scan_safety import method_override_risk, read_only_body_risk


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
        return ConfigValidator.is_auth_header(
            name,
            custom_auth_names=self._custom_auth_header_names(),
            spec_auth_names=self._spec_auth_header_names(),
        )

    def _custom_auth_header_names(self) -> List[str]:
        custom_headers: List[str] = []
        for identity_name, identity in self.identities.items():
            if identity_name == "roles":
                continue  # A role map, not an identity; roles have no auth_header_names.
            extra = identity.get("auth_header_names", []) if isinstance(identity, dict) else []
            if not isinstance(extra, list) or any(not isinstance(key, str) for key in extra):
                raise ValueError("auth_header_names must be a list of header names")
            custom_headers.extend(extra)
        return custom_headers

    def _spec_auth(self) -> SpecAuth:
        """The credentials the current specification declares, recomputed when the parser changes."""
        cached = getattr(self, "_spec_auth_cache", None)
        if cached is not None and cached[0] is self.parser:
            return cached[1]
        spec = SpecAuth.from_schemes(self.parser.get_security_schemes())
        self._spec_auth_cache = (self.parser, spec)
        return spec

    def _spec_auth_header_names(self) -> Set[str]:
        return {
            scheme["name"].lower()
            for scheme in self.parser.get_security_schemes().values()
            if scheme.get("in") == "header" and scheme.get("name")
        }

    def _is_auth_query_parameter(self, name: str) -> bool:
        """Whether a query parameter carries credentials: an apiKey scheme's name, or access_token."""
        lowered = name.lower()
        return lowered in ConfigValidator.STANDARD_AUTH_QUERY_PARAMETERS or any(
            scheme.get("in") == "query" and isinstance(scheme.get("name"), str)
            and scheme["name"].lower() == lowered
            for scheme in self.parser.get_security_schemes().values()
        )

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

        for identity_name, identity in self.identities.items():
            entries = (list(identity.values()) if identity_name == "roles" and isinstance(identity, dict)
                       else [identity])
            cookie_headers = [(k, v) for item in entries if isinstance(item, dict)
                              and isinstance(item.get("headers", {}), dict) for k, v in item.get("headers", {}).items()]
            for k, v in cookie_headers:
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
            if name == "roles":
                for role_name, role in identity.items():
                    if not isinstance(role, dict) or not isinstance(role.get("headers", {}), dict):
                        raise ValueError(f"role '{role_name}' must be an object with object headers")
                continue
            if not isinstance(identity.get("headers", {}), dict):
                raise ValueError(f"identity '{name}' headers must be an object")
        self._validate_read_only_identity_material()
        for name in ("owner", "visitor", "anonymous"):
            self._identity_wire_headers(name)  # Line breaks and duplicate headers are refused here.
        problems = self._identity_isolation_problems()
        if problems:
            raise IdentityAuthError("; ".join(problem.message for problem in problems))

    def _identity_isolation_problems(self) -> List[Any]:
        """The configuration validation rules for identity credentials (core.identity_auth)."""
        spec = self._spec_auth()
        custom = self._custom_auth_header_names()

        def is_auth_header(name: str) -> bool:
            return ConfigValidator.is_auth_header(name, custom_auth_names=custom, spec_auth_names=spec.header_names)

        return isolation_problems(self.identities, spec, is_auth_header, custom)

    def _validate_read_only_identity_material(self) -> None:
        """Apply the read-only rules of configuration validation to identities given in Python.

        The CLI validates the configuration first; an auditor built directly
        from Python did not, so these headers and bodies were sent. Identity
        headers ride on every request, GET included, and a role body replaces
        the Owner body on read-only POST role probes. The rules are those of
        core.scan_safety; values are never repeated in the error. The
        transport applies the same rules again to each request it sends.
        """
        for name, identity in self.identities.items():
            entries = list(identity.items()) if name == "roles" else [(None, identity)]
            for role_name, entry in entries:
                label = f"role '{role_name}'" if role_name is not None else f"identity '{name}'"
                headers = entry.get("headers") or {}
                if any(method_override_risk(str(key), str(value)) for key, value in headers.items()):
                    raise ValueError(f"{label} has a header that overrides the HTTP method to one that can change "
                                     "state; identity headers are sent with every request")
                body = entry.get("body") if role_name is not None else None
                risk = read_only_body_risk(body) if body is not None else None
                if risk:
                    raise ValueError(f"{label} has a request body that asks for a write; role bodies are sent "
                                     f"only to read-only POST operations ({risk['safety_reason']})")

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
            if identity_name == "roles" and isinstance(identity, dict):
                for role_name, role_data in identity.items():
                    if isinstance(role_data, dict):
                        for key, value in self.identity_headers(role_name).items():
                            # Roles cannot declare auth_header_names: every role
                            # header is identity material and is redacted.
                            if value:
                                secrets.add(value)
                                if key.lower() == "authorization" and " " in value:
                                    secrets.add(value.split(" ", 1)[1])
                                if key.lower() == "cookie":
                                    for part in value.split(";"):
                                        if "=" in part:
                                            c_val = part.split("=", 1)[1].strip().strip('"')
                                            if c_val:
                                                secrets.add(c_val)
                        for p_name, p_val in role_data.get("parameters", {}).items():
                            _collect_from_param(p_name, p_val)
                continue
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

    def _identity_entry(self, identity_name: str) -> Dict[str, Any]:
        """A built-in identity or a role of identities.roles; KeyError for any other name.

        "roles" itself, the map of roles, is no identity and has no credentials:
        callers that walk identities (report templates) get no headers for it.
        """
        if identity_name == "roles" and "roles" in self.identities:
            return {}
        if identity_name in self.identities:
            return self.identities[identity_name]
        roles = self.identities.get("roles")
        if isinstance(roles, dict) and identity_name in roles:
            return roles[identity_name]
        raise KeyError(f"Unknown identity: {identity_name}")

    def identity_headers(self, identity_name: str) -> Dict[str, str]:
        """The headers every request of this identity carries, session cookies included.

        The identity rules of configuration validation are applied first, to
        the identities as they are now: material changed after construction
        that would let this identity act as another, send credentials as
        Anonymous, or be denied for a missing credential stops its requests
        before any is built (IdentityAuthError, a ParameterSerializationError).
        """
        headers = self._identity_wire_headers(identity_name)
        blocking = problems_for(self._identity_isolation_problems(), identity_name)
        if blocking:
            raise IdentityAuthError(blocking[0].message + "; no request was sent")
        return headers

    def _identity_wire_headers(self, identity_name: str) -> Dict[str, str]:
        identity = self._identity_entry(identity_name)
        headers: Dict[str, str] = {}
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
        # Session cookies named by an apiKey cookie scheme ride on every request, like the Cookie header.
        return merge_session_cookies(headers, identity, self._spec_auth())

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
        identity_obj = (
            self.identities.get(identity_name)
            if identity_name in self.identities
            else (self.identities.get("roles", {}).get(identity_name)
                  if isinstance(self.identities.get("roles"), dict) else None)
        )
        identity_values = identity_obj.get("parameters", {}) if isinstance(identity_obj, dict) else {}
        if isinstance(identity_values, dict):
            values.update(identity_values)
        return values

    @staticmethod
    def _operation_value_names(configured: Any, identity_name: str) -> Set[str]:
        """Names given a value for this operation in parameter_values (common, this identity, or flat)."""
        if not isinstance(configured, dict):
            return set()
        names = {key for key in configured if key not in {"common", "owner", "visitor", "anonymous"}}
        for scope in ("common", identity_name):
            if isinstance(configured.get(scope), dict):
                names.update(configured[scope])
        return names

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
        explicit_values = self._operation_value_names(configured, identity_name) | set(extra_values or {})

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
                    req_headers, swagger2, explicit_values,
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
            configured = [bool(self.identity_headers(role).get(normalized_name)) for role in ("owner", "visitor")]
            if all(configured):
                if not req_headers.get(normalized_name):
                    # A role probe without it could be refused as unauthenticated, not as unauthorized.
                    raise ParameterSerializationError(
                        f"Authentication header '{name}' is configured for owner and visitor but not for role "
                        f"'{identity_name}'; configure it under identities.roles.{identity_name}.headers; "
                        "no request was sent"
                    )
                return None  # Sent from each requester's own identity headers.
            if name in requester_values:
                raise ParameterSerializationError(
                    f"Authentication header '{name}' cannot be supplied via parameter values; no request was sent"
                )
            if any(configured):
                # A visitor missing a credential the owner sends could be
                # refused as unauthenticated, not as unauthorized.
                raise ParameterSerializationError(
                    f"Authentication header '{name}' is configured for only one of owner and visitor; configure "
                    "it for both under identities.*.headers; no request was sent"
                )
            if metadata.get("required") is True:
                raise ParameterSerializationError(
                    f"Missing required authentication header '{name}'; configure it for owner and visitor under "
                    "identities.*.headers; no request was sent"
                )
            return None  # Optional and configured for neither identity: not sent.

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
        explicit_values: Optional[Set[str]] = None,
    ) -> Optional[Tuple[str, str, Any, bool]]:
        """Serialize one cookie parameter, or return None when it is not sent.

        Returns the cookie name and value, the configured value and whether the
        cookie carries authentication. ``explicit_values`` names the values set
        for this operation (parameter_values and readback values), as opposed to
        the requester's identity parameters.
        """
        explicit_values = explicit_values if explicit_values is not None else set(requester_values)
        if swagger2:
            raise ParameterSerializationError("Swagger 2 does not support cookie parameters; no request was sent")

        is_auth_cookie = self._is_auth_cookie(name)
        is_required = metadata.get("required") is True

        if is_auth_cookie:
            if identity_name == "anonymous":
                return None  # An anonymous probe intentionally omits credentials.
            identity = self._identity_entry(identity_name)
            identity_parameters = identity.get("parameters", {}) if isinstance(identity.get("parameters"), dict) else {}
            scoped_values = configured.get(identity_name, {}) if isinstance(configured, dict) else {}
            scoped_val = scoped_values.get(name) if isinstance(scoped_values, dict) else None
            scoped_val = identity_parameters.get(name, scoped_val)
            identity_cookies = dict(parse_cookie_header(req_headers.get("cookie", "")))
            # A session cookie parameter is already part of the identity's Cookie header.
            sessions = {key for _, key, _ in session_cookie_parameters(identity, self._spec_auth())}
            supplied = (name in explicit_values
                        or (name in identity_parameters and name not in sessions))
            if name in identity_cookies and supplied:
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
                owner_val = self._identity_entry(resource_identity).get("parameters", {}).get(name, owner_val)
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
            if location == "query" and isinstance(name, str) and self._is_auth_query_parameter(name):
                # One URL, built from the resource owner's values, is sent by
                # several identities: the visitor and anonymous would send the
                # owner's credential and appear authorized.
                raise ParameterSerializationError(
                    f"Query parameter '{name}' carries authentication; each URL is built from the resource "
                    "owner's parameter values and sent by every identity, so the visitor and anonymous requests "
                    "would carry the owner's credential. API keys in the query string are not supported; "
                    "no request was sent"
                )
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
        ident_entry = (
            self.identities.get(resource_identity)
            if resource_identity in self.identities
            else (self.identities.get("roles", {}).get(resource_identity)
                  if isinstance(self.identities.get("roles"), dict) else None)
        )
        candidate_id = ident_entry.get("id") if isinstance(ident_entry, dict) else None
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
            schema = metadata.get("schema")
            if name in values:
                value = values[name]
            elif metadata.get("required") is True or (
                    candidate_id is not None and SmartDataGenerator.is_resource_identifier(metadata)):
                value = self._unconfigured_parameter_value(metadata, candidate_id, resource_identity, swagger2)
            elif "default" in metadata or (isinstance(schema, dict) and "default" in schema):
                value = metadata["default"] if "default" in metadata else schema["default"]
            else:
                # An invented value (sample text, the first enum member, an
                # example) could filter out the resource or change behavior.
                continue
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
        not own. Other parameters keep their generated schema value; _build_url
        calls this only for required ones and resource identifiers.
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
