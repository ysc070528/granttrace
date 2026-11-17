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

import math
import re
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple

from core.config_validator import ConfigValidator
from core.evidence import (
    is_auth_credential_key,
    is_credential_parameter,
    is_resource_identifier_key,
    is_sensitive_key,
)
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
        spec_headers = self._spec_auth_header_names()
        custom_headers = []
        for identity_name, identity in self.identities.items():
            if identity_name == "roles":
                continue  # A role map, not an identity; roles have no auth_header_names.
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
        """Collect static authentication credentials from configuration and security schemes.

        Business PII fields (such as ``name``, ``email`` or ``ssn``) are excluded so
        they never masquerade as credentials in ``comparison_context``.
        """
        return self._collect_config_secrets(include_business_pii=False)

    def _collect_sensitive_config_values(self) -> Set[str]:
        """Collect all configured credentials and sensitive PII for output redaction only."""
        return self._collect_config_secrets(include_business_pii=True)

    def _collect_config_secrets(self, *, include_business_pii: bool) -> Set[str]:
        secrets: Set[str] = set()

        def add_scalar(raw: Any, *, is_cookie: bool = False) -> None:
            if raw is None or isinstance(raw, bool):
                return
            if isinstance(raw, float) and not math.isfinite(raw):
                return
            if not isinstance(raw, (str, int, float)):
                return
            text = str(raw)
            if not text:
                return
            secrets.add(text)
            scheme_match = re.match(r"(?i)^(?:bearer|basic|token)\s+(.+)$", text.strip())
            if scheme_match and scheme_match.group(1).strip():
                secrets.add(scheme_match.group(1).strip())
            if is_cookie:
                for part in text.split(";"):
                    if "=" in part:
                        c_val = part.split("=", 1)[1].strip().strip('"')
                        if c_val:
                            secrets.add(c_val)

        def collect_all_scalars(node: Any, depth: int, seen: Set[int], *, is_cookie: bool = False) -> None:
            if depth > 20:
                return
            if isinstance(node, (dict, list, tuple)):
                obj_id = id(node)
                if obj_id in seen:
                    return
                next_seen = seen | {obj_id}
                items = node.values() if isinstance(node, dict) else node
                for child in items:
                    collect_all_scalars(child, depth + 1, next_seen, is_cookie=is_cookie)
            else:
                add_scalar(node, is_cookie=is_cookie)

        def walk_structured(
            node: Any,
            matcher: Callable[[str], bool],
            depth: int = 0,
            seen: Optional[Set[int]] = None,
        ) -> None:
            if depth > 20:
                return
            active_seen = set() if seen is None else seen
            if isinstance(node, dict):
                obj_id = id(node)
                if obj_id in active_seen:
                    return
                next_seen = active_seen | {obj_id}
                for raw_key, child in node.items():
                    key_str = str(raw_key)
                    if matcher(key_str):
                        collect_all_scalars(
                            child,
                            depth + 1,
                            next_seen,
                            is_cookie=key_str.strip().lower() == "cookie" or self._is_auth_cookie(key_str),
                        )
                    elif isinstance(child, (dict, list, tuple)):
                        walk_structured(child, matcher, depth + 1, next_seen)
            elif isinstance(node, (list, tuple)):
                obj_id = id(node)
                if obj_id in active_seen:
                    return
                next_seen = active_seen | {obj_id}
                for child in node:
                    if isinstance(child, (dict, list, tuple)):
                        walk_structured(child, matcher, depth + 1, next_seen)

        # Names that a security scheme or auth_header_names declares carry credentials whatever they say.
        declared_names = {
            scheme["name"].strip().lower()
            for scheme in self.parser.get_security_schemes().values()
            if isinstance(scheme, dict) and isinstance(scheme.get("name"), str) and scheme["name"].strip()
        } | {name.lower() for name in ConfigValidator.STANDARD_AUTH_QUERY_PARAMETERS}
        for identity_name, identity in self.identities.items():
            extra = identity.get("auth_header_names") if identity_name != "roles" and isinstance(identity, dict) else None
            if isinstance(extra, list):
                declared_names.update(item.strip().lower() for item in extra if isinstance(item, str))

        def param_matcher(name: str) -> bool:
            if is_resource_identifier_key(name) and name.strip().lower() not in declared_names:
                # session_id or ticket_id selects the object a request reads: a resource value
                # that keyed comparison fingerprints, still redacted from output as sensitive.
                return include_business_pii and is_sensitive_key(name)
            is_auth = (
                self._is_auth_header(name)
                or self._is_auth_cookie(name)
                or self._is_auth_query_parameter(name)
                or is_auth_credential_key(name)
            )
            return is_auth or (include_business_pii and is_sensitive_key(name))

        def body_matcher(name: str) -> bool:
            return is_credential_parameter(name) or (include_business_pii and is_sensitive_key(name))

        for identity_name, identity in self.identities.items():
            if identity_name == "roles" and isinstance(identity, dict):
                for role_name, role_data in identity.items():
                    if not isinstance(role_data, dict):
                        continue
                    for key, value in self.identity_headers(role_name).items():
                        # Roles cannot declare auth_header_names: every role
                        # header is identity material and is redacted.
                        if value:
                            add_scalar(value, is_cookie=key.lower() == "cookie")
                    if isinstance(role_data.get("parameters"), dict):
                        walk_structured(role_data["parameters"], param_matcher)
                    if role_data.get("body") is not None:
                        walk_structured(role_data["body"], body_matcher)
                continue
            if not isinstance(identity, dict):
                continue
            for key, value in self.identity_headers(identity_name).items():
                if self._is_auth_header(key) and value:
                    add_scalar(value, is_cookie=key.lower() == "cookie")
            if isinstance(identity.get("parameters"), dict):
                walk_structured(identity["parameters"], param_matcher)
            if identity.get("body") is not None:
                walk_structured(identity["body"], body_matcher)

        for conf in (getattr(self, "parameter_values", None) or {}).values():
            if not isinstance(conf, dict):
                continue
            for sub_key, sub_val in conf.items():
                if sub_key in {"common", "owner", "visitor", "anonymous"} and isinstance(sub_val, dict):
                    walk_structured(sub_val, param_matcher)
                else:
                    walk_structured({sub_key: sub_val}, param_matcher)

        for policy in (getattr(self, "bola_config", None) or {}).values():
            if not isinstance(policy, dict):
                continue
            if policy.get("body") is not None:
                walk_structured(policy["body"], body_matcher)
            identity_bodies = policy.get("identity_bodies")
            if isinstance(identity_bodies, dict):
                for body_val in identity_bodies.values():
                    if body_val is not None:
                        walk_structured(body_val, body_matcher)

        for rb in (getattr(self, "readback_config", None) or {}).values():
            if not isinstance(rb, dict):
                continue
            if isinstance(rb.get("parameters"), dict):
                walk_structured(rb["parameters"], param_matcher)
            rb_params = rb.get("parameter_values")
            if isinstance(rb_params, dict):
                for sub_key, sub_val in rb_params.items():
                    if sub_key in {"common", "owner", "visitor", "anonymous"} and isinstance(sub_val, dict):
                        walk_structured(sub_val, param_matcher)
                    else:
                        walk_structured({sub_key: sub_val}, param_matcher)
            if rb.get("baseline_payload") is not None:
                walk_structured(rb["baseline_payload"], body_matcher)

        return secrets

    def identity_headers(self, identity_name: str) -> Dict[str, str]:
        if identity_name in self.identities:
            identity = self.identities[identity_name]
        elif isinstance(self.identities.get("roles"), dict) and identity_name in self.identities["roles"]:
            identity = self.identities["roles"][identity_name]
        else:
            raise KeyError(f"Unknown identity: {identity_name}")
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
                if is_auth_cookie or is_sensitive_key(name):
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
        if is_auth_hdr or is_sensitive_key(name):
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
                if self._is_auth_header(k) or self._is_auth_cookie(k) or is_sensitive_key(k):
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
