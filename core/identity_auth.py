"""The authentication material of each configured identity, and the rules that keep identities apart.

One implementation decides configuration validation, the construction of
APISentinelAuditor and every request the auditor builds, so the CLI, the Python
API and an identity changed after construction cannot disagree.

An identity authenticates with its ``token`` (sent as Authorization), its
authentication headers (named like a credential, declared by an ``apiKey``
header scheme or listed in ``auth_header_names``) and its session cookies. A
session cookie is either a cookie of the identity's ``Cookie`` header or a value
in ``identities.*.parameters`` whose name an ``apiKey`` ``in: cookie`` scheme
declares; both are sent with every request of that identity. Any other cookie
(a theme, a language) is no credential. Values never appear in a message:
problems name identities, headers and cookies only.

The specification's ``security`` lists alternatives (OR); the schemes of one
alternative are required together (AND). A credential that every alternative of
every requirement includes is mandatory: owner, visitor and every role send it,
or none does, because an identity without it would be refused as
unauthenticated and that 401 would read as an authorization denial. Where the
specification offers alternatives, identities may authenticate differently.
The mandatory rule reads the requirements of the specification document without
resolving path-item references (a documented limit).

Two identities never send the same value in a header that can identify the
caller (an authentication header, or one named like a key, token, secret,
session or user) or in a session cookie: a server that identifies callers by it
would treat both as one. Default deny. The one exception is an application-level
gateway header the operator lists in ``identity_isolation.shared_gateway_headers``;
it is accepted only when the specification, resolved operation by operation
exactly as the scanner resolves it (path-item references included), requires a
per-identity credential next to it wherever it applies, and every security
declaration resolves. Anything that cannot be resolved fails closed. Even then the
backend's identity binding is unverified, and reports say so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from core.config_validation.base import ValidatorBase
from core.parameters import ParameterSerializationError, serialize_cookie_parameter

AUTHENTICATED = ("owner", "visitor")
AUTHORIZATION_SCHEMES = frozenset({"http", "basic", "oauth2", "openIdConnect"})

SHARED_GATEWAY_HEADERS = "shared_gateway_headers"
IDENTITY_ISOLATION_KEYS = frozenset({SHARED_GATEWAY_HEADERS})
# Headers that always identify the caller: never shared, whatever the configuration says.
_NEVER_SHARED_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
# RFC 9110 field-name token.
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
# A header name containing one of these (separators removed) can identify the caller.
_IDENTITY_WORDS = (
    "auth", "token", "secret", "session", "sessid", "credential", "jwt", "bearer", "ticket", "passwd",
    "password", "apikey", "accesskey", "subscriptionkey", "signature", "cookie", "impersonat", "onbehalfof",
)
# ... and so can one with one of these words: X-API-Key, X-Sid, X-Uid, X-Principal.
_IDENTITY_TOKENS = frozenset({"key", "sid", "uid", "userid", "principal"})
# A user assertion header ends with "user" or a user attribute: X-User, X-Forwarded-User, X-User-Email.
_USER_ASSERTION = re.compile(r"user(?:id|name|email|login|principal)?$")

UNVERIFIED_BINDING_NOTICE = (
    "These headers carry the same value for more than one identity because "
    "identity_isolation.shared_gateway_headers authorizes them and every operation where they apply also "
    "requires a per-identity credential. GrantTrace does not verify that the server identifies the caller by "
    "that per-identity credential: a CONFIRMED or SUSPICIOUS result can come from the server treating the "
    "identities as one caller. A SECURE result needs different authorization outcomes for the identities on the "
    "same request, which a server that identifies callers by the shared header alone does not produce."
)


class IdentityAuthError(ParameterSerializationError):
    """Identity authentication material that would break identity isolation; nothing is sent."""


def _name_tokens(name: Any) -> List[str]:
    """Lower-case words of a header or cookie name: X-SessionKey, x_session_key and X-SESSION-KEY alike."""
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", str(name))
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", spaced)
    return [token for token in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if token]


def is_session_like_name(name: Any) -> bool:
    """A header or cookie named like a session: X-Session-Key, X-SessionKey, SessionId, X-Sid, PHPSESSID."""
    tokens = _name_tokens(name)
    compact = "".join(tokens)
    return "session" in compact or "sessid" in compact or "sid" in tokens


def is_identity_bearing_header(name: Any) -> bool:
    """A header whose value can identify the caller, by its name alone (default deny for shared values)."""
    tokens = _name_tokens(name)
    if not tokens:
        return False
    compact = "".join(tokens)
    return (any(word in compact for word in _IDENTITY_WORDS)
            or bool(_IDENTITY_TOKENS.intersection(tokens))
            or "userid" in compact
            or bool(_USER_ASSERTION.search(compact)))


def identity_isolation_settings(value: Any) -> Tuple[FrozenSet[str], List[Tuple[str, str]]]:
    """The lower-case header names an operator authorized for sharing, and the problems of the setting.

    Any problem authorizes nothing (fail closed). Problems name configuration paths, never values.
    """
    if value is None:
        return frozenset(), []
    if not isinstance(value, Mapping):
        return frozenset(), [("identity_isolation", "identity_isolation must be an object")]
    problems = [(f"identity_isolation.{key}", f"Unknown identity_isolation key; only '{SHARED_GATEWAY_HEADERS}' "
                 "is supported") for key in value if key not in IDENTITY_ISOLATION_KEYS]
    names = value.get(SHARED_GATEWAY_HEADERS, [])
    path = f"identity_isolation.{SHARED_GATEWAY_HEADERS}"
    if not isinstance(names, list):
        return frozenset(), problems + [(path, "shared_gateway_headers must be a list of header names")]
    seen: Set[str] = set()
    for index, name in enumerate(names):
        item = f"{path}[{index}]"
        if not isinstance(name, str) or not _HEADER_NAME.match(name.strip()):
            problems.append((item, "Each entry must be an HTTP header name"))
            continue
        lowered = name.strip().lower()
        if lowered in seen:
            problems.append((item, "Header is listed more than once"))
        elif lowered in _NEVER_SHARED_HEADERS:
            problems.append((item, f"'{lowered}' identifies the caller and can never be shared"))
        elif is_session_like_name(lowered):
            problems.append((item, "A session-like header identifies the caller and can never be shared"))
        seen.add(lowered)
    if problems:
        return frozenset(), problems
    return frozenset(seen), []


@dataclass(frozen=True)
class SpecAuth:
    """What the specification's security schemes declare about credentials."""

    header_names: frozenset = frozenset()  # lower-case apiKey header names
    cookie_names: Mapping[str, str] = field(default_factory=dict)  # lower-case -> declared apiKey cookie name
    # Credentials every alternative of every security requirement includes, as Material.kinds() names
    # them: "authorization", a lower-case header name or "cookie:<lower-case name>".
    mandatory: frozenset = frozenset()
    # The security requirement of every operation the scanner resolves (path-item references included):
    # an OR tuple of AND credential sets, "" for a scheme GrantTrace cannot send or check (an undefined
    # scheme, a query key, mutual TLS). An anonymous alternative ({}) is left out; a public operation has
    # none. None when an operation or a security declaration cannot be resolved: then no shared header
    # can be authorized (fail closed).
    operation_requirements: Optional[Tuple[Tuple[FrozenSet[str], ...], ...]] = None

    @classmethod
    def from_spec(
        cls,
        schemes: Mapping[str, Any],
        raw_spec: Optional[Mapping[str, Any]],
        operations: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> "SpecAuth":
        """The schemes, the credentials the specification's security requirements make mandatory and,
        given the resolved operations (OpenAPIParser.get_endpoints), each operation's requirement."""
        spec = cls.from_schemes(schemes)
        credentials = _scheme_credentials(schemes)
        requirements = [alternatives for operation in operations_from_spec(raw_spec or {})
                        if (alternatives := requirement_alternatives(operation["security"])) is not None]
        candidates = {credential for credential in credentials.values() if credential}
        mandatory = frozenset(
            credential for credential in candidates if requirements and all(
                any(credentials.get(name) == credential for name in alternative)
                for alternatives in requirements for alternative in alternatives))
        return cls(spec.header_names, spec.cookie_names, mandatory,
                   _operation_requirements(operations, credentials))

    @classmethod
    def from_schemes(cls, schemes: Mapping[str, Any]) -> "SpecAuth":
        """Like the scanner's own lookups, by location: only apiKey schemes have one."""
        headers: Set[str] = set()
        cookies: Dict[str, str] = {}
        for scheme in schemes.values():
            if not isinstance(scheme, Mapping):
                continue
            location, name = scheme.get("in"), scheme.get("name")
            if isinstance(name, str) and name.strip():
                if location == "header":
                    headers.add(name.strip().lower())
                elif location == "cookie":
                    cookies.setdefault(name.strip().lower(), name.strip())
        return cls(frozenset(headers), cookies)


def _scheme_credentials(schemes: Mapping[str, Any]) -> Dict[str, str]:
    """Security scheme name -> the credential that satisfies it ("" when the scanner cannot send it:
    a query key, mutual TLS)."""
    credentials: Dict[str, str] = {}
    for scheme_name, scheme in schemes.items():
        if not isinstance(scheme, Mapping):
            continue
        location, name = scheme.get("in"), scheme.get("name")
        credential = "authorization" if scheme.get("type") in AUTHORIZATION_SCHEMES else ""
        if isinstance(name, str) and name.strip() and location in ("header", "cookie"):
            credential = name.strip().lower() if location == "header" else "cookie:" + name.strip().lower()
        credentials[str(scheme_name)] = credential
    return credentials


def _operation_requirements(
    operations: Optional[Sequence[Mapping[str, Any]]], credentials: Mapping[str, str],
) -> Optional[Tuple[Tuple[FrozenSet[str], ...], ...]]:
    """Each resolved operation's alternatives as credential sets, or None if any cannot be resolved."""
    if operations is None:
        return None
    resolved = []
    for operation in operations:
        if (not isinstance(operation, Mapping) or operation.get("unresolved_schema_error")
                or str(operation.get("method", "")).upper() == "UNKNOWN"):
            return None
        alternatives = _credential_alternatives(operation.get("security"), credentials)
        if alternatives is None:
            return None
        resolved.append(alternatives)
    return tuple(resolved)


def _credential_alternatives(security: Any, credentials: Mapping[str, str]) -> Optional[Tuple[FrozenSet[str], ...]]:
    """An operation's OR list of AND credential sets; None when the declaration is malformed.

    An anonymous alternative ({}) is left out: it allows anonymous access but takes nothing away from
    the other alternatives, so [{ApiKeyAuth: []}, {}] still lets the key alone authenticate.
    """
    if not isinstance(security, list):
        return None
    alternatives = []
    for requirement in security:
        if not isinstance(requirement, Mapping):
            return None
        if any(not isinstance(name, str) or not isinstance(scopes, list) for name, scopes in requirement.items()):
            return None
        if requirement:
            alternatives.append(frozenset(credentials.get(name, "") for name in requirement))
    return tuple(alternatives)


def parse_cookie_header(value: Any) -> List[Tuple[str, str]]:
    """The name/value pairs of a Cookie header, in order; a part without '=' has an empty value."""
    pairs = []
    for part in str(value).split(";"):
        part = part.strip()
        if part:
            name, _, item = part.partition("=")
            pairs.append((name.strip(), item.strip()))
    return pairs


def is_authentication_cookie(name: str, spec: SpecAuth) -> bool:
    """A cookie the specification declares as a session, or, without one, a cookie named like a credential."""
    lowered = str(name).strip().lower()
    if spec.cookie_names:
        return lowered in spec.cookie_names
    normalized = lowered.replace("-", "_")
    return any(word in normalized for word in ValidatorBase.STANDARD_AUTH_COOKIE_WORDS)


def session_cookie_parameters(entry: Mapping[str, Any], spec: SpecAuth) -> List[Tuple[str, str, Any]]:
    """(declared cookie name, parameter key, value) for each identity parameter a cookie scheme names."""
    parameters = entry.get("parameters")
    if not isinstance(parameters, Mapping) or not spec.cookie_names:
        return []
    return [(spec.cookie_names[str(key).strip().lower()], str(key), value)
            for key, value in parameters.items() if str(key).strip().lower() in spec.cookie_names]


def session_cookie_value(name: str, value: Any) -> str:
    """The value sent for a session cookie parameter, or IdentityAuthError; the value is never repeated."""
    if not isinstance(value, str) or not value.strip():
        raise IdentityAuthError(f"session cookie '{name}' must be a non-empty string")
    try:
        return serialize_cookie_parameter({"name": name, "in": "cookie", "schema": {"type": "string"}},
                                          value.strip())[1]
    except ParameterSerializationError as exc:
        raise IdentityAuthError(f"session cookie '{name}' cannot be sent: {exc}") from None


def merge_session_cookies(headers: Dict[str, str], entry: Mapping[str, Any], spec: SpecAuth) -> Dict[str, str]:
    """Add an identity's session cookie parameters to its lower-case wire headers."""
    sessions = session_cookie_parameters(entry, spec)
    if not sessions:
        return headers
    present = {name.lower() for name, _ in parse_cookie_header(headers.get("cookie", ""))}
    pairs = []
    for name, _, value in sessions:
        if name.lower() in present:
            raise IdentityAuthError(f"session cookie '{name}' is configured more than once")
        present.add(name.lower())
        pairs.append(f"{name}={session_cookie_value(name, value)}")
    existing = headers.get("cookie", "").strip().rstrip(";").strip()
    headers["cookie"] = "; ".join(([existing] if existing else []) + pairs)
    return headers


@dataclass
class Material:
    """The credentials an identity sends, by header and cookie name."""

    headers: Dict[str, str] = field(default_factory=dict)  # lower-case authentication header -> value
    cookies: Dict[str, str] = field(default_factory=dict)  # authentication cookie as sent -> value
    # Everything that can identify the caller, for the sharing rule: the authentication headers plus any
    # header named like a key, token, secret, session or user; the authentication cookies plus any
    # session-like cookie, also where the specification declares other cookies.
    identity_headers: Dict[str, str] = field(default_factory=dict)
    identity_cookies: Dict[str, str] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.headers or self.cookies)

    def fingerprint(self) -> Tuple[Tuple[str, str, str], ...]:
        items = [("header", name, value) for name, value in self.headers.items()]
        items += [("cookie", name.lower(), value) for name, value in self.cookies.items()]
        return tuple(sorted(items))

    def kinds(self) -> Set[str]:
        return set(self.headers) | {"cookie:" + name.lower() for name in self.cookies}

    def names(self) -> List[str]:
        return sorted(set(self.headers) | set(self.cookies))

    def credential_value(self, kind: str) -> Optional[str]:
        if kind.startswith("cookie:"):
            target = kind[7:]
            return next((val for name, val in self.identity_cookies.items() if name.lower() == target), None)
        return self.identity_headers.get(kind)


def _normalized(name: str, value: str) -> str:
    if name == "authorization" and " " in value:
        scheme, credential = value.split(None, 1)
        return scheme.lower() + " " + credential.strip()
    return value


def _cookie_header(entry: Mapping[str, Any]) -> str:
    headers = entry.get("headers")
    return next((value.strip() for key, value in (headers.items() if isinstance(headers, Mapping) else ())
                 if str(key).strip().lower() == "cookie" and isinstance(value, str)), "")


def identity_material(entry: Mapping[str, Any], spec: SpecAuth, is_auth_header: Callable[[str], bool]) -> Material:
    material = Material()
    headers = entry.get("headers")
    for key, value in (headers.items() if isinstance(headers, Mapping) else ()):
        name, text = str(key).strip().lower(), value.strip() if isinstance(value, str) else ""
        if not text or name == "cookie":
            continue
        if is_auth_header(name):
            material.headers[name] = _normalized(name, text)
        if name in material.headers or is_identity_bearing_header(name):
            material.identity_headers[name] = _normalized(name, text)
    cookie_header = _cookie_header(entry)
    token = entry.get("token")
    if isinstance(token, str) and token.strip():
        material.headers["authorization"] = _normalized("authorization", token.strip())
        material.identity_headers["authorization"] = material.headers["authorization"]
    for name, value in parse_cookie_header(cookie_header):
        # Only a session cookie authenticates; a theme or language cookie does not, whatever it holds.
        if name and value.strip('"') and is_authentication_cookie(name, spec):
            material.cookies[name] = value.strip('"')
        if name and value.strip('"') and (name in material.cookies or is_session_like_name(name)):
            material.identity_cookies[name] = value.strip('"')
    for name, _, value in session_cookie_parameters(entry, spec):
        if isinstance(value, str) and value.strip():
            material.cookies.setdefault(name, value.strip().strip('"'))
            material.identity_cookies.setdefault(name, value.strip().strip('"'))
    return material


@dataclass(frozen=True)
class Problem:
    path: str
    message: str
    identities: Tuple[str, ...]  # the identities whose requests this problem stops
    actual: str = ""


def _label(name: str) -> str:
    return name if name in ("owner", "visitor", "anonymous") else f"role '{name}'"


def _subject(name: str) -> str:
    label = _label(name)
    return label[:1].upper() + label[1:]  # Only the first letter: role names keep their case.


def _path(name: str) -> str:
    return f"identities.{name}" if name in ("owner", "visitor", "anonymous") else f"identities.roles.{name}"


def _shared_kinds(first: Material, second: Material) -> Dict[str, str]:
    """Kind ("header name" or "cookie:<name>") -> display name, for everything both send with one value."""
    shared = {name: name for name, value in first.identity_headers.items()
              if second.identity_headers.get(name) == value}
    for name, value in first.identity_cookies.items():
        if any(other.lower() == name.lower() and item == value for other, item in second.identity_cookies.items()):
            shared["cookie:" + name.lower()] = name
    return shared


def _shared_header_refusal(
    header: str, first: Material, second: Material, shared: Set[str], spec: SpecAuth, custom_names: Set[str],
) -> Optional[str]:
    """Why an authorized shared header still cannot be shared by these two identities; None if it can.

    The specification is the only evidence, and it must resolve completely: no alternative of any
    operation may consist of shared credentials alone, an alternative with the header must hold only
    credentials GrantTrace can send, and wherever the header applies (every protected operation, when no
    requirement names it) each identity must satisfy an alternative with a credential of its own. This
    proves only what the specification declares, never what the server does.
    """
    if header in _NEVER_SHARED_HEADERS:
        return "it identifies the caller and can never be shared"
    if is_session_like_name(header):
        return "it is named like a session credential"
    if header in custom_names:
        return "auth_header_names declares it as a per-identity credential"
    requirements = spec.operation_requirements
    if requirements is None:
        return ("the specification's operations and security requirements could not all be resolved, so where "
                "it applies cannot be checked")
    protected = [alternatives for alternatives in requirements if alternatives]
    if not protected:
        return "the specification declares no security requirement with a per-identity credential"
    # Where the header applies: the operations whose requirement names it, or every protected operation
    # when no requirement does (undeclared, or declared by a scheme no operation uses).
    named = any(header in alternative for alternatives in protected for alternative in alternatives)
    first_kinds, second_kinds = first.kinds(), second.kinds()
    for alternatives in protected:
        for alternative in alternatives:
            if "" not in alternative and alternative <= shared:
                return "the specification lets shared credentials alone authenticate in at least one operation"
            if header in alternative and "" in alternative:
                return "an operation combines it with a scheme GrantTrace cannot send or check"
        if named and not any(header in alternative for alternative in alternatives):
            continue
        for kinds in (first_kinds, second_kinds):
            if not any("" not in alternative and alternative <= kinds and alternative - shared
                       for alternative in alternatives):
                return ("an operation where it applies has no security alternative that each identity satisfies "
                        "with a credential of its own")
    return None


def _shared(
    first: Material, second: Material, spec: SpecAuth, custom_names: Set[str], authorized: FrozenSet[str],
) -> Tuple[List[str], List[Tuple[str, str]], List[str]]:
    """(unauthorized shared names, (authorized name, why refused), accepted authorized names) for a pair."""
    shared = _shared_kinds(first, second)
    unauthorized: List[str] = []
    refused: List[Tuple[str, str]] = []
    accepted: List[str] = []
    for kind in sorted(shared):
        if kind.startswith("cookie:") or kind not in authorized:
            unauthorized.append(shared[kind])
            continue
        reason = _shared_header_refusal(kind, first, second, set(shared), spec, custom_names)
        if reason:
            refused.append((kind, reason))
        else:
            accepted.append(kind)
    return unauthorized, refused, accepted


def _entries(identities: Mapping[str, Any]) -> Tuple[Dict[str, Mapping[str, Any]], List[str]]:
    raw_roles = identities.get("roles")
    roles: Mapping[str, Any] = raw_roles if isinstance(raw_roles, Mapping) else {}
    entries: Dict[str, Mapping[str, Any]] = {
        name: identities[name] for name in ("owner", "visitor", "anonymous")
        if isinstance(identities.get(name), Mapping)}
    # A role named like a built-in identity is refused on its own; it must not replace that identity here.
    role_names = [name for name, entry in roles.items()
                  if isinstance(name, str) and isinstance(entry, Mapping)
                  and name.lower() not in ("owner", "visitor", "anonymous", "roles")]
    entries.update({name: roles[name] for name in role_names})
    return entries, role_names


def _pairs(entries: Mapping[str, Any], role_names: Sequence[str]) -> List[Tuple[str, str]]:
    pairs = [("owner", "visitor")] if all(name in entries for name in AUTHENTICATED) else []
    return pairs + [(first, second) for index, first in enumerate(role_names) for second in role_names[index + 1:]]


def _custom(custom_names: Iterable[str]) -> Set[str]:
    return {str(name).strip().lower() for name in custom_names if isinstance(name, str) and name.strip()}


def isolation_problems(
    identities: Mapping[str, Any],
    spec: SpecAuth,
    is_auth_header: Callable[[str], bool],
    custom_names: Iterable[str] = (),
    shared_gateway_headers: Iterable[str] = (),
) -> List[Problem]:
    """Everything about the identities' credentials that would let one identity act as another,
    or let a denial come from a missing credential rather than from authorization."""
    problems: List[Problem] = []
    custom = _custom(custom_names)
    authorized = frozenset(str(name).strip().lower() for name in shared_gateway_headers)
    entries, role_names = _entries(identities)
    authenticated = [name for name in (*AUTHENTICATED, *role_names) if name in entries]

    for name, entry in entries.items():
        seen = {cookie.lower() for cookie, _ in parse_cookie_header(_cookie_header(entry))}
        for cookie, key, value in session_cookie_parameters(entry, spec):
            path = f"{_path(name)}.parameters.{key}"
            if name == "anonymous":
                continue  # Reported below with the rest of Anonymous's credentials.
            if cookie.lower() in seen:
                problems.append(Problem(path, f"{_subject(name)} configures session cookie '{cookie}' "
                                        "more than once (Cookie header and parameters, or two spellings); "
                                        "configure it in one place", (name,)))
            seen.add(cookie.lower())
            try:
                session_cookie_value(cookie, value)
            except IdentityAuthError as exc:
                problems.append(Problem(path, f"{_subject(name)}: {exc}", (name,)))

    materials = {name: identity_material(entries[name], spec, is_auth_header) for name in entries}
    for name in authenticated:
        if not materials[name]:
            message = (f"{name.capitalize()} identity has no effective authentication material (token, "
                       "Authorization, custom auth header, or session cookie)" if name in AUTHENTICATED else
                       f"Role '{name}' has no effective authentication material (token, Authorization, "
                       "authentication header, or session cookie); its probe would be refused as "
                       "unauthenticated and read as a denial")
            problems.append(Problem(_path(name), message, (name,), "empty auth material"))

    anonymous = entries.get("anonymous")
    if anonymous is not None and (materials["anonymous"] or session_cookie_parameters(anonymous, spec)
                                  or _cookie_header(anonymous)):
        # Any cookie of Anonymous's own may be a session the names do not reveal: it sends none.
        names = sorted(set(materials["anonymous"].names())
                       | {cookie for cookie, _, _ in session_cookie_parameters(anonymous, spec)}
                       | ({"cookie"} if _cookie_header(anonymous) else set()))
        problems.append(Problem("identities.anonymous",
                                "Anonymous identity must not define authentication credentials or auth headers; "
                                "anonymous requests carry none",
                                ("anonymous",), f"credentials configured under: {names}"))

    for first, second in _pairs(entries, role_names):
        one, two = materials[first], materials[second]
        if not one or not two:
            continue
        if one.fingerprint() == two.fingerprint():
            message = ("Owner and visitor must use distinct effective authentication credentials to verify "
                       "authorization boundaries" if first == "owner" else
                       f"Roles '{first}' and '{second}' use the same authentication credentials; a lower role "
                       "would be read as the privileged one")
            message += f" (both send the same {', '.join(repr(name) for name in one.names())})"
            problems.append(Problem(_path(second), message, (first, second),
                                    "identical auth material (redacted)"))
            continue
        unauthorized, refused, _ = _shared(one, two, spec, custom, authorized)
        if not unauthorized and not refused:
            continue
        names = unauthorized + [name for name, _ in refused]
        message = (f"{_subject(first)} and {_label(second)} send the same value for "
                   f"{', '.join(repr(item) for item in names)}; a server that identifies the caller by it would "
                   f"treat {_label(second)} as {_label(first)}")
        for name, reason in refused:
            message += f"; identity_isolation.shared_gateway_headers lists {name!r}, but {reason}"
        if unauthorized:
            message += ("; give each identity its own value (only an application-level gateway header listed in "
                        "identity_isolation.shared_gateway_headers may be shared, where the specification requires "
                        "a per-identity credential with it)")
        problems.append(Problem(_path(second), message, (first, second), "shared credential (redacted)"))

    # A credential every security alternative requires, and a header listed in auth_header_names (which
    # the specification does not describe), is sent by every authenticated identity or by none: one
    # without it would be refused as unauthenticated. Where alternatives exist, identities may differ.
    sending = [name for name in authenticated if materials[name]]
    for kind in sorted(set(spec.mandatory) | custom):
        present = [name for name in sending if kind in materials[name].kinds()]
        if not present or len(present) == len(sending):
            continue
        what = (f"session cookie '{spec.cookie_names.get(kind[7:], kind[7:])}'" if kind.startswith("cookie:")
                else "Authorization (token)" if kind == "authorization"
                else f"authentication header '{kind}'")
        why = ("listed in auth_header_names" if kind in custom and kind not in spec.mandatory
               else "which every security requirement of the specification includes")
        for name in sending:
            if name not in present:
                problems.append(Problem(
                    _path(name),
                    f"{_subject(name)} does not send the {what} that {', '.join(_label(item) for item in present)} "
                    f"send, {why}; a denial of {_label(name)} could come from the missing credential, not from "
                    "authorization",
                    (name,), "credential missing"))
    return problems


def authorized_shared_headers(
    identities: Mapping[str, Any],
    spec: SpecAuth,
    is_auth_header: Callable[[str], bool],
    custom_names: Iterable[str] = (),
    shared_gateway_headers: Iterable[str] = (),
) -> List[str]:
    """The authorized headers that two identities actually share and that the specification accepts."""
    authorized = frozenset(str(name).strip().lower() for name in shared_gateway_headers)
    if not authorized:
        return []
    custom = _custom(custom_names)
    entries, role_names = _entries(identities)
    materials = {name: identity_material(entries[name], spec, is_auth_header) for name in entries}
    accepted: Set[str] = set()
    for first, second in _pairs(entries, role_names):
        if materials[first] and materials[second]:
            accepted.update(_shared(materials[first], materials[second], spec, custom, authorized)[2])
    return sorted(accepted)


def identity_isolation_record(authorized: Iterable[str], shared_in_scan: Iterable[str]) -> Optional[Dict[str, Any]]:
    """What reports state about authorized shared headers: configured, and backend binding unverified."""
    configured = sorted({str(name).strip().lower() for name in authorized})
    if not configured:
        return None
    return {
        SHARED_GATEWAY_HEADERS: configured,
        "shared_in_scan": sorted(set(shared_in_scan)),
        "authorized_by": "configuration",
        "backend_identity_binding": "unverified",
        "notice": UNVERIFIED_BINDING_NOTICE,
    }


def requirement_alternatives(security: Any) -> Optional[List[Tuple[str, ...]]]:
    """The OR list of AND scheme-name tuples an operation requires, or None when it requires nothing.

    None for no security, ``security: []``, or an alternative ``{}`` (anonymous access allowed). Used for
    the mandatory rule only; the shared-header rule uses SpecAuth.operation_requirements.
    """
    if not isinstance(security, list) or not security:
        return None
    alternatives = []
    for requirement in security:
        if not isinstance(requirement, Mapping) or not requirement:
            return None
        alternatives.append(tuple(str(name) for name in requirement))
    return alternatives


def operations_from_spec(raw_spec: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Method, path and effective security of each operation, read without resolving references.

    A path item given by $ref is left out: its requirements do not take part in the mandatory rule.
    """
    paths = raw_spec.get("paths")
    top = raw_spec.get("security")
    operations = []
    for path, item in (paths.items() if isinstance(paths, Mapping) else ()):
        if not isinstance(item, Mapping) or "$ref" in item:
            continue
        for method, operation in item.items():
            if (isinstance(method, str) and isinstance(operation, Mapping)
                    and method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}):
                operations.append({"method": method.upper(), "path": str(path),
                                   "security": operation.get("security", top)})
    return operations


def problems_for(problems: Sequence[Problem], identity: Optional[str]) -> List[Problem]:
    """The problems that stop requests of one identity (all of them for None)."""
    return [problem for problem in problems if identity is None or identity in problem.identities]
