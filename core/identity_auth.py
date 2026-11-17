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
Requirements are not checked operation by operation (a documented limit).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from core.config_validation.base import ValidatorBase
from core.parameters import ParameterSerializationError, serialize_cookie_parameter

AUTHENTICATED = ("owner", "visitor")
AUTHORIZATION_SCHEMES = frozenset({"http", "basic", "oauth2", "openIdConnect"})


class IdentityAuthError(ParameterSerializationError):
    """Identity authentication material that would break identity isolation; nothing is sent."""


@dataclass(frozen=True)
class SpecAuth:
    """What the specification's security schemes declare about credentials."""

    header_names: frozenset = frozenset()  # lower-case apiKey header names
    cookie_names: Mapping[str, str] = field(default_factory=dict)  # lower-case -> declared apiKey cookie name
    # Credentials every alternative of every security requirement includes, as Material.kinds() names
    # them: "authorization", a lower-case header name or "cookie:<lower-case name>".
    mandatory: frozenset = frozenset()
    # Each protected operation's OR list of AND scheme-credential sets ("" for an undefined or
    # unsupported scheme such as an query key or mutual TLS).
    requirements: Tuple[Tuple[FrozenSet[str], ...], ...] = ()

    @classmethod
    def from_spec(cls, schemes: Mapping[str, Any], raw_spec: Optional[Mapping[str, Any]]) -> "SpecAuth":
        """The schemes, and the credentials the specification's security requirements make mandatory."""
        spec = cls.from_schemes(schemes)
        credentials = _scheme_credentials(schemes)
        requirements = [alternatives for operation in operations_from_spec(raw_spec or {})
                        if (alternatives := requirement_alternatives(operation["security"])) is not None]
        candidates = {credential for credential in credentials.values() if credential}
        mandatory = frozenset(
            credential for credential in candidates if requirements and all(
                any(credentials.get(name) == credential for name in alternative)
                for alternatives in requirements for alternative in alternatives))
        resolved_requirements = tuple(
            tuple(frozenset(credentials.get(name, "") for name in alternative) for alternative in alternatives)
            for alternatives in requirements
        )
        return cls(spec.header_names, spec.cookie_names, mandatory, resolved_requirements)

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
            return next((val for name, val in self.cookies.items() if name.lower() == target), None)
        return self.headers.get(kind)


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
        if text and name != "cookie" and is_auth_header(name):
            material.headers[name] = _normalized(name, text)
    cookie_header = _cookie_header(entry)
    token = entry.get("token")
    if isinstance(token, str) and token.strip():
        material.headers["authorization"] = _normalized("authorization", token.strip())
    for name, value in parse_cookie_header(cookie_header):
        # Only a session cookie authenticates; a theme or language cookie does not, whatever it holds.
        if name and value.strip('"') and is_authentication_cookie(name, spec):
            material.cookies[name] = value.strip('"')
    for name, _, value in session_cookie_parameters(entry, spec):
        if isinstance(value, str) and value.strip():
            material.cookies.setdefault(name, value.strip().strip('"'))
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


def _is_and_bound_shared_header(
    header: str,
    first: Material,
    second: Material,
    spec: SpecAuth,
    custom_names: Set[str],
) -> bool:
    """True only for an application-level apiKey header that every relevant security requirement
    combines via AND with another supported credential that keeps the two identities distinct."""
    tokens = set(header.replace("-", "_").split("_"))
    if (
        header == "authorization"
        or "session" in tokens
        or header in custom_names
        or header not in spec.header_names
        or not spec.requirements
    ):
        return False
    relevant = [req for req in spec.requirements if any(header in alt for alt in req)]
    if not relevant:
        return False
    first_kinds, second_kinds = first.kinds(), second.kinds()
    for req in relevant:
        for alt in req:
            if header in alt and ("" in alt or len(alt - {header}) == 0):
                return False
        first_satisfied = [alt for alt in req if "" not in alt and alt <= first_kinds]
        second_satisfied = [alt for alt in req if "" not in alt and alt <= second_kinds]
        if not first_satisfied or not second_satisfied:
            return False
        for alt in first_satisfied:
            if alt in second_satisfied and all(
                first.credential_value(cred) == second.credential_value(cred) for cred in alt
            ):
                return False
    return True


def _shared(first: Material, second: Material, spec: SpecAuth, custom_names: Set[str]) -> List[str]:
    """Credentials both identities send with the same value: a server authenticating by one of them
    would treat the second identity as the first, unless an application-level apiKey header is
    strictly AND-coupled with distinct per-identity credentials."""
    shared = [name for name, value in first.cookies.items()
              if any(other.lower() == name.lower() and second.cookies[other] == value for other in second.cookies)]
    for name in sorted(set(first.headers) & set(second.headers)):
        if first.headers[name] == second.headers[name] and not _is_and_bound_shared_header(
            name, first, second, spec, custom_names
        ):
            shared.append(name)
    return shared


def isolation_problems(
    identities: Mapping[str, Any],
    spec: SpecAuth,
    is_auth_header: Callable[[str], bool],
    custom_names: Iterable[str] = (),
) -> List[Problem]:
    """Everything about the identities' credentials that would let one identity act as another,
    or let a denial come from a missing credential rather than from authorization."""
    problems: List[Problem] = []
    custom = {str(name).strip().lower() for name in custom_names if isinstance(name, str) and name.strip()}
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

    pairs = ([("owner", "visitor")] if all(name in entries for name in AUTHENTICATED) else [])
    pairs += [(first, second) for index, first in enumerate(role_names) for second in role_names[index + 1:]]
    for first, second in pairs:
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
        shared = _shared(one, two, spec, custom)
        if shared:
            problems.append(Problem(
                _path(second),
                f"{_subject(first)} and {_label(second)} send the same value for "
                f"{', '.join(repr(item) for item in shared)}; a server that authenticates by it would treat "
                f"{_label(second)} as {_label(first)}",
                (first, second), "shared credential (redacted)"))

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


def requirement_alternatives(security: Any) -> Optional[List[Tuple[str, ...]]]:
    """The OR list of AND scheme-name tuples an operation requires, or None when it requires nothing.

    None for no security, ``security: []``, or an alternative ``{}`` (anonymous access allowed).
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

    A path item given by $ref is left out: its requirements do not take part.
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
