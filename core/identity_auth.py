"""The authentication material of each configured identity, and the rules that keep identities apart.

One implementation decides configuration validation, the construction of
APISentinelAuditor and every request the auditor builds, so the CLI, the Python
API and an identity changed after construction cannot disagree.

An identity authenticates with its ``token`` (sent as Authorization), its
authentication headers (named like a credential, declared by an ``apiKey``
header scheme or listed in ``auth_header_names``) and its session cookies. A
session cookie is either a cookie of the identity's ``Cookie`` header or a value
in ``identities.*.parameters`` whose name an ``apiKey`` ``in: cookie`` scheme
declares; both are sent with every request of that identity. Values never
appear in a message: problems name identities, headers and cookies only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from core.config_validation.base import ValidatorBase
from core.parameters import ParameterSerializationError, serialize_cookie_parameter

AUTHENTICATED = ("owner", "visitor")


class IdentityAuthError(ParameterSerializationError):
    """Identity authentication material that would break identity isolation; nothing is sent."""


@dataclass(frozen=True)
class SpecAuth:
    """What the specification's security schemes declare about credentials."""

    header_names: frozenset = frozenset()  # lower-case apiKey header names
    cookie_names: Mapping[str, str] = field(default_factory=dict)  # lower-case -> declared apiKey cookie name

    @classmethod
    def from_schemes(cls, schemes: Mapping[str, Any]) -> "SpecAuth":
        headers: Set[str] = set()
        cookies: Dict[str, str] = {}
        for scheme in schemes.values():
            if not isinstance(scheme, Mapping) or scheme.get("type") != "apiKey":
                continue
            location, name = scheme.get("in"), scheme.get("name")
            if isinstance(name, str) and name.strip():
                if location == "header":
                    headers.add(name.strip().lower())
                elif location == "cookie":
                    cookies.setdefault(name.strip().lower(), name.strip())
        return cls(frozenset(headers), cookies)


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
    cookie_header: Optional[str] = None  # a Cookie header without a recognised session cookie, compared whole

    def __bool__(self) -> bool:
        return bool(self.headers or self.cookies or self.cookie_header)

    def fingerprint(self) -> Tuple[Tuple[str, str, str], ...]:
        items = [("header", name, value) for name, value in self.headers.items()]
        items += [("cookie", name.lower(), value) for name, value in self.cookies.items()]
        if self.cookie_header:
            items.append(("cookie-header", "", self.cookie_header))
        return tuple(sorted(items))

    def kinds(self) -> Set[str]:
        return set(self.headers) | {"cookie:" + name.lower() for name in self.cookies}

    def names(self) -> List[str]:
        return sorted(set(self.headers) | set(self.cookies) | ({"cookie"} if self.cookie_header else set()))


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
        if name and value.strip('"') and is_authentication_cookie(name, spec):
            material.cookies[name] = value.strip('"')
    if cookie_header and not material.cookies:
        material.cookie_header = cookie_header  # Any cookie may be the session; the header counts as a whole.
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


def _shared(first: Material, second: Material, custom_names: Set[str]) -> List[str]:
    """Credentials both identities send with the same value: a server authenticating by one of them
    would treat the second identity as the first."""
    shared = [name for name, value in first.cookies.items()
              if any(other.lower() == name.lower() and second.cookies[other] == value for other in second.cookies)]
    shared += [name for name in sorted({"authorization", *custom_names})
               if name in first.headers and first.headers[name] == second.headers.get(name)]
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
    if anonymous is not None and (materials["anonymous"] or session_cookie_parameters(anonymous, spec)):
        names = sorted(set(materials["anonymous"].names())
                       | {cookie for cookie, _, _ in session_cookie_parameters(anonymous, spec)})
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
        shared = _shared(one, two, custom)
        if shared:
            problems.append(Problem(
                _path(second),
                f"{_subject(first)} and {_label(second)} send the same value for "
                f"{', '.join(repr(item) for item in shared)}; a server that authenticates by it would treat "
                f"{_label(second)} as {_label(first)}",
                (first, second), "shared credential (redacted)"))

    # Authorization is not held to this: an http scheme cannot tell a role that authenticates another way
    # the specification allows from one that lacks its token (a remaining limit).
    declared = set(spec.header_names) | custom | {"cookie:" + name for name in spec.cookie_names}
    sending = [name for name in authenticated if materials[name]]
    for kind in sorted(declared):
        present = [name for name in sending if kind in materials[name].kinds()]
        if not present or len(present) == len(sending):
            continue
        what = (f"authentication cookie '{spec.cookie_names[kind[7:]]}'" if kind.startswith("cookie:")
                else f"authentication header '{kind}'")
        for name in sending:
            if name not in present:
                problems.append(Problem(
                    _path(name),
                    f"{_subject(name)} does not send the {what} that "
                    f"{', '.join(_label(item) for item in present)} send; every authenticated identity must send "
                    "the same kinds of declared credentials, or a denial could come from a missing credential",
                    (name,), "credential missing"))
    return problems


def problems_for(problems: Sequence[Problem], identity: Optional[str]) -> List[Problem]:
    """The problems that stop requests of one identity (all of them for None)."""
    return [problem for problem in problems if identity is None or identity in problem.identities]
