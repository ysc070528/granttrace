"""Create deliberately incomplete, offline configuration drafts from OpenAPI.

A contract describes request shapes, not resource ownership, authorization
policy, or read-after-write guarantees. Those decisions remain explicit user
inputs; a draft must never silently become a runnable scan configuration.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import AbstractSet, Any, Dict, List, Optional, Tuple

from core.config_validator import ConfigValidator
from core.parser import OpenAPIParser


DRAFT_KEY = "_granttrace_draft"
INPUT_PREFIX = "__GRANTTRACE_INPUT__:"
WRITE_METHODS = ("PATCH", "PUT")
# Resource parameters belong to the identity that owns the resource; header and
# cookie values are sent by whichever identity makes the request.
RESOURCE_IDENTITIES = ("owner", "visitor")
REQUESTERS = ("owner", "visitor", "anonymous")
# The scanner ignores these header declarations (RequestBuilderMixin._header_parameter).
IGNORED_HEADERS = frozenset({"authorization", "accept", "content-type"})

# Lower-case header and cookie names of the specification's API-key schemes;
# None when the security schemes cannot be resolved.
AuthNames = Optional[Tuple[AbstractSet[str], AbstractSet[str]]]
NO_SPEC_AUTH: AuthNames = (frozenset(), frozenset())


def _input(label: str) -> str:
    return INPUT_PREFIX + label


def config_needs_input(config: Any) -> bool:
    """Reject draft markers and unresolved placeholders without printing values."""
    if isinstance(config, dict) and DRAFT_KEY in config:
        return True
    pending = [config]
    seen = set()
    while pending:
        value = pending.pop()
        if isinstance(value, str) and value.startswith(INPUT_PREFIX):
            return True
        if isinstance(value, (dict, list)):
            if id(value) in seen:
                continue
            seen.add(id(value))
            if isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())
            else:
                pending.extend(value)
    return False


def _spec_auth_names(parser: OpenAPIParser) -> AuthNames:
    """Return the header and cookie names of the specification's API-key schemes."""
    try:
        schemes = parser.get_security_schemes()
    except (TypeError, ValueError, RuntimeError):
        return None
    names: Dict[str, set] = {"header": set(), "cookie": set()}
    for scheme in schemes.values():
        if isinstance(scheme, dict) and scheme.get("in") in names and isinstance(scheme.get("name"), str):
            names[scheme["in"]].add(scheme["name"].lower())
    return frozenset(names["header"]), frozenset(names["cookie"])


def _request_value_review(
    parameter: Dict[str, Any], name: str, location: str, schema: Dict[str, Any], operation: str,
    auth: AuthNames, swagger2: bool,
) -> Tuple[str, str]:
    """Decide where a GET header or cookie value is drafted, and say why.

    Returns the draft target ("" when nothing is drafted) and the review note.
    Mirrors RequestBuilderMixin: it ignores some header declarations, sends a
    declared authentication header only from both owner's and visitor's
    identity headers (refusing the check otherwise, even for an optional one),
    takes an authentication cookie only from the requesting identity, and
    refuses unsupported cookie forms. Optional business values are left out
    like optional query parameters.
    """
    if auth is None:
        return "", (
            "The specification's security schemes could not be resolved, so authentication headers and "
            "cookies cannot be told apart from business ones; nothing was drafted. Fix the security schemes, "
            "or add business values under parameter_values and authentication under identities.*.headers."
        )
    auth_headers, auth_cookies = auth
    lowered = name.lower()
    if location == "header" and lowered in IGNORED_HEADERS:
        return "", (
            "GrantTrace ignores this header declaration: media types come from the operation and "
            "authentication from identities.*.headers. Nothing to configure here."
        )
    if location == "header" and ConfigValidator.is_auth_header(name, spec_auth_names=auth_headers):
        return "identity_headers", (
            "Authentication header: drafted for owner and visitor under identities.*.headers, which are sent "
            "with every request; never put it in parameter_values. GrantTrace refuses this check unless both "
            "identities send it, even when the parameter is optional. Anonymous requests omit it."
        )
    if location == "cookie" and (
        lowered in auth_cookies
        or any(word in lowered.replace("-", "_") for word in ConfigValidator.STANDARD_AUTH_COOKIE_WORDS)
    ):
        if parameter.get("required") is not True:
            return "", (
                "Optional authentication cookie: not drafted. When a test needs it, give owner and visitor "
                "different identity-specific values under identities.*.parameters; never use common. "
                "Anonymous requests omit it."
            )
        return "identity_parameters", (
            "Authentication cookie: drafted for owner and visitor under identities.*.parameters. Values must "
            "be identity-specific and differ between owner and visitor; never use common. Anonymous requests "
            "omit it."
        )
    if "content" in parameter:
        return "", (
            "Parameters described with content are not supported; the check is INCONCLUSIVE before any request."
        )
    if location == "cookie" and (
        swagger2 or parameter.get("style") == "cookie" or schema.get("type") in {"array", "object"}
    ):
        return "", (
            "Cookie arrays and objects, style: cookie and Swagger 2 cookies are not supported; the check is "
            "INCONCLUSIVE before any request."
        )
    if parameter.get("required") is not True:
        return "", (
            "Optional: not drafted. When a test needs it, add a value under parameter_values." + operation
            + ".<identity> (or .common for a value every identity sends)."
        )
    return "requesters", (
        "Sent by the requesting identity, including anonymous. Replace each placeholder with the value that "
        "identity sends; if every identity sends the same value, one parameter_values." + operation
        + ".common entry can replace them. Authentication belongs under identities.*.headers."
    )


def _parameter_notes(endpoint: Dict[str, Any], auth: AuthNames = NO_SPEC_AUTH,
                     swagger2: bool = False) -> List[Dict[str, Any]]:
    notes = []
    present_paths = set()
    operation = str(endpoint.get("method")) + " " + str(endpoint.get("path"))
    for parameter in endpoint["parameters"]:
        name, location = parameter.get("name"), parameter.get("in")
        if not isinstance(name, str) or not name:
            continue
        if location == "path":
            present_paths.add(name)
        schema = parameter.get("schema", parameter)
        schema = schema if isinstance(schema, dict) else {}
        item = {
            "name": name,
            "in": location,
            "required": location == "path" or parameter.get("required") is True,
            "type": schema.get("type", "unspecified"),
            "included_in_config": location == "path" or (
                location == "query" and parameter.get("required") is True
            ),
        }
        for keyword in ("style", "explode", "collectionFormat", "allowReserved"):
            if keyword in parameter:
                item[keyword] = parameter[keyword]
        if isinstance(schema.get("format"), str):
            item["format"] = schema["format"]
        if isinstance(schema.get("items"), dict):
            item["items_type"] = schema["items"].get("type", "unspecified")
        if "content" in parameter:
            item["content_parameter"] = True
        # Where build_config_scaffold drafts the value; removed before output.
        item["_draft"] = "resources" if item["included_in_config"] else ""
        if location in {"header", "cookie"} and endpoint.get("method") == "GET":
            item["_draft"], item["needs_review"] = _request_value_review(
                parameter, name, location, schema, operation, auth, swagger2,
            )
            item["included_in_config"] = bool(item["_draft"])
        elif location not in {"path", "query", "body"}:
            item["needs_review"] = (
                "Header and cookie parameters are sent only for GET operations, and form parameters are "
                "not supported by the scanner. Identity authentication headers must be configured under "
                "identities.*.headers; do not assume an unsupported required parameter will be sent."
            )
        notes.append(item)
    # An undeclared template variable must not fall through to generated data.
    for name in re.findall(r"\{([^{}]+)\}", endpoint["path"]):
        if name not in present_paths:
            notes.append({
                "name": name, "in": "path", "required": True, "type": "unspecified",
                "included_in_config": True, "_draft": "resources",
                "needs_review": "Missing OpenAPI parameter declaration; fix the contract before scanning.",
            })
    return notes


def _security_notes(raw_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    components = raw_spec.get("components", {})
    schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    if not schemes:
        schemes = raw_spec.get("securityDefinitions", {})
    if not isinstance(schemes, dict):
        return []
    notes = []
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        item = {"name": str(name)}
        for keyword in ("type", "scheme", "in", "name"):
            if keyword in scheme:
                item["parameter_name" if keyword == "name" else keyword] = scheme[keyword]
        if "$ref" in scheme:
            item["needs_review"] = "Resolve this security scheme locally and configure authentication manually."
        notes.append(item)
    return notes


def build_config_scaffold(spec_path: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return a blocked config and a separate human review checklist.

    Reuse the scanner's local JSON/YAML parser and its safe reference handling.
    Never copy example/default resource IDs, credentials, or inferred policies.
    """
    parser = OpenAPIParser(spec_path)
    endpoints = parser.get_endpoints()
    auth = _spec_auth_names(parser)
    swagger2 = str(parser.raw_spec.get("swagger", "")).startswith("2.")
    draft: Dict[str, Any] = {
        "description": "INCOMPLETE offline draft. Complete the companion checklist before scanning.",
        DRAFT_KEY: {"status": "needs_user_input", "version": 1},
        "identities": {
            name: {"id": _input(name + " test account id"), "token": None,
                   "headers": {}, "parameters": {}}
            for name in ("owner", "visitor")
        },
        "parameter_values": {},
        "write_allowlist": [],
        "readbacks": {},
        "bola": {},
    }
    draft["identities"]["anonymous"] = {
        "id": None, "token": None, "headers": {}, "parameters": {},
    }
    checklist: Dict[str, Any] = {
        "status": "needs_user_input",
        "offline": True,
        "limitations": [
            "OpenAPI cannot establish resource ownership or which identities should be allowed access.",
            "OpenAPI cannot prove an independent GET observes committed PATCH or PUT changes or strong "
            "consistency.",
            "This draft is incomplete and blocked; generating it sends no requests and authorizes no writes.",
            "Schema defaults and examples are not trusted as test resources or credentials and are not copied.",
        ],
        "steps": [
            "Use a dedicated authorized test target and disposable resources.",
            "Fill owner and visitor with distinct real test-account IDs and authentication. For Bearer auth, "
            "set identities.*.token to 'Bearer <test credential>'; for custom authentication, use "
            "identities.*.headers and auth_header_names. Keep anonymous credentials empty.",
            "Replace every resource placeholder with an existing resource belonging to the named test "
            "identity. Parameter values are JSON values of the declared type, not Python list/boolean text. "
            "Fill optional query parameters deliberately when needed; do not guess resource ownership.",
            "Fill the drafted GET header and cookie values for owner, visitor and anonymous: each requesting "
            "identity sends its own. Keep authentication under identities.*.headers, and check each "
            "operation's parameter notes for headers and cookies that were not drafted.",
            "Confirm permitted and denied access, including same-team sharing and administrator access, "
            "before treating cross-identity access as a finding. Configure bola.expected_public only for "
            "confirmed public operations and resource_id_paths only for confirmed response identifiers.",
            "For each PATCH or PUT you intend to test, independently verify the GET readback path, field_map "
            "(written field -> response field), resource parameters, consistency, baseline and rollback. "
            "Remove unused readback entries; never infer strong consistency from a similar path.",
            "Keep write_allowlist empty for read-only checks. Enabling writes later requires an explicit "
            "reviewed PATCH/PUT allowlist and the separate --allow-write-tests flag; even then the CLI stops "
            "PATCH and PUT checks against an external target before any write, because it cannot verify "
            "the target's authoritative state.",
            "After completing this review, replace all __GRANTTRACE_INPUT__: placeholders and remove "
            "_granttrace_draft. Run --validate-config --config <config> --spec <spec>, then --dry-run with "
            "the same files and review the plan before any scan. Validation does not prove business policy.",
        ],
        "security_schemes": _security_notes(parser.raw_spec),
        "identities": [
            {"identity": name, "status": "needs_user_input",
             "missing": ["test-account id", "distinct test authentication"],
             "config_paths": ["identities." + name + ".id", "identities." + name + ".token",
                              "identities." + name + ".headers"],
             "instruction": "Use token or explicit authentication headers appropriate to the API; "
                            "the account must have the role you intend to test."}
            for name in ("owner", "visitor")
        ],
        "operations": [],
    }
    get_paths = sorted({endpoint["path"] for endpoint in endpoints if endpoint["method"] == "GET"})
    checklist["available_get_paths"] = get_paths
    for endpoint in endpoints:
        operation = endpoint["method"] + " " + endpoint["path"]
        supported = endpoint["method"] in {"GET", *WRITE_METHODS}
        parameters = _parameter_notes(endpoint, auth, swagger2)
        entry: Dict[str, Any] = {
            "operation": operation,
            "scan_supported": supported,
            "parameters": parameters,
            "needs_user_input": [
                "Confirm the intended allowed/denied identities and resource ownership; "
                "same-team sharing or administrator access can be legitimate."
            ] if supported else ["This operation method is not actively tested by GrantTrace."],
        }
        values: Dict[str, Dict[str, str]] = {}
        for parameter in parameters:
            target = parameter.pop("_draft", "")
            if not supported:
                parameter["included_in_config"] = False
            if not supported or not target:
                continue
            name = parameter["name"]
            parameter["status"] = "needs_user_input"
            if target in {"identity_headers", "identity_parameters"}:
                # Identity headers and parameters apply to every operation.
                section, label = (("headers", "authentication header") if target == "identity_headers"
                                  else ("parameters", "authentication cookie"))
                parameter["config_paths"] = []
                for identity in RESOURCE_IDENTITIES:
                    existing = draft["identities"][identity][section]
                    # Another operation may already declare it, in different letter case.
                    key = next((key for key in existing if key.lower() == name.lower()), name)
                    existing.setdefault(key, _input(identity + " " + label + " " + name))
                    parameter["config_paths"].append("identities." + identity + "." + section + "." + key)
                continue
            identities = REQUESTERS if target == "requesters" else RESOURCE_IDENTITIES
            label = "request " + parameter["in"] if target == "requesters" else "resource parameter"
            parameter["config_paths"] = [
                "parameter_values." + operation + "." + identity + "." + name for identity in identities
            ]
            for identity in identities:
                values.setdefault(identity, {})[name] = _input(identity + " " + label + " " + name)
        if values:
            draft["parameter_values"][operation] = {
                identity: values[identity] for identity in REQUESTERS if identity in values
            }
        if endpoint["method"] in WRITE_METHODS:
            draft["readbacks"][operation] = {
                "method": "GET", "path": _input("verified GET readback path"),
                "consistency": _input("verified strong, weak, or eventual consistency"),
                "field_map": {},
            }
            schema = endpoint.get("request_schema")
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
            entry["readback_review"] = {
                "candidate_get_paths": [path for path in get_paths if path == endpoint["path"]],
                "candidate_written_fields": sorted(properties) if isinstance(properties, dict) else [],
                "missing": ["verified GET path", "write-to-response field_map", "consistency guarantee",
                            "readback resource parameters", "baseline and successful rollback"],
                "instruction": "Candidates describe contract shapes only; verify each against real test behavior. "
                               "Nested fields use dot/bracket paths, for example data.role or members[0].role.",
            }
            if endpoint["method"] == "PUT":
                entry["readback_review"]["missing"].append("complete root document readback")
                entry["readback_review"]["instruction"] += (
                    " PUT replaces the whole resource: the readback must return the complete root document "
                    "(no snapshot_path envelope), field_map must map each written field to the same path, "
                    "ignore_readback_paths and baseline_payload must stay empty, and only application/json "
                    "bodies are supported."
                )
        checklist["operations"].append(entry)
    return draft, checklist


def write_config_scaffold(spec_path: str, output_path: str) -> Tuple[Path, Path]:
    """Write both new files exclusively, refusing to overwrite either one."""
    output = Path(output_path).expanduser()
    if output.suffix.lower() != ".json":
        raise ValueError("--init-config output must be a .json file")
    checklist_path = output.with_suffix(".checklist.json")
    for destination in (output, checklist_path):
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"Refusing to overwrite existing file: {destination}")
    draft, checklist = build_config_scaffold(spec_path)
    contents = [json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
                for value in (draft, checklist)]
    output.parent.mkdir(parents=True, exist_ok=True)
    created: List[Path] = []
    try:
        for destination, content in zip((output, checklist_path), contents):
            with destination.open("x", encoding="utf-8") as handle:
                created.append(destination)
                handle.write(content)
    except Exception:
        # Only remove files created by this call; preserve any pre-existing peer.
        for destination in reversed(created):
            destination.unlink()
        raise
    return output, checklist_path
