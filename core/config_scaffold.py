"""Create deliberately incomplete, offline configuration drafts from OpenAPI.

A contract describes request shapes, not resource ownership, authorization
policy, or read-after-write guarantees. Those decisions remain explicit user
inputs; a draft must never silently become a runnable scan configuration.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.parser import OpenAPIParser


DRAFT_KEY = "_granttrace_draft"
INPUT_PREFIX = "__GRANTTRACE_INPUT__:"


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


def _parameter_notes(endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
    notes = []
    present_paths = set()
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
        if location not in {"path", "query", "body"}:
            item["needs_review"] = (
                "Operation header/cookie/form parameters are unsupported by the scanner. "
                "Identity authentication headers must be configured under identities.*.headers; "
                "do not assume an unsupported required parameter will be sent."
            )
        notes.append(item)
    # An undeclared template variable must not fall through to generated data.
    for name in re.findall(r"\{([^{}]+)\}", endpoint["path"]):
        if name not in present_paths:
            notes.append({
                "name": name, "in": "path", "required": True, "type": "unspecified",
                "included_in_config": True,
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
            "OpenAPI cannot prove an independent GET observes committed PATCH changes or strong consistency.",
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
            "Confirm permitted and denied access, including same-team sharing and administrator access, "
            "before treating cross-identity access as a finding. Configure bola.expected_public only for "
            "confirmed public operations and resource_id_paths only for confirmed response identifiers.",
            "For each PATCH you intend to test, independently verify the GET readback path, field_map "
            "(written field -> response field), resource parameters, consistency, baseline and rollback. "
            "Remove unused PATCH readback entries; never infer strong consistency from a similar path.",
            "Keep write_allowlist empty for read-only checks. Enabling writes later requires an explicit "
            "reviewed PATCH allowlist and the separate --allow-write-tests flag.",
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
        supported = endpoint["method"] in {"GET", "PATCH"}
        parameters = _parameter_notes(endpoint)
        entry: Dict[str, Any] = {
            "operation": operation,
            "scan_supported": supported,
            "parameters": parameters,
            "needs_user_input": [
                "Confirm the intended allowed/denied identities and resource ownership; "
                "same-team sharing or administrator access can be legitimate."
            ] if supported else ["This operation method is not actively tested by GrantTrace."],
        }
        if supported:
            names = [p["name"] for p in parameters if p["included_in_config"]]
            for parameter in parameters:
                if parameter["included_in_config"]:
                    parameter["status"] = "needs_user_input"
                    parameter["config_paths"] = [
                        "parameter_values." + operation + "." + identity + "." + parameter["name"]
                        for identity in ("owner", "visitor")
                    ]
            if names:
                draft["parameter_values"][operation] = {
                    identity: {name: _input(identity + " resource parameter " + name) for name in names}
                    for identity in ("owner", "visitor")
                }
        if endpoint["method"] == "PATCH":
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
