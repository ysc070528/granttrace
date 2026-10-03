# -*- coding: utf-8 -*-
"""OpenAPI 3.x / Swagger 2.0 specification parsing helpers.

The parser deliberately keeps its public endpoint shape small, but resolves the
parts that the scanner needs before returning them. References may point at the
root document or another JSON/YAML document below the root specification's
directory. Remote, absolute, and directory-traversing references are rejected
so loading an untrusted contract cannot read arbitrary local files.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import unquote, urlsplit


class OpenAPIParser:
    """Load and normalize the subset of OpenAPI used by the auditor."""

    HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")

    def __init__(self, spec_path: str):
        self.spec_path = str(spec_path)
        self._spec_file = Path(spec_path).expanduser().resolve()
        self._spec_dir = self._spec_file.parent
        self._document_cache: Dict[Path, Dict[str, Any]] = {}
        self._ref_cache: Dict[str, Any] = {}
        self._ref_file_cache: Dict[str, Path] = {}
        self.raw_spec: Dict[str, Any] = self._read_file(str(self._spec_file))
        self.version = self._detect_version()

    def _read_file(self, path: str) -> Dict[str, Any]:
        """Read a JSON or YAML mapping and cache it by canonical path."""
        file_path = Path(path).expanduser().resolve()
        if file_path in self._document_cache:
            return self._document_cache[file_path]

        suffix = file_path.suffix.lower()
        try:
            with file_path.open("r", encoding="utf-8-sig") as handle:
                if suffix in {".yaml", ".yml"}:
                    try:
                        import yaml  # type: ignore
                    except ImportError as exc:
                        raise RuntimeError(
                            "YAML OpenAPI files require the PyYAML package; "
                            "install it with 'pip install PyYAML'."
                        ) from exc
                    data = yaml.safe_load(handle)
                else:
                    data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON specification '{file_path}': {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(f"OpenAPI document '{file_path}' must contain a mapping at its root")

        self._document_cache[file_path] = data
        return data

    def _detect_version(self) -> str:
        if "openapi" in self.raw_spec:
            return f"OpenAPI {self.raw_spec['openapi']}"
        if "swagger" in self.raw_spec:
            return f"Swagger {self.raw_spec['swagger']}"
        return "Unknown Specification"

    @staticmethod
    def _decode_pointer_part(value: str) -> str:
        # The fragment was URI-decoded once in _reference_target. Decoding it
        # again here would change literal percent sequences in property names.
        return value.replace("~1", "/").replace("~0", "~")

    @property
    def _schema_ref_siblings_allowed(self) -> bool:
        return str(self.raw_spec.get("openapi", "")).startswith("3.1.")

    def _reference_siblings(self, node: Dict[str, Any], *, schema: bool) -> Dict[str, Any]:
        siblings = {key: value for key, value in node.items() if key != "$ref"}
        if not siblings:
            return {}
        if schema and self._schema_ref_siblings_allowed:
            return siblings
        # OAS 3.0 / Swagger Reference Objects do not combine sibling schemas.
        # Explicitly reject structural extensions instead of losing fields.
        allowed = {"summary", "description"} if self._schema_ref_siblings_allowed else set()
        unsupported = set(siblings) - allowed
        if unsupported:
            raise ValueError(
                f"$ref siblings {sorted(unsupported)} are unsupported in {self.version}; "
                "use allOf for schema extensions (schema siblings require OpenAPI 3.1)"
            )
        return siblings

    def _reference_target(self, ref_uri: object, base_file: Path) -> Tuple[Path, str, str]:
        if not isinstance(ref_uri, str) or not ref_uri:
            raise ValueError("$ref must be a non-empty string")

        parsed = urlsplit(ref_uri)
        if parsed.scheme or parsed.netloc:
            raise ValueError(f"Remote $ref values are not supported: {ref_uri}")
        if parsed.query:
            raise ValueError(f"Query strings are not valid in local $ref values: {ref_uri}")

        raw_document_path = unquote(parsed.path)
        if raw_document_path:
            candidate = Path(raw_document_path)
            if candidate.is_absolute():
                raise ValueError(f"Absolute paths are not allowed in $ref values: {ref_uri}")
            target_file = (base_file.parent / candidate).resolve()
        else:
            target_file = base_file.resolve()

        try:
            common = Path(os.path.commonpath((str(self._spec_dir), str(target_file))))
        except ValueError as exc:
            raise ValueError(f"$ref escapes the specification directory: {ref_uri}") from exc
        if common != self._spec_dir:
            raise ValueError(f"$ref escapes the specification directory: {ref_uri}")

        fragment = unquote(parsed.fragment)
        cache_key = f"{target_file}#{fragment}"
        return target_file, fragment, cache_key

    def _lookup_ref(self, ref_uri: object, base_file: Path) -> Tuple[Any, Path, str]:
        target_file, fragment, cache_key = self._reference_target(ref_uri, base_file)
        document = self._read_file(str(target_file))
        current: Any = document

        if fragment:
            if not fragment.startswith("/"):
                raise ValueError(f"Only JSON Pointer fragments are supported in $ref: {ref_uri}")
            try:
                for raw_part in fragment[1:].split("/"):
                    part = self._decode_pointer_part(raw_part)
                    if isinstance(current, list):
                        if not part.isdigit() or (len(part) > 1 and part.startswith("0")):
                            raise ValueError("Invalid array index in JSON Pointer")
                        current = current[int(part)]
                    else:
                        current = current[part]
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise ValueError(f"Unresolved $ref '{ref_uri}' in '{base_file.name}'") from exc

        return current, target_file, cache_key

    def _resolve_ref_chain(
        self,
        ref_uri: object,
        base_file: Path,
        max_depth: int,
        seen: Optional[Set[str]] = None,
    ) -> Tuple[Any, Path]:
        """Resolve aliases while retaining the document context of the value."""
        if max_depth <= 0:
            return {"$ref": ref_uri}, base_file

        target, target_file, cache_key = self._lookup_ref(ref_uri, base_file)
        chain = set() if seen is None else set(seen)
        if cache_key in chain:
            return {"$ref": ref_uri}, target_file

        if cache_key in self._ref_cache:
            return (
                copy.deepcopy(self._ref_cache[cache_key]),
                self._ref_file_cache.get(cache_key, target_file),
            )

        chain.add(cache_key)
        value = copy.deepcopy(target)
        if isinstance(value, dict) and "$ref" in value:
            nested_ref = value.get("$ref")
            siblings = self._reference_siblings(value, schema=False)
            resolved, resolved_file = self._resolve_ref_chain(
                nested_ref, target_file, max_depth - 1, chain
            )
            if isinstance(resolved, dict):
                value = dict(resolved)
                value.update(siblings)
            else:
                value = resolved
            target_file = resolved_file

        # Do not cache an unresolved cycle marker.
        if not (isinstance(value, dict) and set(value) == {"$ref"}):
            self._ref_cache[cache_key] = copy.deepcopy(value)
            self._ref_file_cache[cache_key] = target_file
        return value, target_file

    def resolve_ref(self, ref_uri: str, max_depth: int = 20) -> Dict[str, Any]:
        """Resolve a root-relative or local external ``$ref``.

        Malformed/nonexistent pointers, unsafe paths, and remote URLs raise
        ``ValueError`` rather than silently becoming an unconstrained schema.
        """
        target, target_file, _ = self._lookup_ref(ref_uri, self._spec_file)
        value = self._deep_resolve_schema(target, max_depth, _base_file=target_file)
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _merge_all_of(base: Dict[str, Any], branch: Dict[str, Any]) -> Dict[str, Any]:
        """Merge the object-relevant portions of one resolved allOf branch."""
        merged = dict(base)
        for key, value in branch.items():
            if key == "properties" and isinstance(value, dict):
                properties = dict(merged.get("properties", {}))
                for name, child in value.items():
                    if name in properties and properties[name] != child:
                        properties[name] = {"allOf": [properties[name], child]}
                    else:
                        properties[name] = copy.deepcopy(child)
                merged["properties"] = properties
            elif key == "required" and isinstance(value, list):
                required = list(merged.get("required", []))
                required.extend(item for item in value if item not in required)
                merged["required"] = required
            elif key not in {"allOf", "oneOf", "anyOf"}:
                merged.setdefault(key, value)
        return merged

    def _deep_resolve_schema(
        self,
        schema: Union[Dict[str, Any], bool],
        depth: int = 20,
        *,
        _base_file: Optional[Path] = None,
        _seen: Optional[Set[str]] = None,
    ) -> Union[Dict[str, Any], bool]:
        """Recursively resolve schema refs, compositions, properties and items."""
        if not isinstance(schema, dict) or depth <= 0:
            return copy.deepcopy(schema)

        base_file = (_base_file or self._spec_file).resolve()
        seen = set() if _seen is None else set(_seen)
        working: Dict[str, Any] = copy.deepcopy(schema)

        if "$ref" in working:
            ref_uri = working["$ref"]
            target, target_file, cache_key = self._lookup_ref(ref_uri, base_file)
            if cache_key in seen:
                return working
            if not isinstance(target, (dict, bool)):
                raise ValueError(f"$ref '{ref_uri}' does not reference a schema")
            siblings = self._reference_siblings(working, schema=True)
            seen.add(cache_key)
            # Resolve the target and siblings separately; their local refs are
            # relative to different source documents. Retain both constraints.
            inherited = self._deep_resolve_schema(
                target, depth - 1, _base_file=target_file, _seen=seen
            )
            if not siblings:
                return inherited
            local = self._deep_resolve_schema(
                siblings, depth - 1, _base_file=base_file, _seen=_seen
            )
            combined: Dict[str, Any] = {"allOf": [inherited, local]}
            for branch in (inherited, local):
                if isinstance(branch, dict):
                    combined = self._merge_all_of(combined, branch)
            return combined

        resolved: Dict[str, Any] = dict(working)

        properties = working.get("properties")
        if isinstance(properties, dict):
            resolved["properties"] = {
                name: self._deep_resolve_schema(
                    value,
                    depth - 1,
                    _base_file=base_file,
                    _seen=seen,
                )
                if isinstance(value, dict)
                else copy.deepcopy(value)
                for name, value in properties.items()
            }

        items = working.get("items")
        if isinstance(items, dict):
            resolved["items"] = self._deep_resolve_schema(
                items, depth - 1, _base_file=base_file, _seen=seen
            )
        elif isinstance(items, list):
            resolved["items"] = [
                self._deep_resolve_schema(item, depth - 1, _base_file=base_file, _seen=seen)
                if isinstance(item, dict)
                else copy.deepcopy(item)
                for item in items
            ]

        additional = working.get("additionalProperties")
        if isinstance(additional, dict):
            resolved["additionalProperties"] = self._deep_resolve_schema(
                additional, depth - 1, _base_file=base_file, _seen=seen
            )

        for keyword in ("allOf", "oneOf", "anyOf"):
            branches = working.get(keyword)
            if not isinstance(branches, list):
                continue
            resolved_branches = [
                self._deep_resolve_schema(
                    branch, depth - 1, _base_file=base_file, _seen=seen
                )
                if isinstance(branch, dict)
                else copy.deepcopy(branch)
                for branch in branches
            ]
            resolved[keyword] = resolved_branches
            if keyword == "allOf":
                for branch in resolved_branches:
                    if isinstance(branch, dict):
                        resolved = self._merge_all_of(resolved, branch)

        for keyword in ("not", "contains", "propertyNames"):
            child = working.get(keyword)
            if isinstance(child, dict):
                resolved[keyword] = self._deep_resolve_schema(
                    child, depth - 1, _base_file=base_file, _seen=seen
                )

        return resolved

    def _resolve_parameter(self, parameter: Any, base_file: Optional[Path] = None) -> Dict[str, Any]:
        if not isinstance(parameter, dict):
            return {}
        current = copy.deepcopy(parameter)
        parameter_file = (base_file or self._spec_file).resolve()
        if "$ref" in current:
            resolved, parameter_file = self._resolve_ref_chain(
                current["$ref"], parameter_file, 20
            )
            if not isinstance(resolved, dict):
                return {}
            siblings = self._reference_siblings(current, schema=False)
            current = dict(resolved)
            current.update(siblings)

        schema = current.get("schema")
        if isinstance(schema, dict):
            current["schema"] = self._deep_resolve_schema(
                schema, _base_file=parameter_file
            )
        return current

    def _merge_parameters(
        self,
        path_parameters: Any,
        operation_parameters: Any,
        base_file: Optional[Path] = None,
    ) -> List[Dict[str, Any]]:
        """Apply OAS override semantics using the (name, in) identity tuple."""
        merged: List[Dict[str, Any]] = []
        positions: Dict[Tuple[Any, Any], int] = {}
        path_parameters = path_parameters if isinstance(path_parameters, list) else []
        operation_parameters = operation_parameters if isinstance(operation_parameters, list) else []
        for source in path_parameters + operation_parameters:
            parameter = self._resolve_parameter(source, base_file)
            if not parameter:
                continue
            identity = (parameter.get("name"), parameter.get("in"))
            if identity in positions:
                merged[positions[identity]] = parameter
            else:
                positions[identity] = len(merged)
                merged.append(parameter)
        return merged

    @staticmethod
    def _preferred_content_type(content: Dict[str, Any]) -> Optional[str]:
        if not content:
            return None
        if "application/json" in content:
            return "application/json"
        for media_type in content:
            normalized = media_type.split(";", 1)[0].strip().lower()
            if normalized.endswith("+json"):
                return media_type
        return next(iter(content), None)

    def _extract_request_body_details(
        self,
        op_data: Dict[str, Any],
        parameters: Optional[List[Dict[str, Any]]] = None,
        base_file: Optional[Path] = None,
    ) -> Tuple[Optional[Union[Dict[str, Any], bool]], Optional[str], List[str]]:
        request_body = op_data.get("requestBody", {})
        request_file = (base_file or self._spec_file).resolve()
        if isinstance(request_body, dict) and "$ref" in request_body:
            resolved, request_file = self._resolve_ref_chain(
                request_body["$ref"], request_file, 20
            )
            if isinstance(resolved, dict):
                siblings = self._reference_siblings(request_body, schema=False)
                request_body = dict(resolved)
                request_body.update(siblings)

        if isinstance(request_body, dict):
            content = request_body.get("content", {})
        else:
            content = {}
        content = content if isinstance(content, dict) else {}
        content_types = list(content)
        selected_type = self._preferred_content_type(content)
        if selected_type:
            media = content.get(selected_type, {})
            schema = media.get("schema", {}) if isinstance(media, dict) else {}
            if isinstance(schema, dict):
                return (
                    self._deep_resolve_schema(schema, _base_file=request_file),
                    selected_type,
                    content_types,
                )

        # Swagger 2.0 carries body schemas in a parameter and content types in
        # consumes. Use already merged parameters so overrides are respected.
        effective_parameters = parameters
        if effective_parameters is None:
            effective_parameters = [
                self._resolve_parameter(item, request_file) for item in op_data.get("parameters", [])
            ]
        for parameter in effective_parameters:
            if parameter.get("in") == "body" and isinstance(parameter.get("schema"), dict):
                consumes = op_data.get("consumes", self.raw_spec.get("consumes", ["application/json"]))
                consumes = consumes if isinstance(consumes, list) else [consumes]
                chosen = consumes[0] if consumes else "application/json"
                return parameter["schema"], chosen, list(consumes)

        return None, selected_type, content_types

    def _extract_request_body_schema(
        self,
        op_data: Dict[str, Any],
        parameters: Optional[List[Dict[str, Any]]] = None,
        base_file: Optional[Path] = None,
    ) -> Optional[Union[Dict[str, Any], bool]]:
        """Backward-compatible request schema helper."""
        schema, _, _ = self._extract_request_body_details(op_data, parameters, base_file)
        return schema

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Return normalized operations while preserving historical keys."""
        endpoints: List[Dict[str, Any]] = []
        paths = self.raw_spec.get("paths", {})
        if not isinstance(paths, dict):
            return endpoints

        for path_url, raw_path_item in paths.items():
            if not isinstance(raw_path_item, dict):
                continue
            path_item = raw_path_item
            path_file = self._spec_file
            if "$ref" in path_item:
                resolved, path_file = self._resolve_ref_chain(
                    path_item["$ref"], self._spec_file, 20
                )
                if isinstance(resolved, dict):
                    siblings = self._reference_siblings(path_item, schema=False)
                    path_item = dict(resolved)
                    path_item.update(siblings)

            common_parameters = path_item.get("parameters", [])
            for method in self.HTTP_METHODS:
                op_data = path_item.get(method)
                if not isinstance(op_data, dict):
                    continue

                parameters = self._merge_parameters(
                    common_parameters, op_data.get("parameters", []), path_file
                )
                request_schema, content_type, content_types = self._extract_request_body_details(
                    op_data, parameters, path_file
                )

                endpoints.append(
                    {
                        "path": path_url,
                        "method": method.upper(),
                        "operation_id": op_data.get("operationId", f"{method}_{path_url}"),
                        "summary": op_data.get("summary", ""),
                        "parameters": parameters,
                        "spec_version": str(self.raw_spec.get("openapi", self.raw_spec.get("swagger", ""))),
                        "request_schema": request_schema,
                        "request_content_type": content_type,
                        "request_content_types": content_types,
                        "security": op_data.get("security", self.raw_spec.get("security", [])),
                        "security_declared": "security" in op_data or "security" in self.raw_spec,
                    }
                )

        return endpoints
