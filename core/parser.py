# -*- coding: utf-8 -*-
"""OpenAPI 3.x / Swagger 2.0 specification parsing helpers.

The parser deliberately keeps its public endpoint shape small, but resolves the
parts that the scanner needs before returning them. References may point at the
root document or another JSON/YAML document below the root specification's
directory. Remote, absolute, and directory-traversing references are rejected
so loading an untrusted contract cannot read arbitrary local files. When remote
$ref resolution is explicitly enabled and authorized, external HTTPS schemas are
retrieved under strict SSRF, DNS rebinding, and resource limits.
"""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import unquote, urlsplit

from core.remote_refs import (
    RemoteRefConfig,
    RemoteRefDisabledError,
    RemoteRefError,
    RemoteRefFetcher,
    RemoteRefLimitExceededError,
    RemoteRefNotAllowedHostError,
    RemoteRefOfflineBlockedError,
    RemoteRefResolutionError,
    RemoteRefSecurityError,
    resolve_remote_reference_uri,
    sanitize_error_message,
    sanitize_ref_url,
    split_remote_ref,
)


class OpenAPIParser:
    """Load and normalize the subset of OpenAPI used by the auditor."""

    HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")

    def __init__(
        self,
        spec_path: str,
        remote_ref_config: Optional[RemoteRefConfig] = None,
        offline: bool = False,
    ):
        self.spec_path = str(spec_path)
        self._spec_file = Path(spec_path).expanduser().resolve()
        self._spec_dir = self._spec_file.parent
        self._document_cache: Dict[Path, Dict[str, Any]] = {}
        self._ref_cache: Dict[str, Any] = {}
        self._ref_file_cache: Dict[str, Union[Path, str]] = {}
        self._ref_depth_cost: Dict[str, int] = {}
        self.remote_ref_config = remote_ref_config
        self.offline = bool(offline)
        self.remote_fetcher: Optional[RemoteRefFetcher] = (
            RemoteRefFetcher(remote_ref_config)
            if (remote_ref_config is not None and not self.offline)
            else None
        )
        self.raw_spec: Dict[str, Any] = self._read_file(str(self._spec_file))
        self.version = self._detect_version()

    @property
    def max_remote_depth(self) -> int:
        if self.remote_ref_config is not None:
            return self.remote_ref_config.max_depth
        return 10

    @property
    def source_files(self) -> Tuple[Path, ...]:
        """Return an immutable snapshot of specification files actually read."""
        return tuple(self._document_cache)

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
                    try:
                        data = yaml.safe_load(handle)
                    except yaml.YAMLError as exc:
                        raise ValueError("Invalid YAML specification") from exc
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

    def _reference_target(
        self, ref_uri: object, base_context: Union[Path, str]
    ) -> Tuple[Union[Path, str], str, str]:
        if not isinstance(ref_uri, str) or not ref_uri:
            raise ValueError("$ref must be a non-empty string")

        parsed = urlsplit(ref_uri)
        clean_ref = sanitize_ref_url(ref_uri)
        if isinstance(base_context, str):
            # Base context is a remote document
            if parsed.scheme.lower() == "file":
                raise RemoteRefSecurityError(
                    f"Remote document cannot reference local files: {clean_ref}"
                )
            if self.offline:
                raise RemoteRefOfflineBlockedError(
                    f"Remote $ref resolution is blocked in offline mode: {clean_ref}"
                )
            if self.remote_ref_config is None or not self.remote_ref_config.allow_remote_refs:
                raise RemoteRefDisabledError(
                    f"Remote $ref resolution is disabled: {clean_ref}"
                )
            doc_url, fragment = resolve_remote_reference_uri(base_context, ref_uri)
            if self.remote_fetcher is not None:
                self.remote_fetcher.validate_ref_url(doc_url)
            cache_key = f"{doc_url}#{fragment}"
            return doc_url, fragment, cache_key

        # Base context is a local file (Path)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme.lower() == "file":
                raise ValueError(f"Remote $ref values are not supported: {clean_ref}")
            if self.offline:
                raise RemoteRefOfflineBlockedError(
                    f"Remote $ref resolution is blocked in offline mode: {clean_ref}"
                )
            if self.remote_ref_config is None or not self.remote_ref_config.allow_remote_refs:
                raise RemoteRefDisabledError(
                    f"Remote $ref values are not supported: {clean_ref}"
                )
            if not self.remote_ref_config.remote_ref_hosts:
                raise RemoteRefDisabledError(
                    f"Remote $ref values are not supported without authorized hosts: {clean_ref}"
                )
            if self.remote_fetcher is not None:
                self.remote_fetcher.validate_ref_url(ref_uri)
            doc_url, fragment = split_remote_ref(ref_uri)
            cache_key = f"{doc_url}#{fragment}"
            return doc_url, fragment, cache_key

        if parsed.query:
            raise ValueError(f"Query strings are not valid in local $ref values: {ref_uri}")

        raw_document_path = unquote(parsed.path)
        if raw_document_path:
            candidate = Path(raw_document_path)
            if candidate.is_absolute():
                raise ValueError(f"Absolute paths are not allowed in $ref values: {ref_uri}")
            target_file = (base_context.parent / candidate).resolve()
        else:
            target_file = base_context.resolve()

        try:
            common = Path(os.path.commonpath((str(self._spec_dir), str(target_file))))
        except ValueError as exc:
            raise ValueError(f"$ref escapes the specification directory: {ref_uri}") from exc
        if common != self._spec_dir:
            raise ValueError(f"$ref escapes the specification directory: {ref_uri}")

        fragment = unquote(parsed.fragment)
        cache_key = f"{target_file}#{fragment}"
        return target_file, fragment, cache_key

    def _lookup_ref(
        self, ref_uri: object, base_context: Union[Path, str]
    ) -> Tuple[Any, Union[Path, str], str]:
        target_doc, fragment, cache_key = self._reference_target(ref_uri, base_context)
        if isinstance(target_doc, Path):
            document = self._read_file(str(target_doc))
            doc_display: str = target_doc.name
        else:
            clean_ref = sanitize_ref_url(ref_uri)
            if self.offline:
                raise RemoteRefOfflineBlockedError(
                    f"Remote $ref resolution is blocked in offline mode: {clean_ref}"
                )
            if self.remote_fetcher is None:
                raise RemoteRefDisabledError(f"Remote $ref resolution is disabled: {clean_ref}")
            document = self.remote_fetcher.fetch_document(target_doc)
            doc_display = target_doc

        current: Any = document

        if fragment:
            if not fragment.startswith("/"):
                if isinstance(target_doc, str):
                    raise RemoteRefResolutionError(
                        f"Only JSON Pointer fragments are supported in remote $ref: {ref_uri}"
                    )
                raise ValueError(f"Only JSON Pointer fragments are supported in $ref: {ref_uri}")
            try:
                for raw_part in fragment[1:].split("/"):
                    part = self._decode_pointer_part(raw_part)
                    if isinstance(current, list):
                        if not part.isdigit() or (len(part) > 1 and part.startswith("0")):
                            if isinstance(target_doc, str):
                                raise RemoteRefResolutionError(
                                    f"Invalid array index in JSON Pointer for remote $ref: {ref_uri}"
                                )
                            raise ValueError("Invalid array index in JSON Pointer")
                        current = current[int(part)]
                    else:
                        current = current[part]
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                if isinstance(target_doc, str):
                    raise RemoteRefResolutionError(
                        f"Unresolved remote $ref '{ref_uri}' in '{doc_display}'"
                    ) from exc
                raise ValueError(f"Unresolved $ref '{ref_uri}' in '{doc_display}'") from exc

        return current, target_doc, cache_key

    def _resolve_ref_chain(
        self,
        ref_uri: object,
        base_context: Union[Path, str],
        max_depth: int = 20,
        seen: Optional[Set[str]] = None,
        *,
        remote_depth: int = 0,
    ) -> Tuple[Any, Union[Path, str], int]:
        """Resolve aliases while retaining the document context of the value."""
        if max_depth <= 0:
            if isinstance(base_context, str) or remote_depth > 0:
                raise RemoteRefLimitExceededError(
                    f"Reference depth limit ({self.max_remote_depth}) exceeded resolving remote ref: {ref_uri}"
                )
            raise ValueError(f"Reference depth limit exceeded resolving ref: {ref_uri}")

        target_doc, fragment, cache_key = self._reference_target(ref_uri, base_context)
        is_remote_step = isinstance(target_doc, str)
        current_remote_depth = remote_depth + (1 if is_remote_step else 0)
        if is_remote_step and current_remote_depth > self.max_remote_depth:
            raise RemoteRefLimitExceededError(
                f"Remote reference depth limit ({self.max_remote_depth}) exceeded at depth {current_remote_depth}: {ref_uri}"
            )

        chain = set() if seen is None else set(seen)
        if cache_key in chain:
            if is_remote_step or isinstance(base_context, str):
                raise RemoteRefResolutionError(
                    f"Circular reference detected in remote $ref chain: {ref_uri}"
                )
            return {"$ref": ref_uri}, target_doc, current_remote_depth

        if cache_key in self._ref_cache:
            depth_cost = self._ref_depth_cost.get(cache_key, 1 if is_remote_step else 0)
            accumulated_remote_depth = remote_depth + depth_cost
            if accumulated_remote_depth > self.max_remote_depth:
                raise RemoteRefLimitExceededError(
                    f"Remote reference depth limit ({self.max_remote_depth}) exceeded via cached reference at depth {accumulated_remote_depth}: {ref_uri}"
                )
            return (
                copy.deepcopy(self._ref_cache[cache_key]),
                self._ref_file_cache.get(cache_key, target_doc),
                accumulated_remote_depth,
            )

        target, target_doc, _ = self._lookup_ref(ref_uri, base_context)

        chain.add(cache_key)
        value = copy.deepcopy(target)
        if isinstance(value, dict) and "$ref" in value:
            nested_ref = value.get("$ref")
            siblings = self._reference_siblings(value, schema=False)
            resolved, resolved_doc, current_remote_depth = self._resolve_ref_chain(
                nested_ref,
                target_doc,
                max_depth - 1,
                chain,
                remote_depth=current_remote_depth,
            )
            if isinstance(resolved, dict):
                value = dict(resolved)
                value.update(siblings)
            else:
                value = resolved
            target_doc = resolved_doc

        # Do not cache an unresolved cycle marker.
        if not (isinstance(value, dict) and set(value) == {"$ref"}):
            self._ref_cache[cache_key] = copy.deepcopy(value)
            self._ref_file_cache[cache_key] = target_doc
            self._ref_depth_cost[cache_key] = current_remote_depth - remote_depth
        return value, target_doc, current_remote_depth

    def get_security_schemes(self) -> Dict[str, Dict[str, Any]]:
        """Resolve authentication definitions with the existing local-reference limits."""
        legacy = self.raw_spec.get("securityDefinitions", {})
        components = self.raw_spec.get("components", {})
        if not isinstance(legacy, dict) or not isinstance(components, dict):
            raise ValueError("Security scheme definitions must be objects; no request was sent")
        modern = components.get("securitySchemes", {})
        if not isinstance(modern, dict):
            raise ValueError("Security scheme definitions must be objects; no request was sent")
        schemes = dict(legacy)
        schemes.update(modern)
        resolved: Dict[str, Dict[str, Any]] = {}
        for name, scheme in schemes.items():
            if isinstance(scheme, dict) and "$ref" in scheme:
                ref_uri = scheme["$ref"]
                try:
                    self._reference_siblings(scheme, schema=False)
                    resolved_scheme, _, _ = self._resolve_ref_chain(ref_uri, self._spec_file, 20)
                    scheme = resolved_scheme
                except RemoteRefOfflineBlockedError:
                    raise
                except (OSError, TypeError, ValueError, RuntimeError, RemoteRefError):
                    raise ValueError(
                        "Authentication scheme reference cannot be resolved safely; no request was sent"
                    ) from None
            if (not isinstance(scheme, dict) or "$ref" in scheme
                    or not isinstance(scheme.get("type"), str)
                    or scheme.get("type") not in {"apiKey", "http", "basic", "oauth2", "openIdConnect", "mutualTLS"}
                    or (scheme.get("type") == "apiKey" and (
                        not isinstance(scheme.get("in"), str)
                        or scheme.get("in") not in {"header", "query", "cookie"}
                        or not isinstance(scheme.get("name"), str) or not scheme["name"].strip()))
                    or (scheme.get("type") == "http" and (
                        not isinstance(scheme.get("scheme"), str) or not scheme["scheme"].strip()))):
                raise ValueError(
                    "Authentication definition is not a supported security scheme; no request was sent"
                )
            if (scheme.get("type") == "apiKey" and scheme.get("in") in {"header", "cookie"}
                    and re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", scheme["name"]) is None):
                raise ValueError("Authentication parameter name is invalid; no request was sent")
            resolved[name] = scheme
        return resolved

    def resolve_ref(self, ref_uri: str, max_depth: int = 20) -> Dict[str, Any]:
        """Resolve a root-relative or local external ``$ref``.

        Malformed/nonexistent pointers, unsafe paths, and remote URLs raise
        ``ValueError`` or ``RemoteRefError`` rather than silently becoming an unconstrained schema.
        """
        target, target_doc, _ = self._lookup_ref(ref_uri, self._spec_file)
        value = self._deep_resolve_schema(target, max_depth, _base_context=target_doc)
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
            elif key not in {"allOf", "oneOf", "anyOf", "if", "then", "else"}:
                # Conditional keywords interact only within their own schema;
                # copying them out of separate allOf branches changes meaning.
                merged.setdefault(key, value)
        return merged

    def _deep_resolve_schema(
        self,
        schema: Union[Dict[str, Any], bool],
        depth: int = 20,
        *,
        _base_file: Optional[Union[Path, str]] = None,
        _base_context: Optional[Union[Path, str]] = None,
        _seen: Optional[Set[str]] = None,
        remote_depth: int = 0,
    ) -> Union[Dict[str, Any], bool]:
        """Recursively resolve schema refs, compositions, properties and items."""
        if not isinstance(schema, dict):
            return copy.deepcopy(schema)
        if depth <= 0:
            raw_ctx = _base_context if _base_context is not None else _base_file
            if isinstance(raw_ctx, str) or remote_depth > 0:
                raise RemoteRefLimitExceededError(
                    f"Schema recursion depth limit exceeded for remote schema: {schema}"
                )
            raise ValueError(f"Schema recursion depth limit exceeded: {schema}")

        raw_context = _base_context if _base_context is not None else _base_file
        base_context: Union[Path, str] = (
            raw_context if isinstance(raw_context, (Path, str)) else self._spec_file
        )
        # Recursive calls always pass an already resolved local path (or a
        # remote URL); skip the filesystem lookup there. Reference containment
        # is enforced on the resolved target in _reference_target either way.
        if _seen is None and isinstance(base_context, Path):
            base_context = base_context.resolve()
        seen = set() if _seen is None else set(_seen)
        working: Dict[str, Any] = copy.deepcopy(schema)

        if "$ref" in working:
            ref_uri = working["$ref"]
            target_doc, fragment, cache_key = self._reference_target(ref_uri, base_context)
            is_remote_step = isinstance(target_doc, str)
            current_remote_depth = remote_depth + (1 if is_remote_step else 0)
            if is_remote_step and current_remote_depth > self.max_remote_depth:
                raise RemoteRefLimitExceededError(
                    f"Remote reference depth limit ({self.max_remote_depth}) exceeded at depth {current_remote_depth}: {ref_uri}"
                )

            if cache_key in seen:
                if is_remote_step or isinstance(base_context, str):
                    raise RemoteRefResolutionError(
                        f"Circular remote schema reference detected: {ref_uri}"
                    )
                return working

            target, target_doc, _ = self._lookup_ref(ref_uri, base_context)
            if not isinstance(target, (dict, bool)):
                raise ValueError(f"$ref '{ref_uri}' does not reference a schema")
            siblings = self._reference_siblings(working, schema=True)
            seen.add(cache_key)
            # Resolve the target and siblings separately; their local refs are
            # relative to different source documents. Retain both constraints.
            inherited = self._deep_resolve_schema(
                target,
                depth - 1,
                _base_context=target_doc,
                _seen=seen,
                remote_depth=current_remote_depth,
            )
            if not siblings:
                return inherited
            local = self._deep_resolve_schema(
                siblings,
                depth - 1,
                _base_context=base_context,
                _seen=_seen,
                remote_depth=current_remote_depth,
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
                    _base_context=base_context,
                    _seen=seen,
                    remote_depth=remote_depth,
                )
                if isinstance(value, dict)
                else copy.deepcopy(value)
                for name, value in properties.items()
            }

        items = working.get("items")
        if isinstance(items, dict):
            resolved["items"] = self._deep_resolve_schema(
                items,
                depth - 1,
                _base_context=base_context,
                _seen=seen,
                remote_depth=remote_depth,
            )
        elif isinstance(items, list):
            resolved["items"] = [
                self._deep_resolve_schema(
                    item,
                    depth - 1,
                    _base_context=base_context,
                    _seen=seen,
                    remote_depth=remote_depth,
                )
                if isinstance(item, dict)
                else copy.deepcopy(item)
                for item in items
            ]

        additional = working.get("additionalProperties")
        if isinstance(additional, dict):
            resolved["additionalProperties"] = self._deep_resolve_schema(
                additional,
                depth - 1,
                _base_context=base_context,
                _seen=seen,
                remote_depth=remote_depth,
            )

        for keyword in ("allOf", "oneOf", "anyOf"):
            branches = working.get(keyword)
            if not isinstance(branches, list):
                continue
            resolved_branches = [
                self._deep_resolve_schema(
                    branch,
                    depth - 1,
                    _base_context=base_context,
                    _seen=seen,
                    remote_depth=remote_depth,
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

        for keyword in ("not", "contains", "propertyNames", "if", "then", "else", "additionalItems"):
            child = working.get(keyword)
            if isinstance(child, dict):
                resolved[keyword] = self._deep_resolve_schema(
                    child,
                    depth - 1,
                    _base_context=base_context,
                    _seen=seen,
                    remote_depth=remote_depth,
                )

        prefix_items = working.get("prefixItems")
        if isinstance(prefix_items, list):
            resolved["prefixItems"] = [
                self._deep_resolve_schema(
                    child,
                    depth - 1,
                    _base_context=base_context,
                    _seen=seen,
                    remote_depth=remote_depth,
                )
                if isinstance(child, dict) else copy.deepcopy(child)
                for child in prefix_items
            ]
        for keyword in ("patternProperties", "dependentSchemas", "dependencies"):
            children = working.get(keyword)
            if isinstance(children, dict):
                resolved[keyword] = {
                    name: self._deep_resolve_schema(
                        child,
                        depth - 1,
                        _base_context=base_context,
                        _seen=seen,
                        remote_depth=remote_depth,
                    )
                    if isinstance(child, dict) else copy.deepcopy(child)
                    for name, child in children.items()
                }

        return resolved

    def _resolve_parameter(
        self,
        parameter: Any,
        base_context: Optional[Union[Path, str]] = None,
        *,
        remote_depth: int = 0,
    ) -> Dict[str, Any]:
        if not isinstance(parameter, dict):
            return {}
        current = copy.deepcopy(parameter)
        param_context: Union[Path, str] = (
            base_context.resolve()
            if isinstance(base_context, Path)
            else (base_context if isinstance(base_context, str) else self._spec_file.resolve())
        )
        current_remote_depth = remote_depth
        if "$ref" in current:
            ref_uri = current["$ref"]
            resolved, param_context, current_remote_depth = self._resolve_ref_chain(
                ref_uri, param_context, 20, remote_depth=current_remote_depth
            )
            if not isinstance(resolved, dict):
                if isinstance(param_context, str) or current_remote_depth > 0:
                    raise RemoteRefResolutionError(
                        f"Parameter $ref '{ref_uri}' resolved to non-object: {type(resolved).__name__}"
                    )
                raise ValueError(f"Parameter $ref '{ref_uri}' resolved to non-object: {type(resolved).__name__}")
            if "$ref" in resolved and set(resolved) == {"$ref"}:
                if isinstance(param_context, str) or current_remote_depth > 0:
                    raise RemoteRefResolutionError(
                        f"Parameter $ref '{ref_uri}' could not be fully resolved"
                    )
                raise ValueError(f"Parameter $ref '{ref_uri}' could not be fully resolved")
            siblings = self._reference_siblings(current, schema=False)
            current = dict(resolved)
            current.update(siblings)

        schema = current.get("schema")
        if isinstance(schema, dict):
            current["schema"] = self._deep_resolve_schema(
                schema, _base_context=param_context, remote_depth=current_remote_depth
            )
        return current

    def _merge_parameters(
        self,
        path_parameters: Any,
        operation_parameters: Any,
        base_context: Optional[Union[Path, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Apply OAS override semantics using the (name, in) identity tuple."""
        merged: List[Dict[str, Any]] = []
        positions: Dict[Tuple[Any, Any], int] = {}
        path_parameters = path_parameters if isinstance(path_parameters, list) else []
        operation_parameters = operation_parameters if isinstance(operation_parameters, list) else []
        for source in path_parameters + operation_parameters:
            parameter = self._resolve_parameter(source, base_context)
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
        for media_type in content:
            if media_type.split(";", 1)[0].strip().lower() == "application/json":
                return media_type
        for media_type in content:
            normalized = media_type.split(";", 1)[0].strip().lower()
            if normalized.endswith("+json"):
                return media_type
        return next(iter(content), None)

    def _extract_request_body_details(
        self,
        op_data: Dict[str, Any],
        parameters: Optional[List[Dict[str, Any]]] = None,
        base_context: Optional[Union[Path, str]] = None,
        *,
        remote_depth: int = 0,
    ) -> Tuple[Optional[Union[Dict[str, Any], bool]], Optional[str], List[str]]:
        request_body = op_data.get("requestBody", {})
        request_context: Union[Path, str] = (
            base_context.resolve()
            if isinstance(base_context, Path)
            else (base_context if isinstance(base_context, str) else self._spec_file.resolve())
        )
        current_remote_depth = remote_depth
        if isinstance(request_body, dict) and "$ref" in request_body:
            body_ref = request_body["$ref"]
            resolved, request_context, current_remote_depth = self._resolve_ref_chain(
                body_ref, request_context, 20, remote_depth=current_remote_depth
            )
            if not isinstance(resolved, dict):
                if isinstance(request_context, str) or current_remote_depth > 0:
                    raise RemoteRefResolutionError(
                        f"requestBody $ref '{body_ref}' resolved to non-object: {type(resolved).__name__}"
                    )
                raise ValueError(f"requestBody $ref '{body_ref}' resolved to non-object: {type(resolved).__name__}")
            if "$ref" in resolved and set(resolved) == {"$ref"}:
                if isinstance(request_context, str) or current_remote_depth > 0:
                    raise RemoteRefResolutionError(
                        f"requestBody $ref '{body_ref}' could not be fully resolved"
                    )
                raise ValueError(f"requestBody $ref '{body_ref}' could not be fully resolved")
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
                resolved_schema = self._deep_resolve_schema(
                    schema,
                    _base_context=request_context,
                    remote_depth=current_remote_depth,
                )
                if isinstance(resolved_schema, dict) and "$ref" in resolved_schema and set(resolved_schema) == {"$ref"}:
                    if isinstance(request_context, str) or current_remote_depth > 0:
                        raise RemoteRefResolutionError(
                            f"requestBody schema $ref '{resolved_schema['$ref']}' could not be resolved safely"
                        )
                    raise ValueError("requestBody schema $ref could not be resolved safely")
                return (
                    resolved_schema,
                    selected_type,
                    content_types,
                )

        # Swagger 2.0 carries body schemas in a parameter and content types in
        # consumes. Use already merged parameters so overrides are respected.
        effective_parameters = parameters
        if effective_parameters is None:
            effective_parameters = [
                self._resolve_parameter(item, request_context, remote_depth=current_remote_depth)
                for item in op_data.get("parameters", [])
            ]
        for parameter in effective_parameters:
            if parameter.get("in") == "body" and isinstance(parameter.get("schema"), dict):
                consumes = op_data.get("consumes", self.raw_spec.get("consumes", ["application/json"]))
                consumes = consumes if isinstance(consumes, list) else [consumes]
                chosen = self._preferred_content_type({media: {} for media in consumes}) or "application/json"
                return parameter["schema"], chosen, list(consumes)

        return None, selected_type, content_types

    def _extract_request_body_schema(
        self,
        op_data: Dict[str, Any],
        parameters: Optional[List[Dict[str, Any]]] = None,
        base_context: Optional[Union[Path, str]] = None,
    ) -> Optional[Union[Dict[str, Any], bool]]:
        """Backward-compatible request schema helper."""
        schema, _, _ = self._extract_request_body_details(op_data, parameters, base_context)
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
            path_context: Union[Path, str] = self._spec_file
            path_error: Optional[str] = None
            if "$ref" in path_item:
                try:
                    resolved, path_context, _ = self._resolve_ref_chain(
                        path_item["$ref"], self._spec_file, 20
                    )
                    if isinstance(resolved, dict):
                        siblings = self._reference_siblings(path_item, schema=False)
                        path_item = dict(resolved)
                        path_item.update(siblings)
                except RemoteRefOfflineBlockedError as exc:
                    path_error = sanitize_error_message(str(exc))
                except (RemoteRefDisabledError, RemoteRefNotAllowedHostError, RemoteRefSecurityError):
                    raise
                except (RemoteRefResolutionError, RemoteRefLimitExceededError) as exc:
                    path_error = sanitize_error_message(str(exc))

            if path_error:
                endpoints.append(
                    {
                        "path": path_url,
                        "method": "UNKNOWN",
                        "operation_id": f"ref_{path_url}",
                        "summary": "",
                        "description": "",
                        "tags": [],
                        "parameters": [],
                        "spec_version": str(self.raw_spec.get("openapi", self.raw_spec.get("swagger", ""))),
                        "request_schema": None,
                        "request_content_type": None,
                        "request_content_types": [],
                        "security": [],
                        "security_declared": False,
                        "unresolved_schema_error": path_error,
                    }
                )
                continue

            common_parameters = path_item.get("parameters", [])
            for method in self.HTTP_METHODS:
                op_data = path_item.get(method)
                if not isinstance(op_data, dict):
                    continue

                op_error: Optional[str] = None
                parameters: List[Dict[str, Any]] = []
                request_schema = None
                content_type = None
                content_types: List[str] = []
                try:
                    parameters = self._merge_parameters(
                        common_parameters, op_data.get("parameters", []), path_context
                    )
                    request_schema, content_type, content_types = self._extract_request_body_details(
                        op_data, parameters, path_context
                    )
                except RemoteRefOfflineBlockedError as exc:
                    op_error = sanitize_error_message(str(exc))
                except (RemoteRefDisabledError, RemoteRefNotAllowedHostError, RemoteRefSecurityError):
                    raise
                except (RemoteRefResolutionError, RemoteRefLimitExceededError) as exc:
                    op_error = sanitize_error_message(str(exc))

                endpoint_record: Dict[str, Any] = {
                    "path": path_url,
                    "method": method.upper(),
                    "operation_id": op_data.get("operationId", f"{method}_{path_url}"),
                    "summary": op_data.get("summary", ""),
                    "description": op_data.get("description", ""),
                    "tags": op_data.get("tags", []),
                    "parameters": parameters,
                    "spec_version": str(self.raw_spec.get("openapi", self.raw_spec.get("swagger", ""))),
                    "request_schema": request_schema,
                    "request_content_type": content_type,
                    "request_content_types": content_types,
                    "security": op_data.get("security", self.raw_spec.get("security", [])),
                    "security_declared": "security" in op_data or "security" in self.raw_spec,
                }
                if op_error:
                    endpoint_record["unresolved_schema_error"] = op_error
                endpoints.append(endpoint_record)

        return endpoints
