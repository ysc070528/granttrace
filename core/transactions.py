"""Prepare reversible object PATCH bodies from observed resource state.

Generated/example values select fields, but never become ordinary business
values sent to the server. Nested containers and arrays are copied in full.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

from core.models import json_values_equal


def path_parts(path: Any) -> Tuple[Any, ...]:
    if isinstance(path, (list, tuple)):
        parts = tuple(path)
        if not parts or any(not isinstance(p, (str, int)) or isinstance(p, bool) for p in parts):
            raise ValueError("invalid field path")
        if any(isinstance(p, int) and p < 0 for p in parts):
            raise ValueError("negative array indexes are unsupported")
        return parts
    if not isinstance(path, str) or not path:
        raise ValueError("field path must be non-empty")
    result = []
    offset = 0
    for match in re.finditer(r"(?:^|\.)([^.\[\]]+)|\[(\d+)\]", path):
        if match.start() != offset:
            raise ValueError("invalid dot/bracket field path")
        result.append(int(match.group(2)) if match.group(2) is not None else match.group(1))
        offset = match.end()
    if offset != len(path) or not result:
        raise ValueError("invalid dot/bracket field path")
    return tuple(result)


def paths_collide(path_a: Sequence[Any], path_b: Sequence[Any]) -> bool:
    """Return True if path_a is equal to, a parent of, or a child of path_b."""
    if not path_a or not path_b:
        return False
    min_len = min(len(path_a), len(path_b))
    return tuple(path_a[:min_len]) == tuple(path_b[:min_len])


def get_path(value: Any, path: Any) -> Tuple[bool, Any]:
    current = value
    for part in path_parts(path):
        if isinstance(part, str) and isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(part, int) and isinstance(current, list) and 0 <= part < len(current):
            current = current[part]
        else:
            return False, None
    return True, current


def replace_path(value: Dict[str, Any], path: Any, replacement: Any) -> None:
    """Replace an existing leaf. Never invent partial arrays or containers."""
    parts = path_parts(path)
    current: Any = value
    for index, part in enumerate(parts):
        found, child = get_path(current, (part,))
        if not found:
            raise ValueError("mutation path is absent in the full snapshot")
        if index == len(parts) - 1:
            current[part] = copy.deepcopy(replacement)
        else:
            current = child


@dataclass
class PatchSnapshot:
    mutation: Dict[str, Any]
    restore: Dict[str, Any]
    guards: List[Tuple[Tuple[Any, ...], Any]]
    read_path: Tuple[Any, ...]
    original: Any
    target: Any
    document: Dict[str, Any]
    ignored_paths: List[Tuple[Any, ...]]

    def _comparison_document(self, document: Dict[str, Any]) -> Dict[str, Any]:
        result = copy.deepcopy(document)
        for path in self.ignored_paths:
            exists, parent = get_path(result, path[:-1]) if len(path) > 1 else (True, result)
            if not exists:
                continue
            leaf = path[-1]
            if isinstance(parent, dict) and isinstance(leaf, str):
                parent.pop(leaf, None)
            elif isinstance(parent, list) and isinstance(leaf, int) and leaf < len(parent):
                parent[leaf] = "[EXPLICITLY_IGNORED_VOLATILE_VALUE]"
        return result

    def matches(self, document: Any) -> bool:
        if not isinstance(document, dict):
            return False
        return (all(get_path(document, path) == (True, value) for path, value in self.guards)
                and json_values_equal(self._comparison_document(document),
                                      self._comparison_document(self.document)))


def prepare_patch(before: Dict[str, Any], case: Dict[str, Any], mapping: Dict[str, Any]) -> PatchSnapshot:
    if not isinstance(before, dict) or not json_values_equal(before, before):
        raise ValueError("original snapshot must be a finite, JSON-serializable object")
    mutation_path = path_parts(case.get("path", case["field_path"]))
    read_path = path_parts(mapping["field_map"][case["field_path"]])
    found, original = get_path(before, read_path)
    if not found:
        raise ValueError("probe field has no original value to restore")
    target = copy.deepcopy(case["value"])
    if json_values_equal(target, original):
        raise ValueError("probe equals the original value; a distinct probe is required")
    template = copy.deepcopy(case.get("payload") or {})
    baseline = mapping.get("baseline_payload", {})
    if not isinstance(template, dict) or not isinstance(baseline, dict):
        raise ValueError("PATCH baseline must be an object")
    template.update(baseline)
    root = mutation_path[0]
    if not isinstance(root, str):
        raise ValueError("only object PATCH bodies are supported")
    template.setdefault(root, None)
    container_map = mapping.get("snapshot_field_map", {})
    if not isinstance(container_map, dict):
        raise ValueError("snapshot_field_map must be an object")
    prefix = path_parts(mapping["snapshot_path"]) if mapping.get("snapshot_path") else ()
    restore: Dict[str, Any] = {}
    guards: List[Tuple[Tuple[Any, ...], Any]] = []
    for key in template:
        if key in container_map:
            source_path = path_parts(container_map[key])
        elif key == root:
            tail = mutation_path[1:]
            if tail and read_path[-len(tail):] != tail:
                raise ValueError("nested field mapping requires an explicit snapshot_field_map")
            source_path = read_path[:-len(tail)] if tail else read_path
            if not source_path:
                raise ValueError("cannot map PATCH container to a readback container")
        else:
            source_path = prefix + (key,)
        exists, value = get_path(before, source_path)
        if not exists:
            raise ValueError("a field in the PATCH body has no recoverable snapshot: " + str(key))
        restore[key] = copy.deepcopy(value)
        guards.append((source_path, copy.deepcopy(value)))
    request_exists, request_original = get_path(restore, mutation_path)
    if not request_exists or not json_values_equal(request_original, original):
        raise ValueError("request and readback field mappings disagree")
    mutation = copy.deepcopy(restore)
    replace_path(mutation, mutation_path, target)
    ignored = mapping.get("ignore_readback_paths", [])
    if not isinstance(ignored, list):
        raise ValueError("ignore_readback_paths must be a list")
    ignored_paths = [path_parts(path) for path in ignored]
    for ignored_path in ignored_paths:
        if paths_collide(mutation_path, ignored_path) or any(
            paths_collide(source, ignored_path) for source, _ in guards
        ):
            raise ValueError("cannot ignore any part of a written field/container snapshot")
    snapshot = PatchSnapshot(mutation, restore, guards, read_path, copy.deepcopy(original), target,
                             copy.deepcopy(before), ignored_paths)
    if (not snapshot.matches(before) or not json_values_equal(mutation, mutation)
            or not json_values_equal(restore, restore)):
        raise ValueError("PATCH snapshot and request payloads must be verifiable finite JSON")
    return snapshot
