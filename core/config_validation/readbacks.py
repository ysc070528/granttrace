"""Validation of write tests: the write allowlist, readbacks and parameter values."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Set, Tuple

from core.config_validation.base import ConfigIssue, ValidationSummary, ValidatorBase
from core.evidence import safe_diagnostic_value
from core.models import parse_operation_key
from core.transactions import path_parts, paths_collide


class ReadbackChecks(ValidatorBase):
    """Write allowlist, readback mappings and per-operation parameter values."""

    @classmethod
    def _validate_write_allowlist_section(
        cls,
        allowlist: Any,
        issues: List[ConfigIssue],
        summary: ValidationSummary,
        allowlisted_set: Set[str],
    ) -> None:
        if not isinstance(allowlist, list):
            issues.append(
                ConfigIssue(
                    path="write_allowlist",
                    message="'write_allowlist' must be a list of 'PATCH /path' or 'PUT /path' strings",
                    expected="list of strings",
                    actual=safe_diagnostic_value(allowlist),
                )
            )
            return

        for index, item in enumerate(allowlist):
            is_valid, method, path, canonical, err_msg = parse_operation_key(item)
            if not is_valid:
                issues.append(
                    ConfigIssue(
                        path=f"write_allowlist[{index}]",
                        message=f"Write allowlist entry is invalid: {err_msg}",
                        expected="'PATCH /case-sensitive-path'",
                        actual=safe_diagnostic_value(item),
                        suggestion="Ensure method is uppercase 'PATCH' followed by a space and a path starting with '/'",
                    )
                )
            elif method not in ("PATCH", "PUT"):
                issues.append(
                    ConfigIssue(
                        path=f"write_allowlist[{index}]",
                        message=f"Write allowlist only supports 'PATCH' and 'PUT' operations (got '{method}')",
                        expected="'PATCH /path'",
                        actual=safe_diagnostic_value(item),
                        suggestion="Change method to 'PATCH'",
                    )
                )
            else:
                allowlisted_set.add(canonical)
                summary.allowlisted_endpoints += 1

    @classmethod
    def _validate_readbacks_section(
        cls,
        readbacks: Any,
        issues: List[ConfigIssue],
        summary: ValidationSummary,
        readbacks_set: Set[str],
    ) -> None:
        if not isinstance(readbacks, dict):
            issues.append(
                ConfigIssue(
                    path="readbacks",
                    message="'readbacks' must be an object mapping 'PATCH /path' to readback definitions",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(readbacks),
                )
            )
            return

        for op_key, rb_data in readbacks.items():
            is_valid, method, path, canonical, err_msg = parse_operation_key(op_key)
            if not is_valid:
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}",
                        message=f"Invalid readback operation key: {err_msg}",
                        expected="'PATCH /path'",
                        actual=safe_diagnostic_value(op_key),
                    )
                )
            elif method not in ("PATCH", "PUT"):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}",
                        message=f"Readback keys must strictly be 'PATCH /path' or 'PUT /path' operations (got '{method}')",
                        expected="'PATCH /path'",
                        actual=safe_diagnostic_value(op_key),
                    )
                )
            else:
                readbacks_set.add(canonical)

            if not isinstance(rb_data, dict):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}",
                        message=f"Readback definition for '{op_key}' must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(rb_data),
                    )
                )
                continue

            summary.readbacks_count += 1
            cls._validate_single_readback(op_key, rb_data, issues)

    @classmethod
    def _validate_single_readback(
        cls,
        op_key: str,
        readback: Dict[str, Any],
        issues: List[ConfigIssue],
    ) -> None:
        # Sections run in this order so issues are reported in configuration order.
        cls._validate_readback_request(op_key, readback, issues)
        cls._validate_readback_parameters(op_key, readback, issues)
        parsed_written_paths, parsed_readback_paths = cls._validate_readback_field_map(op_key, readback, issues)
        cls._validate_readback_polling(op_key, readback, issues)
        cls._validate_readback_snapshot(op_key, readback, issues, parsed_written_paths, parsed_readback_paths)

    @classmethod
    def _validate_readback_request(
        cls,
        op_key: str,
        readback: Dict[str, Any],
        issues: List[ConfigIssue],
    ) -> None:
        """Unknown keys, the GET method and the readback path."""
        # Check unknown keys
        for key in readback.keys():
            if key not in cls.KNOWN_READBACK_KEYS:
                closest = cls._find_closest_match(str(key), sorted(cls.KNOWN_READBACK_KEYS))
                suggestion = f"Did you mean '{closest}'?" if closest else None
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.{key}",
                        message=f"Unrecognized field '{key}' in readback configuration",
                        expected=f"one of {sorted(cls.KNOWN_READBACK_KEYS)}",
                        actual=safe_diagnostic_value(key),
                        suggestion=suggestion,
                    )
                )

        # method (Required to be uppercase GET)
        method = readback.get("method")
        if method is None:
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.method",
                    message="Readback requires an explicit 'method' specifying 'GET'",
                    expected="'GET'",
                    actual="missing",
                )
            )
        elif not isinstance(method, str):
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.method",
                    message="Readback method must be a string",
                    expected="'GET'",
                    actual=safe_diagnostic_value(method),
                )
            )
        elif method != "GET":
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.method",
                    message=f"Readback method must strictly be uppercase 'GET' (got '{method}')",
                    expected="'GET'",
                    actual=safe_diagnostic_value(method),
                    suggestion="Set method to 'GET'",
                )
            )

        # path (Required, starts with /)
        path = readback.get("path")
        if path is None:
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.path",
                    message="Readback requires an explicit 'path'",
                    expected="string path starting with '/'",
                    actual="missing",
                )
            )
        elif not isinstance(path, str) or not path.startswith("/") or any(c in path for c in "\r\n\t "):
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.path",
                    message="Readback path must be a clean string starting with '/' without whitespace",
                    expected="string starting with '/'",
                    actual=safe_diagnostic_value(path),
                )
            )

    @classmethod
    def _validate_readback_parameters(
        cls,
        op_key: str,
        readback: Dict[str, Any],
        issues: List[ConfigIssue],
    ) -> None:
        """Readback parameter objects and their parameter_values."""
        # The readback URL builder consumes a list of Parameter Objects directly;
        # mappings, reference objects, and unsupported locations are not expanded.
        if "parameters" in readback:
            parameters = readback["parameters"]
            if not isinstance(parameters, list):
                issues.append(ConfigIssue(
                    path=f"readbacks.{op_key}.parameters",
                    message="Readback parameters must be an array of path/query parameter objects",
                    expected="list of objects with name, in, and schema",
                    actual=safe_diagnostic_value(parameters),
                ))
            else:
                identities: Set[Tuple[str, str]] = set()
                for index, parameter in enumerate(parameters):
                    parameter_path = f"readbacks.{op_key}.parameters[{index}]"
                    if not isinstance(parameter, dict):
                        issues.append(ConfigIssue(
                            path=parameter_path,
                            message="Readback parameter must be an object",
                            expected="object with name, in, and schema",
                            actual=safe_diagnostic_value(parameter),
                        ))
                        continue
                    name, location = parameter.get("name"), parameter.get("in")
                    valid_name = isinstance(name, str) and bool(name) and not any(
                        character.isspace() or ord(character) < 32 for character in name
                    )
                    if not valid_name:
                        issues.append(ConfigIssue(
                            path=parameter_path + ".name",
                            message="Readback parameter name must be a non-empty clean string",
                            expected="non-empty name without whitespace or control characters",
                            actual=safe_diagnostic_value(name),
                        ))
                    if location not in ("path", "query"):
                        issues.append(ConfigIssue(
                            path=parameter_path + ".in",
                            message="Readback parameter location must be supported by the URL builder",
                            expected="'path' or 'query'",
                            actual=safe_diagnostic_value(location),
                        ))
                    if not isinstance(parameter.get("schema"), dict):
                        issues.append(ConfigIssue(
                            path=parameter_path + ".schema",
                            message="Readback parameter requires a schema object",
                            expected="JSON object",
                            actual=safe_diagnostic_value(parameter.get("schema")),
                        ))
                    if (
                        valid_name and isinstance(name, str) and isinstance(location, str)
                        and location in ("path", "query")
                    ):
                        identity = (name, location)
                        if identity in identities:
                            issues.append(ConfigIssue(
                                path=parameter_path,
                                message="Duplicate readback parameter name and location",
                                expected="unique (name, in) pair",
                                actual=safe_diagnostic_value(name),
                            ))
                        identities.add(identity)

        if "parameter_values" in readback:
            values = readback["parameter_values"]
            if not isinstance(values, dict):
                issues.append(ConfigIssue(
                    path=f"readbacks.{op_key}.parameter_values",
                    message="Readback parameter_values must be an object",
                    expected="parameter name -> value object",
                    actual=safe_diagnostic_value(values),
                ))
            else:
                for name in values:
                    if not isinstance(name, str) or not name or any(
                        character.isspace() or ord(character) < 32 for character in name
                    ):
                        issues.append(ConfigIssue(
                            path=f"readbacks.{op_key}.parameter_values",
                            message="Readback parameter value names must be non-empty clean strings",
                            expected="non-empty names without whitespace or control characters",
                            actual=safe_diagnostic_value(name),
                        ))

    @classmethod
    def _validate_readback_field_map(
        cls,
        op_key: str,
        readback: Dict[str, Any],
        issues: List[ConfigIssue],
    ) -> Tuple[List[Tuple[Any, ...]], List[Tuple[Any, ...]]]:
        """The written-to-readback field map; returns the parsed written and readback paths."""
        # field_map (Required, non-empty dict of valid_path -> valid_path)
        field_map = readback.get("field_map")
        parsed_written_paths: List[Tuple[Any, ...]] = []
        parsed_readback_paths: List[Tuple[Any, ...]] = []
        if field_map is None:
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.field_map",
                    message="Readback requires an explicit non-empty 'field_map'",
                    expected="non-empty object mapping write field path to readback field path",
                    actual="missing",
                )
            )
        elif not isinstance(field_map, dict) or len(field_map) == 0:
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.field_map",
                    message="'field_map' must be a non-empty object mapping write fields to readback paths",
                    expected="non-empty dict",
                    actual=safe_diagnostic_value(field_map),
                )
            )
        else:
            for w_path, r_path in field_map.items():
                if not isinstance(w_path, str) or not isinstance(r_path, str):
                    issues.append(
                        ConfigIssue(
                            path=f"readbacks.{op_key}.field_map",
                            message="field_map keys and values must be string path expressions",
                            expected="string -> string",
                            actual=f"{safe_diagnostic_value(w_path)} -> {safe_diagnostic_value(r_path)}",
                        )
                    )
                    continue

                # Verify dot/bracket path syntax compatible with transactions.path_parts
                try:
                    parts_w = path_parts(w_path)
                    parsed_written_paths.append(parts_w)
                except ValueError as exc:
                    issues.append(
                        ConfigIssue(
                            path=f"readbacks.{op_key}.field_map.{w_path}",
                            message=f"Invalid mutation path expression in field_map: {exc}",
                            expected="valid dot/bracket path (e.g. 'role', 'members[0].role')",
                            actual=safe_diagnostic_value(w_path),
                        )
                    )
                try:
                    parts_r = path_parts(r_path)
                    parsed_readback_paths.append(parts_r)
                except ValueError as exc:
                    issues.append(
                        ConfigIssue(
                            path=f"readbacks.{op_key}.field_map.{w_path}",
                            message=f"Invalid readback path expression in field_map: {exc}",
                            expected="valid dot/bracket path (e.g. 'data.role')",
                            actual=safe_diagnostic_value(r_path),
                        )
                    )

        return parsed_written_paths, parsed_readback_paths

    @classmethod
    def _validate_readback_polling(
        cls,
        op_key: str,
        readback: Dict[str, Any],
        issues: List[ConfigIssue],
    ) -> None:
        """Consistency, readback attempts and delay."""
        # consistency (Optional enum: strong, weak, eventual)
        consistency = readback.get("consistency")
        if consistency is not None:
            if not isinstance(consistency, str) or consistency not in cls.VALID_CONSISTENCY_VALUES:
                closest = cls._find_closest_match(
                    str(consistency).lower(), cls.VALID_CONSISTENCY_VALUES
                )
                suggestion = f"Did you mean '{closest}'?" if closest else None
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.consistency",
                        message=f"Invalid readback consistency '{consistency}'",
                        expected=f"one of {list(cls.VALID_CONSISTENCY_VALUES)}",
                        actual=safe_diagnostic_value(consistency),
                        suggestion=suggestion,
                    )
                )

        # readback_attempts (int in [1, 10], not bool)
        attempts = readback.get("readback_attempts")
        if attempts is not None:
            if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1 or attempts > 10:
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.readback_attempts",
                        message="readback_attempts must be an integer between 1 and 10",
                        expected="integer in range [1, 10]",
                        actual=safe_diagnostic_value(attempts),
                    )
                )

        # readback_delay (float or int in [0.0, 5.0], not bool, finite)
        delay = readback.get("readback_delay")
        if delay is not None:
            if (
                not isinstance(delay, (int, float))
                or isinstance(delay, bool)
                or math.isnan(delay)
                or math.isinf(delay)
                or delay < 0.0
                or delay > 5.0
            ):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.readback_delay",
                        message="readback_delay must be a finite number between 0.0 and 5.0 seconds",
                        expected="number in range [0.0, 5.0]",
                        actual=safe_diagnostic_value(delay),
                    )
                )

    @classmethod
    def _validate_readback_snapshot(
        cls,
        op_key: str,
        readback: Dict[str, Any],
        issues: List[ConfigIssue],
        parsed_written_paths: List[Tuple[Any, ...]],
        parsed_readback_paths: List[Tuple[Any, ...]],
    ) -> None:
        """Snapshot paths, baseline payload and ignored readback paths."""
        # snapshot_path
        snapshot_path = readback.get("snapshot_path")
        if snapshot_path is not None:
            if not isinstance(snapshot_path, str):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.snapshot_path",
                        message="snapshot_path must be a string dot/bracket path",
                        expected="string path",
                        actual=safe_diagnostic_value(snapshot_path),
                    )
                )
            else:
                try:
                    parts_sp = path_parts(snapshot_path)
                    parsed_readback_paths.append(parts_sp)
                except ValueError as exc:
                    issues.append(
                        ConfigIssue(
                            path=f"readbacks.{op_key}.snapshot_path",
                            message=f"Invalid snapshot_path expression: {exc}",
                            expected="valid dot/bracket path",
                            actual=safe_diagnostic_value(snapshot_path),
                        )
                    )

        # snapshot_field_map
        snapshot_field_map = readback.get("snapshot_field_map")
        if snapshot_field_map is not None:
            if not isinstance(snapshot_field_map, dict):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.snapshot_field_map",
                        message="snapshot_field_map must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(snapshot_field_map),
                    )
                )
            else:
                for k, v in snapshot_field_map.items():
                    if not isinstance(k, str) or not isinstance(v, str):
                        issues.append(
                            ConfigIssue(
                                path=f"readbacks.{op_key}.snapshot_field_map",
                                message="snapshot_field_map keys and values must be strings",
                                expected="string -> string",
                                actual=f"{safe_diagnostic_value(k)} -> {safe_diagnostic_value(v)}",
                            )
                        )
                    else:
                        for p in (k, v):
                            try:
                                path_parts(p)
                            except ValueError as exc:
                                issues.append(
                                    ConfigIssue(
                                        path=f"readbacks.{op_key}.snapshot_field_map",
                                        message=f"Invalid path in snapshot_field_map: {exc}",
                                        expected="valid dot/bracket path",
                                        actual=safe_diagnostic_value(p),
                                    )
                                )
                        try:
                            parsed_written_paths.append(path_parts(k))
                            parsed_readback_paths.append(path_parts(v))
                        except ValueError:
                            pass

        # baseline_payload
        baseline_payload = readback.get("baseline_payload")
        if baseline_payload is not None and not isinstance(baseline_payload, dict):
            issues.append(
                ConfigIssue(
                    path=f"readbacks.{op_key}.baseline_payload",
                    message="baseline_payload must be an object",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(baseline_payload),
                )
            )

        # ignore_readback_paths & collision check with written and readback fields (parent, child, exact)
        ignored_paths = readback.get("ignore_readback_paths")
        if ignored_paths is not None:
            if not isinstance(ignored_paths, list) or any(not isinstance(p, str) for p in ignored_paths):
                issues.append(
                    ConfigIssue(
                        path=f"readbacks.{op_key}.ignore_readback_paths",
                        message="ignore_readback_paths must be a list of field path strings",
                        expected="list of strings",
                        actual=safe_diagnostic_value(ignored_paths),
                    )
                )
            else:
                for ignored in ignored_paths:
                    try:
                        ig_parts = path_parts(ignored)
                    except ValueError as exc:
                        issues.append(
                            ConfigIssue(
                                path=f"readbacks.{op_key}.ignore_readback_paths",
                                message=f"Invalid path in ignore_readback_paths: {exc}",
                                expected="valid dot/bracket path",
                                actual=safe_diagnostic_value(ignored),
                            )
                        )
                        continue

                    # Collision: ignored path cannot match, be a parent of, or be a child of any written field
                    for w_parts in parsed_written_paths:
                        if paths_collide(ig_parts, w_parts):
                            w_str = ".".join(str(p) for p in w_parts)
                            issues.append(
                                ConfigIssue(
                                    path=f"readbacks.{op_key}.ignore_readback_paths",
                                    message=f"Dangerous ignore_readback_paths entry '{ignored}' collides with written field '{w_str}' in field_map",
                                    expected="only non-written volatile fields (e.g. 'updatedAt')",
                                    actual=f"written field or its parent/child path '{ignored}' is ignored",
                                    suggestion="Never ignore written probe fields or their parent/child paths during rollback verification",
                                )
                            )
                    # Collision: ignored path cannot match, be a parent of, or be a child of any readback field
                    for r_parts in parsed_readback_paths:
                        if paths_collide(ig_parts, r_parts):
                            r_str = ".".join(str(p) for p in r_parts)
                            issues.append(
                                ConfigIssue(
                                    path=f"readbacks.{op_key}.ignore_readback_paths",
                                    message=f"Dangerous ignore_readback_paths entry '{ignored}' collides with readback field '{r_str}' in field_map",
                                    expected="only non-written volatile fields (e.g. 'updatedAt')",
                                    actual=f"readback field or its parent/child path '{ignored}' is ignored",
                                    suggestion="Never ignore readback target fields or their parent/child paths during rollback verification",
                                )
                            )

    @classmethod
    def _validate_parameter_values_section(
        cls,
        parameter_values: Any,
        issues: List[ConfigIssue],
        summary: ValidationSummary,
    ) -> None:
        if not isinstance(parameter_values, dict):
            issues.append(
                ConfigIssue(
                    path="parameter_values",
                    message="'parameter_values' must be an object indexed by 'METHOD /path'",
                    expected="dict / JSON object",
                    actual=safe_diagnostic_value(parameter_values),
                )
            )
            return

        for ep_key, values in parameter_values.items():
            is_valid, method, path, canonical, err_msg = parse_operation_key(ep_key)
            if not is_valid:
                issues.append(
                    ConfigIssue(
                        path=f"parameter_values.{ep_key}",
                        message=f"Invalid operation key in parameter_values: {err_msg}",
                        expected="'METHOD /path' (e.g. 'GET /api/users/{id}')",
                        actual=safe_diagnostic_value(ep_key),
                    )
                )
            if not isinstance(values, dict):
                issues.append(
                    ConfigIssue(
                        path=f"parameter_values.{ep_key}",
                        message=f"Parameter values for '{ep_key}' must be an object",
                        expected="dict / JSON object",
                        actual=safe_diagnostic_value(values),
                    )
                )
            else:
                summary.parameter_endpoints += 1
                for k, v in values.items():
                    if not isinstance(k, str) or not k.strip():
                        issues.append(
                            ConfigIssue(
                                path=f"parameter_values.{ep_key}",
                                message="Parameter names must be non-empty strings",
                                expected="non-empty string key",
                                actual=safe_diagnostic_value(k),
                            )
                        )
