"""Cross-checks between the configuration and the OpenAPI specification."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.config_validation.base import ConfigIssue, ValidatorBase
from core.generator import SmartDataGenerator
from core.models import parse_operation_key
from core.parameters import ParameterSerializationError, normalize_parameter_value
from core.parser import OpenAPIParser
from core.remote_refs import RemoteRefConfig, RemoteRefOfflineBlockedError, sanitize_error_message


class SpecChecks(ValidatorBase):
    """Operations, parameter schemas and authentication declared by the specification."""

    @classmethod
    def _validate_spec_cross_checks(
        cls, config: Dict[str, Any], raw_spec: Dict[str, Any], issues: List[ConfigIssue],
        *, spec_path: Optional[str], seen: Set[Tuple[str, str]], remote_ref_config: Optional[RemoteRefConfig] = None, offline: bool = True, allow_offline_unresolved: bool = False,
    ) -> None:
        try:
            if spec_path is not None:
                endpoints = OpenAPIParser(spec_path, remote_ref_config=remote_ref_config, offline=offline).get_endpoints()
            else:
                # A mapping has no base directory for relative file references.
                # A temporary root permits internal refs without guessing a source path.
                with tempfile.TemporaryDirectory(prefix="granttrace-config-spec-") as directory:
                    source = Path(directory) / "openapi.json"
                    source.write_text(json.dumps(raw_spec, allow_nan=False), encoding="utf-8")
                    endpoints = OpenAPIParser(
                        str(source),
                        remote_ref_config=remote_ref_config,
                        offline=offline,
                    ).get_endpoints()
        except RemoteRefOfflineBlockedError as exc:
            issues.append(ConfigIssue(
                path="<spec>",
                message=f"Specification contains remote $ref which cannot be fetched in offline validation mode: {exc}",
                expected="locally resolvable operations and parameter schemas without remote network requests",
                actual="unresolved_reference",
                suggestion="Provide a locally resolvable specification or run an online scan with --allow-remote-refs",
                is_warning=allow_offline_unresolved,
            ))
            return
        except Exception as exc:
            issues.append(ConfigIssue(
                path="<spec>",
                message=f"Selected specification operation metadata could not be resolved for cross-checking: {exc}",
                expected="locally resolvable operations and parameter schemas without remote network requests",
                actual=type(exc).__name__,
                suggestion=("Pass the original spec_path when validating a mapping with relative file references"
                            if spec_path is None else "Fix the specification's local references and supported schemas"),
            ))
            return

        for endpoint in endpoints:
            if endpoint.get("unresolved_schema_error"):
                sanitized_err = sanitize_error_message(endpoint["unresolved_schema_error"])
                issues.append(ConfigIssue(
                    path=f"{endpoint['method']} {endpoint['path']}",
                    message=f"Endpoint schema could not be resolved safely: {sanitized_err}",
                    expected="resolvable endpoint schema without unresolvable remote dependencies",
                    actual="unresolved_reference",
                    suggestion="Fix the reference or provide a resolvable local specification",
                    is_warning=allow_offline_unresolved,
                ))

        operations = {f"{endpoint['method']} {endpoint['path']}": endpoint for endpoint in endpoints}
        allowlist = config.get("write_allowlist")
        if isinstance(allowlist, list):
            for index, operation in enumerate(allowlist):
                cls._check_spec_operation(operation, f"write_allowlist[{index}]", operations, issues)
        for section in ("bola", "parameter_values", "readbacks"):
            entries = config.get(section)
            if isinstance(entries, dict):
                for operation in entries:
                    cls._check_spec_operation(operation, f"{section}.{operation}", operations, issues)

        bopla_entries = config.get("bopla")
        if isinstance(bopla_entries, dict):
            for index, operation in enumerate(bopla_entries):
                cls._check_spec_operation(operation, f"bopla[{index}]", operations, issues)

        for operation, endpoint in operations.items():
            # Anonymous probes reuse the selected Owner URL; they do not select
            # a separate resource from Anonymous parameter values.
            for role in ("owner", "visitor"):
                values, origins = cls._effective_parameter_values(config, operation, role)
                cls._check_parameter_schemas(endpoint.get("parameters"), values, origins, issues, seen)

        readbacks = config.get("readbacks")
        if not isinstance(readbacks, dict):
            return
        for operation, mapping in readbacks.items():
            if not isinstance(mapping, dict) or operation not in operations:
                continue
            method, path = mapping.get("method"), mapping.get("path")
            if method != "GET" or not isinstance(path, str) or not path.startswith("/"):
                continue
            read_operation = f"GET {path}"
            documented = operations.get(read_operation)
            if documented is None:
                issues.append(ConfigIssue(
                    path=f"readbacks.{operation}.path",
                    message="Independent GET readback is not declared in the selected specification",
                    expected="a documented GET operation, or a manually verified external readback contract",
                    actual="GET operation absent from specification",
                    suggestion="Confirm this readback path and its parameters manually; runtime readback and recovery checks still apply",
                    is_warning=True,
                ))
            values, origins = cls._effective_parameter_values(config, read_operation, "visitor")
            extra_values = mapping.get("parameter_values")
            if isinstance(extra_values, dict):
                values.update(extra_values)
                origins.update({name: f"readbacks.{operation}.parameter_values.{name}" for name in extra_values})
            if documented is not None:
                cls._check_parameter_schemas(documented.get("parameters"), values, origins, issues, seen)
            parameters = mapping.get("parameters", (documented or operations[operation]).get("parameters"))
            cls._check_parameter_schemas(parameters, values, origins, issues, seen)

    @classmethod
    def _validate_configured_readback_parameters(
        cls, config: Dict[str, Any], issues: List[ConfigIssue], seen: Set[Tuple[str, str]],
    ) -> None:
        readbacks = config.get("readbacks")
        if not isinstance(readbacks, dict):
            return
        for operation, mapping in readbacks.items():
            if not isinstance(mapping, dict):
                continue
            read_operation = f"{mapping.get('method')} {mapping.get('path')}"
            values, origins = cls._effective_parameter_values(config, read_operation, "visitor")
            extra_values = mapping.get("parameter_values")
            if isinstance(extra_values, dict):
                values.update(extra_values)
                origins.update({name: f"readbacks.{operation}.parameter_values.{name}" for name in extra_values})
            cls._check_parameter_schemas(mapping.get("parameters"), values, origins, issues, seen)

    @staticmethod
    def _check_spec_operation(
        operation: Any, path: str, operations: Dict[str, Dict[str, Any]], issues: List[ConfigIssue],
    ) -> None:
        valid, _, _, canonical, _ = parse_operation_key(operation)
        if valid and canonical not in operations:
            issues.append(ConfigIssue(
                path=path,
                message="Configured operation is not declared in the selected specification",
                expected="an exact METHOD /path operation in the selected specification",
                actual="operation absent from specification",
                suggestion="Correct the operation key or select the matching specification; unused entries are not applied",
            ))

    @staticmethod
    def _effective_parameter_values(
        config: Dict[str, Any], operation: str, role: str,
    ) -> Tuple[Dict[str, Any], Dict[str, str]]:
        values: Dict[str, Any] = {}
        origins: Dict[str, str] = {}

        def add(source: Any, prefix: str) -> None:
            if isinstance(source, dict):
                values.update(source)
                origins.update({name: f"{prefix}.{name}" for name in source})

        configured = config.get("parameter_values")
        entry = configured.get(operation) if isinstance(configured, dict) else None
        if isinstance(entry, dict):
            add(entry.get("common"), f"parameter_values.{operation}.common")
            add(entry.get(role), f"parameter_values.{operation}.{role}")
            add({name: value for name, value in entry.items()
                 if name not in {"common", "owner", "visitor", "anonymous"}}, f"parameter_values.{operation}")
        identities = config.get("identities")
        identity = identities.get(role) if isinstance(identities, dict) else None
        if isinstance(identity, dict):
            add(identity.get("parameters"), f"identities.{role}.parameters")
        return values, origins

    @staticmethod
    def _check_parameter_schemas(
        parameters: Any, values: Dict[str, Any], origins: Dict[str, str], issues: List[ConfigIssue],
        seen: Set[Tuple[str, str]],
    ) -> None:
        if not isinstance(parameters, list):
            return
        for parameter in parameters:
            if not isinstance(parameter, dict) or parameter.get("in") not in {"path", "query", "header", "cookie"}:
                continue
            name = parameter.get("name")
            if not isinstance(name, str) or name not in values:
                continue
            schema = parameter.get("schema", SmartDataGenerator.parameter_schema(parameter))
            try:
                normalized = normalize_parameter_value({**parameter, "schema": schema}, values[name])
                valid = SmartDataGenerator.validate_schema_value(normalized, schema, request=False)
            except ParameterSerializationError:
                valid = False
            if valid:
                continue
            key = (origins[name], json.dumps(schema, default=str))
            if key in seen:
                continue
            seen.add(key)
            issues.append(ConfigIssue(
                path=origins[name],
                message="Configured parameter value does not satisfy its declared supported schema",
                expected="the parameter's JSON type and supported enum, bounds and structural constraints",
                actual="value omitted",
                suggestion="Use native JSON types or canonical scalar strings; correct invalid values or unsupported constraints",
            ))

    @classmethod
    def _extract_spec_auth_headers(
        cls, raw_spec: Optional[Dict[str, Any]], *, spec_path: Optional[str] = None, remote_ref_config: Optional[RemoteRefConfig] = None, offline: bool = True,
    ) -> Set[str]:
        if not isinstance(raw_spec, dict) and spec_path is None:
            return set()
        try:
            if spec_path is not None:
                schemes = OpenAPIParser(
                    spec_path,
                    remote_ref_config=remote_ref_config,
                    offline=offline,
                ).get_security_schemes()
            else:
                # A mapping supplies no origin for external files. Internal refs
                # can still be resolved without guessing a local base directory.
                with tempfile.TemporaryDirectory(prefix="granttrace-auth-spec-") as directory:
                    source = Path(directory) / "openapi.json"
                    source.write_text(json.dumps(raw_spec, allow_nan=False), encoding="utf-8")
                    schemes = OpenAPIParser(
                        str(source),
                        remote_ref_config=remote_ref_config,
                        offline=offline,
                    ).get_security_schemes()
        except RemoteRefOfflineBlockedError:
            raise
        except (OSError, TypeError, ValueError, RuntimeError):
            raise ValueError("Security schemes could not be resolved safely from the selected specification") from None
        return {
            scheme["name"].lower()
            for scheme in schemes.values()
            if scheme.get("in") == "header" and scheme.get("name")
        }
