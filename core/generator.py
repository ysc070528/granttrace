# -*- coding: utf-8 -*-
"""Constraint-aware request data generation for GrantTrace."""

from __future__ import annotations

import copy
import datetime
import json
import math
import re
import uuid
from fractions import Fraction
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


JsonPathPart = Union[str, int]


class SchemaGenerationError(ValueError):
    """The bounded generator cannot construct a demonstrably valid request."""


class SmartDataGenerator:
    PRIVILEGE_KEYS = [
        "is_admin",
        "isAdmin",
        "admin",
        "role",
        "roles",
        "user_type",
        "privilege",
        "privileges",
        "permission",
        "permissions",
        "is_superuser",
        "superuser",
        "verified",
        "status",
        "group",
        "group_id",
        "tier",
        "plan",
        "credit",
        "balance",
    ]

    _NON_RESOURCE_PARAMETER_NAMES = {
        "page",
        "page_id",
        "page_size",
        "pagesize",
        "limit",
        "offset",
        "cursor",
        "sort",
        "order",
        "q",
        "query",
        "search",
        "filter",
    }
    _PARAMETER_SCHEMA_KEYS = {
        "type",
        "format",
        "enum",
        "default",
        "example",
        "examples",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "uniqueItems",
        "items",
        "nullable",
    }

    @classmethod
    def _parameter_schema(cls, param_meta: Dict[str, Any]) -> Dict[str, Any]:
        schema = param_meta.get("schema")
        if isinstance(schema, dict):
            return schema
        # Swagger 2.0 puts primitive parameter constraints directly on the
        # parameter instead of under a schema key.
        return {
            key: copy.deepcopy(value)
            for key, value in param_meta.items()
            if key in cls._PARAMETER_SCHEMA_KEYS
        }

    @classmethod
    def _is_resource_identifier(cls, param_meta: Dict[str, Any]) -> bool:
        original = str(param_meta.get("name", ""))
        normalized = re.sub(r"[-.\s]+", "_", original).lower()
        if normalized in cls._NON_RESOURCE_PARAMETER_NAMES:
            return False
        if normalized in {"id", "uuid", "uid", "resource_id", "object_id"}:
            return True
        if re.search(r"(?:^|_)(?:id|uuid|uid)$", normalized):
            return True
        return bool(re.search(r"(?:Id|ID|Uuid|UUID|Uid|UID)$", original))

    @staticmethod
    def _example_from_examples(examples: Any) -> Any:
        if isinstance(examples, list) and examples:
            return examples[0]
        if isinstance(examples, dict):
            for entry in examples.values():
                if isinstance(entry, dict) and "value" in entry:
                    return entry["value"]
                if not isinstance(entry, dict):
                    return entry
        return None

    @classmethod
    def _documented_values(
        cls, param_meta: Dict[str, Any], schema: Dict[str, Any]
    ) -> Iterable[Any]:
        if "example" in param_meta:
            yield param_meta["example"]
        parameter_example = cls._example_from_examples(param_meta.get("examples"))
        if parameter_example is not None:
            yield parameter_example
        if "example" in schema:
            yield schema["example"]
        schema_example = cls._example_from_examples(schema.get("examples"))
        if schema_example is not None:
            yield schema_example
        if "default" in schema:
            yield schema["default"]
        if "const" in schema:
            yield schema["const"]
        enum = schema.get("enum")
        if isinstance(enum, list):
            yield from enum

    @staticmethod
    def _coerce_for_schema(value: Any, schema: Dict[str, Any]) -> Any:
        schema_type = schema.get("type")
        if schema_type == "integer" and not isinstance(value, bool):
            try:
                return int(value)
            except (TypeError, ValueError):
                return value
        if schema_type == "number" and not isinstance(value, bool):
            try:
                return float(value)
            except (TypeError, ValueError):
                return value
        if schema_type == "boolean" and isinstance(value, str):
            if value.lower() in {"true", "1"}:
                return True
            if value.lower() in {"false", "0"}:
                return False
        if schema_type == "string" and value is not None:
            return str(value)
        return value

    @classmethod
    def _assert_supported_schema(cls, schema: Any) -> None:
        """Reject unknown evaluations before boolean/conditional composition.

        Unsupported is not equivalent to a schema mismatch: negating an
        unresolved reference, or using it as ``if``, must never make a request
        value valid. Inspect even inactive/absent child schemas so these cases
        cannot be hidden behind ``not``, alternatives or optional properties.
        """
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict):
            raise SchemaGenerationError("A schema must be an object or boolean")
        if any(key in schema for key in (
            "$ref", "$dynamicRef", "$recursiveRef", "unevaluatedProperties", "unevaluatedItems"
        )):
            raise SchemaGenerationError("A schema contains unresolved or unsupported evaluation constraints")
        schema_type = schema.get("type")
        if "type" in schema:
            types = schema_type if isinstance(schema_type, list) else [schema_type]
            if not types or any(not isinstance(kind, str) or kind not in {
                "null", "integer", "number", "boolean", "string", "array", "object"
            } for kind in types):
                raise SchemaGenerationError("A schema contains an unsupported type")
        for keyword in ("uniqueItems", "nullable", "readOnly", "writeOnly"):
            if keyword in schema and not isinstance(schema[keyword], bool):
                raise SchemaGenerationError("Schema boolean constraints/annotations must be booleans")
        if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
            raise SchemaGenerationError("A schema enum must be a non-empty array")
        for keyword in ("required", "dependentRequired"):
            if keyword not in schema:
                continue
            groups = [schema[keyword]] if keyword == "required" else schema[keyword]
            if keyword == "dependentRequired":
                if not isinstance(groups, dict):
                    raise SchemaGenerationError("dependentRequired must be an object")
                groups = list(groups.values())
            if any(not isinstance(group, list) or any(not isinstance(name, str) for name in group)
                   for group in groups):
                raise SchemaGenerationError("Required/dependent fields must be arrays of names")
        for keyword in ("minimum", "maximum", "multipleOf"):
            if keyword in schema:
                bound = schema[keyword]
                if isinstance(bound, bool) or not isinstance(bound, (int, float)) or not math.isfinite(bound):
                    raise SchemaGenerationError("Numeric schema constraints must be finite numbers")
                if keyword == "multipleOf" and bound <= 0:
                    raise SchemaGenerationError("multipleOf must be positive")
        for keyword in ("exclusiveMinimum", "exclusiveMaximum"):
            if keyword in schema and not isinstance(schema[keyword], bool):
                bound = schema[keyword]
                if not isinstance(bound, (int, float)) or not math.isfinite(bound):
                    raise SchemaGenerationError("Exclusive bounds must be booleans or finite numbers")
        for keyword in ("minLength", "maxLength", "minItems", "maxItems", "minProperties",
                        "maxProperties", "minContains", "maxContains"):
            if keyword in schema:
                count = schema[keyword]
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise SchemaGenerationError("Schema length/count constraints must be non-negative integers")
        if "pattern" in schema:
            re.compile(schema["pattern"])
        for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
            if keyword not in schema:
                continue
            children = schema[keyword]
            if not isinstance(children, list) or (keyword != "prefixItems" and not children):
                raise SchemaGenerationError("Schema composition must contain an array of schemas")
            for child in children:
                cls._assert_supported_schema(child)
        for keyword in ("not", "if", "then", "else", "contains", "propertyNames",
                        "additionalProperties", "additionalItems"):
            if keyword in schema:
                cls._assert_supported_schema(schema[keyword])
        if "items" in schema:
            children = schema["items"]
            for child in children if isinstance(children, list) else [children]:
                cls._assert_supported_schema(child)
        for keyword in ("properties", "patternProperties", "dependentSchemas", "dependencies"):
            if keyword not in schema:
                continue
            children = schema[keyword]
            if not isinstance(children, dict):
                raise SchemaGenerationError("Schema property/dependency definitions must be objects")
            for name, child in children.items():
                if keyword == "patternProperties":
                    re.compile(name)
                if keyword == "dependencies" and isinstance(child, list):
                    if any(not isinstance(item, str) for item in child):
                        raise SchemaGenerationError("Property dependencies must contain field names")
                else:
                    cls._assert_supported_schema(child)

    @classmethod
    def validate_schema_value(cls, value: Any, schema: Any, *, request: bool = True) -> bool:
        """Validate the supported schema subset recursively, failing closed.

        In request mode, required readOnly properties need not be supplied.
        readOnly is otherwise an annotation, so explicitly authorized injection
        probes can still validate the field's type and value constraints.
        Unresolved references and unsupported evaluation-dependent keywords
        return False. This is not a complete JSON Schema implementation.
        """
        try:
            cls._assert_supported_schema(schema)
            return cls._validate_schema_value(value, schema, request=request)
        except (TypeError, ValueError, OverflowError, RecursionError, re.error):
            return False

    @classmethod
    def _value_satisfies_schema(cls, value: Any, schema: Dict[str, Any]) -> bool:
        """Backward-compatible request-value validation helper."""
        return cls.validate_schema_value(value, schema)

    @classmethod
    def _validate_schema_value(cls, value: Any, schema: Any, *, request: bool) -> bool:
        if isinstance(schema, bool):
            return schema
        if not isinstance(schema, dict):
            return False
        if any(key in schema for key in (
            "$ref", "$dynamicRef", "$recursiveRef", "unevaluatedProperties", "unevaluatedItems"
        )):
            return False

        def check(candidate, child):
            return cls._validate_schema_value(candidate, child, request=request)

        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword not in schema:
                continue
            branches = schema[keyword]
            if not isinstance(branches, list) or not branches:
                return False
            matches = [check(value, child) for child in branches]
            if keyword == "allOf" and not all(matches):
                return False
            if keyword == "anyOf" and not any(matches):
                return False
            if keyword == "oneOf" and sum(matches) != 1:
                return False
        if "not" in schema and check(value, schema["not"]):
            return False
        if "if" in schema:
            selected = "then" if check(value, schema["if"]) else "else"
            if selected in schema and not check(value, schema[selected]):
                return False

        def json_equal(left: Any, right: Any) -> bool:
            # Python considers True == 1, but JSON Schema does not.
            if isinstance(left, bool) != isinstance(right, bool):
                return False
            if isinstance(left, dict) and isinstance(right, dict):
                return left.keys() == right.keys() and all(json_equal(left[k], right[k]) for k in left)
            if isinstance(left, list) and isinstance(right, list):
                return len(left) == len(right) and all(json_equal(a, b) for a, b in zip(left, right))
            return left == right

        if "const" in schema and not json_equal(value, schema["const"]):
            return False

        enum = schema.get("enum")
        if enum is not None and (not isinstance(enum, list) or not any(json_equal(value, item) for item in enum)):
            return False

        schema_type = schema.get("type")
        if value is None and schema.get("nullable"):
            return True
        if isinstance(schema_type, list):
            return any(
                check(value, {**schema, "type": item})
                for item in schema_type
            )
        if schema_type == "null":
            return value is None
        if value is None:
            return schema_type is None
        if schema_type is not None and schema_type not in {
            "integer", "number", "boolean", "string", "array", "object"
        }:
            return False
        if schema_type == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            return False
        if schema_type == "number" and (
            isinstance(value, bool) or not isinstance(value, (int, float))
        ):
            return False
        if schema_type == "boolean" and not isinstance(value, bool):
            return False
        if schema_type == "string" and not isinstance(value, str):
            return False
        if schema_type == "array" and not isinstance(value, list):
            return False
        if schema_type == "object" and not isinstance(value, dict):
            return False

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not math.isfinite(value):
                return False
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            exclusive_minimum = schema.get("exclusiveMinimum")
            exclusive_maximum = schema.get("exclusiveMaximum")
            if minimum is not None:
                if exclusive_minimum is True and value <= minimum:
                    return False
                if exclusive_minimum is not True and value < minimum:
                    return False
            if isinstance(exclusive_minimum, (int, float)) and not isinstance(exclusive_minimum, bool):
                if value <= exclusive_minimum:
                    return False
            if maximum is not None:
                if exclusive_maximum is True and value >= maximum:
                    return False
                if exclusive_maximum is not True and value > maximum:
                    return False
            if isinstance(exclusive_maximum, (int, float)) and not isinstance(exclusive_maximum, bool):
                if value >= exclusive_maximum:
                    return False
            multiple = schema.get("multipleOf")
            if isinstance(multiple, (int, float)) and multiple > 0:
                quotient = Fraction(str(value)) / Fraction(str(multiple))
                if quotient.denominator != 1:
                    return False

        if isinstance(value, str):
            if len(value) < int(schema.get("minLength", 0)):
                return False
            max_length = schema.get("maxLength")
            if max_length is not None and len(value) > int(max_length):
                return False
            pattern = schema.get("pattern")
            if pattern:
                try:
                    if re.search(str(pattern), value) is None:
                        return False
                except re.error:
                    return False
            fmt = str(schema.get("format", "")).lower()
            if fmt == "uuid":
                try:
                    uuid.UUID(value)
                except (ValueError, AttributeError):
                    return False
            elif fmt == "email" and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
                return False
            elif fmt == "date":
                try:
                    datetime.date.fromisoformat(value)
                except ValueError:
                    return False
            elif fmt == "date-time":
                try:
                    datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return False

        if isinstance(value, list):
            if len(value) < int(schema.get("minItems", 0)):
                return False
            max_items = schema.get("maxItems")
            if max_items is not None and len(value) > int(max_items):
                return False
            if schema.get("uniqueItems"):
                if any(json_equal(item, previous) for index, item in enumerate(value) for previous in value[:index]):
                    return False
            prefix = schema.get("prefixItems", [])
            items = schema.get("items", {})
            if isinstance(items, list):
                prefix, items = items, schema.get("additionalItems", {})
            if not all(check(item, prefix[index] if index < len(prefix) else items) for index, item in enumerate(value)):
                return False
            if "contains" in schema:
                count = sum(check(item, schema["contains"]) for item in value)
                if count < schema.get("minContains", 1) or count > schema.get("maxContains", math.inf):
                    return False

        if isinstance(value, dict):
            properties = schema.get("properties", {})
            if not isinstance(properties, dict):
                return False
            required = schema.get("required", [])
            for name in required:
                child = properties.get(name, {})
                effective = cls._effective_schema(child) if isinstance(child, dict) else {}
                if request and effective.get("readOnly"):
                    continue
                if name not in value:
                    return False
            if len(value) < schema.get("minProperties", 0) or len(value) > schema.get("maxProperties", math.inf):
                return False
            patterns = schema.get("patternProperties", {})
            for name, item in value.items():
                if "propertyNames" in schema and not check(name, schema["propertyNames"]):
                    return False
                if name in properties and not check(item, properties[name]):
                    return False
                matched = [child for pattern, child in patterns.items() if re.search(pattern, name)]
                if not all(check(item, child) for child in matched):
                    return False
                if name not in properties and not matched and not check(item, schema.get("additionalProperties", {})):
                    return False
            for name, dependencies in schema.get("dependentRequired", {}).items():
                if name in value and not all(key in value for key in dependencies):
                    return False
            for name, child in schema.get("dependentSchemas", {}).items():
                if name in value and not check(value, child):
                    return False
            for name, dependency in schema.get("dependencies", {}).items():
                if name in value:
                    if isinstance(dependency, list):
                        if not all(key in value for key in dependency):
                            return False
                    elif not check(value, dependency):
                        return False

        return True

    @staticmethod
    def _serialize_parameter_value(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, list):
            return ",".join(SmartDataGenerator._serialize_parameter_value(item) for item in value)
        if isinstance(value, dict):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return str(value)

    @classmethod
    def generate_value_for_param(
        cls, param_meta: Dict[str, Any], candidate_id: Optional[str] = None
    ) -> str:
        """Return the historical string representation for existing callers.

        Request builders should use ``generate_raw_value_for_param`` so arrays,
        objects and booleans retain their types until style-aware serialization.
        """
        return cls._serialize_parameter_value(cls.generate_raw_value_for_param(param_meta, candidate_id))

    @classmethod
    def generate_raw_value_for_param(
        cls, param_meta: Dict[str, Any], candidate_id: Optional[str] = None
    ) -> Any:
        """Generate a schema-valid parameter value without serializing it.

        ``candidate_id`` is applied only to parameters whose names identify a
        resource (for example ``user_id`` or ``documentUuid``). Paging, search,
        sorting, and unrelated query parameters continue to use their schemas.
        """
        schema = cls._parameter_schema(param_meta)

        if candidate_id is not None and cls._is_resource_identifier(param_meta):
            candidate = cls._coerce_for_schema(candidate_id, schema)
            if cls._value_satisfies_schema(candidate, schema):
                return candidate

        for documented in cls._documented_values(param_meta, schema):
            value = cls._coerce_for_schema(documented, schema)
            if cls._value_satisfies_schema(value, schema):
                return value

        if not schema:
            parameter_name = str(param_meta.get("name", "")).lower()
            return "test_user_id" if ("user" in parameter_name or "name" in parameter_name) else "sample_param"

        value = cls._generate_schema_sample(schema, include_optional=True, field_name=param_meta.get("name"))
        return value

    @classmethod
    def _numeric_bounds(cls, schema: Dict[str, Any]) -> Tuple[Any, bool, Any, bool]:
        bounds: List[Tuple[Any, bool]] = []
        for ordinary, exclusive, lower in (
            ("minimum", "exclusiveMinimum", True), ("maximum", "exclusiveMaximum", False)
        ):
            bound = schema.get(ordinary)
            strict = schema.get(exclusive) is True
            extra = schema.get(exclusive)
            if isinstance(extra, (int, float)) and not isinstance(extra, bool):
                if bound is None or (extra >= bound if lower else extra <= bound):
                    bound, strict = extra, True
            bounds.append((bound, strict))
        return bounds[0] + bounds[1]

    @classmethod
    def _numeric_sample(cls, schema: Dict[str, Any], integer: bool) -> Union[int, float]:
        lower, lower_strict, upper, upper_strict = cls._numeric_bounds(schema)
        if lower is not None and upper is not None:
            if lower > upper or (lower == upper and (lower_strict or upper_strict)):
                raise SchemaGenerationError("Numeric constraints have an empty intersection")
        multiple = schema.get("multipleOf")
        candidates: List[Any] = [0, 1, -1]
        if multiple is not None:
            if isinstance(multiple, bool) or multiple <= 0:
                raise SchemaGenerationError("multipleOf must be positive")
            step = Fraction(str(multiple))
            if integer:
                # Integer multiples of p/q are exactly multiples of p.
                step = Fraction(step.numerator)
            if lower is not None:
                count = math.ceil(Fraction(str(lower)) / step)
                if lower_strict and count * step <= Fraction(str(lower)):
                    count += 1
            elif upper is not None:
                count = math.floor(Fraction(str(upper)) / step)
                if upper_strict and count * step >= Fraction(str(upper)):
                    count -= 1
            else:
                count = 1
            candidates.insert(0, int(count * step) if integer else float(count * step))
        elif integer:
            if lower is not None:
                candidates.insert(0, math.floor(lower) + 1 if lower_strict else math.ceil(lower))
            if upper is not None:
                candidates.append(math.ceil(upper) - 1 if upper_strict else math.floor(upper))
        else:
            if lower is not None and upper is not None:
                candidates.insert(0, lower / 2 + upper / 2)
            if lower is not None:
                candidates.append(math.nextafter(float(lower), math.inf) if lower_strict else float(lower))
            if upper is not None:
                candidates.append(math.nextafter(float(upper), -math.inf) if upper_strict else float(upper))
        for candidate in candidates:
            if cls.validate_schema_value(candidate, schema):
                return int(candidate) if integer else float(candidate)
        raise SchemaGenerationError("Cannot construct a number satisfying all constraints")

    @staticmethod
    def _pattern_token(pattern: str) -> Optional[str]:
        """Synthesize common anchored regexes without adding a dependency."""
        source = pattern
        if source.startswith("^"):
            source = source[1:]
        if source.endswith("$") and not source.endswith("\\$"):
            source = source[:-1]

        result: List[str] = []
        index = 0
        try:
            while index < len(source):
                char = source[index]
                if char in "()|":
                    return None
                if char == "\\":
                    index += 1
                    token = source[index]
                    atom = {"d": "0", "w": "a", "s": " "}.get(token, token)
                elif char == "[":
                    end = source.index("]", index + 1)
                    content = source[index + 1 : end]
                    if content.startswith("^"):
                        return None
                    if "A-Z" in content:
                        atom = "A"
                    elif "a-z" in content:
                        atom = "a"
                    elif "0-9" in content or "\\d" in content:
                        atom = "0"
                    else:
                        atom = content[0] if content else "a"
                    index = end
                elif char == ".":
                    atom = "a"
                else:
                    atom = char

                repeat = 1
                if index + 1 < len(source):
                    next_char = source[index + 1]
                    if next_char == "{":
                        end = source.index("}", index + 2)
                        repeat = int(source[index + 2 : end].split(",", 1)[0] or "0")
                        index = end
                    elif next_char == "+":
                        repeat = 1
                        index += 1
                    elif next_char in "*?":
                        repeat = 0
                        index += 1
                result.append(atom * repeat)
                index += 1
        except (IndexError, ValueError):
            return None

        value = "".join(result)
        try:
            return value if re.search(pattern, value) is not None else None
        except re.error:
            return None

    @classmethod
    def _string_sample(cls, schema: Dict[str, Any], field_name: Optional[str]) -> str:
        fmt = str(schema.get("format", "")).lower()
        normalized_name = str(field_name or "").lower()
        if fmt == "uuid" or "uuid" in normalized_name:
            value = str(uuid.uuid4())
        elif fmt == "email" or "email" in normalized_name:
            value = "audit@example.com"
        elif fmt == "date-time":
            value = datetime.datetime.now(datetime.timezone.utc).isoformat()
        elif fmt == "date":
            value = datetime.date.today().isoformat()
        elif schema.get("pattern"):
            value = cls._pattern_token(str(schema["pattern"])) or "sample"
        elif "name" in normalized_name:
            value = "test_user"
        else:
            value = "sample_text"

        minimum = int(schema.get("minLength", 0))
        maximum_raw = schema.get("maxLength")
        maximum = int(maximum_raw) if maximum_raw is not None else None
        if len(value) < minimum:
            value += "a" * (minimum - len(value))
        if maximum is not None and len(value) > maximum:
            value = value[:maximum]
        return value

    @classmethod
    def _merge_constraints(cls, left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
        """Build an intersection view for synthesis, never last-wins constraints.

        Original schemas remain the authority for final recursive validation;
        this view intentionally does not claim to normalize all JSON Schema.
        """
        merged = copy.deepcopy(left)
        for key, value in right.items():
            if key not in merged:
                merged[key] = copy.deepcopy(value)
            elif key == "properties":
                for name, child in value.items():
                    old = merged[key].get(name)
                    merged[key][name] = copy.deepcopy(child) if old is None or old == child else {"allOf": [old, child]}
            elif key == "required":
                merged[key] = list(dict.fromkeys(merged[key] + value))
            elif key in {"minLength", "minItems", "minProperties", "minContains"}:
                merged[key] = max(merged[key], value)
            elif key in {"maxLength", "maxItems", "maxProperties", "maxContains"}:
                merged[key] = min(merged[key], value)
            elif key == "enum":
                merged[key] = [item for item in merged[key] if cls.validate_schema_value(item, {"enum": value})]
            elif key == "const" and merged[key] != value:
                merged["enum"] = []
            elif key == "type":
                old_types = merged[key] if isinstance(merged[key], list) else [merged[key]]
                new_types = value if isinstance(value, list) else [value]
                shared = [kind for kind in old_types if kind in new_types]
                if ("integer" in old_types and "number" in new_types) or ("number" in old_types and "integer" in new_types):
                    shared.append("integer")
                shared = list(dict.fromkeys(shared))
                merged[key] = shared[0] if len(shared) == 1 else shared
            elif key in {"readOnly", "writeOnly", "uniqueItems"}:
                merged[key] = bool(merged[key] or value)
            elif key == "multipleOf":
                a, b = Fraction(str(merged[key])), Fraction(str(value))
                if a <= 0 or b <= 0:
                    raise SchemaGenerationError("multipleOf must be positive")
                merged[key] = float(Fraction(math.lcm(a.numerator, b.numerator), math.gcd(a.denominator, b.denominator)))
            elif key in {"items", "additionalProperties"} and merged[key] != value:
                merged[key] = {"allOf": [merged[key], copy.deepcopy(value)]}

        for offset, ordinary, exclusive in (
            (0, "minimum", "exclusiveMinimum"), (2, "maximum", "exclusiveMaximum")
        ):
            bounds = [cls._numeric_bounds(item)[offset:offset + 2] for item in (left, right)]
            bounds = [item for item in bounds if item[0] is not None]
            if bounds:
                extreme = (max if offset == 0 else min)(item[0] for item in bounds)
                merged[ordinary] = extreme
                merged[exclusive] = any(strict for bound, strict in bounds if bound == extreme)
        return merged

    @classmethod
    def _effective_schema(cls, schema: Dict[str, Any]) -> Dict[str, Any]:
        if schema is True:
            return {}
        if schema is False:
            return {"enum": []}
        if not isinstance(schema, dict):
            raise SchemaGenerationError("A schema must be an object or boolean")
        effective = {key: copy.deepcopy(value) for key, value in schema.items() if key != "allOf"}
        branches = schema.get("allOf", [])
        if not isinstance(branches, list):
            raise SchemaGenerationError("allOf must be an array")
        for branch in branches:
            effective = cls._merge_constraints(effective, cls._effective_schema(branch))
        return effective

    @classmethod
    def _request_sample(cls, value: Any, schema: Any) -> Any:
        """Remove readOnly data from documented examples before using them."""
        effective = cls._effective_schema(schema)
        if isinstance(value, dict):
            properties = effective.get("properties", {})
            return {
                name: cls._request_sample(item, properties.get(name, {}))
                for name, item in value.items()
                if not cls._effective_schema(properties.get(name, {})).get("readOnly")
            }
        if isinstance(value, list):
            items = effective.get("items", {})
            prefix = effective.get("prefixItems", [])
            if isinstance(items, list):
                prefix, items = items, effective.get("additionalItems", {})
            return [cls._request_sample(item, prefix[index] if index < len(prefix) else items) for index, item in enumerate(value)]
        return copy.deepcopy(value)

    @classmethod
    def _generate_schema_sample(
        cls,
        schema: Dict[str, Any],
        *,
        include_optional: bool,
        field_name: Optional[str] = None,
    ) -> Any:
        if not isinstance(schema, (dict, bool)):
            raise SchemaGenerationError("A schema must be an object or boolean")
        effective = cls._effective_schema(schema)
        for documented in cls._documented_values({}, effective):
            candidate = cls._request_sample(documented, schema)
            if cls.validate_schema_value(candidate, schema):
                return candidate
        if "enum" in effective and not effective["enum"]:
            raise SchemaGenerationError("Schema constraints have an empty enum intersection")

        for keyword in ("oneOf", "anyOf"):
            if keyword not in effective:
                continue
            branches = effective[keyword]
            base = {key: value for key, value in effective.items() if key != keyword}
            for branch in branches:
                try:
                    candidate = cls._generate_schema_sample(
                        {"allOf": [base, branch]}, include_optional=include_optional, field_name=field_name
                    )
                except SchemaGenerationError:
                    continue
                if cls.validate_schema_value(candidate, schema):
                    return candidate
            raise SchemaGenerationError(f"Cannot construct a value satisfying {keyword}")

        candidate = cls._synthesize_schema_sample(effective, include_optional=include_optional, field_name=field_name)
        if not cls.validate_schema_value(candidate, schema):
            raise SchemaGenerationError(
                f"Cannot construct a valid value for {field_name or 'request body'}; "
                "constraints may conflict or require unsupported synthesis. Supply a valid example."
            )
        return candidate

    @classmethod
    def _synthesize_schema_sample(cls, effective: Dict[str, Any], *, include_optional: bool, field_name: Optional[str]) -> Any:
        if not effective:
            return {}

        schema_type = effective.get("type")
        if isinstance(schema_type, list):
            for kind in schema_type:
                try:
                    return cls._generate_schema_sample({**effective, "type": kind}, include_optional=include_optional, field_name=field_name)
                except SchemaGenerationError:
                    continue
            raise SchemaGenerationError("No allowed type yields a valid request value")
        if not schema_type:
            if "properties" in effective or "additionalProperties" in effective:
                schema_type = "object"
            elif "items" in effective:
                schema_type = "array"
            else:
                schema_type = "string"

        if schema_type == "object":
            properties = effective.get("properties", {})
            if not isinstance(properties, dict):
                raise SchemaGenerationError("Object properties must be a mapping")
            required = set(effective.get("required", []))
            result: Dict[str, Any] = {}
            for name, child in properties.items():
                if cls._effective_schema(child).get("readOnly"):
                    continue
                if include_optional or name in required or len(result) < effective.get("minProperties", 0):
                    result[name] = cls._generate_schema_sample(
                        child, include_optional=include_optional, field_name=name
                    )
            for name in required - set(properties):
                result[name] = cls._generate_schema_sample(
                    effective.get("additionalProperties", {}), include_optional=include_optional, field_name=name
                )
            return result

        if schema_type == "array":
            minimum = int(effective.get("minItems", 0))
            maximum_raw = effective.get("maxItems")
            maximum = int(maximum_raw) if maximum_raw is not None else None
            count = max(1, minimum) if include_optional else minimum
            if maximum is not None:
                count = min(count, maximum)
            item_schema = effective.get("items", {})
            prefix = effective.get("prefixItems", [])
            if isinstance(item_schema, list):
                prefix, item_schema = item_schema, effective.get("additionalItems", {})
            return [
                cls._generate_schema_sample(
                    prefix[index] if index < len(prefix) else item_schema,
                    include_optional=include_optional, field_name=field_name
                )
                for index in range(max(0, count))
            ]
        if schema_type == "integer":
            return cls._numeric_sample(effective, integer=True)
        if schema_type == "number":
            return cls._numeric_sample(effective, integer=False)
        if schema_type == "boolean":
            return False
        if schema_type == "null":
            return None
        return cls._string_sample(effective, field_name)

    @classmethod
    def generate_schema_sample(cls, schema: Dict[str, Any]) -> Any:
        """Backward-compatible full schema sample (includes optional fields)."""
        return cls._generate_schema_sample(schema, include_optional=True)

    @classmethod
    def build_baseline_body(
        cls, schema: Optional[Dict[str, Any]], *, include_optional: bool = False
    ) -> Any:
        """Build a valid baseline body, including required fields by default."""
        if schema is None:
            return {}
        return cls._generate_schema_sample(schema, include_optional=include_optional)

    # A descriptive alias for callers that prefer the word "valid".
    build_valid_baseline_body = build_baseline_body

    @classmethod
    def _normalized_privilege_names(cls) -> set:
        return {
            re.sub(r"[^a-z0-9]", "", key.lower())
            for key in cls.PRIVILEGE_KEYS
        }

    @classmethod
    def _is_privilege_key(cls, name: str) -> bool:
        normalized = re.sub(r"[^a-z0-9]", "", name.lower())
        targets = cls._normalized_privilege_names()
        if normalized in targets:
            return True
        if any(normalized.endswith(target) for target in targets if len(target) >= 4):
            return True
        # Preserve the old detector's useful handling of names such as
        # account_role while avoiding matches in arbitrary prose-like names.
        tokens = [
            re.sub(r"[^a-z0-9]", "", token)
            for token in re.split(r"[_\-.\s]+", name.lower())
        ]
        return any(token in targets for token in tokens if token)

    @classmethod
    def _iter_privilege_fields(
        cls,
        schema: Dict[str, Any],
        path: Tuple[JsonPathPart, ...] = (),
    ) -> Iterable[Tuple[Tuple[JsonPathPart, ...], Dict[str, Any]]]:
        effective = cls._effective_schema(schema)
        for keyword in ("oneOf", "anyOf"):
            for branch in effective.get(keyword, []):
                if isinstance(branch, dict):
                    yield from cls._iter_privilege_fields(branch, path)
        properties = effective.get("properties", {})
        if not isinstance(properties, dict):
            return
        for name, child in properties.items():
            # readOnly describes normal writes; it is precisely a useful
            # protected-field candidate for authorized mass-assignment tests.
            if not isinstance(child, dict):
                continue
            child_path = path + (name,)
            if cls._is_privilege_key(name):
                yield child_path, child

            child_effective = cls._effective_schema(child)
            child_type = child_effective.get("type")
            if child_type == "object" or "properties" in child_effective:
                yield from cls._iter_privilege_fields(child_effective, child_path)
            elif child_type == "array" and isinstance(child_effective.get("items"), dict):
                item_schema = cls._effective_schema(child_effective["items"])
                if item_schema.get("type") == "object" or "properties" in item_schema:
                    yield from cls._iter_privilege_fields(item_schema, child_path + (0,))

    @classmethod
    def _mutation_value(cls, field_name: str, schema: Dict[str, Any]) -> Any:
        effective = cls._effective_schema(schema)
        schema_type = effective.get("type")
        if not schema_type:
            if "properties" in effective:
                schema_type = "object"
            elif "items" in effective:
                schema_type = "array"
            else:
                schema_type = "string"

        normalized = field_name.lower()
        if schema_type == "boolean":
            candidates: Sequence[Any] = (True, False)
        elif schema_type in {"integer", "number"}:
            maximum = effective.get("maximum")
            candidates = (maximum, 1, cls._numeric_sample(effective, schema_type == "integer"))
        elif schema_type == "array":
            item_schema = effective.get("items", {})
            item_schema = item_schema if isinstance(item_schema, dict) else {}
            item_value = cls._mutation_value(field_name, item_schema)
            count = max(1, int(effective.get("minItems", 0)))
            maximum = effective.get("maxItems")
            if maximum is not None:
                count = min(count, int(maximum))
            candidates = ([copy.deepcopy(item_value) for _ in range(max(0, count))],)
        elif schema_type == "object":
            candidates = (cls._generate_schema_sample(effective, include_optional=True),)
        else:
            if any(word in normalized for word in ("role", "admin", "user_type")):
                preferred = ("admin", "superuser", "root")
            elif any(word in normalized for word in ("permission", "privilege")):
                preferred = ("root", "*", "admin")
            elif normalized in {"status", "verified"}:
                preferred = ("active", "verified", "admin")
            elif normalized in {"tier", "plan", "group", "group_id"}:
                preferred = ("enterprise", "premium", "admin")
            else:
                preferred = ("admin", "root", "superuser")
            enum = effective.get("enum")
            if isinstance(enum, list):
                ordered_enum = [value for value in preferred if value in enum]
                ordered_enum.extend(value for value in enum if value not in ordered_enum)
                candidates = tuple(ordered_enum) + preferred
            else:
                candidates = preferred

        for candidate in candidates:
            if candidate is None:
                continue
            coerced = cls._coerce_for_schema(candidate, effective)
            if cls._value_satisfies_schema(coerced, effective):
                return copy.deepcopy(coerced)
        return cls._generate_schema_sample(
            effective, include_optional=True, field_name=field_name
        )

    @staticmethod
    def _set_path(container: Any, path: Tuple[JsonPathPart, ...], value: Any) -> Any:
        if not path:
            return copy.deepcopy(value)
        root = copy.deepcopy(container)
        if not isinstance(root, (dict, list)):
            root = [] if isinstance(path[0], int) else {}
        current = root
        for index, part in enumerate(path):
            final = index == len(path) - 1
            next_part = None if final else path[index + 1]
            if isinstance(part, int):
                if not isinstance(current, list):
                    raise TypeError("Numeric mutation path requires a list container")
                while len(current) <= part:
                    current.append([] if isinstance(next_part, int) else {})
                if final:
                    current[part] = copy.deepcopy(value)
                else:
                    if not isinstance(current[part], (dict, list)):
                        current[part] = [] if isinstance(next_part, int) else {}
                    current = current[part]
            else:
                if not isinstance(current, dict):
                    raise TypeError("Named mutation path requires an object container")
                if final:
                    current[part] = copy.deepcopy(value)
                else:
                    expected = list if isinstance(next_part, int) else dict
                    if not isinstance(current.get(part), expected):
                        current[part] = [] if isinstance(next_part, int) else {}
                    current = current[part]
        return root

    @staticmethod
    def _format_path(path: Tuple[JsonPathPart, ...]) -> str:
        output = ""
        for part in path:
            if isinstance(part, int):
                output += f"[{part}]"
            else:
                output += ("." if output else "") + part
        return output

    @classmethod
    def build_mass_assignment_cases(
        cls,
        schema: Optional[Dict[str, Any]],
        baseline: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Return complete one-field-at-a-time mutation cases.

        Each result contains ``field_path`` (dot/bracket notation), ``path``
        (tuple form), ``value``, ``mutation`` (sparse body), and ``payload``
        (the valid baseline plus only that mutation).
        """
        effective_schema = schema if isinstance(schema, dict) else {}
        base = (
            copy.deepcopy(baseline)
            if baseline is not None
            else cls.build_baseline_body(effective_schema)
        )
        cases: List[Dict[str, Any]] = []
        fields = []
        seen_fields = set()
        for path, field_schema in cls._iter_privilege_fields(effective_schema):
            if path not in seen_fields:
                fields.append((path, field_schema))
                seen_fields.add(path)
        if not fields:
            fields = [
                (("role",), {"type": "string", "enum": ["admin"]}),
                (("is_admin",), {"type": "boolean"}),
                (("privilege",), {"type": "string", "enum": ["root"]}),
                (("user_type",), {"type": "string", "enum": ["superuser"]}),
            ]

        for path, field_schema in fields:
            field_name = str(next((part for part in reversed(path) if isinstance(part, str)), ""))
            value = cls._mutation_value(field_name, field_schema)
            mutation = cls._set_path({}, path, value)
            payload = cls._set_path(base, path, value)
            cases.append(
                {
                    "field_path": cls._format_path(path),
                    "path": path,
                    "value": value,
                    "mutation": mutation,
                    "payload": payload,
                }
            )
        return cases

    @classmethod
    def build_mass_assignment_payloads(
        cls,
        schema: Optional[Dict[str, Any]],
        baseline: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Convenience view returning just complete payloads for each case."""
        return [case["payload"] for case in cls.build_mass_assignment_cases(schema, baseline)]

    @classmethod
    def build_mass_assignment_payload(cls, schema: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Return the historical combined sparse mutation payload.

        New callers should prefer :meth:`build_mass_assignment_cases` so each
        dangerous field is tested independently.
        """
        combined: Dict[str, Any] = {}
        for case in cls.build_mass_assignment_cases(schema, baseline={}):
            combined = cls._deep_merge(combined, case["mutation"])
        return combined

    @classmethod
    def _deep_merge(cls, left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
        merged = copy.deepcopy(left)
        for key, value in right.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = cls._deep_merge(merged[key], value)
            elif isinstance(value, list) and isinstance(merged.get(key), list):
                result = copy.deepcopy(merged[key])
                for index, item in enumerate(value):
                    if index < len(result) and isinstance(item, dict) and isinstance(result[index], dict):
                        result[index] = cls._deep_merge(result[index], item)
                    elif index < len(result):
                        result[index] = copy.deepcopy(item)
                    else:
                        result.append(copy.deepcopy(item))
                merged[key] = result
            else:
                merged[key] = copy.deepcopy(value)
        return merged
