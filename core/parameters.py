"""Strict parameter serialization shared by scans and readbacks.

Supported contracts follow the OpenAPI Parameter Object rules:
https://spec.openapis.org/oas/v3.0.4.html#parameter-object
https://spec.openapis.org/oas/v2.0.html#parameter-object

Values are validated and encoded individually before joining, so data cannot
introduce URL syntax or HTTP header/cookie injection. Unsupported or ambiguous
formats fail before any request is sent. Authentication credentials remain
strictly governed by the requester identity context.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Dict, List, NoReturn, Tuple
from urllib.parse import quote

from core.generator import SmartDataGenerator


class ParameterSerializationError(ValueError):
    """A parameter cannot be represented safely using its declared contract."""


def _fail(message: str) -> NoReturn:
    # Diagnostics intentionally omit parameter values, which may be credentials.
    raise ParameterSerializationError(message + "; no request was sent")


def normalize_parameter_value(metadata: Dict[str, Any], value: Any, *, swagger2: bool = False) -> Any:
    """Normalize only unambiguous canonical scalar strings, preserving wire text.

    Legacy configuration may store an integer/number/boolean parameter as a
    string. Conversion is allowed only when its declared type is explicit and
    the resulting native value has exactly the same serialized representation.
    Containers, declared strings and multi-type unions are never coerced.
    Callers must still validate the complete schema after normalization.
    """
    if not isinstance(metadata, dict):
        _fail("Parameter metadata must be an object")
    schema = metadata.get("schema", SmartDataGenerator._parameter_schema(metadata) if swagger2 else {})
    if not isinstance(value, str) or not isinstance(schema, dict):
        return value
    declared = schema.get("type")
    if isinstance(declared, list):
        if any(not isinstance(kind, str) for kind in declared):
            return value
        nonnull = [kind for kind in declared if kind != "null"]
        if len(nonnull) != 1 or len(declared) > 2 or len(set(declared)) != len(declared):
            return value
        declared = nonnull[0]
    if declared == "integer":
        if re.fullmatch(r"(?:0|-?[1-9][0-9]*)", value) is None:
            _fail("Integer parameter strings must use canonical ASCII integer notation")
        try:
            return int(value)
        except ValueError:
            _fail("Integer parameter string cannot be represented safely")
    if declared == "boolean":
        if value == "true":
            return True
        if value == "false":
            return False
        _fail("Boolean parameter strings must be exactly lowercase true or false")
    if declared == "number":
        if re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", value) is None:
            _fail("Number parameter strings must use canonical JSON number notation")
        try:
            parsed = json.loads(value)
            if not math.isfinite(parsed) or str(parsed) != value:
                _fail("Number parameter strings must retain their native wire representation without precision loss")
            return parsed
        except (ValueError, OverflowError):
            _fail("Number parameter string cannot be represented safely")
    return value


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return str(value)
    _fail("Only finite scalar parameter values are supported; null and nested values are unsupported")


def _encoded(value: Any, *, label: bool = False) -> str:
    text = _scalar(value)
    encoded = quote(text, safe="")
    # quote always leaves unreserved dots alone. A standalone dot segment or
    # an exploded label's dot delimiter must not change the selected resource.
    if label or text in {".", ".."}:
        encoded = encoded.replace(".", "%2E")
    return encoded


def _kind(value: Any) -> str:
    if isinstance(value, list):
        if not value:
            _fail("Empty array parameter serialization is unsupported")
        for item in value:
            _scalar(item)
        return "array"
    if isinstance(value, dict):
        if not value:
            _fail("Empty object parameter serialization is unsupported")
        if any(not isinstance(key, str) for key in value):
            _fail("Object parameter property names must be strings")
        for item in value.values():
            _scalar(item)
        return "object"
    _scalar(value)
    return "primitive"


def _settings(metadata: Dict[str, Any], value: Any, swagger2: bool) -> Tuple[str, str, str, bool]:
    if not isinstance(metadata, dict):
        _fail("Parameter metadata must be an object")
    location = metadata.get("in")
    name = metadata.get("name")
    if not isinstance(location, str) or location not in {"path", "query", "header", "cookie"}:
        _fail("Only path/query/header/cookie parameter serialization is supported; formData/unsupported parameters are unsupported")
    if swagger2 and location == "cookie":
        _fail("Swagger 2 does not support cookie parameters")
    if not isinstance(name, str) or not name or any(ord(char) < 32 for char in name):
        _fail("Parameter name must be a non-empty string without control characters")
    if location == "header" and not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9a-zA-Z]+", name):
        _fail("Header parameter name must be a valid RFC 7230 token without whitespace or control characters")
    if location == "cookie" and not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9a-zA-Z]+", name):
        _fail("Cookie parameter name must be a valid RFC 6265 token without whitespace or separators")
    if "$ref" in metadata:
        _fail("Unresolved parameter references are unsupported")
    if "content" in metadata:
        _fail("Content-based parameter serialization is unsupported; use a supported schema/style contract")
    if "allowReserved" in metadata:
        if not isinstance(metadata["allowReserved"], bool):
            _fail("allowReserved must be a boolean")
        if metadata["allowReserved"]:
            _fail("allowReserved=true parameter serialization is unsupported")
    kind = _kind(value)
    if location == "path" and kind == "primitive" and _scalar(value) == "":
        _fail("Empty path parameter values are unsupported because they can select a different resource")
    if location == "cookie":
        if kind != "primitive":
            _fail("Array and object cookie parameter serialization is ambiguous and unsupported")
        text = _scalar(value)
        if any(ord(c) < 33 or ord(c) >= 127 or c in '\",;\\' for c in text):
            _fail("Cookie parameter value contains invalid characters, line breaks, or separators (CRLF or semicolon injection prevented)")
    if location == "header":
        if kind == "object":
            _fail("Object header parameter serialization is ambiguous and unsupported")
        if kind == "array":
            _fail("Array header parameter serialization is ambiguous and unsupported")
        text = _scalar(value)
        if any(c in "\r\n\0" for c in text) or any(ord(c) < 32 and c != "\t" or ord(c) >= 127 for c in text):
            _fail("Header parameter value contains invalid characters or line breaks (CRLF injection prevented)")
    schema = metadata.get("schema", SmartDataGenerator._parameter_schema(metadata) if swagger2 else {})
    if isinstance(schema, dict):
        declared = schema.get("type")
        if isinstance(declared, list):
            declared = next((item for item in declared if item != "null"), None) if len(declared) <= 2 else None
        if isinstance(declared, str) and declared in {"array", "object"} and kind != declared:
            _fail("Configured parameter value must retain its declared array/object structure")
        if isinstance(declared, str) and declared in {"string", "integer", "number", "boolean"} and kind != "primitive":
            _fail("Configured parameter value conflicts with its declared scalar type")
        if declared == "file":
            _fail("File parameter serialization is unsupported")
    if not SmartDataGenerator.validate_schema_value(value, schema, request=False):
        _fail("Parameter value does not satisfy its declared schema or the schema is unsupported")
    if swagger2:
        if "style" in metadata or "explode" in metadata:
            _fail("Swagger 2 parameters use collectionFormat; style/explode are unsupported")
        if kind == "object":
            _fail("Swagger 2 non-body object parameters are unsupported")
        collection = metadata.get("collectionFormat", "csv")
        if not isinstance(collection, str) or collection not in {"csv", "ssv", "tsv", "pipes", "multi"}:
            _fail("Unsupported Swagger 2 collectionFormat")
        if "collectionFormat" in metadata and kind != "array":
            _fail("Swagger 2 collectionFormat requires an array parameter")
        if collection == "multi" and location != "query":
            _fail("Swagger 2 collectionFormat=multi is supported only for query parameters")
        if location == "header" and collection != "csv":
            _fail("Swagger 2 header parameters only support collectionFormat=csv")
        return location, name, collection, collection == "multi"
    if "collectionFormat" in metadata:
        _fail("OpenAPI 3 parameters use style/explode; collectionFormat is unsupported")
    style = metadata.get("style", "form" if location in {"query", "cookie"} else "simple")
    explode = metadata.get("explode", style == "form")
    if not isinstance(explode, bool):
        _fail("explode must be a boolean")
    if location == "path":
        allowed = {"simple", "label", "matrix"}
    elif location == "query":
        allowed = {"form", "spaceDelimited", "pipeDelimited", "deepObject"}
    elif location == "header":
        allowed = {"simple"}
    elif location == "cookie":
        allowed = {"form"}
    else:
        allowed = set()
    if not isinstance(style, str) or style not in allowed:
        _fail("Unsupported parameter style for its location")
    if style in {"spaceDelimited", "pipeDelimited"}:
        if kind == "primitive" or explode:
            _fail("spaceDelimited/pipeDelimited require a flat array/object and explode=false")
    if style == "deepObject" and (kind != "object" or not explode):
        _fail("deepObject requires a flat object and explicit explode=true")
    return location, name, style, explode


def _tokens(value: Any, *, label: bool = False) -> List[str]:
    if isinstance(value, dict):
        return [part for key, item in value.items() for part in (_encoded(key, label=label), _encoded(item, label=label))]
    if isinstance(value, list):
        return [_encoded(item, label=label) for item in value]
    return [_encoded(value, label=label)]


def _delimited(value: Any, style: str) -> str:
    delimiter = {"csv": ",", "ssv": " ", "tsv": "\t", "pipes": "|",
                 "spaceDelimited": " ", "pipeDelimited": "|"}[style]
    # Space and pipe delimiters are themselves percent-encoded. Contracts must
    # define an extra escape convention for delimiter characters in data; we
    # cannot infer one, so reject those ambiguous inputs instead of guessing.
    if delimiter != ",":
        raw = (list(value.keys()) + list(value.values())) if isinstance(value, dict) else value
        if any(delimiter in _scalar(item) for item in raw):
            _fail("Delimited parameter data contains its delimiter; an API-specific escape convention is unsupported")
    encoded_delimiter = "," if delimiter == "," else quote(delimiter, safe="")
    return encoded_delimiter.join(_tokens(value))


def serialize_path_parameter(metadata: Dict[str, Any], value: Any, *, swagger2: bool = False) -> str:
    value = normalize_parameter_value(metadata, value, swagger2=swagger2)
    location, name, style, explode = _settings(metadata, value, swagger2)
    if location != "path":
        _fail("Path serialization requires in=path")
    if swagger2:
        return _delimited(value, style) if isinstance(value, list) else _encoded(value)
    if isinstance(value, dict) and explode:
        delimiter = ";" if style == "matrix" else "." if style == "label" else ","
        body = delimiter.join(_encoded(key, label=style == "label") + "=" +
                              _encoded(item, label=style == "label") for key, item in value.items())
        return (";" if style == "matrix" else "." if style == "label" else "") + body
    if style == "matrix":
        encoded_name = _encoded(name)
        if isinstance(value, list) and explode:
            return "".join(";" + encoded_name + "=" + _encoded(item) for item in value)
        return ";" + encoded_name + "=" + ",".join(_tokens(value))
    separator = "." if style == "label" and explode else ","
    return ("." if style == "label" else "") + separator.join(_tokens(value, label=style == "label"))


def serialize_query_parameter(metadata: Dict[str, Any], value: Any, *, swagger2: bool = False) -> List[Tuple[str, str]]:
    """Return pairs whose names and values are already percent-encoded."""
    value = normalize_parameter_value(metadata, value, swagger2=swagger2)
    location, name, style, explode = _settings(metadata, value, swagger2)
    if location != "query":
        _fail("Query serialization requires in=query")
    encoded_name = _encoded(name)
    if swagger2:
        if isinstance(value, list):
            if style == "multi":
                return [(encoded_name, _encoded(item)) for item in value]
            return [(encoded_name, _delimited(value, style))]
        return [(encoded_name, _encoded(value))]
    if style == "deepObject":
        if "[" in name or "]" in name or any("[" in key or "]" in key for key in value):
            _fail("deepObject property/parameter names containing brackets are ambiguous and unsupported")
        return [(_encoded(name + "[" + key + "]"), _encoded(item)) for key, item in value.items()]
    if style in {"spaceDelimited", "pipeDelimited"}:
        return [(encoded_name, _delimited(value, style))]
    if explode and isinstance(value, dict):
        return [(_encoded(key), _encoded(item)) for key, item in value.items()]
    if explode and isinstance(value, list):
        return [(encoded_name, _encoded(item)) for item in value]
    return [(encoded_name, ",".join(_tokens(value)))]


def serialize_header_parameter(metadata: Dict[str, Any], value: Any, *, swagger2: bool = False) -> Tuple[str, str]:
    value = normalize_parameter_value(metadata, value, swagger2=swagger2)
    location, name, style, explode = _settings(metadata, value, swagger2)
    if location != "header":
        _fail("Header serialization requires in=header")
    return name, _scalar(value)


def serialize_cookie_parameter(metadata: Dict[str, Any], value: Any, *, swagger2: bool = False) -> Tuple[str, str]:
    value = normalize_parameter_value(metadata, value, swagger2=swagger2)
    location, name, style, explode = _settings(metadata, value, swagger2)
    if location != "cookie":
        _fail("Cookie serialization requires in=cookie")
    return name, _scalar(value)
