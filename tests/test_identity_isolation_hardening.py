"""Identity isolation hardening for shared authentication headers (F-02, R105-01 to R105-06).

Two identities never share a header that can identify the caller, unless the operator lists it
in identity_isolation.shared_gateway_headers and the specification, resolved exactly as the
scanner resolves it, requires a per-identity credential next to it on every operation where it
applies. Anything the validation cannot resolve fails closed. An authorized shared header is
reported as configured but with an unverified backend identity binding.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import api_sentinel
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator
from core.identity_auth import SpecAuth, is_identity_bearing_header, is_session_like_name
from core.parameters import ParameterSerializationError

GATEWAY_KEY = "gatewayKey-r105-shared-7311"
OWNER_KEY = "ownerKey-r105-distinct-1001"
VISITOR_KEY = "visitorKey-r105-distinct-1002"
TOKENS = {
    "owner": "Bearer ownerJwt-r105-1111aaaa",
    "visitor": "Bearer visitorJwt-r105-2222bbbb",
    "admin": "Bearer adminJwt-r105-3333cccc",
    "viewer": "Bearer viewerJwt-r105-4444dddd",
}
SECRETS = (GATEWAY_KEY, OWNER_KEY, VISITOR_KEY, *(token.split()[1] for token in TOKENS.values()))

KEY = {"type": "apiKey", "in": "header", "name": "X-API-Key"}
BEARER = {"type": "http", "scheme": "bearer"}
SCHEMES = {"ApiKeyAuth": KEY, "BearerAuth": BEARER}
AND = [{"ApiKeyAuth": [], "BearerAuth": []}]
OR = [{"ApiKeyAuth": []}, {"BearerAuth": []}]
KEY_ONLY = [{"ApiKeyAuth": []}]
OPT_IN = {"shared_gateway_headers": ["X-API-Key"]}


def get_op(operation_id: str, security: Any = None, with_id: bool = True) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"operationId": operation_id, "responses": {"200": {"description": "OK"}}}
    if with_id:
        operation["parameters"] = [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]
    if security is not None:
        operation["security"] = security
    return operation


def make_spec(security: Any = AND, *, schemes: Optional[Dict[str, Any]] = None, extra_paths: Optional[Dict[str, Any]] = None,
              version: str = "3.0.3", components: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    spec: Dict[str, Any] = {
        "openapi": version,
        "info": {"title": "R105 identity isolation", "version": "1.0"},
        "components": {"securitySchemes": dict(SCHEMES if schemes is None else schemes), **(components or {})},
        "paths": {
            "/users/{id}": {"get": get_op("getUser")},
            "/admin/settings": {"get": get_op("getAdminSettings", with_id=False)},
        },
    }
    if security is not None:
        spec["security"] = security
    spec["paths"].update(extra_paths or {})
    return spec


def identities(shared: Optional[Dict[str, str]] = None, *, roles: bool = False,
               visitor_token: Optional[str] = TOKENS["visitor"]) -> Dict[str, Any]:
    headers = {"X-API-Key": GATEWAY_KEY} if shared is None else shared
    result: Dict[str, Any] = {
        "owner": {"id": "1001", "token": TOKENS["owner"], "headers": dict(headers), "parameters": {"id": "1001"}},
        "visitor": {"id": "1002", "headers": dict(headers), "parameters": {"id": "1002"}},
        "anonymous": {},
    }
    if visitor_token is not None:
        result["visitor"]["token"] = visitor_token
    if roles:
        result["roles"] = {
            "admin": {"role": "administrator", "token": TOKENS["admin"], "headers": dict(headers)},
            "viewer": {"role": "viewer", "token": TOKENS["viewer"], "headers": dict(headers)},
        }
    return result


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assert_no_secrets(self, text: str) -> None:
        for secret in SECRETS:
            self.assertNotIn(secret, text)

    def write(self, name: str, payload: Dict[str, Any]) -> Path:
        path = self.folder / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def validator_errors(self, config: Dict[str, Any], spec: Optional[Dict[str, Any]],
                         spec_path: Optional[Path] = None) -> List[Tuple[str, str]]:
        result = ConfigValidator.validate(config, raw_spec=spec, spec_path=str(spec_path) if spec_path else None)
        rendered = "\n".join(issue.format() for issue in result.issues)
        self.assert_no_secrets(rendered)
        return [(issue.path, issue.message) for issue in result.errors]

    def api_error(self, spec_path: Path, config: Dict[str, Any], target: str = "http://127.0.0.1:9") -> Optional[str]:
        try:
            APISentinelAuditor(str(spec_path), target, identities_config=copy.deepcopy(config["identities"]),
                               identity_isolation=config.get("identity_isolation"), request_delay=0)
        except (ValueError, ParameterSerializationError) as exc:
            self.assert_no_secrets(str(exc))
            return str(exc)
        return None

    def decision(self, config: Dict[str, Any], spec: Dict[str, Any], name: str = "spec.json") -> Tuple[bool, bool]:
        """(ConfigValidator accepts, Python API accepts) for the same configuration and specification."""
        spec_path = self.write(name, spec)
        accepted = not self.validator_errors(config, spec, spec_path)
        return accepted, self.api_error(spec_path, config) is None


class DefaultDenyTests(Harness):
    """R105-05/06: no shared identity header without an explicit, validated authorization."""

    def test_true_and_shared_gateway_key_is_refused_without_opt_in(self) -> None:
        config = {"identities": identities(roles=True)}
        errors = self.validator_errors(config, make_spec(AND))
        self.assertIn("identities.visitor", [path for path, _ in errors])
        self.assertIn("identities.roles.viewer", [path for path, _ in errors])
        message = next(text for path, text in errors if path == "identities.visitor")
        self.assertIn("x-api-key", message)
        self.assertIn("identity_isolation.shared_gateway_headers", message)
        self.assertEqual(self.decision(config, make_spec(AND)), (False, False))

    def test_opt_in_accepts_true_and_shared_gateway_key_for_identities_and_roles(self) -> None:
        config = {"identities": identities(roles=True), "identity_isolation": OPT_IN}
        self.assertEqual(self.decision(config, make_spec(AND)), (True, True))

    def test_identity_bearing_headers_shared_without_opt_in_are_refused(self) -> None:
        spec = make_spec([{"BearerAuth": []}])
        for header in ("X-Gateway-Token", "Ocp-Apim-Subscription-Key", "X-User-Id", "X-Client-Secret",
                       "X-Forwarded-User", "X-SessionKey", "X-Auth-User", "X-Sid"):
            with self.subTest(header=header):
                config = {"identities": identities({header: GATEWAY_KEY})}
                self.assertEqual(self.decision(config, spec), (False, False))
                self.assertTrue(is_identity_bearing_header(header))

    def test_ordinary_shared_headers_are_still_allowed(self) -> None:
        spec = make_spec([{"BearerAuth": []}])
        for header in ("Accept", "X-Tenant-Id", "X-Request-Id", "User-Agent", "X-Api-Version", "X-User-Lang"):
            with self.subTest(header=header):
                config = {"identities": identities({header: "same-value"})}
                self.assertEqual(self.decision(config, spec), (True, True))
                self.assertFalse(is_identity_bearing_header(header))

    def test_opt_in_never_covers_authorization_session_or_auth_header_names(self) -> None:
        spec = make_spec(AND)
        shared_bearer = identities()
        shared_bearer["visitor"]["token"] = TOKENS["owner"]
        shared_bearer["visitor"]["headers"]["X-API-Key"] = VISITOR_KEY
        config = {"identities": shared_bearer, "identity_isolation": {"shared_gateway_headers": ["Authorization"]}}
        self.assertEqual(self.decision(config, spec), (False, False))

        custom = identities()
        custom["owner"]["auth_header_names"] = ["X-API-Key"]
        self.assertEqual(self.decision({"identities": custom, "identity_isolation": OPT_IN}, spec), (False, False))

        for entry in ("Cookie", "Authorization", "X-Session-Key", "PHPSESSID", "", 7, "Bad Header"):
            with self.subTest(entry=entry):
                config = {"identities": identities(), "identity_isolation": {"shared_gateway_headers": [entry]}}
                errors = self.validator_errors(config, spec)
                self.assertTrue(any(path.startswith("identity_isolation") for path, _ in errors), errors)

    def test_identity_isolation_section_shape_is_validated(self) -> None:
        spec = make_spec(AND)
        for section in ([], "X-API-Key", {"shared_gateway_headers": "X-API-Key"}, {"unexpected": []},
                        {"shared_gateway_headers": ["X-API-Key", "x-api-key"]}):
            with self.subTest(section=section):
                config = {"identities": identities(), "identity_isolation": section}
                errors = self.validator_errors(config, spec)
                self.assertTrue(any(path.startswith("identity_isolation") for path, _ in errors), errors)
                spec_path = self.write("shape.json", spec)
                self.assertIsNotNone(self.api_error(spec_path, config))

    def test_opt_in_without_resolvable_security_requirements_fails_closed(self) -> None:
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        # Configuration-only validation cannot see any operation.
        self.assertIn("identities.visitor", [path for path, _ in self.validator_errors(config, None)])
        # A specification without any security requirement cannot show a per-identity credential.
        self.assertEqual(self.decision(config, make_spec(None)), (False, False))

    def test_undeclared_opt_in_header_needs_a_per_identity_credential_everywhere(self) -> None:
        header = {"Ocp-Apim-Subscription-Key": GATEWAY_KEY}
        config = {"identities": identities(header),
                  "identity_isolation": {"shared_gateway_headers": ["Ocp-Apim-Subscription-Key"]}}
        self.assertEqual(self.decision(config, make_spec([{"BearerAuth": []}])), (True, True))
        cookie_only = make_spec([{"BearerAuth": []}], schemes={**SCHEMES, "CookieAuth": {
            "type": "apiKey", "in": "cookie", "name": "sid"}},
            extra_paths={"/reports/{id}": {"get": get_op("getReport", [{"CookieAuth": []}])}})
        self.assertEqual(self.decision(config, cookie_only, "cookie_only.json"), (False, False))

    def test_declared_but_unused_opt_in_header_is_checked_like_an_undeclared_one(self) -> None:
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        schemes = {**SCHEMES, "CookieAuth": {"type": "apiKey", "in": "cookie", "name": "sid"}}
        # ApiKeyAuth is declared, but no operation names it: it applies wherever the server may read it.
        self.assertEqual(self.decision(config, make_spec([{"BearerAuth": []}])), (True, True))
        unused = make_spec([{"BearerAuth": []}], schemes=schemes,
                           extra_paths={"/reports/{id}": {"get": get_op("getReport", [{"CookieAuth": []}])}})
        self.assertEqual(self.decision(config, unused, "unused.json"), (False, False))


class ResolvedOperationTests(Harness):
    """R105-01: the operations checked are the operations the scanner resolves and sends."""

    def test_openapi_31_path_item_reference_with_key_only_security_is_refused(self) -> None:
        spec = make_spec(AND, version="3.1.0", extra_paths={"/files/{id}": {"$ref": "#/components/pathItems/Files"}},
                         components={"pathItems": {"Files": {"get": get_op("getFile", KEY_ONLY)}}})
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        self.assertEqual(self.decision(config, spec), (False, False))
        errors = self.validator_errors(config, spec, self.write("spec.json", spec))
        self.assertIn("authenticate", next(text for path, text in errors if path == "identities.visitor"))

    def test_openapi_31_path_item_reference_with_and_security_is_accepted(self) -> None:
        spec = make_spec(AND, version="3.1.0", extra_paths={"/files/{id}": {"$ref": "#/components/pathItems/Files"}},
                         components={"pathItems": {"Files": {"get": get_op("getFile", AND)}}})
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        self.assertEqual(self.decision(config, spec), (True, True))

    def test_openapi_30_external_path_item_with_key_only_security_is_refused(self) -> None:
        self.write("paths.json", {"Files": {"get": get_op("getFile", KEY_ONLY)}})
        spec = make_spec(AND, extra_paths={"/files/{id}": {"$ref": "./paths.json#/Files"}})
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        self.assertEqual(self.decision(config, spec), (False, False))

    def test_openapi_30_external_path_item_inheriting_global_and_is_accepted(self) -> None:
        self.write("paths.json", {"Files": {"get": get_op("getFile")}})
        spec = make_spec(AND, extra_paths={"/files/{id}": {"$ref": "./paths.json#/Files"}})
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        self.assertEqual(self.decision(config, spec), (True, True))

    def test_unresolvable_path_item_reference_fails_closed(self) -> None:
        spec = make_spec(AND, version="3.1.0", extra_paths={"/files/{id}": {"$ref": "#/components/pathItems/Missing"}},
                         components={"pathItems": {}})
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        spec_path = self.write("spec.json", spec)
        self.assertTrue(self.validator_errors(config, spec, spec_path))
        self.assertIsNotNone(self.api_error(spec_path, config))


class OptionalAndMalformedSecurityTests(Harness):
    """R105-02 and R105-03: an anonymous alternative hides nothing, and malformed security fails closed."""

    def test_optional_security_with_a_key_only_alternative_is_refused(self) -> None:
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        spec = make_spec(AND, extra_paths={"/feed/{id}": {"get": get_op("getFeed", [{"ApiKeyAuth": []}, {}])}})
        self.assertEqual(self.decision(config, spec), (False, False))
        for security in ([{}, {"ApiKeyAuth": []}], [{"ApiKeyAuth": []}, {}, {"BearerAuth": []}]):
            with self.subTest(security=security):
                spec = make_spec(AND, extra_paths={"/feed/{id}": {"get": get_op("getFeed", security)}})
                self.assertEqual(self.decision(config, spec, "variant.json"), (False, False))

    def test_optional_security_whose_other_alternative_is_and_is_accepted(self) -> None:
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        spec = make_spec(AND, extra_paths={"/feed/{id}": {"get": get_op("getFeed", [AND[0], {}])}})
        self.assertEqual(self.decision(config, spec), (True, True))

    def test_mandatory_credentials_are_unchanged(self) -> None:
        cases = {
            "global AND": (make_spec(AND), frozenset({"x-api-key", "authorization"})),
            "global OR": (make_spec(OR), frozenset()),
            "AND with an optional operation": (
                make_spec(AND, extra_paths={"/feed/{id}": {"get": get_op("getFeed", [{"ApiKeyAuth": []}, {}])}}),
                frozenset({"x-api-key", "authorization"})),
            "public operation": (
                make_spec(AND, extra_paths={"/public/{id}": {"get": get_op("getPublic", [])}}),
                frozenset({"x-api-key", "authorization"})),
            "no security": (make_spec(None), frozenset()),
        }
        for label, (spec, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(SpecAuth.from_spec(spec["components"]["securitySchemes"], spec).mandatory, expected)

    def test_malformed_or_unsupported_security_fails_closed(self) -> None:
        config = {"identities": identities(), "identity_isolation": OPT_IN}
        schemes = {**SCHEMES, "QueryKey": {"type": "apiKey", "in": "query", "name": "api_key"},
                   "ClientCert": {"type": "mutualTLS"}}
        malformed = {
            "object": {"ApiKeyAuth": []},
            "string": "ApiKeyAuth",
            "string alternative": ["ApiKeyAuth"],
            "scopes not a list": [{"ApiKeyAuth": "read", "BearerAuth": []}],
            "null": None,
            "undefined scheme with the key": [{"ApiKeyAuth": [], "Undefined": []}],
            "query key with the key": [{"ApiKeyAuth": [], "QueryKey": []}],
            "mutual TLS with the key": [{"ApiKeyAuth": [], "ClientCert": []}],
        }
        for label, security in malformed.items():
            with self.subTest(case=label):
                operation = get_op("getOdd")
                operation["security"] = security
                spec = make_spec(AND, schemes=schemes, extra_paths={"/odd/{id}": {"get": operation}})
                self.assertEqual(self.decision(config, spec, "odd.json"), (False, False))
        with self.subTest(case="malformed global security inherited by an operation"):
            spec = make_spec({"ApiKeyAuth": [], "BearerAuth": []}, schemes=schemes)
            self.assertEqual(self.decision(config, spec, "global.json"), (False, False))


class SessionHeaderTests(Harness):
    """R105-04: one rule for session-like names, whatever the separators."""

    def test_session_like_names_are_recognized(self) -> None:
        for name in ("X-Session-Key", "X-SessionKey", "X-SessionToken", "SessionId", "x_session_id", "X-Sid",
                     "PHPSESSID", "JSESSIONID", "connect.sid", "ASP.NET_SessionId"):
            with self.subTest(name=name):
                self.assertTrue(is_session_like_name(name))
        for name in ("X-API-Key", "Considerations", "X-Inside", "Authorization"):
            with self.subTest(name=name):
                self.assertFalse(is_session_like_name(name))

    def test_session_like_headers_cannot_be_shared_even_when_declared_and_listed(self) -> None:
        for header in ("X-Session-Key", "X-SessionKey", "X-SessionToken", "SessionId"):
            with self.subTest(header=header):
                spec = make_spec([{"SessionAuth": [], "BearerAuth": []}], schemes={
                    "SessionAuth": {"type": "apiKey", "in": "header", "name": header}, "BearerAuth": BEARER})
                config = {"identities": identities({header: GATEWAY_KEY}),
                          "identity_isolation": {"shared_gateway_headers": [header]}}
                self.assertEqual(self.decision(config, spec), (False, False))


class ExampleAndSchemaTests(Harness):
    """The committed example and config.schema.json describe the same setting the validator enforces."""

    ROOT = Path(__file__).resolve().parents[1]

    def test_committed_example_is_valid_only_with_its_authorization(self) -> None:
        folder = self.ROOT / "examples" / "shared-gateway-key"
        spec = json.loads((folder / "openapi.json").read_text(encoding="utf-8"))
        config = json.loads((folder / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(self.validator_errors(config, spec, folder / "openapi.json"), [])
        self.assertIsNone(self.api_error(folder / "openapi.json", config))
        without = {key: value for key, value in config.items() if key != "identity_isolation"}
        self.assertIn("identities.visitor", [path for path, _ in self.validator_errors(without, spec)])

    def test_schema_declares_identity_isolation(self) -> None:
        import re

        schema = json.loads((self.ROOT / "config.schema.json").read_text(encoding="utf-8"))
        section = schema["properties"]["identity_isolation"]
        self.assertFalse(section["additionalProperties"])
        items = section["properties"]["shared_gateway_headers"]["items"]
        allowed, forbidden = re.compile(items["pattern"]), re.compile(items["not"]["pattern"])
        for name in ("X-API-Key", "Ocp-Apim-Subscription-Key"):
            self.assertTrue(allowed.match(name) and not forbidden.match(name))
        for name in ("Authorization", "cookie", "Proxy-Authorization"):
            self.assertTrue(forbidden.match(name))
        self.assertFalse(allowed.match("Bad Header"))


class ConsistencyTests(Harness):
    """CLI --validate-config, ConfigValidator and the Python API decide alike."""

    def run_cli(self, args: List[str]) -> Tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = api_sentinel.main(args)
        return code, out.getvalue() + err.getvalue()

    def test_three_entry_points_agree(self) -> None:
        ref_key_only = make_spec(AND, version="3.1.0", extra_paths={"/files/{id}": {"$ref": "#/components/pathItems/F"}},
                                 components={"pathItems": {"F": {"get": get_op("getFile", KEY_ONLY)}}})
        cases = {
            "AND without opt-in": ({"identities": identities()}, make_spec(AND), False),
            "AND with opt-in": ({"identities": identities(), "identity_isolation": OPT_IN}, make_spec(AND), True),
            "OR with opt-in": ({"identities": identities(), "identity_isolation": OPT_IN}, make_spec(OR), False),
            "key only with opt-in": ({"identities": identities(), "identity_isolation": OPT_IN}, make_spec(KEY_ONLY),
                                     False),
            "path item ref with opt-in": ({"identities": identities(), "identity_isolation": OPT_IN}, ref_key_only,
                                          False),
            "distinct keys without opt-in": (
                {"identities": {**identities(), "visitor": {**identities()["visitor"],
                                                            "headers": {"X-API-Key": VISITOR_KEY}}}},
                make_spec(OR), True),
        }
        for label, (config, spec, expected) in cases.items():
            with self.subTest(case=label):
                spec_path = self.write("spec.json", spec)
                config_path = self.write("config.json", config)
                code, output = self.run_cli(["--spec", str(spec_path), "--config", str(config_path), "--validate-config"])
                self.assert_no_secrets(output)
                self.assertEqual(code == 0, expected, output)
                self.assertEqual(not self.validator_errors(config, spec, spec_path), expected)
                self.assertEqual(self.api_error(spec_path, config) is None, expected)


class LoopbackHarness(Harness):
    """A loopback API whose caller identity comes from the Bearer token or from the shared key alone."""

    MODE = "bearer"

    def setUp(self) -> None:
        super().setUp()
        self.seen: List[Dict[str, Any]] = []
        self.mode = self.MODE
        seen, outer = self.seen, self

        class Api(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                key, auth = self.headers.get("X-API-Key"), self.headers.get("Authorization")
                caller = outer.caller(key, auth)
                seen.append({"path": self.path, "key": key, "auth": auth, "caller": caller})
                path = self.path.split("?")[0]
                if caller is None:
                    status, body = 401, {"error": "Unauthorized"}
                elif path == "/users/1001" and caller == "owner":
                    status, body = 200, {"id": "1001", "email": "owner@example.test"}
                elif path == "/users/1002" and caller == "visitor":
                    status, body = 200, {"id": "1002", "email": "visitor@example.test"}
                elif path == "/admin/settings" and caller == "admin":
                    status, body = 200, {"signing_key": "admin-only-setting"}
                else:
                    status, body = 403, {"error": "Forbidden"}
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Api)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.target = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        super().tearDown()

    def caller(self, key: Optional[str], auth: Optional[str]) -> Optional[str]:
        if key != GATEWAY_KEY:
            return None
        if self.mode == "bearer":
            return next((name for name, token in TOKENS.items() if token == auth), None)
        # The backend identifies the caller by the shared key alone and ignores the Bearer token.
        return {"key_owner": "owner", "key_visitor": "visitor", "key_admin": "admin", "key_third": "someone"}[self.mode]

    def run_cli(self, args: List[str]) -> Tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = api_sentinel.main(args)
        return code, out.getvalue() + err.getvalue()

    def scan(self, config: Dict[str, Any], spec: Dict[str, Any], *, dry_run: bool = False) -> Tuple[int, str, Dict[str, Any]]:
        spec_path, config_path = self.write("spec.json", spec), self.write("config.json", config)
        report = self.folder / "report.json"
        args = ["--spec", str(spec_path), "--config", str(config_path), "--target", self.target, "--delay", "0",
                "--export-json", str(report), "--output", str(self.folder / "report.html")]
        code, output = self.run_cli(args + (["--dry-run"] if dry_run else []))
        self.assert_no_secrets(output)
        payload = json.loads(report.read_text(encoding="utf-8")) if report.exists() else {}
        self.assert_no_secrets(json.dumps(payload))
        if (self.folder / "report.html").exists():
            self.assert_no_secrets((self.folder / "report.html").read_text(encoding="utf-8"))
        return code, output, payload


SCAN_POLICY = {
    "bola": {
        "GET /users/{id}": {"resource_id_paths": ["id"]},
        "GET /admin/settings": {"required_role": "administrator", "private_data_paths": ["signing_key"]},
    },
}


class RefusedBeforeWireTests(LoopbackHarness):
    """R105-01/02/03: a refused shared header stops every request; the API receives nothing."""

    MODE = "key_owner"

    def test_refused_specifications_send_zero_requests(self) -> None:
        config = {"identities": identities(roles=True), "identity_isolation": OPT_IN, **SCAN_POLICY}
        specs = {
            "R105-01 path item reference": make_spec(
                AND, version="3.1.0", extra_paths={"/files/{id}": {"$ref": "#/components/pathItems/F"}},
                components={"pathItems": {"F": {"get": get_op("getFile", KEY_ONLY)}}}),
            "R105-02 optional key-only security": make_spec(
                AND, extra_paths={"/feed/{id}": {"get": get_op("getFeed", [{"ApiKeyAuth": []}, {}])}}),
            "R105-03 malformed security": make_spec(
                AND, extra_paths={"/odd/{id}": {"get": get_op("getOdd", {"ApiKeyAuth": []})}}),
            "no opt-in": None,
        }
        for label, spec in specs.items():
            with self.subTest(case=label):
                self.seen.clear()
                if spec is None:
                    code, output, _ = self.scan({k: v for k, v in config.items() if k != "identity_isolation"},
                                                make_spec(AND))
                else:
                    code, output, _ = self.scan(config, spec)
                self.assertEqual(code, 2, output)
                self.assertEqual(self.seen, [])
                spec_path = self.write("api.json", spec or make_spec(AND))
                api_config = config if spec is not None else {"identities": config["identities"]}
                self.assertIsNotNone(self.api_error(spec_path, api_config, self.target))
                self.assertEqual(self.seen, [])


class BindingUnverifiedTests(LoopbackHarness):
    """R105-05: an authorized shared header is reported, and a key-only backend never yields SECURE."""

    def test_key_identified_backends_never_produce_secure(self) -> None:
        config = {"identities": identities(roles=True), "identity_isolation": OPT_IN, **SCAN_POLICY}
        for mode in ("key_owner", "key_visitor", "key_admin", "key_third"):
            with self.subTest(mode=mode):
                self.mode = mode
                self.seen.clear()
                code, output, report = self.scan(config, make_spec(AND))
                self.assertIn(code, (0, 1), output)
                self.assertTrue(self.seen)
                # Anonymous carries no shared header; every check that compares two identities stays non-SECURE.
                verdicts = [result["verdict"] for result in report["results"] if result["check"] != "BROKEN_AUTH"]
                self.assertTrue(verdicts)
                self.assertNotIn("SECURE", verdicts, report["results"])
                self.assertEqual(report["identity_isolation"]["backend_identity_binding"], "unverified")

    def test_bearer_bound_backend_is_scanned_and_reported_as_unverified_binding(self) -> None:
        self.mode = "bearer"
        config = {"identities": identities(roles=True), "identity_isolation": OPT_IN, **SCAN_POLICY}
        code, output, report = self.scan(config, make_spec(AND))
        self.assertEqual(code, 0, output)
        verdicts = {(r["check"], r["endpoint"], (r.get("evidence") or {}).get("rbac_role")): r["verdict"]
                    for r in report["results"]}
        self.assertEqual(verdicts[("BOLA", "GET /users/{id}", None)], "SECURE")
        self.assertEqual(verdicts[("RBAC", "GET /admin/settings", "viewer")], "SECURE")
        marking = report["identity_isolation"]
        self.assertEqual(marking["shared_gateway_headers"], ["x-api-key"])
        self.assertEqual(marking["shared_in_scan"], ["x-api-key"])
        self.assertEqual(marking["authorized_by"], "configuration")
        self.assertEqual(marking["backend_identity_binding"], "unverified")
        self.assertIn("identity_isolation.shared_gateway_headers", output)
        html = (self.folder / "report.html").read_text(encoding="utf-8")
        self.assertIn("identity-isolation-notice", html)
        self.assertIn("后端身份绑定未验证", html)
        self.assertTrue(all(r["key"] == GATEWAY_KEY for r in self.seen if r["auth"]))

    def test_dry_run_plan_marks_the_authorized_header(self) -> None:
        config = {"identities": identities(), "identity_isolation": OPT_IN, **SCAN_POLICY}
        code, output, plan = self.scan(config, make_spec(AND), dry_run=True)
        self.assertEqual(code, 0, output)
        self.assertEqual(self.seen, [])
        self.assertEqual(plan["identity_isolation"]["backend_identity_binding"], "unverified")

    def test_scans_without_a_shared_header_carry_no_marking(self) -> None:
        self.mode = "bearer"
        config = {"identities": identities({"X-API-Key": GATEWAY_KEY}), **SCAN_POLICY}
        config["identities"]["visitor"]["headers"] = {"X-API-Key": GATEWAY_KEY + "-v"}
        code, output, report = self.scan(config, make_spec(OR))
        self.assertNotIn("identity_isolation", report)


class LateMutationTests(LoopbackHarness):
    """Identity material changed after construction is checked again before each request."""

    def build(self) -> APISentinelAuditor:
        spec_path = self.write("spec.json", make_spec(AND))
        return APISentinelAuditor(str(spec_path), self.target, request_delay=0, max_workers=1,
                                  identities_config=identities(), identity_isolation=OPT_IN,
                                  bola_config={"GET /users/{id}": {"resource_id_paths": ["id"]}})

    def assert_blocked(self, auditor: APISentinelAuditor) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            auditor.run()
        self.assertEqual([r for r in self.seen if r["auth"] in (TOKENS["visitor"], TOKENS["owner"])], [])
        bola = next(r for r in auditor.results if r["check"] == "BOLA")
        self.assertNotEqual(bola["verdict"], "SECURE")
        self.assertIn("no request was sent", bola["reason"])
        self.assert_no_secrets(json.dumps(auditor.results))

    def test_visitor_given_owner_bearer_after_construction_is_blocked(self) -> None:
        auditor = self.build()
        auditor.identities["visitor"]["token"] = TOKENS["owner"]
        self.assert_blocked(auditor)

    def test_visitor_losing_its_own_credential_after_construction_is_blocked(self) -> None:
        auditor = self.build()
        del auditor.identities["visitor"]["token"]
        self.assert_blocked(auditor)

    def test_unauthorized_identity_header_added_after_construction_is_blocked(self) -> None:
        auditor = self.build()
        for name in ("owner", "visitor"):
            auditor.identities[name]["headers"]["X-User-Id"] = "1001"
        self.assert_blocked(auditor)


if __name__ == "__main__":
    unittest.main()
