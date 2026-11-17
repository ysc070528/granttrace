"""Regression tests for authentication header identity isolation across OR and AND security (F-02).

Verifies that shared header credentials (such as X-API-Key, X-Session-Key,
Authorization, or declared apiKey headers) between Owner/Visitor or between RBAC
roles are refused whenever they can cause identity confusion, while allowing a
legitimate application-level shared apiKey header strictly under true OpenAPI
AND semantics accompanied by distinct per-identity credentials.
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
from typing import Any, Dict, List, Optional

import api_sentinel
from core.auditor import APISentinelAuditor
from core.config_validator import ConfigValidator

APP_KEY = "appGatewayKey-f02-shared-9911"
OWNER_KEY = "ownerApiKey-f02-distinct-1001"
VISITOR_KEY = "visitorApiKey-f02-distinct-1002"
ADMIN_KEY = "adminApiKey-f02-distinct-9001"
VIEWER_KEY = "viewerApiKey-f02-distinct-9002"

TOKENS = {
    "owner": "Bearer ownerJwt-f02-aaaa1111",
    "visitor": "Bearer visitorJwt-f02-bbbb2222",
    "admin": "Bearer adminJwt-f02-cccc3333",
    "viewer": "Bearer viewerJwt-f02-dddd4444",
}
SESSIONS = {
    "owner": "ownerSid-f02-eeee5555",
    "visitor": "visitorSid-f02-ffff6666",
    "admin": "adminSid-f02-abab7777",
    "viewer": "viewerSid-f02-cdcd8888",
}
ALL_SECRETS = (
    APP_KEY,
    OWNER_KEY,
    VISITOR_KEY,
    ADMIN_KEY,
    VIEWER_KEY,
    *(t.split()[1] for t in TOKENS.values()),
    *SESSIONS.values(),
)


def make_spec(
    schemes: Dict[str, Any],
    security: Any,
    extra_op_security: Optional[Any] = None,
) -> Dict[str, Any]:
    admin_get: Dict[str, Any] = {
        "operationId": "getAdminSettings",
        "responses": {"200": {"description": "OK"}},
    }
    if extra_op_security is not None:
        admin_get["security"] = extra_op_security
    return {
        "openapi": "3.0.3",
        "info": {"title": "F-02 Header Isolation API", "version": "1.0"},
        "components": {"securitySchemes": schemes},
        "security": security,
        "paths": {
            "/users/{id}": {
                "get": {
                    "operationId": "getUser",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/admin/settings": {"get": admin_get},
        },
    }


HEADER_SCHEME_ONLY = {
    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
}
HEADER_AND_BEARER_SCHEMES = {
    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
    "BearerAuth": {"type": "http", "scheme": "bearer"},
}
SESSION_HEADER_AND_BEARER_SCHEMES = {
    "SessionKeyAuth": {"type": "apiKey", "in": "header", "name": "X-Session-Key"},
    "BearerAuth": {"type": "http", "scheme": "bearer"},
}
HEADER_AND_COOKIE_SCHEMES = {
    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
    "CookieAuth": {"type": "apiKey", "in": "cookie", "name": "SESSIONID"},
}


class HeaderIsolationValidationTests(unittest.TestCase):
    """Unit and ConfigValidator checks for shared header credentials across OR and AND security."""

    def assert_no_leaked_secrets(self, text: str) -> None:
        for secret in ALL_SECRETS:
            self.assertNotIn(secret, text)

    def validate_paths(self, identities: Dict[str, Any], spec: Optional[Dict[str, Any]]) -> List[str]:
        res = ConfigValidator.validate({"identities": identities}, raw_spec=spec)
        rendered = "\n".join(i.format() for i in res.issues)
        self.assert_no_leaked_secrets(rendered)
        return sorted(i.path for i in res.errors)

    def test_shared_declared_apikey_header_masked_by_distinct_tokens_is_refused_in_single_and_or_security(self) -> None:
        identities = {
            "owner": {"id": "1001", "headers": {"X-API-Key": OWNER_KEY}, "token": TOKENS["owner"]},
            "visitor": {"id": "1002", "headers": {"X-API-Key": OWNER_KEY}, "token": TOKENS["visitor"]},
            "anonymous": {},
        }
        cases = {
            "single apiKey scheme": make_spec(HEADER_SCHEME_ONLY, [{"ApiKeyAuth": []}]),
            "OR security (ApiKey OR Bearer)": make_spec(
                HEADER_AND_BEARER_SCHEMES, [{"ApiKeyAuth": []}, {"BearerAuth": []}]
            ),
            "AND globally but OR on one operation": make_spec(
                HEADER_AND_BEARER_SCHEMES,
                [{"ApiKeyAuth": [], "BearerAuth": []}],
                extra_op_security=[{"ApiKeyAuth": []}, {"BearerAuth": []}],
            ),
            "AND globally but standalone ApiKey on one operation": make_spec(
                HEADER_AND_BEARER_SCHEMES,
                [{"ApiKeyAuth": [], "BearerAuth": []}],
                extra_op_security=[{"ApiKeyAuth": []}],
            ),
            "unused scheme with no security requirement": make_spec(HEADER_AND_BEARER_SCHEMES, []),
            "config-only validation without spec": None,
        }
        for label, spec in cases.items():
            with self.subTest(case=label):
                paths = self.validate_paths(identities, spec)
                self.assertIn("identities.visitor", paths, f"Expected visitor error for {label}, got {paths}")

    def test_shared_x_session_key_and_authorization_across_identities_and_roles_are_refused(self) -> None:
        or_spec = make_spec(SESSION_HEADER_AND_BEARER_SCHEMES, [{"SessionKeyAuth": []}, {"BearerAuth": []}])

        # 1. Owner and Visitor share X-Session-Key (even without auth_header_names) behind distinct Bearer tokens
        shared_session_hdr = {
            "owner": {"id": "1001", "headers": {"X-Session-Key": OWNER_KEY}, "token": TOKENS["owner"]},
            "visitor": {"id": "1002", "headers": {"X-Session-Key": OWNER_KEY}, "token": TOKENS["visitor"]},
            "anonymous": {},
        }
        self.assertIn("identities.visitor", self.validate_paths(shared_session_hdr, or_spec))

        # 2. Roles share X-API-Key or X-Session-Key behind distinct Bearer tokens on OR security
        role_shared_hdr = {
            "owner": {"id": "1001", "headers": {"X-Session-Key": OWNER_KEY}, "token": TOKENS["owner"]},
            "visitor": {"id": "1002", "headers": {"X-Session-Key": VISITOR_KEY}, "token": TOKENS["visitor"]},
            "anonymous": {},
            "roles": {
                "admin": {"role": "administrator", "headers": {"X-Session-Key": ADMIN_KEY}, "token": TOKENS["admin"]},
                "operator": {"role": "operator", "headers": {"X-Session-Key": VIEWER_KEY}, "token": TOKENS["viewer"]},
                "viewer": {"role": "viewer", "headers": {"X-Session-Key": ADMIN_KEY}, "token": "Bearer viewer2Jwt-9999"},
            },
        }
        self.assertIn("identities.roles.viewer", self.validate_paths(role_shared_hdr, or_spec))

        # 3. Shared Authorization header is ALWAYS refused, even under AND security with distinct X-API-Key!
        and_spec = make_spec(HEADER_AND_BEARER_SCHEMES, [{"ApiKeyAuth": [], "BearerAuth": []}])
        shared_bearer_under_and = {
            "owner": {"id": "1001", "headers": {"X-API-Key": OWNER_KEY}, "token": TOKENS["owner"]},
            "visitor": {"id": "1002", "headers": {"X-API-Key": VISITOR_KEY}, "token": TOKENS["owner"]},
            "anonymous": {},
        }
        self.assertIn("identities.visitor", self.validate_paths(shared_bearer_under_and, and_spec))

        # 4. Shared X-Session-Key is refused even under AND security (a session key is per-session, not an app key)
        and_session_hdr = make_spec(SESSION_HEADER_AND_BEARER_SCHEMES, [{"SessionKeyAuth": [], "BearerAuth": []}])
        self.assertIn("identities.visitor", self.validate_paths(shared_session_hdr, and_session_hdr))

    def test_legitimate_shared_gateway_apikey_is_allowed_only_under_true_and_with_distinct_identity_creds(self) -> None:
        # 1. True AND: X-API-Key (shared app key) + Bearer (distinct per identity and role)
        and_bearer_spec = make_spec(HEADER_AND_BEARER_SCHEMES, [{"ApiKeyAuth": [], "BearerAuth": []}])
        valid_and_bearer = {
            "owner": {"id": "1001", "headers": {"X-API-Key": APP_KEY}, "token": TOKENS["owner"]},
            "visitor": {"id": "1002", "headers": {"X-API-Key": APP_KEY}, "token": TOKENS["visitor"]},
            "anonymous": {},
            "roles": {
                "admin": {"role": "administrator", "headers": {"X-API-Key": APP_KEY}, "token": TOKENS["admin"]},
                "viewer": {"role": "viewer", "headers": {"X-API-Key": APP_KEY}, "token": TOKENS["viewer"]},
            },
        }
        self.assertEqual(self.validate_paths(valid_and_bearer, and_bearer_spec), [])

        # 2. True AND: X-API-Key (shared app key) + Session Cookie (distinct per identity and role)
        and_cookie_spec = make_spec(HEADER_AND_COOKIE_SCHEMES, [{"ApiKeyAuth": [], "CookieAuth": []}])
        valid_and_cookie = {
            "owner": {"id": "1001", "headers": {"X-API-Key": APP_KEY}, "parameters": {"SESSIONID": SESSIONS["owner"]}},
            "visitor": {"id": "1002", "headers": {"X-API-Key": APP_KEY}, "parameters": {"SESSIONID": SESSIONS["visitor"]}},
            "anonymous": {},
            "roles": {
                "admin": {"role": "administrator", "headers": {"X-API-Key": APP_KEY}, "parameters": {"SESSIONID": SESSIONS["admin"]}},
                "viewer": {"role": "viewer", "headers": {"X-API-Key": APP_KEY}, "parameters": {"SESSIONID": SESSIONS["viewer"]}},
            },
        }
        self.assertEqual(self.validate_paths(valid_and_cookie, and_cookie_spec), [])

        # 3. Negative AND guards:
        #    (a) Unsupported companion scheme (in: query) cannot excuse a shared header
        bad_query_and = make_spec(
            {
                "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                "QueryKey": {"type": "apiKey", "in": "query", "name": "user_key"},
            },
            [{"ApiKeyAuth": [], "QueryKey": []}],
        )
        self.assertIn("identities.visitor", self.validate_paths(valid_and_bearer, bad_query_and))

        #    (b) Duplicate schemes pointing to the same X-API-Key header in AND cannot excuse sharing
        dup_header_and = make_spec(
            {
                "KeyOne": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                "KeyTwo": {"type": "apiKey", "in": "header", "name": "x-api-key"},
            },
            [{"KeyOne": [], "KeyTwo": []}],
        )
        self.assertIn("identities.visitor", self.validate_paths(valid_and_bearer, dup_header_and))

        #    (c) Explicitly listing X-API-Key in auth_header_names marks it as an identity credential (not shared)
        explicit_custom = copy.deepcopy(valid_and_bearer)
        explicit_custom["owner"]["auth_header_names"] = ["X-API-Key"]
        self.assertIn("identities.visitor", self.validate_paths(explicit_custom, and_bearer_spec))


class HeaderIsolationEndToEndTests(unittest.TestCase):
    """End-to-end --validate-config, Python API construction, and loopback wire verification."""

    def setUp(self) -> None:
        self.seen: List[Dict[str, Any]] = []
        sink = self.seen

        class GatewayMock(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                api_key = self.headers.get("X-API-Key")
                auth = self.headers.get("Authorization")
                sink.append({"path": self.path, "api_key": api_key, "auth": auth})
                if api_key != APP_KEY or not auth:
                    status, body = 401, {"error": "Unauthorized"}
                elif auth == TOKENS["visitor"] and self.path == "/users/1001":
                    status, body = 200, {"id": "1001", "email": "owner@example.test"}  # BOLA flaw
                elif auth == TOKENS["visitor"] and self.path == "/users/1002":
                    status, body = 200, {"id": "1002", "email": "visitor@example.test"}
                elif auth == TOKENS["owner"] and self.path == "/users/1001":
                    status, body = 200, {"id": "1001", "email": "owner@example.test"}
                elif self.path == "/admin/settings":
                    status, body = (
                        (200, {"signing_key": "secret-admin-key"})
                        if auth in (TOKENS["owner"], TOKENS["admin"])
                        else (403, {"error": "Forbidden"})
                    )
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

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), GatewayMock)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.target = f"http://127.0.0.1:{self.server.server_port}"
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def run_cli(self, args: List[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = api_sentinel.main(args)
        return code, out.getvalue(), err.getvalue()

    def test_cli_validate_config_refuses_or_shared_apikey_and_accepts_true_and_shared_apikey(self) -> None:
        identities = {
            "owner": {"id": "1001", "headers": {"X-API-Key": APP_KEY}, "token": TOKENS["owner"], "parameters": {"id": "1001"}},
            "visitor": {"id": "1002", "headers": {"X-API-Key": APP_KEY}, "token": TOKENS["visitor"], "parameters": {"id": "1002"}},
            "anonymous": {},
            "roles": {
                "admin": {"role": "administrator", "headers": {"X-API-Key": APP_KEY}, "token": TOKENS["admin"]},
                "viewer": {"role": "viewer", "headers": {"X-API-Key": APP_KEY}, "token": TOKENS["viewer"]},
            },
        }
        cfg = {
            "identities": identities,
            "bola": {
                "GET /users/{id}": {"resource_id_paths": ["id"]},
                "GET /admin/settings": {"required_role": "administrator", "private_data_paths": ["signing_key"]},
            },
        }
        cfg_path = self.folder / "config.json"
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

        # 1. OR spec -> --validate-config MUST fail (exit 2) and Python API MUST raise ValueError
        or_spec = make_spec(HEADER_AND_BEARER_SCHEMES, [{"ApiKeyAuth": []}, {"BearerAuth": []}])
        or_spec_path = self.folder / "or_spec.json"
        or_spec_path.write_text(json.dumps(or_spec), encoding="utf-8")
        code, out, err = self.run_cli(["--spec", str(or_spec_path), "--config", str(cfg_path), "--validate-config"])
        self.assertEqual(code, 2, out + err)
        self.assertIn("x-api-key", (out + err).lower())
        for secret in ALL_SECRETS:
            self.assertNotIn(secret, out + err)
        with self.assertRaises(ValueError):
            APISentinelAuditor(str(or_spec_path), self.target, identities_config=identities)
        self.assertEqual(self.seen, [])

        # 2. True AND spec -> --validate-config MUST pass (exit 0) and full loopback scan isolates identities
        and_spec = make_spec(HEADER_AND_BEARER_SCHEMES, [{"ApiKeyAuth": [], "BearerAuth": []}])
        and_spec_path = self.folder / "and_spec.json"
        and_spec_path.write_text(json.dumps(and_spec), encoding="utf-8")
        code, out, err = self.run_cli(["--spec", str(and_spec_path), "--config", str(cfg_path), "--validate-config"])
        self.assertEqual(code, 0, out + err)

        rep_json = self.folder / "and_report.json"
        rep_html = self.folder / "and_report.html"
        code, out, err = self.run_cli([
            "--spec", str(and_spec_path),
            "--config", str(cfg_path),
            "--target", self.target,
            "--delay", "0",
            "--export-json", str(rep_json),
            "--output", str(rep_html),
        ])
        self.assertEqual(code, 0, out + err)
        report = json.loads(rep_json.read_text(encoding="utf-8"))
        verdicts = {(r["check"], r["endpoint"], (r.get("evidence") or {}).get("rbac_role")): r["verdict"] for r in report["results"]}
        self.assertEqual(verdicts[("BOLA", "GET /users/{id}", None)], "CONFIRMED")
        self.assertEqual(verdicts[("RBAC", "GET /admin/settings", "viewer")], "SECURE")

        # Anonymous sent neither header; every authenticated identity sent APP_KEY + its own Bearer token
        anon_reqs = [r for r in self.seen if r["auth"] is None]
        self.assertTrue(anon_reqs and all(r["api_key"] is None for r in anon_reqs))
        auth_reqs = [r for r in self.seen if r["auth"] is not None]
        self.assertEqual({r["auth"] for r in auth_reqs}, set(TOKENS.values()))
        self.assertTrue(all(r["api_key"] == APP_KEY for r in auth_reqs))

    def test_late_shared_apikey_mutation_on_or_spec_is_blocked_before_wire(self) -> None:
        or_spec = make_spec(HEADER_AND_BEARER_SCHEMES, [{"ApiKeyAuth": []}, {"BearerAuth": []}])
        or_spec_path = self.folder / "late_or.json"
        or_spec_path.write_text(json.dumps(or_spec), encoding="utf-8")
        identities = {
            "owner": {"id": "1001", "headers": {"X-API-Key": OWNER_KEY}, "token": TOKENS["owner"], "parameters": {"id": "1001"}},
            "visitor": {"id": "1002", "headers": {"X-API-Key": VISITOR_KEY}, "token": TOKENS["visitor"], "parameters": {"id": "1002"}},
            "anonymous": {},
        }
        auditor = APISentinelAuditor(
            str(or_spec_path),
            self.target,
            request_delay=0,
            max_workers=1,
            identities_config=identities,
            bola_config={"GET /users/{id}": {"resource_id_paths": ["id"]}},
        )
        # Mutate visitor after construction to share owner's X-API-Key
        auditor.identities["visitor"]["headers"]["X-API-Key"] = OWNER_KEY
        with contextlib.redirect_stdout(io.StringIO()):
            auditor.run()
        self.assertEqual([r for r in self.seen if r["api_key"] == OWNER_KEY], [])
        bola = next(r for r in auditor.results if r["check"] == "BOLA" and r["endpoint"] == "GET /users/{id}")
        self.assertIn("no request was sent", bola["reason"])


if __name__ == "__main__":
    unittest.main()
