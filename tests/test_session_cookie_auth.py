"""Session cookie authentication from the specification to the wire.

An OpenAPI ``apiKey`` scheme ``in: cookie`` names a session cookie. GrantTrace
drafts it for Owner and Visitor (``--init-config``), configuration validation and
the Python API accept it as each identity's authentication, and every request of
an identity carries its own session cookie and no other. The same rules decide
validation, construction and each request, so an identity changed after the
auditor was built is held to them too.

Every dynamic test talks to a loopback server in this process; the session
values below are fictitious and must never appear in a message or report.
"""

from __future__ import annotations

import copy
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import api_sentinel
from core.auditor import APISentinelAuditor
from core.config_scaffold import DRAFT_KEY, INPUT_PREFIX, build_config_scaffold, config_needs_input
from core.config_validator import ConfigValidator
from core.transport import HttpTransport

COOKIE = "SESSIONID"
SESSIONS = {"owner": "ownerSess-c0ffee01", "visitor": "visitorSess-c0ffee02",
            "admin": "adminSess-c0ffee03", "viewer": "viewerSess-c0ffee04"}
TOKENS = {"owner": "Bearer ownerTok-c0ffee05", "visitor": "Bearer visitorTok-c0ffee06",
          "admin": "Bearer adminTok-c0ffee07", "viewer": "Bearer viewerTok-c0ffee08"}
KEYS = {"owner": "ownerKey-c0ffee09", "visitor": "visitorKey-c0ffee0a",
        "admin": "adminKey-c0ffee0b", "viewer": "viewerKey-c0ffee0c"}
SECRETS = (*SESSIONS.values(), *(token.split()[1] for token in TOKENS.values()), *KEYS.values())
ACCOUNTS = {"owner": ("1001", "user"), "visitor": ("1002", "user"),
            "admin": ("9001", "administrator"), "viewer": ("9002", "viewer")}


def _jar(header: Optional[str]) -> Dict[str, str]:
    return dict(part.strip().split("=", 1) for part in (header or "").split(";") if "=" in part)


class _Api(BaseHTTPRequestHandler):
    """Authenticates by the session cookie, X-Session-Key or a bearer token, and records every request.

    With ``require_all`` set, a request is authenticated only when every
    credential it carries belongs to the same account and the session cookie
    and bearer token are both present (Bearer + Cookie authentication).
    """

    seen: List[Dict[str, Any]] = []
    lock = threading.Lock()
    require_all = False
    session_only = False  # Only the session cookie authenticates (an ordinary cookie or a token does not).

    def log_message(self, *args: Any) -> None:
        pass

    @classmethod
    def account(cls, jar: Dict[str, str], key: Optional[str], auth: Optional[str]) -> Optional[str]:
        by_session = next((name for name, value in SESSIONS.items() if jar.get(COOKIE) == value), None)
        by_key = next((name for name, value in KEYS.items() if key == value), None)
        by_token = next((name for name, value in TOKENS.items() if auth == value), None)
        if cls.require_all:
            return by_session if by_session and by_session == by_token else None
        if cls.session_only:
            return by_session
        return by_session or by_key or by_token

    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        jar = _jar(self.headers.get("Cookie"))
        who = self.account(jar, self.headers.get("X-Session-Key"), self.headers.get("Authorization"))
        with self.lock:
            type(self).seen.append({"method": self.command, "path": self.path, "jar": jar, "who": who,
                                    "cookie_raw": self.headers.get("Cookie") or "",
                                    "auth": self.headers.get("Authorization"),
                                    "key": self.headers.get("X-Session-Key"), "body": body})
        role = ACCOUNTS[who][1] if who else None
        if who is None:
            status, document = 401, {"error": "Unauthorized"}
        elif self.path.startswith("/users/"):
            user = self.path.split("/")[2].split("?")[0]
            status, document = 200, {"id": user, "email": f"user{user}@example.test"}  # BOLA: any session reads any user
        elif self.path.startswith("/admin/settings") or self.path.startswith("/reports/search"):
            status, document = ((200, {"signing_key": "sk-settings-c0ffee"}) if role == "administrator"
                                else (403, {"error": "Forbidden"}))
        else:
            status, document = 404, {"error": "Not found"}
        data = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _answer


def _spec(declare_cookie: bool = False, schemes: Optional[Dict[str, Any]] = None,
          security: Optional[List[Dict[str, Any]]] = None, post: bool = False) -> Dict[str, Any]:
    cookie = [{"name": COOKIE, "in": "cookie", "required": True, "schema": {"type": "string"}}] if declare_cookie else []
    paths: Dict[str, Any] = {
        "/users/{id}": {"get": {"operationId": "getUser", "responses": {"200": {"description": "OK"}},
                                "parameters": [{"name": "id", "in": "path", "required": True,
                                                "schema": {"type": "string"}}, *cookie]}},
        "/admin/settings": {"get": {"operationId": "getAdminSettings", "responses": {"200": {"description": "OK"}},
                                    **({"parameters": cookie} if cookie else {})}},
    }
    if post:
        paths["/reports/search"] = {"post": {"operationId": "searchReports",
                                             "responses": {"200": {"description": "OK"}}}}
    return {
        "openapi": "3.0.3", "info": {"title": "Session cookie API", "version": "1"},
        "components": {"securitySchemes": schemes if schemes is not None else {
            "cookieAuth": {"type": "apiKey", "in": "cookie", "name": COOKIE}}},
        "security": security if security is not None else [{"cookieAuth": []}],
        "paths": paths,
    }


MIXED_SCHEMES = {"bearer": {"type": "http", "scheme": "bearer"},
                 "cookieAuth": {"type": "apiKey", "in": "cookie", "name": COOKIE}}
MIXED_SECURITY = [{"bearer": [], "cookieAuth": []}]  # Bearer AND Cookie
OR_SECURITY = [{"bearer": []}, {"cookieAuth": []}]  # Bearer OR Cookie


def _session(name: str) -> Dict[str, Any]:
    return {"parameters": {COOKIE: SESSIONS[name]}}


def _identities(roles: bool = True, **changes: Any) -> Dict[str, Any]:
    identities: Dict[str, Any] = {
        "owner": {"id": "1001", **_session("owner")},
        "visitor": {"id": "1002", **_session("visitor")},
        "anonymous": {},
    }
    if roles:
        identities["roles"] = {"admin": {"role": "administrator", **_session("admin")},
                               "viewer": {"role": "viewer", **_session("viewer")}}
    for name, value in changes.items():
        target = identities["roles"] if name in ("admin", "viewer") else identities
        if value is None:
            target.pop(name, None)
        else:
            target[name] = value
    return identities


RBAC = {"GET /admin/settings": {"required_role": "administrator", "private_data_paths": ["signing_key"]}}


class _Loopback(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.target = f"http://127.0.0.1:{cls.server.server_address[1]}"
        folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(folder.cleanup)
        cls.folder = Path(folder.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        with _Api.lock:
            _Api.seen = []
        _Api.require_all = False
        _Api.session_only = False

    def write_spec(self, spec: Dict[str, Any], name: str = "spec.json") -> Path:
        path = self.folder / name
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path

    def auditor(self, identities: Dict[str, Any], spec: Optional[Dict[str, Any]] = None,
                **options: Any) -> APISentinelAuditor:
        spec_path = self.write_spec(spec or _spec(), "auditor-spec.json")
        return APISentinelAuditor(str(spec_path), self.target, request_delay=0, max_workers=1,
                                  identities_config=copy.deepcopy(identities),
                                  bola_config=copy.deepcopy(options.pop("bola", RBAC)), **options)

    @staticmethod
    def run_scan(auditor: APISentinelAuditor) -> None:
        with redirect_stdout(io.StringIO()):
            auditor.run()

    def assert_isolated(self, expected_identities: Optional[set] = None) -> None:
        """Each request carries one account's credentials only; anonymous requests carry none."""
        for item in _Api.seen:
            sessions = [name for name, value in SESSIONS.items() if value in json.dumps(item["jar"])]
            tokens = [name for name, value in TOKENS.items() if item["auth"] == value]
            keys = [name for name, value in KEYS.items() if item["key"] == value]
            self.assertLessEqual(len(set(sessions + tokens + keys)), 1, item["path"])
            self.assertLessEqual(len(sessions), 1)
            self.assertEqual(item["cookie_raw"].count(COOKIE + "="), 1 if sessions else 0)
        if expected_identities is not None:
            self.assertEqual({item["who"] for item in _Api.seen}, expected_identities)

    def results(self, auditor: APISentinelAuditor, check: str, endpoint: str) -> List[Dict[str, Any]]:
        return [item for item in auditor.results if item["check"] == check and item["endpoint"] == endpoint]

    def rbac(self, auditor: APISentinelAuditor, role: str) -> Dict[str, Any]:
        return next(item for item in auditor.results if item["check"] == "RBAC"
                    and (item.get("evidence") or {}).get("rbac_role") == role)

    def assert_no_secret(self, *texts: str) -> None:
        for text in texts:
            for secret in SECRETS:
                self.assertNotIn(secret, text)


class EndToEndTests(_Loopback):
    """Specification -> --init-config -> filled config -> --validate-config -> scan -> wire."""

    def call_cli(self, arguments: List[str]):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("urllib.request.getproxies", return_value={}), redirect_stdout(stdout), redirect_stderr(stderr):
            code = api_sentinel.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def fill(value: Any, mapping: Dict[str, Any]) -> Any:
        if isinstance(value, dict):
            return {key: EndToEndTests.fill(item, mapping) for key, item in value.items()}
        if isinstance(value, list):
            return [EndToEndTests.fill(item, mapping) for item in value]
        if isinstance(value, str) and value.startswith(INPUT_PREFIX):
            label = value[len(INPUT_PREFIX):]
            return next((replacement for key, replacement in mapping.items() if label.startswith(key)),
                        "UNFILLED " + label)
        return value

    def test_session_cookie_specification_reaches_the_wire_isolated(self):
        for declared in (False, True):
            with self.subTest(cookie_parameter_declared=declared):
                with _Api.lock:
                    _Api.seen = []
                tag = "declared" if declared else "scheme"
                spec_path = self.write_spec(_spec(declare_cookie=declared), f"e2e-{tag}.json")
                config_path = self.folder / f"e2e-{tag}.json.config.json"
                code, out, err = self.call_cli(["--spec", str(spec_path), "--init-config", str(config_path)])
                self.assertEqual(code, 0, err)
                draft = json.loads(config_path.read_text(encoding="utf-8"))
                checklist = json.loads(config_path.with_suffix(".checklist.json").read_text(encoding="utf-8"))
                # The session cookie is drafted for Owner and Visitor only, never for Anonymous.
                for name in ("owner", "visitor"):
                    self.assertTrue(draft["identities"][name]["parameters"][COOKIE].startswith(INPUT_PREFIX))
                self.assertNotIn(COOKIE, json.dumps(draft["identities"]["anonymous"]))
                self.assertTrue(config_needs_input(draft))
                scheme = next(item for item in checklist["security_schemes"] if item["name"] == "cookieAuth")
                self.assertEqual(scheme["config_paths"], [f"identities.owner.parameters.{COOKIE}",
                                                          f"identities.visitor.parameters.{COOKIE}"])
                self.assertIn("every request", scheme["needs_review"])
                self.assertIn("identities.roles", scheme["needs_review"])

                filled = self.fill(draft, {
                    "owner test account id": "1001", "visitor test account id": "1002",
                    "owner session cookie": SESSIONS["owner"], "visitor session cookie": SESSIONS["visitor"],
                    "owner authentication cookie": SESSIONS["owner"],
                    "visitor authentication cookie": SESSIONS["visitor"],
                    "owner resource parameter id": "1001", "visitor resource parameter id": "1002",
                })
                filled.pop(DRAFT_KEY)
                self.assertNotIn("UNFILLED", json.dumps(filled))
                filled["identities"]["roles"] = {"admin": {"role": "administrator", **_session("admin")},
                                                 "viewer": {"role": "viewer", **_session("viewer")}}
                filled["bola"] = copy.deepcopy(RBAC)
                filled_path = self.folder / f"e2e-{tag}-filled.json"
                filled_path.write_text(json.dumps(filled), encoding="utf-8")

                code, out, err = self.call_cli(["--spec", str(spec_path), "--config", str(filled_path),
                                                "--validate-config"])
                self.assertEqual(code, 0, out + err)
                self.assertEqual(_Api.seen, [])

                html, exported = self.folder / f"e2e-{tag}.html", self.folder / f"e2e-{tag}-report.json"
                code, out, err = self.call_cli(["--spec", str(spec_path), "--config", str(filled_path),
                                                "--target", self.target, "--delay", "0", "--output", str(html),
                                                "--export-json", str(exported)])
                self.assertEqual(code, 0, out + err)
                report = json.loads(exported.read_text(encoding="utf-8"))
                verdicts = {(item["check"], item["endpoint"], (item.get("evidence") or {}).get("rbac_role")):
                            item["verdict"] for item in report["results"]}
                self.assertEqual(verdicts[("BOLA", "GET /users/{id}", None)], "CONFIRMED")
                self.assertEqual(verdicts[("RBAC", "GET /admin/settings", "viewer")], "SECURE")
                # Every account sent requests, each with its own session only; Anonymous sent none.
                self.assert_isolated({"owner", "visitor", "admin", "viewer", None})
                anonymous = [item for item in _Api.seen if item["who"] is None]
                self.assertTrue(anonymous)
                self.assertTrue(all(COOKIE not in item["jar"] for item in anonymous))
                self.assert_no_secret(out, err, html.read_text(encoding="utf-8"), exported.read_text(encoding="utf-8"))


class ValidationTests(unittest.TestCase):
    """Configuration validation decides session cookies like the scanner does."""

    def errors(self, identities: Dict[str, Any], spec: Optional[Dict[str, Any]] = None,
               **sections: Any) -> List[Any]:
        config = {"identities": identities, **sections}
        result = ConfigValidator.validate(config, spec if spec is not None else _spec())
        rendered = "\n".join(issue.format() for issue in result.issues)
        for secret in SECRETS:
            self.assertNotIn(secret, rendered)
        return result.errors

    def paths(self, *args: Any, **kwargs: Any) -> List[str]:
        return sorted(issue.path for issue in self.errors(*args, **kwargs))

    def test_session_cookie_identities_are_accepted(self):
        cases = {
            "identity parameters": (_identities(), _spec()),
            "declared cookie parameter": (_identities(), _spec(declare_cookie=True)),
            "Cookie header": (_identities(
                owner={"id": "1001", "headers": {"Cookie": f"{COOKIE}={SESSIONS['owner']}; theme=dark"}},
                visitor={"id": "1002", "headers": {"Cookie": f"{COOKIE}={SESSIONS['visitor']}; theme=dark"}}),
                _spec()),
            "Bearer and Cookie": (_identities(
                owner={"id": "1001", "token": TOKENS["owner"], **_session("owner")},
                visitor={"id": "1002", "token": TOKENS["visitor"], **_session("visitor")},
                admin={"role": "administrator", "token": TOKENS["admin"], **_session("admin")},
                viewer={"role": "viewer", "token": TOKENS["viewer"], **_session("viewer")}),
                _spec(schemes=MIXED_SCHEMES, security=MIXED_SECURITY)),
            "Bearer or Cookie, identities authenticating differently": (_identities(
                owner={"id": "1001", "token": TOKENS["owner"]},
                admin={"role": "administrator", "token": TOKENS["admin"]}),
                _spec(schemes=MIXED_SCHEMES, security=OR_SECURITY)),
        }
        for name, (identities, spec) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.paths(identities, spec, bola=RBAC), [])

    def test_identity_material_that_breaks_isolation_is_refused(self):
        same = {"id": "1002", **_session("owner")}
        cases = {
            "owner and visitor share the session": (_identities(visitor=same), _spec(),
                                                   ["identities.visitor"]),
            "shared session behind a different second cookie": (_identities(
                owner={"id": "1001", "headers": {"Cookie": f"{COOKIE}={SESSIONS['owner']}; theme=dark"}},
                visitor={"id": "1002", "headers": {"Cookie": f"{COOKIE}={SESSIONS['owner']}; theme=light"}}),
                _spec(), ["identities.visitor"]),
            "shared session behind different bearer tokens": (_identities(
                roles=False,
                owner={"id": "1001", "token": TOKENS["owner"], **_session("owner")},
                visitor={"id": "1002", "token": TOKENS["visitor"], **_session("owner")}),
                _spec(schemes=MIXED_SCHEMES, security=MIXED_SECURITY), ["identities.visitor"]),
            "visitor without the session cookie the specification requires": (_identities(
                roles=False, visitor={"id": "1002", "token": TOKENS["visitor"]}),
                _spec(schemes=MIXED_SCHEMES, security=[{"cookieAuth": []}]),
                ["identities.visitor"]),
            "visitor without the bearer token Bearer + Cookie requires": (_identities(
                roles=False, owner={"id": "1001", "token": TOKENS["owner"], **_session("owner")}),
                _spec(schemes=MIXED_SCHEMES, security=MIXED_SECURITY), ["identities.visitor"]),
            "anonymous identity with a session cookie": (_identities(anonymous=_session("owner")), _spec(),
                                                         ["identities.anonymous"]),
            "role without credentials": (_identities(viewer={"role": "viewer"}), _spec(),
                                         ["identities.roles.viewer"]),
            "role reusing another role's session": (_identities(viewer={"role": "viewer", **_session("admin")}),
                                                    _spec(), ["identities.roles.viewer"]),
            "role without the session cookie the others send": (_identities(
                viewer={"role": "viewer", "token": TOKENS["viewer"]}), _spec(), ["identities.roles.viewer"]),
            "role session in both the Cookie header and parameters": (_identities(
                viewer={"role": "viewer", "headers": {"Cookie": f"{COOKIE}={SESSIONS['viewer']}"},
                        **_session("viewer")}), _spec(), ["identities.roles.viewer.parameters.SESSIONID"]),
            "session cookie value that cannot be sent": (_identities(
                viewer={"role": "viewer", "parameters": {COOKIE: SESSIONS["viewer"] + "; admin=1"}}), _spec(),
                ["identities.roles.viewer.parameters.SESSIONID"]),
        }
        for name, (identities, spec, expected) in cases.items():
            with self.subTest(name=name):
                paths = self.paths(identities, spec, bola=RBAC)
                for path in expected:
                    self.assertIn(path, paths)

    def test_roles_are_held_to_custom_authentication_headers(self):
        identities = {
            "owner": {"id": "1001", "headers": {"X-Session-Key": KEYS["owner"]}, "auth_header_names": ["X-Session-Key"]},
            "visitor": {"id": "1002", "headers": {"X-Session-Key": KEYS["visitor"]}},
            "anonymous": {},
            "roles": {"admin": {"role": "administrator", "headers": {"X-Session-Key": KEYS["admin"]}},
                      "viewer": {"role": "viewer", "token": TOKENS["viewer"]}},
        }
        spec = _spec(schemes={}, security=[])
        self.assertEqual(self.paths(identities, spec), ["identities.roles.viewer"])
        identities["roles"]["viewer"]["headers"] = {"X-Session-Key": KEYS["admin"]}
        self.assertEqual(self.paths(identities, spec), ["identities.roles.viewer"])
        identities["roles"]["viewer"]["headers"] = {"X-Session-Key": KEYS["viewer"]}
        self.assertEqual(self.paths(identities, spec), [])

    def test_anonymous_parameter_values_must_not_carry_authentication(self):
        for declared in (False, True):
            spec = _spec(declare_cookie=declared)
            with self.subTest(cookie_parameter_declared=declared):
                paths = self.paths(_identities(), spec, parameter_values={
                    "GET /users/{id}": {"anonymous": {COOKIE: SESSIONS["owner"]}}})
                self.assertEqual(paths, ["parameter_values.GET /users/{id}.anonymous.SESSIONID"])
        paths = self.paths(_identities(), _spec(), parameter_values={
            "GET /users/{id}": {"common": {COOKIE: SESSIONS["owner"]}}})
        self.assertEqual(paths, ["parameter_values.GET /users/{id}.common.SESSIONID"])

    def test_messages_name_identities_and_cookies_not_values(self):
        errors = self.errors(_identities(visitor={"id": "1002", **_session("owner")}))
        message = " ".join(issue.message + issue.actual for issue in errors)
        self.assertIn(COOKIE, message)
        identities = _identities()
        identities["roles"]["ReadOnlyViewer"] = {"role": "viewer"}
        messages = [issue.message for issue in self.errors(identities)]
        self.assertTrue(any(message.startswith("Role 'ReadOnlyViewer'") for message in messages), messages)


class PythonApiTests(_Loopback):
    """APISentinelAuditor applies the same rules when it is built without the CLI."""

    def test_session_cookie_identities_are_accepted(self):
        for identities, spec in (
                (_identities(), _spec()),
                (_identities(), _spec(declare_cookie=True)),
                (_identities(owner={"id": "1001", "token": TOKENS["owner"], **_session("owner")},
                             visitor={"id": "1002", "token": TOKENS["visitor"], **_session("visitor")},
                             admin={"role": "administrator", "token": TOKENS["admin"], **_session("admin")},
                             viewer={"role": "viewer", "token": TOKENS["viewer"], **_session("viewer")}),
                 _spec(schemes=MIXED_SCHEMES, security=MIXED_SECURITY))):
            with self.subTest(schemes=sorted(spec["components"]["securitySchemes"])):
                self.auditor(identities, spec)

    def test_material_that_breaks_isolation_is_refused_before_any_request(self):
        cases = {
            "shared session": _identities(visitor={"id": "1002", **_session("owner")}),
            "shared session behind a second cookie": _identities(
                owner={"id": "1001", "headers": {"Cookie": f"{COOKIE}={SESSIONS['owner']}; theme=dark"}},
                visitor={"id": "1002", "headers": {"Cookie": f"{COOKIE}={SESSIONS['owner']}; theme=light"}}),
            "anonymous session": _identities(anonymous=_session("visitor")),
            "role without credentials": _identities(viewer={"role": "viewer"}),
            "role reusing the admin session": _identities(viewer={"role": "viewer", **_session("admin")}),
            "role without the session cookie": _identities(viewer={"role": "viewer", "token": TOKENS["viewer"]}),
            "role session twice": _identities(viewer={"role": "viewer", **_session("viewer"),
                                                      "headers": {"Cookie": f"{COOKIE}={SESSIONS['viewer']}"}}),
        }
        for name, identities in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as caught:
                    self.auditor(identities)
                self.assert_no_secret(str(caught.exception))
                self.assertEqual(_Api.seen, [])


class RequestIsolationTests(_Loopback):
    """What each identity actually sends."""

    def test_session_cookies_are_isolated_for_bola_and_rbac(self):
        for declared in (False, True):
            with self.subTest(cookie_parameter_declared=declared):
                with _Api.lock:
                    _Api.seen = []
                auditor = self.auditor(_identities(), _spec(declare_cookie=declared))
                self.run_scan(auditor)
                self.assert_isolated({"owner", "visitor", "admin", "viewer", None})
                self.assertEqual(self.results(auditor, "BOLA", "GET /users/{id}")[0]["verdict"], "CONFIRMED")
                self.assertEqual(self.rbac(auditor, "viewer")["verdict"], "SECURE")
                matrix = auditor.rbac_matrix_record()["GET /admin/settings"]["roles"]
                self.assertTrue(matrix["admin"]["baseline"])
                self.assertEqual(matrix["viewer"]["status"], 403)
                self.assert_no_secret(json.dumps(auditor.results, default=str))

    def test_bearer_and_cookie_are_sent_together_per_identity(self):
        _Api.require_all = True
        identities = _identities(
            owner={"id": "1001", "token": TOKENS["owner"], **_session("owner")},
            visitor={"id": "1002", "token": TOKENS["visitor"], **_session("visitor")},
            admin={"role": "administrator", "token": TOKENS["admin"], **_session("admin")},
            viewer={"role": "viewer", "token": TOKENS["viewer"], **_session("viewer")})
        auditor = self.auditor(identities, _spec(schemes=MIXED_SCHEMES, security=MIXED_SECURITY))
        self.run_scan(auditor)
        self.assert_isolated({"owner", "visitor", "admin", "viewer", None})
        for item in _Api.seen:
            self.assertEqual(item["auth"] is None, COOKIE not in item["jar"])
        self.assertEqual(self.rbac(auditor, "viewer")["verdict"], "SECURE")

    def test_session_cookie_rides_with_declared_business_cookies(self):
        spec = _spec(declare_cookie=True)
        spec["paths"]["/users/{id}"]["get"]["parameters"].append(
            {"name": "theme", "in": "cookie", "required": True, "schema": {"type": "string"}})
        auditor = self.auditor(_identities(roles=False), spec, bola={},
                               parameter_values={"GET /users/{id}": {"common": {"theme": "dark"}}})
        self.run_scan(auditor)
        users = [item for item in _Api.seen if item["path"].startswith("/users/")]
        self.assertTrue(users)
        for item in users:
            self.assertEqual(item["jar"].get("theme"), "dark")
        self.assert_isolated({"owner", "visitor", None})

    def test_a_role_probe_on_a_declared_session_cookie_does_not_fail_on_the_role_name(self):
        auditor = self.auditor(_identities(), _spec(declare_cookie=True))
        self.run_scan(auditor)
        for role in ("admin", "viewer"):
            record = auditor.rbac_matrix_record()["GET /admin/settings"]["roles"][role]
            self.assertNotEqual(record.get("access"), "ERROR", record)
        self.assertNotIn("KeyError", json.dumps(auditor.results, default=str))


class LateChangeTests(_Loopback):
    """Identity material changed after construction is held to the same rules at each request."""

    def scan_after(self, change) -> APISentinelAuditor:
        auditor = self.auditor(_identities())
        change(auditor.identities)
        self.run_scan(auditor)
        return auditor

    def test_a_shared_session_is_not_sent(self):
        auditor = self.scan_after(lambda ids: ids["visitor"]["parameters"].update({COOKIE: SESSIONS["owner"]}))
        self.assertFalse(any(item["jar"].get(COOKIE) == SESSIONS["owner"] for item in _Api.seen))
        bola = self.results(auditor, "BOLA", "GET /users/{id}")[0]
        self.assertNotEqual(bola["verdict"], "CONFIRMED")
        self.assertIn("no request was sent", bola["reason"])
        self.assert_no_secret(json.dumps(auditor.results, default=str))

    def test_an_anonymous_session_is_not_sent(self):
        auditor = self.scan_after(lambda ids: ids["anonymous"].update(_session("visitor")))
        # No request carries the Visitor session except the Visitor's own.
        self.assertFalse(any(item["jar"].get(COOKIE) == SESSIONS["visitor"] for item in _Api.seen
                             if item["path"] == "/users/1001" and item["method"] == "GET"
                             and item["who"] != "visitor"))
        self.assertFalse(any(item["who"] is None and COOKIE in item["jar"] for item in _Api.seen))
        reasons = " ".join(item["reason"] for item in auditor.results)
        self.assertIn("anonymous", reasons.lower())

    def test_a_role_that_loses_its_session_is_not_probed_unauthenticated(self):
        auditor = self.scan_after(lambda ids: ids["roles"]["viewer"].pop("parameters"))
        record = self.rbac(auditor, "viewer")
        self.assertNotEqual(record["verdict"], "SECURE")
        self.assertEqual(record["verdict"], "ERROR")
        unauthenticated_admin = [item for item in _Api.seen if item["path"] == "/admin/settings" and item["who"] is None]
        # Only the Anonymous probe reaches the server without a session.
        self.assertEqual(len(unauthenticated_admin), 1)

    def test_a_role_that_copies_the_privileged_session_is_not_probed(self):
        auditor = self.scan_after(lambda ids: ids["roles"]["viewer"]["parameters"].update({COOKIE: SESSIONS["admin"]}))
        # Either role could be the wrong one: neither sends the shared session, and nothing is confirmed.
        self.assertEqual(sum(1 for item in _Api.seen if item["who"] == "admin"), 0)
        rbac = [item for item in auditor.results if item["check"] == "RBAC"]
        self.assertTrue(rbac)
        self.assertFalse(any(item["verdict"] in ("CONFIRMED", "SECURE") for item in rbac))

    def test_a_role_session_in_two_places_is_not_sent(self):
        auditor = self.scan_after(lambda ids: ids["roles"]["viewer"].update(
            {"headers": {"Cookie": f"{COOKIE}=otherSess-c0ffee0d"}}))
        self.assertEqual(self.rbac(auditor, "viewer")["verdict"], "ERROR")
        self.assertEqual(sum(1 for item in _Api.seen if item["who"] == "admin"), 1)
        self.assertFalse(any(item["who"] == "viewer" for item in _Api.seen))


class RequestGuardCompatibilityTests(_Loopback):
    """The read-only request rules of #99 / #100 still hold for session cookie identities."""

    def test_method_override_and_writing_bodies_are_still_refused(self):
        for name, identities in (
                ("owner override", _identities(owner={"id": "1001", **_session("owner"),
                                                      "headers": {"X-HTTP-Method-Override": "DELETE"}})),
                ("role writing body", _identities(viewer={"role": "viewer", **_session("viewer"),
                                                          "body": {"query": "mutation { resetAll { ok } }"}}))):
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as caught:
                    self.auditor(identities)
                self.assertNotIn("session", str(caught.exception).lower())
                self.assertEqual(_Api.seen, [])

    def test_a_late_override_on_a_session_identity_never_leaves(self):
        auditor = self.auditor(_identities())
        auditor.identities["visitor"]["headers"] = {"X-HTTP-Method-Override": "DELETE"}
        self.run_scan(auditor)
        self.assertFalse(any(item["who"] == "visitor" for item in _Api.seen))
        self.assert_isolated()

    def test_read_only_post_probes_carry_each_role_session(self):
        spec = _spec(post=True)
        bola = {"POST /reports/search": {"read_only": True, "body": {"q": "x"}, "required_role": "administrator",
                                         "private_data_paths": ["signing_key"]}}
        auditor = self.auditor(_identities(), spec, bola=bola)
        self.run_scan(auditor)
        posts = [item for item in _Api.seen if item["method"] == "POST"]
        self.assertEqual({item["who"] for item in posts}, {"owner", "visitor", "admin", "viewer", None})
        self.assert_isolated()
        self.assertEqual(self.rbac(auditor, "viewer")["verdict"], "SECURE")

    def test_the_transport_still_refuses_writing_post_bodies_with_a_session(self):
        transport = HttpTransport(request_delay=0, request_timeout=2, max_response_bytes=4096, insecure_ssl=False)
        result = transport.send("POST", self.target + "/reports/search",
                                {"cookie": f"{COOKIE}={SESSIONS['owner']}"}, {"query": "mutation { a { b } }"})
        self.assertIn("no request was sent", result.error)
        self.assertEqual(_Api.seen, [])


BEARER_SCHEMES = {"bearer": {"type": "http", "scheme": "bearer"}}
BFLA = {"GET /admin/settings": {"required_role": "administrator", "owner_role": "administrator",
                                "visitor_role": "user", "private_data_paths": ["signing_key"]}}


class OrdinaryCookieTests(_Loopback):
    """A cookie that is not a credential (theme, language) does not authenticate an identity."""

    THEME_ONLY = {"owner": {"id": "1001", "headers": {"Cookie": "theme=dark"}},
                  "visitor": {"id": "1002", "headers": {"Cookie": "theme=light"}}, "anonymous": {}}

    def validation_paths(self, identities: Dict[str, Any], spec: Dict[str, Any], bola: Any = None) -> List[str]:
        result = ConfigValidator.validate({"identities": identities, **({"bola": bola} if bola else {})}, spec)
        return sorted(issue.path for issue in result.errors)

    def test_theme_cookies_are_no_credentials_when_the_specification_requires_a_session(self):
        self.assertIn("identities.owner", self.validation_paths(self.THEME_ONLY, _spec()))
        self.assertIn("identities.visitor", self.validation_paths(self.THEME_ONLY, _spec()))
        with self.assertRaises(ValueError) as caught:
            self.auditor(self.THEME_ONLY, bola={})
        self.assertIn("no effective authentication material", str(caught.exception))
        self.assertEqual(_Api.seen, [])

    def test_theme_cookies_are_no_credentials_without_a_cookie_scheme(self):
        spec = _spec(schemes=BEARER_SCHEMES, security=[{"bearer": []}])
        identities = {"owner": {"id": "9001", "token": TOKENS["admin"]},
                      "visitor": {"id": "1002", "headers": {"Cookie": "theme=light"}}, "anonymous": {}}
        # A visitor that cannot authenticate would read as a clean BFLA denial: SECURE.
        self.assertIn("identities.visitor", self.validation_paths(identities, spec, BFLA))
        with self.assertRaises(ValueError):
            self.auditor(identities, spec, bola=BFLA)
        roles = dict(self.THEME_ONLY, owner={"id": "1001", "token": TOKENS["owner"]},
                     visitor={"id": "1002", "token": TOKENS["visitor"]},
                     roles={"admin": {"role": "administrator", "token": TOKENS["admin"]},
                            "viewer": {"role": "viewer", "headers": {"Cookie": "theme=light"}}})
        self.assertIn("identities.roles.viewer", self.validation_paths(roles, spec, RBAC))
        with self.assertRaises(ValueError):
            self.auditor(roles, spec)
        self.assertEqual(_Api.seen, [])

    def test_a_theme_cookie_next_to_a_session_adds_nothing_and_may_be_shared(self):
        identities = _identities(
            owner={"id": "1001", "headers": {"Cookie": f"{COOKIE}={SESSIONS['owner']}; theme=dark"}},
            visitor={"id": "1002", "headers": {"Cookie": f"{COOKIE}={SESSIONS['visitor']}; theme=dark"}})
        self.assertEqual(self.validation_paths(identities, _spec(), RBAC), [])
        _Api.session_only = True
        auditor = self.auditor(identities)
        self.run_scan(auditor)
        self.assert_isolated({"owner", "visitor", "admin", "viewer", None})
        self.assertEqual(self.rbac(auditor, "viewer")["verdict"], "SECURE")

    def test_anonymous_still_sends_no_identity_cookie(self):
        with self.assertRaises(ValueError) as caught:
            self.auditor(_identities(anonymous={"headers": {"Cookie": "theme=dark"}}))
        self.assertIn("anonymous", str(caught.exception))

    def test_a_late_theme_only_role_is_not_probed(self):
        _Api.session_only = True
        auditor = self.auditor(_identities())
        auditor.identities["roles"]["viewer"] = {"role": "viewer", "headers": {"Cookie": "theme=light"}}
        self.run_scan(auditor)
        self.assertEqual(self.rbac(auditor, "viewer")["verdict"], "ERROR")
        self.assertEqual([item["who"] for item in _Api.seen if item["path"] == "/admin/settings"].count(None), 1)


class SecurityRequirementTests(_Loopback):
    """OpenAPI security: alternatives are OR, the schemes of one alternative are AND.

    A credential that every alternative of every requirement includes is
    mandatory: every authenticated identity sends it, or none does. Where the
    specification offers alternatives, identities may authenticate differently.
    """

    def validation(self, identities: Dict[str, Any], spec: Dict[str, Any], bola: Any = RBAC):
        return ConfigValidator.validate({"identities": identities, "bola": bola}, spec)

    def both(self, name: str, role: Optional[str] = None) -> Dict[str, Any]:
        entry: Dict[str, Any] = {"token": TOKENS[name], **_session(name)}
        if role:
            entry["role"] = role
        else:
            entry["id"] = ACCOUNTS[name][0]
        return entry

    def complete(self) -> Dict[str, Any]:
        return _identities(owner=self.both("owner"), visitor=self.both("visitor"),
                           admin=self.both("admin", "administrator"), viewer=self.both("viewer", "viewer"))

    def test_and_requires_every_scheme_of_the_alternative(self):
        spec = _spec(schemes=MIXED_SCHEMES, security=MIXED_SECURITY)
        self.assertEqual(self.validation(self.complete(), spec).errors, [])
        for name, change, path, missing in (
                ("viewer without bearer", {"viewer": {"role": "viewer", **_session("viewer")}},
                 "identities.roles.viewer", "Authorization"),
                ("viewer without session", {"viewer": {"role": "viewer", "token": TOKENS["viewer"]}},
                 "identities.roles.viewer", COOKIE),
                ("visitor without bearer", {"visitor": {"id": "1002", **_session("visitor")}},
                 "identities.visitor", "Authorization")):
            with self.subTest(name=name):
                identities = self.complete()
                target = identities["roles"] if "viewer" in change else identities
                target.update(change)
                errors = self.validation(identities, spec).errors
                self.assertIn(path, [issue.path for issue in errors])
                self.assertTrue(any(missing in issue.message for issue in errors if issue.path == path))
                with self.assertRaises(ValueError):
                    self.auditor(identities, spec)
                self.assertEqual(_Api.seen, [])

    def test_or_accepts_either_scheme_and_identities_may_differ(self):
        spec = _spec(schemes=MIXED_SCHEMES, security=OR_SECURITY)
        identities = _identities(owner={"id": "1001", "token": TOKENS["owner"]},
                                 admin={"role": "administrator", "token": TOKENS["admin"]})
        self.assertEqual(self.validation(identities, spec).errors, [])
        auditor = self.auditor(identities, spec)
        self.run_scan(auditor)
        self.assert_isolated({"owner", "visitor", "admin", "viewer", None})
        owner_requests = [item for item in _Api.seen if item["who"] == "owner"]
        self.assertTrue(owner_requests and all(COOKIE not in item["jar"] for item in owner_requests))
        visitor_requests = [item for item in _Api.seen if item["who"] == "visitor"]
        self.assertTrue(visitor_requests and all(item["auth"] is None for item in visitor_requests))
        self.assertEqual(self.rbac(auditor, "viewer")["verdict"], "SECURE")

    def test_a_credential_is_mandatory_only_when_every_requirement_includes_it(self):
        # /users/{id} accepts either; /admin/settings needs both: neither credential is mandatory everywhere.
        spec = _spec(schemes=MIXED_SCHEMES, security=OR_SECURITY)
        spec["paths"]["/admin/settings"]["get"]["security"] = MIXED_SECURITY
        mixed = _identities(owner={"id": "1001", "token": TOKENS["owner"]})
        self.assertEqual(self.validation(mixed, spec, bola={}).errors, [])
        # A public operation (security: []) does not make a required session optional elsewhere.
        spec = _spec()
        spec["paths"]["/admin/settings"]["get"]["security"] = []
        errors = self.validation(_identities(viewer={"role": "viewer", "token": TOKENS["viewer"]}), spec).errors
        self.assertIn("identities.roles.viewer", [issue.path for issue in errors])

    def test_a_late_missing_bearer_stops_the_role_probe_before_transmission(self):
        _Api.require_all = True
        spec = _spec(schemes=MIXED_SCHEMES, security=MIXED_SECURITY)
        auditor = self.auditor(self.complete(), spec)
        auditor.identities["roles"]["viewer"].pop("token")
        self.run_scan(auditor)
        record = self.rbac(auditor, "viewer")
        self.assertEqual(record["verdict"], "ERROR")
        self.assertIn("no request was sent", record["reason"])
        self.assertFalse(any(SESSIONS["viewer"] in json.dumps(item["jar"]) for item in _Api.seen))


class ScaffoldTests(unittest.TestCase):
    """--init-config drafts the session cookie a security scheme requires."""

    def draft(self, spec: Dict[str, Any]):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "spec.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            return build_config_scaffold(str(path))

    def test_a_required_session_cookie_is_drafted_per_identity(self):
        draft, checklist = self.draft(_spec())
        for name in ("owner", "visitor"):
            self.assertEqual(list(draft["identities"][name]["parameters"]), [COOKIE])
        self.assertEqual(draft["identities"]["anonymous"]["parameters"], {})
        steps = " ".join(checklist["steps"])
        self.assertIn("session cookie", steps.lower())

    def test_an_unused_cookie_scheme_is_not_drafted(self):
        draft, checklist = self.draft(_spec(schemes=MIXED_SCHEMES, security=[{"bearer": []}]))
        for name in ("owner", "visitor"):
            self.assertEqual(draft["identities"][name]["parameters"], {})
        scheme = next(item for item in checklist["security_schemes"] if item["name"] == "cookieAuth")
        self.assertNotIn("config_paths", scheme)

    def test_a_referenced_cookie_scheme_is_drafted_and_keeps_its_review_note(self):
        spec = _spec(schemes={"cookieAuth": {"$ref": "#/components/x-session"}})
        spec["components"]["x-session"] = {"type": "apiKey", "in": "cookie", "name": COOKIE}
        draft, checklist = self.draft(spec)
        for name in ("owner", "visitor"):
            self.assertEqual(list(draft["identities"][name]["parameters"]), [COOKIE])
        scheme = next(item for item in checklist["security_schemes"] if item["name"] == "cookieAuth")
        self.assertIn("Resolve this security scheme locally", scheme["needs_review"])
        self.assertIn("every request", scheme["needs_review"])

    def test_an_operation_level_cookie_requirement_is_drafted_once(self):
        spec = _spec(declare_cookie=True, security=[])
        spec["paths"]["/users/{id}"]["get"]["security"] = [{"cookieAuth": []}]
        draft, _ = self.draft(spec)
        for name in ("owner", "visitor"):
            self.assertEqual(list(draft["identities"][name]["parameters"]), [COOKIE])


if __name__ == "__main__":
    unittest.main()
