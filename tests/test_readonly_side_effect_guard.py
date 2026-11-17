"""Regression tests for GET/HEAD side-effect verb blocking in read-only mode (F-03).

Every dynamic check uses an in-process 127.0.0.1 loopback server and verifies
that side-effecting GET/HEAD routes are blocked before any socket transmission,
while ordinary plural resource nouns and read queries remain eligible.
"""

from __future__ import annotations

import contextlib
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
from core.scan_safety import query_write_risk, read_only_risk


def get_ep(
    path: str = "/api/items/{id}",
    operation_id: Optional[str] = None,
    summary: Optional[str] = None,
    description: Optional[str] = None,
    method: str = "GET",
) -> Dict[str, Any]:
    ep: Dict[str, Any] = {"method": method, "path": path}
    if operation_id is not None:
        ep["operation_id"] = operation_id
    if summary is not None:
        ep["summary"] = summary
    if description is not None:
        ep["description"] = description
    return ep


class SideEffectVerbStaticTests(unittest.TestCase):
    """Dangerous state-changing verbs in path segments, operationId, summary, and description."""

    REQUIRED_VERBS = (
        "logout",
        "signout",
        "refund",
        "accept",
        "decline",
        "unsubscribe",
        "purge",
        "clear",
        "destroy",
        "kill",
        "ban",
        "impersonate",
        "run",
        "confirm",
        "redeem",
        "renew",
        "rotate",
        "unlock",
    )

    def test_action_path_segments_are_blocked_for_get_and_head(self) -> None:
        for method in ("GET", "HEAD"):
            for verb in self.REQUIRED_VERBS:
                for path in (
                    f"/api/resources/{{id}}/{verb}",
                    f"/api/{verb}-resource/{{id}}",
                    f"/api/{verb}_resource/{{id}}",
                    f"/api/{verb}Resource/{{id}}",
                ):
                    with self.subTest(method=method, verb=verb, path=path):
                        risk = read_only_risk(get_ep(path=path, method=method))
                        self.assertIsNotNone(risk, f"Expected {method} {path} to be blocked")
                        assert risk is not None
                        self.assertEqual(risk["safety_signal"], "path")
                        self.assertTrue(risk["safety_reason"].endswith("no request was sent"))

    def test_phrasal_logout_and_signout_variants_are_blocked(self) -> None:
        cases: List[Tuple[Dict[str, Any], str]] = [
            (get_ep(path="/api/auth/log-out"), "path"),
            (get_ep(path="/api/auth/log_out"), "path"),
            (get_ep(path="/api/auth/logOut"), "path"),
            (get_ep(path="/api/auth/sign-out"), "path"),
            (get_ep(path="/api/auth/sign_out"), "path"),
            (get_ep(path="/api/auth/signOut"), "path"),
            (get_ep(operation_id="logOut"), "operation_id"),
            (get_ep(operation_id="log_out_user"), "operation_id"),
            (get_ep(operation_id="log-out-session"), "operation_id"),
            (get_ep(operation_id="signOutUser"), "operation_id"),
            (get_ep(operation_id="sign_out_session"), "operation_id"),
            (get_ep(summary="Log out the current user"), "summary"),
            (get_ep(summary="Logs out the active session"), "summary"),
            (get_ep(summary="Sign out current account"), "summary"),
            (get_ep(description="This endpoint signs out the caller."), "description"),
        ]
        for ep, expected_signal in cases:
            with self.subTest(ep=ep):
                risk = read_only_risk(ep)
                self.assertIsNotNone(risk, f"Expected {ep} to be blocked")
                assert risk is not None
                self.assertEqual(risk["safety_signal"], expected_signal)

    def test_operation_ids_in_camel_snake_and_kebab_case_are_blocked(self) -> None:
        for verb in self.REQUIRED_VERBS:
            for op_id in (
                f"{verb}Target",
                f"{verb}_target",
                f"{verb}-target",
                f"getItemAnd{verb.capitalize()}",
            ):
                with self.subTest(verb=verb, operation_id=op_id):
                    risk = read_only_risk(get_ep(operation_id=op_id))
                    self.assertIsNotNone(risk, f"Expected operationId={op_id} to be blocked")
                    assert risk is not None
                    self.assertEqual(risk["safety_signal"], "operation_id")

    def test_affirmative_summaries_and_descriptions_are_blocked(self) -> None:
        prose_cases = [
            (get_ep(summary="Refund a payment"), "summary"),
            (get_ep(summary="Refunds the specified charge"), "summary"),
            (get_ep(summary="Accept an invitation"), "summary"),
            (get_ep(summary="Declines a team invite"), "summary"),
            (get_ep(summary="Unsubscribe user from mailing list"), "summary"),
            (get_ep(summary="Purge cached objects"), "summary"),
            (get_ep(summary="Clear session state"), "summary"),
            (get_ep(summary="Destroy active token"), "summary"),
            (get_ep(summary="Kill worker process"), "summary"),
            (get_ep(summary="Ban member from workspace"), "summary"),
            (get_ep(summary="Impersonate target account"), "summary"),
            (get_ep(summary="Run scheduled backup job"), "summary"),
            (get_ep(summary="Confirm pending order"), "summary"),
            (get_ep(summary="Redeem promotional voucher"), "summary"),
            (get_ep(summary="Renew subscription lease"), "summary"),
            (get_ep(summary="Rotate API signing key"), "summary"),
            (get_ep(summary="Unlock suspended user"), "summary"),
            (get_ep(description="This endpoint refunds the payment and notifies billing."), "description"),
            (get_ep(description="This GET operation runs the migration job."), "description"),
            (get_ep(description="Returns the token and rotates its secret."), "description"),
        ]
        for ep, expected_signal in prose_cases:
            with self.subTest(ep=ep):
                risk = read_only_risk(ep)
                self.assertIsNotNone(risk, f"Expected {ep} to be blocked")
                assert risk is not None
                self.assertEqual(risk["safety_signal"], expected_signal)

    def test_ordinary_plural_resources_and_read_metadata_are_not_falsely_blocked(self) -> None:
        safe_endpoints = [
            get_ep(path="/api/subscriptions", operation_id="listSubscriptions", summary="Subscriptions"),
            get_ep(path="/api/subscriptions/{id}", operation_id="getSubscription", summary="Get subscription"),
            get_ep(path="/api/reports", operation_id="listReports", summary="Reports"),
            get_ep(path="/api/reports/{id}", operation_id="getReport", summary="Retrieve report"),
            get_ep(path="/api/invitations", operation_id="listInvitations", summary="Invitations"),
            get_ep(path="/api/invites/{id}", operation_id="getInvite", summary="Get invitation details"),
            get_ep(path="/api/refunds", operation_id="listRefunds", summary="Refunds"),
            get_ep(path="/api/refunds/{id}", operation_id="getRefund", summary="Refund details"),
            get_ep(path="/api/payments/{id}/refunds", operation_id="listPaymentRefunds", summary="Refunds for a payment"),
            get_ep(path="/api/runs", operation_id="listRuns", summary="Runs"),
            get_ep(path="/api/runs/{id}", operation_id="getRun", summary="Run status"),
            get_ep(path="/api/workflows/{id}/runs", operation_id="listWorkflowRuns", summary="Runs of a workflow"),
            get_ep(path="/api/jobs/running", operation_id="listRunningJobs", summary="Running jobs"),
            get_ep(path="/api/bans", operation_id="listBans", summary="Bans"),
            get_ep(path="/api/guilds/{id}/bans", operation_id="getGuildBans", summary="Ban details"),
            get_ep(path="/api/players/{id}/unlocks", operation_id="listPlayerUnlocks", summary="Unlocks"),
            get_ep(path="/api/logs", operation_id="listLogs", summary="Audit logs"),
            get_ep(path="/api/confirmations/{id}", operation_id="getConfirmation", summary="Get confirmation"),
            get_ep(path="/api/redemptions/{id}", operation_id="getRedemption", summary="Get redemption"),
            get_ep(path="/api/renewals/{id}", operation_id="getRenewal", summary="Get renewal"),
            get_ep(path="/api/rotations/{id}", operation_id="getRotation", summary="Get key rotation record"),
            get_ep(path="/api/clearances/{id}", operation_id="getClearance", summary="Clearance status"),
            get_ep(
                path="/api/invites/{id}",
                operation_id="getInvite",
                description="To accept or decline an invite, use POST. This GET returns existing invite details.",
            ),
            get_ep(
                path="/api/payments/{id}",
                operation_id="getPayment",
                description="Returns payment details and does not refund or cancel the charge.",
            ),
        ]
        for ep in safe_endpoints:
            with self.subTest(ep=ep):
                self.assertIsNone(read_only_risk(ep), f"Safe read endpoint falsely blocked: {ep}")

    def test_read_only_post_and_query_action_consistency(self) -> None:
        # Legitimate search POSTs on plural collections remain allowed
        for path, op_id in (
            ("/api/subscriptions/search", "searchSubscriptions"),
            ("/api/refunds/search", "searchRefunds"),
            ("/api/runs/query", "queryRuns"),
            ("/api/invitations/lookup", "lookupInvitations"),
        ):
            with self.subTest(path=path):
                self.assertIsNone(read_only_risk({"method": "POST", "path": path, "operation_id": op_id}))

        # Impersonate and run are also refused on declared read-only POSTs and action query switches
        self.assertIsNotNone(
            read_only_risk({"method": "POST", "path": "/api/users/impersonate", "operation_id": "searchAndImpersonate"})
        )
        self.assertIsNotNone(
            read_only_risk({"method": "POST", "path": "/api/jobs/run", "operation_id": "runJobSearch"})
        )
        self.assertIsNotNone(query_write_risk("http://127.0.0.1:8080/api/rpc?action=impersonate"))
        self.assertIsNotNone(query_write_risk("http://127.0.0.1:8080/api/rpc?action=refund"))
        self.assertIsNone(query_write_risk("http://127.0.0.1:8080/api/runs?run_id=42&refund_id=7"))


class SideEffectZeroNetworkLoopbackTests(unittest.TestCase):
    """Verify against a 127.0.0.1 Mock that side-effecting GETs never leave the client."""

    def setUp(self) -> None:
        self.received: List[Tuple[str, str]] = []
        sink = self.received

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                sink.append((self.command, self.path))
                auth = self.headers.get("Authorization", "")
                if not auth:
                    status, payload = 401, {"error": "Unauthorized"}
                elif "VISITOR" in auth and "1001" in self.path:
                    status, payload = 403, {"error": "Forbidden"}
                else:
                    status, payload = 200, {"id": "1001", "status": "ok"}
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_HEAD = do_GET

            def log_message(self, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.target = f"http://127.0.0.1:{self.server.server_port}"
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

        id_param = {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
        self.spec = {
            "openapi": "3.0.3",
            "info": {"title": "F-03 Side-Effect Guard Mock", "version": "1.0"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearer": []}],
            "paths": {
                # Dangerous side-effecting GETs that must send 0 requests
                "/api/payments/{id}/refund": {
                    "get": {"operationId": "refundPayment", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
                "/api/invites/{id}/accept": {
                    "get": {"operationId": "acceptInvite", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
                "/api/auth/log-out": {
                    "get": {"operationId": "logOutCurrentUser", "responses": {"200": {"description": "ok"}}}
                },
                "/api/admin/users/{id}/impersonate": {
                    "get": {"operationId": "impersonateUser", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
                "/api/jobs/{id}/run": {
                    "get": {"operationId": "runJob", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
                "/api/keys/{id}/rotate": {
                    "get": {"operationId": "rotateKey", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
                # Legitimate read-only GETs that must continue working
                "/api/payments/{id}": {
                    "get": {"operationId": "getPayment", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
                "/api/refunds/{id}": {
                    "get": {"operationId": "getRefund", "summary": "Refund details", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
                "/api/subscriptions/{id}": {
                    "get": {"operationId": "getSubscription", "summary": "Subscriptions", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
                "/api/invitations/{id}": {
                    "get": {"operationId": "getInvitation", "summary": "Invitations", "parameters": [id_param], "responses": {"200": {"description": "ok"}}}
                },
            },
        }
        self.config = {
            "identities": {
                "owner": {"id": "1001", "token": "Bearer OWNER_TOK", "parameters": {"id": "1001"}},
                "visitor": {"id": "1002", "token": "Bearer VISITOR_TOK", "parameters": {"id": "1002"}},
                "anonymous": {},
            },
            "bola": {
                "GET /api/payments/{id}": {"resource_id_paths": ["id"]},
                "GET /api/refunds/{id}": {"resource_id_paths": ["id"]},
                "GET /api/subscriptions/{id}": {"resource_id_paths": ["id"]},
                "GET /api/invitations/{id}": {"resource_id_paths": ["id"]},
            },
        }
        self.spec_path = self.folder / "openapi.json"
        self.config_path = self.folder / "config.json"
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def test_default_scan_and_dry_run_block_side_effect_gets_before_any_request(self) -> None:
        plan_json = self.folder / "plan.json"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            dry_code = api_sentinel.main([
                "--spec", str(self.spec_path),
                "--config", str(self.config_path),
                "--dry-run",
                "--export-json", str(plan_json),
            ])
        self.assertEqual(dry_code, 0, err.getvalue())
        self.assertEqual(self.received, [])
        plan = json.loads(plan_json.read_text(encoding="utf-8"))
        blocked_eps = {op["endpoint"] for op in plan["operations"] if op.get("safety_blocked")}
        self.assertEqual(
            blocked_eps,
            {
                "GET /api/payments/{id}/refund",
                "GET /api/invites/{id}/accept",
                "GET /api/auth/log-out",
                "GET /api/admin/users/{id}/impersonate",
                "GET /api/jobs/{id}/run",
                "GET /api/keys/{id}/rotate",
            },
        )

        report_json = self.folder / "report.json"
        report_html = self.folder / "report.html"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            scan_code = api_sentinel.main([
                "--spec", str(self.spec_path),
                "--config", str(self.config_path),
                "--target", self.target,
                "--delay", "0",
                "--export-json", str(report_json),
                "--output", str(report_html),
            ])
        self.assertEqual(scan_code, 0, err.getvalue())

        # Zero dangerous paths reached the loopback server
        hit_paths = [path for _, path in self.received]
        for forbidden in ("/refund", "/accept", "/log-out", "/impersonate", "/run", "/rotate"):
            self.assertFalse(
                any(path.endswith(forbidden) or f"{forbidden}/" in path for path in hit_paths),
                f"Forbidden side-effect route was actually requested: {hit_paths}",
            )
        # All four legitimate read collections were audited
        for allowed_prefix in ("/api/payments/1001", "/api/refunds/1001", "/api/subscriptions/1001", "/api/invitations/1001"):
            self.assertIn(allowed_prefix, hit_paths)

        report = json.loads(report_json.read_text(encoding="utf-8"))
        by_ep = {r["endpoint"]: r for r in report["results"] if r["check"] == "BOLA"}
        for ep_key in blocked_eps:
            self.assertEqual(by_ep[ep_key]["verdict"], "SKIPPED")
            self.assertEqual(by_ep[ep_key]["evidence"]["reason_category"], "safety_policy")
            self.assertEqual(by_ep[ep_key]["evidence"]["requests_attempted"], 0)

        # Direct _http_request preflight also blocks before transport
        auditor = APISentinelAuditor(
            str(self.spec_path),
            self.target,
            request_delay=0,
            identities_config=self.config["identities"],
            bola_config=self.config["bola"],
        )
        before_count = len(self.received)
        for method in ("GET", "HEAD"):
            res = auditor._http_request(method, self.target + "/api/payments/1001/refund", identity_name="owner")
            self.assertEqual(res.status, 0)
            self.assertIn("safety policy", res.error or "")
        self.assertEqual(len(self.received), before_count)


if __name__ == "__main__":
    unittest.main()
