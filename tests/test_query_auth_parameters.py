"""Query-string credentials are refused before any request.

Every check builds a URL from the resource owner's parameter values and sends it
as several identities, so a credential in the query string would be sent by the
visitor and the anonymous probe too. A correctly secured API then looks like it
lets them read the owner's resource.
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
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlsplit

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.models import Verdict

KEYS = {"OWNER-QUERY-KEY": "1001", "VISITOR-QUERY-KEY": "1002"}
OWNERS = {"11": "1001", "22": "1002"}


class QueryKeyHandler(BaseHTTPRequestHandler):
    """A correctly secured API that identifies the caller only by ?api_key= or ?access_token=."""

    requests: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        key = (query.get("api_key") or query.get("access_token") or [""])[0]
        caller = KEYS.get(key)
        with self.lock:
            self.requests.append({"path": self.path, "caller": caller})
        resource = url.path.rsplit("/", 1)[-1]
        if caller is None:
            status, body = 401, {"error": "unauthenticated"}
        elif OWNERS.get(resource) != caller:
            status, body = 403, {"error": "forbidden"}
        else:
            status, body = 200, {"id": resource, "owner_id": caller, "title": "quarterly figures " + caller}
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


class QueryAuthParameterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), QueryKeyHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        with QueryKeyHandler.lock:
            QueryKeyHandler.requests.clear()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def spec(self, name: str, *, scheme: bool = True) -> Dict[str, Any]:
        spec: Dict[str, Any] = {
            "openapi": "3.0.3",
            "info": {"title": "reports", "version": "1"},
            "paths": {"/reports/{reportId}": {"get": {
                "parameters": [
                    {"name": "reportId", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": name, "in": "query", "required": True, "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "ok"}},
            }}},
        }
        if scheme:
            spec["components"] = {"securitySchemes": {
                "queryKey": {"type": "apiKey", "in": "query", "name": name}}}
            spec["security"] = [{"queryKey": []}]
        return spec

    def config(self, name: str) -> Dict[str, Any]:
        # Placeholder tokens satisfy identity validation; the API ignores them.
        return {
            "identities": {
                "owner": {"id": "1001", "token": "Bearer owner-placeholder"},
                "visitor": {"id": "1002", "token": "Bearer visitor-placeholder"},
                "anonymous": {"id": None, "token": None},
            },
            "parameter_values": {"GET /reports/{reportId}": {
                "owner": {"reportId": "11", name: "OWNER-QUERY-KEY"},
                "visitor": {"reportId": "22", name: "VISITOR-QUERY-KEY"},
            }},
            "bola": {"GET /reports/{reportId}": {"expected_visitor_access": "deny", "resource_id_paths": ["id"]}},
        }

    def audit(self, spec: Dict[str, Any], config: Dict[str, Any]) -> APISentinelAuditor:
        spec_file = self.folder / "spec.json"
        spec_file.write_text(json.dumps(spec), encoding="utf-8")
        auditor = APISentinelAuditor(
            spec_path=str(spec_file), target_base_url=self.target, allow_http=True, request_delay=0,
            identities_config=config["identities"], parameter_values=config["parameter_values"],
            bola_config=config["bola"],
        )
        with contextlib.redirect_stdout(io.StringIO()):
            auditor.run()
        return auditor

    def assert_refused(self, auditor: APISentinelAuditor, name: str) -> None:
        self.assertEqual(QueryKeyHandler.requests, [])
        result = auditor.results[0]
        self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE, result["reason"])
        self.assertEqual(result["evidence"]["reason_category"], "invalid_input")
        self.assertIn(f"Query parameter '{name}' carries authentication", result["reason"])
        self.assertIn("not supported", result["reason"])

    def test_query_api_key_scheme_is_refused_before_any_request(self) -> None:
        auditor = self.audit(self.spec("api_key"), self.config("api_key"))
        self.assert_refused(auditor, "api_key")

    def test_rfc6750_access_token_query_parameter_is_refused_without_a_scheme(self) -> None:
        auditor = self.audit(self.spec("access_token", scheme=False), self.config("access_token"))
        self.assert_refused(auditor, "access_token")

    def test_scheme_name_matches_regardless_of_letter_case(self) -> None:
        spec = self.spec("API_KEY")
        spec["components"]["securitySchemes"]["queryKey"]["name"] = "api_key"
        auditor = self.audit(spec, self.config("API_KEY"))
        self.assert_refused(auditor, "API_KEY")

    def test_business_query_parameter_named_like_a_token_is_still_sent(self) -> None:
        spec = self.spec("page_token", scheme=False)
        config = self.config("page_token")
        for identity in ("owner", "visitor"):
            config["parameter_values"]["GET /reports/{reportId}"][identity]["page_token"] = "cursor-1"
        self.audit(spec, config)
        self.assertTrue(QueryKeyHandler.requests)
        self.assertTrue(all("page_token=cursor-1" in item["path"] for item in QueryKeyHandler.requests))

    def test_dry_run_plan_explains_the_refusal_without_sending_requests(self) -> None:
        spec_file, config_file, plan_file = (self.folder / name for name in ("spec.json", "config.json", "plan.json"))
        spec_file.write_text(json.dumps(self.spec("api_key")), encoding="utf-8")
        config_file.write_text(json.dumps(self.config("api_key")), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(["--spec", str(spec_file), "--config", str(config_file), "--dry-run",
                         "--export-json", str(plan_file)])
        self.assertEqual(code, 0)
        (operation,) = json.loads(plan_file.read_text(encoding="utf-8"))["operations"]
        self.assertEqual(operation["reason_category"], "invalid_input")
        self.assertIn("Query parameter 'api_key' carries authentication", operation["reason"])
        self.assertEqual(QueryKeyHandler.requests, [])


if __name__ == "__main__":
    unittest.main()
