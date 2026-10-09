"""Concrete path preflight against normalizing proxies, without business targets."""

import contextlib
import io
import json
import posixpath
import re
import socket
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import quote, unquote, urlsplit

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.models import HTTPResult
from core.parameters import ParameterSerializationError


def extra_encoding(value, layers):
    for _ in range(layers):
        value = quote(value, safe="")
    return value


AMBIGUOUS_PATHS = (
    "/opaque/%2563reate_report",
    "/opaque/%252563reate_report",
    "/opaque/" + extra_encoding("%63reate_report", 11),
    "/opaque%252Fcreate_report",
    "/opaque%25252Fcreate_report",
    "/opaque" + extra_encoding("%2F", 11) + "create_report",
    "/opaque/./create_report",
    "/opaque/../opaque/create_report",
    "/opaque/.%2Fcreate_report",
    "/opaque/%2E%2Fcreate_report",
    "/opaque/%2e%2e%2Fopaque%2Fcreate_report",
    "/opaque/.;v=1/create_report",
    "/opaque/..;v=1/opaque/create_report",
    "/opaque/%2E%3Bv%3D1%2Fcreate_report",
    "/records//1001",
    "/records/a%2F%2Fb",
    "/records/%2Fa",
    "/records/a%2F",
    "/records/a\\b",
    "/records/a%5Cb",
    "/records/a\tb",
    "/records/a\nb",
    "/records/a\rb",
    "/records/a%00b",
    "/records/a%0Ab",
    "/records/a%7Fb",
    "/records/a\x7fb",
    "/records/a\u0085b",
    "/records/a%C2%85b",
    "/records/a%C2%9Fb",
    "/records/a%FFb",
    "/records/a%C0%AFb",
    "/records/a%E2%82",
    "/records/a%ED%A0%80b",
    "/records/100%",
    "/records/100%2",
    "/records/100%GG",
)


def successful_response():
    response = MagicMock()
    response.__enter__.return_value = response
    response.status = 200
    response.headers = Message()
    response.headers["Content-Type"] = "application/json"
    response.read.return_value = b'{"id":"1002","role":"user"}'
    return response


class ReadOnlyPathGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_requests = []
        cls.side_effects = 0
        cls.server_lock = threading.Lock()

        class NormalizingHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.reply()

            def do_HEAD(self):
                self.reply()

            def do_PATCH(self):
                self.reply()

            def reply(self):
                # This intentionally models a proxy/application which recursively
                # decodes and normalizes a received path. It is the independent
                # server oracle, not the product's safety implementation.
                normalized = urlsplit(self.path).path
                for _ in range(len(normalized) + 1):
                    decoded = unquote(normalized)
                    if decoded == normalized:
                        break
                    normalized = decoded
                normalized = normalized.replace("\\", "/")
                normalized = "/".join(part.split(";", 1)[0] for part in normalized.split("/"))
                normalized = posixpath.normpath(re.sub(r"/+", "/", normalized))
                with cls.server_lock:
                    cls.server_requests.append((self.command, self.path, normalized))
                    if normalized.rstrip("/").endswith("/opaque/create_report"):
                        cls.side_effects += 1
                payload = json.dumps({"id": "1002", "role": "user", "path": normalized}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), NormalizingHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        cls.target = cls.origin + "/api/v1"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.spec_path = Path(self.temp.name) / "spec.json"
        identifier = {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
        self.spec = {"openapi": "3.0.3", "paths": {
            "/records/{id}": {"get": {"operationId": "getRecord", "parameters": [identifier]}},
            "/opaque/{id}": {"get": {"operationId": "getOpaqueRecord", "parameters": [identifier]}},
            "/opaque/create_report": {"get": {"operationId": "createReport"}},
            "/settings/{id}": {"patch": {"parameters": [identifier], "requestBody": {
                "content": {"application/json": {"schema": {
                    "type": "object", "properties": {"role": {
                        "type": "string", "readOnly": True, "enum": ["user", "admin"]}}}}}}}},
        }}
        self.write_spec()
        with self.server_lock:
            self.server_requests.clear()
            type(self).side_effects = 0

    def write_spec(self):
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")

    def auditor(self, **kwargs):
        return APISentinelAuditor(str(self.spec_path), self.target, request_delay=0, **kwargs)

    def test_ambiguous_paths_are_rejected_before_get_or_head_transport(self):
        auditor = self.auditor()
        for method in ("GET", "HEAD"):
            for path in AMBIGUOUS_PATHS:
                with self.subTest(method=method, path=repr(path)), \
                        patch.object(auditor._opener, "open", return_value=successful_response()) as opener:
                    risk = auditor._read_request_risk(method, self.target + path)
                    self.assertIsNotNone(risk)
                    self.assertEqual(risk["safety_signal"], "path_ambiguity")
                    self.assertNotIn(path, risk["safety_reason"])
                    result = auditor._http_request(method, self.target + path, identity_name="owner")
                    self.assertEqual(result.status, 0)
                    opener.assert_not_called()

    def test_local_normalizing_server_receives_no_ambiguous_requests(self):
        auditor = self.auditor()
        witness_paths = ("/opaque/%2563reate_report", "/opaque/%252563reate_report",
                         "/opaque/.%2Fcreate_report", "/opaque/%2e%2e%2Fopaque%2Fcreate_report")
        for method in ("GET", "HEAD"):
            for path in witness_paths:
                with self.subTest(method=method, path=path), \
                        patch("socket.create_connection", wraps=socket.create_connection) as connection, \
                        patch.object(auditor._opener, "open", wraps=auditor._opener.open) as opener:
                    result = auditor._http_request(method, self.target + path, identity_name="owner")
                    self.assertEqual(result.status, 0)
                    connection.assert_not_called()
                    opener.assert_not_called()
        self.assertEqual(self.server_requests, [])
        self.assertEqual(self.side_effects, 0)

    def test_once_encoded_action_overlap_and_trailing_alias_remain_blocked(self):
        auditor = self.auditor()
        paths = ("/opaque/create_report", "/opaque/%63reate_report", "/opaque%2Fcreate_report",
                 "/opaque/create_report/", "/opaque/%63reate_report/", "/opaque/create_report;view=summary",
                 "/opaque/create_report%3Bview%3Dsummary", "/opaque/%63reate_report;view=summary",
                 "/opaque;v=1/create_report", "/opaque/;v=1/create_report")
        for method in ("GET", "HEAD"):
            for path in paths:
                with self.subTest(method=method, path=path), patch.object(auditor._opener, "open") as opener:
                    risk = auditor._read_request_risk(method, self.target + path)
                    self.assertIsNotNone(risk)
                    result = auditor._http_request(method, self.target + path, identity_name="owner")
                    self.assertEqual(result.status, 0)
                    opener.assert_not_called()
        self.assertEqual(self.server_requests, [])

    def test_benign_route_alias_does_not_certify_undocumented_actions(self):
        auditor = self.auditor()
        for method in ("GET", "HEAD"):
            for path in ("/records/create_report/", "/records;view=current/create_report"):
                with self.subTest(method=method, path=path), patch.object(auditor._opener, "open") as opener:
                    self.assertIsNotNone(auditor._read_request_risk(method, self.target + path))
                    result = auditor._http_request(method, self.target + path, identity_name="owner")
                    self.assertEqual(result.status, 0)
                    opener.assert_not_called()

    def test_risky_documented_root_is_checked_when_url_path_is_empty(self):
        self.spec["paths"] = {"/": {"get": {"operationId": "createReport"}}}
        self.write_spec()
        for target in (self.origin, self.target):
            auditor = APISentinelAuditor(str(self.spec_path), target, request_delay=0)
            for method in ("GET", "HEAD"):
                for url in (target, target + "/"):
                    with self.subTest(target=target, method=method, url=url), \
                            patch.object(auditor._opener, "open") as opener:
                        self.assertIsNotNone(auditor._read_request_risk(method, url))
                        self.assertEqual(auditor._http_request(method, url).status, 0)
                        opener.assert_not_called()

    def test_ordinary_serialized_values_and_query_data_still_execute(self):
        auditor = self.auditor()
        endpoint = next(item for item in auditor.parser.get_endpoints() if item["path"] == "/records/{id}")
        values = ("1001", "汉 字", "report.v1", "100% complete", "literal%", "x?y#z", "a/b", "item;id=normal")
        for method in ("GET", "HEAD"):
            for value in values:
                url = auditor._build_url(endpoint, "owner", {"id": value})
                with self.subTest(method=method, value=value):
                    self.assertIsNone(auditor._read_request_risk(method, url))
                    self.assertEqual(auditor._http_request(method, url, identity_name="owner").status, 200)
        query_url = self.target + "/records/1001?redirect=%252fopaque%252fcreate_report&data=..%2f"
        self.assertIsNone(auditor._read_request_risk("GET", query_url))
        self.assertEqual(auditor._http_request("GET", query_url, identity_name="owner").status, 200)
        wire_paths = [path for _, path, _ in self.server_requests]
        self.assertIn("/api/v1/records/a%2Fb", wire_paths)
        self.assertIn("/api/v1/records/x%3Fy%23z", wire_paths)
        self.assertIn("/api/v1/records/100%25%20complete", wire_paths)
        self.assertEqual(len(wire_paths), len(values) * 2 + 1)
        self.assertEqual(self.side_effects, 0)

    def test_bola_checks_both_concrete_identity_paths_before_owner_baseline(self):
        for identity in ("owner", "visitor"):
            for value in ("%63reate_report", "../opaque/create_report", ".;v=1/create_report", "a//b", "a\\b"):
                with self.subTest(identity=identity, value=value):
                    values = {"owner": {"id": "1001"}, "visitor": {"id": "1002"}}
                    values[identity] = {"id": value}
                    auditor = self.auditor(parameter_values={"GET /opaque/{id}": values})
                    endpoint = next(item for item in auditor.parser.get_endpoints() if item["path"] == "/opaque/{id}")
                    denied = HTTPResult(403, '{"message":"denied"}')
                    with patch.object(auditor, "_http_request", return_value=denied) as transport:
                        auditor.audit_endpoint_bola(endpoint)
                    transport.assert_not_called()
                    result = auditor.results[0]
                    self.assertEqual(result["verdict"], "SKIPPED")
                    self.assertEqual(result["evidence"]["reason_category"], "safety_policy")
                    self.assertEqual(result["evidence"]["safety_signal"], "path_ambiguity")
                    self.assertEqual(result["evidence"]["requests_attempted"], 0)
                    plan = auditor.build_plan()
                    operation = next(item for item in plan["operations"] if item["endpoint"] == "GET /opaque/{id}")
                    self.assertTrue(operation["safety_blocked"])
                    self.assertEqual(operation["reason_category"], "safety_policy")
                    self.assertEqual(plan["requests_sent"], 0)
        self.assertEqual(self.server_requests, [])

    def test_independent_patch_readback_ambiguity_blocks_get_and_patch(self):
        for value in ("%63reate_report", "../opaque/create_report", ".;v=1/create_report", "a//b", "a\\b"):
            with self.subTest(value=value):
                mapping = {"method": "GET", "path": "/opaque/{id}", "parameter_values": {"id": value},
                           "field_map": {"role": "role"}, "consistency": "strong"}
                auditor = self.auditor(allow_write_tests=True, write_allowlist=["PATCH /settings/{id}"],
                                       readback_config={"PATCH /settings/{id}": mapping})
                endpoints = auditor.parser.get_endpoints()
                endpoint = next(item for item in endpoints if item["method"] == "PATCH")
                with patch.object(auditor, "_http_request") as transport, \
                        patch.object(auditor._opener, "open") as opener:
                    with self.assertRaises(ParameterSerializationError):
                        auditor._readback_result(endpoint, mapping, "visitor")
                    auditor.audit_endpoint_mass_assignment(endpoint, endpoints)
                transport.assert_not_called()
                opener.assert_not_called()
                result = auditor.results[0]
                self.assertEqual(result["verdict"], "SKIPPED")
                self.assertEqual(result["evidence"]["reason_category"], "safety_policy")
                self.assertEqual(result["evidence"]["safety_signal"], "path_ambiguity")
                self.assertEqual(result["evidence"]["requests_attempted"], 0)
                operation = next(item for item in auditor.build_plan()["operations"]
                                 if item["check"] == "MASS_ASSIGNMENT")
                self.assertFalse(operation["writes_enabled"])
                self.assertTrue(operation["safety_blocked"])
        self.assertEqual(self.server_requests, [])

    def test_warmed_cache_still_checks_each_concrete_path_in_multiple_threads(self):
        auditor = self.auditor()
        self.assertIsNone(auditor._read_request_risk("GET", self.target + "/records/1001"))
        paths = [(method, path) for method in ("GET", "HEAD") for path in AMBIGUOUS_PATHS]

        def check(item):
            method, path = item
            risk = auditor._read_request_risk(method, self.target + path)
            result = auditor._http_request(method, self.target + path, identity_name="owner")
            return risk, result

        for workers in (1, 4):
            with self.subTest(workers=workers), patch.object(auditor.parser, "get_endpoints") as normalize, \
                    patch.object(auditor._opener, "open", return_value=successful_response()) as opener:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    results = list(executor.map(check, paths))
                self.assertTrue(all(risk and risk["safety_signal"] == "path_ambiguity"
                                    and result.status == 0 for risk, result in results))
                normalize.assert_not_called()
                opener.assert_not_called()

    def test_base_path_ambiguity_is_checked_before_prefix_removal(self):
        for base_path in ("/api/../v1", "/api//v1", "/api/%2561/v1", "/api/a%5Cb/v1"):
            with self.subTest(base_path=base_path):
                target = self.origin + base_path
                auditor = APISentinelAuditor(str(self.spec_path), target, request_delay=0)
                with patch.object(auditor._opener, "open", return_value=successful_response()) as opener:
                    risk = auditor._read_request_risk("GET", target + "/records/1001")
                    self.assertIsNotNone(risk)
                    self.assertEqual(risk["safety_signal"], "path_ambiguity")
                    self.assertEqual(auditor._http_request("GET", target + "/records/1001").status, 0)
                    opener.assert_not_called()

    def test_validation_and_dry_run_keep_network_zero_for_ambiguous_values(self):
        config_path = Path(self.temp.name) / "settings.json"
        config_path.write_text(json.dumps({"parameter_values": {"GET /opaque/{id}": {
            "owner": {"id": "1001"}, "visitor": {"id": "%63reate_report"}}}}), encoding="utf-8")
        for flag in ("--validate-config", "--dry-run"):
            with self.subTest(flag=flag), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()), patch("socket.create_connection") as connection, \
                    patch("urllib.request.OpenerDirector.open") as opener, patch("urllib.request.urlopen") as urlopen:
                self.assertEqual(main(["--spec", str(self.spec_path), "--target", self.target,
                                       "--config", str(config_path), flag]), 0)
            connection.assert_not_called()
            opener.assert_not_called()
            urlopen.assert_not_called()
        self.assertEqual(self.server_requests, [])


if __name__ == "__main__":
    unittest.main()
