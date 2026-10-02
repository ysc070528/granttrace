# -*- coding: utf-8 -*-
"""Local, stateful target used by GrantTrace's integration tests.

The server intentionally exposes one BOLA endpoint and one mass-assignment
endpoint. It binds only to loopback and can reset its in-memory state between
tests so results do not leak across runs.
"""

import copy
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict


class TargetMockHandler(BaseHTTPRequestHandler):
    INITIAL_DATABASE: Dict[str, Any] = {
        "users": {
            "1001": {
                "id": "1001",
                "name": "Alice",
                "role": "user",
                "salary": "25,000 USD",
                "department": "Engineering",
            },
            "1002": {
                "id": "1002",
                "name": "Bob",
                "role": "user",
                "salary": "18,000 USD",
                "department": "Marketing",
            },
        },
        "documents": {
            "550e8400-e29b-41d4-a716-446655440000": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "owner_id": "1001",
                "title": "Alice_Confidential_Patent.pdf",
                "content": "Top secret architecture design",
            },
            "7d444840-9dc0-11d1-b245-5ffdce74fad2": {
                "id": "7d444840-9dc0-11d1-b245-5ffdce74fad2",
                "owner_id": "1002",
                "title": "Visitor_Test_Document.pdf",
                "content": "Dedicated visitor baseline",
            },
        },
        "articles": {
            "101": {
                "id": 101,
                "title": "2026 年企业安全开源建设倡议",
                "author": "Security Team",
                "public": True,
            }
        },
    }
    DATABASE: Dict[str, Any] = copy.deepcopy(INITIAL_DATABASE)

    @classmethod
    def reset_database(cls) -> None:
        cls.DATABASE = copy.deepcopy(cls.INITIAL_DATABASE)

    def _write_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _get_current_user(self) -> str:
        auth_header = self.headers.get("Authorization", "")
        if auth_header == "Bearer TOKEN_ALICE_OWNER_1001":
            return "1001"
        if auth_header == "Bearer TOKEN_BOB_VISITOR_1002":
            return "1002"
        return ""

    def do_GET(self) -> None:
        current_user = self._get_current_user()

        article_match = re.fullmatch(r"/api/public/articles/([^/?]+)", self.path)
        if article_match:
            article = self.DATABASE["articles"].get(article_match.group(1))
            if article is None:
                self._write_json(404, {"error": "Article not found", "code": 404})
            else:
                self._write_json(200, article)
            return

        document_match = re.fullmatch(r"/api/documents/([^/?]+)", self.path)
        if document_match:
            if not current_user:
                self._write_json(401, {"error": "Unauthorized", "code": 401})
                return
            document = self.DATABASE["documents"].get(document_match.group(1))
            if document is None:
                self._write_json(404, {"error": "Document not found", "code": 404})
                return
            if document["owner_id"] != current_user:
                self._write_json(403, {"error": "Forbidden", "code": 403})
                return
            self._write_json(200, document)
            return

        profile_match = re.fullmatch(r"/api/users/([^/?]+)/profile", self.path)
        if profile_match:
            if not current_user:
                self._write_json(401, {"error": "Authentication required", "code": 401})
                return
            # Deliberate BOLA: subject is not compared with requested user id.
            target_user = self.DATABASE["users"].get(profile_match.group(1))
            if target_user is None:
                self._write_json(404, {"error": "User not found", "code": 404})
                return
            self._write_json(200, target_user)
            return

        self._write_json(404, {"error": "Route not found", "code": 404})

    def _read_payload(self) -> Dict[str, Any]:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len <= 0 or content_len > 1024 * 1024:
            return {}
        try:
            payload = json.loads(self.rfile.read(content_len).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def do_PUT(self) -> None:
        current_user = self._get_current_user()
        if not current_user:
            self._write_json(401, {"error": "Unauthorized", "code": 401})
            return

        payload = self._read_payload()

        settings_match = re.fullmatch(r"/api/users/([^/?]+)/settings", self.path)
        if settings_match:
            user_id = settings_match.group(1)
            if user_id != current_user:
                self._write_json(403, {"error": "Forbidden", "code": 403})
                return
            if user_id not in self.DATABASE["users"]:
                self._write_json(404, {"error": "User not found", "code": 404})
                return
            # Deliberate mass-assignment flaw: every supplied field is copied.
            self.DATABASE["users"][user_id].update(payload)
            self._write_json(200, {"status": "success", "data": self.DATABASE["users"][user_id]})
            return

        nickname_match = re.fullmatch(r"/api/users/([^/?]+)/nickname", self.path)
        if nickname_match:
            user_id = nickname_match.group(1)
            if user_id != current_user:
                self._write_json(403, {"error": "Forbidden", "code": 403})
                return
            if user_id not in self.DATABASE["users"]:
                self._write_json(404, {"error": "User not found", "code": 404})
                return
            # Safe allowlist: injected privilege fields are ignored.
            if isinstance(payload.get("nickname"), str):
                self.DATABASE["users"][user_id]["nickname"] = payload["nickname"]
            self._write_json(200, {"status": "ok", "message": "Nickname updated"})
            return

        self._write_json(404, {"error": "Route not found", "code": 404})

    do_PATCH = do_PUT

    def log_message(self, format: str, *args: Any) -> None:
        return


def run_server(port: int = 8080) -> None:
    TargetMockHandler.reset_database()
    server = ThreadingHTTPServer(("127.0.0.1", port), TargetMockHandler)
    print(f"[*] GrantTrace test server listening on 127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
