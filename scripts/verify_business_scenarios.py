"""Run local authorization fixtures with independently declared expected access."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.auditor import APISentinelAuditor


# Truth is declared before any scan; neither the report nor tool verdict sets it.
SCENARIOS = (
    {
        "name": "team_sharing",
        "relationship": "shared_team",
        "policy": "allow",
        "expected": "AUTHORIZED",
        "vulnerable": False,
    },
    {
        "name": "tenant_admin",
        "relationship": "tenant_admin",
        "policy": "allow",
        "expected": "AUTHORIZED",
        "vulnerable": False,
    },
    {
        "name": "unshared_same_tenant",
        "relationship": "unshared",
        "policy": "deny",
        "expected": "SECURE",
        "vulnerable": False,
    },
    {
        "name": "cross_tenant_isolation",
        "relationship": "cross_tenant",
        "policy": "deny",
        "expected": "SECURE",
        "vulnerable": False,
    },
    {
        "name": "cross_tenant_leak",
        "relationship": "cross_tenant",
        "policy": "deny",
        "expected": "CONFIRMED",
        "vulnerable": True,
    },
    {
        "name": "same_tenant_leak",
        "relationship": "unshared",
        "policy": "deny",
        "expected": "CONFIRMED",
        "vulnerable": True,
    },
)


def run_scenarios():
    outcomes = []
    for scenario in SCENARIOS:
        owner = {
            "id": "owner-document",
            "tenant": "tenant-a",
            "title": "Owner contract",
            "private_note": "Owner-only accounting",
        }
        visitor = {
            "id": "visitor-document",
            "tenant": (
                "tenant-b" if scenario["relationship"] == "cross_tenant" else "tenant-a"
            ),
            "title": "Visitor contract",
            "private_note": "Visitor accounting",
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                token = self.headers.get("Authorization")
                payload, status = {"error": "Forbidden"}, 403
                if token not in ("Bearer fixture-owner", "Bearer fixture-visitor"):
                    payload, status = {"error": "Unauthorized"}, 401
                elif (
                    self.path == "/documents/visitor-document"
                    and token == "Bearer fixture-visitor"
                ):
                    payload, status = visitor, 200
                elif self.path == "/documents/owner-document":
                    allowed = (
                        token == "Bearer fixture-owner"
                        or scenario["relationship"] in ("shared_team", "tenant_admin")
                    )
                    if allowed or scenario["vulnerable"]:
                        payload, status = owner, 200
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Local authorization fixture", "version": "1"},
            "paths": {
                "/documents/{document_id}": {
                    "get": {
                        "security": [{"bearer": []}],
                        "parameters": [
                            {
                                "name": "document_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "Document"}},
                    }
                }
            },
            "components": {
                "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}
            },
        }
        identities = {
            "owner": {
                "id": "fixture-owner",
                "token": "Bearer fixture-owner",
                "parameters": {"document_id": "owner-document"},
            },
            "visitor": {
                "id": "fixture-visitor",
                "token": "Bearer fixture-visitor",
                "parameters": {"document_id": "visitor-document"},
            },
            "anonymous": {"id": None, "token": None, "parameters": {}},
        }
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                spec_path = Path(directory) / "openapi.json"
                spec_path.write_text(json.dumps(spec), encoding="utf-8")
                auditor = APISentinelAuditor(
                    str(spec_path),
                    f"http://127.0.0.1:{server.server_port}",
                    request_delay=0,
                    identities_config=identities,
                    bola_config={
                        "GET /documents/{document_id}": {
                            "expected_visitor_access": scenario["policy"],
                            "resource_id_paths": ["id"],
                        }
                    },
                )
                with contextlib.redirect_stdout(io.StringIO()):
                    auditor.run()
                outcome = auditor.results[0]
                outcomes.append(
                    {
                        **scenario,
                        "actual": outcome["verdict"],
                        "matches_expectation": outcome["verdict"] == scenario["expected"],
                        "finding_count": len(auditor.findings),
                        "reason": outcome["reason"],
                    }
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
    return {
        "scope": "Six local model fixtures; not production API detection rates",
        "scenarios": outcomes,
        "false_positives": sum(
            not item["vulnerable"] and item["actual"] == "CONFIRMED" for item in outcomes
        ),
        "false_negatives": sum(
            item["vulnerable"] and item["actual"] != "CONFIRMED" for item in outcomes
        ),
        "inconclusive": sum(
            item["actual"] in ("INCONCLUSIVE", "SUSPICIOUS", "ERROR") for item in outcomes
        ),
        "matches_expectation": all(item["matches_expectation"] for item in outcomes),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(ROOT / "dist" / "business-scenarios.json"))
    args = parser.parse_args()
    result = run_scenarios()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["matches_expectation"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
