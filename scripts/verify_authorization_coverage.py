"""Run fixed-truth authorization fixtures on disposable loopback HTTP servers.

The same fixture definitions can measure an older source tree with --source-root.
Expected outcomes are declared before scanning, never inferred from tool verdicts.
No production target or credentials are accepted.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    {"name": "ordinary_denial", "expected": "SECURE", "vulnerable": False},
    {"name": "cross_user_leak", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "cross_tenant_denial", "expected": "SECURE", "vulnerable": False},
    {"name": "cross_tenant_leak", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "team_sharing", "expected": "AUTHORIZED", "vulnerable": False},
    {"name": "tenant_admin", "expected": "AUTHORIZED", "vulnerable": False},
    {"name": "shared_but_denied", "expected": "INCONCLUSIVE", "vulnerable": False},
    {"name": "caller_self_instead_of_owner", "expected": "SUSPICIOUS", "vulnerable": False},
    {"name": "nested_resource_leak", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "array_resource_leak", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "paged_resource_leak", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "query_resource_leak", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "masked_404_denial", "expected": "INCONCLUSIVE", "vulnerable": False},
    {"name": "error_500_owner_data", "expected": "SUSPICIOUS", "vulnerable": True},
    {"name": "error_404_owner_data", "expected": "SUSPICIOUS", "vulnerable": True},
    {"name": "error_500_generic", "expected": "INCONCLUSIVE", "vulnerable": False},
    {"name": "truncated_owner_response", "expected": "INCONCLUSIVE", "vulnerable": True},
    {"name": "no_object_selector", "expected": "SKIPPED", "vulnerable": None},
    {"name": "unsafe_read", "expected": "SKIPPED", "vulnerable": None},
    {"name": "patch_persist_restore", "kind": "patch", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "patch_no_persistence", "kind": "patch", "expected": "SECURE", "vulnerable": False},
    {"name": "patch_nested_restore", "kind": "patch", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "patch_custom_readonly", "kind": "patch", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "patch_nested_readonly", "kind": "patch", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "patch_swagger_json_alternative", "kind": "patch", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "patch_restore_failure", "kind": "patch", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "patch_initial_202", "kind": "patch", "expected": "INCONCLUSIVE", "vulnerable": True},
    {"name": "patch_initial_206", "kind": "patch", "expected": "INCONCLUSIVE", "vulnerable": True},
    {"name": "patch_initial_content_range", "kind": "patch", "expected": "INCONCLUSIVE", "vulnerable": True},
    {"name": "patch_stale_202", "kind": "patch", "expected": "INCONCLUSIVE", "vulnerable": True},
    {"name": "patch_stale_203", "kind": "patch", "expected": "INCONCLUSIVE", "vulnerable": True},
    {"name": "patch_stale_206", "kind": "patch", "expected": "INCONCLUSIVE", "vulnerable": True},
    {"name": "patch_restore_202", "kind": "patch", "expected": "CONFIRMED", "vulnerable": True},
    {"name": "patch_invalid_after", "kind": "patch", "expected": "INCONCLUSIVE", "vulnerable": True},
    {"name": "patch_default_readonly", "kind": "patch", "expected": "SKIPPED", "vulnerable": True},
    {"name": "patch_not_allowlisted", "kind": "patch", "expected": "SKIPPED", "vulnerable": True},
)

# These deliberate controls lack a selector, safety clearance, write opt-in,
# or usable initial snapshot. Keep them in the all-vulnerabilities denominator.
CONTROL_ONLY_NAMES = {
    "no_object_selector", "unsafe_read", "patch_default_readonly", "patch_not_allowlisted",
    "patch_initial_202", "patch_initial_206", "patch_initial_content_range",
}


def run_scenario(scenario):
    from core.auditor import APISentinelAuditor
    from core.config_validator import ConfigValidator

    name = scenario["name"]
    is_patch = scenario.get("kind") == "patch"
    nested = name in {"patch_nested_restore", "patch_nested_readonly"}
    custom = name in {"patch_custom_readonly", "patch_nested_readonly"}
    field = "server_marker" if custom else "role"
    original_value = False if custom else "user"
    original = {"profile": {field: original_value}} if nested else {field: original_value}
    state = copy.deepcopy(original)
    calls = []
    patch_count = 0
    failed_restore = name in {"patch_restore_failure", "patch_restore_202"}

    owner_record = {"id": "owner-record", "tenant": "tenant-a", "private_note": "Owner-only 8294"}
    visitor_record = {"id": "visitor-record", "tenant": "tenant-b", "private_note": "Visitor-only 5163"}

    def document(record):
        if name == "nested_resource_leak":
            return {"data": {"record": copy.deepcopy(record)}}
        if name == "array_resource_leak":
            return [copy.deepcopy(record)]
        if name == "paged_resource_leak":
            return {"items": [copy.deepcopy(record)], "page": 1, "total": 1}
        return copy.deepcopy(record)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, payload, *, content_range=False, invalid=False):
            body = b"" if status == 204 else (b"{" if invalid else json.dumps(payload).encode("utf-8"))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if content_range or status == 206:
                self.send_header("Content-Range", f"bytes 0-{len(body)-1}/{len(body)+100}")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            calls.append({"method": "GET", "path": self.path})
            if is_patch:
                status, body = 200, state
                content_range = name == "patch_initial_content_range" and patch_count == 0
                if name in {"patch_initial_202", "patch_initial_206"} and patch_count == 0:
                    status = int(name.rsplit("_", 1)[1])
                if name.startswith("patch_stale_") and patch_count == 1:
                    status, body = int(name.rsplit("_", 1)[1]), original
                if name == "patch_restore_202" and patch_count >= 2:
                    status, body = 202, original
                self.respond(status, body, content_range=content_range,
                             invalid=name == "patch_invalid_after" and patch_count == 1)
                return
            identity = self.headers.get("Authorization")
            parts = urlsplit(self.path)
            resource = (parse_qs(parts.query).get("record_id", [""])[0]
                        if name == "query_resource_leak" else parts.path.rsplit("/", 1)[-1])
            if identity not in {"Bearer fixture-owner", "Bearer fixture-visitor"}:
                self.respond(401, {"error": "Unauthorized"})
            elif identity == "Bearer fixture-owner":
                payload = document(owner_record)
                if name == "truncated_owner_response":
                    payload["large_note"] = "x" * 2048
                self.respond(200, payload)
            elif resource == "visitor-record" or name == "caller_self_instead_of_owner":
                self.respond(200, document(visitor_record))
            elif name in {"ordinary_denial", "cross_tenant_denial", "shared_but_denied"}:
                self.respond(403, {"error": "Forbidden"})
            elif name == "masked_404_denial":
                self.respond(404, {"message": "Not found"})
            elif name == "error_500_generic":
                self.respond(500, {"error": "Temporary server failure"})
            elif name in {"error_500_owner_data", "error_404_owner_data"}:
                self.respond(500 if "500" in name else 404, document(owner_record))
            else:
                self.respond(200, document(owner_record))

        def do_PATCH(self):
            nonlocal patch_count
            patch_count += 1
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append({"method": "PATCH", "path": self.path, "body": body,
                          "content_type": self.headers.get("Content-Type")})
            if failed_restore and patch_count >= 2:
                self.respond(500 if name == "patch_restore_failure" else 200, {"ok": True})
                return
            if name != "patch_no_persistence":
                state.update(copy.deepcopy(body))
            self.respond(scenario.get("write_status", 200), {"ok": True})

    identities = {
        "owner": {"id": "owner-record", "token": "Bearer fixture-owner",
                  "parameters": {"record_id": "owner-record"}},
        "visitor": {"id": "visitor-record", "token": "Bearer fixture-visitor",
                    "parameters": {"record_id": "visitor-record"}},
        "anonymous": {},
    }
    kwargs = {"identities_config": identities, "request_delay": 0, "max_workers": 1,
              "max_response_bytes": 1024}
    if is_patch:
        child = ({"type": "boolean", "readOnly": True} if custom else
                 {"type": "string", "enum": ["user", "admin"]})
        properties = {"profile": {"type": "object", "properties": {field: child}}} if nested else {field: child}
        schema = {"type": "object", "properties": properties}
        operation = {"requestBody": {"content": {"application/json": {"schema": schema}}},
                     "responses": {"200": {"description": "Updated"}}}
        spec = {"openapi": "3.0.3", "paths": {"/profile": {
            "get": {"responses": {"200": {"description": "Current state"}}}, "patch": operation}}}
        if name == "patch_swagger_json_alternative":
            spec.pop("openapi")
            spec["swagger"] = "2.0"
            operation.pop("requestBody")
            operation.update({"consumes": ["application/xml", "application/json"],
                              "parameters": [{"in": "body", "name": "body", "schema": schema}]})
        field_path = f"profile.{field}" if nested else field
        readback = {"method": "GET", "path": "/profile", "field_map": {field_path: field_path},
                    "consistency": "strong", "readback_attempts": 1, "readback_delay": 0}
        readbacks = {"PATCH /profile": readback}
        allowlist = [] if name == "patch_not_allowlisted" else ["PATCH /profile"]
        if failed_restore:
            spec["paths"]["/later"] = {"patch": copy.deepcopy(operation)}
            readbacks["PATCH /later"] = copy.deepcopy(readback)
            allowlist.append("PATCH /later")
        config = {"identities": identities, "readbacks": readbacks, "write_allowlist": allowlist}
        validation = ConfigValidator.validate(config, spec)
        if not validation.is_valid:
            raise AssertionError(f"Invalid fixture configuration: {validation.errors}")
        kwargs.update({"allow_write_tests": name != "patch_default_readonly",
                       "write_allowlist": allowlist, "readback_config": readbacks})
        target_key = "PATCH /profile"
    else:
        path = "/records/{record_id}"
        parameters = [{"name": "record_id", "in": "path", "required": True, "schema": {"type": "string"}}]
        if name == "query_resource_leak":
            path, parameters[0]["in"] = "/records", "query"
        elif name == "no_object_selector":
            path, parameters = "/records", []
        elif name == "unsafe_read":
            path = "/records/{record_id}/delete"
        operation = {"security": [{"bearer": []}], "parameters": parameters,
                     "responses": {"200": {"description": "Selected record"}}}
        spec = {"openapi": "3.0.3", "paths": {path: {"get": operation}}}
        target_key = "GET " + path
        id_path = {"nested_resource_leak": "data.record.id", "array_resource_leak": "[].id",
                   "paged_resource_leak": "items[].id"}.get(name, "id")
        policy = "allow" if name in {"team_sharing", "tenant_admin", "shared_but_denied"} else "deny"
        kwargs["bola_config"] = {target_key: {"expected_visitor_access": policy, "resource_id_paths": [id_path]}}

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="granttrace-coverage-") as directory:
            spec_path = Path(directory) / "openapi.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            with patch("urllib.request.getproxies", return_value={}):
                auditor = APISentinelAuditor(str(spec_path), f"http://127.0.0.1:{server.server_port}", **kwargs)
            with contextlib.redirect_stdout(io.StringIO()):
                auditor.run()
            primary = next(item for item in auditor.results if item["endpoint"] == target_key and item["check"] != "ROLLBACK")
            evidence = primary["evidence"]
            failures = []
            if primary["verdict"] != scenario["expected"]:
                failures.append("Unexpected primary verdict")
            if is_patch:
                if not failed_restore and state != original:
                    failures.append("Disposable resource was not restored")
                if failed_restore and (evidence.get("rollback_verified") is not False
                                       or not auditor._writes_halted_reason):
                    failures.append("Failed/ambiguous restoration was trusted")
                if failed_restore and not any(item["endpoint"] == "PATCH /later" and item["verdict"] == "SKIPPED"
                                              for item in auditor.results):
                    failures.append("Later write was not halted")
                if name.startswith("patch_initial_") or name in {"patch_default_readonly", "patch_not_allowlisted"}:
                    if patch_count:
                        failures.append("A write was sent despite an unusable baseline or write gate")
            return {**scenario, "actual": primary["verdict"], "oracle_failures": failures,
                    "matches_expectation": not failures, "requests": len(calls), "patch_requests": patch_count,
                    "executed": evidence.get("requests_attempted", 0) > 0,
                    "resource_restored": state == original if is_patch else None,
                    "rollback_verified": evidence.get("rollback_verified"),
                    "recovery_sent": evidence.get("recovery_sent"),
                    "later_writes_halted": bool(auditor._writes_halted_reason),
                    "stats": auditor.stats, "results": auditor.results}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def run_scenarios():
    outcomes = [run_scenario(scenario) for scenario in SCENARIOS]
    known = [item for item in outcomes if item["vulnerable"] is True]
    eligible = [item for item in outcomes if item["name"] not in CONTROL_ONLY_NAMES]
    confirmed = sum(item["actual"] == "CONFIRMED" for item in known)
    return {
        "scope": "Fixed synthetic loopback fixtures; not production detection rates",
        "metric_definitions": {
            "known_vulnerability_detection_rate": "CONFIRMED / all independently declared vulnerable fixtures, including safely blocked or opt-out cases",
            "false_negative": "Known vulnerable fixture without CONFIRMED; SUSPICIOUS is still not a confirmation",
            "executed": "Primary check attempted at least one HTTP request; initial readback counts as execution, not a PATCH",
        },
        "scenario_count": len(outcomes), "executed_scenarios": sum(item["executed"] for item in outcomes),
        "eligible_target_scenarios": len(eligible),
        "executed_eligible_targets": sum(bool(item["patch_requests"]) if item.get("kind") == "patch"
                                         else item["executed"] for item in eligible),
        "control_only_names": sorted(CONTROL_ONLY_NAMES),
        "verdict_counts": dict(Counter(item["actual"] for item in outcomes)),
        "known_vulnerable_scenarios": len(known), "confirmed_known_vulnerabilities": confirmed,
        "known_vulnerability_detection_rate": round(100 * confirmed / len(known), 2) if known else None,
        "false_positives": sum(item["vulnerable"] is False and item["actual"] == "CONFIRMED" for item in outcomes),
        "false_negatives": len(known) - confirmed,
        "safety_or_expectation_failures": sum(not item["matches_expectation"] for item in outcomes),
        "unrestored_resources": sum(item["resource_restored"] is False for item in outcomes),
        "false_restoration_claims": sum(item["resource_restored"] is False and item["rollback_verified"] is True for item in outcomes),
        "scenarios": outcomes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "authorization-coverage.json")
    args = parser.parse_args()
    sys.path.insert(0, str(args.source_root.resolve()))
    result = run_scenarios()
    result["source_root"] = str(args.source_root.resolve())
    result["source_commit"] = subprocess.check_output(
        ["git", "-C", str(args.source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    result["source_tree_dirty"] = bool(subprocess.check_output(
        ["git", "-C", str(args.source_root), "status", "--porcelain"], text=True
    ).strip())
    source_hash = hashlib.sha256()
    for source in sorted((args.source_root / "core").rglob("*.py")) + [args.source_root / "api_sentinel.py"]:
        source_hash.update(source.relative_to(args.source_root).as_posix().encode() + b"\0")
        source_hash.update(source.read_bytes())
    result["runtime_source_sha256"] = source_hash.hexdigest()
    result["fixture_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "scenarios"}, indent=2))
    return int(bool(result["safety_or_expectation_failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
