"""Measure what the read-only request policy costs per request and per loopback scan.

Only interfaces that every compared revision has are used (``APISentinelAuditor.run``,
``APISentinelAuditor._request_risk`` and ``HttpTransport.send``), so the same script measures a
baseline and a candidate checkout:

    python scripts/benchmark_request_policy.py --output before.json      # in the baseline checkout
    python scripts/benchmark_request_policy.py --output after.json       # in the candidate checkout

Every request goes to a server this script runs on 127.0.0.1. Timings are medians of
``--repeats`` runs and are observations for one machine; the request and result counts are
deterministic and must be equal between revisions that make the same decisions.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.auditor import APISentinelAuditor  # noqa: E402 - standalone script imports from the repository root
from core.transport import HttpTransport  # noqa: E402

IDENTITIES = {
    "owner": {"id": "1001", "token": "Bearer BENCHMARK-OWNER-TOKEN", "parameters": {}},
    "visitor": {"id": "1002", "token": "Bearer BENCHMARK-VISITOR-TOKEN", "parameters": {}},
    "anonymous": {"id": None, "token": None, "parameters": {}},
}
# Values filled into /reports{n}/{kind}: half ordinary, half refused by every compared revision's
# literal-path rule, so the policy's allow and refuse paths are both measured.
VALUES = ("summary", "history", "monthly", "delete", "withdraw", "cancel")


class _Server:
    def __init__(self) -> None:
        self.count = 0
        self.lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                with server.lock:
                    server.count += 1
                body = b'{"id": "1001", "owner": "alice", "items": [1, 2, 3]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_HEAD = do_POST = do_GET

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _spec(folder: Path, endpoints: int) -> str:
    paths: Dict[str, Any] = {}
    for index in range(endpoints):
        paths[f"/reports{index}/{{kind}}"] = {"get": {
            "operationId": f"readReport{index}", "summary": "Read one report", "security": [{"bearer": []}],
            "parameters": [{"name": "kind", "in": "path", "required": True,
                            "schema": {"type": "string", "enum": [VALUES[index % len(VALUES)]]}}],
            "responses": {"200": {"description": "ok"}}}}
    spec = {"openapi": "3.0.3", "info": {"title": "benchmark", "version": "1"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}, "paths": paths}
    target = folder / f"spec-{endpoints}.json"
    target.write_text(json.dumps(spec), encoding="utf-8")
    return str(target)


def _median_seconds(action: Callable[[], Any], repeats: int) -> float:
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        action()
        samples.append(time.perf_counter() - started)
    return statistics.median(samples)


def _commit() -> str:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def measure(endpoints: int, requests: int, repeats: int) -> Dict[str, Any]:
    server = _Server()
    folder = tempfile.TemporaryDirectory(prefix="granttrace-policy-benchmark-")
    try:
        spec = _spec(Path(folder.name), endpoints)
        transport = HttpTransport(request_delay=0.0, request_timeout=5.0, max_response_bytes=65536,
                                  insecure_ssl=False)
        allowed = server.origin + "/reports0/summary?page=2"
        refused = server.origin + "/reports0/withdraw?page=2"
        auditor = APISentinelAuditor(spec, server.origin, request_delay=0, identities_config=IDENTITIES)
        urls = [f"{server.origin}/reports{index}/{VALUES[index % len(VALUES)]}" for index in range(endpoints)]
        checks = max(1, requests // max(1, len(urls))) * len(urls)

        def auditor_checks() -> None:
            for _ in range(checks // len(urls)):
                for url in urls:
                    auditor._request_risk("GET", url)

        def sends(url: str) -> Callable[[], None]:
            def run() -> None:
                for _ in range(requests):
                    transport.send("GET", url, {})
            return run

        refusals = sum(1 for url in urls if auditor._request_risk("GET", url))
        sent_before = server.count
        transport.send("GET", refused, {})
        refused_reaches = server.count - sent_before

        scan_counts: Dict[str, Any] = {}

        def scan() -> None:
            scan_auditor = APISentinelAuditor(spec, server.origin, request_delay=0, identities_config=IDENTITIES)
            before = server.count
            scan_auditor.run()
            verdicts: Dict[str, int] = {}
            for result in scan_auditor.results:
                verdicts[result["verdict"]] = verdicts.get(result["verdict"], 0) + 1
            scan_counts.update({"requests_received": server.count - before,
                                "http_requests_sent": scan_auditor.stats["http_requests_sent"],
                                "transport_attempts": scan_auditor.stats["transport_attempts"],
                                "verdicts": dict(sorted(verdicts.items()))})

        scan_seconds = _median_seconds(scan, repeats)
        return {
            "auditor_check_us": round(_median_seconds(auditor_checks, repeats) / checks * 1e6, 2),
            "auditor_checks": checks,
            "auditor_refusals_per_pass": refusals,
            "send_allowed_us": round(_median_seconds(sends(allowed), repeats) / requests * 1e6, 2),
            "send_refused_us": round(_median_seconds(sends(refused), repeats) / requests * 1e6, 2),
            "refused_send_reached_server": refused_reaches,
            "scan_seconds": round(scan_seconds, 4),
            "scan": scan_counts,
        }
    finally:
        server.close()
        folder.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--endpoints", type=int, default=60)
    parser.add_argument("--requests", type=int, default=300)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output")
    args = parser.parse_args()
    if min(args.endpoints, args.requests, args.repeats) < 1:
        parser.error("--endpoints, --requests and --repeats must be at least 1")
    document = {
        "commit": _commit(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "parameters": {"endpoints": args.endpoints, "requests": args.requests, "repeats": args.repeats},
        "results": measure(args.endpoints, args.requests, args.repeats),
    }
    text = json.dumps(document, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
