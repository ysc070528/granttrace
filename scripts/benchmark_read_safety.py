"""Compare cached safety checks with the previous implementation, without network I/O.

The legacy function intentionally retains the previous request-time normalization
and route construction. Timings are observations; regression tests assert work
counts and safety parity instead of depending on machine-specific thresholds.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.auditor import APISentinelAuditor  # noqa: E402 - standalone script imports from the repository root
from core.scan_safety import read_only_risk  # noqa: E402


TARGET = "http://127.0.0.1:8080/api/v1"


def synthetic_spec(endpoint_count):
    """Build exactly endpoint_count operations with local parameter/schema refs."""
    identifier = {"name": "id", "in": "path", "required": True,
                  "schema": {"$ref": "#/components/schemas/Identifier"}}
    paths = {
        "/records/{id}": {"get": {"operationId": "getRecord", "parameters": [identifier]}},
        "/records/current": {"get": {"operationId": "getCurrentRecord"}},
        "/opaque/{id}": {"get": {"operationId": "getOpaqueRecord", "parameters": [identifier]}},
        "/opaque/create_report": {"get": {"operationId": "createReport"}},
        "/desc/{id}": {"get": {"description": "This endpoint updates a report.",
                               "parameters": [identifier]}},
        "/heads/{id}": {"head": {"operationId": "sendReport", "parameters": [identifier]}},
        "/heads/current": {"get": {"operationId": "getCurrentHead"}},
        "/slashes/{id}": {"get": {"operationId": "getSlashedRecord", "parameters": [identifier]}},
        "/slashes/a/b": {"get": {"description": "This endpoint creates a report."}},
        "/suffix/{id}.json": {"get": {"operationId": "getJsonRecord", "parameters": [identifier]}},
        "/suffix/admin.json": {"get": {"summary": "Updates settings."}},
        "/collection/{id}/{field}": {"get": {"operationId": "getField"}},
        "/collection/{kind}/private": {"get": {"operationId": "assignPrivateField"}},
        "/state/{id}": {"get": {"operationId": "getState", "parameters": [identifier]}},
        "/settings/{id}": {"patch": {"parameters": [identifier], "requestBody": {
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Settings"}}}}}},
    }
    if endpoint_count < len(paths):
        raise ValueError("endpoint_count must accommodate the fixed safety routes")
    for index in range(endpoint_count - len(paths)):
        dynamic = index % 2 == 0
        path = (f"/resources/group{index:04d}/{{id}}" if dynamic
                else f"/resources/item{index:04d}")
        operation = {
            "operationId": f"getResource{index}",
            "description": "Returns the existing record. Updates are available using PATCH.",
            "parameters": [{"$ref": "#/components/parameters/Query"}],
        }
        if dynamic:
            operation["parameters"].append({"$ref": "#/components/parameters/Identifier"})
        paths[path] = {"get": operation}
    return {
        "openapi": "3.0.3", "info": {"title": "Local read safety benchmark", "version": "1"},
        "paths": paths,
        "components": {
            "parameters": {
                "Identifier": identifier,
                "Query": {"name": "q", "in": "query", "schema": {
                    "type": "string", "maxLength": 128, "default": "existing"}},
            },
            "schemas": {
                "Identifier": {"type": "string", "minLength": 1},
                "Settings": {"type": "object", "properties": {
                    "role": {"type": "string", "readOnly": True, "enum": ["user", "admin"]}}},
            },
        },
    }


def safety_requests(target=TARGET):
    """Fixed routes cover safe reads, encoding, overlap, HEAD and fallback."""
    cases = (
        ("GET", "/records/1001", False),
        ("GET", "/records/current?expand=true", False),
        ("GET", "/records/create_report", False),
        ("GET", "/opaque/%63reate_report", True),
        ("HEAD", "/opaque/create_report", True),
        ("GET", "/opaque/1001", False),
        ("GET", "/desc/1001", True),
        ("GET", "/heads/1001", True),
        ("GET", "/heads/current", True),
        ("GET", "/slashes/a%2Fb", True),
        ("GET", "/suffix/admin%2Ejson", True),
        ("GET", "/suffix/1001.json", False),
        ("GET", "/collection/1001/private", True),
        ("GET", "/collection/1001/public", False),
        ("GET", "/undocumented/create_report", True),
        ("GET", "/undocumented/read_record", False),
        ("POST", "/opaque/create_report", False),
        ("GET", "/resources/group0000/1001?q=existing", False),
    )
    return [(method, target + path, blocked) for method, path, blocked in cases]


def legacy_read_request_risk(auditor, method, url):
    """Previous _read_request_risk, preserved as the before comparator."""
    if str(method).upper() in {"GET", "HEAD"}:
        request_path = urllib.parse.urlsplit(url).path
        base_path = urllib.parse.urlsplit(auditor.target_base_url).path.rstrip("/")
        if base_path and request_path.startswith(base_path + "/"):
            request_path = request_path[len(base_path):]
        request_paths = {request_path, urllib.parse.unquote(request_path)}
        documented = []
        for endpoint in auditor.parser.get_endpoints():
            if endpoint["method"] not in {"GET", "HEAD"}:
                continue
            pattern = re.escape(endpoint["path"])
            pattern = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", pattern)
            if any(re.fullmatch(pattern, path) for path in request_paths):
                documented.append(endpoint)
        candidates = documented or [{"method": method, "path": urllib.parse.unquote(request_path)}]
        return next((risk for endpoint in candidates if (risk := read_only_risk(endpoint))), None)
    return None


def execute_checks(auditor, requests, workers, legacy=False):
    def check(request):
        method, url, _ = request
        if legacy:
            return legacy_read_request_risk(auditor, method, url)
        return auditor._read_request_risk(method, url)

    if workers == 1:
        return [check(request) for request in requests]
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(check, requests))


def measure_work(auditor, requests, workers, legacy=False):
    """Count deterministic work separately from uninstrumented timing."""
    work = {"normalization_passes": 0, "normalized_operations": 0, "route_pattern_builds": 0}
    lock = threading.Lock()

    def counted(function, key):
        def call(*args, **kwargs):
            with lock:
                work[key] += 1
            return function(*args, **kwargs)
        return call

    with patch.object(auditor.parser, "get_endpoints",
                      new=counted(auditor.parser.get_endpoints, "normalization_passes")), \
            patch.object(auditor.parser, "_merge_parameters",
                         new=counted(auditor.parser._merge_parameters, "normalized_operations")), \
            patch("re.escape", new=counted(re.escape, "route_pattern_builds")):
        results = execute_checks(auditor, requests, workers, legacy)
    return results, work


def benchmark(endpoint_count, workers, requests_per_case=2, repeats=3):
    with tempfile.TemporaryDirectory() as folder:
        spec_path = Path(folder) / "spec.json"
        spec_path.write_text(json.dumps(synthetic_spec(endpoint_count)), encoding="utf-8")
        started = time.perf_counter()
        auditor = APISentinelAuditor(str(spec_path), TARGET, request_delay=0)
        # Include any lazy snapshot initialization in the separately stated setup cost.
        auditor._read_request_risk("GET", TARGET + "/records/1001")
        initialization_ms = (time.perf_counter() - started) * 1000
        requests = safety_requests() * requests_per_case
        before_results, before_work = measure_work(auditor, requests, workers, legacy=True)
        after_results, after_work = measure_work(auditor, requests, workers)
        if before_results != after_results:
            raise AssertionError("cached safety results diverged from the previous implementation")
        if [bool(result) for result in after_results] != [blocked for _, _, blocked in requests]:
            raise AssertionError("synthetic safety truth does not match the result")
        before_times, after_times = [], []
        for _ in range(repeats):
            started = time.perf_counter()
            execute_checks(auditor, requests, workers, legacy=True)
            before_times.append((time.perf_counter() - started) * 1000)
            started = time.perf_counter()
            execute_checks(auditor, requests, workers)
            after_times.append((time.perf_counter() - started) * 1000)
        before_ms, after_ms = statistics.median(before_times), statistics.median(after_times)
        return {
            "endpoints": endpoint_count, "workers": workers, "checks": len(requests),
            "initialization_ms": round(initialization_ms, 3),
            "before_ms": round(before_ms, 3), "after_ms": round(after_ms, 3),
            "speedup": round(before_ms / after_ms, 2),
            "before_work": before_work, "after_work": after_work,
            "safety_parity": True, "network_requests": 0,
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[100, 500, 1000])
    parser.add_argument("--workers", nargs="+", type=int, default=[1, 4])
    parser.add_argument("--requests-per-case", type=int, default=2)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.requests_per_case < 1 or args.repeats < 1 or any(worker < 1 for worker in args.workers):
        parser.error("workers, requests-per-case and repeats must be positive")
    rows = [benchmark(size, workers, args.requests_per_case, args.repeats)
            for size in args.sizes for workers in args.workers]
    payload = {"method": "median elapsed time; work counts collected in a separate run", "results": rows}
    rendered = json.dumps(payload, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
