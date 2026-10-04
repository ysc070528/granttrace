"""Run the existing auditor against an isolated, bundled loopback playground."""

from __future__ import annotations

import argparse
import copy
import io
import json
import sys
import tempfile
import threading
import time
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

from core import __version__
from core.auditor import APISentinelAuditor, _NoRedirectHandler
from core.config_validator import ConfigValidator
from core.evidence import sanitize_log_text, sanitize_text
from core.models import HTTPResult, json_values_equal, strict_json_loads
from core.reporter import SecurityReportGenerator
from core.reproduction import build_reproduction_templates
from mock_server.server import TargetMockHandler


def load_assets() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    assets = resources.files("core.demo_assets")
    spec = strict_json_loads(assets.joinpath("openapi.json").read_text(encoding="utf-8"))
    config = strict_json_loads(assets.joinpath("demo-config.json").read_text(encoding="utf-8"))
    database = strict_json_loads(assets.joinpath("mock-data.json").read_text(encoding="utf-8"))
    return spec, config, database


class DemoServer:
    """Own one in-process server and an independent copy of fictional data."""

    def __init__(self, database: Dict[str, Any]) -> None:
        class Handler(TargetMockHandler):
            INITIAL_DATABASE = copy.deepcopy(database)
            DATABASE = copy.deepcopy(database)
            requests: list = []

            def _get_current_user(self) -> str:
                # Public, fictional role labels, not user-supplied credentials.
                return {"granttrace-demo-owner-1001": "1001", "granttrace-demo-visitor-1002": "1002"}.get(
                    self.headers.get("X-GrantTrace-Demo-Identity", ""), "")

            def _record(self, method: str) -> None:
                self.requests.append({"method": method, "path": self.path,
                                      "user_agent": self.headers.get("User-Agent", "")})

            def do_GET(self) -> None:
                self._record("GET")
                super().do_GET()

            def do_PATCH(self) -> None:
                self._record("PATCH")
                super().do_PATCH()

            def do_PUT(self) -> None:
                self._write_json(405, {"error": "Demo only supports GET and PATCH"})

        self.handler = Handler
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.target = f"http://127.0.0.1:{self.server.server_port}"
        try:
            self.thread = threading.Thread(
                target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                name=f"granttrace-demo-{self.server.server_port}", daemon=True)
        except BaseException:
            self.server.server_close()
            raise

    def __enter__(self) -> DemoServer:
        try:
            self.thread.start()
            # A real loopback response confirms readiness; bypass environment proxies.
            opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
            with opener.open(self.target + "/api/public/articles/101", timeout=3) as response:
                if response.status != 200:
                    raise RuntimeError("Local demo server is not ready")
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        try:
            if self.thread.is_alive():
                self.server.shutdown()
        finally:
            self.server.server_close()
            if self.thread.ident is not None:
                self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise RuntimeError("Local demo server did not stop")

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        # Do not reset the database: real rollback must restore it before shutdown.
        self.close()


class _LocalDemoAuditor(APISentinelAuditor):
    """Keep the inherited detectors; constrain demo transport to its own server."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._demo_origin = urlsplit(self.target_base_url)
        if self._demo_origin.scheme != "http" or self._demo_origin.hostname != "127.0.0.1":
            raise ValueError("Demo must use the bundled loopback server")
        self._opener = build_opener(ProxyHandler({}), _NoRedirectHandler())

    def _http_request(self, method: str, url: str, data: Optional[Dict[str, Any]] = None,
                      identity_name: str = "anonymous", content_type: str = "application/json") -> HTTPResult:
        selected = urlsplit(url)
        if (method not in {"GET", "PATCH"}
                or (selected.scheme, selected.netloc) != (self._demo_origin.scheme, self._demo_origin.netloc)):
            raise ValueError("Demo requests must stay on the bundled loopback GET/PATCH target")
        return super()._http_request(method, url, data, identity_name, content_type)


def _verify_demo(auditor: APISentinelAuditor, server: DemoServer, read_only: bool) -> Dict[str, Any]:
    expected = {"bola_confirmed": 1, "mass_assignment_confirmed": 0 if read_only else 1,
                "error_count": 0, "inconclusive_count": 0, "suspicious_count": 0}
    if any(auditor.stats.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Built-in demo did not produce the expected authorization results")
    restored = json_values_equal(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
    if not restored:
        raise RuntimeError("Demo database was not fully restored; demo verification failed")
    writes = [item for item in auditor.results if item["check"] == "MASS_ASSIGNMENT"]
    methods = [item["method"] for item in server.handler.requests]
    rollback: Optional[bool] = None
    if read_only:
        if "PATCH" in methods or len(writes) != 2 or any(item["verdict"] != "SKIPPED" for item in writes):
            raise RuntimeError("Read-only demo must not send PATCH requests")
    else:
        if (len(writes) != 2 or "PATCH" not in methods
                or not all(item["evidence"].get("rollback_verified") is True for item in writes)):
            raise RuntimeError("Independent readback and rollback verification did not succeed")
        mass = next(item for item in auditor.findings if item["cwe"] == "CWE-915")
        evidence = mass["evidence"]
        if (evidence["readback_url"] == evidence["target_url"] or evidence["after"]["status"] != 200
                or not evidence["recovery_sent"]):
            raise RuntimeError("Demo must verify persistence using an independent readback and recovery")
        rollback = True
    return {"read_only": read_only, "rollback_verified": rollback, "database_restored": restored,
            "target_bound_to_loopback": server.server.server_address[0] == "127.0.0.1",
            "request_methods": sorted(set(methods)),
            "user_agents": sorted({item["user_agent"] for item in server.handler.requests
                                   if item["user_agent"].startswith("GrantTrace/")})}


def run_demo(output_dir: Optional[str] = None, read_only: bool = False) -> int:
    print(f"GrantTrace Demo {__version__}")
    try:
        spec, config, database = load_assets()
        validation = ConfigValidator.validate(config, raw_spec=spec)
        if not validation.is_valid:
            raise ValueError("Bundled demo configuration is invalid")
        base = Path(output_dir).expanduser() if output_dir is not None else Path.cwd() / "granttrace-demo"
        base = base.resolve()
        base.mkdir(parents=True, exist_ok=True)
        # mkdtemp creates a new directory atomically; existing reports remain untouched.
        output = Path(tempfile.mkdtemp(prefix="run-", dir=str(base)))
        html = output / "granttrace_report.html"
        exported = output / "granttrace_report.json"
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="granttrace-demo-assets-") as temporary:
            spec_file = Path(temporary) / "openapi.json"
            spec_file.write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
            with DemoServer(database) as server:
                print("Local target: " + server.target)
                print("PATCH tests: " + ("disabled (read-only)." if read_only else
                      "bundled disposable local data only, with readback and rollback."))
                print("Running authorization audit...")
                auditor = _LocalDemoAuditor(
                    spec_path=str(spec_file), target_base_url=server.target,
                    max_workers=3, request_delay=0, request_timeout=3,
                    identities_config=config["identities"], parameter_values=config["parameter_values"],
                    readback_config=config["readbacks"], write_allowlist=config["write_allowlist"],
                    bola_config=config["bola"], allow_write_tests=not read_only)
                with redirect_stdout(io.StringIO()):
                    auditor.run()
                verification = _verify_demo(auditor, server, read_only)
        verification["server_stopped"] = not server.thread.is_alive() and server.server.socket.fileno() == -1
        if not verification["server_stopped"]:
            raise RuntimeError("Local demo server is still running")
        reproduction_secrets = set(auditor._secret_values)
        for identity_name in auditor.identities:
            reproduction_secrets.update(auditor._identity_headers(identity_name).values())
        reproduction_templates = build_reproduction_templates(
            auditor.findings, auditor._identity_headers("visitor"), reproduction_secrets,
        )
        SecurityReportGenerator.generate(
            stats=auditor.stats, findings=auditor.findings, results=auditor.results,
            target_url=server.target, output_path=str(html), reproduction_templates=reproduction_templates)
        payload = {"tool_version": __version__, "report_schema_version": 2,
                   "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "elapsed_seconds": round(time.monotonic() - started, 3), "target": server.target,
                   "stats": auditor.stats, "results": auditor.results, "findings": auditor.findings,
                   "demo": verification}
        exported.write_text(json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
        print("Findings:")
        print(f"- BOLA / IDOR: {auditor.stats['bola_confirmed']} confirmed")
        print(f"- Mass Assignment: {auditor.stats['mass_assignment_confirmed']} confirmed")
        print("Rollback verified: " + ("not applicable (read-only)" if read_only else "yes"))
        print("Mock database restored: yes\nLocal server stopped: yes")
        print(f"HTML report:\n{html}\nJSON report:\n{exported}")
        print("Demo completed successfully.")
        print("\nTo audit your own API (read-only by default):")
        print("  granttrace --spec your-openapi.yaml --init-config config.local.json")
        print("  granttrace --spec your-openapi.yaml --config config.local.json --validate-config")
        print("  granttrace --spec your-openapi.yaml --config config.local.json --dry-run")
        return 0
    except KeyboardInterrupt:
        print("[ERROR] Demo interrupted; the local server was closed.", file=sys.stderr)
        return 130
    except Exception as exc:
        message = sanitize_log_text(sanitize_text(f"{type(exc).__name__}: {exc}"))
        print("[ERROR] Demo failed: " + message, file=sys.stderr)
        return 2


def demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="granttrace demo", description="Bundled disposable loopback demo; no external targets or credentials")
    parser.add_argument("--output-dir", metavar="PATH", help="Report parent directory; create a unique run subdirectory")
    parser.add_argument("--read-only", action="store_true", help="Compare identities without sending PATCH requests")
    args = parser.parse_args(argv)
    return run_demo(output_dir=args.output_dir, read_only=args.read_only)
