"""Large-spec safety parity, deterministic cache savings and offline boundaries."""

import contextlib
import io
import json
import re
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from pathlib import Path
from unittest.mock import MagicMock, patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.parameters import ParameterSerializationError
from core.parser import OpenAPIParser
from scripts.benchmark_read_safety import TARGET, measure_work, safety_requests, synthetic_spec


def successful_response():
    response = MagicMock()
    response.__enter__.return_value = response
    response.status = 200
    response.headers = Message()
    response.headers["Content-Type"] = "application/json"
    response.read.return_value = b'{"id":"1002","role":"user"}'
    return response


class ReadSafetyCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.spec_path = self.folder / "spec.json"
        self.write_spec(synthetic_spec(100))

    def write_spec(self, spec):
        self.spec_path.write_text(json.dumps(spec), encoding="utf-8")

    def auditor(self, **kwargs):
        return APISentinelAuditor(str(self.spec_path), TARGET, request_delay=0, **kwargs)

    def test_constructor_normalizes_and_precompiles_once_without_network(self):
        original = OpenAPIParser.get_endpoints
        with patch.object(OpenAPIParser, "get_endpoints", autospec=True, side_effect=original) as normalize, \
                patch("re.escape", wraps=re.escape) as routes, \
                patch("urllib.request.OpenerDirector.open") as transport:
            auditor = self.auditor()
        self.assertEqual(normalize.call_count, 1)
        # The one PATCH does not need a request-time read route.
        self.assertEqual(routes.call_count, 99)
        transport.assert_not_called()
        results, work = measure_work(auditor, safety_requests(), 1)
        self.assertEqual(work, {"normalization_passes": 0, "normalized_operations": 0,
                                "route_pattern_builds": 0})
        self.assertEqual([bool(result) for result in results], [blocked for _, _, blocked in safety_requests()])

    def test_large_specs_keep_legacy_verdicts_and_eliminate_repeated_normalization(self):
        for size in (100, 500, 1000):
            self.write_spec(synthetic_spec(size))
            auditor = self.auditor()
            self.assertEqual(len(auditor.parser.get_endpoints()), size)
            requests = safety_requests()
            read_checks = sum(method in {"GET", "HEAD"} for method, _, _ in requests)
            for workers in (1, 4):
                with self.subTest(endpoints=size, workers=workers):
                    before_results, before = measure_work(auditor, requests, workers, legacy=True)
                    after_results, after = measure_work(auditor, requests, workers)
                    self.assertEqual(before_results, after_results)
                    self.assertEqual([bool(result) for result in after_results],
                                     [blocked for _, _, blocked in requests])
                    self.assertEqual(before, {"normalization_passes": read_checks,
                                              "normalized_operations": size * read_checks,
                                              "route_pattern_builds": (size - 1) * read_checks})
                    self.assertEqual(after, {"normalization_passes": 0, "normalized_operations": 0,
                                             "route_pattern_builds": 0})

    def test_multithreaded_reads_execute_and_block_risk_before_transport(self):
        self.write_spec(synthetic_spec(1000))
        auditor = self.auditor()
        requests = [item for item in safety_requests() if item[0] in {"GET", "HEAD"}]
        for workers in (1, 4):
            with self.subTest(workers=workers), \
                    patch.object(auditor._opener, "open", return_value=successful_response()) as transport:
                def send(item):
                    method, url, _ = item
                    return auditor._http_request(method, url, identity_name="owner")

                with ThreadPoolExecutor(max_workers=workers) as executor:
                    results = list(executor.map(send, requests))
                safe_urls = {url for _, url, blocked in requests if not blocked}
                self.assertEqual(transport.call_count, len(safe_urls))
                self.assertTrue(all(call.args[0].full_url in safe_urls for call in transport.call_args_list))
                for result, (_, _, blocked) in zip(results, requests):
                    self.assertEqual(result.status, 0 if blocked else 200)
                    if blocked:
                        self.assertIn("safety policy", result.error)

    def test_unsafe_overlapping_patch_readback_blocks_baseline_and_write(self):
        self.write_spec(synthetic_spec(1000))
        mapping = {"method": "GET", "path": "/opaque/{id}", "parameter_values": {"id": "create_report"},
                   "field_map": {"role": "role"}, "consistency": "strong"}
        auditor = self.auditor(allow_write_tests=True, write_allowlist=["PATCH /settings/{id}"],
                               readback_config={"PATCH /settings/{id}": mapping})
        endpoints = auditor.parser.get_endpoints()
        endpoint = next(item for item in endpoints if item["method"] == "PATCH")
        with patch.object(auditor, "_http_request") as transport:
            auditor.audit_endpoint_mass_assignment(endpoint, endpoints)
            with self.assertRaises(ParameterSerializationError):
                auditor._readback_result(endpoint, mapping, "visitor")
        transport.assert_not_called()
        self.assertEqual(auditor.results[0]["verdict"], "SKIPPED")
        self.assertEqual(auditor.results[0]["evidence"]["reason_category"], "safety_policy")
        self.assertEqual(auditor.results[0]["evidence"]["requests_attempted"], 0)
        operation = next(item for item in auditor.build_plan()["operations"]
                         if item["check"] == "MASS_ASSIGNMENT")
        self.assertFalse(operation["writes_enabled"])
        self.assertTrue(operation["safety_blocked"])

    def test_safe_patch_readback_executes_without_renormalizing_spec(self):
        auditor = self.auditor()
        endpoint = {"method": "PATCH", "path": "/settings/{id}"}
        mapping = {"method": "GET", "path": "/state/{id}", "parameter_values": {"id": "1002"}}
        with patch.object(auditor.parser, "get_endpoints") as normalize, \
                patch.object(auditor._opener, "open", return_value=successful_response()) as transport:
            url, result = auditor._readback_result(endpoint, mapping, "visitor")
        normalize.assert_not_called()
        transport.assert_called_once()
        self.assertEqual(url, TARGET + "/state/1002")
        self.assertEqual(result.status, 200)

    def test_cache_results_and_readback_parameters_do_not_expose_mutable_state(self):
        auditor = self.auditor()
        url = TARGET + "/opaque/create_report"
        first = auditor._read_request_risk("GET", url)
        expected = dict(first)
        first["safety_reason"] = "modified by caller"
        self.assertEqual(auditor._read_request_risk("GET", url), expected)
        endpoint = {"method": "PATCH", "path": "/settings/{id}"}
        mapping = {"method": "GET", "path": "/state/{id}"}
        first_readback = auditor._readback_endpoint(endpoint, mapping)
        first_readback["parameters"][0]["schema"]["minLength"] = 999
        self.assertEqual(auditor._readback_endpoint(endpoint, mapping)["parameters"][0]["schema"]["minLength"], 1)

    def test_parser_replacement_rebuilds_once_for_concurrent_first_reads(self):
        auditor = self.auditor()
        self.assertIsNone(auditor._read_request_risk("GET", TARGET + "/records/1001"))
        replacement_spec = synthetic_spec(500)
        replacement_spec["paths"]["/records/{id}"]["get"]["operationId"] = "deleteRecords"
        self.write_spec(replacement_spec)
        replacement = OpenAPIParser(str(self.spec_path))
        auditor.parser = replacement
        barrier = threading.Barrier(4)

        def first_read(_):
            barrier.wait(timeout=10)
            return auditor._read_request_risk("GET", TARGET + "/records/1001")

        with patch.object(replacement, "get_endpoints", wraps=replacement.get_endpoints) as normalize, \
                patch("re.escape", wraps=re.escape) as routes:
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = list(executor.map(first_read, range(4)))
            self.assertTrue(all(result["safety_signal"] == "operation_id" for result in results))
            self.assertEqual(normalize.call_count, 1)
            self.assertEqual(routes.call_count, 499)
            self.assertIsNotNone(auditor._read_request_risk("GET", TARGET + "/records/current"))
            self.assertEqual(normalize.call_count, 1)

    def test_failed_parser_replacement_does_not_reuse_previous_safe_snapshot(self):
        auditor = self.auditor()
        self.assertIsNone(auditor._read_request_risk("GET", TARGET + "/records/1001"))
        auditor.parser = OpenAPIParser(str(self.spec_path))
        with patch.object(auditor.parser, "get_endpoints", side_effect=ValueError("invalid replacement")), \
                patch.object(auditor._opener, "open") as transport:
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, "invalid replacement"):
                    auditor._http_request("GET", TARGET + "/records/1001", identity_name="owner")
        transport.assert_not_called()

    def test_large_spec_validation_and_dry_run_make_zero_network_requests(self):
        config = self.folder / "settings.json"
        config.write_text("{}", encoding="utf-8")
        for size in (100, 500, 1000):
            self.write_spec(synthetic_spec(size))
            for flag in ("--validate-config", "--dry-run"):
                with self.subTest(endpoints=size, flag=flag), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                        patch("urllib.request.OpenerDirector.open") as opener, \
                        patch("urllib.request.urlopen") as urlopen:
                    self.assertEqual(main(["--spec", str(self.spec_path), "--target", TARGET,
                                           "--config", str(config), flag]), 0)
                opener.assert_not_called()
                urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
