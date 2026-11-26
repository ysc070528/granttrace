"""The request-policy benchmark measures the same decisions on every revision it compares.

Timings vary by machine; the counts it reports do not. A small run pins them, so a change that
alters what the policy sends shows up in the benchmark output, not only in its timings.
"""

from __future__ import annotations

import unittest

from scripts.benchmark_request_policy import VALUES, measure


class RequestPolicyBenchmarkTests(unittest.TestCase):
    def test_a_small_run_reports_deterministic_counts(self) -> None:
        endpoints = 2 * len(VALUES)
        results = measure(endpoints=endpoints, requests=4, repeats=1)
        refused_values = {"delete", "withdraw", "cancel"}
        refused = sum(1 for index in range(endpoints) if VALUES[index % len(VALUES)] in refused_values)
        self.assertEqual(results["refused_send_reached_server"], 0)
        self.assertEqual(results["auditor_refusals_per_pass"], refused)
        scan = results["scan"]
        self.assertEqual(scan["requests_received"], scan["http_requests_sent"])
        self.assertEqual(scan["transport_attempts"], scan["http_requests_sent"])
        self.assertEqual(scan["verdicts"].get("SKIPPED"), refused)
        self.assertEqual(sum(scan["verdicts"].values()), endpoints)
        for key in ("auditor_check_us", "send_allowed_us", "send_refused_us", "scan_seconds"):
            self.assertGreater(results[key], 0)


if __name__ == "__main__":
    unittest.main()
