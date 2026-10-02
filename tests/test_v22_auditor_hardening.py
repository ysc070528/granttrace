"""Regression tests for transaction safety, transport and CI hardening (v2.2)."""
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.auditor import APISentinelAuditor
from core.models import HTTPResult
from core.models import json_values_equal
from core.transactions import prepare_patch
from core.diff import ResponseDiffEngine

ROOT = Path(__file__).resolve().parents[1]


class JsonEqualityTests(unittest.TestCase):
    def test_boolean_and_numeric_values_are_not_interchangeable(self):
        self.assertFalse(json_values_equal({"isAdmin": False}, {"isAdmin": 0}))
        self.assertFalse(json_values_equal([True], [1]))
        self.assertFalse(json_values_equal(float("nan"), float("nan")))

    def test_full_snapshot_does_not_hide_boolean_to_numeric_change(self):
        snapshot = prepare_patch({"role": "user", "isAdmin": False},
                                 {"field_path": "role", "value": "admin", "payload": {"role": "admin"}},
                                 {"field_map": {"role": "role"}})
        self.assertFalse(snapshot.matches({"role": "user", "isAdmin": 0}))

    def test_public_comparison_preserves_json_value_types(self):
        result = ResponseDiffEngine.evaluate_bola(
            (200, '{"published":true,"title":"article"}'),
            (200, '{"published":true,"title":"article"}'),
            (200, '{"published":1,"title":"article"}'), expected_public=True)
        self.assertNotEqual(result["verdict"], "PUBLIC_ENDPOINT")


class TransactionHardeningTests(unittest.TestCase):
    def make_auditor(self, state, case=None, field_map=None, consistency="strong", content_type="application/json"):
        ep = {
            "method": "PATCH", "path": "/users/{user_id}", "parameters": [],
            "request_schema": {"type": "object", "properties": {"role": {"type": "string"}}},
            "request_content_type": content_type,
        }
        mapping = {"path": "/users/{user_id}", "field_map": field_map or {"role": "role"},
                   "readback_attempts": 1, "readback_delay": 0, "consistency": consistency}
        auditor = APISentinelAuditor(
            str(ROOT / "openapi.json"), "http://127.0.0.1:8080", request_delay=0,
            allow_write_tests=True, write_allowlist=["PATCH /users/{user_id}", "PATCH /later"],
            readback_config={"PATCH /users/{user_id}": mapping, "PATCH /later": mapping},
        )
        writes = []
        case = case or {"field_path": "role", "path": ("role",), "value": "admin",
                        "payload": {"display_name": "GENERATED", "role": "admin"}}
        auditor._normalise_mutation_cases = lambda schema: [copy.deepcopy(case)]
        auditor._readback_result = lambda *args: ("readback", HTTPResult(200, json.dumps(state)))

        def write(method, url, data=None, identity_name="anonymous", **kwargs):
            writes.append((url, copy.deepcopy(data), kwargs))
            state.update(copy.deepcopy(data))
            return HTTPResult(200, '{"ok":true}')

        auditor._http_request = write
        return auditor, ep, writes

    def test_generated_normal_values_never_overwrite_original_business_values(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        original = copy.deepcopy(state)
        auditor, ep, writes = self.make_auditor(state)
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state, original)
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[0][1], {"display_name": "ORIGINAL", "role": "admin"})
        self.assertEqual(writes[1][1], original)
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])

    def test_array_snapshot_preserves_other_members_and_sibling_fields(self):
        state = {"members": [{"role": "user", "label": "first"},
                             {"role": "user", "label": "second"}]}
        original = copy.deepcopy(state)
        case = {"field_path": "members[0].role", "path": ("members", 0, "role"), "value": "admin",
                "payload": {"members": [{"role": "admin"}]}}
        auditor, ep, writes = self.make_auditor(state, case, {"members[0].role": "members[0].role"})
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state, original)
        self.assertEqual(len(writes[0][1]["members"]), 2)
        self.assertEqual(writes[0][1]["members"][0]["label"], "first")
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])

    def test_missing_ordinary_field_snapshot_prevents_all_writes(self):
        auditor, ep, writes = self.make_auditor({"role": "user"})
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(writes, [])
        self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")

    def test_exception_after_server_commit_still_restores_every_field(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state)
        original_write = auditor._http_request

        def fail_after_commit(*args, **kwargs):
            response = original_write(*args, **kwargs)
            if len(writes) == 1:
                raise LookupError("unknown response encoding after server commit")
            return response

        auditor._http_request = fail_after_commit
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state, {"display_name": "ORIGINAL", "role": "user"})
        self.assertEqual(len(writes), 2)
        self.assertEqual(auditor.results[0]["verdict"], "ERROR")

    def test_exception_in_post_write_readback_also_runs_recovery(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state)
        read_count = [0]
        reader = auditor._readback_result

        def read(*args):
            read_count[0] += 1
            if read_count[0] == 2:
                raise ValueError("bad readback")
            return reader(*args)

        auditor._readback_result = read
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state["role"], "user")
        self.assertEqual(len(writes), 2)
        self.assertEqual(auditor.results[0]["verdict"], "ERROR")

    def test_failed_restore_halts_later_endpoints(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state)
        original_write = auditor._http_request

        def refuse_restore(method, url, data=None, **kwargs):
            if data["role"] == "user":
                return HTTPResult(403, '{"error":"forbidden"}')
            return original_write(method, url, data=data, **kwargs)

        auditor._http_request = refuse_restore
        later = dict(ep, path="/later")
        with patch.object(auditor.parser, "get_endpoints", return_value=[ep, later]), redirect_stdout(io.StringIO()):
            auditor.run()
        self.assertEqual(len(writes), 1)
        self.assertEqual(state["role"], "admin")
        self.assertTrue(auditor._writes_halted_reason)
        self.assertEqual(auditor.results[-1]["endpoint"], "PATCH /later")
        self.assertEqual(auditor.results[-1]["verdict"], "SKIPPED")
        self.assertGreater(auditor.stats["error_count"], 0)

    def test_verification_covers_normal_fields_not_only_privilege_field(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state)
        original_write = auditor._http_request

        def corrupt_ordinary_field(*args, **kwargs):
            result = original_write(*args, **kwargs)
            state["display_name"] = "CORRUPTED"
            return result

        auditor._http_request = corrupt_ordinary_field
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state["role"], "user")
        self.assertFalse(auditor.findings[0]["evidence"]["rollback_verified"])
        self.assertTrue(auditor._writes_halted_reason)
        self.assertGreater(auditor.stats["error_count"], 0)

    def test_async_acceptance_halts_even_if_state_is_currently_restored(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state)
        writer = auditor._http_request

        def async_write(*args, **kwargs):
            result = writer(*args, **kwargs)
            return HTTPResult(202, '{"queued":true}') if len(writes) == 1 else result

        auditor._http_request = async_write
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state["role"], "user")
        self.assertTrue(auditor._writes_halted_reason)
        self.assertGreater(auditor.stats["error_count"], 0)

    def test_exception_inside_recovery_itself_halts_all_later_writes(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state)
        with patch.object(auditor, "_rollback_and_verify", side_effect=RuntimeError("recovery failed")):
            auditor.audit_endpoint_mass_assignment(ep, [ep])
        auditor.audit_endpoint_mass_assignment(dict(ep, path="/later"), [ep])
        self.assertEqual(len(writes), 1)
        self.assertTrue(auditor._writes_halted_reason)
        self.assertGreater(auditor.stats["error_count"], 0)
        self.assertEqual(auditor.results[-1]["verdict"], "SKIPPED")

    def test_non_finite_readback_attempts_cannot_escape_recovery(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state)
        auditor.readback_config["PATCH /users/{user_id}"]["readback_attempts"] = float("inf")
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state["role"], "user")
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])

    def test_denial_response_does_not_skip_readback_or_recovery(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state)
        writer = auditor._http_request

        def lying_status(*args, **kwargs):
            result = writer(*args, **kwargs)
            return HTTPResult(403, '{"error":"forbidden"}') if len(writes) == 1 else result

        auditor._http_request = lying_status
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state["role"], "user")
        self.assertEqual(auditor.results[0]["verdict"], "CONFIRMED")
        self.assertEqual(len(writes), 2)

    def test_weakly_consistent_unchanged_read_is_not_secure(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state, consistency="eventual")
        auditor._http_request = lambda *args, **kwargs: HTTPResult(200, '{"ok":true}')
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")

    def test_derived_privilege_change_outside_payload_prevents_successful_recovery_claim(self):
        state = {"display_name": "ORIGINAL", "role": "user", "effectiveAdmin": False}
        auditor, ep, writes = self.make_auditor(state)
        writer = auditor._http_request

        def derived_change(*args, **kwargs):
            result = writer(*args, **kwargs)
            if state["role"] == "admin":
                state["effectiveAdmin"] = True
            return result

        auditor._http_request = derived_change
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(state["role"], "user")
        self.assertTrue(state["effectiveAdmin"])
        self.assertFalse(auditor.findings[0]["evidence"]["rollback_verified"])
        self.assertTrue(auditor._writes_halted_reason)

    def test_explicit_volatile_path_can_be_ignored_but_written_fields_cannot(self):
        state = {"display_name": "ORIGINAL", "role": "user", "updatedAt": 1}
        auditor, ep, writes = self.make_auditor(state)
        auditor.readback_config["PATCH /users/{user_id}"]["ignore_readback_paths"] = ["updatedAt"]
        writer = auditor._http_request

        def timestamp_change(*args, **kwargs):
            result = writer(*args, **kwargs)
            state["updatedAt"] += 1
            return result

        auditor._http_request = timestamp_change
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertTrue(auditor.findings[0]["evidence"]["rollback_verified"])
        auditor.readback_config["PATCH /users/{user_id}"]["ignore_readback_paths"] = ["role"]
        previous_writes = len(writes)
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(len(writes), previous_writes)
        self.assertEqual(auditor.results[-1]["verdict"], "INCONCLUSIVE")

    def test_uncovered_configured_field_prevents_secure_result(self):
        state = {"display_name": "ORIGINAL", "role": "user", "isAdmin": False}
        auditor, ep, writes = self.make_auditor(state, field_map={"role": "role", "isAdmin": "isAdmin"})
        auditor._http_request = lambda *args, **kwargs: HTTPResult(200, '{"ok":true}')
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(auditor.results[0]["verdict"], "INCONCLUSIVE")
        self.assertIn("isAdmin", auditor.results[0]["reason"])

    def test_real_generator_probes_readonly_admin_after_writable_status_is_ignored(self):
        state = {"status": "disabled", "isAdmin": False}
        auditor, ep, writes = self.make_auditor(state, field_map={"status": "status", "isAdmin": "isAdmin"})
        del auditor._normalise_mutation_cases
        ep["request_schema"] = {
            "type": "object", "properties": {
                "status": {"type": "string", "enum": ["active", "disabled"]},
                "isAdmin": {"type": "boolean", "readOnly": True},
            },
        }

        def only_readonly_field_is_vulnerable(method, url, data=None, **kwargs):
            writes.append(copy.deepcopy(data))
            if "isAdmin" in data:
                state["isAdmin"] = data["isAdmin"]
            return HTTPResult(200, '{"ok":true}')

        auditor._http_request = only_readonly_field_is_vulnerable
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(auditor.results[0]["verdict"], "CONFIRMED")
        self.assertEqual(auditor.findings[0]["evidence"]["field"], "isAdmin")
        self.assertEqual(state, {"status": "disabled", "isAdmin": False})

    def test_merge_patch_content_type_is_propagated_to_mutation_and_restore(self):
        state = {"display_name": "ORIGINAL", "role": "user"}
        auditor, ep, writes = self.make_auditor(state, content_type="application/merge-patch+json")
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(len(writes), 2)
        self.assertTrue(all(w[2]["content_type"] == "application/merge-patch+json" for w in writes))

    def test_json_patch_and_unknown_vendor_bodies_are_not_sent(self):
        for media in ("application/json-patch+json", "application/custom+json"):
            with self.subTest(media=media):
                auditor, ep, writes = self.make_auditor({"role": "user"}, content_type=media)
                auditor.audit_endpoint_mass_assignment(ep, [ep])
                self.assertEqual(writes, [])
                self.assertEqual(auditor.results[0]["verdict"], "SKIPPED")

    def test_allowlist_preserves_case_sensitive_path(self):
        auditor, ep, writes = self.make_auditor({"role": "user"})
        ep["path"] = "/Users/{user_id}"
        auditor.audit_endpoint_mass_assignment(ep, [ep])
        self.assertEqual(writes, [])
        self.assertEqual(auditor.results[0]["verdict"], "SKIPPED")


class IdentityTransportHardeningTests(unittest.TestCase):
    def test_token_vs_header_alias_and_trace_headers_do_not_create_distinct_identities(self):
        identities = {
            "owner": {"id": "1", "token": "Bearer SAME", "headers": {"X-Trace": "a"}},
            "visitor": {"id": "2", "headers": {"authorization": "bearer SAME", "X-Trace": "b"}},
            "anonymous": {},
        }
        with self.assertRaises(ValueError):
            APISentinelAuditor(str(ROOT / "openapi.json"), "http://127.0.0.1", identities_config=identities)

    def test_only_non_auth_headers_are_not_valid_credentials(self):
        with self.assertRaises(ValueError):
            APISentinelAuditor(str(ROOT / "openapi.json"), "http://127.0.0.1", identities_config={
                "owner": {"headers": {"X-Trace": "a"}},
                "visitor": {"headers": {"X-Trace": "b"}}, "anonymous": {},
            })

    def test_custom_auth_header_can_be_explicitly_declared(self):
        auditor = APISentinelAuditor(str(ROOT / "openapi.json"), "http://127.0.0.1", identities_config={
            "owner": {"headers": {"X-Session": "a"}, "auth_header_names": ["X-Session"]},
            "visitor": {"headers": {"x-session": "b"}}, "anonymous": {},
        })
        self.assertEqual(auditor._identity_headers("visitor")["x-session"], "b")

    def test_unsupported_charset_is_transport_error_not_uncaught_exception(self):
        class Response:
            status = 200
            headers = Message()

            def read(self, size):
                return b'{"role":"admin"}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        Response.headers["Content-Type"] = "application/json; charset=unsupported-encoding"
        auditor = APISentinelAuditor(str(ROOT / "openapi.json"), "http://127.0.0.1", request_delay=0)
        with patch.object(auditor._opener, "open", return_value=Response()):
            result = auditor._http_request("PATCH", "http://127.0.0.1/users/2", {"role": "admin"}, "visitor")
        self.assertEqual(result.status, 0)
        self.assertIn("LookupError", result.error)

    def test_full_result_pipeline_redacts_urls_and_errors(self):
        auditor = APISentinelAuditor(str(ROOT / "openapi.json"), "http://127.0.0.1", request_delay=0)
        ep = {"method": "GET", "path": "/users/{id}", "parameters": []}
        response = HTTPResult(0, "password=RAW_SECRET", error="failed https://host/x?access_token=QUERY_SECRET")
        with patch.object(auditor, "_http_request", return_value=response):
            auditor.audit_endpoint_bola(ep)
        rendered = json.dumps(auditor.results)
        self.assertNotIn("RAW_SECRET", rendered)
        self.assertNotIn("QUERY_SECRET", rendered)
        self.assertEqual(auditor.results[0]["verdict"], "ERROR")


class CliHardeningTests(unittest.TestCase):
    def invoke_spec(self, paths, flags):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            spec = folder / "spec.json"
            spec.write_text(json.dumps({"openapi": "3.0.3", "paths": paths}), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                return main(["--spec", str(spec), "--output", str(folder / "report.html"), *flags])

    def test_empty_spec_cannot_pass_fail_on_error(self):
        self.assertEqual(self.invoke_spec({}, ["--fail-on-vuln", "--fail-on-error"]), 2)

    def test_all_unsupported_operations_cannot_pass_fail_on_error(self):
        self.assertEqual(self.invoke_spec({"/users": {"post": {"responses": {}}}}, ["--fail-on-error"]), 2)

    def test_minimum_conclusive_coverage_is_enforced_independently(self):
        self.assertEqual(self.invoke_spec({}, ["--min-coverage", "1"]), 2)

    def test_dry_run_never_opens_target_connection(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self.invoke_spec({"/users/{id}": {"get": {}}}, ["--dry-run"]), 0)

    def test_cli_allowlist_replaces_configured_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.json"
            config.write_text(json.dumps({
                "write_allowlist": ["PATCH /broad"],
                "readbacks": {"PATCH /narrow": {
                    "method": "GET", "path": "/narrow", "field_map": {"role": "role"},
                }},
            }), encoding="utf-8")
            with patch("api_sentinel.APISentinelAuditor") as auditor, redirect_stdout(io.StringIO()):
                auditor.return_value.build_plan.return_value = {"mode": "DRY_RUN"}
                code = main(["--spec", str(ROOT / "openapi.json"), "--config", str(config),
                             "--dry-run", "--write-endpoint", "PATCH /narrow"])
                self.assertEqual(code, 0)
                self.assertEqual(auditor.call_args.kwargs["write_allowlist"], ["PATCH /narrow"])

    def test_invalid_nan_options_return_error(self):
        self.assertEqual(self.invoke_spec({}, ["--min-coverage", "nan"]), 2)


if __name__ == "__main__":
    unittest.main()
