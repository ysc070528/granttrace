"""Offline configuration drafts remain blocked until reviewed and completed."""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from api_sentinel import main
from core.config_scaffold import DRAFT_KEY, INPUT_PREFIX, _parameter_notes, build_config_scaffold, config_needs_input
from core.config_validator import ConfigValidator


class ConfigScaffoldTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.spec = self.folder / "api.json"
        self.output = self.folder / "config.json"
        self.checklist = self.folder / "config.checklist.json"
        self.spec_data = {
            "openapi": "3.0.3",
            "components": {
                "securitySchemes": {"access": {"type": "apiKey", "in": "header", "name": "X-Access"}},
                "parameters": {"id": {"name": "id", "in": "path", "required": True,
                                      "schema": {"type": "integer", "example": 987654321}}},
            },
            "paths": {
                "/items/{id}": {
                    "parameters": [{"$ref": "#/components/parameters/id"}],
                    "get": {"parameters": [
                        {"name": "labels", "in": "query", "required": True,
                         "style": "form", "explode": False, "schema": {"type": "array", "items": {"type": "string"}}},
                        {"name": "view", "in": "query", "schema": {"type": "string", "default": "secret-default"}},
                    ]},
                    "patch": {"requestBody": {"content": {"application/json": {"schema": {
                        "type": "object", "properties": {"role": {"type": "string"}},
                    }}}}},
                    "delete": {},
                },
                "/shared": {"get": {"parameters": [{"name": "X-Account", "in": "header", "required": True,
                                                        "schema": {"type": "string"}}]}},
            },
        }
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")

    def call_cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("socket.socket", side_effect=AssertionError("Network socket opened")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("Network request sent")), \
             patch("api_sentinel.APISentinelAuditor", side_effect=AssertionError("Auditor constructed")), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def init_args(self, spec=None):
        return ["--spec", str(spec or self.spec), "--init-config", str(self.output)]

    def test_generates_no_requests_and_keeps_write_scope_empty(self):
        code, out, error = self.call_cli(self.init_args())
        self.assertEqual(code, 0, error)
        self.assertIn("Needs user input", out)
        draft = json.loads(self.output.read_text(encoding="utf-8"))
        checklist = json.loads(self.checklist.read_text(encoding="utf-8"))
        self.assertEqual(draft[DRAFT_KEY]["status"], "needs_user_input")
        self.assertEqual(draft["write_allowlist"], [])
        self.assertEqual(draft["bola"], {})
        self.assertEqual(draft["identities"]["owner"]["token"], None)
        self.assertEqual(draft["identities"]["anonymous"]["headers"], {})
        self.assertTrue(config_needs_input(draft))
        self.assertFalse(ConfigValidator.validate(draft, self.spec_data).is_valid)
        self.assertTrue(checklist["offline"])
        self.assertEqual(checklist["status"], "needs_user_input")
        self.assertIn("X-Access", json.dumps(checklist))

    def test_required_resources_and_resolved_metadata_are_listed_without_example_ids(self):
        draft, checklist = build_config_scaffold(str(self.spec))
        values = draft["parameter_values"]["GET /items/{id}"]
        for identity in ("owner", "visitor"):
            self.assertEqual(set(values[identity]), {"id", "labels"})
            self.assertTrue(values[identity]["id"].startswith(INPUT_PREFIX))
        self.assertNotIn("secret-default", json.dumps((draft, checklist)))
        self.assertNotIn("987654321", json.dumps((draft, checklist)))
        operation = next(item for item in checklist["operations"] if item["operation"] == "GET /items/{id}")
        labels = next(p for p in operation["parameters"] if p["name"] == "labels")
        self.assertEqual(labels["style"], "form")
        self.assertFalse(labels["explode"])
        self.assertEqual(labels["type"], "array")

    def test_patch_readback_candidates_require_manual_verification(self):
        draft, checklist = build_config_scaffold(str(self.spec))
        mapping = draft["readbacks"]["PATCH /items/{id}"]
        self.assertTrue(mapping["path"].startswith(INPUT_PREFIX))
        self.assertTrue(mapping["consistency"].startswith(INPUT_PREFIX))
        self.assertEqual(mapping["field_map"], {})
        operation = next(item for item in checklist["operations"] if item["operation"] == "PATCH /items/{id}")
        self.assertEqual(operation["readback_review"]["candidate_get_paths"], ["/items/{id}"])
        self.assertEqual(operation["readback_review"]["candidate_written_fields"], ["role"])
        self.assertTrue(any("strong consistency" in text for text in checklist["limitations"]))

    def test_unsupported_parameters_and_methods_are_explicit(self):
        draft, checklist = build_config_scaffold(str(self.spec))
        header_operation = next(item for item in checklist["operations"] if item["operation"] == "GET /shared")
        header = header_operation["parameters"][0]
        # A required GET business header is drafted for every requesting identity.
        self.assertTrue(header["included_in_config"])
        self.assertNotIn("unsupported", header["needs_review"])
        for identity in ("owner", "visitor", "anonymous"):
            value = draft["parameter_values"]["GET /shared"][identity]["X-Account"]
            self.assertTrue(value.startswith(INPUT_PREFIX))
        # Other methods still cannot send them.
        write_header = _parameter_notes({"method": "PATCH", "path": "/x", "parameters": [
            {"name": "X-Account", "in": "header", "required": True, "schema": {"type": "string"}}]})[0]
        self.assertIn("only for GET", write_header["needs_review"])
        delete_operation = next(item for item in checklist["operations"] if item["operation"].startswith("DELETE"))
        self.assertFalse(delete_operation["scan_supported"])
        self.assertTrue(delete_operation["parameters"])
        self.assertFalse(any(item["included_in_config"] for item in delete_operation["parameters"]))
        self.assertNotIn("DELETE /items/{id}", draft["parameter_values"])

    def test_marker_blocks_validation_dry_run_and_scan_before_auditor_creation(self):
        self.assertEqual(self.call_cli(self.init_args())[0], 0)
        for mode in (["--validate-config"], ["--dry-run"], []):
            with self.subTest(mode=mode):
                code, _, error = self.call_cli([*mode, "--config", str(self.output), "--spec", str(self.spec)])
                self.assertEqual(code, 2)
                self.assertIn("draft needs user input", error)

    def test_unresolved_parameter_still_blocks_when_marker_is_removed_and_auth_is_filled(self):
        draft, _ = build_config_scaffold(str(self.spec))
        del draft[DRAFT_KEY]
        draft["readbacks"] = {}
        for identity in ("owner", "visitor"):
            draft["identities"][identity].update({"id": identity, "token": "Bearer " + identity + "-key"})
        self.output.write_text(json.dumps(draft), encoding="utf-8")
        for mode in (["--validate-config"], ["--dry-run"], []):
            code, _, error = self.call_cli([*mode, "--config", str(self.output), "--spec", str(self.spec)])
            self.assertEqual(code, 2)
            self.assertIn("draft needs user input", error)
            self.assertNotIn("owner-key", error)

    def test_existing_config_or_checklist_is_never_overwritten(self):
        for destination in (self.output, self.checklist):
            with self.subTest(destination=destination):
                destination.write_text("original", encoding="utf-8")
                code, _, error = self.call_cli(self.init_args())
                self.assertEqual(code, 2)
                self.assertIn("Refusing to overwrite", error)
                self.assertEqual(destination.read_text(encoding="utf-8"), "original")
                peer = self.checklist if destination == self.output else self.output
                self.assertFalse(peer.exists())
                destination.unlink()

    def test_invalid_spec_creates_no_output(self):
        for spec_text in ("[]", "{bad", json.dumps({"openapi": "3.0.3", "paths": {
            "/items": {"get": {"parameters": [{"$ref": "https://example.invalid/params.json"}]}}
        }})):
            with self.subTest(spec_text=spec_text):
                self.spec.write_text(spec_text, encoding="utf-8")
                self.assertEqual(self.call_cli(self.init_args())[0], 2)
                self.assertFalse(self.output.exists())
                self.assertFalse(self.checklist.exists())

    def test_conflicting_modes_are_rejected_without_creating_files(self):
        for extra in (["--dry-run"], ["--validate-config"], ["--allow-write-tests"],
                      ["--write-endpoint", "PATCH /items/{id}"], ["--config", "existing.json"]):
            with self.subTest(extra=extra):
                code, _, error = self.call_cli([*self.init_args(), *extra])
                self.assertEqual(code, 2)
                self.assertIn("cannot be combined", error)
                self.assertFalse(self.output.exists())

    def test_missing_template_parameter_is_an_explicit_input(self):
        self.spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {"/lost/{resource}": {"get": {}}}}),
                             encoding="utf-8")
        draft, checklist = build_config_scaffold(str(self.spec))
        self.assertIn("resource", draft["parameter_values"]["GET /lost/{resource}"]["owner"])
        self.assertIn("Missing OpenAPI", checklist["operations"][0]["parameters"][0]["needs_review"])

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML is optional")
    def test_yaml_and_json_produce_equivalent_scaffolds(self):
        import yaml
        yaml_spec = self.folder / "api.yaml"
        yaml_spec.write_text(yaml.safe_dump(self.spec_data, sort_keys=False), encoding="utf-8")
        self.assertEqual(build_config_scaffold(str(self.spec)), build_config_scaffold(str(yaml_spec)))
        code, _, error = self.call_cli(self.init_args(yaml_spec))
        self.assertEqual(code, 0, error)

    def test_placeholder_detection_handles_deep_mappings_without_recursion(self):
        config = {}
        cursor = config
        for _ in range(2000):
            cursor["nested"] = {}
            cursor = cursor["nested"]
        cursor["resource"] = INPUT_PREFIX + "resource"
        self.assertTrue(config_needs_input(config))
        self.assertFalse(config_needs_input({"identities": {"owner": {"token": "Bearer owner"}}}))


class HeaderCookieAndPutDraftTests(unittest.TestCase):
    """Required GET header/cookie values and PUT readbacks are drafted, never guessed."""

    GET = "GET /orders/{order_id}"
    PUT = "PUT /orders/{order_id}"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.spec = self.folder / "api.json"
        self.spec_data = {
            "openapi": "3.0.3",
            "components": {"securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"},
                "sessionCookie": {"type": "apiKey", "in": "cookie", "name": "app_session"},
                "partnerKey": {"type": "apiKey", "in": "header", "name": "X-Partner"},
            }},
            "security": [{"bearer": []}],
            "paths": {"/orders/{order_id}": {
                "get": {"parameters": [
                    {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "X-Tenant", "in": "header", "required": True,
                     "schema": {"type": "string", "example": "tenant-from-spec"}},
                    {"name": "region", "in": "cookie", "required": True,
                     "schema": {"type": "string", "default": "region-from-spec"}},
                    {"name": "X-Trace", "in": "header", "schema": {"type": "string"}},
                    {"name": "Accept", "in": "header", "required": True, "schema": {"type": "string"}},
                    {"name": "X-Api-Key", "in": "header", "required": True, "schema": {"type": "string"}},
                    {"name": "X-Partner", "in": "header", "required": True, "schema": {"type": "string"}},
                    {"name": "app_session", "in": "cookie", "required": True, "schema": {"type": "string"}},
                    {"name": "remember_login", "in": "cookie", "schema": {"type": "string"}},
                    {"name": "prefs", "in": "cookie", "required": True,
                     "schema": {"type": "array", "items": {"type": "string"}}},
                ]},
                "put": {
                    "parameters": [{"name": "order_id", "in": "path", "required": True,
                                    "schema": {"type": "integer"}}],
                    "requestBody": {"content": {"application/json": {"schema": {
                        "type": "object", "properties": {"status": {"type": "string"}, "note": {"type": "string"}},
                    }}}},
                },
            }},
        }
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")
        self.draft, self.checklist = build_config_scaffold(str(self.spec))

    def operation(self, key):
        return next(item for item in self.checklist["operations"] if item["operation"] == key)

    def parameter(self, key, name):
        return next(item for item in self.operation(key)["parameters"] if item["name"] == name)

    def test_required_get_business_headers_and_cookies_are_drafted_for_each_requester(self):
        values = self.draft["parameter_values"][self.GET]
        for identity in ("owner", "visitor", "anonymous"):
            for name in ("X-Tenant", "region"):
                self.assertTrue(values[identity][name].startswith(INPUT_PREFIX), (identity, name))
        # Resource parameters stay with the resource identities only.
        self.assertIn("order_id", values["owner"])
        self.assertNotIn("order_id", values["anonymous"])
        self.assertNotIn("common", values)
        for name in ("X-Tenant", "region"):
            item = self.parameter(self.GET, name)
            self.assertTrue(item["included_in_config"])
            self.assertEqual(item["status"], "needs_user_input")
            self.assertEqual(item["config_paths"], [
                f"parameter_values.{self.GET}.{identity}.{name}" for identity in ("owner", "visitor", "anonymous")
            ])
            self.assertIn("common", item["needs_review"])
        text = json.dumps((self.draft, self.checklist))
        self.assertNotIn("tenant-from-spec", text)
        self.assertNotIn("region-from-spec", text)

    def test_header_and_cookie_parameters_that_are_not_drafted_say_why(self):
        reasons = {
            "X-Trace": "Optional: not drafted",
            "Accept": "ignores",
            "remember_login": "Optional authentication cookie",
            "prefs": "not supported",
        }
        drafted = json.dumps(self.draft["parameter_values"])
        for name, reason in reasons.items():
            with self.subTest(name=name):
                item = self.parameter(self.GET, name)
                self.assertFalse(item["included_in_config"])
                self.assertIn(reason, item["needs_review"])
                self.assertNotIn(f'"{name}"', drafted)

    def test_authentication_headers_and_cookies_are_drafted_per_identity_not_per_request(self):
        identities = self.draft["identities"]
        drafted = json.dumps(self.draft["parameter_values"])
        for name, section in (("X-Api-Key", "headers"), ("X-Partner", "headers"), ("app_session", "parameters")):
            with self.subTest(name=name):
                for identity in ("owner", "visitor"):
                    self.assertTrue(identities[identity][section][name].startswith(INPUT_PREFIX))
                self.assertNotIn(name, identities["anonymous"][section])
                self.assertNotIn(f'"{name}"', drafted)
                item = self.parameter(self.GET, name)
                self.assertTrue(item["included_in_config"])
                self.assertEqual(item["config_paths"], [
                    f"identities.{identity}.{section}.{name}" for identity in ("owner", "visitor")])
                self.assertIn("identities.*." + section, item["needs_review"])
        self.assertIn("differ between owner and visitor", self.parameter(self.GET, "app_session")["needs_review"])

    def test_identity_values_shared_by_operations_are_drafted_once(self):
        self.spec_data["paths"]["/invoices"] = {"get": {"parameters": [
            {"name": "x-api-key", "in": "header", "required": True, "schema": {"type": "string"}},
            {"name": "app_session", "in": "cookie", "required": True, "schema": {"type": "string"}},
        ]}}
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")
        draft, checklist = build_config_scaffold(str(self.spec))
        for identity in ("owner", "visitor"):
            self.assertEqual([key for key in draft["identities"][identity]["headers"]
                              if key.lower() == "x-api-key"], ["X-Api-Key"])
            self.assertEqual(list(draft["identities"][identity]["parameters"]), ["app_session"])
        operation = next(item for item in checklist["operations"] if item["operation"] == "GET /invoices")
        header = next(item for item in operation["parameters"] if item["name"] == "x-api-key")
        self.assertEqual(header["config_paths"], [
            "identities.owner.headers.X-Api-Key", "identities.visitor.headers.X-Api-Key"])

    def test_unresolvable_security_schemes_draft_no_header_or_cookie_values(self):
        with patch("core.config_scaffold.OpenAPIParser.get_security_schemes",
                   side_effect=ValueError("bad schemes")):
            draft, checklist = build_config_scaffold(str(self.spec))
        values = draft["parameter_values"][self.GET]
        self.assertEqual(set(values), {"owner", "visitor"})
        operation = next(item for item in checklist["operations"] if item["operation"] == self.GET)
        tenant = next(item for item in operation["parameters"] if item["name"] == "X-Tenant")
        self.assertFalse(tenant["included_in_config"])
        self.assertIn("security schemes", tenant["needs_review"])

    def test_put_operations_get_parameter_and_readback_drafts(self):
        operation = self.operation(self.PUT)
        self.assertTrue(operation["scan_supported"])
        values = self.draft["parameter_values"][self.PUT]
        for identity in ("owner", "visitor"):
            self.assertTrue(values[identity]["order_id"].startswith(INPUT_PREFIX))
        mapping = self.draft["readbacks"][self.PUT]
        self.assertEqual(mapping["method"], "GET")
        self.assertTrue(mapping["path"].startswith(INPUT_PREFIX))
        self.assertTrue(mapping["consistency"].startswith(INPUT_PREFIX))
        self.assertEqual(mapping["field_map"], {})
        review = operation["readback_review"]
        self.assertEqual(review["candidate_get_paths"], ["/orders/{order_id}"])
        self.assertEqual(review["candidate_written_fields"], ["note", "status"])
        self.assertIn("complete root document", review["instruction"])
        self.assertIn("same path", review["instruction"])
        self.assertEqual(self.draft["write_allowlist"], [])

    def test_parameters_marked_as_included_are_in_the_draft(self):
        for operation in self.checklist["operations"]:
            for item in operation["parameters"]:
                if not item["included_in_config"]:
                    continue
                with self.subTest(operation=operation["operation"], name=item["name"]):
                    self.assertTrue(item.get("config_paths"))
                    for path in item["config_paths"]:
                        if path.startswith("identities."):
                            _, identity, section, name = path.split(".", 3)
                            container = self.draft["identities"][identity][section]
                        else:
                            prefix = "parameter_values." + operation["operation"] + "."
                            self.assertTrue(path.startswith(prefix), path)
                            identity, name = path[len(prefix):].split(".", 1)
                            container = self.draft["parameter_values"][operation["operation"]][identity]
                        self.assertTrue(container[name].startswith(INPUT_PREFIX), path)

    def test_completed_draft_validates_and_plans_without_missing_parameters(self):
        # Without the unsupported cookie array, every value the GET needs is drafted.
        operation = self.spec_data["paths"]["/orders/{order_id}"]["get"]
        operation["parameters"] = [item for item in operation["parameters"] if item["name"] != "prefs"]
        self.spec.write_text(json.dumps(self.spec_data), encoding="utf-8")
        draft, _ = build_config_scaffold(str(self.spec))
        del draft[DRAFT_KEY]
        for identity, number in (("owner", "1001"), ("visitor", "1002")):
            draft["identities"][identity].update({"id": number, "token": f"Bearer {identity}-test-credential"})
            draft["identities"][identity]["headers"].update(
                {"X-Api-Key": f"{identity}-api-key", "X-Partner": f"{identity}-partner-key"})
            draft["identities"][identity]["parameters"]["app_session"] = f"{identity}-session"
        for identity in ("owner", "visitor", "anonymous"):
            draft["parameter_values"][self.GET][identity].update({"X-Tenant": "tenant-a", "region": "eu"})
        for operation, ids in ((self.GET, (11, 22)), (self.PUT, (11, 22))):
            draft["parameter_values"][operation]["owner"]["order_id"] = ids[0]
            draft["parameter_values"][operation]["visitor"]["order_id"] = ids[1]
        draft["readbacks"][self.PUT].update(
            {"path": "/orders/{order_id}", "consistency": "strong", "field_map": {"status": "status"}})
        self.assertFalse(config_needs_input(draft))
        config = self.folder / "config.json"
        config.write_text(json.dumps(draft), encoding="utf-8")
        plan_path = self.folder / "plan.json"
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("socket.socket", side_effect=AssertionError("Network socket opened")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("Network request sent")), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            validated = main(["--spec", str(self.spec), "--config", str(config), "--validate-config"])
            planned = main(["--spec", str(self.spec), "--config", str(config), "--dry-run",
                            "--export-json", str(plan_path)])
        self.assertEqual((validated, planned), (0, 0), stderr.getvalue())
        plan = {item["endpoint"]: item for item in json.loads(plan_path.read_text(encoding="utf-8"))["operations"]}
        self.assertNotIn("reason_category", plan[self.GET], plan[self.GET].get("reason"))
        self.assertEqual(plan[self.PUT]["readback_path"], "/orders/{order_id}")


if __name__ == "__main__":
    unittest.main()
