"""HTML escaping, offline copy behavior and real scan-to-report cURL boundaries."""

import io
import json
import shlex
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

import api_sentinel
from core import demo
from core.reporter import SecurityReportGenerator
from core.reproduction import CurlTemplate, build_reproduction_templates


class CurlReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.commands = []
        self.buttons = []
        self.scripts = []
        self.items = []
        self.attributes = []
        self.ancestors = []
        self.in_command = False
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.attributes.append(attrs)
        if "data-audit-item" in attrs:
            self.items.append({"auditItem": attrs["data-audit-item"],
                               "endpoint": attrs["data-endpoint"], "verdict": attrs["data-verdict"]})
        if "data-copy-curl" in attrs:
            self.buttons.append({"attributes": attrs, "ancestors": list(self.ancestors)})
        if tag == "pre" and "curl-template" in attrs.get("class", "").split():
            self.commands.append("")
            self.in_command = True
        if tag == "script":
            self.scripts.append("")
            self.in_script = True
        if tag not in {"meta", "input", "br", "hr", "img", "link"}:
            self.ancestors.append((tag, attrs))

    def handle_endtag(self, tag):
        if tag == "pre":
            self.in_command = False
        if tag == "script":
            self.in_script = False
        for index in range(len(self.ancestors) - 1, -1, -1):
            if self.ancestors[index][0] == tag:
                del self.ancestors[index:]
                break

    def handle_data(self, data):
        if self.in_command:
            self.commands[-1] += data
        if self.in_script:
            self.scripts[-1] += data


class CurlReportTests(unittest.TestCase):
    def finding(self, cwe="CWE-639", verdict="CONFIRMED"):
        return {"cwe": cwe, "verdict": verdict,
                "endpoint": "PATCH /api/users/{id}" if cwe == "CWE-915" else "GET /api/users/{id}",
                "injected_payload": {"role": "admin"},
                "evidence": {"target_url": "https://example.test/api/users/1001",
                             "request_content_type": "application/json"}}

    def render(self, findings=None, results=None, templates=None):
        findings = [self.finding()] if findings is None else findings
        if templates is None:
            templates = build_reproduction_templates(findings, {"Authorization": "Bearer NEVER_EXPORT_TOKEN"})
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            SecurityReportGenerator.generate({}, findings, "https://example.test", str(output),
                                             results=results or [], reproduction_templates=templates)
            text = output.read_text(encoding="utf-8")
        parser = CurlReportParser()
        parser.feed(text)
        return text, parser

    def test_confirmed_cards_render_native_keyboard_button_and_visible_template(self):
        text, parser = self.render(findings=[self.finding(), self.finding("CWE-915")])
        self.assertEqual(len(parser.buttons), 2)
        self.assertEqual(len(parser.commands), 2)
        self.assertIn("cURL 复现模板（请填入授权测试凭据）", text)
        self.assertIn("POSIX shell", text)
        for button in parser.buttons:
            self.assertEqual(button["attributes"]["type"], "button")
            self.assertTrue(any(tag == "article" for tag, _ in button["ancestors"]))
            self.assertTrue(any("reproduction" in attrs.get("class", "").split()
                                for _, attrs in button["ancestors"]))
        self.assertNotIn("NEVER_EXPORT_TOKEN", text)

    def test_nonconfirmed_findings_and_all_endpoint_rows_have_no_copy_button(self):
        verdicts = ("SECURE", "PUBLIC", "AUTHORIZED", "SUSPICIOUS", "INCONCLUSIVE", "SKIPPED", "ERROR")
        findings = [self.finding(verdict=verdict) for verdict in verdicts]
        results = [{"check": "BOLA", "endpoint": item["endpoint"], "verdict": item["verdict"]}
                   for item in findings]
        text, parser = self.render(findings, results)
        self.assertEqual(parser.buttons, [])
        self.assertEqual(parser.commands, [])
        self.assertNotIn("<pre class='curl-template'>", text)

    def test_confirmed_endpoint_result_does_not_duplicate_finding_button(self):
        finding = self.finding()
        _, parser = self.render([finding], [{"check": "BOLA", "endpoint": finding["endpoint"],
                                             "verdict": "CONFIRMED"}])
        self.assertEqual(len(parser.buttons), 1)
        self.assertTrue(all(tag != "tr" for tag, _ in parser.buttons[0]["ancestors"]))

    def test_missing_safe_target_or_malformed_operation_has_no_copy_ui(self):
        missing = self.finding()
        missing["evidence"].pop("target_url")
        malformed = self.finding()
        malformed["endpoint"] = "get /api/users/{id}"
        _, parser = self.render([missing, malformed])
        self.assertEqual(parser.buttons, [])
        self.assertEqual(parser.commands, [])

    def test_html_special_characters_are_escaped_and_dom_text_is_exact_command(self):
        finding = self.finding("CWE-915")
        finding["injected_payload"] = {"role": "admin <test> & \"quoted\" 'single'"}
        templates = build_reproduction_templates([finding], {"X-API-Key": "private-key"})
        text, parser = self.render([finding], templates=templates)
        self.assertEqual(parser.commands, [templates[0].command])
        self.assertIn("&lt;test&gt;", text)
        self.assertIn("&amp;", text)
        self.assertNotIn("admin <test>", text)
        self.assertEqual(json.loads(shlex.split(parser.commands[0])[-1]), finding["injected_payload"])

    def test_script_terminator_and_event_markup_cannot_escape_text_context(self):
        hostile = "</script><script>alert('XSS')</script><img src=x onerror=alert(1)>"
        finding = self.finding("CWE-915")
        finding["injected_payload"] = {"role": hostile}
        templates = build_reproduction_templates([finding], {"X-API-Key": "private-key"})
        text, parser = self.render([finding], templates=templates)
        self.assertEqual(len(parser.scripts), 1)
        self.assertEqual(parser.commands, [templates[0].command])
        self.assertNotIn(hostile, text)
        self.assertNotIn(hostile, parser.scripts[0])
        self.assertNotIn("alert('XSS')", parser.scripts[0])
        self.assertTrue(all(not any(name.lower().startswith("on") for name in attrs)
                            for attrs in parser.attributes))
        self.assertNotIn("innerHTML", parser.scripts[0])

    def test_command_does_not_enter_button_attribute_or_javascript_string(self):
        command = "curl --globoff -X GET 'https://example.test/UNIQUE_CURL_SENTINEL'"
        _, parser = self.render(templates={0: CurlTemplate(command, False, "")})
        self.assertEqual(parser.commands, [command])
        self.assertNotIn("UNIQUE_CURL_SENTINEL", "".join(parser.scripts))
        self.assertNotIn("UNIQUE_CURL_SENTINEL", json.dumps(parser.buttons[0]["attributes"]))
        self.assertIn("textContent", "".join(parser.scripts))

    def test_redacted_template_has_visible_completion_note(self):
        finding = self.finding()
        finding["evidence"]["target_url"] += "?token=private-query-secret"
        text, parser = self.render([finding])
        self.assertIn("部分值已脱敏，请补全测试值", text)
        self.assertNotIn("private-query-secret", "".join(parser.commands))

    def test_existing_callers_without_safe_metadata_remain_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            SecurityReportGenerator.generate({}, [self.finding()], "https://example.test", str(output))
            text = output.read_text(encoding="utf-8")
        parser = CurlReportParser()
        parser.feed(text)
        self.assertEqual(parser.buttons, [])
        self.assertEqual(parser.commands, [])

    def test_stale_metadata_cannot_add_template_to_explicit_nonconfirmed_finding(self):
        _, parser = self.render([self.finding(verdict="SECURE")],
                                templates={0: CurlTemplate("curl --globoff -X GET https://example.test", False, "")})
        self.assertEqual(parser.buttons, [])
        self.assertEqual(parser.commands, [])

    def test_without_javascript_full_command_remains_manual_copyable_text(self):
        text, parser = self.render()
        self.assertIn("<noscript>", text)
        self.assertEqual(len(parser.commands), 1)
        self.assertIn("Authorization: Bearer <VISITOR_TOKEN>", parser.commands[0])
        self.assertIn("https://example.test/api/users/1001", parser.commands[0])
        self.assertTrue(all("hidden" not in attrs for attrs in parser.attributes
                            if "curl-template" in attrs.get("class", "").split()))

    @unittest.skipUnless(shutil.which("node"), "Node.js is optional for executing offline HTML interactions")
    def test_real_copy_script_success_fallback_failures_cleanup_reset_and_filters(self):
        finding = self.finding()
        results = [{"endpoint": "GET /api/users/{id}", "check": "BOLA", "verdict": "CONFIRMED"},
                   {"endpoint": "GET /api/teams/{id}", "check": "BOLA", "verdict": "SECURE"}]
        _, parser = self.render([finding], results)
        self.assertEqual(len(parser.scripts), 1)
        harness = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const script = REPORT_SCRIPT;
const command = REPORT_COMMAND;
const datasets = REPORT_ITEMS;
async function exercise(clipboardMode, fallbackMode, expected, keyboardFocus = false, repeat = false) {
  const clipboardCalls = [], children = [], selections = [], removed = [], timers = new Map();
  let fallbackCalls = 0, restoredFocus = 0, buttonFocus = 0, nextTimer = 0;
  const originalFocus = {focus() { restoredFocus++; }};
  const button = {textContent: '复制 cURL', disabled: false, handlers: {},
    focus() { buttonFocus++; document.activeElement = this; },
    parentElement: {querySelector(selector) { assert.equal(selector, '.curl-template'); return {textContent: command}; }},
    addEventListener(event, callback) { this.handlers[event] = callback; }};
  const controls = {};
  for (const id of ['endpoint-search', 'verdict-filter', 'filter-count', 'no-matching-results', 'no-matching-findings']) {
    controls[id] = {value: '', hidden: false, textContent: '', handlers: {},
      addEventListener(event, callback) { this.handlers[event] = callback; }};
  }
  const items = datasets.map(dataset => ({dataset, hidden: false}));
  const body = {appendChild(element) { children.push(element); element.parentNode = body; },
    removeChild(element) { assert.equal(children.pop(), element); removed.push(element); element.parentNode = null; }};
  const document = {body, activeElement: keyboardFocus ? button : originalFocus,
    getElementById: id => controls[id],
    querySelectorAll(selector) {
      if (selector === '[data-audit-item]') return items;
      if (selector === '[data-copy-curl]') return [button];
      throw new Error('Unexpected selector ' + selector);
    },
    createElement(tag) {
      assert.equal(tag, 'textarea');
      if (fallbackMode === 'create-throw') throw new Error('Cannot create textarea');
      return {value: '', style: {}, attrs: {}, parentNode: null,
        setAttribute(name, value) { this.attrs[name] = value; },
        focus() { document.activeElement = this; },
        select() { selections.push(this.value); },
        setSelectionRange(start, end) { assert.equal(start, 0); assert.equal(end, command.length); }};
    }};
  if (fallbackMode !== 'absent') {
    document.execCommand = kind => {
      assert.equal(kind, 'copy'); fallbackCalls++;
      assert.equal(selections[selections.length - 1], command);
      if (fallbackMode === 'throw') throw new Error('Copy failed');
      return fallbackMode === 'true';
    };
  }
  const navigator = {};
  if (clipboardMode === 'getter-throw') Object.defineProperty(navigator, 'clipboard', {
    get() { throw new Error('Clipboard access is unavailable'); }});
  else if (!['absent', 'undefined'].includes(clipboardMode)) navigator.clipboard = {writeText(value) {
    clipboardCalls.push(value);
    if (clipboardMode === 'throw') throw new Error('Clipboard threw');
    return clipboardMode === 'reject' ? Promise.reject(new Error('Permission denied')) : Promise.resolve();
  }};
  const context = {document,
    setTimeout(callback, delay) { assert.equal(delay, 2500); const id = ++nextTimer; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); }};
  if (clipboardMode !== 'undefined') context.navigator = navigator;
  vm.runInNewContext(script, context);
  assert.equal(items.filter(item => !item.hidden).length, 3);
  await button.handlers.click();
  assert.equal(button.disabled, false);
  assert.equal(button.textContent, expected ? '已复制' : '复制失败，请手动选择');
  assert.deepEqual(clipboardCalls, ['absent', 'undefined', 'getter-throw'].includes(clipboardMode) ? [] : [command]);
  assert.equal(children.length, 0, 'Temporary textarea survived copy');
  if (clipboardMode === 'success') {
    assert.equal(fallbackCalls, 0); assert.equal(removed.length, 0);
  } else if (fallbackMode !== 'create-throw') {
    assert.equal(removed.length, 1);
    if (!keyboardFocus) assert.equal(restoredFocus, 1);
  }
  if (keyboardFocus) {
    assert.equal(document.activeElement, button);
    assert.ok(buttonFocus > 0, 'Keyboard copy button did not regain focus after enabling');
  }
  assert.equal(timers.size, 1);
  if (repeat) {
    await button.handlers.click();
    assert.equal(timers.size, 1, 'Repeated click did not clear the previous reset timer');
    assert.equal(button.textContent, expected ? '已复制' : '复制失败，请手动选择');
  }
  controls['endpoint-search'].value = '/TEAMS';
  controls['endpoint-search'].handlers.input();
  assert.equal(controls['filter-count'].textContent, '端点结果 1/2 条 · 确认漏洞 0/1 条');
  controls['verdict-filter'].value = 'CONFIRMED';
  controls['verdict-filter'].handlers.change();
  assert.equal(items.filter(item => !item.hidden).length, 0);
  assert.equal(controls['no-matching-results'].hidden, false);
  controls['endpoint-search'].value = '';
  controls['verdict-filter'].value = '';
  controls['verdict-filter'].handlers.change();
  assert.equal(items.filter(item => !item.hidden).length, 3);
  for (const callback of timers.values()) callback();
  assert.equal(button.textContent, '复制 cURL');
}
(async () => {
  await exercise('success', 'false', true);
  await exercise('reject', 'true', true);
  await exercise('throw', 'true', true);
  await exercise('absent', 'true', true);
  await exercise('reject', 'false', false);
  await exercise('absent', 'false', false);
  await exercise('absent', 'throw', false);
  await exercise('reject', 'absent', false);
  await exercise('absent', 'create-throw', false);
  await exercise('getter-throw', 'true', true);
  await exercise('undefined', 'true', true);
  await exercise('success', 'false', true, true, true);
  await exercise('absent', 'true', true, true);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
        harness = (harness.replace("REPORT_SCRIPT", json.dumps(parser.scripts[0]))
                   .replace("REPORT_COMMAND", json.dumps(parser.commands[0]))
                   .replace("REPORT_ITEMS", json.dumps(parser.items)))
        result = subprocess.run([shutil.which("node"), "-"], input=harness, capture_output=True,
                                text=True, encoding="utf-8", timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class CurlReportIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="granttrace-curl-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def read_html(self, path):
        parser = CurlReportParser()
        parser.feed(path.read_text(encoding="utf-8"))
        return parser

    def test_real_active_demo_builds_safe_metadata_before_reporter_and_restores_database(self):
        original = SecurityReportGenerator.generate
        with patch.object(demo.SecurityReportGenerator, "generate", wraps=original) as reporter, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = demo.run_demo(output_dir=str(self.directory))
        self.assertEqual(code, 0)
        metadata = reporter.call_args.kwargs["reproduction_templates"]
        self.assertEqual(len(metadata), 2)
        serialized = repr(metadata)
        self.assertNotIn("granttrace-demo-owner-1001", serialized)
        self.assertNotIn("granttrace-demo-visitor-1002", serialized)
        self.assertIn("<VISITOR_X_GRANTTRACE_DEMO_IDENTITY>", serialized)
        report_path = next(self.directory.rglob("granttrace_report.json"))
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["stats"]["bola_confirmed"], 1)
        self.assertEqual(payload["stats"]["mass_assignment_confirmed"], 1)
        for flag in ("rollback_verified", "database_restored", "server_stopped"):
            self.assertTrue(payload["demo"][flag])
        parser = self.read_html(report_path.with_suffix(".html"))
        self.assertEqual(len(parser.commands), 2)
        mass_args = next(shlex.split(command) for command in parser.commands if "--data" in shlex.split(command))
        self.assertEqual(json.loads(mass_args[mass_args.index("--data") + 1]), {"role": "admin"})

    def test_real_read_only_demo_emits_bola_template_and_sends_zero_patch(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = demo.run_demo(output_dir=str(self.directory), read_only=True)
        self.assertEqual(code, 0)
        report_path = next(self.directory.rglob("granttrace_report.json"))
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["demo"]["request_methods"], ["GET"])
        self.assertTrue(payload["demo"]["database_restored"])
        self.assertTrue(payload["demo"]["server_stopped"])
        self.assertEqual(len(self.read_html(report_path.with_suffix(".html")).commands), 1)

    def test_cli_sensitive_optin_keeps_all_template_authentication_values_placeholder(self):
        spec, config, database = demo.load_assets()
        credentials = ("OWNER_PRIVATE_AUTH", "VISITOR_PRIVATE_AUTH", "API_PRIVATE_KEY", "COOKIE_PRIVATE_SESSION")
        config["identities"]["owner"]["token"] = "Bearer " + credentials[0]
        config["identities"]["visitor"]["token"] = "Bearer " + credentials[1]
        config["identities"]["visitor"]["headers"].update({"X-API-Key": credentials[2],
                                                           "Cookie": "session=" + credentials[3]})
        spec_path, config_path = self.directory / "spec.json", self.directory / "config.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        output = self.directory / "report.html"
        exported = self.directory / "report.json"
        original = SecurityReportGenerator.generate
        with demo.DemoServer(database) as server, \
                patch.object(api_sentinel.SecurityReportGenerator, "generate", wraps=original) as reporter, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = api_sentinel.main([
                "--spec", str(spec_path), "--config", str(config_path), "--target", server.target,
                "--output", str(output), "--export-json", str(exported), "--allow-http", "--delay", "0",
                "--allow-write-tests", "--include-sensitive-evidence",
            ])
            self.assertEqual(code, 0)
            self.assertEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        metadata = reporter.call_args.kwargs["reproduction_templates"]
        self.assertEqual(len(metadata), 2)
        parser = self.read_html(output)
        self.assertEqual(len(parser.commands), 2)
        for secret in credentials:
            self.assertNotIn(secret, repr(metadata))
            self.assertNotIn(secret, "".join(parser.commands))
        for placeholder in ("<VISITOR_TOKEN>", "<VISITOR_X_API_KEY>", "<VISITOR_COOKIE>"):
            self.assertIn(placeholder, "".join(parser.commands))
        self.assertFalse(any("identity" in key.lower() or "header" in key.lower()
                             for key in reporter.call_args.kwargs))
        payload = json.loads(exported.read_text(encoding="utf-8"))
        self.assertEqual(payload["stats"]["bola_confirmed"], 1)
        self.assertEqual(payload["stats"]["mass_assignment_confirmed"], 1)
        self.assertTrue(next(item for item in payload["findings"] if item["cwe"] == "CWE-915")
                        ["evidence"]["rollback_verified"])

    def test_real_merge_patch_scan_records_actual_wire_content_type_and_reproduction(self):
        spec, config, database = demo.load_assets()
        for path in spec["paths"].values():
            if "patch" in path:
                request = path["patch"]["requestBody"]["content"]
                request["application/merge-patch+json"] = request.pop("application/json")
        spec_path = self.directory / "merge-patch-spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        recorded = []
        with demo.DemoServer(database) as server:
            original_patch = server.handler.do_PATCH

            def record_patch(handler):
                recorded.append(handler.headers["Content-Type"])
                return original_patch(handler)

            auditor = demo._LocalDemoAuditor(
                spec_path=str(spec_path), target_base_url=server.target,
                identities_config=config["identities"], parameter_values=config["parameter_values"],
                readback_config=config["readbacks"], write_allowlist=config["write_allowlist"],
                bola_config=config["bola"], allow_write_tests=True, request_delay=0,
            )
            with patch.object(server.handler, "do_PATCH", new=record_patch), redirect_stdout(io.StringIO()):
                auditor.run()
            self.assertTrue(recorded)
            self.assertEqual(set(recorded), {"application/merge-patch+json"})
            self.assertEqual(server.handler.DATABASE, server.handler.INITIAL_DATABASE)
        mass = next(item for item in auditor.findings if item["cwe"] == "CWE-915")
        self.assertEqual(mass["evidence"]["request_content_type"], "application/merge-patch+json")
        templates = build_reproduction_templates(auditor.findings, auditor.identities["visitor"]["headers"],
                                                  auditor._secret_values)
        template = templates[auditor.findings.index(mass)]
        args = shlex.split(template.command)
        self.assertIn("Content-Type: application/merge-patch+json", args)
        self.assertTrue(mass["evidence"]["rollback_verified"])
        self.assertEqual(auditor.stats["mass_assignment_confirmed"], 1)


if __name__ == "__main__":
    unittest.main()
