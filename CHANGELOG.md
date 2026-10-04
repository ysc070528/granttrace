# Changelog

## 2.5.1 - Unreleased

### Fixed

- Reject unsafe Merge Patch probes before writes when the original state cannot be restored exactly.
- Preserve array record associations during BOLA comparison to avoid overstating confirmed authorization bypasses.
- Harden report target/metadata redaction for known credentials and prevent report outputs from overwriting specification, configuration, or loaded local `$ref` inputs.
- Improve local and conditional schema resolution plus configuration-to-spec operation validation.
- Preserve legacy v2.5.0 scalar parameter configurations while applying strict schema-aware normalization and validation for canonical integer, number, and boolean values.

## 2.5.0 - 2026-10-04

### Added

- Export SARIF 2.1.0 with `--export-sarif`, alongside HTML and JSON reports.
  Only existing CONFIRMED findings produce results: BOLA / IDOR maps to
  `GT-BOLA-001` / `CWE-639`, and Mass Assignment to `GT-MASS-001` / `CWE-915`.
  A safely represented OpenAPI file inside the workspace supplies the artifact
  location for GitHub Code Scanning; no source lines or endpoint files are invented.
- Add safe cURL reproduction templates and copy buttons to confirmed HTML finding
  cards. Use the actual tested URL and confirmed injected payload where safe,
  Visitor credential placeholders, POSIX shell quoting and `curl --globoff`.
  Clipboard fallback supports offline reports; manual selection works without
  JavaScript. Real credentials never enter the templates, including when sensitive
  report evidence is enabled.
- Guide configuration onboarding from draft generation and manual review through
  validation, a local dry-run and a read-only first real scan. Distinguish
  config-only from spec-aware validation, summarize dry-run counts, and format
  next-step commands safely for POSIX shells or PowerShell.

### Changed

- Align README, configuration and advanced guidance with the first API onboarding
  flow and the SARIF / cURL outputs, without changing configuration formats.
- Explain validation scope, warnings and dry-run write eligibility more clearly.
  An active PATCH configuration is separate from enabling active execution;
  the recommended first real scan remains read-only.
- Promote the release source to `2.5.0` across package metadata, runtime version
  and generated examples; prepare the release checklist and OIDC workflow for
  the new tag without publishing it during release preparation.

### Security / Safety

- Preserve BOLA / IDOR verdicts and Mass Assignment detection criteria, default
  read-only auditing, and the existing TLS / HTTP / redirect / proxy boundaries.
- Active PATCH still requires explicit `--allow-write-tests`, an explicit write
  allowlist, independent GET readback, original-state snapshots, rollback and
  rollback verification. Failed recovery still halts further writes.
- SARIF, cURL templates and onboarding output do not expose real credentials;
  onboarding also omits configured resource values. Workspace-external specs
  never expose absolute local paths in SARIF.
- Validation and dry-run remain offline; dry-run sends zero requests. No active
  POST / PUT testing or automated OAuth / login is added.

### Quality

- Retain the 486-test baseline, Python 3.9 / 3.12 / 3.14 CI, blocking mypy and Ruff,
  Runtime dependency audit, CodeQL and the branch-aware coverage gate of 80%.
- Fresh release-prep acceptance passes all 486 tests with **82.78%** branch-aware
  local coverage, mypy reporting no issues in 18 source files, Ruff and the runtime
  dependency audit. All six bundled business scenarios match their expected
  outcomes; JSON / YAML scans restore the full mock database. A fresh wheel
  installed outside the checkout passes both demo modes and verifies version
  `2.5.0`, read-only 0 PATCH, active rollback and local server shutdown. See
  [VERIFICATION.md](VERIFICATION.md) for the exact scope and remote check results.

## 2.4.1 - 2026-10-03

### Added

- Add `granttrace demo` with packaged OpenAPI, configuration and fictional mock
  data, so an installed wheel can demonstrate identity comparison, BOLA / IDOR,
  Mass Assignment, independent readback and rollback verification outside a Git
  checkout without user credentials or external API access.
- Start the disposable mock on a dynamic loopback port, close it on completion
  or failure, and retain HTML / JSON reports in a unique output directory.
- Add `--output-dir` and optional `--read-only` controls for the built-in demo.

### Changed

- Put the single-command installed-package demo before the source-checkout
  walkthrough and retain configuration onboarding and safety boundaries. During
  release preparation, distinguish the upcoming package from the published stable
  version and do not claim an unpublished PyPI release is available.
- Give missing spec/config files and offline configuration failures a concise
  next step; an empty write allowlist still sends no PATCH requests.
- Promote the 2.4.1.dev0 development package to 2.4.1 consistently across runtime,
  package metadata and generated reports; update the release acceptance checklist.

### Quality

- Resolve the existing 20 mypy errors in six files using accurate annotations and
  type narrowing, without new suppression directives or weaker mypy settings.
- Make mypy a blocking CI check and add a minimum 80% branch-aware coverage gate.
- Add weekly Dependabot checks for pip dependencies and GitHub Actions, without
  automatic merging; exclude the release workflow from dependency updates.
- Verify installed demo resources, source-independent startup, both demo modes,
  complete database restoration and local server shutdown.

### Security / Safety

- The demo accepts no external target or user credentials. Its active PATCH checks
  run only against bundled, disposable data on a dynamic `127.0.0.1` server.
- Keep auditing users' own APIs read-only by default; `granttrace demo --read-only`
  sends no PATCH requests.
- Preserve the BOLA / IDOR and Mass Assignment detection criteria, explicit write
  allowlists, independent GET readback, original-state snapshots and rollback
  verification. Failed recovery still blocks subsequent writes.
- Keep the existing `granttrace --spec ...` CLI, TLS / HTTP / redirect / proxy
  safety boundaries and evidence minimisation unchanged.

## 2.4.0 - 2026-10-03

### Added

- Generate offline OpenAPI configuration drafts and missing-input checklists;
  reject unresolved drafts and refuse to overwrite existing files.
- Add offline HTML report search/status filters and compact severity labels.
- Support strict OpenAPI style/explode and Swagger collectionFormat parameter
  serialization in scans/readbacks, including arrays and lowercase booleans;
  decline unsupported or ambiguous formats before sending requests.
- Add explicit per-pair expected_visitor_access for legitimate sharing/admin
  reads, recorded as AUTHORIZED, and six local authorization truth fixtures with
  false-positive/false-negative accounting.
- Add mandatory Ruff checks, real unittest branch coverage with text/XML/JSON
  evidence, runtime dependency auditing with pip-audit, and a Python CodeQL
  workflow. Keep mypy advisory while recording existing type debt.
- Add simple issue templates and contribution guidance with private vulnerability
  reporting and reminders to exclude credentials and sensitive target data.

### Changed

- Promote the previously identified 2.4.0.dev0 development build to 2.4.0 across
  runtime, package metadata and reports; retain api_sentinel.py and
  APISentinelAuditor compatibility.
- Use granttrace_report.html when no output path is supplied and align package
  description, version status and GrantTrace branding.
- Keep a concise five-minute README walkthrough, add identity/readback/restoration
  highlights, and preserve the visible report preview and detailed guide links.
- Explain identity/resource access, changed fields, restoration and next steps
  before raw evidence. JSON report schema is version 2.
- Remove tests' dependence on untracked config.json; automate JSON/YAML mock
  restoration and clean wheel installation outside the checkout in CI.
- Maintain reproducible release verification and local-output ignore rules;
  remove an unused demo image while preserving the report preview.
- Include example configuration, guides and verification scripts in the source
  distribution so its documented local checks can be reproduced.

### Security / Safety

- Preserve default read-only auditing and explicit allowlisted JSON PATCH checks;
  active POST/PUT checks and automated authentication are not added.
- Preserve independent GET readback, original-state snapshots, finally-protected
  restoration and rollback verification. Failed recovery halts subsequent writes.
- Preserve TLS verification by default, explicit non-loopback HTTP opt-in and
  minimized/redacted evidence by default.
- Retain denial, anonymous-leak and invalid-baseline boundaries without changing
  the BOLA / IDOR or Mass Assignment detection criteria during release preparation.

Historical release tags and assets, including v2.3.1, remain unchanged.

## 2.3.1 - Verified authorization, snapshot and credential fixes

- Require trustworthy, clean anonymous rejection before a visitor-denial branch
  can produce endpoint-level SECURE; leaked business data remains suspicious.
- Reject non-standard JSON constants and overflowing floats in response parsing.
  Validate the original snapshot and finite request payloads before any PATCH;
  preserve recovery when a post-write readback is invalid.
- Redact component values from request Cookie headers, including names such as
  path/domain/secure/version, quoted/encoded echoes and known numeric credentials.
- Align readback parameter arrays, elements and override mappings between the
  editor schema, semantic validator and runtime.
- Load the same JSON/YAML specification authentication context in configuration
  validation and scanning; reject explicit invalid specifications cleanly.
- Validate the effective CLI write allowlist against its own readback mappings.
- Add 45 regression tests across four release modules; all 223 tests pass with
  real PyYAML installed. Repeat complete CLI mock audits for JSON and YAML and
  confirm full database restoration.
- Build/install the 2.3.1 wheel and smoke-test its installed console entry point;
  refresh sample reports and record current verification separately from history.

## 2.3.0 (v2.3.0-final) - Configuration validation, authoritative identity rules, and release hardening

- **Authoritative Configuration Validator (`core/config_validator.py`)**:
  - Implemented offline semantic validation engine for `config.json` without external network requests.
  - Added `--validate-config` CLI flag for pre-flight validation (exit code 0 for valid, 2 for invalid), without target-network requests or state-changing target actions.
  - Normal CLI scanning automatically runs the authoritative preflight check, rejecting invalid configurations before creating the auditor or sending any HTTP requests.
  - Enforced single canonical format for operation keys (`<METHOD> /<path>` with strictly single space), consistent case handling, and spelling error suggestions (Levenshtein distance).
  - Implemented symmetric two-way path collision detection (`paths_collide`) between `ignore_readback_paths` and written/readback paths across both validator and transaction rollback.
  - Unified authentication header recognition rules between Validator and Auditor, standardizing `session`, `credential`, custom `auth_header_names`, and OpenAPI-declared security schemes.

- **Schema and Exemplary Assets**:
  - Added standard `config.schema.json` (JSON Schema Draft-07) for editor autocomplete, hover documentation, and structural validation.
  - Added comprehensive `config.example.json` with `$schema` linkage, sample identities, readbacks, and BOLA policies.

- **Security and Robustness Hardening**:
  - Bound recursion depth (`MAX_RECURSION_DEPTH = 15`) and explicitly reject non-standard JSON numeric values (`NaN`, `Infinity`).
  - Strict credential sanitization across all diagnostic outputs (`Actual`, `Expected`, errors) and stripped CR/LF/control characters to mitigate known log-injection paths.

- **Core Detection Behavior Compatibility**:
  - No intentional behavior changes were made to BOLA decisions, snapshot recovery, diff, generator, or parser logic in this release; all existing regression tests continue to pass.

- **Test Suite Expansion**:
  - Total automated tests expanded from 118 to 178 (all 178 passing, 0 failures, 0 errors).
  - Added 22 offline configuration validation tests (`tests/test_config_validation.py`).
  - Added 20 security and sanitization tests (`tests/test_rc2_security_hardening.py`).
  - Added 18 strict regression counterexample tests (`tests/test_rc3_hardening.py`).

- **Packaging Hygiene and Metadata**:
  - Standardized Python package version in `pyproject.toml` to PEP 440 compliant `2.3.0`, with GitHub / ZIP delivery tag designated as `v2.3.0-final`.
  - Purged all build artifacts, temporary test reports (`API_Security_Report.html`, `result.json`), and caches (`__pycache__`, `*.pyc`, `.pytest_cache`, `.git`) from the distribution archive.

## 2.2.0 - Regression-driven safety fixes

- Snapshot/recover complete written fields, objects and arrays using original
  business values; compare the full readback state, including derived changes.
- Recover after mutation/readback exceptions, guard recovery's own exceptions,
  and stop later writes on failed verification or asynchronous acceptance.
- Require configured strong readback consistency for unchanged-write SECURE.
- Do not mistake 403-with-data, historical denial text, anonymous private
  increments, or undeclared public access for access-control enforcement.
- Compare effective authentication headers; exclude request/trace echoes from
  identity evidence and support explicit trusted response resource_id_paths.
- Probe readOnly privilege fields while excluding them from ordinary baselines.
- Recursively validate samples, intersect allOf constraints and reject invalid
  baselines. Resolve 3.1 ref siblings in their original contexts; reject ambiguous
  3.0/Swagger structural siblings and missing pointers instead of losing fields.
- Propagate supported media types, rejecting unsupported JSON Patch arrays.
- Bound/redact bodies, URLs, known credentials, error text and result metadata.
- Add zero-check CI failure, coverage/suspicious gates, no-network dry-run and
  case-sensitive CLI allowlist replacement.

Migration: PUBLIC needs explicit policy; unchanged active checks need strong
readback consistency. Rewrite 3.0 structural ref siblings as allOf. Full-state
verification may require explicitly identifying harmless volatile fields. These
checks do not establish a universal rollback or privacy guarantee.

## 2.1.0 - Safety hardening

- Made read-only auditing the default and limited active mutations to explicitly
  allowlisted JSON `PATCH` operations.
- Added independent read-before/write/read-after/rollback verification, retrying
  readback and treating asynchronous or ambiguous outcomes as errors.
- Reworked BOLA decisions around owner, cross-visitor, anonymous, and distinct
  visitor-self baselines. Matching JSON structure alone is never confirmation.
- Added explicit `CONFIRMED`, `SECURE`, `PUBLIC`, `SUSPICIOUS`, `INCONCLUSIVE`,
  `SKIPPED`, and `ERROR` results with honest attempted/conclusive coverage.
- Enabled TLS verification by default, blocked redirects, capped response sizes,
  added global throttling, and restricted non-loopback clear-text HTTP.
- Added default evidence minimisation, secret/PII redaction, hashes, and HTML
  escaping.
- Expanded OpenAPI parsing to JSON/YAML, safe local external references,
  recursive schemas/compositions, and parameter override semantics.
- Added constraint-aware parameters, valid request baselines, and one-field
  nested mass-assignment mutations.
- Added packaging metadata, CI, an Apache-2.0 license, security guidance, and a
  standard-library regression suite.

The bundled mock remains intentionally vulnerable in one BOLA route and one
mass-assignment route so the end-to-end flow can be verified safely on loopback.
