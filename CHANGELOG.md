# Changelog

## Unreleased - Onboarding, actionable reports and parameter contracts

- Align the runtime version with package metadata and the existing v2.3.1 release;
  use granttrace_report.html when no output path is supplied. These unreleased
  changes are not included in the historical v2.3.1 release assets.
- Add a visible README report preview, private vulnerability reporting link,
  local-output ignore rules and a reproducible release checklist.
- Keep one five-minute README walkthrough and link detailed configuration,
  migration, complete sample reports and independently recorded verification.
- Explain identity/resource access, changed fields, restoration and next steps
  before raw evidence; add offline search/status filters and compact severity labels.
- Generate offline OpenAPI configuration drafts and missing-input checklists;
  reject unresolved drafts and refuse to overwrite existing files.
- Share strict OpenAPI style/explode and Swagger collectionFormat encoding across
  scans/readbacks; preserve arrays and lowercase booleans, and decline unsupported
  or ambiguous parameter formats before sending requests.
- Add explicit per-pair expected_visitor_access for legitimate sharing/admin
  reads, recorded as AUTHORIZED. JSON report schema becomes version 2.
- Add six local authorization truth fixtures with false-positive/false-negative
  accounting; retain denial, anonymous-leak and invalid-baseline boundaries.
- Remove tests' dependence on untracked config.json; automate JSON/YAML mock
  restoration and clean wheel installation outside the checkout in CI.

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
