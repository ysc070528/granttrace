# Security regression gate in CI

[中文](ci-gate.zh-CN.md)

`granttrace diff` compares two JSON scan reports offline (see
[comparing scans](advanced.md#对比两次扫描granttrace-diff)). With one or more
`--fail-on-*` options it also decides whether a pipeline may continue: it fails
on new confirmed findings, on a decrease in conclusive coverage, or on findings
that cannot be compared, as you choose.

Without these options `granttrace diff` behaves exactly as before: the same
terminal output, the same JSON, exit code 0 when the comparison is done and 2
for invalid input.

The gate **fails closed**. Results that are not comparable, verdicts without
evidence and assumptions you stated never count as a pass. A pass means that the
enabled conditions were not found; it does not show that the API is secure.

## Quick start

```bash
granttrace diff baseline.json current.json --fail-on-new --fail-on-coverage-decrease
```

Both scans should run with the same `GRANTTRACE_COMPARISON_KEY` against the
same target, and every test identity should have an account `id`. Then the
reports carry keyed fingerprints and the gate can verify that the target, the
test accounts and the configuration did not change. Without the key the gate
cannot pass (exit 3); see [assumptions](#assumptions).

## Options

| Option | Effect |
|---|---|
| `--fail-on-new` | Exit 1 on a new confirmed finding. Exit 3 when the current report has a confirmed finding that cannot be shown to be in the baseline, or a check the baseline verified as not vulnerable can no longer be verified |
| `--fail-on-coverage-decrease` | Exit 1 when conclusive coverage decreased |
| `--fail-on-not-comparable` | Exit 3 when any confirmed finding, in either report, is not comparable |
| `--gate-allow-assumptions` | Let conclusions that rely on `--assume-*` statements decide the gate. Needs at least one `--fail-on-*` option |
| `--github-actions` | GitHub Actions annotations and a step summary; see [GitHub Actions](#github-actions) |

Options must be spelled out in full.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Every enabled condition was shown to hold. Without `--fail-on-*`: the comparison is done |
| `1` | A regression was found: an enabled condition is violated, and the reports are shown to be comparable |
| `2` | Invalid input or options, or an output could not be written. No gate decision |
| `3` | Not verified: an enabled condition could neither be shown to hold nor to be violated |

When several apply, `2` comes before `1`, and `1` before `3`, so a proven
regression is never reported as merely unverified.

Every non-zero code fails a CI step. To stop only on proven regressions and
treat `3` as a warning, say so in the pipeline; for example in a shell step:

```bash
set +e
granttrace diff baseline.json current.json --fail-on-new --github-actions
code=$?
if [ "$code" -eq 3 ]; then echo "::warning::GrantTrace could not verify the gate"; exit 0; fi
exit "$code"
```

## What each condition checks

Each finding or check is identified as in `granttrace diff`: check, operation
template and subject. The JSON lists each item with one of these reason codes.

### `--fail-on-new`

| Result | When | Reason code |
|---|---|---|
| Regression (1) | The baseline verified the check as not vulnerable; it is now confirmed | `new_finding` |
| Not verified (3) | A confirmed finding in the current report is neither new nor persisting: a first detection, a new operation, a changed specification, policy or resources, an unverified baseline, a verdict without a request, an unreadable subject | `confirmed_not_comparable` |
| Not verified (3) | A check the baseline verified as not vulnerable has no conclusive result now: error, skipped, inconclusive, a verdict without a request, a missing check or a removed operation | `no_longer_verified` |
| Not verified (3) | A check the baseline verified as not vulnerable is now PUBLIC or AUTHORIZED, and its specification, policy or resources changed or cannot be shown unchanged (the rule `diff` applies to findings; any difference in the request URLs also counts) | `accepted_after_declaration_change` |

The last two rows matter: a current report without new confirmed findings is
not enough. A vulnerability can hide behind a check that no longer reaches a
conclusion, or behind a change that also edits what the check is judged by, for
example removing `security` from the operation in the specification or allowing
the Visitor in the policy.

Persisting findings do not fail `--fail-on-new`: the condition asks whether
things got worse. To fail on any confirmed finding, scan with `--fail-on-vuln`.

### `--fail-on-coverage-decrease`

| Result | When | Reason code |
|---|---|---|
| Regression (1) | A check with a conclusive result in the baseline has none now, including checks of removed operations | `conclusive_check_lost` |
| Regression (1) | The conclusive coverage percentage in the report statistics went down, for example after adding an operation that cannot be checked conclusively | `coverage_pct_decreased` |

This is the same definition as `coverage.decreased` in the comparison.

### `--fail-on-not-comparable`

| Result | When | Reason code |
|---|---|---|
| Not verified (3) | A confirmed finding in either report is not comparable; the comparison's own reason codes are listed with it | `finding_not_comparable` |

## When the gate cannot pass

Whatever the condition, the result is at best "not verified" (exit 3) when:

| Reason code | Situation |
|---|---|
| `comparison_blocked` | The comparison has a blocking reason: target, test accounts or configuration not verified or changed, or an unreadable record that may be a confirmed finding |
| `assumptions_not_allowed` | The comparison relies on `--assume-*` statements and `--gate-allow-assumptions` is not given |
| `no_conclusive_results` | The current report has no conclusive result at all, for example because the target was unreachable |

A coverage decrease seen in reports that are not shown to be comparable is
reported as not verified, not as a regression.

## Assumptions

Reports without matching keyed fingerprints (no key, different keys, or reports
from 2.7.1 and earlier) need `--assume-same-identities` and
`--assume-same-configuration`, and `--assume-same-target` when the target
differs. These are your statements, not something the reports show. By default
the gate does not let them decide the result: it exits 3 with
`assumptions_not_allowed`.

`--gate-allow-assumptions` lets them count. The result is then labelled as
relying on them: `verified` is `false` in the JSON, `relies_on_assumptions`
lists them, and the terminal, the annotations and the step summary say so. A
regression found on assumptions still exits 1. Assumptions never cover a change
the reports show.

Prefer the comparison key. In CI, keep it in a secret.

## GitHub Actions

The GitHub Actions runner reads every line a step prints, on stdout and stderr,
and runs `::command::` at the start of a line and the legacy `##[command]`
anywhere in a line. A report's role and field names are free text, so the
terminal output of `granttrace diff` escapes these markers in every mode, with
or without `--github-actions`: `##[` is printed as `##\u005b`, and the first
colon of `::` at the start of a line as `\u003a`. This is the only change to
the printed text, and only text containing these markers is affected; JSON,
step summaries and annotations keep the values exactly.

`--github-actions` adds, on top of the normal output:

- **A second guard for the log.** Everything taken from the reports is printed
  between `::stop-commands::` and its random token, so the runner ignores
  commands there even if a future change missed an escape.
- **Annotations.** An error for each regression, a warning for each item that
  could not be verified, at most 9 of each, then one line with the result:
  error for failed or not verified, warning for a pass that relies on
  assumptions, notice for a verified pass.
- **Step summary.** A Markdown summary appended to `$GITHUB_STEP_SUMMARY`: the
  result, each condition, and up to 100 items. Text from the reports is encoded
  so that it cannot form links, images, HTML or table cells. If the variable is
  not set, a note goes to stderr and nothing else changes. If the file cannot be
  written, the exit code is 2.

`--github-actions` also works without `--fail-on-*`: then it writes the
comparison to the step summary and protects the log, without annotations.

### Example workflow

[`examples/github-actions/granttrace-security-gate.yml`](../examples/github-actions/granttrace-security-gate.yml)
scans the base branch and the pull request against a service it starts on
127.0.0.1 and runs the gate. Before you use it:

1. Add a repository secret `GRANTTRACE_COMPARISON_KEY`:
   `python -c "import secrets; print(secrets.token_hex(32))"`. Pull requests
   from forks receive no secrets; their gate exits 3.
2. Keep the GrantTrace configuration on the base branch and read it from there
   for both scans, so that a pull request cannot change the identities,
   policies or resource values it is judged by. The specification comes from
   each branch: a changed operation is then not comparable and stops the gate
   with exit 3 for review.
3. Code from the pull request runs on the same runner as the gate and could
   alter files there. Run the service in a container without the workspace
   mounted, give the key only to the scan steps, and require approval for
   workflows from outside contributors.
4. A pull request can change the workflow itself. Make the job a required
   status check and protect `.github/` with code owner review.
5. Keep the `pull_request` trigger. `pull_request_target` would run code from
   the pull request with access to your secrets.
6. Scan only the service the job starts. GrantTrace's safety rules apply as for
   any scan: no PATCH, PUT or DELETE to external targets.

The baseline must come from a source the pull request cannot influence. A
forged baseline that lists a vulnerability as already confirmed makes it
persisting, and `--fail-on-new` lets persisting findings through.

## Output

The terminal output of the comparison is followed by the gate: the result and
exit code, each condition, up to 50 items, and the exit code legend.

With `--export-json`, the comparison gains a `gate` object (only when a
`--fail-on-*` option is given; `comparison_schema_version` stays 1):

| Field | Content |
|---|---|
| `gate_schema_version` | 1 |
| `result` | `passed`, `failed` or `unverified` |
| `exit_code` | 0, 1 or 3 |
| `verified` | `true` when the result does not rely on any assumption; always `false` for `unverified` |
| `allow_assumptions` | whether `--gate-allow-assumptions` was given |
| `relies_on_assumptions` | the assumptions the result relies on |
| `prerequisites` | unmet prerequisites, each with its `reason` and the blocking codes or assumptions |
| `conditions` | per enabled condition: `condition`, `flag`, `result`, `regressions`, `unverified` |

Items hold the reason code, finding ID, check, operation template, subject,
baseline and current verdicts and, for findings, the comparison's reason codes.
Like the comparison, the gate output contains no evidence, URLs, credentials or
free text from the reports.

## What the gate does not show

- That the API is secure. Persisting findings and checks that neither scan
  verified are outside the comparison.
- That the reports are genuine. They are not signed; see
  `comparability.not_verified`.
- That test data on the server is unchanged between the scans.

Compatibility: no new dependencies; Python 3.9 and later; the Windows portable
build includes the gate.
