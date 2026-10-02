# Security and safe operation

GrantTrace sends requests to the target named on the command line. Use it
only against systems for which you have explicit authorization.

The default mode does not execute mutation checks. `--allow-write-tests`
enables state-changing PATCH requests and must be limited to disposable test
data. Every operation must be present in an explicit write allowlist. POST and
PUT are not mutated automatically because generic compensation and full-state
restoration cannot be inferred safely. Active checks require a JSON request
schema plus a configured GET readback endpoint and explicit field mapping. When a
change is observed, the scanner attempts to restore the original value and
verifies the restoration. A rollback failure is reported as an error and must
be investigated immediately.

Since version 2.2, GrantTrace snapshots complete written containers and arrays, using observed
business values instead of generated examples. Every possibly committed mutation
passes through finally-protected recovery, including decode/readback exceptions.
Recovery errors or HTTP 202 halt subsequent writes. Verification compares the
entire readback document, not only payload fields. Explicit ignore_readback_paths
may exclude known harmless volatile fields, but cannot overlap written snapshots.
Never ignore privilege/derived-permission fields to make verification pass.

This is not a database transaction. Forced termination, concurrent changes,
late asynchronous work, logs, notifications and state not exposed by readback
cannot be undone generically. Use disposable, isolated test resources. Only
declare consistency=strong after checking the actual server/cache behavior;
unchanged eventual or unspecified readback cannot establish SECURE. Restoration
verification describes observed state, not a guarantee about all future state.

Only object application/json and application/merge-patch+json are implemented.
JSON Patch arrays, arbitrary vendor JSON and non-restorable Merge Patch null
object members are not sent. Explicit CLI write selections replace the config
allowlist; paths are case sensitive. Use --dry-run to inspect local scope without
target requests. In CI, use --fail-on-error and an appropriate --min-coverage;
--fail-on-suspicious also gates unresolved findings. Zero-check scans are not
security passes.

TLS certificate verification is enabled by default. Use `--insecure` only for
an isolated test environment. Plain HTTP is accepted automatically only for
loopback targets; other HTTP targets require `--allow-http`.

Reports contain minimized and redacted evidence by default. The
`--include-sensitive-evidence` option should be used only when the report will
be stored with access controls appropriate for the target data.

Non-JSON/broken bodies are omitted by default and represented by hashes. URL
query values, known credentials and common secret fields are sanitized at result
boundaries. This is not a universal PII detector: arbitrary private free text,
path identifiers and unrecognized business fields may remain. Treat minimized
reports as sensitive too.

To report a vulnerability in GrantTrace itself, contact the project owner
privately before publishing details.

