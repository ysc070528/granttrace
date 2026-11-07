# Secure Remote OpenAPI `$ref` Resolution

GrantTrace supports resolving remote OpenAPI schema references over HTTPS with strict security controls designed to prevent Server-Side Request Forgery (SSRF), DNS rebinding attacks, credential leakage, resource exhaustion, and local file exposure.

---

## 1. Safety-First Default Policy

By default, **remote `$ref` resolution is completely disabled**.

- Any OpenAPI specification containing a remote `$ref` (e.g. `https://schemas.example.com/user.yaml#/User`) is rejected during initialization or schema parsing.
- Zero network requests, zero DNS lookups, and zero socket connections are initiated when remote `$ref` resolution is disabled.
- GrantTrace exits fail-closed, ensuring an untrusted contract cannot trigger outbound connections or map private network topology.

---

## 2. Enabling Remote References

Remote schema retrieval requires **two explicit, simultaneous conditions**:

1. Passing `--allow-remote-refs` on the command line.
2. Specifying at least one authorized remote host via `--remote-ref-host <HOST>`.

```bash
# Authorize a single external schema repository
granttrace --spec openapi.yaml --config config.json \
  --allow-remote-refs \
  --remote-ref-host schemas.example.com

# Authorize multiple external hosts
granttrace --spec openapi.yaml --config config.json \
  --allow-remote-refs \
  --remote-ref-host schemas.example.com \
  --remote-ref-host cdn.models.example.org
```

> **Rules:**
> - Passing `--allow-remote-refs` without at least one `--remote-ref-host` is an error (exit code 2).
> - Passing `--remote-ref-host` without `--allow-remote-refs` is an error (exit code 2).
> - Hostnames are matched exactly (case-insensitive ASCII); wildcard domains or subdomains are **not** permitted.
> - Pass a bare hostname such as `schemas.example.com`. A value that can never match a `$ref` URL host — with a scheme, port, path, credentials or wildcard (`https://schemas.example.com`, `schemas.example.com:443`, `*.example.com`), or an empty value — is an error (exit code 2).
> - Non-ASCII hostnames must be given in IDNA form (`xn--bcher-kva.example`, not `bücher.example`). IP literals are compared in canonical form; IPv6 may be written with or without brackets.
> - Flags `--allow-http` or `--insecure` apply strictly to target API testing, **never** to remote schema retrieval.

---

## 3. Comprehensive Security Controls

Remote `$ref` retrieval implements defense-in-depth protections:

### A. Strict HTTPS & Port Requirements
- Only `https://` URLs are accepted. `http://`, `file://`, `ftp://`, `data://` and any other schemes are rejected.
- Standard port 443 only. URLs specifying alternate ports (e.g. `:8443`, `:8080`) are forbidden.
- URLs containing userinfo credentials (e.g. `https://user:pass@host/`) are rejected immediately.
- Strict TLS certificate verification with certificate hostname validation (SNI) is mandatory and cannot be disabled.

### B. Robust SSRF Defense
All target hosts undergo strict IP address validation prior to connection:
- Both IPv4 and IPv6 addresses are validated.
- All resolved A and AAAA records are checked against forbidden address ranges:
  - Loopback (`127.0.0.0/8`, `::1`)
  - Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
  - Link-local and multicast (`169.254.0.0/16`, `fe80::/10`, `224.0.0.0/4`, `ff00::/8`)
  - Carrier-grade NAT (`100.64.0.0/10`)
  - Cloud provider metadata endpoints (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`)
  - IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1`, `::ffff:169.254.169.254`)
  - IPv6 transition addresses whose embedded IPv4 destination is blocked: 6to4 (`2002::/16`, e.g. `2002:a9fe:a9fe::1`), Teredo (`2001::/32`) and NAT64 (`64:ff9b::/96`)
  - IPv4-compatible (`::/96`), local-use NAT64 (`64:ff9b:1::/48`) and deprecated site-local (`fec0::/10`) IPv6 ranges
- These rules are applied directly rather than relying only on Python's `ipaddress` classification, which differs between Python patch releases (releases before its 2024 update treat some 6to4 addresses as global).
- **Multi-IP Fail-Closed**: If a hostname resolves to multiple IP addresses and any address is unsafe or unroutable, the entire connection is rejected immediately.

### C. DNS Rebinding Defense (IP Pinning)
To eliminate Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks:
- The socket is opened directly to the pre-validated IP address using `PinnedIPHTTPSConnection`.
- No secondary DNS lookup occurs at connection time.
- The TLS handshake enforces the intended hostname via SNI and certificate subject verification.

### D. Prohibition of HTTP Redirects
- HTTP 3xx redirects (301, 302, 303, 307, 308) are strictly prohibited.
- A remote schema server attempting to redirect (e.g. to an internal service or unallowed host) causes an immediate security error and fails closed.

### E. Strict Resource Limits
To defend against decompression bombs, slowloris downloads, and circular reference exhaustion:
- **Maximum single document size**: 512 KiB (524,288 bytes), enforced chunk-by-chunk while streaming.
- **Maximum cumulative download size**: 2 MiB (2,097,152 bytes) across all documents.
- **Maximum distinct remote documents**: 4 documents.
- **Maximum `$ref` resolution depth**: 10 levels.
- **Overall deadline**: 3.0 seconds per remote document, covering DNS, connection, TLS, headers and body. It is an absolute deadline, not a per-read socket timeout: a server that drips bytes slowly is cut off when the deadline passes, and a body cut off at the deadline is never treated as complete.
- **Complete documents only**: a body shorter than its declared `Content-Length` is rejected rather than parsed as a truncated document.
- **YAML alias expansion**: anchors and aliases may add at most max(250,000, 10 × the document's own nodes) nodes; recursive aliases are rejected. This also applies to local YAML specifications.
- Unrequested automatic decompression streams are not decoded.

### F. Strict Isolation from Local Filesystem
- A remote document **cannot** reference local files under any circumstances.
- References using `file://` or pointing to local paths inside a remote schema raise `RemoteRefSecurityError`.
- Relative references inside a remote document (e.g. `../models/item.yaml`) resolve strictly against the remote base URL and stay within authorized remote HTTPS hosts.

### G. Complete Credential Isolation
- Remote schema fetching is an unauthenticated, read-only operation.
- Target API authentication headers (e.g. `Authorization`, `Cookie`, `X-API-Key`, Bearer tokens) configured in identities are **never** included in requests to remote schema hosts.
- Headers sent to remote schema hosts are limited strictly to `Host`, `User-Agent`, `Accept`, and `Connection`.

---

## 4. Fail-Closed Error Handling

If a remote `$ref` fails for any reason (network timeout, TLS validation failure, SSRF policy trigger, HTTP 4xx/5xx, malformed or truncated HTTP response, redirect attempt, size limit exceeded, or JSON/YAML syntax error):
- The failure is strictly fail-closed.
- Policy violations (remote refs disabled, a host outside the allowlist, an SSRF or transport-security violation) halt the scan during specification loading.
- Fetch and resolution failures mark the affected operations/checks as `INCONCLUSIVE` with `reason_category: unresolved_reference`, including a whole path item whose `$ref` fails, so `--fail-on-error` reports them.
- **Zero HTTP probe requests** are sent to the target API for affected checks.
- Under no circumstances will a remote reference failure produce a false `CONFIRMED` (vulnerable) or `SECURE` conclusion.

---

## 5. Offline Modes and Zero Network Guarantee

Offline modes never fetch remote documents or resolve their hosts, **even when `--allow-remote-refs` is passed**:
- `--dry-run`: operations that depend on a remote `$ref` appear in the plan as `INCONCLUSIVE` (`unresolved_reference`) with a warning; the plan itself succeeds.
- `--validate-config`: an unresolved remote `$ref` is reported as a validation error ("cannot be validated offline") and the command exits with code 2. A specification that depends on remote references therefore cannot pass offline validation.
- `--init-config` cannot be combined with `--allow-remote-refs` or `--remote-ref-host`.

Only a real scan resolves remote references, on demand and within the limits above; there is no proactive probing or pre-flight request to remote hosts.
