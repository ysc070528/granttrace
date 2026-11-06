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
- **Socket timeout**: 3.0 seconds per remote document.
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

If a remote `$ref` fails for any reason (network timeout, TLS validation failure, SSRF policy trigger, HTTP 4xx/5xx, redirect attempt, size limit exceeded, or JSON/YAML syntax error):
- The failure is strictly fail-closed.
- Scanning halts during specification loading, or affected operations/checks are marked as `INCONCLUSIVE`.
- **Zero HTTP probe requests** are sent to the target API for affected checks.
- Under no circumstances will a remote reference failure produce a false `CONFIRMED` (vulnerable) or `SECURE` conclusion.

---

## 5. Offline Modes and Zero Network Guarantee

In offline modes (`--dry-run`, `--validate-config`, `--init-config`):
- When `--allow-remote-refs` is not passed, encounters with remote `$ref` fail immediately offline with zero network requests.
- Even when `--allow-remote-refs` is passed, no proactive network probing, pinging, or pre-flight requests are made to remote hosts. Requests are initiated strictly on-demand if and when a remote schema reference must be resolved.
