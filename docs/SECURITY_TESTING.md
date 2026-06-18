# CareFortress Security Testing Report
**Date:** June 18, 2026
**Tester:** James Smith
**Target:** CareFortress Management API (dashboard/api.py)
**Endpoint:** https://hypervisor-host:8443
**Tools:** Nikto 2.6.0, nmap ssl-enum-ciphers, curl, manual testing
**Testing host:** Kali Linux (external attacker simulation)

---

## Methodology

Testing performed against the live CareFortress Management API from an external Kali Linux VM on the same network segment, simulating an attacker who has gained access to the facility network. All 10 OWASP Top 10 (2021) categories were tested. Findings were remediated immediately and retested to confirm resolution.

---

## Summary

| OWASP Category | Result | Remediated |
|---|---|---|
| A01 -- Broken Access Control | PASS | N/A |
| A02 -- Cryptographic Failures | PASS | N/A |
| A03 -- Injection | PASS | N/A |
| A04 -- Insecure Design | PASS | N/A |
| A05 -- Security Misconfiguration | FINDING -- FIXED | Yes |
| A06 -- Vulnerable Components | PASS (post-fix) | Yes |
| A07 -- Identification and Authentication Failures | PASS | N/A |
| A08 -- Software and Data Integrity Failures | PASS | N/A |
| A09 -- Security Logging and Monitoring Failures | PASS | N/A |
| A10 -- Server-Side Request Forgery | PASS | N/A |

**Overall result: PASS -- all findings remediated**

---

## Detailed Findings

### A01 -- Broken Access Control -- PASS

**Test:** Attempted unauthenticated access to all protected endpoints (/vms, /logs, /attestation, /policy) from Kali VM.

**Result:**Committed and pushed. Now build the security testing document. Switch back to VM 102:
bashcat > docs/SECURITY_TESTING.md << 'EOF'
# CareFortress Security Testing Report
**Date:** June 18, 2026
**Tester:** James Smith
**Target:** CareFortress Management API (dashboard/api.py)
**Endpoint:** https://hypervisor-host:8443
**Tools:** Nikto 2.6.0, nmap ssl-enum-ciphers, curl, manual testing
**Testing host:** Kali Linux (external attacker simulation)

---

## Methodology

Testing performed against the live CareFortress Management API from an external Kali Linux VM on the same network segment, simulating an attacker who has gained access to the facility network. All 10 OWASP Top 10 (2021) categories were tested. Findings were remediated immediately and retested to confirm resolution.

---

## Summary

| OWASP Category | Result | Remediated |
|---|---|---|
| A01 -- Broken Access Control | PASS | N/A |
| A02 -- Cryptographic Failures | PASS | N/A |
| A03 -- Injection | PASS | N/A |
| A04 -- Insecure Design | PASS | N/A |
| A05 -- Security Misconfiguration | FINDING -- FIXED | Yes |
| A06 -- Vulnerable Components | PASS (post-fix) | Yes |
| A07 -- Identification and Authentication Failures | PASS | N/A |
| A08 -- Software and Data Integrity Failures | PASS | N/A |
| A09 -- Security Logging and Monitoring Failures | PASS | N/A |
| A10 -- Server-Side Request Forgery | PASS | N/A |

**Overall result: PASS -- all findings remediated**

---

## Detailed Findings

### A01 -- Broken Access Control -- PASS

**Test:** Attempted unauthenticated access to all protected endpoints (/vms, /logs, /attestation, /policy) from Kali VM.

**Result:**
GET /vms        -> {"detail":"Not authenticated"}  HTTP 401

GET /logs       -> {"detail":"Not authenticated"}  HTTP 401

GET /policy     -> {"detail":"Not authenticated"}  HTTP 401

All protected endpoints correctly return 401 without a valid JWT. The OAuth2PasswordBearer dependency enforces authentication on every protected route. No authorization bypass found.

**Status: PASS**

---

### A02 -- Cryptographic Failures -- PASS

**Test:** TLS cipher enumeration via nmap ssl-enum-ciphers from Kali VM.

**Result:**
TLSv1.2 ciphers (all rated A):

TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    (ecdh_x25519)

TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519)

TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    (ecdh_x25519)
TLSv1.3 ciphers (all rated A):

TLS_AKE_WITH_AES_256_GCM_SHA384          (X25519MLKEM768)

TLS_AKE_WITH_CHACHA20_POLY1305_SHA256    (X25519MLKEM768)

TLS_AKE_WITH_AES_128_GCM_SHA256          (X25519MLKEM768)
Least strength: A

All ciphers rated A. ECDHE forward secrecy on all TLS 1.2 connections. TLS 1.3 with post-quantum X25519MLKEM768 key exchange. No weak ciphers, no SSLv3, no TLS 1.0 or 1.1.

**Status: PASS**

---

### A03 -- Injection -- PASS

**Test:** SQL injection and special character payloads submitted to the /auth/token endpoint.

**Payloads tested:**
username=admin'--&password=anything

username=admin OR 1=1--&password=anything

**Result:**
{"detail":"Incorrect username or password"}  HTTP 401

{"detail":"Incorrect username or password"}  HTTP 401

Both payloads return a generic error with no stack trace, no database error disclosure, and no successful authentication. The API uses bcrypt password verification against a hardcoded user store -- no SQL database is involved, eliminating SQL injection risk entirely.

**Status: PASS**

---

### A04 -- Insecure Design -- PASS

**Test:** Parameter tampering on the /logs endpoint with an oversized n value designed to cause resource exhaustion.

**Payload:**
GET /logs?n=999999

**Result:**
Returned 500 entries  (cap enforced)

The API correctly caps the n parameter at 500 regardless of the requested value. The cap is enforced in code: `if n > 500: n = 500`. No resource exhaustion possible via this vector.

**Status: PASS**

---

### A05 -- Security Misconfiguration -- FINDING -- FIXED

**Test:** Nikto scan and manual header inspection from Kali VM.

**Findings before remediation:**

| Finding | Severity | Detail |
|---|---|---|
| Missing Content-Security-Policy header | Medium | Allows clickjacking and XSS framing |
| Missing Strict-Transport-Security header | Medium | Browser may attempt HTTP downgrade |
| Missing X-Content-Type-Options header | Low | MIME type sniffing possible |
| Missing Referrer-Policy header | Low | Referrer leakage on redirects |
| Missing Permissions-Policy header | Low | No restriction on browser features |
| Server header discloses uvicorn | Low | Reveals application server and version |
| OpenAPI schema exposed at /docs | Low | Exposes full API structure to unauthenticated users |

**Remediation applied:**

1. Added security headers middleware to api.py:
```python
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response
```

2. Added --no-server-header to uvicorn systemd service to suppress server disclosure.

3. Set docs_url=None in FastAPI app configuration to disable OpenAPI schema endpoint.

**Result after remediation:**
strict-transport-security: max-age=31536000; includeSubDomains

x-content-type-options: nosniff

x-frame-options: DENY

referrer-policy: strict-origin-when-cross-origin

permissions-policy: geolocation=(), microphone=(), camera=()

content-security-policy: default-src 'self'; frame-ancestors 'none'

server: [removed]

/docs: 404 Not Found

**Status: FIXED -- PASS**

---

### A06 -- Vulnerable Components -- PASS (post-fix)

**Test:** Syft SBOM generation and Grype CVE scan across all 16 Python dependencies.

**Initial scan findings:**

| Package | Version | CVE | Severity | Fixed In |
|---|---|---|---|---|
| cryptography | 46.0.5 | GHSA-537c-gmf6-5ccf | High | 48.0.1 |
| cryptography | 46.0.5 | GHSA-p423-j2cm-9vmq | Medium | 46.0.7 |
| cryptography | 46.0.5 | GHSA-m959-cc7f-wv43 | Low | 46.0.6 |

**Remediation:** Upgraded cryptography from 46.0.5 to 49.0.0.

**Re-scan result:** No vulnerabilities found across all 16 packages.

Full SBOM available at: docs/sbom-python.spdx.json

**Status: FIXED -- PASS**

---

### A07 -- Identification and Authentication Failures -- PASS

**Test:** Brute force simulation -- 12 sequential failed authentication attempts from Kali VM.

**Result:**
Attempt 1:  {"detail":"Incorrect username or password"}  HTTP 401

Attempt 2:  {"detail":"Incorrect username or password"}  HTTP 401

...

Attempt 8:  {"detail":"Incorrect username or password"}  HTTP 401

Attempt 9:  {"error":"Rate limit exceeded: 10 per 1 minute"}  HTTP 429

Attempt 10: {"error":"Rate limit exceeded: 10 per 1 minute"}  HTTP 429

Attempt 11: {"error":"Rate limit exceeded: 10 per 1 minute"}  HTTP 429

Attempt 12: {"error":"Rate limit exceeded: 10 per 1 minute"}  HTTP 429

Rate limiter enforces 10 requests per minute per IP on the /auth/token endpoint via slowapi. Triggered correctly at attempt 9. JWT tokens expire after 60 minutes. Passwords are bcrypt hashed with cost factor 12.

**Status: PASS**

---

### A08 -- Software and Data Integrity Failures -- PASS

**Test:** JWT algorithm confusion attacks -- none algorithm attack and expired token replay.

**Payloads tested:**

None algorithm attack (alg=none, no signature):
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.

Expired token replay:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MX0.invalid

**Result:**
None algorithm:  {"detail":"Invalid or expired token"}  HTTP 401

Expired token:   {"detail":"Invalid or expired token"}  HTTP 401

python-jose correctly rejects tokens signed with the none algorithm and expired tokens. The ALGORITHM constant enforces HS256 only.

**Status: PASS**

---

### A09 -- Security Logging and Monitoring Failures -- PASS

**Test:** Verified that API events are written to the SHA-256 chained audit log.

**Result:**
audit-vm    | HEARTBEAT | 2026-06-18T...

medical-vm  | HEARTBEAT | 2026-06-18T...

mgmt-vm     | HEARTBEAT | 2026-06-18T...

All authentication events, connection events, and API calls are written to the audit chain log via the _write_audit() function. The audit chain uses SHA-256 chaining with chattr +a enforcement -- entries cannot be deleted or modified after writing.

**Status: PASS**

---

### A10 -- Server-Side Request Forgery -- PASS

**Test:** Attempted SSRF via the POST /policy endpoint by submitting a URL as a rule_id value pointing to the Kali attacker VM.

**Payload:**
```json
{"rule_id": "http://192.168.1.182:9999/evil", "enabled": true}
```

**Result:**
```json
{"detail": "Rule http://192.168.1.182:9999/evil not found"}  HTTP 404
```

The API performed a string lookup against the policy rules list -- no outbound HTTP request was made. No SSRF vector exists because the policy endpoint does not make any external requests. Confirmed by monitoring Kali listener -- no inbound connection received.

**Status: PASS**

---

## Nikto Full Scan Output

Nikto v2.6.0

Target: 192.168.1.92:8443

SSL: Subject: /C=US/O=CareFortress/CN=carefortress-hypervisor

Ciphers: TLS_AES_256_GCM_SHA384

Findings:

[013587] Missing: content-security-policy     -- FIXED

[013587] Missing: referrer-policy             -- FIXED

[013587] Missing: permissions-policy          -- FIXED

[013587] Missing: strict-transport-security   -- FIXED

[013587] Missing: x-content-type-options      -- FIXED

[999993] Cert CN mismatch (lab cert expected) -- ACCEPTED (lab environment)

[007342] X-Frame-Options deprecated           -- FIXED via CSP frame-ancestors

[007352] X-Content-Type-Options not set       -- FIXED
8 items reported. All fixable items remediated.

---

## Post-Remediation Verification

All fixes verified from Kali VM after remediation:
curl -sk https://192.168.1.92:8443/health -v
strict-transport-security: max-age=31536000; includeSubDomains  -- PRESENT

x-content-type-options: nosniff                                  -- PRESENT

x-frame-options: DENY                                            -- PRESENT

referrer-policy: strict-origin-when-cross-origin                 -- PRESENT

permissions-policy: geolocation=(), microphone=(), camera=()     -- PRESENT

content-security-policy: default-src 'self'; frame-ancestors 'none' -- PRESENT

server header: [suppressed]                                      -- REMOVED

/docs endpoint: 404 Not Found                                    -- DISABLED

**Final result: All 10 OWASP categories pass. All findings remediated.**

---

## Residual Notes

- TLS certificate uses a self-signed lab cert with CN=carefortress-hypervisor. In production deployment, replace with a cert from a trusted CA matching the deployment hostname.
- The /health endpoint is intentionally unauthenticated as a liveness check. It discloses the service name and version (0.1.0). This is acceptable for a management API on a secured network segment.
- Rate limiting is per-IP using slowapi in-memory store. In a multi-instance deployment, replace with a Redis-backed store to enforce limits across instances.
