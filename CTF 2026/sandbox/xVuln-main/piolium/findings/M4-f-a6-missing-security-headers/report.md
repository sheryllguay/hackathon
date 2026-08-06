# M4 — Missing HTTP Security Headers (F-A6)

**Severity:** Medium  
**CWE:** CWE-693 | **OWASP:** A05:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-026-f-a6-missing-security-headers.md`

## Summary

The application does not set any standard HTTP security headers anywhere in the codebase. Missing: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Strict-Transport-Security`, `Permissions-Policy`.

## Impact

These headers are defense-in-depth. Their absence amplifies:

- **V03 (Stored XSS):** No CSP means uploaded scripts run with full same-origin access.
- **H8 (V15 Unrestricted upload):** No `nosniff` means an uploaded `.html` file is sniffed and executed as HTML.
- **General:** No clickjacking protection (`X-Frame-Options`/`frame-ancestors`).
- **General:** No HSTS means TLS-stripping MITM is possible when paired with F-A5.

## PoC

```bash
curl -I http://localhost:4443/
# Response headers: only Content-Type, possibly Set-Cookie. No CSP, no nosniff, no X-Frame-Options.
```

## Severity Note

Medium. Defense-in-depth, not a primary vulnerability. Listed because it's straightforward to fix and amplifies the impact of every other XSS / upload finding.
