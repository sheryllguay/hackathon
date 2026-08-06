# H10 — HTTP Request Smuggling (Kitchen Dispatch Simulation) (V18)

**Severity:** High  
**CWE:** CWE-444 | **OWASP:** A05:2021  
**Status:** Confirmed (simulator)  
**Source draft:** `piolium/findings-draft/p7-018-v18-request-smuggling-sim.md`

## Summary

`POST /api/kitchen/dispatch` accepts both `Content-Length` and `Transfer-Encoding: chunked` headers and reports a fabricated "desync" with a parsed embedded request. This is a **simulator** — the embedded request is parsed and echoed but not actually dispatched. The vulnerability is the handler's willingness to accept malformed dual-header requests and the information disclosure of parser-mismatch metadata.

## PoC

```bash
curl -X POST http://localhost:4443/api/kitchen/dispatch \
  -H "Content-Length: 4" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Type: text/plain" \
  --data-binary $'4\nPING\n0\n\nGET /admin/users HTTP/1.1\nHost: localhost:4443\n'
# Response includes: {"desync":true, "smuggled_request":{"method":"GET","path":"/admin/users"}, ...}
```

Requires `ENABLE_ADVANCED_VULNS=true`. Rate-limited 10/min per IP.

## Simulation Note

No real backend round-trip occurs. `smuggled_response_preview` is computed locally from the parsed path. The vuln is information disclosure (parser behavior fingerprint + internal admin path knowledge), not actual request smuggling.
