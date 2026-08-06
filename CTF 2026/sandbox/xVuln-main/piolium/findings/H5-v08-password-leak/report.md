# H5 — Sensitive Data Exposure: Password in Profile Response (V08)

**Severity:** High  
**CWE:** CWE-200 | **OWASP:** A02:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-008-v08-password-leak.md`

## Summary

`models.User` struct has `Password string \`json:"password"\``, and `GetProfile` SELECTs the password column. The plaintext password is always included in the JSON response.

## PoC

Same as H4: `GET /api/user/profile?id=1` returns `"password": "Admin@2024!"`.

Root cause is C8 (F-A1) plaintext storage. Fixing C8 (hashing) would convert the leak from plaintext to hash.
