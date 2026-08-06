# M3 — Session Cookie Lacks `Secure` Flag (F-A5)

**Severity:** Medium  
**CWE:** CWE-614 | **OWASP:** A05:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-025-f-a5-session-cookie-secure.md`

## Summary

`middleware/session.go::InitSession` hardcodes `Secure: false` on the session cookie. The cookie is sent over plain HTTP, allowing network attackers to capture the session token.

## Vulnerable Code

```go
// middleware/session.go
Store.Options = &sessions.Options{
    Path:     "/",
    MaxAge:   86400,
    HttpOnly: true,
    SameSite: http.SameSiteNoneMode,
    Secure:   false, // localhost dev — no TLS required
}
```

## Impact (deployment context)

If deployed without TLS the application is aware of, the cookie is sent in cleartext over HTTP. Network attackers can sniff and replay it. No env-var override exists.

## PoC (deployment context)

```bash
# On a coffee-shop WiFi, sniff port 80:
tcpdump -i wlan0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
# Look for "Cookie: restaurant_session=..." in the captured output.
```

## Severity Note

Medium because the README explicitly notes the application is intended for local lab use. In a hypothetical production deployment, this would be High.
