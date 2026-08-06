# H3 — IDOR: Cross-User Order Access (V05)

**Severity:** High  
**CWE:** CWE-639 | **OWASP:** A01:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-005-v05-idor-orders.md`

## Summary

`GET /api/orders/{id}` checks session presence but never compares `userID` to `order.UserID`. Any authenticated user can read any order.

## PoC

```bash
# alice (user_id=2) fetches bob's order (id=3)
curl http://localhost:4443/api/orders/3 -H "Cookie: restaurant_session=<alice_session>"
# Response includes "user_id": 3, full item list
```
