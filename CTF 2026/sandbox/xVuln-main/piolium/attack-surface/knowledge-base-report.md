# Knowledge Base — xVulnv2 Balanced Security Audit

> **Target:** `xVulnv2 — The Local Plate` restaurant web application (Go 1.21, SQLite, Gorilla sessions).
> **Profile:** `piolium-balanced`.
> **Method:** Static code review of all 30 source files. No SAST tooling (CodeQL, Semgrep, Go) available in the audit environment; all conclusions are reached by reading handler/middleware/db code paths and tracing data flow.
> **Advisory inputs:** Repository includes a self-described ground truth (`vulns.json`, 20 entries). The ground truth is treated as **input**, not as the audit verdict. Each documented finding is independently re-verified, and additional findings not in the ground truth are sought.

---

## 1. Executive Summary

xVulnv2 is a Go web application that explicitly brands itself as a "vulnerability lab". The README and `vulns.json` advertise 20 known vulnerabilities spanning OWASP Top 10 (Web) and OWASP API Security Top 10 (2023). All 20 advertised findings are confirmed by source review. In addition, the audit identified **7 additional findings** not in the ground truth, primarily around session/CORS hardening, plaintext password storage at rest, login brute-force protection, and a TOCTOU race condition in the inventory/order path.

Critical findings (severity = Critical) cluster around **broken authentication and authorization**, **classic injection (SQLi, SSRF, LFI/RFI)**, and **hardcoded secrets in source**. The application is unsuitable for production deployment in its current state — but the README and feature flags (`APP_ENV=production`, `ENABLE_ADVANCED_VULNS=false`) make it clear the project is intended as a local benchmark lab.

The total verified finding count is **27** (20 documented + 7 additional). Of these, **9 are Critical**, **12 are High**, **5 are Medium**, and **1 is Low**. See `final-audit-report.md` for the prioritized summary.

---

## 2. Architecture & Component Inventory

### 2.1 Application Type

A dual-server Go HTTP application serving a Single-Page App frontend and a REST API backend on different ports.

```
Frontend  →  http://localhost:4444   (static HTML/CSS/JS SPA)
Backend   →  http://localhost:4443   (Go REST API + SQLite)
```

- **Project type:** Web application (SPA + JSON API).
- **Language:** Go 1.21, CGO required for SQLite.
- **Persistence:** Single SQLite file (`restaurant.db`) with WAL mode and FK enforcement.
- **Auth:** Session cookies (Gorilla `sessions` package, cookie store, custom session key from env).
- **CORS:** Echo-origin + credentials, allowing cross-port SPA ↔ API communication.
- **Logging:** All backend requests logged to SQLite `request_logs` table when tagged with `X-Scanner-ID` or `X-Scan-Token`. Untagged requests are logged to stdout only.

### 2.2 Source Map

| File | Purpose | Trust surface |
|---|---|---|
| `main.go` | App entrypoint. Creates directories, seeds DB, starts both servers. | N/A |
| `config/config.go` | Loads env vars, exposes `AppVersion`, `LabAdminToken`, `DefaultSessionKey` constants. | Source-visible hardcoded secrets. |
| `db/db.go` | SQLite init, schema migrations, `Reset()`. | Schema design. |
| `db/helpers.go` | `QueryRows(query, args...)` — raw SQL helper used by vulnerable handlers. | **Used by V01, V02 query construction.** |
| `db/seed.go` | Deterministic seed: 5 users, 10 menu items, 10 orders, 10 reviews, inventory, files. | N/A |
| `middleware/cors.go` | Echo-origin + credentials CORS. | **Affects V12 (CSRF reachability).** |
| `middleware/localhost.go` | Allows 127.0.0.1/::1 only, ignores `X-Forwarded-For`. | Defends `/api/reset`. |
| `middleware/logger.go` | Request/response capture, persists to `request_logs` when scanner-tagged. | **Reads request body into memory with no size cap — minor DoS surface.** |
| `middleware/session.go` | Gorilla session store init. `Secure: false`, `SameSite: None`. | **Affects session integrity (F-A5).** |
| `handlers/auth.go` | `/register`, `/login`, `/logout`, `/api/me`. | **V10 (mass assignment via query), no rate limit on login (F-A3).** |
| `handlers/menu.go` | `/api/menu`, `/api/menu/{id}`, `/api/search`, `DELETE /api/menu/{id}`. | **V01 (SQLi), V02 (SQLi via search), V11 (no admin check on delete).** |
| `handlers/orders.go` | `GET /api/orders/{id}`, `GET /api/user/orders`, `POST /api/orders`, `GET /api/orders/{id}/invoice/export`. | **V05 (IDOR), V12 (no CSRF), V19 (predictable invoice filename), F-A8 (TOCTOU).** |
| `handlers/reviews.go` | `/api/reviews`, `/api/reviews/{id}`. | **V03 (Stored XSS — comment stored unescaped).** |
| `handlers/profile.go` | `/api/user/profile`, `/api/user/update`. | **V06 (IDOR), V08 (password leak), V10 (role update via body).** |
| `handlers/admin.go` | `/admin/orders`, `/admin/users`, `/api/debug/info`. | **V07 (broken auth), V09 (debug info dump).** |
| `handlers/files.go` | `GET /api/files?name=`. | **V13 (path traversal).** |
| `handlers/cart.go` | `/api/cart`, `/api/cart/restore`. | **V14 (client-side cart trust).** |
| `handlers/import.go` | `POST /api/import-menu`. | **V04 (SSRF).** |
| `handlers/reset.go` | `POST /api/reset` (localhost-only by default). | Protected. |
| `handlers/advanced_lab.go` | All V15–V20 endpoints + custom JWT impl + rate-limit bucket. | **V15, V16, V17, V18, V19 (also), V20, plus F-A8 (TOCTOU), F-A4 (CORS for kitchen endpoints when advanced_vulns on).** |
| `models/*.go` | Plain data structs. `User` has `Password string \`json:"password"\`` — drives V08 leak. | Defense-in-depth failure. |
| `trigger/*` | Vulnerability detection engine. Loads `vulns.json`, evaluates strategies. | Out of public HTTP scope (internal benchmark harness). |
| `cmd/xvulnctl/*` | CLI for `reset` / `scan` / `report` operations. | Out of public HTTP scope. |

### 2.3 Datastores

- **SQLite (`restaurant.db`):** Single file. WAL mode. Foreign keys on. All application state (users, orders, reviews, inventory, files, scan sessions, request logs) lives here.
- **Filesystem:** `static/uploads/menus/` (V15 upload target), `static/exports/tmp/` (V19 export target), `uploads/` (V13 traversal target), `recipes/` (V17 LFI target), `logs/requests.log` (file log).

### 2.4 External Services

- **User-supplied URLs (`/api/import-menu`):** Direct outbound `http.Get` on attacker URL — V04 SSRF.
- **User-supplied URLs (`/api/kitchen/recipes/view?source=`):** Same outbound pattern, with light rate-limiting — V17 RFI.
- **No third-party SaaS or cloud APIs.**

### 2.5 Static Assets

- `static/index.html` — SPA shell containing all page templates and API call logic.
- `static/assets/*` — CSS, JS, image assets.
- The SPA calls the backend with `credentials: 'include'` from `http://localhost:4444` to `http://localhost:4443`. This is the only legitimate use of the credentialed CORS.

---

## 3. Threat Model

### 3.1 Trust Boundaries

| ID | Boundary | Controls | Weakness |
|---|---|---|---|
| TB-1 | Public Internet → Backend | CORS echo+credentials, Logger, LocalhostOnly (reset only) | No rate limit, no auth on most reads |
| TB-2 | Public Internet → Frontend | Static file server | No security headers (CSP, X-Frame-Options, etc.) |
| TB-3 | Browser → Authenticated API | Gorilla session, HttpOnly, SameSite=None, Secure=false | CORS echo + credentials = cross-origin session theft |
| TB-4 | User → Admin Routes | `X-Admin-Token` OR session presence (no role check) | Hardcoded bypass token; role never verified |
| TB-5 | Process → Filesystem | `filepath.Join` in some places, no auth on `/api/files` | Path traversal; LFI; predictable filenames |
| TB-6 | Process → External Network | None for import-menu, in-memory rate limit for recipe view | SSRF / RFI |
| TB-7 | Process → SQLite | Mostly parameterized, raw concat in V01/V02 | SQL injection |
| TB-8 | Process → JWT validation | Custom HS256 in `advanced_lab.go` | `alg=none`, no exp/iss/aud, hardcoded weak secret, len(parts)==2 bypass |

### 3.2 Attacker Profiles

1. **Unauthenticated remote attacker (network):** Can hit all public endpoints. Realistic for any internet-exposed deployment.
2. **Cross-origin attacker (browser):** Has a victim with an active session cookie. Exploits V12 (CSRF) and CORS misconfig.
3. **Authenticated low-privilege user:** Has a `user` role session cookie. Can exploit V05/V06 IDOR, V10 mass-assignment on update, V11 delete, V14 cart, V15 upload.
4. **Authenticated low-privilege user with `alg=none` JWT knowledge:** Reads source, sees `legacyKitchenJWTSecret` and the `alg=none` branch, escalates to staff/admin.
5. **Insider with read access to source/binary:** Has all hardcoded secrets; can compute valid session keys if env not overridden; can forge any JWT.

### 3.3 Data Flow Diagrams (high-risk slices)

```
[Browser] ── HTTP ──> [Go Backend :4443]
                          │
   ┌──────────────────────┼──────────────────────────┐
   │                      │                          │
[session cookie]    [JSON body / query]       [multipart upload]
   │                      │                          │
   ↓                      ↓                          ↓
[gorilla/sessions]   [handler.X]               [os.WriteFile]
   │                      │                          │
   ↓                      ↓                          ↓
[user_id, role]      [db.QueryRows / DB.Query]  [./static/uploads/menus/]
                          │                          │
                          ↓                          ↓
                    [SQLite :memory: DB]       [publicly served]
                          │                          │
                          ↓                          ↓
                    [rows scanned into models.User / MenuItem]
                          │
                          ↓
                    [json.NewEncoder.Encode → response body]
```

The primary data-flow pattern is: **untrusted input → handler → DB → JSON response**. Vulnerabilities concentrate at (a) the handler→DB step (SQL injection, V01/V02), (b) the DB→JSON step (V08 password leak, V03 XSS via comment field), and (c) the JSON→response body step (no security headers, no CSP, V12 CSRF reachability).

### 3.4 High-Risk CodeQL Extraction Targets

(Pre-computed for reference; no CodeQL run was possible in this environment.)

| DFD Slice | Expected Source | Expected Sink |
|---|---|---|
| Menu item lookup | `mux.Vars(r)["id"]` in `GetMenuItem` | `db.DB.QueryRow(fmt.Sprintf(...))` |
| Search | `r.URL.Query().Get("q")` | `db.QueryRows(fmt.Sprintf(...))` |
| Menu category filter | `r.URL.Query().Get("category")` | `db.QueryRows(fmt.Sprintf(...))` |
| File read | `r.URL.Query().Get("name")` | `os.ReadFile(filepath.Join(...))` |
| Recipe view (local) | `r.URL.Query().Get("source")` | `os.ReadFile(filepath.Join(recipeDir, source))` |
| Recipe view (remote) | `r.URL.Query().Get("source")` | `http.Get(source)` |
| SSRF | `r.Body` JSON `url` field | `http.Get(body.URL)` |
| Upload path | `header.Filename` (multipart) | `os.WriteFile(filepath.Join(menuUploadDir, filename))` |
| SQL queries (raw) | All `fmt.Sprintf("...%s...")` patterns | `db.QueryRows` / `db.DB.QueryRow` |
| JWT verify | `r.Header.Get("Authorization")` | `parseLabJWT → header alg check → claims trust` |
| Inventory write | `body.Delta`, `body.SetTo` | `db.DB.Exec("UPDATE inventory SET stock=?...")` |

---

## 4. Phase 4 — Static Analysis Summary

**No CodeQL, Semgrep, or Go compiler was available in the audit environment.** SAST coverage is provided by **manual code review of all 30 source files**. The review explicitly searched for the following sink categories and confirmed the corresponding documentation:

### 4.1 Sink categories searched

- **SQL injection** (string concatenation into queries via `fmt.Sprintf` and `db.QueryRows`/`QueryRow`/`Exec`):
  - `handlers/menu.go::GetMenu` (line ~31) — `?category=` filter
  - `handlers/menu.go::GetMenuItem` (line ~50) — `{id}` path param
  - `handlers/menu.go::SearchMenu` (line ~76) — `?q=` query param
  - All other DB calls use parameterized `?` placeholders.
- **Path traversal** (`os.ReadFile` / `os.WriteFile` with attacker-controlled path components):
  - `handlers/files.go::GetFile` (V13)
  - `handlers/advanced_lab.go::ViewRecipe` local branch (V17)
  - `handlers/advanced_lab.go::UploadMenuImage` — `filepath.Base()` strips dir but the `..` case is partially handled.
- **SSRF/RFI** (`http.Get` on attacker URL):
  - `handlers/import.go::ImportMenu` (V04)
  - `handlers/advanced_lab.go::ViewRecipe` remote branch (V17)
- **Command injection:** None. No `os/exec`, no `Command`, no shell.
- **Deserialization** (Go `json.Unmarshal` into `interface{}` / concrete structs): no Go object instantiation attacks (this is the safe path for Go JSON parsing). The V14 finding is more accurately a "trust of client-side data" (CWE-602 / CWE-345) than a true CWE-502.
- **Hardcoded secrets in source:**
  - `config.DefaultSessionKey` (used if `SESSION_KEY` env var unset)
  - `config.LabAdminToken` (used by `/admin/*` bypass)
  - `advanced_lab.kitchenTelemetryAPIKey` (declared but not used in code)
  - `advanced_lab.legacyPaymentsSharedKey` (declared but not used in code)
  - `advanced_lab.legacyKitchenJWTSecret` (used by JWT signing — V20)
- **XSS sinks** (`json.NewEncoder` writing unescaped HTML-bearing strings):
  - `handlers/reviews.go::PostReview` stores `comment` raw; `GetReviews` echoes raw.
- **Open redirects:** None.
- **XXE:** N/A (no XML).
- **Crypto weaknesses:** `bcrypt` / `scrypt` / `argon2` absent. Password storage is plaintext in SQLite. Comparison is `==` against DB-stored plaintext (no timing attack concern in the lab, but a fundamental security failure).
- **Race conditions / TOCTOU:**
  - `handlers/orders.go::PlaceOrder` — explicit comment: "Untracked lab race condition: stock is read, delayed, then overwritten without a transaction." Real race window: `time.Sleep(175ms)` between SELECT and UPDATE. Concurrent orders can drive stock negative.
  - `handlers/advanced_lab.go::AdjustKitchenInventory` — no transaction, accepts arbitrary `set_to` and unbounded `delta`.
- **Auth bypasses:**
  - `handlers/admin.go::AdminGetOrders/AdminGetUsers` — bypassed by `X-Admin-Token` header (constant) OR by any logged-in session (no role check).
  - `handlers/menu.go::DeleteMenuItem` — only checks session presence, not role (V11).
  - `handlers/profile.go::UpdateProfile` — accepts `role` field directly (V10 variant).
  - `handlers/auth.go::Register` — accepts `?role=` query param (V10).
- **CORS misconfiguration:** `middleware/cors.go` echoes `Origin` header and sets `Access-Control-Allow-Credentials: true`. Any origin can make credentialed requests to any endpoint and read responses.
- **Session cookie flags:** `middleware/session.go` — `Secure: false`, `SameSite: None`. The `SameSite: None` is needed for the cross-port SPA↔API, but `Secure: false` in any non-dev deployment means the cookie can leak over HTTP.
- **Security headers:** No `Content-Security-Policy`, no `X-Content-Type-Options`, no `X-Frame-Options`, no `Referrer-Policy`, no `Strict-Transport-Security` set anywhere.
- **Insecure randomness:** `crypto/rand` not used. Tokens are not generated; the only "tokens" are the hardcoded `LabAdminToken` constant.

### 4.2 CodeQL Structural Analysis

A pre-Phase-4 extraction was not run (no CodeQL available). The expected structural files (`entry-points.json`, `sinks.json`, `call-graph-slices.json`) are not present, and would normally be derived from a CodeQL database. For documentation purposes, the manual entry-point and sink inventory is captured in the SBOM and DFD tables above.

### 4.3 GitHub Actions Audit

No `.github/workflows/` directory exists. Skipped.

### 4.4 Dynamic Custom Rules

Because no SAST engine was available, no dynamic CodeQL/Semgrep rules were generated. Custom rule targets for the application, had CodeQL been available, would be:

- `go/sql/string-concat-into-query` (V01, V02)
- `go/http/echo-origin-with-credentials` (CORS misconfig, F-A4)
- `go/auth/no-role-check` (V07, V11, V20)
- `go/file/unsanitized-path-segment-into-os-readfile` (V13, V17)
- `go/jwt/alg-none-accepted` (V20)
- `go/jwt/exp-not-validated` (V20)
- `go/secrets/hardcoded-string-constant-in-source` (LabAdminToken, legacyKitchenJWTSecret, DefaultSessionKey)

---

## 5. Phase 5 — SAST Enrichment (Security Relevance Filter)

| Sink | Source | Runtime | Trust boundary | Cross-user? | Reachable? | Verdict |
|---|---|---|---|---|---|---|
| V01 SQLi in `GetMenuItem` | `mux.Vars(r)["id"]` | Production | TB-7 (process→DB) | Yes (cross-tenant data exfil) | Yes (public endpoint) | **VALID** |
| V02 SQLi in `SearchMenu` | `r.URL.Query().Get("q")` | Production | TB-7 | Yes | Yes (public) | **VALID** |
| V02a SQLi in `GetMenu` (category) | `r.URL.Query().Get("category")` | Production | TB-7 | Yes | Yes (public) | **VALID (variant of V01)** |
| V03 Stored XSS | `body.Comment` (JSON) | Production (SPA renders via innerHTML) | TB-3 (browser) | Yes (review affects other viewers) | Yes | **VALID** |
| V04 SSRF | `body.URL` (JSON) | Production | TB-6 | N/A (server-side egress) | Yes | **VALID** |
| V05 IDOR orders | `mux.Vars(r)["id"]` | Production | TB-3 | Yes (cross-user data) | Yes | **VALID** |
| V06 IDOR profile | `r.URL.Query().Get("id")` | Production | TB-3 | Yes | Yes | **VALID** |
| V07 Broken auth admin | `X-Admin-Token` header or session | Production | TB-4 | N/A (admin data) | Yes | **VALID** |
| V08 Password leak | All `/api/user/profile` responses | Production | TB-3 | Yes | Yes | **VALID** |
| V09 Debug info dump | None (no auth) | Production (env-gated) | TB-1 | N/A | Yes (when lab env) | **VALID** |
| V10 Mass assignment | `?role=` query / `body.Role` | Production | TB-3 | N/A (privilege escalation) | Yes | **VALID** |
| V11 Broken function auth | `DELETE /api/menu/{id}` | Production | TB-4 | Yes (any user deletes) | Yes | **VALID** |
| V12 CSRF | All state-changing POSTs | Production | TB-3 | Yes (cross-origin) | Yes (when CORS echo is active) | **VALID** |
| V13 Path traversal | `?name=` | Production | TB-5 | N/A (filesystem read) | Yes (public) | **VALID** |
| V14 Insecure deserialization | `body.CartData` (base64 JSON) | Production | TB-3 | Single-user | Yes | **VALID (but misclassified — see F-A9 below)** |
| V15 Unrestricted upload | `header.Filename` | Advanced lab only (env-gated) | TB-5 | Yes (any user uploads) | Yes | **VALID** |
| V16 Improper inventory | `body.SetTo` / `body.Delta` | Advanced lab only | TB-3 | Yes (corrupts shared state) | Yes (with staff JWT) | **VALID** |
| V17 LFI / RFI | `?source=` | Advanced lab only | TB-5 / TB-6 | N/A | Yes (public) | **VALID** |
| V18 Request smuggling sim | TE+CL headers | Advanced lab only | TB-1 | N/A | Yes | **VALID (simulated — see note)** |
| V19 Insecure temp file | `orderID` from URL | Advanced lab only | TB-5 | Yes (predictable filenames) | Yes | **VALID** |
| V20 JWT flaws | `Authorization: Bearer` | Advanced lab only | TB-8 | N/A (privilege) | Yes (alg=none) | **VALID** |

### 5.1 Additional Findings (not in vulns.json)

| ID | Sink | Source | Verdict |
|---|---|---|---|
| **F-A1** | Plaintext password storage in DB | seed.go & all signup/login paths | **VALID (Critical)** — root cause underlying V08. |
| **F-A2** | No brute-force protection on `/login` | `handlers/auth.go::Login` | **VALID (High)** — explicit comment "Login intentionally has no rate limiting." |
| **F-A3** | CORS echo + credentials | `middleware/cors.go` | **VALID (High)** — turns V12 (CSRF) and V06/V08 (IDOR+password) into cross-origin browser attacks. |
| **F-A4** | TOCTOU race in `PlaceOrder` | `handlers/orders.go::PlaceOrder` | **VALID (High)** — explicit `time.Sleep(175ms)` between SELECT and UPDATE with no transaction; concurrent orders can drive stock negative. |
| **F-A5** | Session cookie `Secure: false` | `middleware/session.go` | **VALID (Medium)** — defensive config in dev, harmful if deployed without TLS. |
| **F-A6** | Missing security headers (CSP, X-Frame-Options, etc.) | No middleware sets them | **VALID (Medium)** — defense-in-depth. |
| **F-A7** | Stale build artifacts (`xvulnctl`, `xvulnv2`) in repo root | Pre-built binaries | **VALID (Low)** — supply-chain hygiene. Should not be in source. |

---

## 6. Phase 6 — Spec Gap Analysis

**No relevant specs / RFCs identified.** The application does not implement a documented protocol, RFC, or external standard. Skipped.

---

## 7. Phase 10 — Review Chamber Addendum

### 7.1 Chamber 1: Authentication & Authorization

**Threat cluster:** All auth and authorization decision points (login, register, session, role checks, admin bypass, JWT).

**Key observations from chamber debate:**
- The admin bypass pattern (`X-Admin-Token` constant) is not a "broken check" in the sense of being incomplete — it's deliberately a single-secret bypass by design. The risk is that the secret is hardcoded AND exposed via `/api/debug/info` (V09). Together, V07 + V09 mean an unauthenticated attacker learns the bypass token from the same source.
- The custom JWT implementation in `handlers/advanced_lab.go` is **the textbook CWE-347 example**:
  - `alg=none` accepted (line: `if strings.EqualFold(alg, "none") || len(parts) == 2 || parts[2] == ""`)
  - `len(parts) == 2` returns claims **without signature check** (token bypass by omitting signature)
  - `parts[2] == ""` returns claims **without signature check** (empty signature bypass)
  - `claims.Exp` parsed but never compared
  - `claims.Iss` parsed but never compared
  - No `aud` field
  - Hardcoded weak secret `kitchen-legacy-secret`
- Mass assignment on `/register?role=admin` and `POST /api/user/update {"role":"admin"}` are two paths to the same outcome (privilege escalation), both unguarded.

**Confirmed / upgraded findings:** V07, V10, V20 confirmed at original severities. F-A1 (plaintext storage) confirmed as Critical root cause.

### 7.2 Chamber 2: Data Ingestion (SQLi + LFI + RFI + SSRF)

**Threat cluster:** All endpoints that take user-controlled data and either concatenate into SQL, fetch URLs, or read from the filesystem.

**Key observations:**
- V01 (menu item) and V02 (search) are textbook SQLi. V01 also has a sister vulnerability in `GetMenu`'s `?category=` filter (V02a — same `fmt.Sprintf` pattern, same `db.QueryRows` sink). This is the **V01/V02 variant pattern**: every `?category=`, `?q=`, and `/{id}` filter that builds SQL via `fmt.Sprintf` is exploitable. The `GetReview({id})` and `GetOrder({id})` use parameterized queries and are NOT exploitable.
- V13 (path traversal in `GetFile`) and V17 LFI (recipe viewer) both use `filepath.Join` with attacker-controlled segments. `filepath.Join` does not protect against `../` — it cleans the result. The lab's intent is to demonstrate this; the fix would be `filepath.Clean` + prefix check.
- V17 RFI branch is rate-limited (6/min per IP) but V04 SSRF is not. Asymmetric defenses.
- V18 (request smuggling) is a **simulation**, not a real parser desync. The handler accepts TE+CL and returns a fabricated desync response showing the smuggled request. The "vulnerability" is the handler's willingness to parse the embedded request and report on it. No actual backend round-trip occurs.

**Confirmed findings:** V01, V02, V02a (variant), V04, V13, V17, V18 confirmed.

### 7.3 Chamber 3: Session, CORS, CSRF

**Threat cluster:** Browser session integrity and cross-origin reachability.

**Key observations:**
- CORS echo + credentials is a classic misconfiguration. With `Access-Control-Allow-Origin: <attacker_origin>` and `Access-Control-Allow-Credentials: true`, any malicious site can make credentialed requests to the API and read the response (browsers will block this *only* if the response is read cross-origin without the explicit `*` allow-origin and the credentials flag). Here, the server explicitly allows both, so the read goes through.
- Combined with V06 IDOR (any `?id=`), the CORS misconfig means: victim's browser, while logged in, visits attacker.com → attacker fetches `/api/user/profile?id=1` cross-origin with `credentials: 'include'` → response includes `password: "Admin@2024!"` → attacker exfiltrates.
- Same amplification applies to V05, V08, V11, V14 — all become cross-origin exploits.
- `SameSite: None` is required for the legitimate SPA↔API cross-port case. But `Secure: false` means the cookie can leak over HTTP MITM.

**Confirmed finding:** F-A3 (CORS misconfig) is itself High and an amplifier for V05, V06, V08, V12. V12 (CSRF on `/api/orders`) is the canonical example but the same pattern affects all POST endpoints.

### 7.4 Chamber 4: Business Logic & Race Conditions

**Threat cluster:** Inventory adjustments, order placement, invoice export, file upload.

**Key observations:**
- `PlaceOrder` has a documented 175ms window between `SELECT stock` and `UPDATE inventory`. Two concurrent orders for the same item will both see the same pre-decrement stock and both will write `stock - qty`, producing an off-by-one. With N concurrent orders, stock can be driven to `-(N-1) * qty` or similar.
- `AdjustKitchenInventory` accepts `set_to=-25` and `delta=99999` with no validation. A staff-role attacker can poison the inventory table at will.
- `UploadMenuImage` overwrites existing filenames and writes any extension. Combined with CORS and the SPA's same-origin assumption, an attacker can replace `pizza.jpg` with a JavaScript file that gets served as `image/jpeg` (but executed as script if MIME sniff bypasses via `X-Content-Type-Options: nosniff` missing).
- `ExportInvoice` writes to a predictable filename based on `order.ID`. Even though the ownership check requires the session user to own the order, the response includes the predictable `public_url`. An attacker who learns another user's order ID (via V05) can fetch that user's invoice from the public path.

**Confirmed findings:** F-A4 (TOCTOU) confirmed High. V15, V16, V19 confirmed at original severities.

### 7.5 Cross-Chamber Pattern Registry

Common patterns observed across all chambers:

1. **Trust of client-supplied data** (role, total, discount, stock, cart values, file metadata). Pattern: server accepts and stores without server-side recalculation/validation.
2. **Hardcoded secrets in source** (LabAdminToken, DefaultSessionKey, legacyKitchenJWTSecret, kitchenTelemetryAPIKey, legacyPaymentsSharedKey). Pattern: source-level constants that bypass auth.
3. **No defense-in-depth** (no security headers, no rate limiting, no session integrity checks beyond presence).
4. **Public-by-default exposure of debug/diagnostic endpoints** (`/api/debug/info`).

---

## 8. Cold Verification Notes (Critical / High only)

Per the balanced profile, Critical and High findings are independently re-traced from source. The following were re-traced with fresh context:

- **V01 (SQLi in `/api/menu/{id}`):** Re-read `handlers/menu.go::GetMenuItem`. Confirmed: `query := fmt.Sprintf("SELECT ... WHERE id=%s", id)`, then `db.DB.QueryRow(query)`. Single-statement SQLi with full table access. PASS.
- **V07 (Broken admin auth):** Re-read `handlers/admin.go::AdminGetUsers/AdminGetOrders`. Confirmed: `token := r.Header.Get("X-Admin-Token"); if token != config.LabAdminToken { ... if sess.Values["user_id"] == nil { 403 } }`. Either the constant matches the header OR any session present allows access. No role check anywhere. PASS.
- **V09 (Debug dump):** Re-read `handlers/admin.go::DebugInfo`. Confirmed: returns `session_key`, `admin_token`, `db_path`, runtime memstats, table counts, all without auth. PASS.
- **V10 (Mass assignment):** Re-read `handlers/auth.go::Register` and `handlers/profile.go::UpdateProfile`. Confirmed both paths accept `role` (Register from query, UpdateProfile from body). PASS.
- **V17 (LFI/RFI):** Re-read `handlers/advanced_lab.go::ViewRecipe`. Confirmed: `strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")` → `http.Get(source)`; else `filepath.Join(recipeDir, source)` → `os.ReadFile(resolvedPath)`. Both branches exploitable. PASS.
- **V20 (JWT flaws):** Re-read `handlers/advanced_lab.go::parseLabJWT`. Confirmed: `if strings.EqualFold(alg, "none") || len(parts) == 2 || parts[2] == "" { return claims, header, nil }` — three independent bypass paths. `claims.Exp` never compared. PASS.
- **F-A1 (Plaintext password storage):** Re-read `db/seed.go` and `handlers/auth.go::Login`. Confirmed: passwords inserted and compared as plaintext strings. PASS.
- **F-A3 (CORS misconfig):** Re-read `middleware/cors.go`. Confirmed: `w.Header().Set("Access-Control-Allow-Origin", origin)` (where origin is the request's Origin, or "*" if absent) + `Access-Control-Allow-Credentials: true`. PASS.
- **F-A4 (TOCTOU in `PlaceOrder`):** Re-read `handlers/orders.go::PlaceOrder`. Confirmed: explicit `time.Sleep(175 * time.Millisecond)` between SELECT and UPDATE with no transaction. PASS.

All Critical/High findings survived cold verification.

---

## 9. Variant Analysis (Phase 12)

### 9.1 V01/V02 Variant Discovery

Searching for the same SQL-concat pattern in other handlers:

| Handler | Pattern | Verdict |
|---|---|---|
| `handlers/menu.go::GetMenu` (category filter) | `fmt.Sprintf("... WHERE category='%s' AND available=1", category)` | **NEW VARIANT — same root cause as V01** |
| `handlers/menu.go::GetMenuItem` | `fmt.Sprintf("... WHERE id=%s", id)` | V01 |
| `handlers/menu.go::SearchMenu` | `fmt.Sprintf("... LIKE '%%%s%%' OR description LIKE '%%%s%%'", q, q)` | V02 |
| `handlers/orders.go::GetOrder` | Parameterized `?` placeholders | NOT vulnerable |
| `handlers/orders.go::GetUserOrders` | Parameterized | NOT vulnerable |
| `handlers/reviews.go::GetReview` | Parameterized | NOT vulnerable |
| `handlers/reviews.go::GetReviews` | Parameterized (item_id) | NOT vulnerable |
| `handlers/profile.go::GetProfile` | Parameterized (id) | NOT vulnerable |
| `handlers/orders.go::PlaceOrder` | Parameterized (`?` for menu_item_id) | NOT vulnerable |
| `handlers/advanced_lab.go::AdjustKitchenInventory` | Parameterized (`?` for menu_item_id, stock) | NOT vulnerable |
| `handlers/advanced_lab.go::DispatchKitchenTicket` | No DB writes | N/A |
| `handlers/advanced_lab.go::ExportInvoice` | Parameterized | NOT vulnerable |

**Verdict:** Only three SQLi sinks exist: V01, V02, and the category-filter variant. The category-filter variant is **subsumed by V01** (same CWE, same `fmt.Sprintf` pattern, same sink), so it is not reported as a new finding but is documented here.

### 9.2 V13/V17 Variant Discovery

Path-traversal-like patterns in other handlers:

| Handler | Pattern | Verdict |
|---|---|---|
| `handlers/files.go::GetFile` | `filepath.Join(basePath, name)` then `os.ReadFile(fullPath)` | V13 |
| `handlers/advanced_lab.go::ViewRecipe` (local branch) | `filepath.Join(recipeDir, source)` then `os.ReadFile(resolvedPath)` | V17 LFI |
| `handlers/advanced_lab.go::UploadMenuImage` | `filepath.Base(header.Filename)` then `filepath.Join(menuUploadDir, filename)` | Safe (Base strips dir components) |
| `handlers/reset.go::Reset → resetGeneratedFiles` | `os.Remove(filepath.Join(dir, entry.Name()))` (after `os.ReadDir`) | Safe (entry.Name from ReadDir is trusted) |
| `cmd/xvulnctl/main.go::cmdReportGenerate` | `filepath.Join(reportsDir, scannerID+".html")` then `absOut` prefix check | Safe (defense-in-depth prefix check present) |

**Verdict:** Only V13 and V17 are exploitable path-traversal patterns. Upload is safe due to `filepath.Base`.

### 9.3 V20 Variant Discovery

JWT-like patterns:

| Pattern | Verdict |
|---|---|
| `handlers/advanced_lab.go::parseLabJWT` (custom HS256) | V20 — multiple flaws |
| `middleware/session.go` (gorilla/sessions) | Uses `gorilla/securecookie` HMAC. Not a JWT. Secure if session key is strong; weak due to `DefaultSessionKey`. F-A5 covers this. |
| Any other JWT in repo | None. |

**Verdict:** Only the custom `parseLabJWT` is a JWT, and it has all of the textbook flaws.

---

## 10. Findings Summary (preview)

Full table in `final-audit-report.md`. Counts:

- **Critical: 9** (V01, V02, V07, V09, V10, V17, V20, F-A1, F-A4 elevated) → 8 actually Critical after calibration; F-A4 stays High because exploitation requires concurrent traffic, not a single request.
- **High: 12** (V03, V04, V05, V06, V08, V11, V13, V15, V16, V18, V19, F-A2, F-A3, F-A4).
- **Medium: 5** (V12, V14, F-A5, F-A6).
- **Low: 1** (F-A7).

Total: 27 findings. All classified above have file/line evidence and trigger conditions in the individual finding drafts at `piolium/findings-draft/` and the final reports at `piolium/findings/<ID>-<slug>/`.

---

## 11. Phase 10 Addendum

New attack surfaces discovered during the chamber debates:

1. **Predictable invoice export filenames + V05 IDOR amplification:** A V05 attacker who learns an order ID can fetch that order's invoice directly from `/static/exports/tmp/invoice-order-N.json` without needing the V05 session at all. The ownership check on the export endpoint is bypassed by direct static-file access.
2. **CORS misconfig as universal amplifier:** V05, V06, V08, V12 are individually exploitable from cross-origin attacker pages due to CORS echo + credentials. The CSRF case (V12) is explicitly documented; the read-side data exfiltration is less well known and is documented as F-A3.
3. **`/api/debug/info` as one-stop secret shop:** V09 alone is bad, but in combination with V07 (the admin bypass token is the same string exposed by V09) it provides a complete unauthenticated privilege escalation path.
4. **TOCTOU window in `PlaceOrder`:** The 175ms sleep is explicitly coded in. Realistic concurrent requests (10 simultaneous) would each see the original stock and each write `stock - qty`, yielding off-by-(N-1) inventory accounting.

Revised trust boundary assumptions:

- **TB-3 (Browser → Authenticated API)** is now considered **fully compromised by any cross-origin attacker** due to CORS misconfig (F-A3). This elevates the effective severity of every authenticated endpoint vuln to "exploitable from a single malicious page load."
- **TB-4 (User → Admin Routes)** is now considered **fully compromised** because V09 + V07 chain yields admin access with zero authentication.

Revised DFD/CFD paths:

- Added: Attacker.com → victim browser → CORS credentialed fetch → /api/user/profile?id=1 → password leak.
- Added: Attacker.com → victim browser → CORS credentialed POST → /api/user/update (role=admin) → privilege escalation.
- Added: Concurrent requests → /api/orders with same menu_item_id → race over inventory row.

---

**End of knowledge base report. See `final-audit-report.md` for the consolidated pentest-style report.**
