# xVulnv2 — Balanced Security Audit Report

> **Target:** `xVulnv2 — The Local Plate` (Go 1.21, SQLite, Gorilla sessions)
> **Profile:** `piolium-balanced`
> **Method:** Manual static code review (no CodeQL / Semgrep / Go toolchain available in audit environment)
> **Audit scope:** All 30 source files in the repository, including `main.go`, `config/`, `db/`, `middleware/`, `handlers/`, `models/`, `trigger/`, `cmd/xvulnctl/`. Repository's self-described ground truth (`vulns.json`, 20 entries) was treated as **input**, not as the audit verdict; every documented finding was independently re-verified and additional findings were sought.

---

## 1. Executive Summary

xVulnv2 is a Go web application that brands itself as a "vulnerability lab" — a deliberately vulnerable system used to benchmark scanner accuracy. The repository advertises 20 known vulnerabilities in `vulns.json` with corresponding detection heuristics in `trigger/engine.go`.

**This audit confirmed all 20 documented findings and identified 7 additional findings not in the ground truth.** The total verified finding count is **27 (1 Low dropped per audit methodology, leaving 26 in final reports): 8 Critical, 14 High, 4 Medium, and 1 Low (documented in KB only).**

The application is **completely unsuitable for production deployment** in its current state. Even for a benchmark lab, the breadth and depth of the bugs would compromise any system that accidentally exposes it beyond localhost. The application is functional as designed, with feature flags (`APP_ENV=production`, `ENABLE_ADVANCED_VULNS=false`) intended to limit exposure in non-lab environments. These flags are not enforced consistently:

- `ENABLE_ADVANCED_VULNS` is checked per-handler but some "advanced" vulns (V15, V17) are not gated by anything stronger than a feature flag.
- `APP_ENV=production` disables advanced lab scenarios but does **not** disable V01–V14, the debug dump (V09), the hardcoded admin token (V07), the plaintext passwords (C8), or the CORS misconfig (H13).

The most impactful chains are:

1. **C8 (plaintext storage) + H5 (V08 password leak) + H4 (V06 IDOR) → full account takeover** of any user from any session.
2. **C4 (V09 debug dump) + C3 (V07 admin token) → unauthenticated admin access** in one HTTP GET.
3. **C7 (V20 JWT flaws) + H9 (V16 inventory) + C6 (V17 LFI/RFI) → staff panel + arbitrary stock corruption + arbitrary file read** in three requests.
4. **H13 (F-A3 CORS) + every authenticated endpoint → every authz bug becomes a cross-origin browser exploit** with a single malicious page load.

The audit was constrained by environment: no Go compiler, no SAST tools. All conclusions were reached by reading the source. Every Critical and High finding was independently re-traced from fresh context during the cold verification stage.

---

## 2. Methodology Summary

| Phase | Activity | Output |
|---|---|---|
| 1. Intelligence Gathering | Reviewed README, blueprint, vulns.json, known_findings.md; mapped 30 source files | `piolium/attack-surface/sbom.json` |
| 2. Patch Bypass Analysis | Skipped — no advisories applicable | — |
| 3. Knowledge Base | Read every Go file; identified trust boundaries, DFD/CFD slices, attacker profiles | KB section 1–3 |
| 4. Static Analysis | Manual code review (CodeQL/Semgrep unavailable); searched for SQLi sinks, path-traversal sinks, SSRF/RFI sinks, hardcoded secrets, authz gaps, race conditions, JWT flaws | KB section 4 |
| 5. Enrichment | Classified each candidate as VALID/FALSE POSITIVE/BY DESIGN/OUT OF SCOPE/DROP | KB section 5 |
| 6. Spec Gap | Skipped — no relevant specs/RFCs | — |
| 7. Deep Bug Hunt | 4 review chambers (auth/authz, data ingestion, session/CORS, business logic) | KB section 7 |
| 8. P11-LITE | Cold verification of all Critical/High findings from fresh context | KB section 8 |
| 9. Variant Analysis | Searched for V01/V02, V13/V17, V20 pattern variants | KB section 9 |
| 10. Review Chamber Addendum | New attack surfaces + revised trust boundary assumptions | KB section 11 |
| 12. Variant Analysis | Structural variants | KB section 9 |
| 15. Final Reporting | Consolidated this report + per-finding folders | `piolium/findings/*/report.md` |

---

## 3. Summary of Findings

**8 Critical · 14 High · 4 Medium · 1 Low (dropped)**

| ID | Title | Type | CWE | OWASP | Source |
|---|---|---|---|---|---|
| **C1** | SQL Injection in `/api/menu/{id}` (V01) | Injection | CWE-89 | A03 | `handlers/menu.go` |
| **C2** | SQL Injection in `/api/search?q=` (V02) | Injection | CWE-89 | A03 | `handlers/menu.go` |
| **C3** | Broken Authentication on Admin Routes (V07) | Auth | CWE-285 | A01 | `handlers/admin.go` |
| **C4** | Debug Info Endpoint Dumps Secrets (V09) | Misconfig | CWE-489 | A05 | `handlers/admin.go` |
| **C5** | Mass Assignment: Privilege Escalation (V10) | Authz | CWE-915 | A04 | `handlers/auth.go`, `handlers/profile.go` |
| **C6** | LFI / RFI in Recipe Viewer (V17) | File/SSRF | CWE-98 | A05 | `handlers/advanced_lab.go` |
| **C7** | JWT Validation Flaws (V20) | Auth | CWE-347 | A07 | `handlers/advanced_lab.go` |
| **C8** | Plaintext Password Storage at Rest (F-A1) | Crypto/Storage | CWE-256 | A02 | `db/seed.go`, `handlers/auth.go` |
| **H1** | Stored XSS in Review Comments (V03) | XSS | CWE-79 | A03 | `handlers/reviews.go` |
| **H2** | SSRF in `/api/import-menu` (V04) | SSRF | CWE-918 | A10 | `handlers/import.go` |
| **H3** | IDOR: Cross-User Order Access (V05) | Authz | CWE-639 | A01 | `handlers/orders.go` |
| **H4** | IDOR: Cross-User Profile Access (V06) | Authz | CWE-639 | A01 | `handlers/profile.go` |
| **H5** | Sensitive Data Exposure: Password in Response (V08) | Data Exposure | CWE-200 | A02 | `handlers/profile.go` |
| **H6** | Broken Function Auth: Menu Item Delete (V11) | Authz | CWE-285 | A01 | `handlers/menu.go` |
| **H7** | Path Traversal in `/api/files` (V13) | File | CWE-22 | A01 | `handlers/files.go` |
| **H8** | Unrestricted File Upload (V15) | File | CWE-434 | A05 | `handlers/advanced_lab.go` |
| **H9** | Improper Inventory Management (V16) | Business Logic | CWE-840 | API9:2023 | `handlers/advanced_lab.go` |
| **H10** | HTTP Request Smuggling Sim (V18) | Protocol | CWE-444 | A05 | `handlers/advanced_lab.go` |
| **H11** | Insecure Temp File: Invoice Export (V19) | File | CWE-377 | A05 | `handlers/advanced_lab.go` |
| **H12** | No Brute-Force Protection on `/login` (F-A2) | Auth | CWE-307 | A07 | `handlers/auth.go` |
| **H13** | CORS Misconfiguration: Echo + Credentials (F-A3) | Misconfig | CWE-942 | A05 | `middleware/cors.go` |
| **H14** | TOCTOU Race in Order Placement (F-A4) | Race | CWE-367 | A04 | `handlers/orders.go` |
| **M1** | CSRF on Order Placement (V12) | CSRF | CWE-352 | A01 | `handlers/orders.go` |
| **M2** | Client-Side Cart Trust (V14, reclassified) | Business Logic | CWE-602 | A08 | `handlers/cart.go` |
| **M3** | Session Cookie Lacks `Secure` Flag (F-A5) | Misconfig | CWE-614 | A05 | `middleware/session.go` |
| **M4** | Missing HTTP Security Headers (F-A6) | Misconfig | CWE-693 | A05 | (multiple) |
| — (L, dropped) | Stale build artifacts in repo root (F-A7) | Supply Chain | CWE-540 | A08 | `xvulnctl`, `xvulnv2` binaries |

**Documented ground-truth coverage:** All 20 entries in `vulns.json` (V01–V20) are confirmed and have corresponding finding IDs above. V14 was reclassified from CWE-502 to CWE-602 (Go JSON parsing is type-safe; the actual issue is server trust of client state).

**Additional findings not in ground truth:** 7 (C8, H12, H13, H14, M3, M4, F-A7). Of these, F-A7 (stale build artifacts) was dropped at the Low-severity threshold per audit methodology; the other 6 are promoted to final reports.

---

## 4. Technical Findings (Consolidated)

Detailed per-finding reports at `piolium/findings/<ID>-<slug>/report.md`. Cross-references below.

### 4.1 Critical Findings

**C1 — SQL Injection in `/api/menu/{id}`** (`piolium/findings/C1-v01-sqli-menu-item/report.md`)
`fmt.Sprintf` builds a SQL query with attacker-controlled `id` from `mux.Vars(r)["id"]`, executed via `db.DB.QueryRow`. UNION SELECT to `users` table yields plaintext passwords. Public, unauthenticated.

**C2 — SQL Injection in `/api/search?q=`** (`piolium/findings/C2-v02-sqli-search/report.md`)
`q` interpolated twice into LIKE pattern via `fmt.Sprintf`. Same impact as C1.

**C3 — Broken Authentication on `/admin/*`** (`piolium/findings/C3-v07-broken-auth-admin/report.md`)
Either `X-Admin-Token: lab-admin-bypass-token` OR any logged-in session grants admin access. No `role == "admin"` check. Combines with C4 to yield unauthenticated admin access.

**C4 — Debug Info Endpoint Dumps Secrets** (`piolium/findings/C4-v09-debug-info-dump/report.md`)
`/api/debug/info` returns `session_key` and `admin_token` in plaintext without auth or env check. One-step path to admin access when combined with C3.

**C5 — Mass Assignment → Admin** (`piolium/findings/C5-v10-mass-assignment/report.md`)
`POST /register?role=admin` and `POST /api/user/update {"role":"admin"}` both persist the role field directly. No allowlist. Unauthenticated path is `Register`; authenticated path is `UpdateProfile`.

**C6 — LFI / RFI in Recipe Viewer** (`piolium/findings/C6-v17-lfi-rfi-recipe/report.md`)
`?source=http://...` triggers `http.Get(source)` with the body echoed. `?source=../../...` triggers `os.ReadFile(filepath.Join(recipeDir, source))`. Both unauthenticated. Chains with C4 to leak session_key and admin_token.

**C7 — JWT Validation Flaws** (`piolium/findings/C7-v20-jwt-flaws/report.md`)
Four independent bypasses in `parseLabJWT`: `alg=none`, two-part tokens, empty signature, no `exp/iss/aud` validation. Hardcoded weak secret. Anyone reading the source can forge `role: admin` tokens.

**C8 — Plaintext Password Storage** (`piolium/findings/C8-f-a1-plaintext-passwords/report.md`)
Passwords stored unhashed. No bcrypt/scrypt/argon2 imported. Root cause that makes H4/H5 (V06/V08) yield credentials directly. Combined with H7 (V13 path traversal), the entire user table can be downloaded.

### 4.2 High Findings

**H1 — Stored XSS in Reviews** (`piolium/findings/H1-v03-stored-xss-reviews/report.md`)
Review `comment` field stored verbatim, rendered via `innerHTML` in SPA. Affects all visitors of the menu item.

**H2 — SSRF in `/api/import-menu`** (`piolium/findings/H2-v04-ssrf-import/report.md`)
`http.Get(body.URL)` with no filter. Reaches cloud metadata services. Note: returns only byte count, not body. Combine with C6 for full content echo.

**H3 — IDOR: Cross-User Order Access** (`piolium/findings/H3-v05-idor-orders/report.md`)
`GET /api/orders/{id}` does not check `userID == order.UserID`. Any session reads any order.

**H4 — IDOR: Cross-User Profile Access** (`piolium/findings/H4-v06-idor-profile/report.md`)
`GET /api/user/profile?id=` ignores session user. Returns any user's profile.

**H5 — Password in Profile Response** (`piolium/findings/H5-v08-password-leak/report.md`)
`models.User.Password` is `json:"password"`. Always serialized. Compounded by C8.

**H6 — Broken Function Auth: Menu Item Delete** (`piolium/findings/H6-v11-broken-fn-auth-delete/report.md`)
`DELETE /api/menu/{id}` only checks session presence. Any user can soft-delete.

**H7 — Path Traversal in `/api/files`** (`piolium/findings/H7-v13-path-traversal/report.md`)
`filepath.Join` does not block `../` traversal. Unauthenticated arbitrary file read.

**H8 — Unrestricted File Upload** (`piolium/findings/H8-v15-unrestricted-upload/report.md`)
Any logged-in user uploads any file type to a publicly served directory. No extension/MIME check. No `X-Content-Type-Options: nosniff` means `.html` is executed.

**H9 — Improper Inventory Management** (`piolium/findings/H9-v16-improper-inventory/report.md`)
`POST /api/kitchen/inventory/adjust` accepts `set_to=-25` and unbounded `delta`. No business-rule validation. Reachable via C7's JWT forgery.

**H10 — HTTP Request Smuggling Sim** (`piolium/findings/H10-v18-request-smuggling-sim/report.md`)
`POST /api/kitchen/dispatch` accepts TE+CL and reports parsed embedded request. **Simulator** — no real backend round-trip. The vuln is information disclosure and parser-fingerprint.

**H11 — Insecure Temp File: Invoice Export** (`piolium/findings/H11-v19-insecure-temp-file/report.md`)
Predictable filename in publicly served path. Direct static access bypasses ownership check. Chains with H3 (V05 IDOR for order ID discovery).

**H12 — No Brute-Force Protection on `/login`** (`piolium/findings/H12-f-a2-no-login-rate-limit/report.md`)
No rate limit, no lockout, no captcha. Source comment explicitly acknowledges.

**H13 — CORS Misconfiguration** (`piolium/findings/H13-f-a3-cors-misconfig/report.md`)
`Access-Control-Allow-Origin: <attacker_origin>` + `Access-Control-Allow-Credentials: true`. Every authenticated endpoint becomes a cross-origin browser exploit.

**H14 — TOCTOU Race in Order Placement** (`piolium/findings/H14-f-a4-toctou-inventory/report.md`)
`SELECT stock; time.Sleep(175ms); UPDATE stock - qty`. No transaction. Concurrent orders oversell.

### 4.3 Medium Findings

**M1 — CSRF on Order Placement** (`piolium/findings/M1-v12-csrf-orders/report.md`)
No anti-CSRF token on any state-changing endpoint. Combined with H13, cross-origin from any attacker page.

**M2 — Client-Side Cart Trust** (`piolium/findings/M2-v14-cart-deserialize/report.md`)
Server echoes client-supplied `discount`, `promo`, `total` without recalculation. Reclassified from CWE-502 to CWE-602 (Go's `json.Unmarshal` is type-safe; the actual issue is server-side trust of client state).

**M3 — Session Cookie Lacks `Secure` Flag** (`piolium/findings/M3-f-a5-session-cookie-secure/report.md`)
`Secure: false` hardcoded in `InitSession`. Cookie sent over HTTP. Deployment context.

**M4 — Missing HTTP Security Headers** (`piolium/findings/M4-f-a6-missing-security-headers/report.md`)
No CSP, no `nosniff`, no `X-Frame-Options`, no HSTS. Amplifies H1, H8.

### 4.4 Low (dropped, KB only)

**F-A7 — Stale Build Artifacts in Repo**
`xvulnctl` and `xvulnv2` binaries are present at the repo root. Supply-chain hygiene issue (binaries should not be in source). Low severity because they are not loaded at runtime from these paths; the actual binaries are built by `make run`. Dropped at Low threshold.

---

## 5. Threat-Model Summary

### 5.1 Trust Boundaries (revised after chambers)

| ID | Boundary | Original | Revised (after Phase 10) |
|---|---|---|---|
| TB-1 | Public Internet → Backend | CORS echo, Logger, LocalhostOnly reset | CORS echo **broken** (F-A3) — see TB-3 |
| TB-2 | Public Internet → Frontend | Static file server | **No CSP, no nosniff, no X-Frame-Options** (F-A6) |
| TB-3 | Browser → Authenticated API | Gorilla session, HttpOnly, SameSite=None, Secure=false | **Fully compromised by cross-origin attacker** due to F-A3 (CORS echo + credentials) |
| TB-4 | User → Admin Routes | `X-Admin-Token` OR session | **Fully compromised** (C3 + C4 chain yields unauthenticated admin) |
| TB-5 | Process → Filesystem | `filepath.Join`, no auth on `/api/files` | V13, V17 confirmed. H11 (predictable filenames) added. |
| TB-6 | Process → External Network | None on import-menu, rate-limited on recipe | V04, V17 confirmed. Asymmetric defenses. |
| TB-7 | Process → SQLite | Mostly parameterized, raw concat in V01/V02 | C1, C2 confirmed. Plaintext storage (C8) is a separate trust violation. |
| TB-8 | Process → JWT validation | Custom HS256 | **Completely broken** (C7) |

### 5.2 Critical Attack Chains

1. **Unauthenticated → Admin → All users (3 requests):**
   ```
   GET /api/debug/info                    # learn session_key + admin_token
   GET /admin/users?X-Admin-Token=...      # all users + passwords
   ```
2. **Cross-origin browser → Account takeover (1 victim visit):**
   ```
   victim on attacker.com while logged into app
   → fetch /api/user/profile?id=1 cross-origin with credentials: include
   → exfil admin password
   ```
3. **Unauthenticated → LFI of source / DB (1 request):**
   ```
   GET /api/files?name=../../go.mod        # or ../../restaurant.db
   ```
4. **Source read → JWT forgery → Staff panel (1 source read + 1 request):**
   ```
   strings xvulnv2 | grep kitchen-legacy-secret
   # forge HS256 token with role: admin
   GET /api/staff/panel -H "Authorization: Bearer <forged>"
   ```
5. **Mass assignment → Self-promotion (1 request, no session):**
   ```
   POST /register?role=admin
   ```

### 5.3 OWASP / API Top 10 Coverage

| OWASP Category | Findings |
|---|---|
| A01:2021 Broken Access Control | C3, H3, H4, H6, H7, M1 |
| A02:2021 Cryptographic Failures | C8, H5 |
| A03:2021 Injection | C1, C2, H1 |
| A04:2021 Insecure Design | C5, H14 |
| A05:2021 Security Misconfiguration | C4, H8, H10, H11, H13, M3, M4 |
| A07:2021 Identification & Auth Failures | C7, H12 |
| A08:2021 Software & Data Integrity | M2, F-A7 (dropped) |
| A10:2021 SSRF | H2 |
| API9:2023 Improper Inventory Management | H9 |

---

## 6. Variant / Pattern Notes

- **SQL concatenation pattern:** Found in `GetMenuItem` (C1), `GetMenu` `?category=` (variant of C1, same CWE), `SearchMenu` (C2). All other DB calls use parameterized `?` placeholders.
- **Path-traversal pattern:** Found in `GetFile` (H7) and `ViewRecipe` (C6 LFI branch). Both use `filepath.Join` with attacker-controlled segments. `UploadMenuImage` is safe due to `filepath.Base` stripping.
- **JWT pattern:** Only one custom JWT implementation (`parseLabJWT` in `handlers/advanced_lab.go`). All five textbook flaws (alg=none, no exp, no iss, no aud, weak secret) confirmed.
- **Authz broken-pattern:** V07 (admin token), V11 (delete), V20 (JWT), V10 (mass assignment) all share the same root: missing role check at the function entry point.

---

## 7. Recommendations (No Fixes Applied — Out of Scope)

This audit is read-only. The following are common remediation patterns, listed for the maintainer's reference only:

1. **Hash passwords:** Use `bcrypt` or `argon2id` for password storage. Removes the plaintext root cause (C8) and the immediate V08 leak impact.
2. **Use parameterized queries** for every SQL call. Removes C1, C2, and the `?category=` variant.
3. **Enforce `role == "admin"`** at every admin handler. Removes C3, H6.
4. **Authenticate `/api/debug/info`** or remove it from production. Removes C4.
5. **Use a vetted JWT library** (e.g., `github.com/golang-jwt/jwt/v5`) and validate `alg`, `exp`, `iss`, `aud`. Removes C7.
6. **Apply `?` placeholders in `RestoreCart`** and re-validate `discount`, `promo`, `total` server-side. Removes M2.
7. **Allowlist Origin** in `middleware/cors.go`. Removes H13.
8. **Add security headers** (CSP, nosniff, X-Frame-Options, HSTS). Removes M4.
9. **Set `Secure: true`** on the session cookie when `APP_ENV=production`. Removes M3.
10. **Wrap inventory + order placement in a transaction** with row lock or optimistic concurrency. Removes H14.
11. **Validate file uploads** by extension + magic bytes; store outside the public static dir. Removes H8.
12. **Rate-limit `/login`** per IP and per account. Removes H12.
13. **Validate `path` against an allowlist** in `GetFile` and `ViewRecipe`. Removes H7, C6 LFI.
14. **Disable the V18 simulator** in production. Removes H10.
15. **Use a single CSRF token** validated on every state-changing endpoint. Removes M1.

---

## 8. Conclusion

xVulnv2 is a well-constructed vulnerability lab. The 20 documented findings are all real, exploitable, and correctly classified (with the exception of V14's CWE-502 → CWE-602 reclassification). The application is unsuitable for production deployment in any form, but the README, `APP_ENV=production` flag, and `ENABLE_ADVANCED_VULNS` flag show that the maintainers are aware of this. As a benchmark target, the application is effective: every documented finding is reachable through normal HTTP traffic without specialized client tools.

The 7 additional findings identified in this audit (C8, H12, H13, H14, M3, M4, F-A7) reflect real developer-mistake patterns that complement the documented bugs. C8 (plaintext storage) and H13 (CORS misconfig) are particularly impactful as cross-cutting amplifiers: C8 makes every "password leak" a direct credential disclosure rather than a hash requiring offline cracking; H13 turns every authz bug into a cross-origin browser exploit reachable from a single malicious page load.

The application should be treated as a **local-only, isolated benchmark target** with no exposure to networks that contain untrusted users. The presence of stale build artifacts (`xvulnctl`, `xvulnv2`) in the repo root is a supply-chain hygiene issue worth fixing even though the binaries are not loaded from these paths at runtime.

**End of audit report.**
