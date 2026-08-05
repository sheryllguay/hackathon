# No FA (picoCTF 2026) - Writeup

## Category: Web Exploitation (Authentication Bypass / Broken 2FA)
## Difficulty: Medium
## Points: 200

### Challenge Description
> Seems like some data has been leaked! Can you get the flag?

The app is a Flask "Expense Tracker" with login + 2FA. Source code (`app.py`) and a leaked SQLite database (`users.db`) are provided. Flag is shown on `/` only when `session['username'] == 'admin'`. The challenge name "No FA" hints at broken/no real two-factor authentication.

### Recon
1. Read `app.py`: passwords are `sha256(password)` with **no salt**; login calls `db.get_user_by_username(username)`.
2. Dump the leaked `users.db` to find the admin hash and a `two_fa` flag:
   ```bash
   sqlite3 users.db .dump
   sqlite3 users.db "SELECT username,password,two_fa FROM users;"
   ```
   - admin hash: `c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67` (64 hex = SHA-256), `two_fa = 1`.
3. Notice the OTP flow stores the code in the **Flask session cookie**: `session['otp_secret'] = otp`.

### Exploitation
1. **Crack the hash offline** (unsalted fast hash, hint: rockyou):
   ```bash
   echo 'c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67' > hash.txt
   hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
   ```
   Result: `apple@123` (verified locally with `echo -n 'apple@123' | sha256sum`).

2. **Login** as `admin / apple@123` → redirected to `/two_fa`.

3. **Read the OTP from the session cookie** (Flask cookies are signed, not encrypted):
   - Cookie format: `payload.timestamp.signature`.
   - Payload is base64url JSON, **zlib-compressed when it starts with `.`**.
   - Decode → `{'logged': 'false', 'otp_secret': '6486', 'otp_timestamp': ..., 'username': 'admin'}`.

4. **Submit the OTP** via `POST /two_fa` with `otp=6486` → `session['logged'] = 'true'`.

5. `GET /` as admin → flag.

### Flag
```
picoCTF{n0_r4t3_n0_4uth_3ed5f244}
```
*(This instance's flag; it changes per instance.)*

### Why It Worked
- **Unsalted SHA-256** makes passwords crackable offline with rockyou (SHA-256 is fast, no salt = rainbow/hashcat ready).
- **Client-side Flask sessions** are only HMAC-signed — the OTP stored in them is fully readable by the client, so 2FA is trivially bypassable without brute force.
- The OTP endpoint had **no rate limiting** and a tiny 4-digit space (1000-9999), so even opaque OTPs are brute-forceable in ~2 minutes.

### Mitigation
- Salt + slow hashing: bcrypt/scrypt/Argon2 (never unsalted SHA/MD5).
- Never store OTPs, roles, or IDs in client-visible sessions; keep them server-side.
- Rate-limit and invalidate OTP attempts; use 6-digit codes; bind OTP to one login attempt.

### Lessons Learned
- **Flask session cookies are readable**: decode `payload.timestamp.signature`; leading `.` = zlib-compressed.
- Prefer **offline hash cracking** over online brute force; try rockyou on any unsalted fast hash.
- A flag gated only by `session['username'] == 'admin'` is a logic check you can trivially satisfy once auth is bypassed.
- Challenge title wordplay ("No FA") often describes the vulnerability.

### Reusable Artifacts
- Skill: `skills/web/AuthBypass.md`
- Script: `scripts/flask_session_decoder.py`
- Payloads: `payloads/AuthBypass.txt`

### References
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- Flask session internals / `flask-unsign`: https://github.com/Paradoxis/Flask-Unsign
- Hashcat mode 1400 (SHA-256): https://hashcat.net/wiki/doku.php?id=example_hashes
