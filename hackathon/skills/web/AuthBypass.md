# Authentication & 2FA Bypass (AuthBypass)

## Purpose
Bypass authentication and multi-factor protection by abusing weak password storage, client-readable session data, and missing rate limits.

## Decision Tree
```
Login protected by MFA / flag gated by role:
 ├── Offline copy of password store available?
 │    ├── Yes -> Dump DB, crack unsalted hash offline (hashcat), then authenticate
 │    └── No  -> Online attacks: default creds, SQLi, brute force (slow)
 ├── OTP / verification code present?
 │    ├── Code stored in signed session cookie? -> Decode cookie, READ the code (signed != encrypted)
 │    ├── Endpoint has no rate limit? -> Brute-force numeric space (e.g. 1000-9999)
 │    └── OTP not invalidated per attempt? -> Keep guessing until correct
 └── Session itself forgeable? -> Client-side sessions (Flask/JWT): decode, tamper, weak secret, alg=none
```

## Recon Checklist
- [ ] Find leaked files/attachments: `users.db`, `*.db`, `.sqlite`, dump files.
- [ ] Determine password hashing: 64 hex = SHA-256, 40 = SHA-1, 32 = MD5, `$2b$` = bcrypt; check for salt columns.
- [ ] Note MFA columns (`two_fa`, `otp`, `is_2fa`) and which accounts have them.
- [ ] Capture the session cookie after login and decode the payload (client-side sessions are readable).
- [ ] Check for rate limiting / lockout on login and OTP endpoints.

## Detection Checklist
- [ ] `sqlite3 file.db .dump` / `.tables` to enumerate schema.
- [ ] Pick hashcat mode from hash length: `-m 1400` SHA-256, `-m 0` MD5, `-m 100` NTLM.
- [ ] Flask session payload segment starts with `.` -> zlib-compressed, else plain base64url JSON.
- [ ] OTP key names in session payload: `otp`, `otp_secret`, `code`, `otp_code`, `token`.

## Recon Workflow
1. Download leaked data + source; inspect the auth SQL schema.
2. Dump hashes and crack offline (fast, no interaction) before touching the live endpoint.
3. Log in with recovered credentials; capture the 2FA session cookie and decode it.

## Enumeration
- Identify hash type by length/prefix (see Detection Checklist).
- Enumerate tables: `users`, `otp`, `tokens`, `sessions`.
- Note per-user `two_fa` flags; prefer accounts with 2FA disabled.

## Useful Tools
- `hashcat` / CrackStation (unsalted hash lookup)
- `sqlite3` (dump leaked DB)
- `flask-unsign` (decode/forge Flask cookies)
- `scripts/flask_session_decoder.py` (stdlib decode, no deps)

## Quick Commands
```bash
# Dump leaked SQLite DB
sqlite3 users.db .dump
# Crack unsalted SHA-256 with rockyou
echo '<64-hex-hash>' > hash.txt && hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
# Decode a Flask session cookie (payload.timestamp.signature)
python3 scripts/flask_session_decoder.py '<session.cookie.value>'
```

## Linux Commands
```bash
sqlite3 users.db ".tables"
sqlite3 users.db "SELECT username,password,two_fa FROM users;"
# Verify a candidate password locally
echo -n 'password' | sha256sum
```

## Common Payloads
```
# OTP brute-force range when no rate limit (4-digit OTP)
for otp in range(1000, 10000)

# Flask session structure: payload.timestamp.signature
# payload = base64url JSON; zlib-compressed when it starts with '.'
```

## Exploitation Workflow
1. Recover password offline from leaked unsalted hash (rockyou/hashcat).
2. Log in; on the 2FA page, decode the session cookie to read the stored OTP.
3. Submit the OTP (or brute-force 1000-9999 if the code is not in the cookie).
4. Access the role-gated page as admin -> flag.

## Example CTF Scenario
"No FA" (picoCTF 2026): leaked `users.db` with unsalted SHA-256 admin hash -> cracked `apple@123` via rockyou. Login triggered 2FA; the 4-digit OTP was stored in the signed-but-readable Flask session cookie -> decoded, submitted, flag retrieved.

## Python Automation Example
```python
import base64, json, zlib

def decode_flask(cookie):
    payload = cookie.rsplit(".", 2)[0]          # drop timestamp.signature
    if payload.startswith("."):                 # zlib-compressed marker
        payload = payload[1:]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        return json.loads(zlib.decompress(base64.urlsafe_b64decode(payload)).decode())
    payload += "=" * ((4 - len(payload) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode())
```

## Common Mistakes
- Decoding the whole cookie (payload.timestamp.signature) instead of only the payload part.
- Missing the leading `.` zlib marker -> base64-decode alone yields garbage bytes.
- Brute-forcing login over HTTP instead of cracking the leaked hash offline.
- Forgetting OTP expiry (e.g. 120s) -> re-login for a fresh session cookie.

## CTF Tips
- Flask sessions are **signed, not encrypted** — anything in them (OTP, role, user id) is readable by the client.
- 4-digit OTP = only 9000 values; without rate limiting it is trivially brute-forceable.
- Unsalted fast hashes (MD5/SHA-1/SHA-256) -> always try rockyou/hashcat offline first.
- "No FA" / "2FA" naming hints usually point to a broken MFA implementation.

## References
- OWASP Authentication Cheat Sheet
- HackTricks: Client-side sessions / Flask session exploitation
- PortSwigger: Two-factor authentication bypass
