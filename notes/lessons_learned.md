# Lessons Learned

## Irish-Name-Repo 1 (picoCTF 2019) - SQL Injection Login Bypass
- **What happened**: The login form concatenated user input directly into an SQL query without sanitization.
- **How we found it**: Submitted a single quote (`'`) in the username field and observed an error page, indicating SQL injection.
- **How we exploited it**: Used the payload `' OR 1=1 --` in the username field (anything in password) to comment out the password check and always evaluate the WHERE clause as true.
- **Fix**: Use prepared statements / parameterized queries, validate and sanitize input, enforce least privilege on the DB account.
- **Reusable payload**: `' OR 1=1 --` (MySQL/SQLite) – remember the space after `--`.
- **Reference**: See `skills/web/SQLi.md` for a general SQLi cheat sheet and `payloads/SQLi.txt` for reusable strings.

## No FA (picoCTF 2026) - 2FA Bypass via Unsalted Hash + Session-Cookie OTP
- **What happened**: Admin password stored as unsalted SHA-256 in leaked `users.db`; the 4-digit 2FA OTP was stored inside the signed-but-readable Flask session cookie.
- **How we found it**: Dumped `users.db` with `sqlite3`, spotted a 64-hex SHA-256 hash and a `two_fa` flag; after login the session cookie payload decoded to reveal `otp_secret`.
- **How we exploited it**: Cracked the hash offline with rockyou (`hashcat -m 1400`) -> `apple@123`; logged in; read the OTP straight out of the session cookie; submitted it -> `logged=true` -> flag on `/`.
- **Fix**: Salt + slow hash (bcrypt/argon2); never store OTP/roles in client-visible sessions; rate-limit and invalidate OTP attempts.
- **Reusable technique**: Flask session cookies are signed, not encrypted -> decode the payload segment (zlib-compressed when it starts with `.`). See `skills/web/AuthBypass.md`, `scripts/flask_session_decoder.py`, `payloads/AuthBypass.txt`.