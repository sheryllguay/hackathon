# Lessons Learned

## Irish-Name-Repo 1 (picoCTF 2019) - SQL Injection Login Bypass
- **What happened**: The login form concatenated user input directly into an SQL query without sanitization.
- **How we found it**: Submitted a single quote (`'`) in the username field and observed an error page, indicating SQL injection.
- **How we exploited it**: Used the payload `' OR 1=1 --` in the username field (anything in password) to comment out the password check and always evaluate the WHERE clause as true.
- **Fix**: Use prepared statements / parameterized queries, validate and sanitize input, enforce least privilege on the DB account.
- **Reusable payload**: `' OR 1=1 --` (MySQL/SQLite) – remember the space after `--`.
- **Reference**: See `skills/web/SQLi.md` for a general SQLi cheat sheet and `payloads/SQLi.txt` for reusable strings.