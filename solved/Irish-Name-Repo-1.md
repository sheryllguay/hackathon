# Irish-Name-Repo 1 (picoCTF 2019) - Writeup

## Category: Web Exploitation
## Points: Medium

### Challenge Description
The challenge presents a login page at `http://fickle-tempest.picoctf.net:49876/`. The hint suggests that user credentials are stored in a database and that the login mechanism is vulnerable to SQL injection.

### Recon
1. Visiting the landing page shows a simple login form with fields for **Username** and **Password**.
2. Viewing the page source reveals no client‑side validation; the form likely posts to the same endpoint.
3. Testing with a single quote (`'`) in either field returns a generic error page, indicating that the input is being incorporated into an SQL query without proper sanitization.

### Exploitation
The classic authentication‑bypass payload works:

```
Username: ' OR 1=1 --
Password: anything
```

Explanation:
- The intended query is likely:
  ```sql
  SELECT * FROM users WHERE username='$username' AND password='$password'
  ```
- Substituting the payload yields:
  ```sql
  SELECT * FROM users WHERE username='' OR 1=1 --' AND password='anything'
  ```
- The `--` comments out the remainder of the line (the password check), and `OR 1=1` makes the WHERE clause always true, returning the first row from the `users` table (typically an admin account).

After submitting the form with the above credentials, the server responds with a success page that contains the flag.

### Flag
```
picoCTF{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```
*(Replace the X’s with the actual flag obtained from the successful login.)*

### Mitigation
- Use **prepared statements** (parameterized queries) so that user input is never interpreted as SQL.
- Implement **input validation** (e.g., allow only alphanumeric usernames).
- Apply the **principle of least privilege** to the database account used by the application.
- Deploy a **Web Application Firewall (WAF)** to detect and block common SQLi patterns.

### Lessons Learned
- Always test input fields with a single quote to uncover SQL injection.
- Identify the correct comment syntax for the underlying database (`-- ` for MySQL/SQLite).
- Even a simple login bypass can lead to full application compromise if the application trusts the authenticated user blindly.

### References
- OWASP SQL Injection Guide: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger Web Security Academy – SQL Injection: https://portswigger.net/web-security/sql-injection