# JSON Web Token (JWT) Exploits

## Purpose
Bypass authentication, forge identities, and execute privilege escalation by tampering with JWT headers, payloads, or signatures.

## Decision Tree
```
Identify JWT vulnerability:
 ├── Algorithm is 'none' accepted? -> Forge signature-less JWT
 ├── Header 'kid' parameter present? -> Directory traversal or SQLi key injection
 ├── Weak HMAC secret? -> Run brute force attack offline
 └── Algorithm RS256 used? -> Test RS256 to HS256 key confusion
```

## Recon Checklist
- [ ] Check if authentication headers or cookie values look like JWT format (`eyJ...`).
- [ ] Base64 decode header and payload parts to identify keys and roles.

## Detection Checklist
- [ ] Test changing the `alg` header parameter to `none` (or `None`, `NONE`).
- [ ] Remove signature suffix entirely (preserving trailing dot `.`).

## Recon Workflow
1. Intercept session requests using Burp.
2. Isolate cookies/headers starting with `eyJ`.
3. Decode portions using `scripts/jwt_decoder.py`.

## Enumeration
- Decode header: Check `alg`, `kid`, `jku`, and `x5u` fields.
- Check payload keys: Look for parameters like `admin`, `role`, `user_id`.

## Useful Tools
- `jwt_tool` (Automated JWT attack framework)
- `hashcat` (HMAC secret cracking)

## Quick Commands
```bash
# Decode JWT token offline
python3 scripts/jwt_decoder.py <jwt_token>
# Crack HMAC secret using hashcat
hashcat -m 16500 jwt.txt wordlist.txt
```

## Linux Commands
*(None applicable)*

## Common Payloads
```
# alg: none header representation
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# altered payload (admin flag set to true)
eyJ1c2VyIjoiYWRtaW4iLCJhZG1pbiI6dHJ1ZX0
```

## Exploitation Workflow
1. Decode valid JWT.
2. Edit target keys in the payload to desired values (e.g. `role=admin`).
3. Set header algorithm parameter to match planned exploit scenario.
4. Forge signature. Send updated JWT cookie/header in requests.

## Example CTF Scenario
A application verifies users by examining a JWT cookie. By changing `alg` to `none` and modifing the username claim inside payload to `admin`, an attacker logs in with administrative rights.

## Python Automation Example
```python
# Craft none algorithm token using templates/jwt_template.py functions
from templates.jwt_template import craft_none_jwt
hdr = {"typ": "JWT", "alg": "none"}
pay = {"user": "admin", "admin": True}
token = craft_none_jwt(hdr, pay)
print(f"[+] Exploit Token: {token}")
```

## Common Mistakes
- Forgetting to include the trailing dot in `none` signature-less exploits.
- Mismatched JSON syntax changes when encoding base64 strings manually.

## CTF Tips
- If the token payload has timestamps (`exp` or `nbf`), make sure they are valid (not expired).
- Look out for `kid` SQL injection to pull arbitrary values from databases to sign payloads.

## References
- PortSwigger: JWT Vulnerabilities
- HackTricks: JWT
