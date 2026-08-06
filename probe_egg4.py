import socket

def raw_full(host, port, req, timeout=15):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req)
    buf = b""
    s.settimeout(timeout)
    try:
        while True:
            c = s.recv(8192)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    s.close()
    return buf

# Full 503 body (wrong host)
req = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
data = raw_full("52.76.96.108", 3012, req)
print("=== 503 FULL (wrong host) len", len(data), "===")
print(data.decode("latin-1", "replace"))
print("\n\n")

# Try /login/ on correct host
for path in ["/login/", "/login", "/admin/", "/static/", "/.git/HEAD", "/flag.txt", "/source", "/src"]:
    req = f"GET {path} HTTP/1.1\r\nHost: 52.76.96.108:3012\r\nConnection: close\r\n\r\n".encode()
    d = raw_full("52.76.96.108", 3012, req)
    print(f"=== {path} (len={len(d)}) ===")
    print(d.decode("latin-1", "replace")[:600])
    print()
