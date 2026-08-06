import socket, time

def raw(host, port, req, timeout=15):
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

base = (
    "GET / HTTP/1.1\r\n"
    "Host: 52.76.96.108:3012\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
)

cases = {
    "clean": base + "\r\n",
    "UA-egg": base.replace("Mozilla/5.0", "egg") + "\r\n",
    "header-egg": base + "Egg: 1\r\n\r\n",
    "header-xyz": base + "X-Foo: 1\r\n\r\n",
    "path-egg": base.replace("GET / ", "GET /egg ") + "\r\n",
    "accept-egg": base + "Accept: text/egg\r\n\r\n",
}
for name, req in cases.items():
    data, dt = raw("52.76.96.108", 3012, req.encode())
    print(f"=== {name} (t={dt:.2f}s, len={len(data)}) ===")
    print(repr(data[:400]))
    print()
