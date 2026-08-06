import socket

def raw(host, port, extra_headers='', method='GET', path='/', body='', ct='application/x-www-form-urlencoded'):
    try:
        s = socket.create_connection((host, port), timeout=8)
        base = f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n"
        if body:
            base += f"Content-Type: {ct}\r\nContent-Length: {len(body)}\r\n"
        req = (base + extra_headers + "\r\n" + body).encode()
        s.sendall(req)
        buf = b""
        s.settimeout(6)
        try:
            while True:
                c = s.recv(4096)
                if not c:
                    break
                buf += c
        except socket.timeout:
            pass
        s.close()
        return buf.decode("latin-1", "replace")
    except Exception as e:
        return f"<ERR {e}>"

tests = [
    ("", "POST", "/", "egg=egg", "application/x-www-form-urlencoded"),
    ("", "POST", "/", "answer=egg", "application/x-www-form-urlencoded"),
    ("", "POST", "/", "egg=Easter+egg", "application/x-www-form-urlencoded"),
    ("", "POST", "/", '{"egg":"egg"}', "application/json"),
    ("", "POST", "/", '{"answer":"egg"}', "application/json"),
    ("", "GET", "/?answer=egg", "", ""),
    ("", "GET", "/?q=egg", "", ""),
    ("", "GET", "/?egg=EGG", "", ""),
]
for h, m, p, b, ct in tests:
    print(f"=== {m} {p} ct={ct} body={b} ===")
    print(raw("52.76.96.108", 3012, h, m, p, b, ct)[:500])
    print()
