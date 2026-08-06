import socket

HOST = '52.76.96.108'
PORT = 3012

def raw(req: bytes, label: str):
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
        s.sendall(req)
        data = b''
        s.settimeout(8)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        s.close()
    except Exception as e:
        print(f'== {label} == ERROR {e}')
        return
    first = data.split(b'\r\n', 1)[0]
    body = data.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in data else b''
    if b'Transfer-Encoding: chunked' in data:
        out = b''
        rest = body
        try:
            while True:
                size_line, rest = rest.split(b'\r\n', 1)
                size = int(size_line.strip(), 16)
                if size == 0:
                    break
                out += rest[:size]
                rest = rest[size+2:]
            body = out
        except Exception:
            pass
    blocked = b'Web Page Blocked' in body
    print(f'== {label} == {first.decode(errors="replace")} len={len(body)} blocked={blocked}')
    if not blocked and body:
        print('   BODY:', body[:300])

tests = [
    ('double-host allowed-first', b'GET / HTTP/1.1\r\nHost: 52.76.96.108:3012\r\nHost: egg\r\nConnection: close\r\n\r\n'),
    ('double-host allowed-last', b'GET / HTTP/1.1\r\nHost: egg\r\nHost: 52.76.96.108:3012\r\nConnection: close\r\n\r\n'),
    ('absolute-uri egg + host allowed', b'GET http://egg/ HTTP/1.1\r\nHost: 52.76.96.108:3012\r\nConnection: close\r\n\r\n'),
    ('absolute-uri allowed + host egg', b'GET http://52.76.96.108:3012/ HTTP/1.1\r\nHost: egg\r\nConnection: close\r\n\r\n'),
    ('host with space before colon', b'GET / HTTP/1.1\r\nHost : 52.76.96.108:3012\r\nConnection: close\r\n\r\n'),
    ('host trailing dot', b'GET / HTTP/1.1\r\nHost: 52.76.96.108.:3012\r\nConnection: close\r\n\r\n'),
    ('host no port', b'GET / HTTP/1.1\r\nHost: 52.76.96.108\r\nConnection: close\r\n\r\n'),
    ('host header name uppercase', b'GET / HTTP/1.1\r\nHOST: 52.76.96.108:3012\r\nConnection: close\r\n\r\n'),
    ('host tab', b'GET / HTTP/1.1\r\nHost:\t52.76.96.108:3012\r\nConnection: close\r\n\r\n'),
]

for label, req in tests:
    raw(req, label)
